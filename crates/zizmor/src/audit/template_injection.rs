//! Template injection detection.
//!
//! This looks for job steps where the step contains indicators of template
//! expansion, i.e. anything matching `${{ ... }}`.
//!
//! Supports both `run:` clauses (i.e. for template injection within a shell
//! context) as well as `uses:` clauses where one or more inputs is known
//! to be a code injection sink. `actions/github-script` with `script:`
//! is an example of the latter.
//!
//! The list of action injection sinks is derived in part from
//! [CodeQL's models](https://github.com/github/codeql/blob/main/actions/ql/lib/ext),
//! which are licensed by GitHub, Inc. under the MIT License.
//!
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::{env, ops::Deref as _, sync::LazyLock, vec};

use fst::Map;
use github_actions_expressions::{Expr, context::Context, literal::Literal};
use github_actions_models::common::{EnvValue, RepositoryUses, Uses, expr::LoE};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Routable as _, SymbolicLocation},
    },
    models::{
        self, StepCommon, action::CompositeStep, inputs::Capability, uses::RepositoryUsesPattern,
        workflow::Step,
    },
    state::AuditState,
    utils::{self, DEFAULT_ENVIRONMENT_VARIABLES, ExtractedExpr, extract_fenced_expressions},
};
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

pub(crate) struct TemplateInjection;

audit_meta!(
    TemplateInjection,
    "template-injection",
    "code injection via template expansion"
);

#[allow(clippy::unwrap_used)]
static ACTION_INJECTION_SINKS: LazyLock<Vec<(RepositoryUsesPattern, Vec<&str>)>> =
    LazyLock::new(|| {
        let mut sinks: Vec<(RepositoryUsesPattern, Vec<&str>)> = serde_json::from_slice(
            include_bytes!(concat!(env!("OUT_DIR"), "/codeql-injection-sinks.json")),
        )
        .unwrap();

        sinks.extend([
            // These sinks are not tracked by CodeQL (yet)
            ("amadevus/pwsh-script".parse().unwrap(), vec!["script"]),
            (
                "jannekem/run-python-script-action".parse().unwrap(),
                vec!["script"],
            ),
            (
                "cardinalby/js-eval-action".parse().unwrap(),
                vec!["expression"],
            ),
            (
                "addnab/docker-run-action".parse().unwrap(),
                vec!["options", "run"],
            ),
        ]);
        sinks
    });

static CONTEXT_CAPABILITIES_FST: LazyLock<Map<&[u8]>> = LazyLock::new(|| {
    fst::Map::new(include_bytes!(concat!(env!("OUT_DIR"), "/context-capabilities.fst")).as_slice())
        .expect("couldn't initialize context capabilities FST")
});

impl Capability {
    fn from_context(context: &str) -> Option<Self> {
        match CONTEXT_CAPABILITIES_FST.get(context) {
            Some(0) => Some(Self::Arbitrary),
            Some(1) => Some(Self::Structured),
            Some(2) => Some(Self::Fixed),
            Some(_) => unreachable!("unexpected context capability"),
            _ => None,
        }
    }
}

impl TemplateInjection {
    fn action_injection_sinks(uses: &RepositoryUses) -> &[&'static str] {
        // TODO: Optimize; this performs a linear scan over the map at the moment.
        // This isn't meaningfully slower than a linear scan over a list
        // of patterns at current sizes, but if we go above a few hundred
        // patterns we might want to consider something like
        // the context capabilities FST.
        ACTION_INJECTION_SINKS
            .iter()
            .find(|(pattern, _)| pattern.matches(&uses.into()))
            .map(|(_, sinks)| sinks.as_slice())
            .unwrap_or(&[])
    }

    /// Returns a list of three-tuples containing the script body,
    /// script location, and any related locations for a step that's
    /// known to be a template injection sink.
    fn scripts_with_location<'doc>(
        step: &impl StepCommon<'doc>,
    ) -> Vec<(
        &'doc str,
        SymbolicLocation<'doc>,
        Vec<SymbolicLocation<'doc>>,
    )> {
        match step.body() {
            Some(models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with: LoE::Literal(with),
            }) => Self::action_injection_sinks(uses)
                .iter()
                .filter_map(|input| {
                    let input = *input;
                    with.get(input)
                        .and_then(|script| {
                            // Non-string env values can't contain expressions,
                            // so we skip them.
                            if let EnvValue::String(script) = script {
                                Some(script.as_str())
                            } else {
                                None
                            }
                        })
                        .map(|script| {
                            (
                                script,
                                step.location().with_keys(["with".into(), input.into()]),
                                vec![
                                    // TODO: Plumb the step name/id as a related
                                    // location here and below; this will require us
                                    // to add it to StepCommon.
                                    step.location()
                                        .with_keys(["uses".into()])
                                        .annotated("action accepts arbitrary code"),
                                    step.location()
                                        .with_keys(["with".into(), input.into()])
                                        .annotated("via this input")
                                        .key_only(),
                                ],
                            )
                        })
                })
                .collect(),
            Some(models::StepBodyCommon::Run { run, .. }) => {
                vec![(
                    run,
                    step.location().with_keys(["run".into()]),
                    vec![
                        step.location()
                            .with_keys(["run".into()])
                            .annotated("this run block")
                            .key_only(),
                    ],
                )]
            }
            _ => vec![],
        }
    }

    /// Returns the appropriate variable expansion syntax for the given variable
    /// based on the step's shell type. Returns `None` if the shell type is unsupported
    /// for auto-fixing.
    fn variable_expansion_for_shell<'doc>(
        env_var: &str,
        step: &impl StepCommon<'doc>,
    ) -> Option<String> {
        // Only provide fixes for run steps
        if !matches!(step.body(), Some(models::StepBodyCommon::Run { .. })) {
            return None;
        }

        let shell = utils::normalize_shell(step.shell()?.0);

        match shell {
            "bash" | "sh" | "zsh" => Some(format!("${{{env_var}}}")),
            "cmd" => Some(format!("%{env_var}%")),
            "pwsh" | "powershell" => Some(format!("$env:{env_var}")),
            _ => None,
        }
    }

    /// Converts a [`Context`] into an appropriate environment variable name,
    /// or `None` if conversion is not possible.
    fn context_to_env_var(ctx: &Context) -> Option<String> {
        // This is annoyingly non-trivial because of a few different syntax
        // forms in contexts, plus some special cases we want to produce:
        //
        // - Contexts like `foo.bar` should become `FOO_BAR` (the happy path)
        // - Contexts that contain `[n]` where `n <= 3` should render with
        //   a friendly index, e.g. `foo.bar[0]` becomes `FOO_FIRST_BAR`
        //   and `foo.bar[2]` becomes `FOO_THIRD_BAR`.
        // - Contexts that contain `[n]` where `n > 3` should render with
        //   an index, e.g. `foo.bar[4]` becomes `FOO_5TH_BAR`.
        // - Contexts that contain `*` should render with `ANY`, e.g.
        //   `foo.bar[*]` becomes `FOO_ANY_BAR`, as does `foo.bar.*`.
        let mut env_parts = vec![];

        let mut ctx_parts = ctx.parts.iter();

        // `env` contexts don't include the `env` prefix in the variable name,
        // both because they're already environment variables and so that
        // we can check against the runner's default environment variables.
        // TODO: We could probably go a step further here and avoid the
        // loop below entirely, since we expect `env` contexts to only
        // have a single part, i.e. `foo.bar` and never `foo.bar.baz`.
        let is_env_context = ctx.child_of("env");
        if is_env_context {
            ctx_parts.next();
        }

        // TODO: Pop off `matrix` and `secrets` heads, since these don't
        // add any extra information to the variable name?
        // Doing this will require us to do a bit of deconflicting, since
        // we don't want to accidentally produce a default environment
        // variable, e.g. `secrets.GITHUB_JOB` should not become `GITHUB_JOB`.

        for part in ctx_parts {
            match part.deref() {
                // We don't support turning call-led contexts into variable names.
                Expr::Call { .. } => return None,
                Expr::Identifier(ident) => {
                    env_parts.push(ident.as_str().replace('-', "_"));
                }
                Expr::Star => {
                    env_parts.insert(env_parts.len() - 1, "ANY".into());
                }
                Expr::Index(idx) => {
                    // We support string, numeric, and star indices;
                    // everything else is presumed computed.
                    match idx.as_ref().deref() {
                        // FIXME: Annoying soundness hole here: index-style
                        // literal keys can be anything, not just valid identifiers.
                        // The right thing to do here is to parse these literals
                        // and refuse to convert them if we can't make them
                        // into valid identifiers.
                        Expr::Literal(Literal::String(lit)) => {
                            env_parts.push(lit.replace('-', "_"))
                        }
                        Expr::Literal(Literal::Number(idx)) => {
                            let name = match *idx as i64 {
                                0 => "FIRST".into(),
                                1 => "SECOND".into(),
                                2 => "THIRD".into(),
                                n => format!("{}TH", n + 1),
                            };

                            env_parts.insert(env_parts.len() - 1, name);
                        }
                        Expr::Star => {
                            env_parts.insert(env_parts.len() - 1, "ANY".into());
                        }
                        _ => return None,
                    }
                }
                _ => {
                    tracing::warn!("unexpected context component: {part:?}");
                    return None;
                }
            }
        }

        let env_var = env_parts.join("_");

        // For `env` contexts, preserve the original case since these refer
        // to existing environment variables. GitHub recommends treating
        // environment variables as case sensitive.
        if is_env_context {
            Some(env_var)
        } else {
            Some(env_var.to_uppercase())
        }
    }

    /// Attempts to produce a `Fix` for a given expression.
    fn attempt_fix<'doc>(
        &self,
        raw: &ExtractedExpr<'doc>,
        parsed: &Expr,
        step: &impl StepCommon<'doc>,
    ) -> Option<Fix<'doc>> {
        // We can only fix `run:` steps for now.
        if !matches!(step.body(), Some(models::StepBodyCommon::Run { .. })) {
            return None;
        }

        // If our expression isn't a single context, then we can't fix it yet.
        let Expr::Context(ctx) = parsed else {
            return None;
        };

        // From here, our fix consists of two patch operations:
        // 1. Replacing the expression in the script with an environment
        //    variable of our generation. The variable syntax depends on
        //    the shell type: `${VAR}` for bash/sh, `%VAR%` for cmd,
        //    `$env:VAR` for PowerShell.
        // 2. Inserting the new environment variable into the step's
        //    `env:` block, e.g. `FOO_BAR: ${{ foo.bar }}`.
        //
        // TODO: We could optimize patching a bit here by keeping track
        // of contexts that have pre-defined environment variable equivalents,
        // e.g. `github.ref_name` is always `GITHUB_REF_NAME`. When we see
        // these, we shouldn't add a new `env:` member.

        // We might fail to produce a reasonable environment variable,
        // e.g. if the context is a call expression or has a computed
        // index. In those kinds of cases, we don't produce a fix.
        let env_var = Self::context_to_env_var(ctx)?;

        // Express the variable's expansion according to the step's shell.
        // For example, `VAR` becomes `${VAR}` in bash/sh/zsh,
        let var_expansion = Self::variable_expansion_for_shell(&env_var, step)?;

        let mut patches = vec![];
        patches.push(Patch {
            route: step.route().with_key("run"),
            operation: Op::RewriteFragment {
                from: subfeature::Subfeature::new(0, raw.as_raw()),
                to: var_expansion.into(),
            },
        });

        // We need to insert a new key into the `env:` block, unless the
        // variable is already a default *or* the context is `env.FOO`,
        // since the latter implies that `FOO` is already present.
        let needs_new_env = !DEFAULT_ENVIRONMENT_VARIABLES
            .iter()
            .map(|t| t.0)
            .contains(&env_var.as_str())
            && !ctx.child_of("env");

        if needs_new_env {
            patches.push(Patch {
                route: step.route(),
                operation: Op::MergeInto {
                    key: "env".to_string(),
                    updates: indexmap::IndexMap::from_iter([(
                        env_var.clone(),
                        yaml_serde::Value::String(raw.as_raw().into()),
                    )]),
                },
            });
        }

        Some(Fix {
            title: "replace expression with environment variable".into(),
            key: step.location().key,
            disposition: Default::default(),
            patches,
        })
    }

    fn injectable_template_expressions<'doc>(
        &self,
        script: &'doc str,
        step: &impl StepCommon<'doc>,
    ) -> Vec<(
        Subfeature<'doc>,
        Option<Fix<'doc>>,
        Severity,
        Confidence,
        Persona,
    )> {
        let mut all_bad_expressions = vec![];
        for (expr, expr_span) in extract_fenced_expressions(script) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_raw());
                continue;
            };
            let mut bad_expressions = vec![];

            for (context, origin) in parsed.dataflow_contexts() {
                // Try and turn our context into a pattern for
                // matching against the FST.
                match context.as_pattern().as_deref() {
                    Some(context_pattern) => {
                        // Try and get the pattern's capability from our FST.
                        match Capability::from_context(context_pattern) {
                            // Fixed means no meaningful injectable structure.
                            Some(Capability::Fixed) => continue,
                            // Structured means some attacker-controllable
                            // structure, but not fully arbitrary.
                            Some(Capability::Structured) => {
                                bad_expressions.push((
                                    Subfeature::new(
                                        expr_span.start + origin.span.start,
                                        origin.raw,
                                    ),
                                    self.attempt_fix(&expr, &parsed, step),
                                    Severity::Medium,
                                    Confidence::High,
                                    Persona::default(),
                                ));
                            }
                            // Arbitrary means the context's expansion is
                            // fully attacker-controllable.
                            Some(Capability::Arbitrary) => {
                                bad_expressions.push((
                                    Subfeature::new(
                                        expr_span.start + origin.span.start,
                                        origin.raw,
                                    ),
                                    self.attempt_fix(&expr, &parsed, step),
                                    Severity::High,
                                    Confidence::High,
                                    Persona::default(),
                                ));
                            }
                            None => {
                                // Without a FST match, we fall back on heuristics.
                                if context.child_of("secrets") {
                                    // While not ideal, secret expansion is typically not exploitable.
                                    continue;
                                } else if context.matches("needs.*.result")
                                    || context.matches("steps.*.outcome")
                                    || context.matches("steps.*.conclusion")
                                {
                                    // These are always one of `success`, `failure`, `cancelled`, or `skipped`.
                                    continue;
                                } else if context.child_of("inputs") {
                                    let (severity, confidence, persona) = match context
                                        .single_tail()
                                        .and_then(|input_name| step.get_input(input_name))
                                    {
                                        Some(Capability::Fixed) => {
                                            (Severity::Low, Confidence::High, Persona::Pedantic)
                                        }
                                        Some(Capability::Structured) => {
                                            (Severity::Medium, Confidence::High, Persona::default())
                                        }
                                        Some(Capability::Arbitrary) => {
                                            (Severity::High, Confidence::High, Persona::default())
                                        }
                                        None => {
                                            (Severity::Low, Confidence::Low, Persona::default())
                                        }
                                    };

                                    bad_expressions.push((
                                        Subfeature::new(
                                            expr_span.start + origin.span.start,
                                            origin.raw,
                                        ),
                                        self.attempt_fix(&expr, &parsed, step),
                                        severity,
                                        confidence,
                                        persona,
                                    ));
                                } else if context.child_of("env") {
                                    let env_is_static = step.env_is_static(context);

                                    if !env_is_static {
                                        bad_expressions.push((
                                            Subfeature::new(
                                                expr_span.start + origin.span.start,
                                                origin.raw,
                                            ),
                                            self.attempt_fix(&expr, &parsed, step),
                                            Severity::Low,
                                            Confidence::High,
                                            Persona::default(),
                                        ));
                                    } else {
                                        // Emit a pedantic finding even if we think the env context
                                        // expansion is probably static.
                                        bad_expressions.push((
                                            Subfeature::new(
                                                expr_span.start + origin.span.start,
                                                origin.raw,
                                            ),
                                            self.attempt_fix(&expr, &parsed, step),
                                            Severity::Low,
                                            Confidence::High,
                                            Persona::Pedantic,
                                        ));
                                    }
                                } else if context.child_of("github") {
                                    // TODO: Filter these more finely; not everything in the event
                                    // context is actually attacker-controllable.
                                    bad_expressions.push((
                                        Subfeature::new(
                                            expr_span.start + origin.span.start,
                                            origin.raw,
                                        ),
                                        self.attempt_fix(&expr, &parsed, step),
                                        Severity::High,
                                        Confidence::High,
                                        Persona::default(),
                                    ));
                                } else if context.child_of("matrix") {
                                    let matrix_is_static = match step.matrix() {
                                        Some(matrix) => matrix.expands_to_static_values(context),
                                        // Context specifies a matrix, but there is no matrix defined.
                                        // This is an invalid workflow so there's no point in flagging it.
                                        None => continue,
                                    };

                                    if !matrix_is_static {
                                        bad_expressions.push((
                                            Subfeature::new(
                                                expr_span.start + origin.span.start,
                                                origin.raw,
                                            ),
                                            self.attempt_fix(&expr, &parsed, step),
                                            Severity::Medium,
                                            Confidence::Medium,
                                            Persona::default(),
                                        ));
                                    }
                                } else {
                                    // All other contexts are typically not attacker controllable,
                                    // but may be in obscure cases.
                                    bad_expressions.push((
                                        Subfeature::new(
                                            expr_span.start + origin.span.start,
                                            origin.raw,
                                        ),
                                        self.attempt_fix(&expr, &parsed, step),
                                        Severity::Informational,
                                        Confidence::Low,
                                        Persona::default(),
                                    ));
                                }
                            }
                        }
                    }
                    None => {
                        // If we couldn't turn the context into a pattern,
                        // we almost certainly have something like
                        // `call(...).foo.bar`.
                        bad_expressions.push((
                            Subfeature::new(expr_span.start + origin.span.start, origin.raw),
                            self.attempt_fix(&expr, &parsed, step),
                            Severity::Informational,
                            Confidence::Low,
                            Persona::default(),
                        ));
                    }
                }
            }

            // If we didn't find anything noteworthy inside the extracted expression
            // (i.e., no injectable contexts with relevant dataflows), then
            // we emit a blanket pedantic finding for the extracted expression itself.
            // We do this because any expression in a code context is a code smell,
            // even if unexploitable.
            if bad_expressions.is_empty() {
                bad_expressions.push((
                    Subfeature::new(expr_span.start, &parsed),
                    // Intentionally not providing a fix here.
                    None,
                    Severity::Low,
                    Confidence::High,
                    Persona::Pedantic,
                ));
            }

            all_bad_expressions.extend(bad_expressions);
        }

        all_bad_expressions
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (script, script_loc, related_locs) in Self::scripts_with_location(step) {
            for (subfeature, fix, severity, confidence, persona) in
                self.injectable_template_expressions(script, step)
            {
                let mut finding_builder = Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(step.location().hidden())
                    .add_location(
                        script_loc
                            .clone()
                            .primary()
                            .subfeature(subfeature)
                            .annotated("may expand into attacker-controllable code".to_string()),
                    );

                for related_loc in &related_locs {
                    finding_builder = finding_builder.add_location(related_loc.clone());
                }

                if let Some(fix) = fix {
                    finding_builder = finding_builder.fix(fix);
                }

                let finding = finding_builder.build(step)?;
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for TemplateInjection {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    use crate::audit::template_injection::{Capability, TemplateInjection};

    #[test]
    fn test_capability_from_context() {
        assert!(matches!(
            Capability::from_context("github.event.workflow_run.triggering_actor.login"),
            Some(Capability::Arbitrary)
        ));
        assert!(matches!(
            Capability::from_context("github.event.answer.user.gists_url"),
            Some(Capability::Structured)
        ));
        assert!(matches!(
            Capability::from_context("github.event.type.is_enabled"),
            Some(Capability::Fixed)
        ));
        assert!(matches!(
            Capability::from_context("runner.arch"),
            Some(Capability::Fixed)
        ));
    }

    #[test]
    fn test_context_to_env_var() {
        for (ctx, expected) in [
            ("foo.bar", Some("FOO_BAR")),
            ("foo.bar[0]", Some("FOO_FIRST_BAR")),
            ("foo.bar[0][0]", Some("FOO_FIRST_FIRST_BAR")),
            ("foo.bar[1]", Some("FOO_SECOND_BAR")),
            ("foo.bar[2]", Some("FOO_THIRD_BAR")),
            ("foo.bar[3]", Some("FOO_4TH_BAR")),
            ("foo.bar[4]", Some("FOO_5TH_BAR")),
            ("foo.bar[*]", Some("FOO_ANY_BAR")),
            ("foo.bar.*", Some("FOO_ANY_BAR")),
            ("foo.bar.*.*", Some("FOO_ANY_ANY_BAR")),
            ("foo.bar.*[*]", Some("FOO_ANY_ANY_BAR")),
            ("foo.bar[*].*", Some("FOO_ANY_ANY_BAR")),
            ("foo.bar.baz", Some("FOO_BAR_BAZ")),
            ("foo.bar['baz']", Some("FOO_BAR_BAZ")),
            ("foo.bar['baz']['quux']", Some("FOO_BAR_BAZ_QUUX")),
            ("foo.bar['baz']['quux'].zap", Some("FOO_BAR_BAZ_QUUX_ZAP")),
            ("github.event.issue.title", Some("GITHUB_EVENT_ISSUE_TITLE")),
            // Calls not supported
            ("fromJSON(foo.bar).baz", None),
            // Computed indices not supported
            ("foo.bar[computed]", None),
            ("foo.bar[abc && def]", None),
            // env contexts should have the env prefix removed and preserve case
            ("env.FOO_BAR", Some("FOO_BAR")),
            ("env.foo_bar", Some("foo_bar")),
            ("ENV.foo_bar", Some("foo_bar")),
            ("ENV['foo_bar']", Some("foo_bar")),
            ("env.GITHUB_ACTOR", Some("GITHUB_ACTOR")),
            // FIXME: soundness hole
            (
                "foo.bar['oops all spaces']",
                Some("FOO_BAR_OOPS ALL SPACES"),
            ),
        ] {
            let expr = Expr::parse(ctx).unwrap();
            let Expr::Context(ctx) = &*expr else {
                panic!("Expected context expression, got: {expr:?}");
            };

            assert_eq!(
                TemplateInjection::context_to_env_var(ctx).as_deref(),
                expected
            );
        }
    }
}
