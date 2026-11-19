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
use github_actions_expressions::evaluation::TrackedValue;
use github_actions_expressions::{Error, Expr, context::Context, literal::Literal};
use github_actions_models::common::{EnvValue, RepositoryUses, Uses, expr::LoE};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Routable as _, SymbolicLocation},
    },
    models::{
        self, StepCommon,
        action::CompositeStep,
        inputs::{Capability, HasInputs},
        uses::RepositoryUsesPattern,
        workflow::Step,
    },
    state::AuditState,
    utils::{self, DEFAULT_ENVIRONMENT_VARIABLES, ExtractedExpr, extract_fenced_expressions},
};
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

type Risk = Option<(Severity, Confidence)>;

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

    /// Rate a runtime context using its known capabilities and input type.
    fn source_risk(source: &str, inputs: &impl HasInputs) -> Risk {
        let pattern = source.to_ascii_lowercase();
        let capability = source
            .split_once('.')
            .filter(|(root, _)| root.eq_ignore_ascii_case("inputs"))
            .and_then(|(_, name)| inputs.get_input(name));
        match Capability::from_context(&pattern).or(capability) {
            Some(Capability::Fixed) => return None,
            Some(Capability::Structured) => return Some((Severity::Medium, Confidence::High)),
            Some(Capability::Arbitrary) => return Some((Severity::High, Confidence::High)),
            None => (),
        }
        let root = pattern.split('.').next().unwrap_or_default();

        match root {
            "secrets" => None,
            "needs" if pattern.ends_with(".result") => None,
            "steps" if pattern.ends_with(".outcome") || pattern.ends_with(".conclusion") => None,
            "inputs" => Some((Severity::Low, Confidence::Low)),
            "env" => {
                if let Some(ctx) = Context::parse(&pattern)
                    && DEFAULT_ENVIRONMENT_VARIABLES
                        .iter()
                        .any(|(_, pat, _, fixed)| *fixed && pat.matches(&ctx))
                {
                    return None;
                }
                Some((Severity::Low, Confidence::High))
            }
            "github" => Some((Severity::High, Confidence::High)),
            "matrix" => Some((Severity::Medium, Confidence::Medium)),
            _ => Some((Severity::Informational, Confidence::Low)),
        }
    }

    fn value_risk(value: &TrackedValue, inputs: &impl HasInputs) -> Risk {
        // A collection's members reach a script through an explicit conversion
        // such as toJSON. Direct interpolation cannot insert their contents.
        let provenance = value.clone().into_string()?.provenance;
        let fallback = (Severity::Low, Confidence::Low);
        provenance
            .sources
            .iter()
            .filter_map(|id| Self::source_risk(&id.path, inputs))
            .chain(provenance.incomplete.then_some(fallback))
            .max()
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (script, script_loc, related_locs) in Self::scripts_with_location(step) {
            for (expression, span) in extract_fenced_expressions(script) {
                let parsed = Expr::parse(expression.as_bare());
                let evaluation = match &parsed {
                    Ok(expr) => step.evaluate(expr),
                    Err(Error::Depth) => models::evaluation::Evaluated::incomplete(),
                    Err(_) => continue,
                };
                if evaluation.values.is_empty() {
                    continue;
                }

                let parsed = parsed.ok();
                let mut contributing = vec![];
                let mut risk = None;
                for value in &evaluation.values {
                    if let Some(rating) = Self::value_risk(value, step) {
                        contributing.push(value);
                        risk = risk.max(Some(rating));
                    }
                }
                let (severity, confidence, persona, annotation) = match risk {
                    Some((severity, confidence)) => (
                        severity,
                        confidence,
                        Persona::default(),
                        "may expand into attacker-controllable code",
                    ),
                    None => (
                        Severity::Low,
                        Confidence::High,
                        Persona::Pedantic,
                        "prefer passing this value through the environment",
                    ),
                };

                let fragment = parsed
                    .as_ref()
                    .map(subfeature::Fragment::from)
                    .unwrap_or_else(|| subfeature::Fragment::new(expression.as_raw()));
                let subfeature = Subfeature::new(span.start, fragment);
                let fix = parsed
                    .as_ref()
                    .filter(|expr| {
                        risk.is_some()
                            || matches!(&expr.inner, Expr::Context(ctx) if ctx.child_of("env"))
                    })
                    .and_then(|parsed| self.attempt_fix(&expression, parsed, step));
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
                            .annotated(annotation),
                    );

                let locations = if contributing.is_empty() {
                    // A pedantic finding concerns the interpolation site. Keep
                    // its declarations available for inline ignores.
                    evaluation
                        .locations(&evaluation.values)
                        .into_iter()
                        .map(|loc| loc.hidden())
                        .collect()
                } else {
                    evaluation.locations(contributing)
                };
                for location in locations.into_iter().chain(related_locs.iter().cloned()) {
                    finding_builder = finding_builder.add_location(location);
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
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _group: &crate::registry::input::InputGroup,
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
