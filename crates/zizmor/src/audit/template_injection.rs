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

use std::{collections::HashMap, env, ops::Deref, sync::LazyLock, vec};

use fst::Map;
use github_actions_expressions::{Expr, Literal, context::Context};
use github_actions_models::{
    common::{EnvValue, RepositoryUses, Uses, expr::LoE},
    workflow::job::Strategy,
};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Routable as _, Subfeature, SymbolicLocation},
    },
    models::{
        self, StepCommon, action::CompositeStep, inputs::Capability, uses::RepositoryUsesPattern,
        workflow::Step,
    },
    state::AuditState,
    utils::{DEFAULT_ENVIRONMENT_VARIABLES, ExtractedExpr, extract_expressions},
    yaml_patch::{Op, Patch},
};

pub(crate) struct TemplateInjection;

audit_meta!(
    TemplateInjection,
    "template-injection",
    "code injection via template expansion"
);

static ACTION_INJECTION_SINKS: LazyLock<Vec<(RepositoryUsesPattern, Vec<&str>)>> =
    LazyLock::new(|| {
        let mut sinks: Vec<(RepositoryUsesPattern, Vec<&str>)> = serde_json::from_slice(
            include_bytes!(concat!(env!("OUT_DIR"), "/codeql-injection-sinks.json")),
        )
        .unwrap();

        // These sinks are not tracked by CodeQL (yet)
        sinks.push(("amadevus/pwsh-script".parse().unwrap(), vec!["script"]));
        sinks.push((
            "jannekem/run-python-script-action".parse().unwrap(),
            vec!["script"],
        ));
        sinks.push((
            "cardinalby/js-eval-action".parse().unwrap(),
            vec!["expression"],
        ));
        sinks
    });

static CONTEXT_CAPABILITIES_FST: LazyLock<Map<&[u8]>> = LazyLock::new(|| {
    fst::Map::new(include_bytes!(concat!(env!("OUT_DIR"), "/context-capabilities.fst")).as_slice())
        .expect("couldn't initialize context capabilities FST")
});

impl Capability {
    fn from_context(context: &str) -> Option<Self> {
        match CONTEXT_CAPABILITIES_FST.get(context) {
            Some(0) => Some(Capability::Arbitrary),
            Some(1) => Some(Capability::Structured),
            Some(2) => Some(Capability::Fixed),
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
            .find(|(pattern, _)| pattern.matches(uses))
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
            models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } => TemplateInjection::action_injection_sinks(uses)
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
                                step.location().with_keys(&["with".into(), input.into()]),
                                vec![
                                    // TODO: Plumb the step name/id as a related
                                    // location here and below; this will require us
                                    // to add it to StepCommon.
                                    step.location()
                                        .with_keys(&["uses".into()])
                                        .annotated("action accepts arbitrary code"),
                                    step.location()
                                        .with_keys(&["with".into(), input.into()])
                                        .annotated("via this input")
                                        .key_only(),
                                ],
                            )
                        })
                })
                .collect(),
            models::StepBodyCommon::Run { run, .. } => {
                vec![(
                    run,
                    step.location().with_keys(&["run".into()]),
                    vec![
                        step.location()
                            .with_keys(&["run".into()])
                            .annotated("this run block")
                            .key_only(),
                    ],
                )]
            }
            _ => vec![],
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
        if ctx.child_of("env") {
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

        Some(env_parts.join("_").to_uppercase())
    }

    /// Attempts to produce a `Fix` for a given expression.
    fn attempt_fix<'doc>(
        &self,
        raw: &ExtractedExpr<'doc>,
        parsed: &Expr,
        step: &impl StepCommon<'doc>,
    ) -> Option<Fix<'doc>> {
        // We can only fix `run:` steps for now.
        if !matches!(step.body(), models::StepBodyCommon::Run { .. }) {
            return None;
        }

        // FIXME: We should only produce a fix if we're confident that
        // the `run:` block has bash syntax.

        // If our expression isn't a single context, then we can't fix it yet.
        let Expr::Context(ctx) = parsed else {
            return None;
        };

        // From here, our fix consists of two patch operations:
        // 1. Replacing the expression in the script with an environment
        //    variable of our generation. For example, `${{ foo.bar }}`
        //    becomes `${FOO_BAR}`.
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

        let mut patches = vec![];
        patches.push(Patch {
            route: step.route().with_keys(&["run".into()]),
            operation: Op::RewriteFragment {
                from: raw.as_raw().to_string().into(),
                to: format!("${{{env_var}}}").into(),
                after: None,
            },
        });

        // We only need to add the environment variable if it doesn't
        // match one of the runner's default environment variables.
        if !DEFAULT_ENVIRONMENT_VARIABLES
            .iter()
            .map(|t| t.0)
            .contains(&env_var.as_str())
        {
            patches.push(Patch {
                route: step.route(),
                operation: Op::MergeInto {
                    key: "env".to_string(),
                    value: serde_yaml::to_value(HashMap::from([(env_var.as_str(), raw.as_raw())]))
                        .unwrap(),
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
        let mut bad_expressions = vec![];
        for (expr, expr_span) in extract_expressions(script) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_raw());
                continue;
            };

            // Emit a blanket pedantic finding for the extracted expression
            // since any expression in a code context is a code smell,
            // even if unexploitable.
            bad_expressions.push((
                Subfeature::new(expr_span.start, &parsed),
                // Intentionally not providing a fix here.
                None,
                Severity::Unknown,
                Confidence::Unknown,
                Persona::Pedantic,
            ));

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
                                            (Severity::Unknown, Confidence::Low, Persona::default())
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
                                            Severity::Unknown,
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
                                    if let Some(Strategy { matrix, .. }) = step.strategy() {
                                        let matrix_is_static = match matrix {
                                            // The matrix is generated by an expression, meaning
                                            // that it's trivially not static.
                                            Some(LoE::Expr(_)) => false,
                                            // The matrix may expand to static values according to the context
                                            Some(inner) => models::workflow::Matrix::new(inner)
                                                .expands_to_static_values(context),
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
                                    }
                                    continue;
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
        }

        bad_expressions
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
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

impl Audit for TemplateInjection {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    use crate::audit::Audit;
    use crate::audit::template_injection::{Capability, TemplateInjection};
    use crate::github_api::GitHubHost;
    use crate::models::AsDocument;
    use crate::models::workflow::Workflow;
    use crate::registry::InputKey;
    use crate::state::AuditState;

    /// Macro for testing workflow audits with common boilerplate
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local($filename, None::<&str>).unwrap();
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState {
                config: &Default::default(),
                no_online_audits: false,
                cache_dir: "/tmp/zizmor".into(),
                gh_token: None,
                gh_hostname: GitHubHost::Standard("github.com".into()),
            };
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit.audit_workflow(&workflow).unwrap();

            $test_fn(&workflow, findings)
        }};
    }

    /// Helper function to apply a specific fix by title and return the result for snapshot testing
    fn apply_fix_by_title_for_snapshot(
        document: &yamlpath::Document,
        finding: &crate::finding::Finding,
        expected_title: &str,
    ) -> yamlpath::Document {
        assert!(!finding.fixes.is_empty(), "Expected fixes but got none");

        let fix = finding
            .fixes
            .iter()
            .find(|f| f.title == expected_title)
            .unwrap_or_else(|| {
                panic!("Expected fix with title '{}' but not found", expected_title)
            });

        fix.apply(document).unwrap()
    }

    #[test]
    fn test_template_injection_fix_github_ref_name() {
        let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step
        run: echo "Branch is ${{ github.ref_name }}"
"#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_fix_github_ref_name.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // Should have at least one finding with a fix
                let finding_with_fix = findings.iter().find(|f| !f.fixes.is_empty());
                assert!(
                    finding_with_fix.is_some(),
                    "Expected at least one finding with a fix"
                );

                if let Some(finding) = finding_with_fix {
                    let fixed_content = apply_fix_by_title_for_snapshot(
                        workflow.as_document(),
                        finding,
                        "replace expression with environment variable",
                    );
                    insta::assert_snapshot!(fixed_content.source(), @r#"
                    name: Test Template Injection
                    on: push
                    jobs:
                      test:
                        runs-on: ubuntu-latest
                        steps:
                          - name: Vulnerable step
                            run: echo "Branch is ${GITHUB_REF_NAME}"
                    "#);
                }
            }
        );
    }

    #[test]
    fn test_template_injection_fix_github_actor() {
        let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step
        run: |
          echo "Hello ${{ github.actor }}"
          echo "Processing user input"
"#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_fix_github_actor.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // Should have at least one finding with a fix
                let finding_with_fix = findings.iter().find(|f| !f.fixes.is_empty());
                assert!(
                    finding_with_fix.is_some(),
                    "Expected at least one finding with a fix"
                );

                if let Some(finding) = finding_with_fix {
                    let fixed_content = apply_fix_by_title_for_snapshot(
                        workflow.as_document(),
                        finding,
                        "replace expression with environment variable",
                    );
                    insta::assert_snapshot!(fixed_content.source(), @r#"
                    name: Test Template Injection
                    on: push
                    jobs:
                      test:
                        runs-on: ubuntu-latest
                        steps:
                          - name: Vulnerable step
                            run: |
                              echo "Hello ${GITHUB_ACTOR}"
                              echo "Processing user input"
                    "#);
                }
            }
        );
    }

    #[test]
    fn test_template_injection_fix_with_existing_env() {
        let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step with existing env
        run: echo "Event name is ${{ github.event.head_commit.message }}"
        env:
          EXISTING_VAR: "existing_value"
"#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_fix_with_existing_env.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // Should have at least one finding with a fix
                let finding_with_fix = findings.iter().find(|f| !f.fixes.is_empty());
                assert!(
                    finding_with_fix.is_some(),
                    "Expected at least one finding with a fix"
                );

                if let Some(finding) = finding_with_fix {
                    let fixed_content = apply_fix_by_title_for_snapshot(
                        workflow.as_document(),
                        finding,
                        "replace expression with environment variable",
                    );
                    insta::assert_snapshot!(fixed_content.source(), @r#"
                    name: Test Template Injection
                    on: push
                    jobs:
                      test:
                        runs-on: ubuntu-latest
                        steps:
                          - name: Vulnerable step with existing env
                            run: echo "Event name is ${GITHUB_EVENT_HEAD_COMMIT_MESSAGE}"
                            env:
                              EXISTING_VAR: existing_value
                              GITHUB_EVENT_HEAD_COMMIT_MESSAGE: ${{ github.event.head_commit.message }}
                    "#);
                }
            }
        );
    }

    #[test]
    fn test_template_injection_no_fix_for_action_sinks() {
        let workflow_content = r#"
name: Test Template Injection - Actions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Action with injection sink
        uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.actor }}")
"#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_no_fix_for_action_sinks.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // But should not have fixes for action sinks (only run: steps get fixes)
                let findings_with_fixes: Vec<_> =
                    findings.iter().filter(|f| !f.fixes.is_empty()).collect();
                assert!(
                    findings_with_fixes.is_empty(),
                    "Expected no fixes for action injection sinks"
                );
            }
        );
    }

    #[test]
    fn test_template_injection_fix_multiple_expressions() {
        let workflow_content = r#"
name: Test Multiple Template Injections
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Multiple vulnerable expressions
        # All expressions are replaced and environment variables are created in a single comprehensive fix
        run: |
          echo "User: ${{ github.actor }}"
          echo "Ref: ${{ github.ref_name }}"
          echo "Commit: ${{ github.event.head_commit.message }}"
"#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_multiple_expressions.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find multiple template injections
                assert!(!findings.is_empty());

                // Should have multiple findings
                assert!(
                    findings.len() >= 3,
                    "Expected at least 3 findings for 3 expressions"
                );

                // Our comprehensive fix approach now handles all expressions in a single operation:
                // All expressions in the script are replaced with environment variables,
                // and all corresponding environment variables are defined in the env section.
                let mut current_document = workflow.as_document().clone();
                let findings_with_fixes: Vec<_> =
                    findings.iter().filter(|f| !f.fixes.is_empty()).collect();

                assert!(
                    !findings_with_fixes.is_empty(),
                    "Expected at least one finding with a fix"
                );

                // Apply each fix in sequence
                for finding in findings_with_fixes {
                    if let Some(fix) = finding
                        .fixes
                        .iter()
                        .find(|f| f.title == "replace expression with environment variable")
                    {
                        if let Ok(new_document) = fix.apply(&current_document) {
                            current_document = new_document;
                        }
                    }
                }

                insta::assert_snapshot!(current_document.source(), @r#"
                name: Test Multiple Template Injections
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Multiple vulnerable expressions
                        # All expressions are replaced and environment variables are created in a single comprehensive fix
                        run: |
                          echo "User: ${GITHUB_ACTOR}"
                          echo "Ref: ${GITHUB_REF_NAME}"
                          echo "Commit: ${GITHUB_EVENT_HEAD_COMMIT_MESSAGE}"
                        env:
                          GITHUB_EVENT_HEAD_COMMIT_MESSAGE: ${{ github.event.head_commit.message }}
                "#);
            }
        );
    }

    #[test]
    fn test_template_injection_fix_duplicate_expressions() {
        let workflow_content = r#"
        name: Test Duplicate Template Injections
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Duplicate vulnerable expressions
                run: |
                  echo "User: ${{ github.actor }}"
                  echo "User again: ${{ github.actor }}"
                  echo "Ref: ${{ github.ref_name }}"
        "#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_fix_duplicate_expressions.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // Should have at least one finding with a fix
                let findings_with_fixes: Vec<_> =
                    findings.iter().filter(|f| !f.fixes.is_empty()).collect();
                assert!(
                    !findings_with_fixes.is_empty(),
                    "Expected at least one finding with a fix"
                );

                // Apply each fix in sequence
                let mut current_document = workflow.as_document().clone();
                for finding in findings_with_fixes {
                    if let Some(fix) = finding
                        .fixes
                        .iter()
                        .find(|f| f.title == "replace expression with environment variable")
                    {
                        if let Ok(new_document) = fix.apply(&current_document) {
                            current_document = new_document;
                        }
                    }
                }

                insta::assert_snapshot!(current_document.source(), @r#"
                name: Test Duplicate Template Injections
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Duplicate vulnerable expressions
                        run: |
                          echo "User: ${GITHUB_ACTOR}"
                          echo "User again: ${GITHUB_ACTOR}"
                          echo "Ref: ${GITHUB_REF_NAME}"
                "#);
            }
        );
    }

    #[test]
    fn test_template_injection_fix_equivalent_expressions() {
        let workflow_content = r#"
        name: Test Duplicate Template Injections
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Equivalent vulnerable expressions
                run: |
                  echo "User: ${{ github.actor }}"
                  echo "User: ${{ env.GITHUB_ACTOR }}"
                  echo "User: ${{ env['GITHUB_ACTOR'] }}"
                  echo "User: ${{ env['github_actor'] }}"
        "#;

        test_workflow_audit!(
            TemplateInjection,
            "test_template_injection_fix_equivalent_expressions.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // Should find template injection
                assert!(!findings.is_empty());

                // Should have at least one finding with a fix
                let findings_with_fixes: Vec<_> =
                    findings.iter().filter(|f| !f.fixes.is_empty()).collect();

                // Apply each fix in sequence
                let mut current_document = workflow.as_document().clone();
                for finding in findings_with_fixes {
                    if let Some(fix) = finding
                        .fixes
                        .iter()
                        .find(|f| f.title == "replace expression with environment variable")
                    {
                        if let Ok(new_document) = fix.apply(&current_document) {
                            current_document = new_document;
                        }
                    }
                }

                insta::assert_snapshot!(current_document.source(), @r#"
                name: Test Duplicate Template Injections
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Equivalent vulnerable expressions
                        run: |
                          echo "User: ${GITHUB_ACTOR}"
                          echo "User: ${GITHUB_ACTOR}"
                          echo "User: ${GITHUB_ACTOR}"
                          echo "User: ${GITHUB_ACTOR}"
                "#);
            }
        );
    }

    #[test]
    fn test_capability_from_context() {
        assert!(matches!(
            Capability::from_context("github.event.workflow_run.triggering_actor.login"),
            Some(Capability::Arbitrary)
        ));
        assert!(matches!(
            Capability::from_context(
                "github.event.workflow_run.triggering_actor.organizations_url"
            ),
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
            ("call(foo.bar).baz", None),
            // Computed indices not supported
            ("foo.bar[computed]", None),
            ("foo.bar[abc && def]", None),
            // env contexts should have the env prefix removed
            ("env.FOO_BAR", Some("FOO_BAR")),
            ("env.foo_bar", Some("FOO_BAR")),
            ("ENV.foo_bar", Some("FOO_BAR")),
            ("ENV['foo_bar']", Some("FOO_BAR")),
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
