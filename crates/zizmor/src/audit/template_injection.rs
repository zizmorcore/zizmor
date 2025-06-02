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

use std::{env, sync::LazyLock};

use fst::Map;
use github_actions_expressions::{Expr, context::Context};
use github_actions_models::{
    common::{
        RepositoryUses, Uses,
        expr::{ExplicitExpr, LoE},
    },
    workflow::job::Strategy,
};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Routable as _, SymbolicLocation},
    },
    models::{self, CompositeStep, Step, StepCommon, uses::RepositoryUsesPattern},
    state::AuditState,
    utils::extract_expressions,
    yaml_patch::{self, YamlPatchOperation},
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

enum Capability {
    Arbitrary,
    Structured,
    Fixed,
}

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

    fn scripts_with_location<'a, 'doc>(
        step: &'a impl StepCommon<'a, 'doc>,
    ) -> Vec<(String, SymbolicLocation<'doc>)> {
        match step.body() {
            models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } => TemplateInjection::action_injection_sinks(uses)
                .iter()
                .filter_map(|input| {
                    let input = *input;
                    with.get(input).map(|script| {
                        (
                            script.to_string(),
                            step.location().with_keys(&["with".into(), input.into()]),
                        )
                    })
                })
                .collect(),
            models::StepBodyCommon::Run { run, .. } => {
                vec![(run.to_string(), step.location().with_keys(&["run".into()]))]
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

        // TODO: Pop off `matrix` and `secrets` heads, since these don't
        // add any extra information to the variable name.

        for part in &ctx.parts {
            match part {
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
                    match idx.as_ref() {
                        // FIXME: Annoying soundness hole here: index-style
                        // literal keys can be anything, not just valid identifiers.
                        // The right thing to do here is to parse these literals
                        // and refuse to convert them if we can't make them
                        // into valid identifiers.
                        Expr::String(lit) => env_parts.push(lit.replace('-', "_")),
                        Expr::Number(idx) => {
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
    fn attempt_fix<'a, 'doc>(
        &self,
        script: &str,
        raw: &ExplicitExpr,
        parsed: &Expr,
        step: &'a impl StepCommon<'a, 'doc>,
    ) -> Option<Fix> {
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

        // NOTE: We only replace the first occurrence of the raw expression,
        // since each fix corresponds to exactly one expression.
        // This implicitly assumes that we perform fixes in the order
        // of findings, which is currently but not inherently the case.
        // The cleaner thing to do here would probably be to replace the
        // expression's exact span, but that would invalidate the
        // next fix's span. Needs more thought.
        let new_script = script.replacen(raw.as_raw(), &format!("${{{env_var}}}"), 1);

        Some(Fix {
            title: "replace expression with environment variable".into(),
            description: "todo".into(),
            apply: Box::new(move |content: &str| -> anyhow::Result<Option<String>> {
                let mut ops = vec![];

                ops.push(YamlPatchOperation::Replace {
                    route: step.route().with_keys(&["run".into()]),
                    value: serde_yaml::Value::String(new_script),
                });

                // ops.push(YamlPatchOperation::MergeInto { route: (), key: (), value: () })

                match yaml_patch::apply_yaml_patch(content, vec![]) {
                    Ok(new_content) => Ok(Some(new_content)),
                    Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
                }
            }),
        })
    }

    fn injectable_template_expressions<'a, 'doc>(
        &self,
        script: &str,
        step: &impl StepCommon<'a, 'doc>,
    ) -> Vec<(String, Option<Fix>, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        for (expr, _) in extract_expressions(script) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            // Emit a blanket pedantic finding for the extracted expression
            // since any expression in a code context is a code smell,
            // even if unexploitable.
            bad_expressions.push((
                expr.as_curly().into(),
                // Intentionally not providing a fix here,
                None,
                Severity::Unknown,
                Confidence::Unknown,
                Persona::Pedantic,
            ));

            for context in parsed.dataflow_contexts() {
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
                                    context.as_str().into(),
                                    self.attempt_fix(script, &expr, &parsed, step),
                                    Severity::Medium,
                                    Confidence::High,
                                    Persona::default(),
                                ));
                            }
                            // Arbitrary means the context's expansion is
                            // fully attacker-controllable.
                            Some(Capability::Arbitrary) => {
                                bad_expressions.push((
                                    context.as_str().into(),
                                    self.attempt_fix(script, &expr, &parsed, step),
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
                                    // TODO: Currently low confidence because we don't check the
                                    // input's type. In the future, we should index back into
                                    // the workflow's triggers and exclude input expansions
                                    // from innocuous types, e.g. booleans.
                                    bad_expressions.push((
                                        context.as_str().into(),
                                        self.attempt_fix(script, &expr, &parsed, step),
                                        Severity::High,
                                        Confidence::Low,
                                        Persona::default(),
                                    ));
                                } else if let Some(env) = context.pop_if("env") {
                                    let env_is_static = step.env_is_static(env);

                                    if !env_is_static {
                                        bad_expressions.push((
                                            context.as_str().into(),
                                            self.attempt_fix(script, &expr, &parsed, step),
                                            Severity::Low,
                                            Confidence::High,
                                            Persona::default(),
                                        ));
                                    }
                                } else if context.child_of("github") {
                                    // TODO: Filter these more finely; not everything in the event
                                    // context is actually attacker-controllable.
                                    bad_expressions.push((
                                        context.as_str().into(),
                                        self.attempt_fix(script, &expr, &parsed, step),
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
                                            Some(inner) => models::Matrix::new(inner)
                                                .expands_to_static_values(context.as_str()),
                                            // Context specifies a matrix, but there is no matrix defined.
                                            // This is an invalid workflow so there's no point in flagging it.
                                            None => continue,
                                        };

                                        if !matrix_is_static {
                                            bad_expressions.push((
                                                context.as_str().into(),
                                                self.attempt_fix(script, &expr, &parsed, step),
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
                                        context.as_str().into(),
                                        self.attempt_fix(script, &expr, &parsed, step),
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
                            context.as_str().into(),
                            self.attempt_fix(script, &expr, &parsed, step),
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

    /// Check if an expression contains functions that should only get suggestions, not automatic fixes
    fn expression_contains_suggestion_only_functions(expr: &str) -> bool {
        let cleaned_expr = expr.trim();
        cleaned_expr.starts_with("fromJSON(")
            || cleaned_expr.starts_with("toJSON(")
            || cleaned_expr.starts_with("contains(")
            || cleaned_expr.starts_with("startsWith(")
            || cleaned_expr.starts_with("endsWith(")
            || cleaned_expr.starts_with("format(")
            || cleaned_expr.starts_with("join(")
            || cleaned_expr.starts_with("hashFiles(")
            || cleaned_expr.starts_with("secrets.")
    }

    // /// Create a fix that moves multiple template expressions to environment variables
    // fn create_env_var_fix(
    //     expressions: &[String],
    //     job_id: &str,
    //     step_index: usize,
    //     script: &str,
    // ) -> Fix {
    //     Fix {
    //         title: "Move template expressions to environment variables".to_string(),
    //         description: format!(
    //             "Move template expressions ({}) to environment variables to prevent code injection. \
    //             Template expansions aren't syntax-aware, meaning that they can result in unintended shell injection vectors. \
    //             This is especially true when they're used with attacker-controllable expression contexts. \
    //             \n\nInstead of using expressions like '${{{{ github.event.issue.title }}}}' directly in the script, \
    //             add them to the 'env:' block and reference them as shell variables like '${{ISSUE_TITLE}}'. \
    //             This avoids the vulnerability, since variable expansion is subject to normal shell quoting/expansion rules.",
    //             expressions.join(", ")
    //         ),
    //         apply: Box::new({
    //             let expressions = expressions.to_vec();
    //             let job_id = job_id.to_string();
    //             let script = script.to_string();
    //             move |content: &str| -> anyhow::Result<Option<String>> {
    //                 let mut operations = Vec::new();
    //                 let mut new_script = script.clone();
    //                 let mut env_vars = serde_yaml::Mapping::new();

    //                 // Process each expression
    //                 for expression in &expressions {
    //                     // Check if the expression already includes ${{ }} wrapper
    //                     let (clean_expr, full_expr) = if expression.trim().starts_with("${{")
    //                         && expression.trim().ends_with("}}")
    //                     {
    //                         // Expression already has wrapper, extract the bare content
    //                         let clean = expression
    //                             .trim()
    //                             .strip_prefix("${{")
    //                             .unwrap()
    //                             .strip_suffix("}}")
    //                             .unwrap()
    //                             .trim();
    //                         (clean, expression.trim().to_string())
    //                     } else {
    //                         // Expression doesn't have wrapper, add it
    //                         let clean = expression.trim();
    //                         (clean, format!("${{{{ {} }}}}", clean))
    //                     };

    //                     // Generate a safe environment variable name
    //                     let env_var_name = Self::generate_env_var_name(clean_expr);

    //                     // Replace the expression in the script with the environment variable
    //                     new_script =
    //                         new_script.replace(&full_expr, &format!("${{{}}}", env_var_name));

    //                     // Add to environment variables
    //                     env_vars.insert(
    //                         serde_yaml::Value::String(env_var_name),
    //                         serde_yaml::Value::String(format!("${{{{ {} }}}}", clean_expr)),
    //                     );
    //                 }

    //                 // Update the run script
    //                 operations.push(YamlPatchOperation::Replace {
    //                     route: format!("/jobs/{}/steps/{}/run", job_id, step_index),
    //                     value: serde_yaml::Value::String(new_script),
    //                 });

    //                 // Add all environment variables at once
    //                 operations.push(YamlPatchOperation::MergeInto {
    //                     route: format!("/jobs/{}/steps/{}", job_id, step_index),
    //                     key: "env".to_string(),
    //                     value: serde_yaml::Value::Mapping(env_vars),
    //                 });

    //                 match crate::yaml_patch::apply_yaml_patch(content, operations) {
    //                     Ok(new_content) => Ok(Some(new_content)),
    //                     Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
    //                 }
    //             }
    //         }),
    //     }
    // }

    // /// Create a fix that moves multiple template expressions to environment variables for composite actions
    // fn create_composite_env_var_fix(
    //     expressions: &[String],
    //     step_index: usize,
    //     script: &str,
    // ) -> Fix {
    //     Fix {
    //         title: "Move template expressions to environment variables".to_string(),
    //         description: format!(
    //             "Move template expressions ({}) to environment variables to prevent code injection. \
    //             Template expansions aren't syntax-aware, meaning that they can result in unintended shell injection vectors. \
    //             This is especially true when they're used with attacker-controllable expression contexts. \
    //             \n\nInstead of using expressions like '${{{{ github.event.issue.title }}}}' directly in the script, \
    //             add them to the 'env:' block and reference them as shell variables like '${{ISSUE_TITLE}}'. \
    //             This avoids the vulnerability, since variable expansion is subject to normal shell quoting/expansion rules.",
    //             expressions.join(", ")
    //         ),
    //         apply: Box::new({
    //             let expressions = expressions.to_vec();
    //             let script = script.to_string();
    //             move |content: &str| -> anyhow::Result<Option<String>> {
    //                 let mut operations = Vec::new();
    //                 let mut new_script = script.clone();
    //                 let mut env_vars = serde_yaml::Mapping::new();

    //                 // Process each expression
    //                 for expression in &expressions {
    //                     // Check if the expression already includes ${{ }} wrapper
    //                     let (clean_expr, full_expr) = if expression.trim().starts_with("${{")
    //                         && expression.trim().ends_with("}}")
    //                     {
    //                         // Expression already has wrapper, extract the bare content
    //                         let clean = expression
    //                             .trim()
    //                             .strip_prefix("${{")
    //                             .unwrap()
    //                             .strip_suffix("}}")
    //                             .unwrap()
    //                             .trim();
    //                         (clean, expression.trim().to_string())
    //                     } else {
    //                         // Expression doesn't have wrapper, add it
    //                         let clean = expression.trim();
    //                         (clean, format!("${{{{ {} }}}}", clean))
    //                     };

    //                     // Generate a safe environment variable name
    //                     let env_var_name = Self::generate_env_var_name(clean_expr);

    //                     // Replace the expression in the script with the environment variable
    //                     new_script =
    //                         new_script.replace(&full_expr, &format!("${{{}}}", env_var_name));

    //                     // Add to environment variables
    //                     env_vars.insert(
    //                         serde_yaml::Value::String(env_var_name),
    //                         serde_yaml::Value::String(format!("${{{{ {} }}}}", clean_expr)),
    //                     );
    //                 }

    //                 // Update the run script
    //                 operations.push(YamlPatchOperation::Replace {
    //                     route: format!("/runs/steps/{}/run", step_index),
    //                     value: serde_yaml::Value::String(new_script),
    //                 });

    //                 // Add all environment variables at once
    //                 operations.push(YamlPatchOperation::MergeInto {
    //                     route: format!("/runs/steps/{}", step_index),
    //                     key: "env".to_string(),
    //                     value: serde_yaml::Value::Mapping(env_vars),
    //                 });

    //                 match crate::yaml_patch::apply_yaml_patch(content, operations) {
    //                     Ok(new_content) => Ok(Some(new_content)),
    //                     Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
    //                 }
    //             }
    //         }),
    //     }
    // }

    /// Generate a safe environment variable name from an expression
    fn generate_env_var_name(expr: &str) -> String {
        // Convert expressions like "github.event.issue.title" to "GITHUB_EVENT_ISSUE_TITLE"

        match expr.trim() {
            expr if Self::expression_contains_suggestion_only_functions(expr) => expr.to_string(),
            // Replace all special characters with underscores to
            // ensure valid environment variable names
            _ => expr
                .to_string()
                .trim()
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect(),
        }
    }

    fn process_step<'a, 'doc>(
        &self,
        step: &'a impl StepCommon<'a, 'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        for (script, script_loc) in Self::scripts_with_location(step) {
            for (context, fix, severity, confidence, persona) in
                self.injectable_template_expressions(&script, step)
            {
                let mut finding_builder = Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(step.location().hidden())
                    .add_location(step.location_with_name())
                    .add_location(script_loc.clone().primary().annotated(format!(
                        "{context} may expand into attacker-controllable code"
                    )));

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
        // let findings_with_expressions = self.process_step(step)?;

        // // Group findings by script to create comprehensive fixes
        // let mut script_to_expressions: std::collections::HashMap<
        //     String,
        //     Vec<(Finding<'doc>, String)>,
        // > = std::collections::HashMap::new();

        // // Separate expressions into those that get fixes vs suggestions only
        // let mut script_to_suggestion_only: std::collections::HashMap<
        //     String,
        //     Vec<(Finding<'doc>, String)>,
        // > = std::collections::HashMap::new();

        // for (finding, full_expr, script) in findings_with_expressions {
        //     // Check if this expression contains functions that should only get suggestions
        //     if Self::expression_contains_suggestion_only_functions(&full_expr) {
        //         script_to_suggestion_only
        //             .entry(script)
        //             .or_default()
        //             .push((finding, full_expr));
        //     } else {
        //         script_to_expressions
        //             .entry(script)
        //             .or_default()
        //             .push((finding, full_expr));
        //     }
        // }

        // let mut all_findings = Vec::new();

        // // Handle expressions that get automatic fixes
        // for (script, findings_and_expressions) in script_to_expressions {
        //     // Extract all expressions for this script
        //     let expressions: Vec<String> = findings_and_expressions
        //         .iter()
        //         .map(|(_, expr)| expr.clone())
        //         .collect();

        //     // Add the fixes to each finding for this script
        //     for (mut finding, _) in findings_and_expressions {
        //         finding.fixes.push(Self::create_env_var_fix(
        //             &expressions,
        //             step.job().id(),
        //             step.index,
        //             &script,
        //         ));
        //         all_findings.push(finding);
        //     }
        // }

        // // Handle expressions that only get suggestions (no automatic fixes)
        // for (_, findings_and_expressions) in script_to_suggestion_only {
        //     for (finding, _) in findings_and_expressions {
        //         // Don't add any automatic fixes for these expressions
        //         // The finding itself serves as the suggestion
        //         all_findings.push(finding);
        //     }
        // }

        // Ok(all_findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
        // let findings_with_expressions = self.process_step(step)?;

        // // Group findings by script to create comprehensive fixes
        // let mut script_to_expressions: std::collections::HashMap<
        //     String,
        //     Vec<(Finding<'a>, String)>,
        // > = std::collections::HashMap::new();

        // // Separate expressions into those that get fixes vs suggestions only
        // let mut script_to_suggestion_only: std::collections::HashMap<
        //     String,
        //     Vec<(Finding<'a>, String)>,
        // > = std::collections::HashMap::new();

        // for (finding, full_expr, script) in findings_with_expressions {
        //     // Check if this expression contains functions that should only get suggestions
        //     if Self::expression_contains_suggestion_only_functions(&full_expr) {
        //         script_to_suggestion_only
        //             .entry(script)
        //             .or_default()
        //             .push((finding, full_expr));
        //     } else {
        //         script_to_expressions
        //             .entry(script)
        //             .or_default()
        //             .push((finding, full_expr));
        //     }
        // }

        // let mut all_findings = Vec::new();

        // // Handle expressions that get automatic fixes
        // for (script, findings_and_expressions) in script_to_expressions {
        //     // Extract all expressions for this script
        //     let expressions: Vec<String> = findings_and_expressions
        //         .iter()
        //         .map(|(_, expr)| expr.clone())
        //         .collect();

        //     // Add the fixes to each finding for this script
        //     for (mut finding, _) in findings_and_expressions {
        //         finding.fixes.push(Self::create_composite_env_var_fix(
        //             &expressions,
        //             step.index,
        //             &script,
        //         ));
        //         all_findings.push(finding);
        //     }
        // }

        // // Handle expressions that only get suggestions (no automatic fixes)
        // for (_, findings_and_expressions) in script_to_suggestion_only {
        //     for (finding, _) in findings_and_expressions {
        //         // Don't add any automatic fixes for these expressions
        //         // The finding itself serves as the suggestion
        //         all_findings.push(finding);
        //     }
        // }

        // Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::{Expr, context::Context};

    use crate::audit::template_injection::{Capability, TemplateInjection};

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
            // FIXME: soundness hole
            (
                "foo.bar['oops all spaces']",
                Some("FOO_BAR_OOPS ALL SPACES"),
            ),
        ] {
            let expr = Expr::parse(ctx).unwrap();
            let Expr::Context(ctx) = expr else {
                panic!("Expected context expression, got: {expr:?}");
            };

            assert_eq!(
                TemplateInjection::context_to_env_var(&ctx).as_deref(),
                expected
            );
        }
    }

    #[test]
    fn test_generate_env_var_name() {
        use super::TemplateInjection;

        // Test basic cases
        assert_eq!(
            TemplateInjection::generate_env_var_name("github.event.issue.title"),
            "GITHUB_EVENT_ISSUE_TITLE"
        );

        // Test direct secrets references (should NOT strip secrets. prefix)
        assert_eq!(
            TemplateInjection::generate_env_var_name("secrets.api-config"),
            "secrets.api-config"
        );

        // Test fromJSON(secrets.*) patterns (should stay the same)
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.config)"),
            "fromJSON(secrets.config)"
        );

        // Test fromJSON(secrets.*) with property access
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.database-config).username"),
            "fromJSON(secrets.database-config).username"
        );

        // Test fromJSON(secrets.*) with special characters
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.api-config)"),
            "fromJSON(secrets.api-config)"
        );

        // Test fromJSON(secrets.*) with complex names and property access
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.database_config).password"),
            "fromJSON(secrets.database_config).password"
        );

        // Test fromJSON with non-secrets content
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(github.event.config)"),
            "fromJSON(github.event.config)"
        );

        // Test with mixed special characters
        assert_eq!(
            TemplateInjection::generate_env_var_name("github.event@issue.title"),
            "GITHUB_EVENT_ISSUE_TITLE"
        );

        // Test with spaces and other special characters (unlikely case)
        assert_eq!(
            TemplateInjection::generate_env_var_name("my var.name-test@prod"),
            "MY_VAR_NAME_TEST_PROD"
        );

        // Test with numbers (should be preserved)
        assert_eq!(
            TemplateInjection::generate_env_var_name("config.v2.test"),
            "CONFIG_V2_TEST"
        );
    }

    // #[test]
    // fn test_fixes_are_added_to_findings() {
    //     use super::TemplateInjection;

    //     let env_var_fix = TemplateInjection::create_env_var_fix(
    //         &["${{ github.event.issue.title }}".to_string()],
    //         "test-job",
    //         0,
    //         "echo \"${{ github.event.issue.title }}\"",
    //     );

    //     assert_eq!(
    //         env_var_fix.title,
    //         "Move template expressions to environment variables"
    //     );
    //     assert!(env_var_fix.description.contains("github.event.issue.title"));
    //     assert!(env_var_fix.description.contains("env:"));
    // }

    // #[test]
    // fn test_fix_descriptions_match_audits_md_guidelines() {
    //     use super::TemplateInjection;

    //     let env_var_fix = TemplateInjection::create_env_var_fix(
    //         &["${{ github.event.issue.title }}".to_string()],
    //         "test-job",
    //         0,
    //         "echo \"${{ github.event.issue.title }}\"",
    //     );

    //     // Verify the description contains key phrases from audits.md
    //     assert!(
    //         env_var_fix
    //             .description
    //             .contains("Template expansions aren't syntax-aware")
    //     );
    //     assert!(env_var_fix.description.contains("shell injection vectors"));
    //     assert!(
    //         env_var_fix
    //             .description
    //             .contains("attacker-controllable expression contexts")
    //     );
    //     assert!(
    //         env_var_fix
    //             .description
    //             .contains("variable expansion is subject to normal shell quoting/expansion rules")
    //     );
    // }

    #[test]
    fn test_suggestion_only_functions_no_fixes() {
        use super::TemplateInjection;

        // Test that expressions with fromJSON, toJSON, etc. are detected correctly
        assert!(
            TemplateInjection::expression_contains_suggestion_only_functions(
                "fromJSON(secrets.config)"
            )
        );
        assert!(
            TemplateInjection::expression_contains_suggestion_only_functions(
                "toJSON(github.event)"
            )
        );
        assert!(
            TemplateInjection::expression_contains_suggestion_only_functions(
                "contains(github.ref, 'main')"
            )
        );
        assert!(
            TemplateInjection::expression_contains_suggestion_only_functions("secrets.API_KEY")
        );
        assert!(
            TemplateInjection::expression_contains_suggestion_only_functions(
                "hashFiles('**/*.lock')"
            )
        );

        // Test that regular expressions are not detected as suggestion-only
        assert!(
            !TemplateInjection::expression_contains_suggestion_only_functions(
                "github.event.issue.title"
            )
        );
        assert!(
            !TemplateInjection::expression_contains_suggestion_only_functions(
                "matrix.node-version"
            )
        );
        assert!(
            !TemplateInjection::expression_contains_suggestion_only_functions(
                "inputs.deployment-target"
            )
        );
    }
}
