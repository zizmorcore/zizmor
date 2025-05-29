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

use std::sync::LazyLock;

use fst::Map;
use github_actions_expressions::Expr;
use github_actions_models::{
    common::{RepositoryUses, Uses, expr::LoE},
    workflow::job::Strategy,
};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Persona, Severity, SymbolicLocation},
    models::{self, CompositeStep, JobExt as _, Step, StepCommon, uses::RepositoryUsesPattern},
    state::AuditState,
    utils::extract_expressions,
    yaml_patch::YamlPatchOperation,
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

    fn scripts_with_location<'s>(
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, SymbolicLocation<'s>)> {
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

    fn injectable_template_expressions<'s>(
        &self,
        run: &str,
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, String, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        for (expr, _) in extract_expressions(run) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            // Emit a blanket pedantic finding for the extracted expression
            // since any expression in a code context is a code smell,
            // even if unexploitable.
            bad_expressions.push((
                expr.as_curly().into(),
                expr.as_raw().into(),
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
                                    expr.as_curly().into(),
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
                                    expr.as_curly().into(),
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
                                        expr.as_curly().into(),
                                        Severity::High,
                                        Confidence::Low,
                                        Persona::default(),
                                    ));
                                } else if let Some(env) = context.pop_if("env") {
                                    let env_is_static = step.env_is_static(env);

                                    if !env_is_static {
                                        bad_expressions.push((
                                            context.as_str().into(),
                                            expr.as_curly().into(),
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
                                        expr.as_curly().into(),
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
                                                expr.as_curly().into(),
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
                                        expr.as_curly().into(),
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
                            expr.as_curly().into(),
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

    /// Create a fix that moves multiple template expressions to environment variables
    fn create_env_var_fix(
        expressions: &[String],
        job_id: &str,
        step_index: usize,
        script: &str,
    ) -> Fix {
        Fix {
            title: "Move template expressions to environment variables".to_string(),
            description: format!(
                "Move template expressions ({}) to environment variables to prevent code injection. \
                Template expansions aren't syntax-aware, meaning that they can result in unintended shell injection vectors. \
                This is especially true when they're used with attacker-controllable expression contexts. \
                \n\nInstead of using expressions like '${{{{ github.event.issue.title }}}}' directly in the script, \
                add them to the 'env:' block and reference them as shell variables like '${{ISSUE_TITLE}}'. \
                This avoids the vulnerability, since variable expansion is subject to normal shell quoting/expansion rules.",
                expressions.join(", ")
            ),
            apply: Box::new({
                let expressions = expressions.to_vec();
                let job_id = job_id.to_string();
                let script = script.to_string();
                move |content: &str| -> anyhow::Result<Option<String>> {
                    let mut operations = Vec::new();
                    let mut new_script = script.clone();
                    let mut env_vars = serde_yaml::Mapping::new();

                    // Process each expression
                    for expression in &expressions {
                        // Check if the expression already includes ${{ }} wrapper
                        let (clean_expr, full_expr) = if expression.trim().starts_with("${{")
                            && expression.trim().ends_with("}}")
                        {
                            // Expression already has wrapper, extract the bare content
                            let clean = expression
                                .trim()
                                .strip_prefix("${{")
                                .unwrap()
                                .strip_suffix("}}")
                                .unwrap()
                                .trim();
                            (clean, expression.trim().to_string())
                        } else {
                            // Expression doesn't have wrapper, add it
                            let clean = expression.trim();
                            (clean, format!("${{{{ {} }}}}", clean))
                        };

                        // Generate a safe environment variable name
                        let env_var_name = Self::generate_env_var_name(clean_expr);

                        // Replace the expression in the script with the environment variable
                        new_script =
                            new_script.replace(&full_expr, &format!("${{{}}}", env_var_name));

                        // Add to environment variables
                        env_vars.insert(
                            serde_yaml::Value::String(env_var_name),
                            serde_yaml::Value::String(format!("${{{{ {} }}}}", clean_expr)),
                        );
                    }

                    // Update the run script
                    operations.push(YamlPatchOperation::Replace {
                        path: format!("/jobs/{}/steps/{}/run", job_id, step_index),
                        value: serde_yaml::Value::String(new_script),
                    });

                    // Add all environment variables at once
                    operations.push(YamlPatchOperation::MergeInto {
                        path: format!("/jobs/{}/steps/{}", job_id, step_index),
                        key: "env".to_string(),
                        value: serde_yaml::Value::Mapping(env_vars),
                    });

                    match crate::yaml_patch::apply_yaml_patch(content, operations) {
                        Ok(new_content) => Ok(Some(new_content)),
                        Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
                    }
                }
            }),
        }
    }

    /// Create a fix that moves multiple template expressions to environment variables for composite actions
    fn create_composite_env_var_fix(
        expressions: &[String],
        step_index: usize,
        script: &str,
    ) -> Fix {
        Fix {
            title: "Move template expressions to environment variables".to_string(),
            description: format!(
                "Move template expressions ({}) to environment variables to prevent code injection. \
                Template expansions aren't syntax-aware, meaning that they can result in unintended shell injection vectors. \
                This is especially true when they're used with attacker-controllable expression contexts. \
                \n\nInstead of using expressions like '${{{{ github.event.issue.title }}}}' directly in the script, \
                add them to the 'env:' block and reference them as shell variables like '${{ISSUE_TITLE}}'. \
                This avoids the vulnerability, since variable expansion is subject to normal shell quoting/expansion rules.",
                expressions.join(", ")
            ),
            apply: Box::new({
                let expressions = expressions.to_vec();
                let script = script.to_string();
                move |content: &str| -> anyhow::Result<Option<String>> {
                    let mut operations = Vec::new();
                    let mut new_script = script.clone();
                    let mut env_vars = serde_yaml::Mapping::new();

                    // Process each expression
                    for expression in &expressions {
                        // Check if the expression already includes ${{ }} wrapper
                        let (clean_expr, full_expr) = if expression.trim().starts_with("${{")
                            && expression.trim().ends_with("}}")
                        {
                            // Expression already has wrapper, extract the bare content
                            let clean = expression
                                .trim()
                                .strip_prefix("${{")
                                .unwrap()
                                .strip_suffix("}}")
                                .unwrap()
                                .trim();
                            (clean, expression.trim().to_string())
                        } else {
                            // Expression doesn't have wrapper, add it
                            let clean = expression.trim();
                            (clean, format!("${{{{ {} }}}}", clean))
                        };

                        // Generate a safe environment variable name
                        let env_var_name = Self::generate_env_var_name(clean_expr);

                        // Replace the expression in the script with the environment variable
                        new_script =
                            new_script.replace(&full_expr, &format!("${{{}}}", env_var_name));

                        // Add to environment variables
                        env_vars.insert(
                            serde_yaml::Value::String(env_var_name),
                            serde_yaml::Value::String(format!("${{{{ {} }}}}", clean_expr)),
                        );
                    }

                    // Update the run script
                    operations.push(YamlPatchOperation::Replace {
                        path: format!("/runs/steps/{}/run", step_index),
                        value: serde_yaml::Value::String(new_script),
                    });

                    // Add all environment variables at once
                    operations.push(YamlPatchOperation::MergeInto {
                        path: format!("/runs/steps/{}", step_index),
                        key: "env".to_string(),
                        value: serde_yaml::Value::Mapping(env_vars),
                    });

                    match crate::yaml_patch::apply_yaml_patch(content, operations) {
                        Ok(new_content) => Ok(Some(new_content)),
                        Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
                    }
                }
            }),
        }
    }

    /// Generate a safe environment variable name from an expression
    fn generate_env_var_name(expr: &str) -> String {
        // Convert expressions like "github.event.issue.title" to "GITHUB_EVENT_ISSUE_TITLE"
        // For fromJSON(secrets.foo).bar patterns, extract meaningful parts

        let cleaned_expr = if expr.trim().starts_with("fromJSON(secrets.") {
            // Handle patterns like "fromJSON(secrets.config).username"
            // Extract the secret name and any property access
            if let Some(closing_paren) = expr.find(')') {
                let secrets_part = &expr[17..closing_paren]; // Skip "fromJSON(secrets."
                let property_part = &expr[closing_paren + 1..]; // Everything after ")"

                // Combine secret name with property access
                if property_part.starts_with('.') {
                    format!("{}_{}", secrets_part, &property_part[1..]) // Remove the leading dot
                } else if property_part.is_empty() {
                    secrets_part.to_string()
                } else {
                    format!("{}_{}", secrets_part, property_part)
                }
            } else {
                // Malformed expression, fall back to original
                expr.to_string()
            }
        } else if expr.trim().starts_with("fromJSON(") && expr.trim().contains(')') {
            // Handle other fromJSON patterns like "fromJSON(github.event.config).field"
            if let Some(closing_paren) = expr.find(')') {
                let inner_part = &expr[9..closing_paren]; // Skip "fromJSON("
                let property_part = &expr[closing_paren + 1..]; // Everything after ")"

                if property_part.starts_with('.') {
                    format!("{}_{}", inner_part, &property_part[1..]) // Remove the leading dot
                } else if property_part.is_empty() {
                    inner_part.to_string()
                } else {
                    format!("{}_{}", inner_part, property_part)
                }
            } else {
                // Malformed expression, fall back to original
                expr.to_string()
            }
        } else if expr.starts_with("secrets.") {
            // For direct secrets references, extract just the secret name
            expr.strip_prefix("secrets.").unwrap_or(expr).to_string()
        } else {
            // For other expressions, use as-is
            expr.to_string()
        };

        // Replace all special characters with underscores to ensure valid environment variable names
        cleaned_expr
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    /// Create a fix that adds explicit shell specification for workflow steps
    fn create_shell_specification_fix(job_id: &str, step_index: usize) -> Fix {
        Fix {
            title: "Add explicit shell specification".to_string(),
            description: "Add 'shell: bash' to ensure consistent variable expansion syntax across different runners. \
                When switching to '${VARNAME}', keep in mind that different shells have different environment variable syntaxes. \
                In particular, PowerShell (the default shell on Windows runners) uses '${env:VARNAME}'. \
                To avoid having to specialize your handling for different runners, you can set 'shell: bash'.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::MergeInto {
                path: format!("/jobs/{}/steps/{}", job_id, step_index),
                key: "shell".to_string(),
                value: serde_yaml::Value::String("bash".to_string()),
            }]),
        }
    }

    /// Create a fix that adds explicit shell specification for composite steps
    fn create_composite_shell_specification_fix(step_index: usize) -> Fix {
        Fix {
            title: "Add explicit shell specification".to_string(),
            description: "Add 'shell: bash' to ensure consistent variable expansion syntax across different runners. \
                When switching to '${VARNAME}', keep in mind that different shells have different environment variable syntaxes. \
                In particular, PowerShell (the default shell on Windows runners) uses '${env:VARNAME}'. \
                To avoid having to specialize your handling for different runners, you can set 'shell: bash'.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::MergeInto {
                path: format!("/runs/steps/{}", step_index),
                key: "shell".to_string(),
                value: serde_yaml::Value::String("bash".to_string()),
            }]),
        }
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<(Finding<'doc>, String, String)>> {
        let mut findings_with_expressions = vec![];

        for (script, script_loc) in Self::scripts_with_location(step) {
            for (context, full_expr, severity, confidence, persona) in
                self.injectable_template_expressions(&script, step)
            {
                let finding_builder = Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(step.location().hidden())
                    .add_location(step.location_with_name())
                    .add_location(script_loc.clone().primary().annotated(format!(
                        "{context} may expand into attacker-controllable code"
                    )));

                let finding = finding_builder.build(step)?;
                findings_with_expressions.push((finding, full_expr, script.clone()));
            }
        }

        Ok(findings_with_expressions)
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
        let findings_with_expressions = self.process_step(step)?;

        // Group findings by script to create comprehensive fixes
        let mut script_to_expressions: std::collections::HashMap<
            String,
            Vec<(Finding<'doc>, String)>,
        > = std::collections::HashMap::new();

        for (finding, full_expr, script) in findings_with_expressions {
            script_to_expressions
                .entry(script)
                .or_default()
                .push((finding, full_expr));
        }

        let mut all_findings = Vec::new();

        for (script, findings_and_expressions) in script_to_expressions {
            // Extract all expressions for this script
            let expressions: Vec<String> = findings_and_expressions
                .iter()
                .map(|(_, expr)| expr.clone())
                .collect();

            // Add the fixes to each finding for this script
            for (mut finding, _) in findings_and_expressions {
                finding.fixes.push(Self::create_env_var_fix(
                    &expressions,
                    step.job().id(),
                    step.index,
                    &script,
                ));
                finding.fixes.push(Self::create_shell_specification_fix(
                    step.job().id(),
                    step.index,
                ));
                all_findings.push(finding);
            }
        }

        Ok(all_findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let findings_with_expressions = self.process_step(step)?;

        // Group findings by script to create comprehensive fixes
        let mut script_to_expressions: std::collections::HashMap<
            String,
            Vec<(Finding<'a>, String)>,
        > = std::collections::HashMap::new();

        for (finding, full_expr, script) in findings_with_expressions {
            script_to_expressions
                .entry(script)
                .or_default()
                .push((finding, full_expr));
        }

        let mut all_findings = Vec::new();

        for (script, findings_and_expressions) in script_to_expressions {
            // Extract all expressions for this script
            let expressions: Vec<String> = findings_and_expressions
                .iter()
                .map(|(_, expr)| expr.clone())
                .collect();

            // Add the fixes to each finding for this script
            for (mut finding, _) in findings_and_expressions {
                finding.fixes.push(Self::create_composite_env_var_fix(
                    &expressions,
                    step.index,
                    &script,
                ));
                finding
                    .fixes
                    .push(Self::create_composite_shell_specification_fix(step.index));
                all_findings.push(finding);
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::template_injection::Capability;

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
    fn test_generate_env_var_name() {
        use super::TemplateInjection;

        // Test basic cases
        assert_eq!(
            TemplateInjection::generate_env_var_name("github.event.issue.title"),
            "GITHUB_EVENT_ISSUE_TITLE"
        );

        // Test direct secrets references (should strip secrets. prefix)
        assert_eq!(
            TemplateInjection::generate_env_var_name("secrets.api-config"),
            "API_CONFIG"
        );

        // Test fromJSON(secrets.*) patterns (should extract just the secret name)
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.config)"),
            "CONFIG"
        );

        // Test fromJSON(secrets.*) with property access
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.database-config).username"),
            "DATABASE_CONFIG_USERNAME"
        );

        // Test fromJSON(secrets.*) with special characters
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.api-config)"),
            "API_CONFIG"
        );

        // Test fromJSON(secrets.*) with complex names and property access
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(secrets.database_config).password"),
            "DATABASE_CONFIG_PASSWORD"
        );

        // Test fromJSON with non-secrets content
        assert_eq!(
            TemplateInjection::generate_env_var_name("fromJSON(github.event.config)"),
            "GITHUB_EVENT_CONFIG"
        );

        // Test with mixed special characters
        assert_eq!(
            TemplateInjection::generate_env_var_name("github.event@issue.title"),
            "GITHUB_EVENT_ISSUE_TITLE"
        );

        // Test with spaces and other special characters
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

    #[test]
    fn test_fixes_are_added_to_findings() {
        use super::TemplateInjection;

        let env_var_fix = TemplateInjection::create_env_var_fix(
            &["${{ github.event.issue.title }}".to_string()],
            "test-job",
            0,
            "echo \"${{ github.event.issue.title }}\"",
        );

        assert_eq!(
            env_var_fix.title,
            "Move template expressions to environment variables"
        );
        assert!(env_var_fix.description.contains("github.event.issue.title"));
        assert!(env_var_fix.description.contains("env:"));

        let shell_fix = TemplateInjection::create_shell_specification_fix("test-job", 0);
        assert_eq!(shell_fix.title, "Add explicit shell specification");
        assert!(shell_fix.description.contains("shell: bash"));
    }

    #[test]
    fn test_fix_descriptions_match_audits_md_guidelines() {
        use super::TemplateInjection;

        let env_var_fix = TemplateInjection::create_env_var_fix(
            &["${{ github.event.issue.title }}".to_string()],
            "test-job",
            0,
            "echo \"${{ github.event.issue.title }}\"",
        );

        // Verify the description contains key phrases from audits.md
        assert!(
            env_var_fix
                .description
                .contains("Template expansions aren't syntax-aware")
        );
        assert!(env_var_fix.description.contains("shell injection vectors"));
        assert!(
            env_var_fix
                .description
                .contains("attacker-controllable expression contexts")
        );
        assert!(
            env_var_fix
                .description
                .contains("variable expansion is subject to normal shell quoting/expansion rules")
        );

        let shell_fix = TemplateInjection::create_shell_specification_fix("test-job", 0);

        // Verify shell fix description contains guidance from audits.md
        assert!(
            shell_fix
                .description
                .contains("different shells have different environment variable syntaxes")
        );
        assert!(shell_fix.description.contains("PowerShell"));
        assert!(shell_fix.description.contains("${env:VARNAME}"));
        assert!(shell_fix.description.contains("shell: bash"));
    }
}
