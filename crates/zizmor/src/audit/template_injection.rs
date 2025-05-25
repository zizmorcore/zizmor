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

    fn script_with_location<'s>(
        step: &impl StepCommon<'s>,
    ) -> Option<(String, SymbolicLocation<'s>)> {
        Self::scripts_with_location(step).into_iter().next()
    }

    fn injectable_template_expressions<'s>(
        &self,
        run: &str,
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        let mut processed_expressions = std::collections::HashSet::new();

        for (expr, _) in extract_expressions(run) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            // Track the overall severity and confidence for this expression
            let mut max_severity = Severity::Unknown;
            let mut max_confidence = Confidence::Unknown;
            let mut has_default_persona = false;

            // Emit a blanket pedantic finding for the extracted expression
            // since any expression in a code context is a code smell,
            // even if unexploitable.
            max_severity = max_severity.max(Severity::Unknown);
            max_confidence = max_confidence.max(Confidence::Unknown);

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
                                max_severity = max_severity.max(Severity::Medium);
                                max_confidence = max_confidence.max(Confidence::High);
                                has_default_persona = true;
                            }
                            // Arbitrary means the context's expansion is
                            // fully attacker-controllable.
                            Some(Capability::Arbitrary) => {
                                max_severity = max_severity.max(Severity::High);
                                max_confidence = max_confidence.max(Confidence::High);
                                has_default_persona = true;
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
                                    max_severity = max_severity.max(Severity::High);
                                    max_confidence = max_confidence.max(Confidence::Low);
                                    has_default_persona = true;
                                } else if let Some(env) = context.pop_if("env") {
                                    let env_is_static = step.env_is_static(env);

                                    if !env_is_static {
                                        max_severity = max_severity.max(Severity::Low);
                                        max_confidence = max_confidence.max(Confidence::High);
                                        has_default_persona = true;
                                    }
                                } else if context.child_of("github") {
                                    // TODO: Filter these more finely; not everything in the event
                                    // context is actually attacker-controllable.
                                    max_severity = max_severity.max(Severity::High);
                                    max_confidence = max_confidence.max(Confidence::High);
                                    has_default_persona = true;
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
                                            max_severity = max_severity.max(Severity::Medium);
                                            max_confidence = max_confidence.max(Confidence::Medium);
                                            has_default_persona = true;
                                        }
                                    }
                                    continue;
                                } else {
                                    // All other contexts are typically not attacker controllable,
                                    // but may be in obscure cases.
                                    max_severity = max_severity.max(Severity::Informational);
                                    max_confidence = max_confidence.max(Confidence::Low);
                                    has_default_persona = true;
                                }
                            }
                        }
                    }
                    None => {
                        // If we couldn't turn the context into a pattern,
                        // we almost certainly have something like
                        // `call(...).foo.bar`.
                        max_severity = max_severity.max(Severity::Informational);
                        max_confidence = max_confidence.max(Confidence::Low);
                        has_default_persona = true;
                    }
                }
            }

            // Only add the full expression once, with the highest severity/confidence found
            let expr_raw = expr.as_raw();
            if !processed_expressions.contains(expr_raw) {
                processed_expressions.insert(expr_raw.to_string());

                let persona = if has_default_persona {
                    Persona::default()
                } else {
                    Persona::Pedantic
                };

                bad_expressions.push((expr_raw.into(), max_severity, max_confidence, persona));
            }
        }

        bad_expressions
    }

    /// Create a fix that moves template expressions to environment variables
    fn create_env_var_fix(
        expressions: &[String],
        job_id: &str,
        step_index: usize,
        script: &str,
    ) -> Fix {
        let expr_list = if expressions.len() <= 3 {
            expressions.join(", ")
        } else {
            format!(
                "{}, and {} others",
                expressions[..3].join(", "),
                expressions.len() - 3
            )
        };

        Fix {
            title: "Move template expressions to environment variables".to_string(),
            description: format!(
                "Move template expressions ({}) to environment variables to prevent code injection. \
                Instead of using expressions like '${{{{ github.event.issue.title }}}}' directly in the script, \
                add them to the 'env:' block and reference them as shell variables like '${{ISSUE_TITLE}}'. \
                \n\nExample:\n\
                Before: run: echo \"${{{{ github.event.issue.title }}}}\"\n\
                After:\n  run: echo \"${{ISSUE_TITLE}}\"\n  env:\n    ISSUE_TITLE: ${{{{ github.event.issue.title }}}}",
                expr_list
            ),
            apply: Box::new({
                let expressions = expressions.to_vec();
                let job_id = job_id.to_string();
                let script = script.to_string();
                move |content: &str| -> anyhow::Result<Option<String>> {
                    let mut operations = Vec::new();
                    let mut new_script = script.clone();
                    let mut env_vars = serde_yaml::Mapping::new();

                    // Process each expression and create environment variables
                    // Replace ALL occurrences of each expression in the entire script
                    for expr in &expressions {
                        // Extract the expression without the ${{ }} wrapper
                        let clean_expr =
                            expr.trim_start_matches("${{").trim_end_matches("}}").trim();

                        // Generate a safe environment variable name
                        let env_var_name = Self::generate_env_var_name(clean_expr);

                        // Replace ALL occurrences of the expression in the script with the environment variable
                        let full_expr = format!("${{{{ {} }}}}", clean_expr);
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

                    // Add environment variables
                    if !env_vars.is_empty() {
                        operations.push(YamlPatchOperation::MergeInto {
                            path: format!("/jobs/{}/steps/{}", job_id, step_index),
                            key: "env".to_string(),
                            value: serde_yaml::Value::Mapping(env_vars),
                        });
                    }

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

    /// Create a fix that moves template expressions to environment variables for composite actions
    fn create_composite_env_var_fix(
        expressions: &[String],
        step_index: usize,
        script: &str,
    ) -> Fix {
        let expr_list = if expressions.len() <= 3 {
            expressions.join(", ")
        } else {
            format!(
                "{}, and {} others",
                expressions[..3].join(", "),
                expressions.len() - 3
            )
        };

        Fix {
            title: "Move template expressions to environment variables".to_string(),
            description: format!(
                "Move template expressions ({}) to environment variables to prevent code injection.",
                expr_list
            ),
            apply: Box::new({
                let expressions = expressions.to_vec();
                let script = script.to_string();
                move |content: &str| -> anyhow::Result<Option<String>> {
                    let mut operations = Vec::new();
                    let mut new_script = script.clone();
                    let mut env_vars = serde_yaml::Mapping::new();

                    // Process each expression and create environment variables
                    // Replace ALL occurrences of each expression in the entire script
                    for expr in &expressions {
                        // Extract the expression without the ${{ }} wrapper
                        let clean_expr =
                            expr.trim_start_matches("${{").trim_end_matches("}}").trim();

                        // Generate a safe environment variable name
                        let env_var_name = Self::generate_env_var_name(clean_expr);

                        // Replace ALL occurrences of the expression in the script with the environment variable
                        let full_expr = format!("${{{{ {} }}}}", clean_expr);
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

                    // Add environment variables
                    if !env_vars.is_empty() {
                        operations.push(YamlPatchOperation::MergeInto {
                            path: format!("/runs/steps/{}", step_index),
                            key: "env".to_string(),
                            value: serde_yaml::Value::Mapping(env_vars),
                        });
                    }

                    match crate::yaml_patch::apply_yaml_patch(content, operations) {
                        Ok(new_content) => Ok(Some(new_content)),
                        Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
                    }
                }
            }),
        }
    }

    /// Create a fix that adds explicit shell specification for workflow steps
    fn create_shell_specification_fix(job_id: &str, step_index: usize) -> Fix {
        Fix {
            title: "Add explicit shell specification".to_string(),
            description: "Add 'shell: bash' to ensure consistent variable expansion syntax across different runners. \
                This prevents issues with PowerShell's different variable syntax ('${env:VARNAME}') on Windows runners.".to_string(),
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
            description: "Add 'shell: bash' to ensure consistent variable expansion syntax across different runners.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::MergeInto {
                path: format!("/runs/steps/{}", step_index),
                key: "shell".to_string(),
                value: serde_yaml::Value::String("bash".to_string()),
            }]),
        }
    }

    /// Create a fix that provides input validation guidance
    fn create_validation_guidance_fix() -> Fix {
        Fix {
            title: "Add input validation".to_string(),
            description: "Add validation for user-controlled inputs before using them in scripts. \
                Validate input format, length, and characters. Use allowlists for expected values when possible. \
                Consider using tools like 'jq' for safe JSON processing.".to_string(),
            apply: Box::new(|content| Ok(Some(content.to_string()))),
        }
    }

    /// Create a fix that suggests using GITHUB_OUTPUT instead of environment variables for step communication
    fn create_output_alternative_fix() -> Fix {
        Fix {
            title: "Use GITHUB_OUTPUT for step communication".to_string(),
            description: "If passing data between steps, consider using GITHUB_OUTPUT instead of environment variables. \
                This provides better isolation and reduces the attack surface for environment variable injection.".to_string(),
            apply: Box::new(|content| Ok(Some(content.to_string()))),
        }
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
        let Some((script, script_location)) = Self::script_with_location(step) else {
            return Ok(vec![]);
        };

        let expressions_info = self.injectable_template_expressions(&script, step);
        if expressions_info.is_empty() {
            return Ok(vec![]);
        }

        // Collect all expressions for fix generation
        let expressions: Vec<String> = expressions_info
            .iter()
            .map(|(expr, _, _, _)| expr.clone())
            .collect();

        // Find the highest severity and confidence from all expressions
        let max_severity = expressions_info
            .iter()
            .map(|(_, severity, _, _)| *severity)
            .max()
            .unwrap_or(Severity::Unknown);

        let max_confidence = expressions_info
            .iter()
            .map(|(_, _, confidence, _)| *confidence)
            .max()
            .unwrap_or(Confidence::Unknown);

        // Use the most restrictive persona (default over pedantic)
        let persona = if expressions_info
            .iter()
            .any(|(_, _, _, persona)| *persona == Persona::default())
        {
            Persona::default()
        } else {
            Persona::Pedantic
        };

        // Create annotation listing all problematic expressions
        let annotation = if expressions.len() == 1 {
            format!(
                "{} may expand into attacker-controllable code",
                expressions[0]
            )
        } else {
            format!(
                "{} expressions may expand into attacker-controllable code: {}",
                expressions.len(),
                expressions.join(", ")
            )
        };

        let mut finding_builder = Self::finding()
            .severity(max_severity)
            .confidence(max_confidence)
            .persona(persona)
            .add_location(step.location().hidden())
            .add_location(step.location_with_name())
            .add_location(script_location.primary().annotated(annotation));

        // Add fixes - only one set of fixes per step
        finding_builder = finding_builder
            .fix(Self::create_env_var_fix(
                &expressions,
                step.job().id(),
                step.index,
                &script,
            ))
            .fix(Self::create_shell_specification_fix(
                step.job().id(),
                step.index,
            ))
            .fix(Self::create_validation_guidance_fix())
            .fix(Self::create_output_alternative_fix());

        Ok(vec![finding_builder.build(step)?])
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let Some((script, script_location)) = Self::script_with_location(step) else {
            return Ok(vec![]);
        };

        let expressions_info = self.injectable_template_expressions(&script, step);
        if expressions_info.is_empty() {
            return Ok(vec![]);
        }

        // Collect all expressions for fix generation
        let expressions: Vec<String> = expressions_info
            .iter()
            .map(|(expr, _, _, _)| expr.clone())
            .collect();

        // Find the highest severity and confidence from all expressions
        let max_severity = expressions_info
            .iter()
            .map(|(_, severity, _, _)| *severity)
            .max()
            .unwrap_or(Severity::Unknown);

        let max_confidence = expressions_info
            .iter()
            .map(|(_, _, confidence, _)| *confidence)
            .max()
            .unwrap_or(Confidence::Unknown);

        // Use the most restrictive persona (default over pedantic)
        let persona = if expressions_info
            .iter()
            .any(|(_, _, _, persona)| *persona == Persona::default())
        {
            Persona::default()
        } else {
            Persona::Pedantic
        };

        // Create annotation listing all problematic expressions
        let annotation = if expressions.len() == 1 {
            format!(
                "{} may expand into attacker-controllable code",
                expressions[0]
            )
        } else {
            format!(
                "{} expressions may expand into attacker-controllable code: {}",
                expressions.len(),
                expressions.join(", ")
            )
        };

        let mut finding_builder = Self::finding()
            .severity(max_severity)
            .confidence(max_confidence)
            .persona(persona)
            .add_location(step.location().hidden())
            .add_location(step.location_with_name())
            .add_location(script_location.primary().annotated(annotation));

        // Add fixes - only one set of fixes per step
        finding_builder = finding_builder
            .fix(Self::create_composite_env_var_fix(
                &expressions,
                step.index,
                &script,
            ))
            .fix(Self::create_composite_shell_specification_fix(step.index))
            .fix(Self::create_validation_guidance_fix())
            .fix(Self::create_output_alternative_fix());

        Ok(vec![finding_builder.build(step)?])
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
    fn test_env_var_fix() {
        use super::TemplateInjection;

        let expressions = vec!["github.event.issue.title".to_string()];
        let fix = TemplateInjection::create_env_var_fix(
            &expressions,
            "build",
            0,
            "echo \"${{ github.event.issue.title }}\"",
        );

        assert_eq!(
            fix.title,
            "Move template expressions to environment variables"
        );
        assert!(fix.description.contains("github.event.issue.title"));
        assert!(fix.description.contains("env:"));
        assert!(fix.description.contains("Example:"));

        // Test that applying the fix actually modifies the content
        let content = r#"jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"#;
        let result = fix.apply_to_content(content).unwrap().unwrap();
        assert!(result.contains("env:"));
        assert!(result.contains("GITHUB_EVENT_ISSUE_TITLE"));
        assert!(result.contains("${GITHUB_EVENT_ISSUE_TITLE}"));
    }

    #[test]
    fn test_env_var_fix_multiple_expressions() {
        use super::TemplateInjection;

        let expressions = vec![
            "github.event.issue.title".to_string(),
            "github.event.pull_request.body".to_string(),
            "github.event.comment.body".to_string(),
            "github.event.issue.body".to_string(),
            "github.event.workflow_run.head_commit.message".to_string(),
        ];
        let fix = TemplateInjection::create_env_var_fix(
            &expressions,
            "build",
            0,
            "echo \"${{ github.event.issue.title }}\"",
        );

        assert!(fix.description.contains("and 2 others"));
        assert!(fix.description.contains("github.event.issue.title"));
        assert!(fix.description.contains("github.event.pull_request.body"));
        assert!(fix.description.contains("github.event.comment.body"));
        assert!(!fix.description.contains("github.event.issue.body")); // Should be truncated
    }

    #[test]
    fn test_shell_specification_fix() {
        use super::TemplateInjection;

        let fix = TemplateInjection::create_shell_specification_fix("build", 0);

        assert_eq!(fix.title, "Add explicit shell specification");
        assert!(fix.description.contains("shell: bash"));
        assert!(fix.description.contains("PowerShell"));

        // Test the fix application on a simple YAML
        let yaml_content = r#"jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        assert!(result.contains("shell: bash"));
    }

    #[test]
    fn test_composite_shell_specification_fix() {
        use super::TemplateInjection;

        let fix = TemplateInjection::create_composite_shell_specification_fix(0);

        assert_eq!(fix.title, "Add explicit shell specification");

        // Test the fix application on a composite action
        let yaml_content = r#"runs:
  using: composite
  steps:
    - run: echo "hello"
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        assert!(result.contains("shell: bash"));
    }

    #[test]
    fn test_validation_guidance_fix() {
        use super::TemplateInjection;

        let fix = TemplateInjection::create_validation_guidance_fix();

        assert_eq!(fix.title, "Add input validation");
        assert!(fix.description.contains("validation"));
        assert!(fix.description.contains("allowlists"));
        assert!(fix.description.contains("jq"));

        // Test that applying the fix returns the content unchanged (guidance only)
        let content = "test content";
        let result = fix.apply_to_content(content).unwrap().unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_output_alternative_fix() {
        use super::TemplateInjection;

        let fix = TemplateInjection::create_output_alternative_fix();

        assert_eq!(fix.title, "Use GITHUB_OUTPUT for step communication");
        assert!(fix.description.contains("GITHUB_OUTPUT"));
        assert!(fix.description.contains("isolation"));

        // Test that applying the fix returns the content unchanged (guidance only)
        let content = "test content";
        let result = fix.apply_to_content(content).unwrap().unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_fix_descriptions_are_informative() {
        use super::TemplateInjection;

        let expressions = vec!["github.event.issue.title".to_string()];

        // Test that all fix descriptions are comprehensive
        let env_var_fix = TemplateInjection::create_env_var_fix(
            &expressions,
            "job",
            0,
            "echo \"${{ github.event.issue.title }}\"",
        );
        let shell_fix = TemplateInjection::create_shell_specification_fix("job", 0);
        let validation_fix = TemplateInjection::create_validation_guidance_fix();
        let output_fix = TemplateInjection::create_output_alternative_fix();

        // Each description should be substantial (more than just a title)
        assert!(env_var_fix.description.len() > 100);
        assert!(shell_fix.description.len() > 50);
        assert!(validation_fix.description.len() > 50);
        assert!(output_fix.description.len() > 50);

        // Each should contain practical guidance
        assert!(env_var_fix.description.contains("Example:"));
        assert!(shell_fix.description.contains("PowerShell"));
        assert!(validation_fix.description.contains("allowlists"));
        assert!(output_fix.description.contains("isolation"));
    }
}
