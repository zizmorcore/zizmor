use github_actions_expressions::{Expr, context::Context};
use github_actions_models::common::{If, expr::ExplicitExpr};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    finding::{Confidence, Fix, Severity},
    models::{JobExt, StepCommon as _},
};

// TODO: Merge this with the list in `template_injection.rs`?
// See also #674.
const USER_CONTROLLABLE_CONTEXTS: &[&str] = &[
    "env",
    "github.actor",
    "github.base_ref",
    "github.head_ref",
    "github.ref",
    "github.ref_name",
    "github.sha",
    "github.triggering_actor",
    "inputs",
];

pub(crate) struct UnsoundContains;

audit_meta!(
    UnsoundContains,
    "unsound-contains",
    "unsound contains condition"
);

impl Audit for UnsoundContains {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(
        &self,
        job: &super::NormalJob<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = Vec::new();

        let conditions = job
            .r#if
            .iter()
            .map(|cond| (cond, job.location(), "job".to_string()))
            .chain(job.steps().enumerate().filter_map(|(step_index, step)| {
                step.r#if
                    .as_ref()
                    .map(|cond| (cond, step.location(), step_index.to_string()))
            }))
            .filter_map(|(cond, loc, step_info)| {
                if let If::Expr(expr) = cond {
                    Some((expr.as_str(), loc, step_info))
                } else {
                    None
                }
            });

        for (expr, loc, step_info) in conditions {
            let unsound_results = Self::unsound_contains(expr);
            for (severity, context, string_arg, context_arg) in unsound_results {
                let fixes = Self::create_fixes_for_unsound_contains(
                    expr,
                    &string_arg,
                    &context_arg,
                    job.id(),
                    step_info.clone(),
                );

                let mut finding_builder = Self::finding()
                    .severity(severity)
                    .confidence(Confidence::High)
                    .add_location(loc.with_keys(&["if".into()]).primary().annotated(format!(
                        "contains(..) condition can be bypassed if attacker can control '{context}'"
                    )));

                for fix in fixes {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(job.parent())?);
            }
        }

        Ok(findings)
    }
}

impl UnsoundContains {
    fn walk_tree_for_unsound_contains<'a>(
        expr: &'a Expr,
    ) -> Box<dyn Iterator<Item = (&'a str, &'a Context<'a>)> + 'a> {
        match expr {
            Expr::Call { func, args: exprs } if func == "contains" => match exprs.as_slice() {
                [Expr::String(s), Expr::Context(c)] => Box::new(std::iter::once((s.as_str(), c))),
                args => Box::new(args.iter().flat_map(Self::walk_tree_for_unsound_contains)),
            },
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context { parts: exprs, .. }) => {
                Box::new(exprs.iter().flat_map(Self::walk_tree_for_unsound_contains))
            }
            Expr::Index(expr) => Self::walk_tree_for_unsound_contains(expr),
            Expr::BinOp { lhs, rhs, .. } => {
                let bc_lhs = Self::walk_tree_for_unsound_contains(lhs);
                let bc_rhs = Self::walk_tree_for_unsound_contains(rhs);

                Box::new(bc_lhs.chain(bc_rhs))
            }
            Expr::UnOp { expr, .. } => Self::walk_tree_for_unsound_contains(expr),
            _ => Box::new(std::iter::empty()),
        }
    }

    fn unsound_contains(expr: &str) -> Vec<(Severity, String, String, String)> {
        let bare = match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => raw_expr.as_bare().to_string(),
            None => expr.to_string(),
        };

        Expr::parse(&bare)
            .inspect_err(|_err| tracing::warn!("couldn't parse expression: {expr}"))
            .iter()
            .flat_map(|expression| Self::walk_tree_for_unsound_contains(expression))
            .map(|(s, ctx)| {
                let severity = if USER_CONTROLLABLE_CONTEXTS
                    .iter()
                    .any(|item| ctx.child_of(*item))
                {
                    Severity::High
                } else {
                    Severity::Informational
                };
                (
                    severity,
                    ctx.as_str().to_string(),
                    s.to_string(),
                    ctx.as_str().to_string(),
                )
            })
            .collect()
    }

    /// Create fixes for unsound contains conditions
    fn create_fixes_for_unsound_contains(
        _expr: &str,
        string_arg: &str,
        context_arg: &str,
        _job_id: &str,
        _step_info: String,
    ) -> Vec<Fix> {
        let mut fixes = vec![];

        // Fix 1: Use fromJSON with array instead of string
        fixes.push(Self::create_fromjson_array_fix(string_arg, context_arg));

        // Fix 2: Use explicit equality checks
        fixes.push(Self::create_equality_checks_fix(string_arg, context_arg));

        // Fix 3: Add input validation guidance
        fixes.push(Self::create_validation_guidance_fix(context_arg));

        fixes
    }

    /// Create a fix that suggests using fromJSON with an array instead of a string
    fn create_fromjson_array_fix(string_arg: &str, context_arg: &str) -> Fix {
        // Parse the string argument to extract individual values
        let values: Vec<&str> = string_arg
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .collect();

        let json_array = format!(
            "[{}]",
            values
                .iter()
                .map(|v| format!("\"{}\"", v))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Fix {
            title: "Use fromJSON with array for safe contains check".to_string(),
            description: format!(
                "Replace 'contains('{}', {})' with 'contains(fromJSON('{}'), {})'. \
                This ensures that the contains() function checks for exact matches in an array \
                rather than substring matches in a string, preventing bypass attacks.",
                string_arg, context_arg, json_array, context_arg
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This is a manual fix that requires updating the expression
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that suggests using explicit equality checks
    fn create_equality_checks_fix(string_arg: &str, context_arg: &str) -> Fix {
        // Parse the string argument to extract individual values
        let values: Vec<&str> = string_arg
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .collect();

        let equality_checks = values
            .iter()
            .map(|v| format!("{} == '{}'", context_arg, v))
            .collect::<Vec<_>>()
            .join(" || ");

        Fix {
            title: "Use explicit equality checks instead of contains".to_string(),
            description: format!(
                "Replace 'contains('{}', {})' with '{}'. \
                This uses explicit equality comparisons that cannot be bypassed with substring attacks. \
                Each condition checks for an exact match rather than a substring match.",
                string_arg, context_arg, equality_checks
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This is a manual fix that requires updating the expression
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that provides input validation guidance
    fn create_validation_guidance_fix(context_arg: &str) -> Fix {
        let guidance = if context_arg.starts_with("github.") {
            "For GitHub context variables, consider adding additional validation to ensure \
            the values match expected patterns. Use regular expressions or allowlists to \
            validate the format before using in conditions."
        } else if context_arg.starts_with("env.") {
            "For environment variables, ensure they are set to known safe values. \
            Consider using a validation step that checks the environment variable \
            against an allowlist of expected values."
        } else if context_arg.starts_with("inputs.") {
            "For workflow inputs, add input validation using the 'type' and 'options' \
            fields in your workflow definition. This restricts the possible values \
            that can be passed to your workflow."
        } else {
            "Add validation for user-controllable inputs to ensure they match expected \
            patterns before using them in security-sensitive conditions."
        };

        Fix {
            title: "Add input validation for security-sensitive conditions".to_string(),
            description: format!(
                "The context variable '{}' can be controlled by attackers. {}",
                context_arg, guidance
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Guidance-only fix
                Ok(Some(content.to_string()))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_condition() {
        for (cond, severity) in &[
            // Vulnerable conditions
            (
                "contains('refs/heads/main refs/heads/develop', github.ref)",
                vec![(
                    Severity::High,
                    String::from("github.ref"),
                    String::from("refs/heads/main refs/heads/develop"),
                    String::from("github.ref"),
                )],
            ),
            (
                "contains('refs/heads/main refs/heads/develop', github.REF)",
                vec![(
                    Severity::High,
                    String::from("github.REF"),
                    String::from("refs/heads/main refs/heads/develop"),
                    String::from("github.REF"),
                )], // case insensitive
            ),
            (
                "false || contains('main,develop', github.head_ref)",
                vec![(
                    Severity::High,
                    String::from("github.head_ref"),
                    String::from("main,develop"),
                    String::from("github.head_ref"),
                )],
            ),
            (
                "!contains('main|develop', github.base_ref)",
                vec![(
                    Severity::High,
                    String::from("github.base_ref"),
                    String::from("main|develop"),
                    String::from("github.base_ref"),
                )],
            ),
            (
                "contains(fromJSON('[true]'), contains('refs/heads/main refs/heads/develop', env.GITHUB_REF))",
                vec![(
                    Severity::High,
                    String::from("env.GITHUB_REF"),
                    String::from("refs/heads/main refs/heads/develop"),
                    String::from("env.GITHUB_REF"),
                )],
            ),
            (
                "contains(fromJSON('[true]'), contains('refs/heads/main refs/heads/develop', env.github_ref))",
                vec![(
                    Severity::High,
                    String::from("env.github_ref"),
                    String::from("refs/heads/main refs/heads/develop"),
                    String::from("env.github_ref"),
                )],
            ),
            (
                "contains(fromJSON('[true]'), contains('refs/heads/main refs/heads/develop', env.SOMETHING_RANDOM))",
                vec![(
                    Severity::High,
                    String::from("env.SOMETHING_RANDOM"),
                    String::from("refs/heads/main refs/heads/develop"),
                    String::from("env.SOMETHING_RANDOM"),
                )],
            ),
            (
                "contains('push pull_request', github.event_name)",
                vec![(
                    Severity::Informational,
                    String::from("github.event_name"),
                    String::from("push pull_request"),
                    String::from("github.event_name"),
                )],
            ),
            // These are okay.
            (
                "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'",
                vec![],
            ),
            (
                "contains(fromJSON('[\"refs/heads/main\", \"refs/heads/develop\"]'), github.ref)",
                vec![],
            ),
        ] {
            assert_eq!(
                UnsoundContains::unsound_contains(cond).as_slice(),
                severity.as_slice()
            );
        }
    }

    #[test]
    fn test_fromjson_array_fix() {
        let fix = UnsoundContains::create_fromjson_array_fix(
            "refs/heads/main refs/heads/develop",
            "github.ref",
        );

        assert_eq!(fix.title, "Use fromJSON with array for safe contains check");
        assert!(
            fix.description
                .contains("fromJSON('[\"refs/heads/main\", \"refs/heads/develop\"]')")
        );
        assert!(fix.description.contains("github.ref"));
        assert!(fix.description.contains("exact matches in an array"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_equality_checks_fix() {
        let fix = UnsoundContains::create_equality_checks_fix("main develop", "github.head_ref");

        assert_eq!(
            fix.title,
            "Use explicit equality checks instead of contains"
        );
        assert!(
            fix.description
                .contains("github.head_ref == 'main' || github.head_ref == 'develop'")
        );
        assert!(fix.description.contains("explicit equality comparisons"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_validation_guidance_fix() {
        // Test GitHub context guidance
        let fix = UnsoundContains::create_validation_guidance_fix("github.ref");
        assert_eq!(
            fix.title,
            "Add input validation for security-sensitive conditions"
        );
        assert!(fix.description.contains("GitHub context variables"));
        assert!(fix.description.contains("regular expressions"));

        // Test environment variable guidance
        let fix = UnsoundContains::create_validation_guidance_fix("env.ENVIRONMENT");
        assert!(fix.description.contains("environment variables"));
        assert!(fix.description.contains("allowlist"));

        // Test input guidance
        let fix = UnsoundContains::create_validation_guidance_fix("inputs.deployment_type");
        assert!(fix.description.contains("workflow inputs"));
        assert!(fix.description.contains("type"));

        // Test generic guidance
        let fix = UnsoundContains::create_validation_guidance_fix("some.other.context");
        assert!(fix.description.contains("user-controllable inputs"));
    }

    #[test]
    fn test_create_fixes_for_unsound_contains() {
        let fixes = UnsoundContains::create_fixes_for_unsound_contains(
            "contains('main develop', github.head_ref)",
            "main develop",
            "github.head_ref",
            "test-job",
            "0".to_string(),
        );

        assert_eq!(fixes.len(), 3);
        assert_eq!(
            fixes[0].title,
            "Use fromJSON with array for safe contains check"
        );
        assert_eq!(
            fixes[1].title,
            "Use explicit equality checks instead of contains"
        );
        assert_eq!(
            fixes[2].title,
            "Add input validation for security-sensitive conditions"
        );
    }
}
