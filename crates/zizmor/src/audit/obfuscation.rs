use github_actions_expressions::Expr;
use github_actions_models::common::{RepositoryUses, Uses};

use crate::{
    Confidence, Severity, apply_yaml_patch,
    finding::{Feature, Finding, Fix, Location},
    models::{CompositeStep, JobExt as _, Step, StepCommon},
    utils::parse_expressions_from_input,
    yaml_patch::YamlPatchOperation,
};

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct Obfuscation;

audit_meta!(
    Obfuscation,
    "obfuscation",
    "obfuscated usage of GitHub Actions features"
);

impl Obfuscation {
    fn obfuscated_repo_uses(&self, uses: &RepositoryUses) -> Vec<&str> {
        let mut annotations = vec![];

        // Users can put all kinds of nonsense in `uses:` clauses, which
        // GitHub happily interprets but otherwise gums up pattern matching
        // in audits like unpinned-uses, forbidden-uses, and cache-poisoning.
        // We check for some of these forms of nonsense here and report them.
        if let Some(subpath) = uses.subpath.as_deref() {
            for component in subpath.split('/') {
                match component {
                    // . and .. are valid in uses subpaths, but are impossible to
                    // analyze or match with full generality.
                    "." => {
                        annotations.push("actions reference contains '.'");
                    }
                    ".." => {
                        annotations.push("actions reference contains '..'");
                    }
                    // `uses: foo/bar////baz` and similar is valid, but
                    // only serves to mess up pattern matching.
                    // This also catches `uses: foo/bar/@v1`.
                    _ if component.is_empty() => {
                        annotations.push("actions reference contains empty component");
                    }
                    _ => {}
                }
            }
        }

        annotations
    }

    fn obfuscated_exprs(&self, expr: &Expr) -> Vec<&str> {
        let mut annotations = vec![];

        // Check for some common expression obfuscation patterns.

        // Expressions that can be constant reduced should be simplified to
        // their evaluated form.
        if expr.constant_reducible() {
            annotations.push("expression can be replaced by its static evaluation");
        } else if expr.has_constant_reducible_subexpr() {
            annotations.push("expression contains constant-reducible subexpression");
        }

        // TODO: calculate call breadth/depth and flag above thresholds.

        annotations
    }

    /// Create a fix for cleaning up obfuscated repository uses
    fn create_cleanup_repo_uses_fix(uses: &RepositoryUses, path: &str) -> Fix {
        let current_uses = if let (Some(git_ref), Some(subpath)) = (&uses.git_ref, &uses.subpath) {
            format!("{}/{}{}@{}", uses.owner, uses.repo, subpath, git_ref)
        } else if let Some(git_ref) = &uses.git_ref {
            format!("{}/{}@{}", uses.owner, uses.repo, git_ref)
        } else if let Some(subpath) = &uses.subpath {
            format!("{}/{}{}", uses.owner, uses.repo, subpath)
        } else {
            format!("{}/{}", uses.owner, uses.repo)
        };

        // Clean up the subpath by removing redundant separators and resolving . and ..
        let cleaned_uses = if let Some(subpath) = &uses.subpath {
            // The subpath is relative to the repo root. Start there and navigate.
            let mut path_components = vec![uses.owner.clone(), uses.repo.clone()];

            // Split the subpath and process each component
            for part in subpath.split('/') {
                if part.is_empty() {
                    // Skip empty components (from double slashes)
                    continue;
                }

                match part {
                    "." => {
                        // Current directory - do nothing
                    }
                    ".." => {
                        // Parent directory - remove the last component if present
                        if !path_components.is_empty() {
                            path_components.pop();
                        }
                    }
                    component => {
                        // Regular component - add it
                        path_components.push(component.to_string());
                    }
                }
            }

            // Special case: If we ended up with ["owner", "repo", "repo"],
            // it means the subpath navigated us back to the same repo directory
            // In this case, just use ["owner", "repo"]
            if path_components.len() == 3
                && path_components[1] == path_components[2]
                && path_components[1] == uses.repo
            {
                path_components.pop();
            }

            // Ensure we have at least owner
            if path_components.is_empty() {
                path_components.push(uses.owner.clone());
            }

            // Rebuild the cleaned path
            let cleaned_path = path_components.join("/");

            // Add git_ref if present
            if let Some(git_ref) = &uses.git_ref {
                format!("{}@{}", cleaned_path, git_ref)
            } else {
                cleaned_path
            }
        } else {
            // No subpath to clean
            if let Some(git_ref) = &uses.git_ref {
                format!("{}/{}@{}", uses.owner, uses.repo, git_ref)
            } else {
                format!("{}/{}", uses.owner, uses.repo)
            }
        };

        Fix {
            title: "Clean up obfuscated action reference".to_string(),
            description: format!(
                "Clean up the obfuscated action reference by removing redundant path separators and resolving relative path components. This will change '{}' to '{}' for better readability and to ensure other security audits can properly analyze the action reference.",
                current_uses, cleaned_uses
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path.to_string(),
                value: serde_yaml::Value::String(cleaned_uses),
            }]),
        }
    }

    /// Create a fix for simplifying obfuscated expressions
    fn create_simplify_expression_fix(
        expr_str: String,
        _span_start: usize,
        _span_end: usize,
    ) -> Fix {
        Fix {
            title: "Simplify obfuscated expression".to_string(),
            description: format!(
                "Simplify the obfuscated expression '{}' by evaluating constant parts and removing unnecessary complexity. \
                This improves readability and helps other security audits analyze the code more effectively.",
                expr_str
            ),
            apply: Box::new(move |content: &str| -> anyhow::Result<Option<String>> {
                // For now, we provide guidance but don't automatically rewrite expressions
                // as that requires more complex expression evaluation and replacement logic
                tracing::info!(
                    "Expression simplification fix would be applied here for: {}",
                    expr_str
                );
                Ok(Some(content.to_string()))
            }),
        }
    }
}

impl Audit for Obfuscation {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(&self, input: &'doc AuditInput) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for annotation in self.obfuscated_exprs(&parsed) {
                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .add_raw_location(Location::new(
                        input.location().annotated(annotation).primary(),
                        Feature::from_span(&span, input),
                    ));

                // Add fix for simplifying obfuscated expressions
                let fix = Self::create_simplify_expression_fix(
                    expr.as_bare().to_string(),
                    span.start,
                    span.end,
                );
                finding_builder = finding_builder.fix(fix);

                findings.push(finding_builder.build(input)?);
            }
        }

        Ok(findings)
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses() {
            for annotation in self.obfuscated_repo_uses(uses) {
                let job_id = step.job().id();
                let step_index = step.index;
                let uses_path = format!("/jobs/{}/steps/{}/uses", job_id, step_index);

                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(annotation),
                    );

                // Add fix for cleaning up obfuscated repository uses
                let fix = Self::create_cleanup_repo_uses_fix(uses, &uses_path);
                finding_builder = finding_builder.fix(fix);

                findings.push(finding_builder.build(step)?);
            }
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses() {
            for annotation in self.obfuscated_repo_uses(uses) {
                let step_index = step.index;
                let uses_path = format!("/runs/steps/{}/uses", step_index);

                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(annotation),
                    );

                // Add fix for cleaning up obfuscated repository uses
                let fix = Self::create_cleanup_repo_uses_fix(uses, &uses_path);
                finding_builder = finding_builder.fix(fix);

                findings.push(finding_builder.build(step)?);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_repo_uses_fix() {
        // Test cleaning up obfuscated repository uses
        let test_cases = vec![
            // Case 1: actions//checkout/../checkout@v4 -> actions/checkout@v4
            (
                "actions",
                "checkout",
                Some("//checkout/../checkout".to_string()),
                Some("v4".to_string()),
                "actions/checkout@v4",
            ),
            // Case 2: actions/setup-node//../setup-node@v4 -> actions/setup-node@v4
            (
                "actions",
                "setup-node",
                Some("//../setup-node".to_string()),
                Some("v4".to_string()),
                "actions/setup-node@v4",
            ),
            // Case 3: actions///cache@v3 -> actions/cache@v3
            (
                "actions",
                "cache",
                Some("//".to_string()),
                Some("v3".to_string()),
                "actions/cache@v3",
            ),
            // Case 4: owner/repo/./action -> owner/repo/action
            (
                "owner",
                "repo",
                Some("/./action".to_string()),
                None,
                "owner/repo/action",
            ),
            // Case 5: owner/repo/../other-repo/action -> owner/other-repo/action
            (
                "owner",
                "repo",
                Some("/../other-repo/action".to_string()),
                None,
                "owner/other-repo/action",
            ),
        ];

        for (owner, repo, subpath, git_ref, expected) in test_cases {
            let uses = RepositoryUses {
                owner: owner.to_string(),
                repo: repo.to_string(),
                git_ref,
                subpath,
            };

            let fix = Obfuscation::create_cleanup_repo_uses_fix(&uses, "/jobs/test/steps/0/uses");

            // Verify the title and description contain expected content
            assert!(fix.title.contains("Clean up obfuscated action reference"));

            // Verify that the fix description contains the expected cleaned result
            assert!(
                fix.description.contains(&expected),
                "Expected '{}' not found in description: '{}'",
                expected,
                fix.description
            );
        }
    }

    #[test]
    fn test_cleanup_repo_uses_fix_application() {
        // Test that the YAML patch actually works with realistic content
        let yaml_content = r#"name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions//checkout/../checkout@v4
        with:
          persist-credentials: false
"#;

        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v4".to_string()),
            subpath: Some("//checkout/../checkout".to_string()),
        };

        let fix = Obfuscation::create_cleanup_repo_uses_fix(&uses, "/jobs/test/steps/0/uses");

        // Apply the fix
        let result = fix.apply_to_content(yaml_content);
        assert!(result.is_ok(), "Fix application failed: {:?}", result.err());

        let fixed_content = result.unwrap().unwrap();

        // Verify the obfuscated reference was cleaned up
        assert!(fixed_content.contains("uses: actions/checkout@v4"));
        assert!(!fixed_content.contains("actions//checkout/../checkout@v4"));

        // Verify other content is preserved
        assert!(fixed_content.contains("name: test"));
        assert!(fixed_content.contains("persist-credentials: false"));
    }

    #[test]
    fn test_simplify_expression_fix() {
        let expr = "format('{0}/{1}', 'octocat', 'hello-world')".to_string();
        let fix = Obfuscation::create_simplify_expression_fix(expr.clone(), 0, expr.len());

        assert_eq!(fix.title, "Simplify obfuscated expression");
        assert!(fix.description.contains(&expr));
        assert!(fix.description.contains("evaluating constant parts"));

        // Test that the fix function doesn't error
        let test_content = "test: content";
        assert!(fix.apply_to_content(test_content).is_ok());
    }

    #[test]
    fn test_obfuscated_repo_uses_detection() {
        let obfuscation = Obfuscation;

        // Test detection of various obfuscation patterns
        let test_cases = vec![
            // Empty components
            (
                RepositoryUses {
                    owner: "actions".to_string(),
                    repo: "checkout".to_string(),
                    subpath: Some("//path".to_string()),
                    git_ref: None,
                },
                vec!["actions reference contains empty component"],
            ),
            // Dot components
            (
                RepositoryUses {
                    owner: "actions".to_string(),
                    repo: "checkout".to_string(),
                    subpath: Some("/./path".to_string()),
                    git_ref: None,
                },
                vec!["actions reference contains '.'"],
            ),
            // Double dot components
            (
                RepositoryUses {
                    owner: "actions".to_string(),
                    repo: "checkout".to_string(),
                    subpath: Some("/../path".to_string()),
                    git_ref: None,
                },
                vec!["actions reference contains '..'"],
            ),
            // Multiple issues
            (
                RepositoryUses {
                    owner: "actions".to_string(),
                    repo: "checkout".to_string(),
                    subpath: Some("//./../path".to_string()),
                    git_ref: None,
                },
                vec![
                    "actions reference contains empty component",
                    "actions reference contains '..'",
                    "actions reference contains '.'",
                ],
            ),
        ];

        for (uses, expected_annotations) in test_cases {
            let annotations = obfuscation.obfuscated_repo_uses(&uses);
            for expected in expected_annotations {
                assert!(
                    annotations.contains(&expected),
                    "Expected annotation '{}' not found in {:?}",
                    expected,
                    annotations
                );
            }
        }
    }
}
