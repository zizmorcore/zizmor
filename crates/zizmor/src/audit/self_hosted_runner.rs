//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use anyhow::Result;
use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::job::RunsOn,
};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::models::Matrix;
use crate::{
    AuditState, apply_yaml_patch,
    finding::{Confidence, Fix, Persona, Severity},
    models::JobExt as _,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

impl SelfHostedRunner {
    /// Create a fix that replaces self-hosted runner with GitHub-hosted runner
    fn create_github_hosted_replacement_fix(job_id: &str) -> Fix {
        let runs_on_path = format!("/jobs/{}/runs-on", job_id);

        Fix {
            title: "Replace self-hosted runner with GitHub-hosted runner".to_string(),
            description: "Replace the self-hosted runner with a GitHub-hosted runner (ubuntu-latest, windows-latest, or macos-latest). \
                GitHub-hosted runners are more secure as they are ephemeral and isolated between runs. \
                This is the safest option for public repositories as it eliminates persistence risks.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: runs_on_path,
                value: serde_yaml::Value::String("ubuntu-latest".to_string()),
            }]),
        }
    }

    /// Create a fix for adding manual approval requirements
    fn create_manual_approval_fix() -> Fix {
        Fix {
            title: "Add manual approval for external contributors".to_string(),
            description: "If you must use self-hosted runners, configure manual approval for workflows from external contributors. \
                This can be done at repository, organization, or enterprise levels in GitHub settings. \
                Go to Settings > Actions > General > Fork pull request workflows from outside collaborators and set appropriate restrictions. \
                This prevents untrusted code from running automatically on your self-hosted infrastructure.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This requires GitHub settings changes, not workflow file changes
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix suggesting ephemeral runners
    fn create_ephemeral_runner_fix() -> Fix {
        Fix {
            title: "Use ephemeral (just-in-time) runners".to_string(),
            description: "If self-hosted runners are necessary, use ephemeral runners that are created just-in-time for each job \
                and destroyed immediately afterwards. This minimizes persistence risks and makes it harder for attackers to maintain access. \
                Configure your runner infrastructure to provision fresh instances for each workflow run. \
                See GitHub's documentation on security hardening for self-hosted runners.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This requires infrastructure changes, not workflow file changes
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix for limiting to private repositories
    fn create_private_repository_fix() -> Fix {
        Fix {
            title: "Use self-hosted runners only on private repositories".to_string(),
            description: "The safest approach is to use self-hosted runners only on private repositories. \
                Public repositories expose self-hosted runners to potential security risks from external contributors. \
                Consider moving workflows with self-hosted runners to private repositories, or rearchitect your solution \
                to use GitHub-hosted runners with appropriate secrets and service configurations.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This requires repository management changes, not workflow file changes
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix for adding runner conditions/restrictions
    fn create_runner_conditions_fix(job_id: &str) -> Fix {
        Fix {
            title: "Add conditions to restrict self-hosted runner usage".to_string(),
            description: "Add conditional logic to restrict when self-hosted runners are used. \
                For example, only use self-hosted runners for trusted events or specific branches. \
                This reduces the attack surface by limiting when potentially risky infrastructure is exposed.".to_string(),
            apply: apply_yaml_patch!(vec![
                YamlPatchOperation::Add {
                    path: format!("/jobs/{}", job_id),
                    key: "if".to_string(),
                    value: serde_yaml::Value::String("github.repository_owner == 'trusted-org' && github.event_name != 'pull_request'".to_string()),
                }
            ]),
        }
    }

    /// Get the appropriate fixes for a self-hosted runner issue
    fn get_self_hosted_fixes(job_id: &str) -> Vec<Fix> {
        vec![
            // Primary fix: replace with GitHub-hosted runner
            Self::create_github_hosted_replacement_fix(job_id),
            // Security configuration fixes (guidance-based)
            Self::create_manual_approval_fix(),
            Self::create_ephemeral_runner_fix(),
            Self::create_private_repository_fix(),
            // Conditional usage fix
            Self::create_runner_conditions_fix(job_id),
        ]
    }
}

impl Audit for SelfHostedRunner {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::Workflow,
    ) -> Result<Vec<crate::finding::Finding<'doc>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(job) = job else {
                continue;
            };

            let job_id = job.id();

            match &job.runs_on {
                LoE::Literal(RunsOn::Target(labels)) => {
                    {
                        let Some(label) = labels.first() else {
                            continue;
                        };

                        if label == "self-hosted" {
                            // All self-hosted runners start with the 'self-hosted'
                            // label followed by any specifiers.
                            let fixes = Self::get_self_hosted_fixes(job_id);

                            let mut finding_builder = Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Unknown)
                                .persona(Persona::Auditor)
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(&["runs-on".into()])
                                        .annotated("self-hosted runner used here"),
                                );

                            // Add fixes for this self-hosted runner usage
                            for fix in fixes {
                                finding_builder = finding_builder.fix(fix);
                            }

                            results.push(finding_builder.build(workflow)?);
                        } else if ExplicitExpr::from_curly(label).is_some() {
                            // The job might also have its runner expanded via an
                            // expression. Long-term we should perform this evaluation
                            // to increase our confidence, but for now we flag it as
                            // potentially expanding to self-hosted.
                            let fixes = Self::get_self_hosted_fixes(job_id);

                            let mut finding_builder = Self::finding()
                                .confidence(Confidence::Low)
                                .severity(Severity::Unknown)
                                .persona(Persona::Auditor)
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(&["runs-on".into()])
                                        .annotated(
                                            "expression may expand into a self-hosted runner",
                                        ),
                                );

                            // Add fixes for potential self-hosted runner usage
                            for fix in fixes {
                                finding_builder = finding_builder.fix(fix);
                            }

                            results.push(finding_builder.build(workflow)?);
                        }
                    }
                }
                // NOTE: GHA docs are unclear on whether runner groups always
                // imply self-hosted runners or not. All examples suggest that they
                // do, but I'm not sure.
                // See: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
                // See: https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job
                LoE::Literal(RunsOn::Group { .. }) => {
                    let fixes = Self::get_self_hosted_fixes(job_id);

                    let mut finding_builder = Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Unknown)
                        .persona(Persona::Auditor)
                        .add_location(
                            job.location()
                                .primary()
                                .with_keys(&["runs-on".into()])
                                .annotated("runner group implies self-hosted runner"),
                        );

                    // Add fixes for runner group usage
                    for fix in fixes {
                        finding_builder = finding_builder.fix(fix);
                    }

                    results.push(finding_builder.build(workflow)?);
                }
                // The entire `runs-on:` is an expression, which may or may
                // not be a self-hosted runner when expanded, like above.
                LoE::Expr(exp) => {
                    let Ok(matrix) = Matrix::try_from(&job) else {
                        continue;
                    };

                    let expansions = matrix.expanded_values;

                    let self_hosted = expansions.iter().any(|(path, expansion)| {
                        exp.as_bare() == path && expansion.contains("self-hosted")
                    });

                    if self_hosted {
                        let fixes = Self::get_self_hosted_fixes(job_id);

                        let mut finding_builder = Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Unknown)
                            .persona(Persona::Auditor)
                            .add_location(
                                job.location()
                                    .with_keys(&["strategy".into()])
                                    .annotated("matrix declares self-hosted runner"),
                            )
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(&["runs-on".into()])
                                    .annotated("expression may expand into a self-hosted runner"),
                            );

                        // Add fixes for matrix-based self-hosted runner usage
                        for fix in fixes {
                            finding_builder = finding_builder.fix(fix);
                        }

                        results.push(finding_builder.build(workflow)?);
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_hosted_replacement_fix() {
        let fix = SelfHostedRunner::create_github_hosted_replacement_fix("test-job");

        assert_eq!(
            fix.title,
            "Replace self-hosted runner with GitHub-hosted runner"
        );
        assert!(
            fix.description
                .contains("GitHub-hosted runners are more secure")
        );
        assert!(fix.description.contains("ephemeral and isolated"));
    }

    #[test]
    fn test_manual_approval_fix() {
        let fix = SelfHostedRunner::create_manual_approval_fix();

        assert_eq!(fix.title, "Add manual approval for external contributors");
        assert!(fix.description.contains("manual approval for workflows"));
        assert!(fix.description.contains("Settings > Actions > General"));
    }

    #[test]
    fn test_ephemeral_runner_fix() {
        let fix = SelfHostedRunner::create_ephemeral_runner_fix();

        assert_eq!(fix.title, "Use ephemeral (just-in-time) runners");
        assert!(fix.description.contains("just-in-time for each job"));
        assert!(fix.description.contains("destroyed immediately afterwards"));
    }

    #[test]
    fn test_private_repository_fix() {
        let fix = SelfHostedRunner::create_private_repository_fix();

        assert_eq!(
            fix.title,
            "Use self-hosted runners only on private repositories"
        );
        assert!(fix.description.contains("only on private repositories"));
        assert!(fix.description.contains("Public repositories expose"));
    }

    #[test]
    fn test_runner_conditions_fix() {
        let fix = SelfHostedRunner::create_runner_conditions_fix("test-job");

        assert_eq!(
            fix.title,
            "Add conditions to restrict self-hosted runner usage"
        );
        assert!(fix.description.contains("conditional logic"));
        assert!(
            fix.description
                .contains("trusted events or specific branches")
        );
    }

    #[test]
    fn test_get_self_hosted_fixes_count() {
        let fixes = SelfHostedRunner::get_self_hosted_fixes("test-job");

        // Should return 5 fixes: replacement, manual approval, ephemeral, private repo, conditions
        assert_eq!(fixes.len(), 5);

        let titles: Vec<&str> = fixes.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.contains(&"Replace self-hosted runner with GitHub-hosted runner"));
        assert!(titles.contains(&"Add manual approval for external contributors"));
        assert!(titles.contains(&"Use ephemeral (just-in-time) runners"));
        assert!(titles.contains(&"Use self-hosted runners only on private repositories"));
        assert!(titles.contains(&"Add conditions to restrict self-hosted runner usage"));
    }

    #[test]
    fn test_github_hosted_replacement_fix_application() {
        let fix = SelfHostedRunner::create_github_hosted_replacement_fix("test-job");

        let yaml_content = r#"
jobs:
  test-job:
    runs-on: self-hosted
    steps:
      - run: echo "hello"
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Should replace self-hosted with ubuntu-latest
        assert!(result.contains("runs-on: ubuntu-latest"));
        assert!(!result.contains("runs-on: self-hosted"));
    }

    #[test]
    fn test_runner_conditions_fix_application() {
        let fix = SelfHostedRunner::create_runner_conditions_fix("test-job");

        let yaml_content = r#"
jobs:
  test-job:
    runs-on: self-hosted
    steps:
      - run: echo "hello"
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Should add an 'if' condition to the job
        assert!(result.contains(
            "if: github.repository_owner == 'trusted-org' && github.event_name != 'pull_request'"
        ));
        assert!(result.contains("runs-on: self-hosted")); // Original runs-on should remain
    }

    #[test]
    fn test_guidance_fixes_dont_modify_content() {
        let manual_fix = SelfHostedRunner::create_manual_approval_fix();
        let ephemeral_fix = SelfHostedRunner::create_ephemeral_runner_fix();
        let private_fix = SelfHostedRunner::create_private_repository_fix();

        let yaml_content = r#"
jobs:
  test-job:
    runs-on: self-hosted
    steps:
      - run: echo "hello"
"#;

        // Guidance fixes should return unchanged content
        let manual_result = manual_fix.apply_to_content(yaml_content).unwrap().unwrap();
        let ephemeral_result = ephemeral_fix
            .apply_to_content(yaml_content)
            .unwrap()
            .unwrap();
        let private_result = private_fix.apply_to_content(yaml_content).unwrap().unwrap();

        assert_eq!(manual_result, yaml_content);
        assert_eq!(ephemeral_result, yaml_content);
        assert_eq!(private_result, yaml_content);
    }
}
