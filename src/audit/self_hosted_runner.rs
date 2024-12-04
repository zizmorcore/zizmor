//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use crate::{
    finding::{Confidence, Persona, Severity},
    AuditState,
};

use super::{audit_meta, WorkflowAudit};
use crate::models::Matrix;
use anyhow::Result;
use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::{job::RunsOn, Job},
};

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

impl WorkflowAudit for SelfHostedRunner {
    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> Result<Vec<crate::finding::Finding<'w>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = *job else {
                continue;
            };

            match &normal.runs_on {
                LoE::Literal(RunsOn::Target(labels)) => {
                    {
                        let Some(label) = labels.first() else {
                            continue;
                        };

                        if label == "self-hosted" {
                            // All self-hosted runners start with the 'self-hosted'
                            // label followed by any specifiers.
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(Severity::Unknown)
                                    .persona(Persona::Auditor)
                                    .add_location(
                                        job.location()
                                            .with_keys(&["runs-on".into()])
                                            .annotated("self-hosted runner used here"),
                                    )
                                    .build(workflow)?,
                            );
                        } else if ExplicitExpr::from_curly(label).is_some() {
                            // The job might also have its runner expanded via an
                            // expression. Long-term we should perform this evaluation
                            // to increase our confidence, but for now we flag it as
                            // potentially expanding to self-hosted.
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::Low)
                                    .severity(Severity::Unknown)
                                    .persona(Persona::Auditor)
                                    .add_location(
                                        job.location().with_keys(&["runs-on".into()]).annotated(
                                            "expression may expand into a self-hosted runner",
                                        ),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                // NOTE: GHA docs are unclear on whether runner groups always
                // imply self-hosted runners or not. All examples suggest that they
                // do, but I'm not sure.
                // See: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
                // See: https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job
                LoE::Literal(RunsOn::Group { .. }) => results.push(
                    Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Unknown)
                        .persona(Persona::Auditor)
                        .add_location(
                            job.location()
                                .with_keys(&["runs-on".into()])
                                .annotated("runner group implies self-hosted runner"),
                        )
                        .build(workflow)?,
                ),
                // The entire `runs-on:` is an expression, which may or may
                // not be a self-hosted runner when expanded, like above.
                LoE::Expr(exp) => {
                    let matrix = Matrix::try_from(&job)?;

                    let expansions = matrix.expand_values();

                    let self_hosted = expansions.iter().any(|(path, expansion)| {
                        exp.as_bare() == path && expansion.contains("self-hosted")
                    });

                    if self_hosted {
                        results.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Unknown)
                                .persona(Persona::Auditor)
                                .add_location(
                                    job.location()
                                        .with_keys(&["strategy".into()])
                                        .annotated("matrix declares self-hosted runner"),
                                )
                                .add_location(
                                    job.location().with_keys(&["runs-on".into()]).annotated(
                                        "expression may expand into a self-hosted runner",
                                    ),
                                )
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::self_hosted_runner::SelfHostedRunner;
    use crate::audit::WorkflowAudit;
    use crate::models::Workflow;
    use crate::state::{AuditState, Caches};
    use camino::Utf8Path;
    use indoc::indoc;
    use std::fs;
    use temp_dir::TempDir;
    use uuid::Uuid;

    fn parsed_workflow(contents: &str) -> Workflow {
        let temp_dir = TempDir::new().expect("Cant create temp dir");
        let file_name = Uuid::new_v4().to_string();
        let target = temp_dir.path().join(format!("{}.yml", file_name));
        fs::write(&target, contents).expect("Failed to write content to sut markdown file");
        let utf8_path = Utf8Path::from_path(target.as_path()).unwrap();
        Workflow::from_file(utf8_path).expect("invalid GitHub Actions workflow")
    }

    fn self_hosted_runner_audit() -> SelfHostedRunner {
        let audit_state = AuditState {
            no_online_audits: true,
            gh_token: None,
            caches: Caches::new(),
        };

        SelfHostedRunner::new(audit_state).expect("invalid audit state")
    }

    #[test]
    fn self_hosted_on_labels() {
        let workflow = indoc! {"
            on:
              push:

            jobs:
              whops:
                runs-on: [self-hosted, linux, arm64]

                steps:
                  - run: echo \"hello from a self-hosted runner\"
        "};

        let auditable = parsed_workflow(workflow);

        let sut = self_hosted_runner_audit();

        let findings = sut.audit(&auditable).expect("cannot audit workflow");

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn self_hosted_from_runner_groups() {
        let workflow = indoc! {"
            on:
              push:

            jobs:
              whops:
                runs-on:
                    group: ubuntu-runners

                steps:
                  - run: echo \"hello from a self-hosted runner\"
        "};

        let auditable = parsed_workflow(workflow);

        let sut = self_hosted_runner_audit();

        let findings = sut.audit(&auditable).expect("cannot audit workflow");

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn self_hosted_within_expanded_matrix_dimension() {
        let workflow = indoc! {"
            on:
              push:

            jobs:
              whops:
                runs-on: ${{ matrix.os }}

                strategy:
                    matrix:
                        os: [self-hosted, ubuntu-latest]
                steps:
                  - run: echo \"hello from a self-hosted runner\"
        "};

        let auditable = parsed_workflow(workflow);

        let sut = self_hosted_runner_audit();

        let findings = sut.audit(&auditable).expect("cannot audit workflow");

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn self_hosted_within_expanded_matrix_inclusion() {
        let workflow = indoc! {"
            on:
              push:

            jobs:
              whops:
                runs-on: ${{ matrix.os }}

                strategy:
                    matrix:
                        os: [macOS-latest, ubuntu-latest]
                        include:
                            - os: self-hosted
                steps:
                  - run: echo \"hello from a self-hosted runner\"
        "};

        let auditable = parsed_workflow(workflow);

        let sut = self_hosted_runner_audit();

        let findings = sut.audit(&auditable).expect("cannot audit workflow");

        assert_eq!(findings.len(), 1);
    }
}
