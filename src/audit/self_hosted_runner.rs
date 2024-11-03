//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "pedantic" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use crate::{
    expr::Expr,
    finding::{Confidence, Severity},
    utils::{extract_expressions, matrix_is_static},
    AuditState,
};

use anyhow::Result;
use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::{
        job::{RunsOn, Strategy},
        Job,
    },
};

use super::WorkflowAudit;

pub(crate) struct SelfHostedRunner {
    pub(crate) _state: AuditState,
}

impl WorkflowAudit for SelfHostedRunner {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "self-hosted-runner"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "runs on a self-hosted runner"
    }

    fn new(state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _state: state })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> Result<Vec<crate::finding::Finding<'w>>> {
        let mut results = vec![];

        if !self._state.config.pedantic {
            log::info!("skipping self-hosted runner checks");
            return Ok(results);
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = *job else {
                continue;
            };

            match &normal.runs_on {
                RunsOn::Target(labels) => {
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
                                .add_location(
                                    job.location()
                                        .with_keys(&["runs-on".into()])
                                        .annotated("self-hosted runner used here"),
                                )
                                .build(workflow)?,
                        );
                    } else {
                        // The label is either a well-known one, or composed
                        // of one or more expressions.
                        let exprs = extract_expressions(&label);
                        if exprs.is_empty() {
                            // No expressions mean the label is well-known,
                            // and therefore not self-hosted.
                            continue;
                        }

                        // Otherwise, look through each expression and see
                        // if it's something that does or could expand to
                        // self-hosted.
                        for expr in exprs {
                            let Ok(expr) = Expr::parse(expr.as_bare()) else {
                                log::warn!(
                                    "couldn't parse expression: {expr}",
                                    expr = expr.as_bare()
                                );
                                continue;
                            };

                            for context in expr.contexts() {
                                if !context.starts_with("matrix.") {
                                    continue;
                                }
                                if context.starts_with("matrix.") {
                                    // runs-on is controlled in part by a matrix expansion.
                                    let matrix = match &normal.strategy {
                                        Some(Strategy { matrix, .. }) => match matrix {
                                            Some(matrix) => matrix,
                                            // Missing is invalid in this context; nothing to do.
                                            None => continue,
                                        },
                                        // Missing is invalid in this context; nothing to do.
                                        None => continue,
                                    };

                                    match matrix {
                                        LoE::Expr(explicit_expr) => todo!(),
                                        LoE::Literal(_) => {
                                            todo!()
                                        }
                                    }

                                    // let Some(Strategy { matrix, .. }) = &normal.strategy else {
                                    //     // Invalid workflow; nothing to do.
                                    //     continue;
                                    // };

                                    // if !matrix_is_static(context, matrix) {}

                                    todo!()
                                } else {
                                    // Fallthrough.
                                    // For everything besides matrix expansions,
                                    // assume that a context access could potentially
                                    // expand to `self-hosted`.
                                    // TODO: Be more precise here.
                                }
                            }
                        }

                        results.push(
                            Self::finding()
                                .confidence(Confidence::Low)
                                .severity(Severity::Unknown)
                                .add_location(
                                    job.location().with_keys(&["runs-on".into()]).annotated(
                                        "runs-on specifier may expand into a self-hosted runner",
                                    ),
                                )
                                .build(workflow)?,
                        );
                    }
                }
                // NOTE: GHA docs are unclear on whether runner groups always
                // imply self-hosted runners or not. All examples suggest that they
                // do, but I'm not sure.
                // See: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
                // See: https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job
                RunsOn::Group {
                    group: _,
                    labels: _,
                } => results.push(
                    Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Unknown)
                        .add_location(
                            job.location()
                                .with_keys(&["runs-on".into()])
                                .annotated("runner group implies self-hosted runner"),
                        )
                        .build(workflow)?,
                ),
            }
        }

        Ok(results)
    }
}
