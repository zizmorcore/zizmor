use super::{audit_meta, Audit, AuditLoadError};
use crate::{
    config::Config,
    finding::{Confidence, Finding, Severity},
    models::workflow::Workflow,
    state::AuditState,
};
use anyhow::Result;
use github_actions_models::{common::expr::LoE, workflow::Concurrency};

// NOTE:
// #[derive(Deserialize, Debug)]
// #[serde(rename_all = "kebab-case", untagged)]
// pub enum Concurrency {
//     Bare(String),
//     Rich {
//         group: String,
//         #[serde(default)]
//         cancel_in_progress: BoE,
//     },
// }

pub(crate) struct ConcurrencyCancel;

audit_meta!(
    ConcurrencyCancel,
    "concurrency-cancel",
    "cancel running jobs when they are re-triggered"
);

impl Audit for ConcurrencyCancel {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];
        match &workflow.concurrency {
            Some(Concurrency::Rich {
                group,
                cancel_in_progress,
            }) => {
                match &cancel_in_progress {
                    LoE::Literal(cancel) => {
                        println!("cancel-in-progress is set");
                        // FIXME: It's saying false even when true
                        if !cancel {
                            findings.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(Severity::Medium)
                                    .add_location(
                                        workflow
                                            .location()
                                            .primary()
                                            .annotated("cancel_in_progress set to false"),
                                    )
                                    .build(workflow)?,
                            );
                        };
                    }
                    // TODO: Account for case of an expression, too
                    LoE::Expr(_) => println!("TODO: expression case"),
                };
                println!("group: {group}")
                // TODO: Also need to check group
            }
            Some(Concurrency::Bare(_)) => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .annotated("concurrency is missing cancel-in-progress"),
                        )
                        .build(workflow)?,
                );
            }
            None => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .annotated("missing concurrency setting"),
                        )
                        .build(workflow)?,
                );
            }
        }

        Ok(findings)
    }
}
