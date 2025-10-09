use anyhow::Result;
use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    config::Config,
    finding::{Confidence, Finding, Persona, Severity, location::Locatable as _},
    models::workflow::Workflow,
    state::AuditState,
};
use github_actions_models::workflow::Concurrency;

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
            Some(concurrency) => {
                findings.push(
                    Self::finding()
                        .build(workflow)?
                    // TODO: Check for cancel
                );
            },
            None => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .annotated("missing concurrency")
                        )
                        .build(workflow)?
                );
            }
        }

        Ok(findings)
    }
}
