use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::workflow::Workflow,
    state::AuditState,
};
use anyhow::Result;
use github_actions_models::{common::expr::BoE, workflow::Concurrency};

pub(crate) struct ConcurrencyLimits;

audit_meta!(
    ConcurrencyLimits,
    "concurrency-limits",
    "insufficient job-level concurrency limits"
);

impl Audit for ConcurrencyLimits {
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
                group: _,
                cancel_in_progress,
            }) => {
                if let BoE::Literal(cancel) = &cancel_in_progress
                    && !cancel
                {
                    findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Low)
                            .persona(Persona::Pedantic)
                            .add_location(
                                workflow
                                    .location()
                                    .primary()
                                    .with_keys(["concurrency".into()])
                                    .annotated("cancel-in-progress set to false"),
                            )
                            .build(workflow)?,
                    );
                };
            }
            Some(Concurrency::Bare(_)) => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(Persona::Pedantic)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .with_keys(["concurrency".into()])
                                .annotated("concurrency is missing cancel-in-progress"),
                        )
                        .build(workflow)?,
                );
            }
            None => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(Persona::Pedantic)
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
