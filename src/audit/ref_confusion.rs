//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will alway refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use std::ops::Deref;

use anyhow::Result;
use github_actions_models::workflow::{job::StepBody, Job};

use crate::{
    finding::{Confidence, Severity},
    github_api,
    models::{AuditConfig, Uses},
};

use super::WorkflowAudit;

const REF_CONFUSION_ANNOTATION: &str =
    "uses a ref that's provided by both the branch and tag namespaces";

pub(crate) struct RefConfusion<'a> {
    pub(crate) _config: AuditConfig<'a>,
    client: github_api::Client,
}

impl<'a> RefConfusion<'a> {
    fn confusable(&self, uses: &Uses) -> Result<bool> {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(false);
        };

        let branches_match = self
            .client
            .list_branches(uses.owner, uses.repo)?
            .iter()
            .any(|b| b.name == sym_ref);

        let tags_match = self
            .client
            .list_tags(uses.owner, uses.repo)?
            .iter()
            .any(|t| t.name == sym_ref);

        // If both the branch and tag namespaces have a match, we have a
        // confusable ref.
        Ok(branches_match && tags_match)
    }
}

impl<'a> WorkflowAudit<'a> for RefConfusion<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "ref-confusion"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            _config: config,
            client: github_api::Client::new(config.gh_token),
        })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        log::debug!("audit: {} evaluating {}", Self::ident(), &workflow.filename);

        let mut findings = vec![];

        for job in workflow.jobs() {
            match job.deref() {
                Job::NormalJob(_) => {
                    for step in job.steps() {
                        let StepBody::Uses { uses, .. } = &step.deref().body else {
                            continue;
                        };

                        let Some(uses) = Uses::from_step(uses) else {
                            continue;
                        };

                        if self.confusable(&uses)? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::Medium)
                                    .confidence(Confidence::High)
                                    .add_location(
                                        step.location().annotated(REF_CONFUSION_ANNOTATION),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    let Some(uses) = Uses::from_reusable(&reusable.uses) else {
                        continue;
                    };

                    if self.confusable(&uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::Medium)
                                .confidence(Confidence::High)
                                .add_location(job.location().annotated(REF_CONFUSION_ANNOTATION))
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        log::debug!("audit: {} completed {}", Self::ident(), &workflow.filename);

        Ok(findings)
    }
}
