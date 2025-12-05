//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will always refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
use crate::finding::Finding;
use crate::finding::location::Locatable as _;
use crate::models::{StepCommon, action::CompositeStep};
use crate::{
    finding::{Confidence, Severity},
    github,
    models::uses::RepositoryUsesExt as _,
    state::AuditState,
};

const REF_CONFUSION_ANNOTATION: &str =
    "uses a ref that's provided by both the branch and tag namespaces";

pub(crate) struct RefConfusion {
    client: github::Client,
}

audit_meta!(
    RefConfusion,
    "ref-confusion",
    "git ref for action with ambiguous ref type"
);

impl RefConfusion {
    async fn confusable(&self, uses: &RepositoryUses) -> Result<bool, AuditError> {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(false);
        };

        // TODO: use a tokio JoinSet here?
        let branches_match = self
            .client
            .has_branch(uses.owner(), uses.repo(), sym_ref)
            .await
            .map_err(Self::err)?;
        let tags_match = self
            .client
            .has_tag(uses.owner(), uses.repo(), sym_ref)
            .await
            .map_err(Self::err)?;

        // If both the branch and tag namespaces have a match, we have a
        // confusable ref.
        Ok(branches_match && tags_match)
    }
}

#[async_trait::async_trait]
impl Audit for RefConfusion {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        state
            .gh_client
            .clone()
            .ok_or_else(|| AuditLoadError::Skip(anyhow!("can't run without a GitHub API token")))
            .map(|client| RefConfusion { client })
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    for step in normal.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.confusable(uses).await? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::Medium)
                                    .confidence(Confidence::High)
                                    .add_location(
                                        step.location()
                                            .primary()
                                            .with_keys(["uses".into()])
                                            .annotated(REF_CONFUSION_ANNOTATION),
                                    )
                                    .build(workflow)
                                    .map_err(Self::err)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    let Uses::Repository(uses) = &reusable.uses else {
                        continue;
                    };

                    if self.confusable(uses).await? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::Medium)
                                .confidence(Confidence::High)
                                .add_location(
                                    reusable
                                        .location()
                                        .primary()
                                        .annotated(REF_CONFUSION_ANNOTATION),
                                )
                                .build(workflow)
                                .map_err(Self::err)?,
                        )
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.confusable(uses).await? {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .annotated(REF_CONFUSION_ANNOTATION),
                    )
                    .build(step)
                    .map_err(Self::err)?,
            );
        }

        Ok(findings)
    }
}
