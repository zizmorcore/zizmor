//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will always refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use anyhow::anyhow;
use github_actions_models::common::Uses;
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
use crate::finding::Finding;
use crate::finding::location::Locatable as _;
use crate::models::pre_commit::PreCommitConfig;
use crate::models::repo_ref::RepoRef;
use crate::models::{StepCommon as _, action::CompositeStep};
use crate::{
    finding::{Confidence, Severity},
    github,
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
    async fn confusable(&self, uses: impl Into<RepoRef<'_>>) -> Result<bool, AuditError> {
        let uses = uses.into();

        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(false);
        };

        let Some(slug) = uses.slug() else {
            return Ok(false);
        };

        // TODO: use a tokio JoinSet here?
        let branches_match = self
            .client
            .has_branch(&slug, sym_ref)
            .await
            .map_err(Self::err)?;
        let tags_match = self
            .client
            .has_tag(&slug, sym_ref)
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
            .map(|client| Self { client })
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

    async fn audit_pre_commit_config<'doc>(
        &self,
        pre_commit: &'doc PreCommitConfig,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for repo in pre_commit.repos() {
            let Some(remote) = repo.repo() else {
                continue;
            };

            if self.confusable(remote).await? {
                findings.push(
                    Self::finding()
                        .severity(Severity::Medium)
                        .confidence(Confidence::High)
                        .add_location(
                            repo.location()
                                .with_keys(["repo".into()])
                                .subfeature(Subfeature::new(0, remote.repo.as_str()))
                                .annotated("this repo"),
                        )
                        .add_location(
                            repo.location()
                                .primary()
                                .with_keys(["rev".into()])
                                .subfeature(Subfeature::new(0, remote.rev.as_str()))
                                .annotated(REF_CONFUSION_ANNOTATION),
                        )
                        .build(pre_commit)?,
                )
            }
        }

        Ok(findings)
    }
}
