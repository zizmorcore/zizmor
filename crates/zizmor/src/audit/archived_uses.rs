use std::sync::LazyLock;

use fst::Set;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, FindingBuilder, Persona, Severity, location::Locatable},
    models::{
        StepCommon as _,
        action::CompositeStep,
        workflow::{ReusableWorkflowCallJob, Step},
    },
    state::AuditState,
};

static ARCHIVED_REPOS_FST: LazyLock<Set<&[u8]>> = LazyLock::new(|| {
    fst::Set::new(include_bytes!(concat!(env!("OUT_DIR"), "/archived-repos.fst")).as_slice())
        .expect("couldn't initialize archived repos FST")
});

pub(crate) struct ArchivedUses;

audit_meta!(
    ArchivedUses,
    "archived-uses",
    "action or reusable workflow from archived repository"
);

impl ArchivedUses {
    pub(crate) fn uses_is_archived<'doc>(uses: &RepositoryUses) -> Option<FindingBuilder<'doc>> {
        // TODO: Annoying that we need to allocate for case normalization here; can we use an
        // automaton to search the FST case-insensitively?
        let normalized = format!(
            "{owner}/{repo}",
            owner = uses.owner().to_lowercase(),
            repo = uses.repo().to_lowercase()
        );

        ARCHIVED_REPOS_FST.contains(normalized.as_bytes()).then(|| {
            Self::finding()
                .confidence(Confidence::High)
                .severity(Severity::Medium)
                .persona(Persona::Regular)
        })
    }
}

#[async_trait::async_trait]
impl Audit for ArchivedUses {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses()
            && let Some(finding) = Self::uses_is_archived(uses)
        {
            findings.push(
                finding
                    .add_location(step.location_with_grip())
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated("repository is archived")
                            .primary(),
                    )
                    .build(step)?,
            )
        }

        Ok(findings)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses()
            && let Some(finding) = Self::uses_is_archived(uses)
        {
            findings.push(
                finding
                    .add_location(step.location_with_grip())
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated("repository is archived")
                            .primary(),
                    )
                    .build(step)?,
            )
        }

        Ok(findings)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Uses::Repository(uses) = &job.uses
            && let Some(finding) = Self::uses_is_archived(uses)
        {
            findings.push(
                finding
                    .add_location(job.location_with_grip())
                    .add_location(
                        job.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated("repository is archived")
                            .primary(),
                    )
                    .build(job)?,
            )
        }

        Ok(findings)
    }
}
