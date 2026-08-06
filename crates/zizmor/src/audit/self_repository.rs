use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Fix, FixDisposition, Severity,
        location::{Locatable, Routable as _},
    },
    models::{
        AsDocument, StepCommon as _,
        action::CompositeStep,
        workflow::{ReusableWorkflowCallJob, Step},
    },
    state::AuditState,
};

audit_meta!(
    SelfRepository,
    "self-repository",
    "use GitHub's dedicated self-repository syntax"
);

pub(crate) struct SelfRepository;

impl SelfRepository {
    async fn audit_common<'a, 'doc, P>(
        &self,
        parent: &'a P,
        uses: &'doc Uses,
    ) -> Result<Vec<Finding<'doc>>, AuditError>
    where
        P: AsDocument<'a, 'doc> + Locatable<'doc>,
    {
        let mut findings = vec![];

        let Uses::Local(uses) = uses else {
            return Ok(findings);
        };

        if !uses.is_self_repository() {
            findings.push(
                Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .add_location(parent.location_with_grip())
                    .add_location(
                        parent
                            .location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("use '$/...' instead of './...'")
                            .primary(),
                    )
                    .fix(Fix {
                        title: "rewrite './...' to '$/...'".to_string(),
                        key: parent.location().key,
                        disposition: FixDisposition::Safe,
                        patches: vec![Patch {
                            route: parent.route().with_key("uses"),
                            operation: Op::RewriteFragment {
                                from: Subfeature::new(0, uses.raw()),
                                to: format!("${path}", path = &uses.raw()[1..]).into(),
                            },
                        }],
                    })
                    .build(parent)?,
            );
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for SelfRepository {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let (parent, uses) = (job, &job.uses);
        self.audit_common(parent, uses).await
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let (parent, uses) = match step.uses() {
            Some(uses) => (step, uses),
            None => return Ok(vec![]),
        };

        self.audit_common(parent, uses).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let (parent, uses) = match step.uses() {
            Some(uses) => (step, uses),
            None => return Ok(vec![]),
        };

        self.audit_common(parent, uses).await
    }
}
