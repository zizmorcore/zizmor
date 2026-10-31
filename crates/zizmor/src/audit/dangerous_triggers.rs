use std::sync::LazyLock;

use itertools::Itertools;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::coordinate::ActionCoordinate;
use crate::models::workflow::{Job, Workflow};
use crate::state::AuditState;

#[allow(clippy::unwrap_used)]
static ACTIONS_LABELER: LazyLock<ActionCoordinate> =
    LazyLock::new(|| ActionCoordinate::NotConfigurable("actions/labeler".parse().unwrap()));

#[allow(clippy::unwrap_used)]
static GITHUB_BRANCH_DEPLOY: LazyLock<ActionCoordinate> =
    LazyLock::new(|| ActionCoordinate::NotConfigurable("github/branch-deploy".parse().unwrap()));

pub(crate) struct DangerousTriggers;

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

impl DangerousTriggers {
    fn is_labeler_exception(workflow: &Workflow) -> bool {
        // If a workflow has exactly one job, that job has exactly one step,
        // and that step is `actions/labeler`, then we suppress any
        // finding for `pull_request_target`. Our rationale for this is
        // that it's a blessed and presumed-secure use of an otherwise
        // fundamentally insecure trigger.
        if let Ok(Job::NormalJob(job)) = workflow.jobs().exactly_one()
            && let Ok(step) = job.steps().exactly_one()
            && ACTIONS_LABELER.usage(&step).is_some()
        {
            true
        } else {
            false
        }
    }

    fn is_branch_deploy_exception(workflow: &Workflow) -> bool {
        // If a workflow has exactly one job, that job has exactly one step,
        // and that step is `github/branch-deploy`, then we suppress any finding
        // for `issue_comment`. Like the `pull_request_target` exemption above,
        // the rationale here is that it's a blessed first-party action
        // and is presumed to be secure on an otherwise insecure trigger.
        if let Ok(Job::NormalJob(job)) = workflow.jobs().exactly_one()
            && let Ok(step) = job.steps().exactly_one()
            && GITHUB_BRANCH_DEPLOY.usage(&step).is_some()
        {
            true
        } else {
            false
        }
    }
}

#[async_trait::async_trait]
impl Audit for DangerousTriggers {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // Bug #2448: we dropped the entire `on:` span when we switched to more
        // precise trigger spans, so users who had an ignore comment elsewhere in
        // the `on:` block stopped getting suppressions.
        let on_location = workflow.location().with_keys(["on".into()]);

        if let Some(location) = workflow.pull_request_target()
            && !Self::is_labeler_exception(workflow)
        {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(on_location.clone().hidden())
                    .add_location(
                        location
                            .primary()
                            .annotated("pull_request_target is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        if let Some(location) = workflow.workflow_run() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(on_location.clone().hidden())
                    .add_location(
                        location
                            .primary()
                            .annotated("workflow_run is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        if let Some(location) = workflow.issue_comment()
            && !Self::is_branch_deploy_exception(workflow)
        {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(on_location.clone().hidden())
                    .add_location(
                        location
                            .primary()
                            .annotated("issue_comment is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        Ok(findings)
    }
}
