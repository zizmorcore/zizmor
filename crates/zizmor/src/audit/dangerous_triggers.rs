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
    /// Tests whether the given workflow is (1) a single job, (2) that single job has a single
    /// step, and (3) that single step matches the given action coordinate.
    fn is_single_step_workflow(workflow: &Workflow, coord: &ActionCoordinate) -> bool {
        if let Ok(Job::NormalJob(job)) = workflow.jobs().exactly_one()
            && let Ok(step) = job.steps().exactly_one()
            && coord.usage(&step).is_some()
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

        // We don't flag `pull_request_target` if the only step in the workflow
        // is `actions/labeler`, since it's a blessed first-party action and
        // is presumed secure for this trigger.
        if let Some(location) = workflow.pull_request_target()
            && !Self::is_single_step_workflow(workflow, &ACTIONS_LABELER)
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

        // Similarly to `pull_request_target`, we don't flag `issue_comment` if only
        // a single blessed `github/branch-deploy` step is present.
        if let Some(location) = workflow.issue_comment()
            && !Self::is_single_step_workflow(workflow, &GITHUB_BRANCH_DEPLOY)
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
