use std::sync::LazyLock;

use github_actions_expressions::{Expr, context::ContextPattern};
use github_actions_models::common::If;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity, location::Locatable as _};
use crate::models::workflow::{Job, JobCommon, NormalJob, Workflow};
use crate::state::AuditState;
use crate::utils::ExtractedExpr;

pub(crate) struct DangerousTriggers;

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

#[allow(clippy::unwrap_used)]
static AUTHOR_ASSOCIATION_CONTEXT: LazyLock<ContextPattern> = LazyLock::new(|| {
    ContextPattern::try_new("github.event.comment.author_association").expect("valid pattern")
});

/// Checks whether a job has an `if:` condition that references
/// `github.event.comment.author_association`, which restricts
/// execution to trusted actors.
fn has_author_association_guard(job: &NormalJob<'_>) -> bool {
    let Some(If::Expr(expr_str)) = &job.r#if else {
        return false;
    };

    let bare = ExtractedExpr::new(expr_str).as_bare();
    let Ok(parsed) = Expr::parse(bare) else {
        return false;
    };

    for (context, _) in parsed.contexts() {
        if AUTHOR_ASSOCIATION_CONTEXT.matches(context) {
            return true;
        }
    }

    false
}

#[async_trait::async_trait]
impl Audit for DangerousTriggers {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        if workflow.has_pull_request_target() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(["on".into()])
                            .annotated("pull_request_target is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }
        if workflow.has_workflow_run() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(["on".into()])
                            .annotated("workflow_run is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        for job in workflow.jobs() {
            if let Job::NormalJob(normal) = job {
                findings.extend(self.audit_normal_job(&normal, _config).await?);
            }
        }

        Ok(findings)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        if !job.parent().has_issue_comment() {
            return Ok(vec![]);
        }

        if has_author_association_guard(job) {
            return Ok(vec![]);
        }

        let finding = Self::finding()
            .confidence(Confidence::Medium)
            .severity(Severity::Medium)
            .add_location(
                job.location()
                    .primary()
                    .annotated(
                        "issue_comment job lacks an author_association guard",
                    ),
            )
            .build(job.parent())?;

        Ok(vec![finding])
    }
}
