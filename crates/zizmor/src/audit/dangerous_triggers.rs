use std::ops::Deref;
use std::sync::LazyLock;

use github_actions_expressions::{
    Expr, SpannedExpr, call::Call, context::ContextPattern, literal::Literal,
};
use github_actions_models::common::If;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity, location::Locatable as _};
use crate::models::workflow::{Job, NormalJob, Workflow};
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

const TRUSTED_AUTHOR_ASSOCIATIONS: &[&str] = &["OWNER", "MEMBER", "COLLABORATOR"];

/// Recursively collects all string literals from an expression tree.
fn collect_string_literals<'a>(expr: &'a SpannedExpr<'a>) -> Vec<&'a str> {
    let mut literals = vec![];

    match expr.deref() {
        Expr::Literal(Literal::String(s)) => {
            literals.push(s.as_ref());
        }
        Expr::BinOp { lhs, op: _, rhs } => {
            literals.extend(collect_string_literals(lhs));
            literals.extend(collect_string_literals(rhs));
        }
        Expr::UnOp { op: _, expr } => {
            literals.extend(collect_string_literals(expr));
        }
        Expr::Call(Call { func: _, args }) => {
            for arg in args {
                literals.extend(collect_string_literals(arg));
            }
        }
        _ => {}
    }

    literals
}

/// Checks whether a job has an `if:` condition that gates on
/// `github.event.comment.author_association` against a trusted role
/// (OWNER, MEMBER, or COLLABORATOR).
fn has_author_association_guard(job: &NormalJob<'_>) -> bool {
    let Some(If::Expr(expr_str)) = &job.r#if else {
        return false;
    };

    let bare = ExtractedExpr::new(expr_str).as_bare();
    let Ok(parsed) = Expr::parse(bare) else {
        return false;
    };

    let has_context = parsed
        .contexts()
        .iter()
        .any(|(context, _)| AUTHOR_ASSOCIATION_CONTEXT.matches(context));

    if !has_context {
        return false;
    }

    let literals = collect_string_literals(&parsed);
    literals.iter().any(|lit| {
        TRUSTED_AUTHOR_ASSOCIATIONS
            .iter()
            .any(|trusted| trusted.eq_ignore_ascii_case(lit))
    })
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

        if workflow.has_issue_comment() {
            for job in workflow.jobs() {
                if let Job::NormalJob(normal) = job
                    && !has_author_association_guard(&normal)
                {
                    findings.push(
                        Self::finding()
                            .confidence(Confidence::Medium)
                            .severity(Severity::Medium)
                            .add_location(
                                normal.location().primary().annotated(
                                    "issue_comment job lacks an \
                                     author_association guard",
                                ),
                            )
                            .build(workflow)?,
                    );
                }
            }
        }

        Ok(findings)
    }
}
