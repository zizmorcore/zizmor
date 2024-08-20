use crate::{
    finding::Finding,
    models::{AuditOptions, Workflow},
};
use anyhow::Result;

pub(crate) mod artipacked;
pub(crate) mod impostor_commits;
pub(crate) mod pull_request_target;

pub(crate) trait WorkflowAudit {
    const AUDIT_IDENT: &'static str;
    fn audit(options: &AuditOptions, workflow: &Workflow) -> Result<Vec<Finding>>;
}
