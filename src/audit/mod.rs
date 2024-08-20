use crate::{
    finding::Finding,
    models::{AuditConfig, Workflow},
};
use anyhow::Result;

pub(crate) mod artipacked;
pub(crate) mod impostor_commit;
pub(crate) mod pull_request_target;

pub(crate) trait WorkflowAudit<'a> {
    const AUDIT_IDENT: &'static str;

    fn new(config: AuditConfig<'a>) -> Result<Self>
    where
        Self: Sized;
    async fn audit(&self, workflow: &Workflow) -> Result<Vec<Finding>>;
}
