use crate::{
    finding::Finding,
    models::{AuditConfig, Workflow},
};
use anyhow::Result;

pub(crate) mod artipacked;
pub(crate) mod impostor_commit;
pub(crate) mod pull_request_target;
pub(crate) mod ref_confusion;
pub(crate) mod use_trusted_publishing;

pub(crate) trait WorkflowAudit<'a> {
    fn ident() -> &'static str
    where
        Self: Sized;

    fn new(config: AuditConfig<'a>) -> Result<Self>
    where
        Self: Sized;
    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>>;
}
