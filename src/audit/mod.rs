use crate::{
    finding::{Finding, FindingBuilder},
    models::{AuditConfig, Workflow},
};
use anyhow::Result;

pub(crate) mod artipacked;
pub(crate) mod impostor_commit;
pub(crate) mod pull_request_target;
pub(crate) mod ref_confusion;
pub(crate) mod use_trusted_publishing;

pub(crate) trait WorkflowAudit<'a> {
    fn finding<'w>() -> FindingBuilder<'w>
    where
        Self: Sized,
    {
        FindingBuilder::new(Self::ident())
    }

    fn ident() -> &'static str
    where
        Self: Sized;

    fn new(config: AuditConfig<'a>) -> Result<Self>
    where
        Self: Sized;

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>>;
}
