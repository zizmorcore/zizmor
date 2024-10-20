//! Core namespace for zizmor's audits.

use anyhow::Result;

use crate::{
    finding::{Finding, FindingBuilder},
    models::Workflow,
    state::AuditState,
};

pub(crate) mod artipacked;
pub(crate) mod dangerous_triggers;
pub(crate) mod excessive_permissions;
pub(crate) mod hardcoded_container_credentials;
pub(crate) mod impostor_commit;
pub(crate) mod known_vulnerable_actions;
pub(crate) mod ref_confusion;
pub(crate) mod self_hosted_runner;
pub(crate) mod template_injection;
pub(crate) mod use_trusted_publishing;

pub(crate) trait WorkflowAudit {
    fn finding<'w>() -> FindingBuilder<'w>
    where
        Self: Sized,
    {
        FindingBuilder::new(Self::ident(), Self::desc())
    }

    fn ident() -> &'static str
    where
        Self: Sized;

    fn desc() -> &'static str
    where
        Self: Sized;

    fn new(state: AuditState) -> Result<Self>
    where
        Self: Sized;

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>>;
}
