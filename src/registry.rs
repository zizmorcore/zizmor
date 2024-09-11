//! Functionality for registering and managing the lifecycles of
//! audits.

use std::collections::HashMap;

use crate::audit::WorkflowAudit;

pub(crate) struct Registry<'config> {
    pub(crate) workflow_audits: HashMap<&'static str, Box<dyn WorkflowAudit<'config> + 'config>>,
}

impl<'config> Registry<'config> {
    pub(crate) fn new() -> Self {
        Self {
            workflow_audits: Default::default(),
        }
    }

    pub(crate) fn register_workflow_audit(
        &mut self,
        ident: &'static str,
        audit: Box<dyn WorkflowAudit<'config> + 'config>,
    ) {
        self.workflow_audits.insert(ident, audit);
    }

    pub(crate) fn iter_workflow_audits(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, &str, Box<dyn WorkflowAudit<'config> + 'config>>
    {
        self.workflow_audits.iter_mut()
    }
}
