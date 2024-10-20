//! Functionality for registering and managing the lifecycles of
//! audits.

use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, Result};

use crate::{audit::WorkflowAudit, models::Workflow};

pub(crate) struct WorkflowRegistry {
    pub(crate) workflows: HashMap<String, Workflow>,
}

impl WorkflowRegistry {
    pub(crate) fn new() -> Self {
        Self {
            workflows: Default::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.workflows.len()
    }

    pub(crate) fn register_workflow(&mut self, path: &Path) -> Result<()> {
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("invalid workflow: no filename component"))?
            .to_str()
            .ok_or_else(|| anyhow!("invalid workflow: path is not UTF-8"))?
            .to_string();

        if self.workflows.contains_key(&name) {
            return Err(anyhow!("can't register {name} more than once"));
        }

        self.workflows.insert(name, Workflow::from_file(path)?);

        Ok(())
    }

    pub(crate) fn iter_workflows(&self) -> std::collections::hash_map::Iter<'_, String, Workflow> {
        self.workflows.iter()
    }

    pub(crate) fn get_workflow(&self, name: &str) -> &Workflow {
        self.workflows
            .get(name)
            .expect("API misuse: requested an un-registered workflow")
    }
}

pub(crate) struct AuditRegistry {
    pub(crate) workflow_audits: HashMap<&'static str, Box<dyn WorkflowAudit>>,
}

impl AuditRegistry {
    pub(crate) fn new() -> Self {
        Self {
            workflow_audits: Default::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.workflow_audits.len()
    }

    pub(crate) fn register_workflow_audit(
        &mut self,
        ident: &'static str,
        audit: Box<dyn WorkflowAudit>,
    ) {
        self.workflow_audits.insert(ident, audit);
    }

    pub(crate) fn iter_workflow_audits(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, &str, Box<dyn WorkflowAudit>> {
        self.workflow_audits.iter_mut()
    }
}
