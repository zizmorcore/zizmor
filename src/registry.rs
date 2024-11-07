//! Functionality for registering and managing the lifecycles of
//! audits.

use std::{collections::HashMap, path::Path, process::ExitCode};

use anyhow::{anyhow, Result};

use crate::{
    audit::WorkflowAudit,
    config::Config,
    finding::{Finding, Severity},
    models::Workflow,
};

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

    /// Returns a subjective relative path for the given workflow.
    ///
    /// In general, this will be a relative path within the repository root,
    /// e.g. if zizmor was told to scan `/tmp/src` then one of the discovered
    /// workflows might be `.github/workflows/ci.yml` relative to `/tmp/src`.
    ///
    /// The exceptional case here is when zizmor is asked to scan a single
    /// workflow at some arbitrary location on disk. In that case, just
    /// the base workflow filename itself is returned.
    pub(crate) fn get_workflow_relative_path(&self, name: &str) -> &str {
        let workflow = self.get_workflow(name);
        let workflow_path = Path::new(&workflow.path);

        match workflow.path.rfind(".github/workflows") {
            Some(start) => &workflow.path[start..],
            // NOTE: Unwraps are safe since file component is always present and
            // all paths are UTF-8 by construction.
            None => workflow_path.file_name().unwrap().to_str().unwrap(),
        }
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

/// A registry of all findings discovered during a `zizmor` run.
pub(crate) struct FindingRegistry<'a> {
    config: &'a Config,
    ignored: Vec<Finding<'a>>,
    findings: Vec<Finding<'a>>,
    highest_severity: Option<Severity>,
}

impl<'a> FindingRegistry<'a> {
    pub(crate) fn new(config: &'a Config) -> Self {
        Self {
            config,
            ignored: Default::default(),
            findings: Default::default(),
            highest_severity: None,
        }
    }

    /// Adds one or more findings to the current findings set,
    /// filtering with the configuration in the process.
    pub(crate) fn extend(&mut self, results: Vec<Finding<'a>>) {
        // TODO: is it faster to iterate like this, or do `find_by_max`
        // and then `extend`?
        for result in results {
            if self.config.ignores(&result) {
                self.ignored.push(result);
            } else {
                if self
                    .highest_severity
                    .map_or(true, |s| result.determinations.severity > s)
                {
                    self.highest_severity = Some(result.determinations.severity);
                }

                self.findings.push(result);
            }
        }
    }

    /// All non-filtered findings.
    pub(crate) fn findings(&self) -> &[Finding<'a>] {
        &self.findings
    }

    /// All filtered findings.
    pub(crate) fn ignored(&self) -> &[Finding<'a>] {
        &self.ignored
    }
}

impl From<FindingRegistry<'_>> for ExitCode {
    fn from(value: FindingRegistry<'_>) -> Self {
        match value.highest_severity {
            Some(sev) => match sev {
                Severity::Unknown => ExitCode::from(10),
                Severity::Informational => ExitCode::from(11),
                Severity::Low => ExitCode::from(12),
                Severity::Medium => ExitCode::from(13),
                Severity::High => ExitCode::from(14),
            },
            None => ExitCode::SUCCESS,
        }
    }
}
