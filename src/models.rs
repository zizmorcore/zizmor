use anyhow::{Context, Ok, Result};
use std::{ops::Deref, path::Path};

use github_actions_models::workflow;

pub(crate) struct Workflow {
    pub(crate) filename: String,
    inner: workflow::Workflow,
}

impl Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Workflow {
    pub(crate) fn from_file<P: AsRef<Path>>(p: P) -> Result<Self> {
        let inner = serde_yaml::from_slice(&std::fs::read(p.as_ref())?)
            .with_context(|| format!("invalid GitHub Actions workflow: {:?}", p.as_ref()))?;

        // NOTE: file_name().unwrap() is safe since the read above only succeeds
        // on a well-formed filepath.
        Ok(Self {
            filename: p
                .as_ref()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            inner,
        })
    }
}

pub(crate) struct AuditOptions {
    pub(crate) pedantic: bool,
}
