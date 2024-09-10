//! `tree-sitter` helpers for extracting and locating concrete features
//! in the original YAML.

use anyhow::Result;

use super::{ConcreteLocation, Feature, JobOrKey, WorkflowLocation};
use crate::models::Workflow;

pub(crate) struct Locator {}

impl Locator {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn concretize<'w>(
        &self,
        workflow: &'w Workflow,
        location: &WorkflowLocation,
    ) -> Result<Feature<'w>> {
        let mut builder = yamlpath::QueryBuilder::new();

        match &location.job_or_key {
            Some(JobOrKey::Job(job)) => {
                builder = builder.key("jobs").key(job.id);

                if let Some(step) = &job.step {
                    builder = builder.key("steps").index(step.index);
                } else if let Some(key) = &job.key {
                    builder = builder.key(*key);
                }
            }
            Some(JobOrKey::Key(key)) => {
                // Non-job top-level key.
                builder = builder.key(*key);
            }
            None => panic!("API misuse: workflow location must specify a top-level key or job"),
        }

        let query = builder.build();
        let feature = workflow.document.query(&query)?;

        Ok(Feature {
            location: ConcreteLocation::from(&feature.location),
            feature: workflow.document.extract(&feature),
        })
    }
}
