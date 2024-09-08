//! `tree-sitter` helpers for extracting and locating concrete features
//! in the original YAML.

use anyhow::Result;

use super::{ConcreteLocation, Feature, WorkflowLocation};
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
        let mut path = vec![];

        if let Some(job) = &location.job {
            path.extend([
                yamlpath::Component::Key("jobs".into()),
                yamlpath::Component::Key(job.id.into()),
            ]);

            if let Some(step) = &job.step {
                path.extend([
                    yamlpath::Component::Key("steps".into()),
                    yamlpath::Component::Index(step.index),
                ]);
            } else if let Some(key) = &job.key {
                path.push(yamlpath::Component::Key(key.to_string()));
            }
        } else {
            // Non-job top-level key.
            path.push(yamlpath::Component::Key(
                location
                    .key
                    .expect("API misuse: must provide key if job is not specified")
                    .to_string(),
            ));
        }

        // Infallible: we always have at least one path component above.
        let query = yamlpath::Query::new(path).unwrap();
        let feature = workflow.document.query(&query)?;

        Ok(Feature {
            location: ConcreteLocation::from(&feature.location),
            feature: workflow.document.extract(&feature),
        })
    }
}
