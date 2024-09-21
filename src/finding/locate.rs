//! `tree-sitter` helpers for extracting and locating concrete features
//! in the original YAML.

use anyhow::Result;

use super::{ConcreteLocation, Feature, SymbolicLocation};
use crate::models::Workflow;

pub(crate) struct Locator {}

impl Locator {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn concretize<'w>(
        &self,
        workflow: &'w Workflow,
        location: &SymbolicLocation,
    ) -> Result<Feature<'w>> {
        let mut builder = yamlpath::QueryBuilder::new();

        for component in &location.route.components {
            builder = match component {
                super::RouteComponent::Key(key) => builder.key(key.clone()),
                super::RouteComponent::Index(idx) => builder.index(*idx),
            }
        }

        let query = builder.build();
        let feature = workflow.document.query(&query)?;

        Ok(Feature {
            location: ConcreteLocation::from(&feature.location),
            feature: workflow.document.extract(&feature),
        })
    }
}
