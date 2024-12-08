//! `tree-sitter` helpers for extracting and locating concrete features
//! in the original YAML.

use anyhow::Result;

use super::{Comment, ConcreteLocation, Feature, SymbolicLocation};
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
        // If we don't have a path into the workflow, all
        // we have is the workflow itself.
        let (feature, parent_feature) = if location.route.components.is_empty() {
            (workflow.document.root(), workflow.document.root())
        } else {
            let mut builder = yamlpath::QueryBuilder::new();

            for component in &location.route.components {
                builder = match component {
                    super::RouteComponent::Key(key) => builder.key(key.clone()),
                    super::RouteComponent::Index(idx) => builder.index(*idx),
                }
            }

            let query = builder.build();
            tracing::trace!(
                "querying {workflow}: {query:?}",
                workflow = workflow.filename()
            );

            let parent_feature = if let Some(parent) = query.parent() {
                workflow.document.query(&parent)?
            } else {
                workflow.document.root()
            };

            (workflow.document.query(&query)?, parent_feature)
        };

        Ok(Feature {
            location: ConcreteLocation::from(&feature.location),
            parent_location: ConcreteLocation::from(&parent_feature.location),
            feature: workflow.document.extract_with_leading_whitespace(&feature),
            comments: workflow
                .document
                .feature_comments(&feature)
                .into_iter()
                .map(Comment)
                .collect(),
            parent_feature: workflow
                .document
                .extract_with_leading_whitespace(&parent_feature),
        })
    }
}
