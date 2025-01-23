//! `tree-sitter` helpers for extracting and locating concrete features
//! in the original YAML.

use anyhow::Result;

use super::{Comment, ConcreteLocation, Feature, SymbolicLocation};

pub(crate) struct Locator {}

impl Locator {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn concretize<'w>(
        &self,
        document: &'w impl AsRef<yamlpath::Document>,
        location: &SymbolicLocation,
    ) -> Result<Feature<'w>> {
        let document = document.as_ref();

        // If we don't have a path into the workflow, all
        // we have is the workflow itself.
        let feature = if location.route.components.is_empty() {
            document.root()
        } else {
            let mut builder = yamlpath::QueryBuilder::new();

            for component in &location.route.components {
                builder = match component {
                    super::RouteComponent::Key(key) => builder.key(key.clone()),
                    super::RouteComponent::Index(idx) => builder.index(*idx),
                }
            }

            let query = builder.build();

            document.query(&query)?
        };

        Ok(Feature {
            location: ConcreteLocation::from(&feature.location),
            feature: document.extract_with_leading_whitespace(&feature),
            comments: document
                .feature_comments(&feature)
                .into_iter()
                .map(Comment)
                .collect(),
        })
    }
}
