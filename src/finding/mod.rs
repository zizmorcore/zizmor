//! Models and APIs for handling findings and their locations.

use std::borrow::Cow;

use anyhow::Result;
use clap::ValueEnum;
use locate::Locator;
use serde::Serialize;
use terminal_link::Link;

use crate::models::{Job, Step, Workflow};

pub(crate) mod locate;

// TODO: Traits + more flexible models here.

#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, ValueEnum,
)]
pub(crate) enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, ValueEnum,
)]
pub(crate) enum Severity {
    #[default]
    Unknown,
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct StepLocation<'w> {
    pub(crate) index: usize,
    pub(crate) id: Option<&'w str>,
    pub(crate) name: Option<&'w str>,
}

impl<'w> From<&Step<'w>> for StepLocation<'w> {
    fn from(step: &Step<'w>) -> Self {
        Self {
            index: step.index,
            id: step.id.as_deref(),
            name: step.name.as_deref(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub(crate) enum RouteComponent<'w> {
    Key(Cow<'w, str>),
    Index(usize),
}

impl<'w> From<usize> for RouteComponent<'w> {
    fn from(value: usize) -> Self {
        Self::Index(value)
    }
}

impl<'w> From<&'w str> for RouteComponent<'w> {
    fn from(value: &'w str) -> Self {
        Self::Key(Cow::Borrowed(value))
    }
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Route<'w> {
    components: Vec<RouteComponent<'w>>,
}

impl<'w> Route<'w> {
    pub(crate) fn new() -> Route<'w> {
        Self {
            components: Default::default(),
        }
    }

    fn with_keys(&self, keys: &[RouteComponent<'w>]) -> Route<'w> {
        let mut components = self.components.clone();
        components.extend(keys.iter().cloned());
        Route { components }
    }
}

/// Represents a symbolic workflow location.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct SymbolicLocation<'w> {
    /// The name of the workflow, as it appears in the workflow registry.
    pub(crate) name: &'w str,

    /// An annotation for this location.
    pub(crate) annotation: String,

    /// An OSC 8 rendered link for the location's annotation, if applicable.
    ///
    /// Not serialized, since it contains ANSI escape codes.
    #[serde(skip_serializing)]
    pub(crate) link: Option<String>,

    /// A symbolic route (of keys and indices) to the final location.
    pub(crate) route: Route<'w>,
}

impl<'w> SymbolicLocation<'w> {
    pub(crate) fn with_keys(&self, keys: &[RouteComponent<'w>]) -> SymbolicLocation<'w> {
        SymbolicLocation {
            name: self.name,
            annotation: self.annotation.clone(),
            link: None,
            route: self.route.with_keys(keys),
        }
    }

    pub(crate) fn with_job(&self, job: &Job<'w>) -> SymbolicLocation<'w> {
        self.with_keys(&["jobs".into(), job.id.into()])
    }

    pub(crate) fn with_step(&self, step: &Step<'w>) -> SymbolicLocation<'w> {
        self.with_keys(&["steps".into(), step.index.into()])
    }

    /// Adds a human-readable annotation to the current `SymbolicLocation`.
    pub(crate) fn annotated(mut self, annotation: impl Into<String>) -> SymbolicLocation<'w> {
        self.annotation = annotation.into();
        self
    }

    /// Adds a URL to the current `SymbolicLocation`.
    pub(crate) fn with_url(mut self, url: impl Into<String>) -> SymbolicLocation<'w> {
        self.link = Some(Link::new(&self.annotation, &url.into()).to_string());
        self
    }

    /// Concretize this `SymbolicLocation`, consuming it in the process.
    pub(crate) fn concretize(self, workflow: &'w Workflow) -> Result<Location<'w>> {
        let feature = Locator::new().concretize(workflow, &self)?;

        Ok(Location {
            symbolic: self,
            concrete: feature,
        })
    }
}

/// Represents a `(row, column)` point within a file.
#[derive(Serialize)]
pub(crate) struct Point {
    pub(crate) row: usize,
    pub(crate) column: usize,
}

/// A "concrete" location for some feature.
/// Every concrete location contains two spans: a line-and-column span,
/// and an offset range.
#[derive(Serialize)]
pub(crate) struct ConcreteLocation {
    pub(crate) start_point: Point,
    pub(crate) end_point: Point,
    pub(crate) start_offset: usize,
    pub(crate) end_offset: usize,
}

impl From<&yamlpath::Location> for ConcreteLocation {
    fn from(value: &yamlpath::Location) -> Self {
        Self {
            start_point: Point {
                row: value.point_span.0 .0,
                column: value.point_span.0 .1,
            },
            end_point: Point {
                row: value.point_span.1 .0,
                column: value.point_span.1 .1,
            },
            start_offset: value.byte_span.0,
            end_offset: value.byte_span.1,
        }
    }
}

/// An extracted feature, along with its concrete location.
#[derive(Serialize)]
pub(crate) struct Feature<'w> {
    /// The feature's concrete location, as both an offset range and point span.
    pub(crate) location: ConcreteLocation,

    /// The feature's concrete parent location.
    /// This can be the same as the feature's own location, if the feature
    /// is the document root.
    pub(crate) parent_location: ConcreteLocation,

    /// The feature's textual content.
    pub(crate) feature: &'w str,

    /// Any comments within the feature's span.
    pub(crate) comments: Vec<&'w str>,

    /// The feature's parent's textual content.
    pub(crate) parent_feature: &'w str,
}

/// A location within a GitHub Actions workflow, with both symbolic and concrete components.
#[derive(Serialize)]
pub(crate) struct Location<'w> {
    /// The symbolic workflow location.
    pub(crate) symbolic: SymbolicLocation<'w>,
    /// The concrete location, including extracted feature.
    pub(crate) concrete: Feature<'w>,
}

/// A finding's "determination," i.e. its confidence and severity classifications.
#[derive(Serialize)]
pub(crate) struct Determinations {
    pub(crate) confidence: Confidence,
    pub(crate) severity: Severity,
}

#[derive(Serialize)]
pub(crate) struct Finding<'w> {
    pub(crate) ident: &'static str,
    pub(crate) desc: &'static str,
    pub(crate) url: &'static str,
    pub(crate) determinations: Determinations,
    pub(crate) locations: Vec<Location<'w>>,
    pub(crate) ignored: bool,
}

pub(crate) struct FindingBuilder<'w> {
    ident: &'static str,
    desc: &'static str,
    url: &'static str,
    severity: Severity,
    confidence: Confidence,
    locations: Vec<SymbolicLocation<'w>>,
}

impl<'w> FindingBuilder<'w> {
    pub(crate) fn new(ident: &'static str, desc: &'static str, url: &'static str) -> Self {
        Self {
            ident,
            desc,
            url,
            severity: Default::default(),
            confidence: Default::default(),
            locations: vec![],
        }
    }

    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub(crate) fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub(crate) fn add_location(mut self, location: SymbolicLocation<'w>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn build(self, workflow: &'w Workflow) -> Result<Finding<'w>> {
        let locations = self
            .locations
            .iter()
            .map(|l| l.clone().concretize(workflow))
            .collect::<Result<Vec<_>>>()?;

        let should_ignore = self.ignored_from_inlined_comment(&locations, self.ident);

        Ok(Finding {
            ident: self.ident,
            desc: self.desc,
            url: self.url,
            determinations: Determinations {
                confidence: self.confidence,
                severity: self.severity,
            },
            locations,
            ignored: should_ignore,
        })
    }

    fn ignored_from_inlined_comment(&self, locations: &[Location], id: &str) -> bool {
        let inlined_ignore = format!("zizmor: ignore[{}]", id);

        locations
            .iter()
            .flat_map(|l| &l.concrete.comments)
            .any(|c| c.contains(&inlined_ignore))
    }
}
