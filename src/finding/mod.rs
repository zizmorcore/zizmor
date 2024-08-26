use anyhow::Result;
use locate::Locator;
use serde::Serialize;

use crate::models::{Job, Step, Workflow};

pub(crate) mod locate;

// TODO: Traits + more flexible models here.

#[derive(Serialize)]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Serialize)]
pub(crate) enum Severity {
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone)]
pub(crate) struct StepLocation<'w> {
    pub(crate) index: usize,
    pub(crate) id: Option<&'w str>,
    pub(crate) name: Option<&'w str>,
}

impl<'w> From<&Step<'w>> for StepLocation<'w> {
    fn from(step: &Step<'w>) -> Self {
        Self {
            index: step.index,
            id: step.inner.id.as_deref(),
            name: step.inner.name.as_deref(),
        }
    }
}

#[derive(Serialize, Clone)]
pub(crate) struct JobLocation<'w> {
    pub(crate) id: &'w str,
    pub(crate) name: Option<&'w str>,
    pub(crate) step: Option<StepLocation<'w>>,
}

impl<'w> JobLocation<'w> {
    fn with_step(&self, step: &Step<'w>) -> JobLocation<'w> {
        JobLocation {
            id: self.id,
            name: self.name,
            step: Some(step.into()),
        }
    }
}

/// Represents a symbolic workflow location.
#[derive(Serialize, Clone)]
pub(crate) struct WorkflowLocation<'w> {
    pub(crate) name: &'w str,

    /// The job location within this workflow, if present.
    pub(crate) job: Option<JobLocation<'w>>,

    /// An optional annotation for this location.
    pub(crate) annotation: Option<String>,
}

impl<'w> WorkflowLocation<'w> {
    /// Creates a new `WorkflowLocation` with the given `Job` added to it.
    pub(crate) fn with_job(&self, job: &Job<'w>) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: self.name,
            job: Some(JobLocation {
                id: job.id,
                name: job.inner.name(),
                step: None,
            }),
            annotation: self.annotation.clone(),
        }
    }

    /// Creates a new `WorkflowLocation` with the given `Step` added to it.
    ///
    /// This can only be called after the `WorkflowLocation` already has a job,
    /// since steps belong to jobs.
    pub(crate) fn with_step(&self, step: &Step<'w>) -> WorkflowLocation<'w> {
        match &self.job {
            None => panic!("API misuse: can't set step without parent job"),
            Some(job) => WorkflowLocation {
                name: self.name,
                job: Some(job.with_step(step)),
                annotation: self.annotation.clone(),
            },
        }
    }

    /// Concretize this `WorkflowLocation`, consuming it in the process.
    pub(crate) fn concretize(self, workflow: &'w Workflow) -> Result<Location<'w>> {
        let feature = Locator::new().concretize(workflow, &self)?;

        Ok(Location {
            symbolic: self,
            concrete: feature,
        })
    }

    /// Adds a human-readable annotation to the current `WorkflowLocation`.
    pub(crate) fn annotated(mut self, annotation: impl Into<String>) -> WorkflowLocation<'w> {
        self.annotation = Some(annotation.into());
        self
    }
}

#[derive(Serialize)]
pub(crate) struct Point {
    pub(crate) row: usize,
    pub(crate) column: usize,
}

impl From<tree_sitter::Point> for Point {
    fn from(value: tree_sitter::Point) -> Self {
        Self {
            row: value.row,
            column: value.column,
        }
    }
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

impl From<tree_sitter::Node<'_>> for ConcreteLocation {
    fn from(value: tree_sitter::Node) -> Self {
        Self {
            start_point: value.start_position().into(),
            end_point: value.end_position().into(),
            start_offset: value.start_byte(),
            end_offset: value.end_byte(),
        }
    }
}

/// An extracted feature.
#[derive(Serialize)]
pub(crate) struct Feature<'w> {
    pub(crate) location: ConcreteLocation,
    pub(crate) feature: &'w str,
}

#[derive(Serialize)]
pub(crate) struct Location<'w> {
    pub(crate) symbolic: WorkflowLocation<'w>,
    pub(crate) concrete: Feature<'w>,
}

#[derive(Serialize)]
pub(crate) struct Determinations {
    pub(crate) confidence: Confidence,
    pub(crate) severity: Severity,
}

#[derive(Serialize)]
pub(crate) struct Finding<'w> {
    pub(crate) ident: &'static str,
    pub(crate) determinations: Determinations,
    pub(crate) locations: Vec<Location<'w>>,
}

pub(crate) struct FindingBuilder<'w> {
    ident: &'static str,
    severity: Option<Severity>,
    confidence: Option<Confidence>,
    locations: Vec<WorkflowLocation<'w>>,
}

impl<'w> FindingBuilder<'w> {
    pub(crate) fn new(ident: &'static str) -> Self {
        Self {
            ident,
            severity: None,
            confidence: None,
            locations: vec![],
        }
    }

    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub(crate) fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub(crate) fn add_location(mut self, location: WorkflowLocation<'w>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn build(self, workflow: &'w Workflow) -> Result<Finding<'w>> {
        Ok(Finding {
            ident: self.ident,
            determinations: Determinations {
                confidence: self
                    .confidence
                    .expect("API misuse: must call confidence() at least once"),
                severity: self
                    .severity
                    .expect("API misuse: must call severity() at least once"),
            },
            locations: self
                .locations
                .into_iter()
                .map(|l| l.concretize(workflow))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}
