use anyhow::Result;
use locate::Locator;
use serde::Serialize;

use crate::models::{Job, Step, Workflow};

pub(crate) mod locate;

// TODO: Traits + more flexible models here.

#[derive(Copy, Clone, Debug, Default, Serialize)]
pub(crate) enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Copy, Clone, Debug, Default, Serialize)]
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

/// Represents a job-level key or step location.
#[derive(Serialize, Clone, Debug)]
pub(crate) enum StepOrKeys<'w> {
    Keys(Vec<&'w str>),
    Step(StepLocation<'w>),
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct JobLocation<'w> {
    /// The job's unique ID within its parent workflow.
    pub(crate) id: &'w str,

    /// The job's name, if present.
    pub(crate) name: Option<&'w str>,

    /// The step or non-step keys within this workflow.
    pub(crate) step_or_keys: Option<StepOrKeys<'w>>,
}

impl<'w> JobLocation<'w> {
    /// Creates a new `JobLocation` with the given non-step `keys`.
    ///
    /// Clears any `step` in the process.
    pub(crate) fn with_keys(&self, keys: &[&'w str]) -> JobLocation<'w> {
        JobLocation {
            id: self.id,
            name: self.name,
            step_or_keys: Some(StepOrKeys::Keys(keys.into())),
        }
    }

    /// Creates a new `JobLocation` with the given interior step location.
    ///
    /// Clears any non-step `key` in the process.
    fn with_step(&self, step: &Step<'w>) -> JobLocation<'w> {
        JobLocation {
            id: self.id,
            name: self.name,
            step_or_keys: Some(StepOrKeys::Step(step.into())),
        }
    }
}

/// Represents a workflow-level key or job location.
#[derive(Serialize, Clone, Debug)]
pub(crate) enum JobOrKeys<'w> {
    Keys(Vec<&'w str>),
    Job(JobLocation<'w>),
}

/// Represents a symbolic workflow location.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct WorkflowLocation<'w> {
    /// The name of the workflow.
    pub(crate) name: &'w str,

    /// An optional annotation for this location.
    pub(crate) annotation: Option<String>,

    /// The job or non-job key within this workflow.
    pub(crate) job_or_key: Option<JobOrKeys<'w>>,
}

impl<'w> WorkflowLocation<'w> {
    /// Creates a new `WorkflowLocation` with the given `key`. Any inner
    /// job location is cleared.
    pub(crate) fn with_keys(&self, keys: &[&'w str]) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: self.name,
            job_or_key: Some(JobOrKeys::Keys(keys.into())),
            annotation: self.annotation.clone(),
        }
    }

    /// Creates a new `WorkflowLocation` with the given `Job` added to it.
    pub(crate) fn with_job(&self, job: &Job<'w>) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: self.name,
            job_or_key: Some(JobOrKeys::Job(JobLocation {
                id: job.id,
                name: job.name(),
                step_or_keys: None,
            })),
            annotation: self.annotation.clone(),
        }
    }

    /// Creates a new `WorkflowLocation` with the given `Step` added to it.
    ///
    /// This can only be called after the `WorkflowLocation` already has a job,
    /// since steps belong to jobs.
    pub(crate) fn with_step(&self, step: &Step<'w>) -> WorkflowLocation<'w> {
        match &self.job_or_key {
            Some(JobOrKeys::Job(job)) => WorkflowLocation {
                name: self.name,
                job_or_key: Some(JobOrKeys::Job(job.with_step(step))),
                annotation: self.annotation.clone(),
            },
            _ => panic!("API misuse: can't set step without parent job"),
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
    /// The feature's textual content.
    pub(crate) feature: &'w str,
}

/// A location within a GitHub Actions workflow, with both symbolic and concrete components.
#[derive(Serialize)]
pub(crate) struct Location<'w> {
    /// The symbolic workflow location.
    pub(crate) symbolic: WorkflowLocation<'w>,
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
    pub(crate) determinations: Determinations,
    pub(crate) locations: Vec<Location<'w>>,
}

pub(crate) struct FindingBuilder<'w> {
    ident: &'static str,
    severity: Severity,
    confidence: Confidence,
    locations: Vec<WorkflowLocation<'w>>,
}

impl<'w> FindingBuilder<'w> {
    pub(crate) fn new(ident: &'static str) -> Self {
        Self {
            ident,
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

    pub(crate) fn add_location(mut self, location: WorkflowLocation<'w>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn build(self, workflow: &'w Workflow) -> Result<Finding<'w>> {
        Ok(Finding {
            ident: self.ident,
            determinations: Determinations {
                confidence: self.confidence,
                severity: self.severity,
            },
            locations: self
                .locations
                .into_iter()
                .map(|l| l.concretize(workflow))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}
