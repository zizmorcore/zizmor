use github_actions_models::workflow::job;
use serde::Serialize;

use crate::models::{Job, Step};

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

impl<'w> StepLocation<'w> {
    pub(crate) fn new(index: usize, step: &'w job::Step) -> Self {
        Self {
            index,
            id: step.id.as_deref(),
            name: step.name.as_deref(),
        }
    }
}

impl<'w> From<&'w Step<'w>> for StepLocation<'w> {
    fn from(step: &'w Step<'w>) -> Self {
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
    fn with_step(&'w self, step: &'w Step) -> JobLocation {
        JobLocation {
            id: &self.id,
            name: self.name,
            step: Some(step.into()),
        }
    }
}

impl<'w> From<&'w Job<'w>> for JobLocation<'w> {
    fn from(job: &'w Job<'w>) -> Self {
        Self {
            id: job.id,
            name: job.inner.name(),
            step: None,
        }
    }
}

#[derive(Serialize, Clone)]
pub(crate) struct WorkflowLocation<'w> {
    pub(crate) name: &'w str,
    /// The job location within this workflow, if present.
    pub(crate) job: Option<JobLocation<'w>>,
}

impl<'w> WorkflowLocation<'w> {
    pub(crate) fn with_job(&self, job: &'w Job<'w>) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: &self.name,
            job: Some(job.into()),
        }
    }

    pub(crate) fn with_step(&'w self, step: &'w Step<'w>) -> WorkflowLocation<'w> {
        match &self.job {
            None => panic!("API misuse: can't set step without parent job"),
            Some(job) => WorkflowLocation {
                name: &self.name,
                job: Some(job.with_step(step)),
            },
        }
    }
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
    pub(crate) locations: Vec<WorkflowLocation<'w>>,
}
