use github_actions_models::workflow::job::{NormalJob, Step};
use serde::Serialize;

// TODO: Traits + more flexible models here.

#[derive(Serialize)]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Serialize)]
pub(crate) enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone)]
pub(crate) struct StepIdentity {
    pub(crate) number: usize,
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
}

impl StepIdentity {
    pub(crate) fn new(number: usize, step: &Step) -> Self {
        Self {
            number,
            id: step.id.clone(),
            name: step.name.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JobIdentity {
    id: String,
    name: Option<String>,
}

impl JobIdentity {
    pub(crate) fn new(id: &str, job: &NormalJob) -> Self {
        Self {
            id: id.to_string(),
            name: job.name.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Finding {
    pub(crate) ident: &'static str,
    // The base filename of the workflow.
    pub(crate) workflow: String,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) job: Option<JobIdentity>,
    pub(crate) steps: Vec<StepIdentity>,
}
