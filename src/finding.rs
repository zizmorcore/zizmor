use github_actions_models::workflow::job::Step;
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
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone)]
pub(crate) struct StepLocation {
    pub(crate) index: usize,
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
}

impl StepLocation {
    pub(crate) fn new(index: usize, step: &Step) -> Self {
        Self {
            index,
            id: step.id.clone(),
            name: step.name.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JobLocation<'w> {
    pub(crate) id: &'w str,
    pub(crate) name: Option<&'w str>,
    pub(crate) steps: Vec<StepLocation>,
}

#[derive(Serialize)]
pub(crate) struct WorkflowLocation<'w> {
    pub(crate) name: String,
    pub(crate) jobs: Vec<JobLocation<'w>>,
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
    pub(crate) location: WorkflowLocation<'w>,
}
