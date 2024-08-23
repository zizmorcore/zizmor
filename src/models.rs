use anyhow::{Context, Ok, Result};
use std::{collections::hash_map, iter::Enumerate, ops::Deref, path::Path};

use github_actions_models::workflow;

use crate::finding::WorkflowLocation;

pub(crate) struct Workflow {
    pub(crate) filename: String,
    inner: workflow::Workflow,
}

impl Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Workflow {
    pub(crate) fn from_file<P: AsRef<Path>>(p: P) -> Result<Self> {
        let inner = serde_yaml::from_slice(&std::fs::read(p.as_ref())?)
            .with_context(|| format!("invalid GitHub Actions workflow: {:?}", p.as_ref()))?;

        // NOTE: file_name().unwrap() is safe since the read above only succeeds
        // on a well-formed filepath.
        Ok(Self {
            filename: p
                .as_ref()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            inner,
        })
    }

    pub(crate) fn location(&self) -> WorkflowLocation {
        WorkflowLocation {
            name: &self.filename,
            job: None,
            annotation: None,
        }
    }

    pub(crate) fn jobs(&self) -> Jobs<'_> {
        Jobs::new(self)
    }
}

pub(crate) struct Job<'w> {
    pub(crate) id: &'w str,
    pub(crate) inner: &'w workflow::Job,
    parent: WorkflowLocation<'w>,
}

impl<'w> Deref for Job<'w> {
    type Target = workflow::Job;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'w> Job<'w> {
    pub(crate) fn new(id: &'w str, inner: &'w workflow::Job, parent: WorkflowLocation<'w>) -> Self {
        Self { id, inner, parent }
    }

    pub(crate) fn location(&self) -> WorkflowLocation<'w> {
        self.parent.with_job(self)
    }

    pub(crate) fn steps(&self) -> Steps<'w> {
        Steps::new(self)
    }
}

pub(crate) struct Jobs<'w> {
    inner: hash_map::Iter<'w, String, workflow::Job>,
    location: WorkflowLocation<'w>,
}

impl<'w> Jobs<'w> {
    pub(crate) fn new(workflow: &'w Workflow) -> Self {
        Self {
            inner: workflow.jobs.iter(),
            location: workflow.location(),
        }
    }
}

impl<'w> Iterator for Jobs<'w> {
    type Item = Job<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((id, job)) => Some(Job::new(id, job, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Step<'w> {
    pub(crate) index: usize,
    pub(crate) inner: &'w workflow::job::Step,
    parent: WorkflowLocation<'w>,
}

impl<'w> Step<'w> {
    pub(crate) fn new(
        index: usize,
        inner: &'w workflow::job::Step,
        parent: WorkflowLocation<'w>,
    ) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    pub(crate) fn location(&self) -> WorkflowLocation<'w> {
        self.parent.with_step(self)
    }
}

pub(crate) struct Steps<'w> {
    inner: Enumerate<std::slice::Iter<'w, github_actions_models::workflow::job::Step>>,
    location: WorkflowLocation<'w>,
}

impl<'w> Steps<'w> {
    pub(crate) fn new(job: &Job<'w>) -> Self {
        // TODO: do something less silly here.
        match &job.inner {
            workflow::Job::ReusableWorkflowCallJob(_) => {
                panic!("API misuse: can't call steps() on a reusable job")
            }
            workflow::Job::NormalJob(ref n) => Self {
                inner: n.steps.iter().enumerate(),
                location: job.location(),
            },
        }
    }
}

impl<'w> Iterator for Steps<'w> {
    type Item = Step<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(Step::new(idx, step, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct AuditConfig<'a> {
    pub(crate) pedantic: bool,
    pub(crate) gh_token: &'a str,
}
