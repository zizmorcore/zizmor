use std::ops::Deref;

use github_actions_models::{
    common::Expression,
    workflow::{
        job::{Container, DockerCredentials},
        Job,
    },
};

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Severity},
    AuditConfig,
};

pub(crate) struct HardcodedContainerCredentials<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> WorkflowAudit<'a> for HardcodedContainerCredentials<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "hardcoded-container-credentials"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &mut self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            if let Some(Container::Container {
                image: _,
                credentials:
                    Some(DockerCredentials {
                        username: _,
                        password: Some(password),
                    }),
                ..
            }) = &normal.container
            {
                // If the password doesn't parse as an expression, it's hardcoded.
                if Expression::from_curly(password.into()).is_none() {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(
                                job.key_location("container")
                                    .annotated("container registry password is hard-coded"),
                            )
                            .build(workflow)?,
                    )
                }
            }

            for (service, config) in normal.services.iter() {
                if let Container::Container {
                    image: _,
                    credentials:
                        Some(DockerCredentials {
                            username: _,
                            password: Some(password),
                        }),
                    ..
                } = &config
                {
                    if Expression::from_curly(password.into()).is_none() {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(job.key_location("services").annotated(format!(
                                    "service {service}: container registry password is hard-coded"
                                )))
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(findings)
    }
}
