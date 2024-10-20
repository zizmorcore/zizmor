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
    state::AuditState,
};

pub(crate) struct HardcodedContainerCredentials {
    pub(crate) _state: AuditState,
}

impl WorkflowAudit for HardcodedContainerCredentials {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "hardcoded-container-credentials"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "hardcoded credential in GitHub Actions container configurations"
    }

    fn new(state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _state: state })
    }

    fn audit<'w>(
        &self,
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
                                job.location()
                                    .with_keys(&["container".into(), "credentials".into()])
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
                                .add_location(
                                    job.location()
                                        .with_keys(&[
                                            "services".into(),
                                            service.as_str().into(),
                                            "credentials".into(),
                                        ])
                                        .annotated(format!(
                                            "service {service}: container registry password is \
                                         hard-coded"
                                        )),
                                )
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(findings)
    }
}
