use github_actions_models::{
    common::expr::ExplicitExpr,
    workflow::job::{Container, DockerCredentials},
};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::{
    finding::{Confidence, Severity, location::Locatable as _},
    state::AuditState,
};

pub(crate) struct HardcodedContainerCredentials;

audit_meta!(
    HardcodedContainerCredentials,
    "hardcoded-container-credentials",
    "hardcoded credential in GitHub Actions container configurations"
);

impl Audit for HardcodedContainerCredentials {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(job) = &job else {
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
            }) = &job.container
            {
                // If the password doesn't parse as an expression, it's hardcoded.
                if ExplicitExpr::from_curly(password).is_none() {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(&["container".into(), "credentials".into()])
                                    .annotated("container registry password is hard-coded"),
                            )
                            .build(workflow)?,
                    )
                }
            }

            for (service, config) in job.services.iter() {
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
                    if ExplicitExpr::from_curly(password).is_none() {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    job.location()
                                        .primary()
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
