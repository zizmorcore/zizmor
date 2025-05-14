use anyhow::Result;

use crate::{
    finding::{Confidence, Finding, Persona, Severity, SymbolicLocation},
    models::JobExt as _,
    state::AuditState,
};

use github_actions_models::common::DockerUses;
use github_actions_models::workflow::job::Container;

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct UnpinnedImages;

impl UnpinnedImages {
    fn build_finding<'doc>(
        &self,
        location: SymbolicLocation<'doc>,
        annotation: &str,
        persona: Persona,
        job: &super::NormalJob<'doc>,
    ) -> Result<Finding<'doc>> {
        let mut annotated_location = location;
        annotated_location = annotated_location.annotated(annotation);
        Self::finding()
            .severity(Severity::High)
            .confidence(Confidence::High)
            .add_location(annotated_location)
            .persona(persona)
            .build(job.parent())
    }
}

audit_meta!(
    UnpinnedImages,
    "unpinned-images",
    "unpinned image references"
);

impl Audit for UnpinnedImages {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];
        let mut image_refs_with_locations: Vec<(DockerUses, SymbolicLocation<'doc>)> = vec![];

        if let Some(Container::Container { image, .. }) = &job.container {
            image_refs_with_locations.push((
                image.parse().unwrap(),
                job.location()
                    .primary()
                    .with_keys(&["container".into(), "image".into()]),
            ));
        }

        for (service, config) in job.services.iter() {
            if let Container::Container { image, .. } = &config {
                image_refs_with_locations.push((
                    image.parse().unwrap(),
                    job.location().primary().with_keys(&[
                        "services".into(),
                        service.as_str().into(),
                        "image".into(),
                    ]),
                ));
            }
        }

        for (image, location) in image_refs_with_locations {
            match image.hash {
                Some(_) => continue,
                None => match image.tag.as_deref() {
                    Some("latest") => {
                        findings.push(self.build_finding(
                            location,
                            "container image is pinned to latest",
                            Persona::Regular,
                            job,
                        )?);
                    }
                    None => {
                        findings.push(self.build_finding(
                            location,
                            "container image is unpinned",
                            Persona::Regular,
                            job,
                        )?);
                    }
                    Some(_) => {
                        findings.push(self.build_finding(
                            location,
                            "container image is not pinned to a SHA256 hash",
                            Persona::Pedantic,
                            job,
                        )?);
                    }
                },
            }
        }

        Ok(findings)
    }
}
