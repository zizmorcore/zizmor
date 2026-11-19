use github_actions_models::{
    action::DockerActionUses,
    common::{DockerUses, expr::LoE},
};

use super::{Audit, AuditLoadError, NormalJob, audit_meta};
use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, FindingBuilder, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::{
        action::DockerAction,
        workflow::images::{ContainerImage, ImageReference},
    },
    registry::input::InputGroup,
    state::AuditState,
};

pub(crate) struct UnpinnedImages;

audit_meta!(
    UnpinnedImages,
    "unpinned-images",
    "unpinned image references"
);

impl UnpinnedImages {
    fn check_image<'doc>(
        image: &DockerUses,
        label: &str,
        location: SymbolicLocation<'doc>,
    ) -> Option<FindingBuilder<'doc>> {
        // An empty image disables the container. An empty tag (e.g. "redis:")
        // is an invalid reference, which the runner cannot pull.
        if image.image().is_empty()
            || image.raw().trim_end().ends_with(':')
            || image.hash().is_some()
        {
            return None;
        }

        let (reason, persona) = match image.tag() {
            Some("latest") => ("uses the floating 'latest' tag", Persona::Regular),
            Some(_) => ("is not pinned to a SHA256 hash", Persona::Pedantic),
            None => ("is unpinned", Persona::Regular),
        };

        Some(
            Self::finding()
                .severity(Severity::High)
                .confidence(Confidence::High)
                .persona(persona)
                .add_location(location.primary().annotated(format!("{label} {reason}"))),
        )
    }

    fn check_container<'doc>(image: ContainerImage<'doc>) -> Option<FindingBuilder<'doc>> {
        let finding = match image.reference {
            ImageReference::Literal(reference) => {
                Self::check_image(reference, "container image", image.location)?
            }
            ImageReference::Evaluated(reference) => {
                let label = format!("container image {:?}", reference.raw());
                Self::check_image(&reference, &label, image.location)?
            }
            ImageReference::Unknown(template) => {
                // A literal digest pins an image whose name is only known at runtime.
                if let Some((_, digest)) = template.trim_end().rsplit_once("@sha256:")
                    && digest.len() == 64
                    && digest.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return None;
                }
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::Low)
                    .add_location(
                        image
                            .location
                            .primary()
                            .annotated("container image may be unpinned"),
                    )
            }
        };
        Some(
            image
                .evidence
                .into_iter()
                .fold(finding, FindingBuilder::add_location),
        )
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedImages {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_docker_action<'doc>(
        &self,
        docker: &DockerAction<'doc>,
        _group: &InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // Action metadata requires a literal image or a Dockerfile.
        let DockerActionUses::Image(LoE::Literal(image)) = &docker.image else {
            return Ok(vec![]);
        };

        Self::check_image(
            image,
            "container image",
            docker.location().with_keys(["image".into()]),
        )
        .into_iter()
        .map(|finding| finding.build(docker))
        .collect()
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _group: &InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        job.container_images()
            .into_iter()
            .filter_map(Self::check_container)
            .map(|finding| finding.build(job))
            .collect()
    }
}
