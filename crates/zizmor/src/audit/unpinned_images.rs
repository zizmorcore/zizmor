use std::collections::HashSet;

use github_actions_expressions::evaluation::{AbstractValue, Access};
use github_actions_models::{
    action::DockerActionUses,
    common::{DockerUses, Uses, expr::LoE},
    workflow::job::{Container, UsesStep},
};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, NormalJob, audit_meta};
use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, FindingBuilder, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::{action::DockerAction, evaluation::Context, workflow::StepInner},
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

    fn check_container<'doc>(
        container: &Container,
        location: SymbolicLocation<'doc>,
        job: &NormalJob<'doc>,
    ) -> Vec<FindingBuilder<'doc>> {
        let (image, location) = match container {
            Container::Name(image) => (image, location),
            Container::Container { image, .. } => (image, location.with_keys(["image".into()])),
        };
        let template = match image {
            LoE::Literal(image) if !image.raw().contains("${{") => {
                return Self::check_image(image, "container image", location)
                    .into_iter()
                    .collect();
            }
            LoE::Literal(image) => image.raw(),
            LoE::Expr(expr) => expr.as_raw(),
        };

        // A literal digest pins the image even when its name is only known at runtime.
        if let Some((_, digest)) = template.trim_end().rsplit_once("@sha256:")
            && digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return vec![];
        }

        let evaluation = Context::job(job.clone()).evaluate_template(template);

        let mut findings = vec![];
        let mut seen = HashSet::new();
        for outcome in &evaluation.outcomes {
            // An expression for the whole container can return a mapping.
            let image;
            let value = if matches!(container, Container::Name(_))
                && matches!(outcome.value.inner, AbstractValue::Object(_))
            {
                image = outcome.value.apply_access(&Access::Key("image".into()));
                &image
            } else {
                &outcome.value
            };

            let name = match &value.inner {
                AbstractValue::Known(value) => Some(value.sema().to_string()),
                AbstractValue::Unknown(_) | AbstractValue::Reference(_) => None,
                AbstractValue::Array(_) | AbstractValue::Object(_) => continue,
            };
            // Rows can reach the same image through the same definition. Keep
            // different definitions separate so an inline ignore only covers its own.
            if !seen.insert((name.clone(), value.dependencies().evidence)) {
                continue;
            }

            let mut finding = match name {
                Some(name) => {
                    let label = format!("container image {name:?}");
                    let Some(finding) =
                        Self::check_image(&DockerUses::parse(name), &label, location.clone())
                    else {
                        continue;
                    };
                    finding
                }
                None => Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::Low)
                    .add_location(
                        location
                            .clone()
                            .primary()
                            .annotated("container image may be unpinned"),
                    ),
            };
            for evidence in evaluation.locations([value]) {
                finding = finding.add_location(evidence);
            }
            findings.push(finding);
        }
        findings
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
        let mut findings = vec![];
        if let Some(container) = &job.container {
            let location = job.location().with_keys(["container".into()]);
            findings.extend(Self::check_container(container, location, job));
        }
        for (service, container) in &job.services {
            let location = job
                .location()
                .with_keys(["services".into(), service.as_str().into()]);
            findings.extend(Self::check_container(container, location, job));
        }

        for step in job.steps() {
            if let StepInner::Uses(UsesStep {
                uses: Uses::Docker(image),
                ..
            }) = &*step
            {
                let location = step
                    .location()
                    .with_keys(["uses".into()])
                    .subfeature(Subfeature::new(0, image.raw()));
                findings.extend(Self::check_image(image, "container image", location));
            }
        }

        findings
            .into_iter()
            .map(|finding| finding.build(job))
            .collect()
    }
}
