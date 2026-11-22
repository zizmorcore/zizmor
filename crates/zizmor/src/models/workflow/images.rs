//! Images used by a job's container, services, and Docker steps.
use github_actions_expressions::evaluation::{AbstractValue, Access};
use github_actions_models::{
    common::{DockerUses, Uses, expr::LoE},
    workflow::job::Container,
};
use subfeature::Subfeature;

use super::NormalJob;
use crate::{
    finding::location::{Locatable as _, SymbolicLocation},
    models::{StepCommon as _, evaluation::Site},
};

pub(crate) struct ContainerImage<'doc> {
    pub(crate) reference: ImageReference<'doc>,
    pub(crate) location: SymbolicLocation<'doc>,
    pub(crate) evidence: Vec<SymbolicLocation<'doc>>,
}

pub(crate) enum ImageReference<'doc> {
    Literal(&'doc DockerUses),
    Evaluated(DockerUses),
    /// The template is available even when its full value is unknown.
    Unknown(&'doc str),
}

impl<'doc> ContainerImage<'doc> {
    fn literal(image: &'doc DockerUses, location: SymbolicLocation<'doc>) -> Self {
        Self {
            reference: ImageReference::Literal(image),
            location,
            evidence: vec![],
        }
    }
}

impl<'doc> NormalJob<'doc> {
    /// Possible image references and the declarations that supplied them.
    pub(crate) fn container_images(&self) -> Vec<ContainerImage<'doc>> {
        let mut images = vec![];
        if let Some(container) = &self.container {
            let location = self.location().with_keys(["container".into()]);
            images.extend(self.resolve_container(container, location));
        }
        for (service, container) in &self.services {
            let location = self
                .location()
                .with_keys(["services".into(), service.as_str().into()]);
            images.extend(self.resolve_container(container, location));
        }
        for step in self.steps() {
            if let Some(Uses::Docker(image)) = step.uses() {
                let location = step
                    .location()
                    .with_keys(["uses".into()])
                    .subfeature(Subfeature::new(0, image.raw()));
                images.push(ContainerImage::literal(image, location));
            }
        }
        images
    }

    fn resolve_container(
        &self,
        container: &'doc Container,
        location: SymbolicLocation<'doc>,
    ) -> Vec<ContainerImage<'doc>> {
        let (image, location) = match container {
            Container::Name(image) => (image, location),
            Container::Container { image, .. } => (image, location.with_keys(["image".into()])),
        };
        let template = match image {
            LoE::Literal(image) if !image.raw().contains("${{") => {
                return vec![ContainerImage::literal(image, location)];
            }
            LoE::Literal(image) => image.raw(),
            LoE::Expr(expr) => expr.as_raw(),
        };

        let mut evaluation = Site::Job(self).evaluate_template(template);
        if matches!(container, Container::Name(_)) {
            // An expression for the entire container can return a mapping.
            let image = Access::from("image");
            for value in &mut evaluation.values {
                if matches!(value.inner, AbstractValue::Object(_)) {
                    *value = value.apply_access(&image);
                }
            }
        }

        evaluation
            .scalar_strings()
            .map(|(name, evidence)| ContainerImage {
                reference: match name {
                    Some(name) => ImageReference::Evaluated(DockerUses::parse(name)),
                    None => ImageReference::Unknown(template),
                },
                location: location.clone(),
                evidence,
            })
            .collect()
    }
}
