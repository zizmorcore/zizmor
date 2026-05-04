use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::{AsDocument, action::DockerAction, workflow::matrix::Matrix},
    state::AuditState,
};

use github_actions_expressions::{Expr, literal::Literal};
use github_actions_models::workflow::job::Container;
use github_actions_models::{
    action::DockerActionUses,
    common::{DockerUses, expr::LoE},
};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct UnpinnedImages;

impl UnpinnedImages {
    /// Classify a list of image references (with locations) and emit findings
    /// for any that are unpinned.
    fn classify_images<'a, 'doc>(
        &self,
        image_refs_with_locations: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)>,
        matrix: Option<Matrix<'doc>>,
        document: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // TODO: Clean this mess up.
        for (image, ref location) in image_refs_with_locations {
            match image {
                LoE::Expr(expr) => {
                    let context = match Expr::parse(expr.as_bare()).map(|e| e.inner) {
                        // Our expression is `${{ matrix.abc... }}`.
                        Ok(Expr::Context(context)) if context.child_of("matrix") => context,
                        // An invalid expression, or otherwise any expression that's
                        // more complex than a simple matrix reference.
                        _ => {
                            // Extract possible leaf expressions from complex
                            // expressions like `inputs.x == 'true' && 'redis:7' || ''`.
                            if let Ok(parsed) = Expr::parse(expr.as_bare()) {
                                for leaf in parsed.leaf_expressions() {
                                    let leaf_location = location.clone().subfeature(
                                        Subfeature::new(0, subfeature::Fragment::from(leaf)),
                                    );

                                    match &leaf.inner {
                                        // String literals can be analyzed precisely.
                                        Expr::Literal(Literal::String(s)) => {
                                            if s.is_empty() {
                                                continue;
                                            }
                                            let image = DockerUses::parse(s.as_ref());
                                            if image.image().is_empty() {
                                                continue;
                                            }
                                            self.check_image(
                                                &image,
                                                &leaf_location,
                                                document,
                                                &mut findings,
                                            )?;
                                        }
                                        // Non-string leaves (contexts, calls, etc.)
                                        // can't be analyzed statically.
                                        _ => {
                                            findings.push(self.build_finding(
                                                &leaf_location,
                                                "container image may be unpinned",
                                                Confidence::Low,
                                                Persona::Regular,
                                                document,
                                            )?);
                                        }
                                    }
                                }
                                continue;
                            }

                            findings.push(self.build_finding(
                                location,
                                "container image may be unpinned",
                                Confidence::Low,
                                Persona::Regular,
                                document,
                            )?);
                            continue;
                        }
                    };

                    let Some(ref matrix) = matrix else {
                        tracing::warn!(
                            "image references {expr} but has no matrix",
                            expr = expr.as_bare()
                        );
                        continue;
                    };

                    for expansion in matrix
                        .expansions()
                        .iter()
                        .filter(|e| context.matches(e.path.as_str()))
                    {
                        if !expansion.is_static() {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::High)
                                    .confidence(Confidence::Low)
                                    .persona(Persona::Regular)
                                    .add_location(
                                        location
                                            .clone()
                                            .primary()
                                            .annotated("container image may be unpinned"),
                                    )
                                    .add_location(expansion.location())
                                    .build(document)?,
                            );
                            break;
                        } else {
                            // Try and parse the expanded value as an image reference.
                            let image = DockerUses::parse(&expansion.value);
                            match (image.tag(), image.hash()) {
                                // Image is pinned by hash.
                                (_, Some(_)) => continue,
                                // Docker image is pinned to "latest".
                                (Some("latest"), None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Regular)
                                        .add_location(
                                            location
                                                .clone()
                                                .primary()
                                                .annotated("container image is pinned to latest"),
                                        )
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(document)?,
                                ),
                                // Docker image is pined to some other tag.
                                (Some(_), None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Pedantic)
                                        .add_location(location.clone().primary().annotated(
                                            "container image is not pinned to a SHA256 hash",
                                        ))
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(document)?,
                                ),
                                // Image is unpinned.
                                (None, None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Regular)
                                        .add_location(
                                            location
                                                .clone()
                                                .primary()
                                                .annotated("container image is unpinned"),
                                        )
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(document)?,
                                ),
                            }
                        }
                    }
                }
                LoE::Literal(image) if image.image().is_empty() => continue,
                LoE::Literal(image) => {
                    self.check_image(image, location, document, &mut findings)?;
                }
            }
        }

        Ok(findings)
    }

    fn build_finding<'a, 'doc>(
        &self,
        location: &SymbolicLocation<'doc>,
        annotation: &'static str,
        confidence: Confidence,
        persona: Persona,
        document: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Finding<'doc>, AuditError> {
        let mut annotated_location = location.clone();
        annotated_location = annotated_location.annotated(annotation);
        Self::finding()
            .severity(Severity::High)
            .confidence(confidence)
            .add_location(annotated_location)
            .persona(persona)
            .build(document)
    }

    /// Classify a `DockerUses` image and push the appropriate finding.
    fn check_image<'a, 'doc>(
        &self,
        image: &DockerUses,
        location: &SymbolicLocation<'doc>,
        document: &'a impl AsDocument<'a, 'doc>,
        findings: &mut Vec<Finding<'doc>>,
    ) -> Result<(), AuditError> {
        match (image.tag(), image.hash()) {
            (_, Some(_)) => {}
            (Some("latest"), None) => {
                findings.push(self.build_finding(
                    location,
                    "container image is pinned to latest",
                    Confidence::High,
                    Persona::Regular,
                    document,
                )?);
            }
            (Some(_), None) => {
                findings.push(self.build_finding(
                    location,
                    "container image is not pinned to a SHA256 hash",
                    Confidence::High,
                    Persona::Pedantic,
                    document,
                )?);
            }
            (None, None) => {
                findings.push(self.build_finding(
                    location,
                    "container image is unpinned",
                    Confidence::High,
                    Persona::Regular,
                    document,
                )?);
            }
        }
        Ok(())
    }
}

audit_meta!(
    UnpinnedImages,
    "unpinned-images",
    "unpinned image references"
);

#[async_trait::async_trait]
impl Audit for UnpinnedImages {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_docker_action<'doc>(
        &self,
        docker: &DockerAction<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        // Nothing to do if the action references its own intrinsic 'Dockerfile'
        // rather than an external image.
        let DockerActionUses::Image(image) = &docker.image else {
            return Ok(vec![]);
        };

        self.classify_images(
            vec![(image, docker.location().with_keys(["image".into()]))],
            None,
            docker,
        )
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        let mut image_refs_with_locations: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)> =
            vec![];

        match &job.container {
            Some(Container::Name(image)) => {
                image_refs_with_locations.push((
                    image,
                    job.location().primary().with_keys(["container".into()]),
                ));
            }
            Some(Container::Container { image, .. }) => {
                image_refs_with_locations.push((
                    image,
                    job.location()
                        .primary()
                        .with_keys(["container".into(), "image".into()]),
                ));
            }
            None => {}
        }

        for (service, config) in job.services.iter() {
            if let Container::Container { image, .. } = &config {
                image_refs_with_locations.push((
                    image,
                    job.location().primary().with_keys([
                        "services".into(),
                        service.as_str().into(),
                        "image".into(),
                    ]),
                ));
            }
        }

        let findings = self.classify_images(image_refs_with_locations, job.matrix(), job)?;

        Ok(findings)
    }
}
