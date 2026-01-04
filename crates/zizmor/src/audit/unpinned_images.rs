use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    state::AuditState,
};

use github_actions_expressions::Expr;
use github_actions_models::common::{DockerUses, expr::LoE};
use github_actions_models::workflow::job::Container;

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct UnpinnedImages;

impl UnpinnedImages {
    fn build_finding<'doc>(
        &self,
        location: &SymbolicLocation<'doc>,
        annotation: &'static str,
        confidence: Confidence,
        persona: Persona,
        job: &super::NormalJob<'doc>,
    ) -> Result<Finding<'doc>, AuditError> {
        let mut annotated_location = location.clone();
        annotated_location = annotated_location.annotated(annotation);
        Self::finding()
            .severity(Severity::High)
            .confidence(confidence)
            .add_location(annotated_location)
            .persona(persona)
            .build(job)
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

    async fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        let mut image_refs_with_locations: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)> =
            vec![];

        if let Some(Container::Container { image, .. }) = &job.container {
            image_refs_with_locations.push((
                image,
                job.location()
                    .primary()
                    .with_keys(["container".into(), "image".into()]),
            ));
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

        // TODO: Clean this mess up.
        for (image, ref location) in image_refs_with_locations {
            match image {
                LoE::Expr(expr) => {
                    let context = match Expr::parse(expr.as_bare()).map(|e| e.inner) {
                        // Our expression is `${{ matrix.abc... }}`.
                        Ok(Expr::Context(context)) if context.child_of("matrix") => context,
                        // An invalid expression, or otherwise any expression that's
                        // more complex than a simple matrix reference.
                        // TODO: Be more precise in some of these cases.
                        _ => {
                            findings.push(self.build_finding(
                                location,
                                "container image may be unpinned",
                                Confidence::Low,
                                Persona::Regular,
                                job,
                            )?);
                            continue;
                        }
                    };

                    let Some(matrix) = job.matrix() else {
                        tracing::warn!(
                            "job references {expr} but has no matrix",
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
                                    .build(job)?,
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
                                        .build(job)?,
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
                                        .build(job)?,
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
                                        .build(job)?,
                                ),
                            }
                        }
                    }
                }
                LoE::Literal(image) => match image.hash() {
                    Some(_) => continue,
                    None => match image.tag() {
                        Some("latest") => {
                            findings.push(self.build_finding(
                                location,
                                "container image is pinned to latest",
                                Confidence::High,
                                Persona::Regular,
                                job,
                            )?);
                        }
                        None => {
                            findings.push(self.build_finding(
                                location,
                                "container image is unpinned",
                                Confidence::High,
                                Persona::Regular,
                                job,
                            )?);
                        }
                        Some(_) => {
                            findings.push(self.build_finding(
                                location,
                                "container image is not pinned to a SHA256 hash",
                                Confidence::High,
                                Persona::Pedantic,
                                job,
                            )?);
                        }
                    },
                },
            }
        }

        Ok(findings)
    }
}
