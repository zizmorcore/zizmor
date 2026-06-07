use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::{AsDocument, action::DockerAction, workflow::matrix::Matrix},
    state::AuditState,
};

use github_actions_expressions::{Expr, SpannedExpr, literal::Literal};
use github_actions_models::workflow::job::Container;
use github_actions_models::{
    action::DockerActionUses,
    common::{DockerUses, expr::LoE},
};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct UnpinnedImages;

/// A single candidate image reference, collected from a job or action and
/// expanded through matrix references where possible.
struct ImageCandidate<'doc> {
    annotation: &'static str,
    confidence: Confidence,
    persona: Persona,
    location: SymbolicLocation<'doc>,
    related: Vec<SymbolicLocation<'doc>>,
}

impl<'doc> ImageCandidate<'doc> {
    /// A candidate for a concrete image reference that we can analyze precisely.
    ///
    /// Returns `None` if the image is empty (i.e. no container) or is
    /// acceptably pinned by a SHA256 hash.
    fn concrete(
        image: &DockerUses,
        location: SymbolicLocation<'doc>,
        related: Vec<SymbolicLocation<'doc>>,
    ) -> Option<Self> {
        if image.image().is_empty() {
            return None;
        }

        let (annotation, persona) = match (image.tag(), image.hash()) {
            // Pinned by hash: nothing to report.
            (_, Some(_)) => return None,
            (Some("latest"), None) => ("container image is pinned to latest", Persona::Regular),
            (Some(_), None) => (
                "container image is not pinned to a SHA256 hash",
                Persona::Pedantic,
            ),
            (None, None) => ("container image is unpinned", Persona::Regular),
        };

        Some(Self {
            annotation,
            confidence: Confidence::High,
            persona,
            location,
            related,
        })
    }

    /// A candidate for an image reference that we can't analyze statically,
    /// e.g. one derived from a non-`matrix` context or a dynamic matrix
    /// expansion.
    fn opaque(location: SymbolicLocation<'doc>, related: Vec<SymbolicLocation<'doc>>) -> Self {
        Self {
            annotation: "container image may be unpinned",
            confidence: Confidence::Low,
            persona: Persona::Regular,
            location,
            related,
        }
    }
}

/// Collect all candidate image references from a single image expression,
/// expanding through the matrix where possible.
fn collect_candidates<'doc>(
    image: &'doc LoE<DockerUses>,
    location: &SymbolicLocation<'doc>,
    matrix: Option<&Matrix<'doc>>,
) -> Vec<ImageCandidate<'doc>> {
    match image {
        // A literal image reference, e.g. `image: foo:1.2.3`.
        LoE::Literal(image) => ImageCandidate::concrete(image, location.clone(), vec![])
            .into_iter()
            .collect(),
        // An expression, e.g. `image: ${{ matrix.image }}`. We expand it into
        // its possible leaf values and analyze each.
        LoE::Expr(expr) => {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                // We can't even parse the expression, so we can't say anything
                // precise about it.
                return vec![ImageCandidate::opaque(location.clone(), vec![])];
            };

            let leaves = parsed.leaf_expressions();
            // When the entire expression is a single leaf (e.g. `${{ matrix.image }}`),
            // it spans the whole feature and we annotate it directly. Otherwise
            // each leaf gets its own subfeature location within the expression.
            let single_leaf = leaves.len() == 1;

            leaves
                .into_iter()
                .flat_map(|leaf| {
                    let leaf_location = if single_leaf {
                        location.clone()
                    } else {
                        location
                            .clone()
                            .subfeature(Subfeature::new(0, subfeature::Fragment::from(leaf)))
                    };

                    candidates_for_leaf(leaf, leaf_location, matrix)
                })
                .collect()
        }
    }
}

/// Collect candidate image references from a single leaf expression.
fn candidates_for_leaf<'doc>(
    leaf: &SpannedExpr<'_>,
    location: SymbolicLocation<'doc>,
    matrix: Option<&Matrix<'doc>>,
) -> Vec<ImageCandidate<'doc>> {
    match &leaf.inner {
        // A string literal can be analyzed precisely as an image reference.
        Expr::Literal(Literal::String(image)) => {
            if image.is_empty() {
                // Empty string literals contribute no image reference.
                vec![]
            } else {
                ImageCandidate::concrete(&DockerUses::parse(image.as_ref()), location, vec![])
                    .into_iter()
                    .collect()
            }
        }
        // A `matrix` context expands into its concrete values; analyze each.
        Expr::Context(context) if context.child_of("matrix") => {
            let Some(matrix) = matrix else {
                tracing::warn!(
                    "image references {raw} but job has no matrix",
                    raw = leaf.origin.raw
                );
                return vec![];
            };

            matrix
                .expansions()
                .iter()
                .filter(|expansion| context.matches(expansion.path.as_str()))
                .flat_map(|expansion| {
                    if expansion.is_static() {
                        ImageCandidate::concrete(
                            &DockerUses::parse(&expansion.value),
                            location.clone(),
                            vec![
                                matrix.location().key_only(),
                                expansion.location().annotated(format!(
                                    "this expansion of {path}",
                                    path = expansion.path
                                )),
                            ],
                        )
                        .into_iter()
                        .collect()
                    } else {
                        // The expansion itself contains an expression, so we
                        // can't analyze it statically.
                        vec![ImageCandidate::opaque(
                            location.clone(),
                            vec![expansion.location()],
                        )]
                    }
                })
                .collect()
        }
        // Any other leaf (non-`matrix` context, function call, etc.) can't be
        // analyzed statically.
        _ => vec![ImageCandidate::opaque(location, vec![])],
    }
}

impl UnpinnedImages {
    /// Collect every candidate image reference from a list of image
    /// expressions (expanding through the matrix where possible) and emit
    /// findings for any that are unpinned.
    fn classify_images<'a, 'doc>(
        &self,
        image_refs: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)>,
        matrix: Option<Matrix<'doc>>,
        document: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (image, location) in image_refs {
            for candidate in collect_candidates(image, &location, matrix.as_ref()) {
                let mut finding = Self::finding()
                    .severity(Severity::High)
                    .confidence(candidate.confidence)
                    .persona(candidate.persona)
                    .add_location(candidate.location.annotated(candidate.annotation));

                for related in candidate.related {
                    finding = finding.add_location(related);
                }

                findings.push(finding.build(document)?);
            }
        }

        Ok(findings)
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
        let mut image_refs: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)> = vec![];

        match &job.container {
            Some(Container::Name(image)) => {
                image_refs.push((
                    image,
                    job.location().primary().with_keys(["container".into()]),
                ));
            }
            Some(Container::Container { image, .. }) => {
                image_refs.push((
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
                image_refs.push((
                    image,
                    job.location().primary().with_keys([
                        "services".into(),
                        service.as_str().into(),
                        "image".into(),
                    ]),
                ));
            }
        }

        self.classify_images(image_refs, job.matrix(), job)
    }
}
