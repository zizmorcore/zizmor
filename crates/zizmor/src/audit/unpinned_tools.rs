use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::{
    StepBodyCommon, StepCommon,
    action::CompositeStep,
    coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, ControlOrigin, Toggle, Usage},
    workflow::Step,
};
use crate::state::AuditState;

use super::AuditLoadError;

#[allow(clippy::unwrap_used)]
static KNOWN_UNPINNED_TOOLS_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    ["aquasecurity/setup-trivy", "1password/load-secrets-action"]
        .into_iter()
        .map(|uses_pattern| ActionCoordinate::Configurable {
            uses_pattern: uses_pattern.parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "version",
                ControlFieldType::Exact(&["latest"]),
                true,
            ),
        })
        .chain([
            ActionCoordinate::Configurable {
                uses_pattern: "extractions/setup-just".parse().unwrap(),
                control: ControlExpr::field(
                    Toggle::OptIn,
                    "just-version",
                    ControlFieldType::Exact(&["*"]),
                    true,
                ),
            },
            ActionCoordinate::Configurable {
                uses_pattern: "extractions/setup-crate".parse().unwrap(),
                control: ControlExpr::field(
                    Toggle::OptIn,
                    "version",
                    ControlFieldType::Exact(&["*"]),
                    true,
                ),
            },
        ])
        .collect()
});

pub(crate) struct UnpinnedTools;

audit_meta!(
    UnpinnedTools,
    "unpinned-tools",
    "action installs an unpinned external tool"
);

impl UnpinnedTools {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            ..
        }) = step.body()
        else {
            return Ok(findings);
        };

        let Some(usage) = KNOWN_UNPINNED_TOOLS_ACTIONS
            .iter()
            .find_map(|coordinate| coordinate.usage(step))
        else {
            return Ok(findings);
        };

        let finding = match usage {
            // The action is definitely installing an unpinned tool, because...
            Usage::Enabled(origins) => {
                if let Some(field) = origins.iter().find_map(|origin| match origin {
                    ControlOrigin::Default { field } => Some(*field),
                    _ => None,
                }) {
                    // (a) the user didn't set any input, and the default is unpinned.
                    Some(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .add_location(
                                step.location()
                                    .primary()
                                    .with_keys(["uses".into()])
                                    .subfeature(Subfeature::new(0, uses.raw()))
                                    .annotated(format!(
                                        "omitting `{field}` implicitly selects an unpinned tool version"
                                    )),
                            ),
                    )
                } else {
                    // (b) The user explicitly set the field to enable unpinning,
                    // e.g. `version: latest`.
                    origins
                        .iter()
                        .find_map(|origin| match origin {
                            ControlOrigin::Input { field } => Some(*field),
                            _ => None,
                        })
                        .map(|field| {
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Medium)
                                .add_location(
                                    step.location()
                                        .with_keys(["uses".into()])
                                        .subfeature(Subfeature::new(0, uses.raw()))
                                        .annotated("this action"),
                                )
                                .add_location(
                                    step.location()
                                        .primary()
                                        .with_keys(["with".into(), field.into()])
                                        .annotated("selects an unpinned tool version".to_string()),
                                )
                        })
                }
            }
            // The action *might* be installing an unpinned tool, but we don't
            // know for sure because the input that controls pinning is
            // opaque (e.g. `version: ${{ expr }}`).
            // TODO: we could probably pierce some expressions here, e.g. `matrix`
            // and `input` evaluations. The coordinate API could also potentially
            // do that for us.
            Usage::Conditional(origins) => origins
                .iter()
                .find_map(|origin| match origin {
                    ControlOrigin::Input { field } => Some(*field),
                    _ => None,
                })
                .map(|field| {
                    Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Medium)
                        .add_location(
                            step.location()
                                .with_keys(["uses".into()])
                                .subfeature(Subfeature::new(0, uses.raw()))
                                .annotated("this action"),
                        )
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), field.into()])
                                .annotated("tool version may be unpinned".to_string()),
                        )
                }),
            // TODO: We don't have any of these at the moment, but in the future
            // we might detect actions that always install an unpinned version
            // no matter what.
            Usage::Always => None,
        };

        if let Some(finding) = finding {
            findings.push(finding.build(step)?);
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedTools {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}
