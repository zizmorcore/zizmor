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
            Usage::Enabled(origins)
                if origins.contains(&ControlOrigin::Default { field: "version" }) =>
            {
                Some(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["uses".into()])
                                .subfeature(Subfeature::new(0, uses.raw()))
                                .annotated("action implicitly uses an unpinned latest version"),
                        ),
                )
            }
            Usage::Enabled(origins)
                if origins.contains(&ControlOrigin::Input { field: "version" }) =>
            {
                Some(
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
                                .with_keys(["with".into(), "version".into()])
                                .annotated("specifies `version: latest` which is unpinned"),
                        ),
                )
            }
            Usage::Conditional(origins)
                if origins.contains(&ControlOrigin::Input { field: "version" }) =>
            {
                Some(
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
                                .with_keys(["with".into(), "version".into()])
                                .annotated(
                                    "specifies `version` dynamically, which may be unpinned",
                                ),
                        ),
                )
            }
            Usage::Conditional(origins) if origins.contains(&ControlOrigin::WithExpression) => {
                Some(
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
                                .with_keys(["with".into()])
                                .annotated(
                                    "specifies `with` dynamically, so `version` may be unpinned",
                                ),
                        ),
                )
            }
            Usage::Enabled(_) | Usage::Conditional(_) | Usage::Always => None,
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
