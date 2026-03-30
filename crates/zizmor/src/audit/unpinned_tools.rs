use std::sync::LazyLock;

use github_actions_models::common::{EnvValue, Uses};

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::StepBodyCommon;
use crate::models::coordinate::ActionCoordinate;
use crate::models::{StepCommon, action::CompositeStep, workflow::Step};
use crate::state::AuditState;

use super::AuditLoadError;

#[allow(clippy::unwrap_used)]
static KNOWN_UNPINNED_TOOLS_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    vec![
        // https://github.com/aquasecurity/trivy-action/blob/master/action.yaml
        ActionCoordinate::NotConfigurable("aquasecurity/trivy-action".parse().unwrap()),
        // https://github.com/1Password/load-secrets-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable("1password/load-secrets-action".parse().unwrap()),
    ]
});

pub(crate) struct UnpinnedTools;

audit_meta!(
    UnpinnedTools,
    "unpinned-tools",
    "unpinned underlying tools used by action are potentially vulnerable"
);

impl UnpinnedTools {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let StepBodyCommon::Uses {
            uses: Uses::Repository(_),
            with,
        } = step.body()
        else {
            return Ok(findings);
        };

        for coord in KNOWN_UNPINNED_TOOLS_ACTIONS.iter() {
            if coord.usage(step).is_some() {
                let finding = match with.get("version") {
                    None => Some(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .add_location(
                                step.location()
                                    .primary()
                                    .with_keys(["uses".into()])
                                    .annotated("this action's tool version is not pinned"),
                            ),
                    ),
                    Some(EnvValue::String(v)) if v == "latest" => Some(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .add_location(
                                step.location()
                                    .with_keys(["uses".into()])
                                    .annotated("this action"),
                            )
                            .add_location(
                                step.location()
                                    .primary()
                                    .with_keys(["with".into(), "version".into()])
                                    .annotated("specifies `version: latest` which is unpinned"),
                            ),
                    ),
                    Some(_) => None,
                };

                if let Some(finding) = finding {
                    findings.push(finding.build(step)?);
                }
            }
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
