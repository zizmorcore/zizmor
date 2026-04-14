use github_actions_models::common::{EnvValue, Uses};

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::StepBodyCommon;
use crate::models::uses::RepositoryUsesExt;
use crate::models::{StepCommon, action::CompositeStep, workflow::Step};
use crate::state::AuditState;

use super::AuditLoadError;

static KNOWN_UNPINNED_TOOLS_ACTIONS: &[&str] =
    &["aquasecurity/trivy-action", "1password/load-secrets-action"];

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
            uses: Uses::Repository(uses),
            with,
        } = step.body()
        else {
            return Ok(findings);
        };

        if !KNOWN_UNPINNED_TOOLS_ACTIONS
            .iter()
            .any(|action| uses.matches(action))
        {
            return Ok(findings);
        }

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
