use github_actions_models::common::Uses;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::config::{Config, ForbiddenUsesConfig};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::{StepCommon, action::CompositeStep, workflow::Step};

pub(crate) struct ForbiddenUses;

audit_meta!(ForbiddenUses, "forbidden-uses", "forbidden action used");

impl ForbiddenUses {
    fn use_denied(&self, uses: &Uses, config: &ForbiddenUsesConfig) -> bool {
        match uses {
            // Local uses are never denied.
            Uses::Local(_) => false,
            // TODO: Support Docker uses here?
            // We'd need some equivalent to RepositoryUsesPattern
            // but for Docker uses, which will be slightly annoying.
            Uses::Docker(_) => {
                tracing::warn!("can't evaluate direct Docker uses");
                false
            }
            Uses::Repository(uses) => match config {
                ForbiddenUsesConfig::Allow { allow } => {
                    !allow.iter().any(|pattern| pattern.matches(uses))
                }
                ForbiddenUsesConfig::Deny { deny } => {
                    deny.iter().any(|pattern| pattern.matches(uses))
                }
            },
        }
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(config) = config.forbidden_uses_config.as_ref() else {
            tracing::trace!("no forbidden-uses config for this input; skipping");
            return Ok(findings);
        };

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if self.use_denied(uses, config) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .annotated("use of this action is forbidden"),
                    )
                    .build(step)?,
            );
        };

        Ok(findings)
    }
}

impl Audit for ForbiddenUses {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step, config)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step, config)
    }
}
