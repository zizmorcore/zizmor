use anyhow::{Context, anyhow};
use github_actions_models::common::Uses;

use super::{Audit, AuditLoadError, AuditState, Finding, Step, audit_meta};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::CompositeStep;
use serde::Deserialize;

pub(crate) struct ForbiddenUses {
    config: ForbiddenUsesConfig,
}

audit_meta!(ForbiddenUses, "forbidden-uses", "forbidden action used");

impl ForbiddenUses {
    pub fn use_denied(&self, uses: &Uses) -> bool {
        todo!()
    }
}

impl Audit for ForbiddenUses {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let Some(config) = state
            .config
            .rule_config(Self::ident())
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?
        else {
            return Err(AuditLoadError::Skip(anyhow!("audit not configured")));
        };

        Ok(Self { config })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if self.use_denied(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated("action is not on the allowlist"),
                    )
                    .build(step.workflow())?,
            );
        };

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if self.use_denied(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated("action is not on the allowlist"),
                    )
                    .build(step.action())?,
            );
        };

        Ok(findings)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", untagged)]
enum ForbiddenUsesConfig {
    Allow { allow: Vec<String> },
    Deny { deny: Vec<String> },
}
