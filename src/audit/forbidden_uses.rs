use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditState, Finding, Step, audit_meta};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::{CompositeStep, uses::RepositoryUsesExt};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
enum ForbiddenUsesListType {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
struct ForbiddenUsesConfig {
    #[serde(default)]
    list_type: ForbiddenUsesListType,
    actions: Vec<String>,
}

const DEFAULT_ALLOWLIST: [&str; 1] = ["actions/*"];

impl Default for ForbiddenUsesConfig {
    fn default() -> Self {
        Self {
            list_type: ForbiddenUsesListType::Allow,
            actions: DEFAULT_ALLOWLIST
                .iter()
                .map(|item| item.to_string())
                .collect(),
        }
    }
}

impl ForbiddenUsesConfig {
    fn is_uses_allowed(&self, uses: &RepositoryUses) -> bool {
        let matched = self
            .actions
            .iter()
            .any(|allowlist_entry| uses.matches(allowlist_entry));
        match &self.list_type {
            ForbiddenUsesListType::Allow => matched,
            ForbiddenUsesListType::Deny => !matched,
        }
    }

    #[inline]
    fn is_uses_denied(&self, uses: &RepositoryUses) -> bool {
        !self.is_uses_allowed(uses)
    }
}

pub(crate) struct ForbiddenUses {
    persona: Persona,
    severity: Severity,
    config: ForbiddenUsesConfig,
}

audit_meta!(ForbiddenUses, "forbidden-uses", "fobidden action used");

impl ForbiddenUses {
    pub fn evaluate_allowlist<'u>(&self, uses: &Uses) -> bool {
        let Uses::Repository(repo_uses) = uses else {
            return false;
        };

        self.config.is_uses_denied(repo_uses)
    }
}

impl Audit for ForbiddenUses {
    fn new(state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let (persona, severity, config) = match state.config.rule_config(Self::ident())? {
            Some(config) => (Persona::default(), Severity::High, config),
            None => (
                Persona::Auditor,
                Severity::Unknown,
                ForbiddenUsesConfig::default(),
            ),
        };

        Ok(Self {
            persona,
            severity,
            config,
        })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if self.evaluate_allowlist(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(self.severity)
                    .persona(self.persona)
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

        if self.evaluate_allowlist(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(self.severity)
                    .persona(self.persona)
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
