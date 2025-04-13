use std::sync::LazyLock;

use github_actions_models::common::Uses;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Deserializer};

use super::{Audit, AuditLoadError, AuditState, Finding, Step, audit_meta};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::{CompositeStep, uses::UsesExt as _};

pub(crate) struct UnpinnedUses {
    config: UnpinnedUsesConfig,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

static USES_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?mi)^[\w-]+/([\w\.-]+)|\*$"#).unwrap());

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UnpinnedUsesConfig {
    policy: IndexMap<UsesPattern, UsesPolicy>,
}

#[derive(Debug, Eq, PartialEq, Hash)]
enum UsesPattern {
    InOrg(String),
    InRepo(String),
    Any,
}

impl<'de> Deserialize<'de> for UsesPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;

        if raw == "*" {
            return Ok(UsesPattern::Any);
        }

        if !USES_PATTERN.is_match(&raw) {
            return Err(serde::de::Error::custom(format!(
                "invalid uses pattern: {raw}"
            )));
        }

        let (_, repo) = raw
            .split_once('/')
            .ok_or_else(|| serde::de::Error::custom(format!("invalid uses pattern: {raw}")))?;

        if repo == "*" {
            Ok(UsesPattern::InOrg(raw))
        } else {
            Ok(UsesPattern::InRepo(raw))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum UsesPolicy {
    Any,
    RefPin,
    HashPin,
}

impl Default for UnpinnedUsesConfig {
    fn default() -> Self {
        Self {
            policy: [
                (UsesPattern::InOrg("actions".into()), UsesPolicy::RefPin),
                (UsesPattern::InOrg("github".into()), UsesPolicy::RefPin),
                (UsesPattern::InOrg("dependabot".into()), UsesPolicy::RefPin),
                (UsesPattern::Any, UsesPolicy::HashPin),
            ]
            .into(),
        }
    }
}

impl UnpinnedUses {
    pub fn evaluate_pinning<'u>(&self, uses: &Uses) -> Option<(&'u str, Severity, Persona)> {
        // Don't evaluate pinning for local `uses:`, since unpinned references
        // are fully controlled by the repository anyways.
        // TODO: auditor-level findings instead, perhaps?
        if matches!(uses, Uses::Local(_)) {
            return None;
        }

        if uses.unpinned() {
            Some((
                "action is not pinned to a tag, branch, or hash ref",
                Severity::Medium,
                Persona::default(),
            ))
        } else if uses.unhashed() {
            Some((
                "action is not pinned to a hash ref",
                Severity::Low,
                Persona::Pedantic,
            ))
        } else {
            None
        }
    }
}

impl Audit for UnpinnedUses {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let config = state
            .config
            .rule_config(Self::ident())
            .map_err(|e| AuditLoadError::Config(e.to_string()))?
            .unwrap_or_default();

        Ok(Self { config })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(severity)
                    .persona(persona)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(annotation),
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

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(severity)
                    .persona(persona)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(annotation),
                    )
                    .build(step.action())?,
            );
        };

        Ok(findings)
    }
}
