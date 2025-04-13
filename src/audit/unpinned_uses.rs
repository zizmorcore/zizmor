use std::collections::HashMap;
use std::sync::LazyLock;

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::{Deserialize, Deserializer};

use super::{Audit, AuditLoadError, AuditState, Finding, Step, audit_meta};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::{CompositeStep, uses::UsesExt as _};

pub(crate) struct UnpinnedUses {
    policies: UnpinnedUsesPolicies,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    pub fn evaluate_pinning(&self, uses: &Uses) -> Option<(String, Severity, Persona)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            // TODO: auditor-level findings instead, perhaps?
            Uses::Local(_) => None,
            // We don't have detailed policies for `uses: docker://` yet,
            // in part because evaluating the risk of a tagged versus hash-pinned
            // Docker image depends on the image and its registry).
            //
            // Instead, we produce a blanket finding for unpinned images,
            // and a pedantic-only finding for unhashed images.
            Uses::Docker(_) => {
                if uses.unpinned() {
                    Some((
                        "action is not pinned to a tag, branch, or hash ref".into(),
                        Severity::Medium,
                        Persona::default(),
                    ))
                } else if uses.unhashed() {
                    Some((
                        "action is not pinned to a hash".into(),
                        Severity::Low,
                        Persona::Pedantic,
                    ))
                } else {
                    None
                }
            }
            Uses::Repository(repo_uses) => {
                let (pattern, policy) = self.policies.get_policy(repo_uses);

                let pat_desc = match pattern {
                    Some(UsesPattern::Any) | None => "blanket".into(),
                    Some(UsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(UsesPattern::InRepo { owner, repo }) => format!("{owner}/{repo}"),
                };

                match policy {
                    UsesPolicy::Any => None,
                    UsesPolicy::RefPin => uses.unpinned().then_some((
                        format!(
                            "action is not pinned to a ref or hash (required by {pat_desc} policy)"
                        ),
                        Severity::High,
                        Persona::default(),
                    )),
                    UsesPolicy::HashPin => uses.unhashed().then_some((
                        format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                        Severity::High,
                        Persona::default(),
                    )),
                }
            }
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
            .rule_config::<UnpinnedUsesConfig>(Self::ident())
            .map_err(|e| AuditLoadError::Config(e.to_string()))?
            .unwrap_or_default();

        Ok(Self {
            policies: config.into(),
        })
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

// Matches patterns like `owner/repo` and `owner/*`.
static USES_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?mi)^[\w-]+/([\w\.-]+)|\*$"#).unwrap());

/// Config for the `unpinned-uses` rule.
///
/// This configuration is reified into an `UnpinnedUsesPolicies`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct UnpinnedUsesConfig {
    /// A mapping of `uses:` patterns to policies.
    policies: HashMap<UsesPattern, UsesPolicy>,
}

impl Default for UnpinnedUsesConfig {
    fn default() -> Self {
        Self {
            policies: [
                (UsesPattern::InOwner("actions".into()), UsesPolicy::RefPin),
                (UsesPattern::InOwner("github".into()), UsesPolicy::RefPin),
                (
                    UsesPattern::InOwner("dependabot".into()),
                    UsesPolicy::RefPin,
                ),
                (UsesPattern::Any, UsesPolicy::HashPin),
            ]
            .into(),
        }
    }
}

/// Represents a pattern for matching `uses` references.
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first.
#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
enum UsesPattern {
    /// `owner/repo`: matches all actions in the given repository.
    InRepo { owner: String, repo: String },
    /// `owner/*`: matches all actions in repositories owned by the given owner.
    InOwner(String),
    /// `*`: matches all actions in all repositories.
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

        let (owner, repo) = raw
            .split_once('/')
            .ok_or_else(|| serde::de::Error::custom(format!("invalid uses pattern: {raw}")))?;

        Ok(if repo == "*" {
            UsesPattern::InOwner(owner.into())
        } else {
            UsesPattern::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }
        })
    }
}

/// A singular policy for a `uses:` reference.
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum UsesPolicy {
    /// No policy; all `uses:` references are allowed, even unpinned ones.
    Any,
    /// `uses:` references must be pinned to a tag, branch, or hash ref.
    RefPin,
    /// `uses:` references must be pinned to a hash ref.
    HashPin,
}

/// Represents the set of policies used to evaluate `uses:` references.
struct UnpinnedUsesPolicies {
    /// The policy tree is a mapping of `owner` slugs to a list of
    /// `(pattern, policy)` pairs under that owner, ordered by specificity.
    ///
    /// For example, a config containing both `foo/*: hash-pin` and
    /// `foo/bar: ref-pin` would produce a policy tree like this:
    ///
    /// ```text
    /// foo:
    ///   - foo/bar: ref-pin
    ///   - foo/*: hash-pin
    /// ```
    ///
    /// This is done for performance reasons: a two-level structure here
    /// means that checking a `uses:` is a linear scan of the policies
    /// for that owner, rather than a full scan of all policies.
    policy_tree: HashMap<String, Vec<(UsesPattern, UsesPolicy)>>,

    /// This is the policy that's applied if nothing in the policy tree matches.
    ///
    /// Normally is this configured by an `*` entry in the config or by
    /// `UnpinnedUsesConfig::default()`. However, if the user explicitly
    /// omits a `*` rule, this will be `UsesPolicy::HashPin`.
    default_policy: UsesPolicy,
}

impl UnpinnedUsesPolicies {
    /// Returns the most specific policy for the given repository `uses` reference,
    /// or the default policy if none match.
    fn get_policy(&self, uses: &RepositoryUses) -> (Option<&UsesPattern>, UsesPolicy) {
        match self.policy_tree.get(&uses.owner) {
            Some(policies) => {
                // Policies are ordered by specificity, so we can
                // iterate and return eagerly.
                for (uses_pattern, policy) in policies {
                    match uses_pattern {
                        UsesPattern::InRepo { owner: _, repo } => {
                            if repo == &uses.repo {
                                return (Some(uses_pattern), *policy);
                            } else {
                                continue;
                            }
                        }
                        UsesPattern::InOwner(_) => return (Some(uses_pattern), *policy),
                        // NOTE: Unreachable because we only
                        // allow `*` to configure the default policy.
                        UsesPattern::Any => unreachable!(),
                    }
                }
                // The policies under `owner/` might be fully divergent
                // if there isn't an `owner/*` rule, so we fall back
                // to the default policy.
                (None, self.default_policy)
            }
            None => (None, self.default_policy),
        }
    }
}

impl From<UnpinnedUsesConfig> for UnpinnedUsesPolicies {
    fn from(config: UnpinnedUsesConfig) -> Self {
        let mut policy_tree: HashMap<String, Vec<(UsesPattern, UsesPolicy)>> = HashMap::new();
        let mut default_policy = UsesPolicy::HashPin;

        for (pattern, policy) in config.policies {
            match pattern {
                UsesPattern::InRepo { owner, repo } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((UsesPattern::InRepo { owner, repo }, policy));
                }
                UsesPattern::InOwner(owner) => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((UsesPattern::InOwner(owner), policy));
                }
                UsesPattern::Any => {
                    default_policy = policy;
                }
            }
        }

        // Sort the policies for each owner by specificity.
        for policies in policy_tree.values_mut() {
            policies.sort_by(|a, b| a.0.cmp(&b.0));
        }

        Self {
            policy_tree,
            default_policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UsesPattern;

    #[test]
    fn test_uses_pattern_ord() {
        let mut patterns = vec![
            UsesPattern::Any,
            UsesPattern::InRepo {
                owner: "owner".into(),
                repo: "repo".into(),
            },
            UsesPattern::InOwner("owner/*".into()),
        ];

        patterns.sort();

        assert_eq!(
            patterns,
            vec![
                UsesPattern::InRepo {
                    owner: "owner".into(),
                    repo: "repo".into()
                },
                UsesPattern::InOwner("owner/*".into()),
                UsesPattern::Any,
            ]
        );
    }
}
