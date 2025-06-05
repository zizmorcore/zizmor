use std::collections::HashMap;

use anyhow::Context;
use github_actions_models::common::{RepositoryUses, Uses};
use serde::Deserialize;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::uses::RepositoryUsesPattern;
use crate::models::{CompositeStep, Step, StepCommon, uses::UsesExt as _};

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
                    Some(RepositoryUsesPattern::Any) | None => "blanket".into(),
                    Some(RepositoryUsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(RepositoryUsesPattern::InRepo { owner, repo }) => {
                        format!("{owner}/{repo}/*")
                    }
                    Some(RepositoryUsesPattern::ExactRepo { owner, repo }) => {
                        format!("{owner}/{repo}")
                    }
                    Some(RepositoryUsesPattern::ExactPath {
                        owner,
                        repo,
                        subpath,
                    }) => {
                        format!("{owner}/{repo}/{subpath}")
                    }
                    // Not allowed in this audit.
                    Some(RepositoryUsesPattern::ExactWithRef { .. }) => unreachable!(),
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

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
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
                    .build(step)?,
            );
        };

        Ok(findings)
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
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?
            .unwrap_or_default();

        let policies = UnpinnedUsesPolicies::try_from(config)
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?;

        Ok(Self { policies })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

/// Config for the `unpinned-uses` rule.
///
/// This configuration is reified into an `UnpinnedUsesPolicies`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct UnpinnedUsesConfig {
    /// A mapping of `uses:` patterns to policies.
    policies: HashMap<RepositoryUsesPattern, UsesPolicy>,
}

impl Default for UnpinnedUsesConfig {
    fn default() -> Self {
        Self {
            policies: [
                (
                    RepositoryUsesPattern::InOwner("actions".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("github".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("dependabot".into()),
                    UsesPolicy::RefPin,
                ),
                (RepositoryUsesPattern::Any, UsesPolicy::HashPin),
            ]
            .into(),
        }
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
    policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>>,

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
    fn get_policy(&self, uses: &RepositoryUses) -> (Option<&RepositoryUsesPattern>, UsesPolicy) {
        match self.policy_tree.get(&uses.owner) {
            Some(policies) => {
                // Policies are ordered by specificity, so we can
                // iterate and return eagerly.
                for (uses_pattern, policy) in policies {
                    if uses_pattern.matches(uses) {
                        return (Some(uses_pattern), *policy);
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

impl TryFrom<UnpinnedUsesConfig> for UnpinnedUsesPolicies {
    type Error = anyhow::Error;

    fn try_from(config: UnpinnedUsesConfig) -> Result<Self, Self::Error> {
        let mut policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>> =
            HashMap::new();
        let mut default_policy = UsesPolicy::HashPin;

        for (pattern, policy) in config.policies {
            match pattern {
                // Patterns with refs don't make sense in this context, since
                // we're establishing policies for the refs themselves.
                RepositoryUsesPattern::ExactWithRef { .. } => {
                    return Err(anyhow::anyhow!("can't use exact ref patterns here"));
                }
                RepositoryUsesPattern::ExactPath { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::ExactRepo { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InRepo { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InOwner(ref owner) => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::Any => {
                    default_policy = policy;
                }
            }
        }

        // Sort the policies for each owner by specificity.
        for policies in policy_tree.values_mut() {
            policies.sort_by(|a, b| a.0.cmp(&b.0));
        }

        Ok(Self {
            policy_tree,
            default_policy,
        })
    }
}
