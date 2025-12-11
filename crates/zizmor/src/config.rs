use std::{collections::HashMap, fs, num::NonZeroUsize, ops::Deref, str::FromStr};

use anyhow::{Context as _, anyhow};
use camino::Utf8Path;
use github_actions_models::common::RepositoryUses;
use serde::{
    Deserialize,
    de::{self, DeserializeOwned},
};
use thiserror::Error;

use crate::{
    App, CollectionOptions,
    audit::{
        AuditCore, dependabot_cooldown::DependabotCooldown, forbidden_uses::ForbiddenUses,
        unpinned_uses::UnpinnedUses,
    },
    finding::Finding,
    github::{Client, ClientError},
    models::uses::RepositoryUsesPattern,
    registry::input::RepoSlug,
};

const CONFIG_CANDIDATES: &[&str] = &[
    ".github/zizmor.yml",
    ".github/zizmor.yaml",
    "zizmor.yml",
    "zizmor.yaml",
];

#[derive(Error, Debug)]
#[error("configuration error in {path}")]
pub(crate) struct ConfigError {
    /// The path to the configuration file that caused this error.
    path: String,
    /// The source of this error.
    pub(crate) source: ConfigErrorInner,
}

#[derive(Error, Debug)]
pub(crate) enum ConfigErrorInner {
    /// An I/O error occurred while loading the input.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The overall configuration file is syntactically invalid.
    #[error("invalid configuration syntax")]
    Syntax(#[source] serde_yaml::Error),

    /// A specific audit's configuration is syntactically invalid.
    #[error("invalid syntax for audit `{1}`")]
    AuditSyntax(#[source] serde_yaml::Error, &'static str),

    /// The `unpinned-uses` config is semantically invalid.
    #[error("invalid `unpinned-uses` config")]
    UnpinnedUsesConfig(#[from] UnpinnedUsesConfigError),

    /// A GitHub API error occurred while fetching a remote config.
    #[error("GitHub API error while fetching remote config")]
    Client(#[from] ClientError),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct WorkflowRule {
    /// The workflow filename.
    pub(crate) filename: String,
    /// The (1-based) line within [`Self::filename`] that the rule occurs on.
    pub(crate) line: Option<usize>,
    /// The (1-based) column within [`Self::filename`] that the rule occurs on.
    pub(crate) column: Option<usize>,
}

impl FromStr for WorkflowRule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        // A rule has three parts, delimited by `:`, two of which
        // are optional: `foobar.yml:line:col`, where `line` and `col`
        // are optional. `col` can only be provided if `line` is provided.
        let parts = s.rsplitn(3, ':').collect::<Vec<_>>();
        let mut parts = parts.iter().rev();

        let filename = parts
            .next()
            .ok_or_else(|| anyhow!("rule is missing a filename component"))?;

        if !filename.ends_with(".yml") && !filename.ends_with(".yaml") {
            return Err(anyhow!("invalid workflow filename: {filename}"));
        }

        let line = parts
            .next()
            .map(|line| NonZeroUsize::from_str(line).map(|line| line.get()))
            .transpose()
            .with_context(|| "invalid line number component (must be 1-based)")?;
        let column = parts
            .next()
            .map(|col| NonZeroUsize::from_str(col).map(|col| col.get()))
            .transpose()
            .with_context(|| "invalid column number component (must be 1-based)")?;

        Ok(Self {
            filename: filename.to_string(),
            line,
            column,
        })
    }
}

impl<'de> Deserialize<'de> for WorkflowRule {
    fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        WorkflowRule::from_str(&raw).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditRuleConfig {
    /// Disables the audit entirely if `true`.
    #[serde(default)]
    disable: bool,
    /// A list of ignore rules for findings from this audit.
    #[serde(default)]
    ignore: Vec<WorkflowRule>,
    /// Rule-specific configuration.
    #[serde(default)]
    config: Option<serde_yaml::Mapping>,
}

/// Data model for zizmor's configuration file.
///
/// This is a "raw" representation that matches exactly what
/// we parse from a `zizmor.yml` file.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    rules: HashMap<String, AuditRuleConfig>,
}

impl RawConfig {
    fn load(contents: &str) -> Result<Self, ConfigErrorInner> {
        serde_yaml::from_str(contents).map_err(ConfigErrorInner::Syntax)
    }

    fn rule_config<T>(&self, ident: &'static str) -> Result<Option<T>, ConfigErrorInner>
    where
        T: DeserializeOwned,
    {
        self.rules
            .get(ident)
            .and_then(|rule_config| rule_config.config.as_ref())
            .map(|policy| serde_yaml::from_value::<T>(serde_yaml::Value::Mapping(policy.clone())))
            .transpose()
            .map_err(|e| ConfigErrorInner::AuditSyntax(e, ident))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DependabotCooldownConfig {
    pub(crate) days: NonZeroUsize,
}

impl Default for DependabotCooldownConfig {
    fn default() -> Self {
        Self {
            days: NonZeroUsize::new(7).expect("impossible"),
        }
    }
}

/// Slightly annoying wrapper for [`ForbiddenUsesConfigInner`], which is our
/// real configuration type for the `forbidden-uses` rule.
///
/// We need this wrapper type so that we can apply the `singleton_map`
/// deserializer to the inner type, ensuring that we deserialize from a
/// mapping with an explicit key discriminant (i.e. `allow:` or `deny:`)
/// rather than a YAML tag. We could work around this by using serde's
/// `untagged` instead, but this produces suboptimal user-facing error messages.
#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
pub(crate) struct ForbiddenUsesConfig(
    #[serde(with = "serde_yaml::with::singleton_map")] pub(crate) ForbiddenUsesConfigInner,
);

impl Deref for ForbiddenUsesConfig {
    type Target = ForbiddenUsesConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ForbiddenUsesConfigInner {
    Allow(Vec<RepositoryUsesPattern>),
    Deny(Vec<RepositoryUsesPattern>),
}

/// Config for the `unpinned-uses` rule.
///
/// This configuration is reified into an `UnpinnedUsesPolicies`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnpinnedUsesConfig {
    /// A mapping of `uses:` patterns to policies.
    policies: HashMap<RepositoryUsesPattern, UsesPolicy>,
}

/// A singular policy for a `uses:` reference.
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UsesPolicy {
    /// No policy; all `uses:` references are allowed, even unpinned ones.
    Any,
    /// `uses:` references must be pinned to a tag, branch, or hash ref.
    RefPin,
    /// `uses:` references must be pinned to a hash ref.
    HashPin,
}

/// Represents the set of policies used to evaluate `uses:` references.
#[derive(Clone, Debug)]
pub(crate) struct UnpinnedUsesPolicies {
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
    pub(crate) fn get_policy(
        &self,
        uses: &RepositoryUses,
    ) -> (Option<&RepositoryUsesPattern>, UsesPolicy) {
        match self.policy_tree.get(uses.owner()) {
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

impl Default for UnpinnedUsesPolicies {
    fn default() -> Self {
        Self {
            policy_tree: [
                (
                    "actions".into(),
                    vec![(
                        RepositoryUsesPattern::InOwner("actions".into()),
                        UsesPolicy::RefPin,
                    )],
                ),
                (
                    "github".into(),
                    vec![(
                        RepositoryUsesPattern::InOwner("github".into()),
                        UsesPolicy::RefPin,
                    )],
                ),
                (
                    "dependabot".into(),
                    vec![(
                        RepositoryUsesPattern::InOwner("dependabot".into()),
                        UsesPolicy::RefPin,
                    )],
                ),
            ]
            .into(),
            default_policy: UsesPolicy::HashPin,
        }
    }
}

/// Semantic errors that can occur while processing an `UnpinnedUsesConfig`
/// into an `UnpinnedUsesPolicies`.
#[derive(Error, Debug)]
pub(crate) enum UnpinnedUsesConfigError {
    /// A pattern with a ref was used in the config.
    #[error("cannot use exact ref patterns here: `{0}`")]
    ExactWithRefUsed(String),
}

impl TryFrom<UnpinnedUsesConfig> for UnpinnedUsesPolicies {
    type Error = UnpinnedUsesConfigError;

    fn try_from(config: UnpinnedUsesConfig) -> anyhow::Result<Self, Self::Error> {
        let mut policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>> =
            HashMap::new();
        let mut default_policy = UsesPolicy::HashPin;

        for (pattern, policy) in config.policies {
            match pattern {
                // Patterns with refs don't make sense in this context, since
                // we're establishing policies for the refs themselves.
                RepositoryUsesPattern::ExactWithRef { .. } => {
                    return Err(UnpinnedUsesConfigError::ExactWithRefUsed(
                        pattern.to_string(),
                    ));
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

/// zizmor's configuration.
///
/// This is a wrapper around [`RawConfig`] that pre-computes various
/// audit-specific fields so that failures are caught up-front
/// rather than at audit time. This also saves us some runtime
/// cost by avoiding potentially (very) repetitive deserialization
/// of per-audit configs (K audits * N inputs).
#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    raw: RawConfig,
    pub(crate) dependabot_cooldown_config: DependabotCooldownConfig,
    pub(crate) forbidden_uses_config: Option<ForbiddenUsesConfig>,
    pub(crate) unpinned_uses_policies: UnpinnedUsesPolicies,
}

impl Config {
    /// Loads a [`Config`] from the given contents.
    fn load(contents: &str) -> Result<Self, ConfigErrorInner> {
        let raw = RawConfig::load(contents)?;

        let dependabot_cooldown_config = raw
            .rule_config(DependabotCooldown::ident())?
            .unwrap_or_default();

        let forbidden_uses_config = raw.rule_config(ForbiddenUses::ident())?;

        let unpinned_uses_policies = {
            if let Some(unpinned_uses_config) =
                raw.rule_config::<UnpinnedUsesConfig>(UnpinnedUses::ident())?
            {
                UnpinnedUsesPolicies::try_from(unpinned_uses_config)?
            } else {
                UnpinnedUsesPolicies::default()
            }
        };

        Ok(Self {
            raw,
            dependabot_cooldown_config,
            forbidden_uses_config,
            unpinned_uses_policies,
        })
    }

    /// Discover a [`Config`] according to the collection options.
    ///
    /// This function models zizmor's current precedence rules for
    /// configuration discovery:
    /// 1. `--no-config` disables all config loading.
    /// 2. `--config <file>` uses the given config file globally,
    ///    which we've already loaded into `options.global_config`.
    /// 3. Otherwise, we use the provided `discover_fn` to attempt
    ///    to discover a config file. This function is typically one
    ///    of [`Config::discover_local`] or [`Config::discover_remote`]
    ///    depending on the input type.
    pub(crate) async fn discover<F>(
        options: &CollectionOptions,
        discover_fn: F,
    ) -> Result<Self, ConfigError>
    where
        F: AsyncFnOnce() -> Result<Option<Self>, ConfigError>,
    {
        if options.no_config {
            // User has explicitly disabled config loading.
            tracing::debug!("skipping config discovery: explicitly disabled");
            Ok(Self::default())
        } else if let Some(config) = &options.global_config {
            // The user gave us a (legacy) global config file,
            // which takes precedence over any discovered config.
            tracing::debug!("config discovery: using global config: {config:?}");
            Ok(config.clone())
        } else {
            // Attempt to discover a config file using the provided function.
            discover_fn().await.map(|conf| conf.unwrap_or_default())
        }
    }

    /// Discover a [`Config`] in the given directory.
    ///
    /// This uses the following discovery procedure:
    /// 1. If the given directory is `blahblah/.github/workflows/`,
    ///    start at the parent (i.e. `blahblah/.github/`). Otherwise, start
    ///    at the given directory. This first directory is the
    ///    first candidate path.
    /// 2. Look for `.github/zizmor.yml` or `zizmor.yml` in the
    ///    candidate path. If found, load and return it.
    /// 3. Otherwise, continue the search in the candidate path's
    ///    parent directory, repeating step 2, terminating when
    ///    we reach the filesystem root or the first .git directory.
    fn discover_in_dir(path: &Utf8Path) -> Result<Option<Self>, ConfigErrorInner> {
        tracing::debug!("attempting config discovery in `{path}`");

        let canonical = path.canonicalize_utf8()?;

        let mut candidate_path = if canonical.file_name() == Some("workflows") {
            let Some(parent) = canonical.parent() else {
                tracing::debug!("no parent for `{canonical}`, cannot discover config");
                return Ok(None);
            };

            parent
        } else {
            canonical.as_path()
        };

        loop {
            for candidate in CONFIG_CANDIDATES {
                let candidate_path = candidate_path.join(candidate);
                if candidate_path.is_file() {
                    tracing::debug!("found config candidate at `{candidate_path}`");
                    return Ok(Some(Self::load(&fs::read_to_string(&candidate_path)?)?));
                }
            }

            if candidate_path.join(".git").is_dir() {
                tracing::debug!("found `{candidate_path}/.git`, stopping search");
                return Ok(None);
            }

            let Some(parent) = candidate_path.parent() else {
                tracing::debug!("reached filesystem root without finding a config");
                return Ok(None);
            };

            candidate_path = parent;
        }
    }

    /// Discover a [`Config`] using rules applicable to the given path.
    ///
    /// For files, this attempts to walk up the directory tree,
    /// looking for either a `zizmor.yml`.
    /// The walk starts at the file's grandparent directory.
    ///
    /// For directories, this attempts to find a `.github/zizmor.yml` or
    /// `zizmor.yml` in the directory itself.
    pub(crate) async fn discover_local(path: &Utf8Path) -> Result<Option<Self>, ConfigError> {
        tracing::debug!("discovering config for local input `{path}`");

        if path.is_dir() {
            Self::discover_in_dir(path).map_err(|err| ConfigError {
                path: path.to_string(),
                source: err,
            })
        } else {
            let parent = match path.parent().map(|p| p.as_str()) {
                // NOTE(ww): Annoying: `parent()` returns `None` for root paths,
                // but `Some("")` for paths like `action.yml` (i.e. no parent dir).
                // We have to handle this sentinel case explicitly, since
                // `canonicalize("")` isn't valid.
                Some("") => Utf8Path::new("."),
                Some(p) => p.into(),
                None => {
                    tracing::debug!("no parent for {path:?}, cannot discover config");
                    return Ok(None);
                }
            };

            Self::discover_in_dir(parent).map_err(|err| ConfigError {
                path: path.to_string(),
                source: err,
            })
        }
    }

    /// Discover a [`Config`] for a repository slug.
    ///
    /// This will look for a `.github/zizmor.yml` or `zizmor.yml`
    /// in the repository's root directory.
    pub(crate) async fn discover_remote(
        client: &Client,
        slug: &RepoSlug,
    ) -> Result<Option<Self>, ConfigError> {
        for candidate in CONFIG_CANDIDATES {
            match client.fetch_single_file(slug, candidate).await {
                Ok(Some(contents)) => {
                    tracing::debug!("retrieved config candidate `{candidate}` for {slug}");

                    return Some(Self::load(&contents).map_err(|err| ConfigError {
                        path: candidate.to_string(),
                        source: err,
                    }))
                    .transpose();
                }
                Ok(None) => {
                    continue;
                }
                Err(err) => {
                    return Err(ConfigError {
                        path: candidate.to_string(),
                        source: err.into(),
                    });
                }
            }
        }

        Ok(None)
    }

    /// Loads a global [`Config`] for the given [`App`].
    ///
    /// Returns `Ok(None)` unless the user explicitly specifies
    /// a config file with `--config`.
    pub(crate) fn global(app: &App) -> Result<Option<Self>, ConfigError> {
        if app.no_config {
            Ok(None)
        } else if let Some(path) = &app.config {
            tracing::debug!("loading config from `{path}`");

            let contents = fs::read_to_string(path).map_err(|err| ConfigError {
                path: path.to_string(),
                source: ConfigErrorInner::Io(err),
            })?;

            Ok(Some(Self::load(&contents).map_err(|err| ConfigError {
                path: path.to_string(),
                source: err,
            })?))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` if this [`Config`] disables the given audit rule.
    pub(crate) fn disables(&self, ident: &str) -> bool {
        self.raw
            .rules
            .get(ident)
            .map(|rule_config| rule_config.disable)
            .unwrap_or(false)
    }

    /// Returns `true` if this [`Config`] has an ignore rule for the
    /// given finding.
    pub(crate) fn ignores(&self, finding: &Finding<'_>) -> bool {
        let Some(rule_config) = self.raw.rules.get(finding.ident) else {
            return false;
        };

        let ignores = &rule_config.ignore;

        // If *any* location in the finding matches an ignore rule,
        // we consider the entire finding ignored.
        // This will hopefully minimize confusion when a finding spans
        // multiple files, as the first location is the one a user will
        // typically ignore, suppressing the rest in the process.
        // TODO: This needs to filter on something other than filename,
        // since that doesn't work for action definitions (which are
        // all `action.yml`).
        for loc in &finding.locations {
            for rule in ignores
                .iter()
                .filter(|i| i.filename == loc.symbolic.key.filename())
            {
                match rule {
                    // Rule has a line and (maybe) a column.
                    WorkflowRule {
                        line: Some(line),
                        column,
                        ..
                    } => {
                        if *line == loc.concrete.location.start_point.row + 1
                            && column.is_none_or(|col| {
                                col == loc.concrete.location.start_point.column + 1
                            })
                        {
                            return true;
                        } else {
                            continue;
                        }
                    }
                    // Rule has no line/col, so we match by virtue of the filename matching.
                    WorkflowRule {
                        line: None,
                        column: None,
                        ..
                    } => return true,
                    _ => unreachable!(),
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::WorkflowRule;

    #[test]
    fn test_parse_workflow_rule() -> anyhow::Result<()> {
        assert_eq!(
            WorkflowRule::from_str("foo.yml:1:2")?,
            WorkflowRule {
                filename: "foo.yml".into(),
                line: Some(1),
                column: Some(2)
            }
        );

        assert_eq!(
            WorkflowRule::from_str("foo.yml:123")?,
            WorkflowRule {
                filename: "foo.yml".into(),
                line: Some(123),
                column: None
            }
        );

        assert!(WorkflowRule::from_str("foo.yml:0:0").is_err());
        assert!(WorkflowRule::from_str("foo.yml:1:0").is_err());
        assert!(WorkflowRule::from_str("foo.yml:0:1").is_err());
        assert!(WorkflowRule::from_str("foo.yml:123:").is_err());
        assert!(WorkflowRule::from_str("foo.yml::").is_err());
        assert!(WorkflowRule::from_str("foo.yml::1").is_err());
        assert!(WorkflowRule::from_str("foo::1").is_err());
        assert!(WorkflowRule::from_str("foo.unrelated::1").is_err());
        // TODO: worth dealing with?
        // assert!(WorkflowRule::from_str(".yml:1:1").is_err());
        assert!(WorkflowRule::from_str("::1").is_err());
        assert!(WorkflowRule::from_str(":1:1").is_err());
        assert!(WorkflowRule::from_str("1:1").is_err());

        Ok(())
    }
}
