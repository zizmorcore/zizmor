//! "v2" Dependabot models.
//!
//! Resources:
//! * [Configuration options for the `dependabot.yml` file](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
//! * [JSON Schema for Dependabot v2](https://json.schemastore.org/dependabot-2.0.json)

use indexmap::{IndexMap, IndexSet};
use serde::Deserialize;

/// A `dependabot.yml` configuration file.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Dependabot {
    /// Invariant: `2`
    pub version: u64,
    #[serde(default)]
    pub enable_beta_ecosystems: bool,
    #[serde(default)]
    pub registries: IndexMap<String, Registry>,
    pub updates: Vec<Update>,
}

/// Different registries known to Dependabot.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum Registry {
    ComposerRepository {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
    DockerRegistry {
        url: String,
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        replaces_base: bool,
    },
    Git {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
    HexOrganization {
        organization: String,
        key: Option<String>,
    },
    HexRepository {
        repo: Option<String>,
        url: String,
        auth_key: Option<String>,
        public_key_fingerprint: Option<String>,
    },
    MavenRepository {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
    NpmRegistry {
        url: String,
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        replaces_base: bool,
    },
    NugetFeed {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
    PythonIndex {
        url: String,
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        replaces_base: bool,
    },
    RubygemsServer {
        url: String,
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        replaces_base: bool,
    },
    TerraformRegistry {
        url: String,
        token: Option<String>,
    },
}

/// A single `update` directive.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Update {
    #[serde(default)]
    pub allow: Vec<Allow>,
    #[serde(default)]
    pub assignees: IndexSet<String>,
    pub commit_message: Option<CommitMessage>,
    pub directory: String,
    #[serde(default)]
    pub groups: IndexMap<String, Group>,
    #[serde(default)]
    pub ignore: Vec<Ignore>,
    #[serde(default)]
    pub insecure_external_code_execution: AllowDeny,
    /// Labels to apply to this update group's pull requests.
    ///
    /// The default label is `dependencies`.
    #[serde(default = "default_labels")]
    pub labels: IndexSet<String>,
    pub milestone: Option<u64>,
    /// The maximum number of pull requests to open at a time from this
    /// update group.
    ///
    /// The default maximum is 5.
    #[serde(default = "default_open_pull_requests_limit")]
    pub open_pull_requests_limit: u64,
    pub package_ecosystem: PackageEcosystem,
    // TODO: pull-request-branch-name
    #[serde(default)]
    pub rebase_strategy: RebaseStrategy,
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
    pub registries: Vec<String>,
    #[serde(default)]
    pub reviewers: IndexSet<String>,
    pub schedule: Schedule,
    pub target_branch: Option<String>,
    #[serde(default)]
    pub vendor: bool,
    pub versioning_strategy: Option<VersioningStrategy>,
}

#[inline]
fn default_labels() -> IndexSet<String> {
    IndexSet::from(["dependencies".to_string()])
}

#[inline]
fn default_open_pull_requests_limit() -> u64 {
    // https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#open-pull-requests-limit
    5
}

/// Allow rules for Dependabot updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Allow {
    pub dependency_name: Option<String>,
    pub dependency_type: Option<DependencyType>,
}

/// Dependency types in `allow` rules.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyType {
    Direct,
    Indirect,
    All,
    Production,
    Development,
}

/// Commit message settings for Dependabot updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct CommitMessage {
    pub prefix: Option<String>,
    pub prefix_development: Option<String>,
    /// Invariant: `"scope"`
    pub include: Option<String>,
}

/// Group settings for batched updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Group {
    /// This can only be [`DependencyType::Development`] or
    /// [`DependencyType::Production`].
    pub dependency_type: Option<DependencyType>,
    #[serde(default)]
    pub patterns: IndexSet<String>,
    #[serde(default)]
    pub exclude_patterns: IndexSet<String>,
    #[serde(default)]
    pub update_types: IndexSet<UpdateType>,
}

/// Update types for grouping.
#[derive(Deserialize, Debug, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateType {
    Major,
    Minor,
    Patch,
}

/// Dependency ignore settings for updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Ignore {
    pub dependency_name: Option<String>,
    /// These are, inexplicably, not [`UpdateType`] variants.
    /// Instead, they're strings like `"version-update:semver-{major,minor,patch}"`.
    #[serde(default)]
    pub update_types: IndexSet<String>,
    #[serde(default)]
    pub versions: IndexSet<String>,
}

/// An "allow"/"deny" toggle.
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AllowDeny {
    Allow,
    #[default]
    Deny,
}

/// Supported packaging ecosystems.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PackageEcosystem {
    Bundler,
    Cargo,
    Composer,
    Docker,
    Elm,
    Gitsubmodule,
    GithubActions,
    Gomod,
    Gradle,
    Maven,
    Mix,
    Npm,
    Nuget,
    Pip,
    Pub,
    Swift,
    Terraform,
}

/// Rebase strategies for Dependabot updates.
#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RebaseStrategy {
    #[default]
    Auto,
    Disabled,
}

/// Scheduling settings for Dependabot updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Schedule {
    pub interval: Interval,
    pub day: Option<Day>,
    pub time: Option<String>,
    pub timezone: Option<String>,
}

/// Schedule intervals.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Interval {
    Daily,
    Weekly,
    Monthly,
}

/// Days of the week.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Day {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Versioning strategies.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum VersioningStrategy {
    Auto,
    Increase,
    IncreaseIfNecessary,
    LockfileOnly,
    Widen,
}
