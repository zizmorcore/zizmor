//! "v2" Dependabot models.
//!
//! Resources:
//! * [Configuration options for the `dependabot.yml` file](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
//! * [JSON Schema for Dependabot v2](https://json.schemastore.org/dependabot-2.0.json)

use indexmap::{IndexMap, IndexSet};
use serde::Deserialize;

use crate::common::custom_error;

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

/// Cooldown settings for Dependabot updates.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Cooldown {
    pub default_days: Option<u64>,
    pub semver_major_days: Option<u64>,
    pub semver_minor_days: Option<u64>,
    pub semver_patch_days: Option<u64>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A `directory` or `directories` field in a Dependabot `update` directive.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Directories {
    Directory(String),
    Directories(Vec<String>),
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
    pub cooldown: Option<Cooldown>,
    #[serde(flatten)]
    pub directories: Directories,
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
    /// `bun`
    Bun,
    /// `bundler`
    Bundler,
    /// `cargo`
    Cargo,
    /// `composer`
    Composer,
    /// `conda`
    Conda,
    /// `devcontainers`
    Devcontainers,
    /// `docker`
    Docker,
    /// `docker-compose`
    DockerCompose,
    /// `dotnet-sdk`
    DotnetSdk,
    /// `helm`
    Helm,
    /// `elm`
    Elm,
    /// `gitsubmodule`
    Gitsubmodule,
    /// `github-actions`
    GithubActions,
    /// `gomod`
    Gomod,
    /// `gradle`
    Gradle,
    /// `maven`
    Maven,
    /// `mix`
    Mix,
    /// `npm`
    Npm,
    /// `nuget`
    Nuget,
    /// `pip`
    Pip,
    /// `pub`
    Pub,
    /// `rust-toolchain`
    RustToolchain,
    /// `swift`
    Swift,
    /// `terraform`
    Terraform,
    /// `uv`
    Uv,
    /// `vcpkg`
    Vcpkg,
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
#[serde(rename_all = "kebab-case", remote = "Self")]
pub struct Schedule {
    pub interval: Interval,
    pub day: Option<Day>,
    pub time: Option<String>,
    pub timezone: Option<String>,
    pub cronjob: Option<String>,
}

impl<'de> Deserialize<'de> for Schedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let schedule = Self::deserialize(deserializer)?;

        if schedule.interval == Interval::Cron && schedule.cronjob.is_none() {
            return Err(custom_error::<D>(
                "`schedule.cronjob` must be set when `schedule.interval` is `cron`",
            ));
        }

        if schedule.interval != Interval::Cron && schedule.cronjob.is_some() {
            return Err(custom_error::<D>(
                "`schedule.cronjob` may only be set when `schedule.interval` is `cron`",
            ));
        }

        if schedule.interval != Interval::Weekly && schedule.day.is_some() {
            return Err(custom_error::<D>(
                "`schedule.day` is only valid when `schedule.interval` is `weekly`",
            ));
        }

        Ok(Self {
            interval: schedule.interval,
            day: schedule.day,
            time: schedule.time,
            timezone: schedule.timezone,
            cronjob: schedule.cronjob,
        })
    }
}

/// Schedule intervals.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Interval {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Semiannually,
    Yearly,
    Cron,
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
