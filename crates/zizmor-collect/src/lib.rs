//! Filesystem, stdin, and remote input collection for zizmor.

use std::{
    collections::{BTreeMap, HashSet, btree_map},
    io::Read as _,
    path::PathBuf,
    str::FromStr as _,
    sync::LazyLock,
};

use camino::{Utf8Path, Utf8PathBuf};
use flate2::read::GzDecoder;
use itertools::Itertools as _;
use tar::Archive;
use thiserror::Error;
use zizmor_config::{Config, ConfigError};
use zizmor_core::{
    github::{Client, ClientError},
    input::AuditInput,
    input::{Group, InputError, InputKey, InputKind, InputSlug},
    models::{
        action::Action,
        dependabot::Dependabot,
        pre_commit::{PreCommitConfig, PreCommitHooks},
        workflow::Workflow,
    },
};

/// Errors that can occur while collecting inputs.
#[derive(Debug, Error)]
pub enum CollectionError {
    /// The input's syntax is invalid.
    /// This typically indicates a user error.
    #[error("invalid YAML syntax: {0}")]
    Syntax(#[source] anyhow::Error),

    /// The input doesn't match the schema for the expected model.
    /// This typically indicates a user error.
    #[error("input does not match expected validation schema")]
    Schema(#[source] anyhow::Error),

    /// The input couldn't be converted into the expected model.
    /// This typically indicates a bug in `github-actions-models`.
    #[error("couldn't turn input into an appropriate model")]
    Model(#[source] yaml_serde::Error),

    /// The input couldn't be loaded into an internal yamlpath document.
    /// This typically indicates a bug in `yamlpath`.
    #[error("failed to load internal pathing document")]
    Yamlpath(#[source] yamlpath::QueryError),

    /// An error in a group or global configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The input couldn't be parsed as one of our known input sources
    /// (file, directory, or GitHub repo).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The user provided the same input in the same group more than once.
    #[error("can't register the same input more than once: {0}")]
    DuplicateInput(InputKey),

    /// The user wants us to fetch a remote repo, but we don't have a
    /// functional GitHub client (maybe because we're offline, or
    /// because no token was provided).
    #[error("can't fetch remote repository: {0}")]
    NoGitHubClient(InputSlug),

    /// An error occurred while processing ignore rules.
    #[error("error while processing ignore rules")]
    Ignore(#[from] ignore::Error),

    /// A single input file failed to load as a specific kind.
    #[error("failed to load {1} as {2}")]
    Inner(#[source] Box<Self>, String, InputKind),

    /// The input doesn't have a `.yml` or `.yaml` extension.
    #[error("invalid input: must have .yml or .yaml extension")]
    InvalidExtension,

    /// Workflow-specific collection was requested, but the remote
    /// input doesn't contain any workflows. This typically means the remote
    /// doesn't have a `.github` or `.github/workflows` directory.
    #[error("input {1} doesn't contain any workflows")]
    RemoteWithoutWorkflows(#[source] ClientError, String),

    /// A GitHub API error occurred while fetching a remote input.
    #[error("GitHub API error while fetching remote input")]
    Client(#[from] ClientError),

    /// An I/O error occurred while loading the input.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The input path isn't valid UTF-8.
    #[error("invalid path (not UTF-8): {1:?}")]
    InvalidPath(#[source] camino::FromPathError, PathBuf),

    /// No inputs were collected.
    #[error("no inputs collected")]
    NoInputs,

    /// The (remote) input has an ambiguous ref.
    ///
    /// For example, `foo/bar@v1` is ambiguous if `v1` is both a tag
    /// and a branch.
    #[error(
        "remote input has an ambiguous Git reference ({0:?} is both a tag and a branch)",
        .slug.git_ref())
    ]
    AmbiguousRemoteRef { slug: InputSlug },
}

impl From<InputError> for CollectionError {
    fn from(error: InputError) -> Self {
        match error {
            InputError::Syntax(error) => Self::Syntax(error),
            InputError::Schema(error) => Self::Schema(error),
            InputError::Model(error) => Self::Model(error),
            InputError::Yamlpath(error) => Self::Yamlpath(error),
            InputError::InvalidInput(input) => Self::InvalidInput(input),
        }
    }
}

impl CollectionError {
    /// Returns the "innermost" variant of this [`CollectionError`].
    ///
    /// In practice this is always `&self` *unless* this is an
    /// `Inner` variant, in which case it recurses into the inner error.
    pub fn inner(&self) -> &Self {
        match self {
            Self::Inner(inner, _, _) => inner.inner(),
            _ => self,
        }
    }
}

/// How `zizmor` collects inputs from local and remote repository sources.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CollectionMode {
    /// Collect all possible inputs, ignoring `.gitignore` files.
    All,
    /// Collect all possible inputs, respecting `.gitignore` files.
    Default,
    /// Collect workflows.
    Workflows,
    /// Collect action definitions (i.e. `action.yml`).
    Actions,
    /// Collect Dependabot configuration files (i.e. `dependabot.yml`).
    Dependabot,
    /// Collect pre-commit configuration and hooks files,
    /// i.e. `.pre-commit-config.yml` and `.pre-commit-hooks.yml`.
    PreCommit,
}

pub struct CollectionModeSet(pub HashSet<CollectionMode>);

impl CollectionModeSet {
    /// Does our collection mode respect `.gitignore` files?
    pub fn respects_gitignore(&self) -> bool {
        !self.0.contains(&CollectionMode::All)
    }

    /// Should we collect workflows?
    pub fn workflows(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Workflows
            )
        })
    }

    /// Should we collect *only* workflows?
    pub fn workflows_only(&self) -> bool {
        self.0.len() == 1 && self.0.contains(&CollectionMode::Workflows)
    }

    /// Should we collect actions?
    pub fn actions(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Actions
            )
        })
    }

    /// Should we collect Dependabot configuration files?
    pub fn dependabot(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Dependabot
            )
        })
    }

    /// Shouldn we collect pre-commit files?
    pub fn pre_commit(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::PreCommit
            )
        })
    }
}

/// State used when collecting input groups.
pub struct CollectionOptions {
    pub mode_set: CollectionModeSet,
    pub strict: bool,
    pub no_config: bool,
    /// Global configuration, if any.
    pub global_config: Option<Config>,
}

fn local_key<P: AsRef<Utf8Path>>(
    group: Group,
    verbatim_path: P,
    prefix: Option<P>,
    root: Option<P>,
) -> InputKey {
    let verbatim_path = verbatim_path.as_ref();

    // Happy path: we have a root directory and the input
    // is relative to it once canonicalized.
    let best_path = if let Some(root) = root.as_ref()
        && let Ok(canonical) = verbatim_path.canonicalize_utf8()
        && let Ok(relative) = canonical.strip_prefix(root.as_ref())
    {
        relative.to_owned()
    // Semi-happy path: we don't have a root directory,
    // but we have a known prefix that we can strip from the
    // input path.
    } else if let Some(prefix) = prefix.as_ref()
        && let Ok(relative) = verbatim_path.strip_prefix(prefix.as_ref())
    {
        relative.to_owned()
    // Sad path: no root or known prefix, so we return the
    // given path as-is and hope for the best.
    } else {
        verbatim_path.to_owned()
    };
    let best_identifier = if best_path.is_relative() {
        best_path.components().join("/")
    } else {
        best_path.into()
    };
    InputKey::local(group, verbatim_path, best_identifier)
}

/// A group of inputs collected from the same source.
pub struct InputGroup {
    /// The configuration for this group.
    pub config: Config,
    /// The group's root directory (as an absolute path), if applicable and inferable.
    pub root: Option<Utf8PathBuf>,
    /// The collected inputs.
    pub inputs: BTreeMap<InputKey, AuditInput>,
}

impl InputGroup {
    pub fn new(config: Config, root: Option<Utf8PathBuf>) -> Self {
        Self {
            config,
            root,
            inputs: Default::default(),
        }
    }

    pub fn register_input(&mut self, input: AuditInput) -> Result<(), CollectionError> {
        if self.inputs.contains_key(input.key()) {
            return Err(CollectionError::DuplicateInput(input.key().clone()));
        }

        self.inputs.insert(input.key().clone(), input);

        Ok(())
    }

    /// Given a path to an input file, attempt to discover the Git repository root that it belongs
    /// to, if any.
    ///
    /// This is a rough approximation of what `git rev-parse --show-toplevel` does.
    ///
    /// Returns `None` if the path is not within a Git repository or if the root can't be determined for any reason.
    pub fn discover_root(path: &Utf8Path) -> Option<Utf8PathBuf> {
        Self::discover_root_with_ceilings(path, &GIT_CEILING_DIRECTORIES)
    }

    fn discover_root_with_ceilings(
        path: &Utf8Path,
        ceilings: &HashSet<Utf8PathBuf>,
    ) -> Option<Utf8PathBuf> {
        // Canonicalize first; this also avoids a `parent()` of `Some("")`
        // for inputs like `foo.yml`.
        let canonical = match path.canonicalize_utf8() {
            Ok(canonical) => canonical,
            Err(_) => {
                tracing::trace!("failed to find a canonical path for {path}");
                return None;
            }
        };

        let mut candidate = if canonical.is_file() {
            canonical.parent()?.to_path_buf()
        } else {
            canonical
        };

        loop {
            if ceilings.contains(&candidate) {
                tracing::trace!("hit a GIT_CEILING_DIRECTORIES entry at {candidate}");
                break;
            }

            // TODO: Handle worktrees?
            tracing::trace!("checking if {candidate} is a Git repository root");
            if candidate.join(".git").is_dir() {
                return Some(candidate);
            }

            if let Some(parent) = candidate.parent() {
                candidate = parent.to_path_buf();
            } else {
                break;
            }
        }

        tracing::trace!("no Git repository root found for {path}");
        None
    }

    pub fn register(
        &mut self,
        kind: InputKind,
        contents: String,
        key: InputKey,
        strict: bool,
    ) -> Result<(), CollectionError> {
        tracing::debug!("registering {kind} input as with key {key}");

        let input: Result<AuditInput, InputError> = match kind {
            InputKind::Workflow => Workflow::from_string(contents, key.clone()).map(Into::into),
            InputKind::Action => Action::from_string(contents, key.clone()).map(Into::into),
            InputKind::Dependabot => Dependabot::from_string(contents, key.clone()).map(Into::into),
            InputKind::PreCommitConfig => {
                PreCommitConfig::from_string(contents, key.clone()).map(Into::into)
            }
            InputKind::PreCommitHooks => {
                PreCommitHooks::from_string(contents, key.clone()).map(Into::into)
            }
        };

        match input {
            Ok(input) => self.register_input(input),
            Err(InputError::Syntax(e)) if !strict => {
                tracing::warn!("failed to parse input: {e}");
                Ok(())
            }
            Err(e @ InputError::Schema { .. }) if !strict => {
                tracing::warn!("failed to validate {key} as {kind}: {e}");
                Ok(())
            }
            Err(e) => Err(CollectionError::Inner(
                Box::new(e.into()),
                key.to_string(),
                kind,
            )),
        }
    }

    fn local_config(
        options: &CollectionOptions,
        path: &Utf8Path,
        root: Option<&Utf8Path>,
    ) -> Result<Config, CollectionError> {
        if options.no_config {
            Ok(Config::default())
        } else if let Some(config) = &options.global_config {
            Ok(config.clone())
        } else {
            Ok(Config::discover_local(path, root)?.unwrap_or_default())
        }
    }

    /// Discover a [`Config`] for a repository slug.
    ///
    /// This will look for a `.github/zizmor.yml` or `zizmor.yml`
    /// in the repository's root directory.
    async fn remote_config(
        options: &CollectionOptions,
        client: &Client,
        slug: &InputSlug,
    ) -> Result<Config, CollectionError> {
        if options.no_config {
            return Ok(Config::default());
        }
        if let Some(config) = &options.global_config {
            return Ok(config.clone());
        }

        for candidate in zizmor_config::CONFIG_CANDIDATES {
            match client.fetch_single_file(slug, candidate).await? {
                Some(contents) => {
                    return Ok(Config::parse_named(&contents, *candidate)?);
                }
                None => continue,
            }
        }
        Ok(Config::default())
    }

    async fn collect_from_file(
        path: &Utf8Path,
        options: &CollectionOptions,
    ) -> Result<Self, CollectionError> {
        let root = Self::discover_root(path);
        let config = Self::local_config(options, path, root.as_deref())?;

        // Workflows can be named anything, including `dependabot.yml`
        // (overlapping with Dependabot configs) and `action.yml` (overlapping
        // with action definitions). Consequently, we make a best effort
        // disambiguate them by looking at their parent path.
        // See: https://github.com/zizmorcore/zizmor/issues/1341
        let is_workflow_path = camino::absolute_utf8(path)?
            .parent()
            .is_some_and(|parent| parent.ends_with(".github/workflows"));

        let mut group = Self::new(config, root);
        let root = group.root.as_deref();

        // When collecting individual files, we don't know which part
        // of the input path is the prefix.
        let (key, kind) = match (path.file_stem(), path.extension()) {
            // TODO: Do we need the `is_workflow_path` disambiguation here?
            // The only way this could be wrong is if the user does something
            // bizarre like `.github/workflows/.pre-commit-{config,hooks}.yml`.
            (Some(".pre-commit-config"), Some("yml" | "yaml")) if !is_workflow_path => (
                local_key(Group(path.as_str().into()), path, None, root),
                InputKind::PreCommitConfig,
            ),
            (Some(".pre-commit-hooks"), Some("yml" | "yaml")) if !is_workflow_path => (
                local_key(Group(path.as_str().into()), path, None, root),
                InputKind::PreCommitHooks,
            ),
            (Some("dependabot"), Some("yml" | "yaml")) if !is_workflow_path => (
                local_key(Group(path.as_str().into()), path, None, root),
                InputKind::Dependabot,
            ),
            (Some("action"), Some("yml" | "yaml")) if !is_workflow_path => (
                local_key(Group(path.as_str().into()), path, None, root),
                InputKind::Action,
            ),
            (Some(_), Some("yml" | "yaml")) => (
                local_key(Group(path.as_str().into()), path, None, root),
                InputKind::Workflow,
            ),
            _ => return Err(CollectionError::InvalidExtension),
        };

        let contents = std::fs::read_to_string(path).map_err(|e| {
            CollectionError::Inner(CollectionError::Io(e).into(), key.to_string(), kind)
        })?;
        group.register(kind, contents, key, options.strict)?;

        Ok(group)
    }

    async fn collect_from_dir(
        path: &Utf8Path,
        options: &CollectionOptions,
    ) -> Result<Self, CollectionError> {
        let root = Self::discover_root(path);
        let config = Self::local_config(options, path, root.as_deref())?;

        let mut group = Self::new(config, root);

        // Start with all filters disabled, i.e. walk everything.
        let mut walker = ignore::WalkBuilder::new(path);
        let walker = walker.standard_filters(false);

        // If the user wants to respect `.gitignore` files, then we need to
        // explicitly enable it. This also enables filtering by a global
        // `.gitignore` file and the `.git/info/exclude` file, since these
        // typically align with the user's expectations.
        //
        // We honor `.gitignore` and similar files even if `.git/` is not
        // present, since users may retrieve or reconstruct a source archive
        // without a `.git/` directory. In particular, this snares some
        // zizmor integrators.
        //
        // See: https://github.com/zizmorcore/zizmor/issues/596
        if options.mode_set.respects_gitignore() {
            walker
                .require_git(false)
                .git_ignore(true)
                .git_global(true)
                .git_exclude(true);
        }

        let root = group.root.clone();
        for entry in walker.build() {
            let entry = entry?;
            let entry = <&Utf8Path>::try_from(entry.path())
                .map_err(|e| CollectionError::InvalidPath(e, entry.path().into()))?;
            // Pre-compute file status so we don't call `stat()` once per mode
            // check below.
            let entry_is_file = entry.is_file();
            let root = root.as_deref();

            if options.mode_set.workflows()
                && entry_is_file
                && matches!(entry.extension(), Some("yml" | "yaml"))
                && camino::absolute_utf8(entry)?
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".github/workflows"))
            {
                let key = local_key(Group(path.as_str().into()), entry, Some(path), root);
                let contents = std::fs::read_to_string(entry).map_err(|e| {
                    CollectionError::Inner(
                        CollectionError::Io(e).into(),
                        key.to_string(),
                        InputKind::Workflow,
                    )
                })?;
                group.register(InputKind::Workflow, contents, key, options.strict)?;
            }

            if options.mode_set.actions()
                && entry_is_file
                && matches!(entry.file_name(), Some("action.yml" | "action.yaml"))
            {
                let key = local_key(Group(path.as_str().into()), entry, Some(path), root);
                let contents = std::fs::read_to_string(entry).map_err(|e| {
                    CollectionError::Inner(
                        CollectionError::Io(e).into(),
                        key.to_string(),
                        InputKind::Action,
                    )
                })?;
                group.register(InputKind::Action, contents, key, options.strict)?;
            }

            if options.mode_set.dependabot()
                && entry_is_file
                && matches!(
                    entry.file_name(),
                    Some("dependabot.yml" | "dependabot.yaml")
                )
            {
                let key = local_key(Group(path.as_str().into()), entry, Some(path), root);
                let contents = std::fs::read_to_string(entry).map_err(|e| {
                    CollectionError::Inner(
                        CollectionError::Io(e).into(),
                        key.to_string(),
                        InputKind::Dependabot,
                    )
                })?;
                group.register(InputKind::Dependabot, contents, key, options.strict)?;
            }

            if options.mode_set.pre_commit() && entry_is_file {
                if matches!(
                    entry.file_name(),
                    Some(".pre-commit-config.yml" | ".pre-commit-config.yaml")
                ) {
                    let key = local_key(Group(path.as_str().into()), entry, Some(path), root);
                    let contents = std::fs::read_to_string(entry).map_err(|e| {
                        CollectionError::Inner(
                            CollectionError::Io(e).into(),
                            key.to_string(),
                            InputKind::PreCommitConfig,
                        )
                    })?;
                    group.register(InputKind::PreCommitConfig, contents, key, options.strict)?;
                } else if matches!(
                    entry.file_name(),
                    Some(".pre-commit-hooks.yml" | ".pre-commit-hooks.yaml")
                ) {
                    let key = local_key(Group(path.as_str().into()), entry, Some(path), root);
                    let contents = std::fs::read_to_string(entry).map_err(|e| {
                        CollectionError::Inner(
                            CollectionError::Io(e).into(),
                            key.to_string(),
                            InputKind::PreCommitHooks,
                        )
                    })?;
                    group.register(InputKind::PreCommitHooks, contents, key, options.strict)?;
                }
            }
        }

        Ok(group)
    }

    #[tracing::instrument(skip(options, gh_client))]
    async fn collect_from_repo_slug(
        slug: InputSlug,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        let client = gh_client.ok_or_else(|| CollectionError::NoGitHubClient(slug.clone()))?;

        let config = Self::remote_config(options, client, &slug).await?;
        let mut group = Self::new(config, None);

        if options.mode_set.workflows_only() {
            // Performance: if we're *only* collecting workflows, then we
            // can save ourselves a full repo download and only fetch the
            // repo's workflow files.
            let files = match client.fetch_workflow_files(&slug).await {
                Ok(files) => files,
                Err(source) if source.is_not_found() => {
                    return Err(CollectionError::RemoteWithoutWorkflows(
                        source,
                        slug.to_string(),
                    ));
                }
                Err(error) => return Err(error.into()),
            };
            for (path, contents) in files {
                let key = InputKey::remote(&slug, path);
                group.register(InputKind::Workflow, contents, key, options.strict)?;
            }
        } else {
            let before = group.len();
            let Some(contents) = client.fetch_repo_archive(&slug).await? else {
                return Err(CollectionError::AmbiguousRemoteRef { slug });
            };
            let mut archive = Archive::new(GzDecoder::new(contents.as_slice()));
            for entry in archive.entries()? {
                let mut entry = entry?;
                if !entry.header().entry_type().is_file() {
                    continue;
                }

                let entry_path = entry.path()?;
                let file_path: &Utf8Path = {
                    let mut components = entry_path.components();
                    components.next();
                    components.as_path().try_into().map_err(|error| {
                        CollectionError::InvalidPath(error, entry_path.clone().into_owned())
                    })?
                };

                let kind = if options.mode_set.workflows()
                    && matches!(file_path.extension(), Some("yaml" | "yml"))
                    && file_path
                        .parent()
                        .is_some_and(|dir| dir.ends_with(".github/workflows"))
                {
                    Some(InputKind::Workflow)
                } else if options.mode_set.actions()
                    && matches!(file_path.file_name(), Some("action.yml" | "action.yaml"))
                {
                    Some(InputKind::Action)
                } else if options.mode_set.dependabot()
                    && matches!(
                        file_path.file_name(),
                        Some("dependabot.yml" | "dependabot.yaml")
                    )
                {
                    Some(InputKind::Dependabot)
                } else if options.mode_set.pre_commit()
                    && matches!(
                        file_path.file_name(),
                        Some(".pre-commit-config.yml" | ".pre-commit-config.yaml")
                    )
                {
                    Some(InputKind::PreCommitConfig)
                } else if options.mode_set.pre_commit()
                    && matches!(
                        file_path.file_name(),
                        Some(".pre-commit-hooks.yml" | ".pre-commit-hooks.yaml")
                    )
                {
                    Some(InputKind::PreCommitHooks)
                } else {
                    None
                };

                if let Some(kind) = kind {
                    let key = InputKey::remote(&slug, file_path.to_string());
                    let mut source = String::with_capacity(entry.size() as usize);
                    entry.read_to_string(&mut source)?;
                    group.register(kind, source, key, options.strict)?;
                }
            }
            let after = group.len();
            let len = after - before;

            tracing::info!(
                "collected {len} inputs from {owner}/{repo}",
                owner = slug.owner,
                repo = slug.repo
            );
        }

        Ok(group)
    }

    async fn collect_from_stdin() -> Result<Self, CollectionError> {
        let mut contents = String::new();
        std::io::stdin()
            .read_to_string(&mut contents)
            .map_err(CollectionError::Io)?;

        // TODO: This should probably honor the global config, if passed by the user?
        let mut group = Self::new(Config::default(), None);
        let key = InputKey::stdin();

        // Infer the input type by trying each parser in order.
        // Workflow is tried first since it's the most common stdin use case.
        match group.register(InputKind::Workflow, contents.clone(), key.clone(), true) {
            Ok(()) => return Ok(group),
            // YAML itself is invalid; no point trying other types.
            Err(e) if matches!(e.inner(), CollectionError::Syntax(_)) => return Err(e),
            // Valid YAML but not a valid workflow; fall through to the next type.
            Err(_) => (),
        };

        if let Ok(()) = group.register(InputKind::Action, contents.clone(), key.clone(), true) {
            return Ok(group);
        }

        if let Ok(()) = group.register(InputKind::Dependabot, contents.clone(), key.clone(), true) {
            return Ok(group);
        }

        if let Ok(()) = group.register(
            InputKind::PreCommitConfig,
            contents.clone(),
            key.clone(),
            true,
        ) {
            return Ok(group);
        }

        if let Ok(()) = group.register(InputKind::PreCommitHooks, contents, key, true) {
            return Ok(group);
        }

        // If we get here, then the input isn't in the right shape for any of our
        // known types. We return an empty group; the CLI will subsequently
        // produce an error since no inputs were collected.
        tracing::warn!("stdin: could not parse as any known input type");
        Ok(group)
    }

    pub async fn collect(
        request: &str,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        if request == "-" {
            return Self::collect_from_stdin().await;
        }

        let path = Utf8Path::new(request);

        if path.is_file() {
            Self::collect_from_file(path, options).await
        } else if path.is_dir() {
            Self::collect_from_dir(path, options).await
        } else {
            let slug = InputSlug::from_str(request).map_err(CollectionError::from)?;
            Self::collect_from_repo_slug(slug, options, gh_client).await
        }
    }

    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// Cached parse of the process's `GIT_CEILING_DIRECTORIES`.
static GIT_CEILING_DIRECTORIES: LazyLock<HashSet<Utf8PathBuf>> = LazyLock::new(|| {
    let Ok(raw) = std::env::var("GIT_CEILING_DIRECTORIES") else {
        return HashSet::new();
    };

    let separator = if cfg!(windows) { ';' } else { ':' };
    let mut resolve = true;
    let mut ceilings = HashSet::new();
    for entry in raw.split(separator) {
        // Per `git` docs, an empty entry means that all subsequent
        // entries are not resolved.
        // See: <https://git-scm.com/docs/git#Documentation/git.txt-GITCEILINGDIRECTORIES>
        if entry.is_empty() {
            resolve = false;
            continue;
        }
        let path = Utf8Path::new(entry);
        if !path.is_absolute() {
            continue;
        }
        let resolved = if resolve {
            path.canonicalize_utf8().ok()
        } else {
            Some(path.to_path_buf())
        };
        if let Some(p) = resolved {
            ceilings.insert(p);
        }
    }
    ceilings
});

#[derive(Default)]
pub struct InputRegistry {
    // NOTE: We use a BTreeMap here to ensure that registered inputs
    // iterate in a deterministic order. This saves us a lot of pain
    // while snapshot testing across multiple input files, and makes
    // the user experience more predictable.
    pub groups: BTreeMap<Group, InputGroup>,
}

impl InputRegistry {
    pub fn new() -> Self {
        Self {
            groups: Default::default(),
        }
    }

    /// Return the total number of inputs registered across all groups
    /// in this registry.
    pub fn len(&self) -> usize {
        self.groups.values().map(|g| g.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.values().all(InputGroup::is_empty)
    }

    pub async fn register_group(
        &mut self,
        name: &str,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<(), CollectionError> {
        // If the group has already been registered, then the user probably
        // duplicated the input multiple times on the command line by accident.
        // We just ignore any duplicate registrations.
        if let btree_map::Entry::Vacant(e) = self.groups.entry(Group(name.into())) {
            e.insert(InputGroup::collect(name, options, gh_client).await?);
        }

        Ok(())
    }

    /// Return an iterator over all inputs in all groups in this registry.
    pub fn iter_inputs(&self) -> impl Iterator<Item = (&InputKey, &AuditInput)> {
        self.groups.values().flat_map(|group| group.inputs.iter())
    }

    /// Get a reference to a registered input by its key.
    pub fn get_input(&self, key: &InputKey) -> &AuditInput {
        self.groups
            .get(key.group())
            .and_then(|group| group.inputs.get(key))
            .expect("API misuse: requested an un-registered input")
    }

    /// Get a reference to the configuration for a given input group.
    pub fn get_config(&self, group: &Group) -> &Config {
        &self
            .groups
            .get(group)
            .expect("API misuse: requested an un-registered input group")
            .config
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr as _};

    use camino::{Utf8Path, Utf8PathBuf};

    use super::{InputGroup, InputKey, InputSlug, local_key};

    #[test]
    fn test_input_key_display() {
        let local = local_key("fakegroup".into(), "/foo/bar/baz.yml", None, None);
        assert_eq!(local.to_string(), "file:///foo/bar/baz.yml");

        // No ref
        let slug = InputSlug::from_str("foo/bar").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into());
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/HEAD/.github/workflows/baz.yml"
        );

        // With a git ref
        let slug = InputSlug::from_str("foo/bar@v1").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into());
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/v1/.github/workflows/baz.yml"
        );
    }

    /// Tests that [`InputKey::presentation_path`] returns the exact path that the user
    /// supplied (regardless of prefix or root), but normalized for the host's default
    /// separator.
    #[test]
    fn test_input_key_local_presentation_path() {
        let local = local_key("fakegroup".into(), "/foo/bar/baz.yml", None, None);
        if cfg!(target_os = "windows") {
            assert_eq!(local.presentation_path(), "\\foo\\bar\\baz.yml");
        } else {
            assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");
        }

        let local = local_key("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"), None);
        if cfg!(target_os = "windows") {
            assert_eq!(local.presentation_path(), "\\foo\\bar\\baz.yml");
        } else {
            assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");
        }
    }

    #[test]
    fn test_input_key_local_best_identifier() {
        // "Rootless" cases: with no group root, best_identifier falls back to
        // stripping the input's own prefix (if any), else returns the path
        // as-is.
        let local = local_key("fakegroup".into(), "bar/baz.yml", None, None);
        assert_eq!(local.best_identifier(), "bar/baz.yml");

        // Rootless with an absolute input passes through as-is.
        let absolute = if cfg!(windows) {
            Utf8Path::new(r"C:\foo\bar\baz.yml")
        } else {
            Utf8Path::new("/foo/bar/baz.yml")
        };
        let local = local_key("fakegroup".into(), absolute, None, None);
        assert_eq!(local.best_identifier(), absolute);

        let local = local_key("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"), None);
        assert_eq!(local.best_identifier(), "bar/baz.yml");

        let local = local_key(
            "fakegroup".into(),
            "/foo/bar/baz.yml",
            Some("/foo/bar/"),
            None,
        );
        assert_eq!(local.best_identifier(), "baz.yml");

        let local = local_key(
            "fakegroup".into(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
            None,
        );
        assert_eq!(local.best_identifier(), ".github/workflows/baz.yml");

        let local = local_key(
            "fakegroup".into(),
            "./.github/workflows/baz.yml",
            Some("."),
            None,
        );
        assert_eq!(local.best_identifier(), ".github/workflows/baz.yml");

        // "Rooted" case: with a real root, best_identifier is canonical-then-strip.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = Utf8PathBuf::try_from(temp_dir.path().to_path_buf())
            .unwrap()
            .canonicalize_utf8()
            .unwrap();

        let child = temp_path.join("foo/bar/baz.yml");
        std::fs::create_dir_all(child.parent().unwrap()).unwrap();
        std::fs::write(&child, "contents").unwrap();

        let local = local_key("fakegroup".into(), child, None, Some(temp_path));
        assert_eq!(local.best_identifier(), "foo/bar/baz.yml");
    }

    #[test]
    fn test_discover_root_respects_ceiling() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = Utf8PathBuf::try_from(temp_dir.path().to_path_buf())
            .unwrap()
            .canonicalize_utf8()
            .unwrap();

        std::fs::create_dir(temp_path.join(".git")).unwrap();
        let child = temp_path.join("project/subdir");
        std::fs::create_dir_all(&child).unwrap();

        // No ceiling: the walk finds the fake repo.
        assert_eq!(
            InputGroup::discover_root_with_ceilings(&child, &HashSet::new()),
            Some(temp_path.clone()),
        );

        // The repo itself is a ceiling: the walk stops before examining it.
        assert_eq!(
            InputGroup::discover_root_with_ceilings(&child, &HashSet::from([temp_path.clone()]),),
            None,
        );

        // An ancestor above the repo is the ceiling, so the repo is still found.
        let parent_ceiling = temp_path.parent().unwrap().to_path_buf();
        assert_eq!(
            InputGroup::discover_root_with_ceilings(&child, &HashSet::from([parent_ceiling]),),
            Some(temp_path.clone()),
        );

        // File inputs: canonicalize then walk from the file's parent.
        let workflow_file = temp_path.join(".github/workflows/test.yml");
        std::fs::create_dir_all(workflow_file.parent().unwrap()).unwrap();
        std::fs::write(&workflow_file, "").unwrap();
        assert_eq!(
            InputGroup::discover_root_with_ceilings(&workflow_file, &HashSet::new()),
            Some(temp_path),
        );
    }
}
