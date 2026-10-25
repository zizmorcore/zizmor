//! Input registry and associated types.

use std::{
    collections::{BTreeMap, btree_map},
    io::Read as _,
    path::PathBuf,
    str::FromStr as _,
};

use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools as _;
use serde::Serialize;
use thiserror::Error;

use crate::{
    CollectionOptions,
    audit::AuditInput,
    config::{Config, ConfigError},
    github::{Client, ClientError},
    models::{
        action::Action,
        dependabot::Dependabot,
        lock::Lock,
        pre_commit::{PreCommitConfig, PreCommitHooks},
        repo_ref::Slug,
        workflow::Workflow,
    },
    registry::input::root::Root,
    utils::once::warn_once,
};

pub(crate) mod root;

/// Errors that can occur while collecting inputs.
#[derive(Debug, Error)]
pub(crate) enum CollectionError {
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
    #[error("couldn't turn input into a an appropriate model")]
    Model(#[from] yaml_serde::Error),

    /// The input couldn't be loaded into an internal yamlpath document.
    /// This typically indicates a bug in `yamlpath`.
    #[error("failed to load internal pathing document")]
    Yamlpath(#[from] yamlpath::QueryError),

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
    /// repository doesn't have a `.github` or `.github/workflows` directory.
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
        .slug.git_ref.as_deref().unwrap_or("HEAD"))
    ]
    AmbiguousRemoteRef { slug: InputSlug },
}

impl CollectionError {
    /// Returns the "innermost" variant of this [`CollectionError`].
    ///
    /// In practice this is always `&self` *unless* this is an
    /// `Inner` variant, in which case it recurses into the inner error.
    pub(crate) fn inner(&self) -> &Self {
        match self {
            Self::Inner(inner, _, _) => inner.inner(),
            _ => self,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) enum InputKind {
    /// A workflow file.
    Workflow,
    /// An action definition.
    Action,
    /// A Dependabot configuration file.
    Dependabot,
    /// A `.pre-commit-config.yaml` file.
    PreCommitConfig,
    /// A `.pre-commit-hooks.yaml` file.
    PreCommitHooks,
}

impl std::fmt::Display for InputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Workflow => write!(f, "workflow"),
            Self::Action => write!(f, "action"),
            Self::Dependabot => write!(f, "dependabot config"),
            Self::PreCommitConfig => write!(f, "pre-commit config"),
            Self::PreCommitHooks => write!(f, "pre-commit hooks definition"),
        }
    }
}

/// A GitHub repository slug used as an input to `zizmor`, i.e. `owner/repo[@ref]`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct InputSlug {
    /// The owner of the repository.
    pub(crate) owner: String,
    /// The name of the repository.
    pub(crate) repo: String,
    /// An optional Git reference, e.g. a branch or tag name.
    ///
    /// Note: intentionally not exposed, so that consumers get
    /// a reasonable default through [`RepoSlug::git_ref()`] instead.
    git_ref: Option<String>,
}

impl InputSlug {
    /// Returns a Git reference for this slug.
    ///
    /// This reference is the one provided by the slug if present,
    /// or the default `HEAD` reference if not provided.
    pub(crate) fn git_ref(&self) -> &str {
        self.git_ref.as_deref().unwrap_or("HEAD")
    }
}

impl std::str::FromStr for InputSlug {
    type Err = CollectionError;

    /// NOTE: This is almost exactly the same as
    /// [`github_actions_models::common::RepositoryUses`],
    /// except that we don't require a git ref and we forbid subpaths.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, git_ref) = match s.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (s, None),
        };

        let Some(slug) = Slug::parse(path) else {
            return Err(CollectionError::InvalidInput(s.into()));
        };

        Ok(Self {
            owner: slug.owner().into(),
            repo: slug.repo().into(),
            git_ref: git_ref.map(|s| s.into()),
        })
    }
}

impl std::fmt::Display for InputSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref git_ref) = self.git_ref {
            write!(f, "{}/{}@{}", self.owner, self.repo, git_ref)
        } else {
            write!(f, "{}/{}", self.owner, self.repo)
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct LocalKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: GroupID,

    /// The input's path prefix.
    ///
    /// This is not necessarily the same as the root. For example, if the user
    /// runs `zizmor .github/` then the prefix will be `.github/` while the root
    /// will be the parent directory of `.github/`.
    #[serde(skip)]
    prefix: Option<Utf8PathBuf>,

    /// The verbatim path to the input, exactly as the user supplied it.
    /// This can be absolute or relative.
    verbatim_path: Utf8PathBuf,

    /// The "native" path to the input. This is the same as [`Self::verbatim_path`],
    /// but normalized for the host's default separator. For example, if the user
    /// supplies a verbatim path of `./foo.yml`, this will be `.\foo.yml` on Windows.
    ///
    /// This can be absolute or relative.
    #[serde(skip)]
    native_path: Utf8PathBuf,

    /// The path to this input, relative to the input's Git root (if it's in a Git repository).
    ///
    /// This path always uses Unix path separators.
    ///
    /// This may or may not be the same as [`Self::verbatim_path`].
    #[serde(skip)]
    root_relative_path: Option<Utf8PathBuf>,
}

impl LocalKey {
    /// Returns a real path to this [`LocalKey`]'s input, on disk.
    ///
    /// This path may be relative or absolute.
    pub(crate) fn path(&self) -> &Utf8Path {
        &self.verbatim_path
    }

    pub(crate) fn root_relative_path(&self) -> Option<&Utf8Path> {
        self.root_relative_path.as_deref()
    }

    /// Returns the "best" identifier for this [`LocalKey`].
    fn best_identifier(&self) -> &str {
        if let Some(path) = &self.root_relative_path {
            // Happiest path: we have a root and our input is known to
            // be relative to it.
            path.as_str()
        } else if let Some(prefix) = &self.prefix
            && let Ok(path) = self.verbatim_path.strip_prefix(prefix)
        {
            // Semi-happy path: we don't have a root, but we have a known
            // prefix that we can strip from the verbatim path.
            path.as_str()
        } else {
            // Sad path: no root or known prefix, so we return
            // the verbatim path as-is and hope for the best.
            self.verbatim_path.as_str()
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct RemoteKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: GroupID,
    slug: InputSlug,
    /// The path to the input file within the repository.
    path: Utf8PathBuf,
}

impl RemoteKey {
    pub(crate) fn path(&self) -> &Utf8Path {
        &self.path
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct StdinKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: GroupID,
}

/// A unique identifying "key" for an input in a given run of zizmor.
///
/// zizmor currently knows three different kinds of keys: local keys
/// are canonical paths to files on disk, remote keys are relative
/// paths within a referenced GitHub repository, and stdin keys
/// represent input read from standard input.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) enum InputKey {
    Local(LocalKey),
    Remote(RemoteKey),
    Stdin(StdinKey),
}

impl std::fmt::Display for InputKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(local) => write!(f, "file://{path}", path = local.verbatim_path),
            Self::Remote(remote) => {
                // No ref means assume HEAD, i.e. whatever's on the default branch.
                let git_ref = remote.slug.git_ref.as_deref().unwrap_or("HEAD");
                write!(
                    f,
                    "https://github.com/{owner}/{repo}/blob/{git_ref}/{path}",
                    owner = remote.slug.owner,
                    repo = remote.slug.repo,
                    path = remote.path
                )
            }
            Self::Stdin(_) => write!(f, "<stdin>"),
        }
    }
}

impl InputKey {
    /// Constructs a local InputKey.
    ///
    /// `prefix` and `root` are used to derive the input's
    /// "best" relative path for output rendering purposes.
    pub(crate) fn local<P: AsRef<Utf8Path>>(
        group: GroupID,
        verbatim_path: P,
        prefix: Option<P>,
        root: Option<Root>,
    ) -> Self {
        let verbatim_path = verbatim_path.as_ref();

        let root_relative_path = if let Some(root) = root
            && let Ok(canonical) = verbatim_path.canonicalize_utf8()
            && let Ok(relative) = canonical.strip_prefix(root.path())
        {
            Some(relative.components().join("/").into())
        } else {
            None
        };

        Self::Local(LocalKey {
            group,
            prefix: prefix.map(|p| p.as_ref().into()),
            verbatim_path: verbatim_path.to_path_buf(),
            native_path: verbatim_path.components().collect(),
            root_relative_path,
        })
    }

    pub(crate) fn remote(slug: &InputSlug, path: String) -> Self {
        Self::Remote(RemoteKey {
            group: slug.into(),
            slug: slug.clone(),
            path: path.into(),
        })
    }

    pub(crate) fn stdin() -> Self {
        Self::Stdin(StdinKey {
            group: GroupID::from("-"),
        })
    }

    /// Returns the "best" identifier for this [`InputKey`].
    ///
    /// This returns an arbitrary identifier for the input which,
    /// depending on the input kind, may or may resemble a userful path
    /// on disk.
    pub(crate) fn best_identifier(&self) -> &str {
        match self {
            // Local keys: always use the "best" relative path,
            // which is opportunistically relative to the repo root
            // if possible.
            Self::Local(local) => local.best_identifier(),
            // Remote keys: always use the path within the repository,
            // which is always relative.
            Self::Remote(remote) => remote.path.as_str(),
            // Standard input uses an arbitrary identifier.
            Self::Stdin(_) => "<stdin>",
        }
    }

    /// Return a "presentation" path for this [`InputKey`].
    ///
    /// This will always be a relative path for remote keys,
    /// and will be the native path for local keys.
    pub(crate) fn presentation_path(&self) -> &str {
        match self {
            Self::Local(local) => local.native_path.as_str(),
            Self::Remote(remote) => remote.path.as_str(),
            Self::Stdin(_) => "<stdin>",
        }
    }

    /// Returns the filename component of this [`InputKey`].
    pub(crate) fn filename(&self) -> &str {
        // NOTE: Safe unwraps, since the presence of a filename component
        // is a construction invariant of all `InputKey` variants.
        match self {
            Self::Local(local) => local
                .verbatim_path
                .file_name()
                .expect("expected input key to have a filename component"),
            Self::Remote(remote) => remote
                .path
                .file_name()
                .expect("expected input key to have a filename component"),
            Self::Stdin(_) => "<stdin>",
        }
    }

    /// Returns the group this input belongs to.
    pub(crate) fn group(&self) -> &GroupID {
        match self {
            Self::Local(local) => &local.group,
            Self::Remote(remote) => &remote.group,
            Self::Stdin(stdin) => &stdin.group,
        }
    }
}

/// An opaque identifier for a group of inputs.
#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct GroupID(Box<str>);

impl From<&str> for GroupID {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<&InputSlug> for GroupID {
    fn from(value: &InputSlug) -> Self {
        Self(value.to_string().into())
    }
}

/// A group of inputs collected from the same source.
pub(crate) struct InputGroup {
    /// The configuration for this group.
    config: Config,
    /// The group's local root directory, if applicable and inferable.
    ///
    /// Note that this will be `None` for remote inputs, even though remote inputs
    /// on GitHub have a Git root by definition, since it's for local inputs only.
    root: Option<Root>,
    /// The group's GitHub Actions lockfile, if it has one.
    lock: Option<Lock>,
    /// The collected inputs.
    inputs: BTreeMap<InputKey, AuditInput>,
}

impl InputGroup {
    pub(crate) fn new(config: Config, root: Option<Root>, lock: Option<Lock>) -> Self {
        Self {
            config,
            root,
            lock,
            inputs: Default::default(),
        }
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) fn lock(&self) -> Option<&Lock> {
        self.lock.as_ref()
    }

    pub(crate) fn register_input(&mut self, input: AuditInput) -> Result<(), CollectionError> {
        if self.inputs.contains_key(input.key()) {
            return Err(CollectionError::DuplicateInput(input.key().clone()));
        }

        self.inputs.insert(input.key().clone(), input);

        Ok(())
    }

    pub(crate) fn register(
        &mut self,
        kind: InputKind,
        contents: String,
        key: InputKey,
        strict: bool,
    ) -> Result<(), CollectionError> {
        tracing::debug!("registering {kind} input with key {key}");

        let input: Result<AuditInput, CollectionError> = match kind {
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
            Err(CollectionError::Syntax(e)) if !strict => {
                tracing::warn!("failed to parse input: {e}");
                Ok(())
            }
            Err(e @ CollectionError::Schema { .. }) if !strict => {
                tracing::warn!("failed to validate {key} as {kind}: {e}");
                Ok(())
            }
            Err(e) => Err(CollectionError::Inner(e.into(), key.to_string(), kind)),
        }
    }

    async fn collect_from_file(
        path: &Utf8Path,
        options: &CollectionOptions,
    ) -> Result<Self, CollectionError> {
        let root = Root::discover(path);
        let config =
            Config::discover(options, || Config::discover_local(path, root.as_ref())).await?;

        // Workflows can be named anything, including `dependabot.yml`
        // (overlapping with Dependabot configs) and `action.yml` (overlapping
        // with action definitions). Consequently, we make a best effort
        // disambiguate them by looking at their parent path.
        // See: https://github.com/zizmorcore/zizmor/issues/1341
        let is_workflow_path = camino::absolute_utf8(path)?
            .parent()
            .is_some_and(|parent| parent.ends_with(".github/workflows"));

        let lock = root
            .as_ref()
            .and_then(|root| Lock::discover_local(root).transpose())
            .transpose()?;

        let mut group = Self::new(config, root, lock);

        // When collecting individual files, we don't know which part
        // of the input path is the prefix.
        let (key, kind) = match (path.file_stem(), path.extension()) {
            // TODO: Do we need the `is_workflow_path` disambiguation here?
            // The only way this could be wrong is if the user does something
            // bizarre like `.github/workflows/.pre-commit-{config,hooks}.yaml`.
            (Some(".pre-commit-config"), Some("yaml")) if !is_workflow_path => (
                InputKey::local(
                    GroupID(path.as_str().into()),
                    path,
                    None,
                    group.root.clone(),
                ),
                InputKind::PreCommitConfig,
            ),
            (Some(".pre-commit-hooks"), Some("yaml")) if !is_workflow_path => (
                InputKey::local(
                    GroupID(path.as_str().into()),
                    path,
                    None,
                    group.root.clone(),
                ),
                InputKind::PreCommitHooks,
            ),
            (Some("dependabot"), Some("yml" | "yaml")) if !is_workflow_path => (
                InputKey::local(
                    GroupID(path.as_str().into()),
                    path,
                    None,
                    group.root.clone(),
                ),
                InputKind::Dependabot,
            ),
            (Some("action"), Some("yml" | "yaml")) if !is_workflow_path => (
                InputKey::local(
                    GroupID(path.as_str().into()),
                    path,
                    None,
                    group.root.clone(),
                ),
                InputKind::Action,
            ),
            (Some(_), Some("yml" | "yaml")) => (
                InputKey::local(
                    GroupID(path.as_str().into()),
                    path,
                    None,
                    group.root.clone(),
                ),
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

    /// Collect inputs in "root-aware" mode.
    ///
    /// Workflows, Dependabot, and pre-commit inputs are anchored to the root.
    /// Only action discovery requires traversing the entire source tree.
    #[tracing::instrument(skip(options))]
    async fn collect_from_repo_root(
        path: &Utf8Path,
        options: &CollectionOptions,
        root: Root,
    ) -> Result<Self, CollectionError> {
        tracing::debug!("performing root-aware collection because '{path}' is a Git root");

        let mut walker = Self::directory_walker(path, options);
        let workflows = options.mode_set.workflows();
        let actions = options.mode_set.actions();
        let dependabot = options.mode_set.dependabot();
        let dotgithub = path.join(".github");
        let workflows_dir = dotgithub.join("workflows");

        // Prune directories before descent while leaving ignore-file handling
        // to the walker. Actions can occur anywhere, so their discovery still
        // requires a recursive walk.
        walker.filter_entry(move |entry| {
            !entry.file_type().is_some_and(|kind| kind.is_dir())
                || entry.depth() == 0
                || actions
                || ((workflows || dependabot) && entry.path() == dotgithub.as_std_path())
                || (workflows && entry.path() == workflows_dir.as_std_path())
        });

        Self::collect_from_walk(path, options, Some(root), walker).await
    }

    /// Collect auditable inputs from a directory, i.e. in non-root-aware mode.
    ///
    /// The given directory is "generic" in the sense that it isn't
    /// a repository root. However, it might be *inside* of a repository
    /// root.
    ///
    /// For example, if `foo/` is a repository, `zizmor foo/bar/` will
    /// take the [`Self::collect_from_generic_dir`] route, but
    /// `zizmor foo/` will be loaded via [`Self::collect_from_repo_root`].
    #[tracing::instrument(skip(options))]
    async fn collect_from_generic_dir(
        path: &Utf8Path,
        options: &CollectionOptions,
        root: Option<Root>,
    ) -> Result<Self, CollectionError> {
        tracing::debug!(
            "performing generic directory collection because '{path}' is not a Git root"
        );
        Self::collect_from_walk(path, options, root, Self::directory_walker(path, options)).await
    }

    /// Build a directory walker with the requested Git ignore behavior.
    fn directory_walker(path: &Utf8Path, options: &CollectionOptions) -> ignore::WalkBuilder {
        // Start with all filters disabled, i.e. walk everything.
        let mut walker = ignore::WalkBuilder::new(path);
        walker.standard_filters(false);

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

        walker
    }

    /// Load inputs from a configured walk, preserving the original request's
    /// configuration, input keys, and repository-relative collection rules.
    async fn collect_from_walk(
        path: &Utf8Path,
        options: &CollectionOptions,
        root: Option<Root>,
        walker: ignore::WalkBuilder,
    ) -> Result<Self, CollectionError> {
        let config =
            Config::discover(options, || Config::discover_local(path, root.as_ref())).await?;
        let is_repo_root = root.as_ref().is_some_and(|root| root.request_is_root);
        let lock = root
            .as_ref()
            .and_then(|root| Lock::discover_local(root).transpose())
            .transpose()?;
        let mut group = Self::new(config, root, lock);
        let dotgithub = path.join(".github");
        let workflows_dir = dotgithub.join("workflows");

        for entry in walker.build() {
            let entry = entry?;
            let entry = <&Utf8Path>::try_from(entry.path())
                .map_err(|e| CollectionError::InvalidPath(e, entry.path().into()))?;
            // Pre-compute file status so we don't call `stat()` once per mode
            // check below.
            let entry_is_file = entry.is_file();

            if options.mode_set.workflows()
                && entry_is_file
                && matches!(entry.extension(), Some("yml" | "yaml"))
                && (!is_repo_root || entry.parent() == Some(workflows_dir.as_path()))
                && camino::absolute_utf8(entry)?
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".github/workflows"))
            {
                let key = InputKey::local(
                    GroupID(path.as_str().into()),
                    entry,
                    Some(path),
                    group.root.clone(),
                );
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
                let key = InputKey::local(
                    GroupID(path.as_str().into()),
                    entry,
                    Some(path),
                    group.root.clone(),
                );
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
                && (!is_repo_root || entry.parent() == Some(dotgithub.as_path()))
                && matches!(
                    entry.file_name(),
                    Some("dependabot.yml" | "dependabot.yaml")
                )
            {
                let key = InputKey::local(
                    GroupID(path.as_str().into()),
                    entry,
                    Some(path),
                    group.root.clone(),
                );
                let contents = std::fs::read_to_string(entry).map_err(|e| {
                    CollectionError::Inner(
                        CollectionError::Io(e).into(),
                        key.to_string(),
                        InputKind::Dependabot,
                    )
                })?;
                group.register(InputKind::Dependabot, contents, key, options.strict)?;
            }

            if options.mode_set.pre_commit()
                && entry_is_file
                && (!is_repo_root || entry.parent() == Some(path))
            {
                if matches!(entry.file_name(), Some(".pre-commit-config.yaml")) {
                    let key = InputKey::local(
                        GroupID(path.as_str().into()),
                        entry,
                        Some(path),
                        group.root.clone(),
                    );
                    let contents = std::fs::read_to_string(entry).map_err(|e| {
                        CollectionError::Inner(
                            CollectionError::Io(e).into(),
                            key.to_string(),
                            InputKind::PreCommitConfig,
                        )
                    })?;
                    group.register(InputKind::PreCommitConfig, contents, key, options.strict)?;
                } else if matches!(entry.file_name(), Some(".pre-commit-hooks.yaml")) {
                    let key = InputKey::local(
                        GroupID(path.as_str().into()),
                        entry,
                        Some(path),
                        group.root.clone(),
                    );
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

    #[tracing::instrument(skip(options))]
    async fn collect_from_dir(
        path: &Utf8Path,
        options: &CollectionOptions,
    ) -> Result<Self, CollectionError> {
        let root = Root::discover(path);

        match root {
            Some(root) if root.request_is_root => {
                Self::collect_from_repo_root(path, options, root).await
            }
            _ => Self::collect_from_generic_dir(path, options, root).await,
        }
    }

    async fn collect_from_repo_slug(
        slug: InputSlug,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        let client = gh_client.ok_or_else(|| CollectionError::NoGitHubClient(slug.clone()))?;

        let (config, lock) = {
            let config = Config::discover(options, || Config::discover_remote(client, &slug));
            let lock = Lock::discover_remote(client, &slug);
            tokio::join!(config, lock)
        };

        // Observe that a remote input does not have a root (because there's no local Git repo),
        // but *can* have a lockfile.
        let mut group = Self::new(config?, None, lock?);

        if options.mode_set.workflows_only() {
            // Performance: if we're *only* collecting workflows, then we
            // can save ourselves a full repo download and only fetch the
            // repo's workflow files.
            client.fetch_workflows(&slug, options, &mut group).await?;
        } else {
            let before = group.len();
            client
                .fetch_audit_inputs(&slug, options, &mut group)
                .await?;
            let after = group.len();
            let len = after - before;

            tracing::info!("collected {len} inputs from {slug}");
        }

        Ok(group)
    }

    async fn collect_from_stdin() -> Result<Self, CollectionError> {
        let mut contents = String::new();
        std::io::stdin()
            .read_to_string(&mut contents)
            .map_err(CollectionError::Io)?;

        // TODO: This should probably honor the global config, if passed by the user?
        // NOTE: stdin inputs have no obvious lockfile.
        let mut group = Self::new(Config::default(), None, None);
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

    pub(crate) async fn collect(
        request: &str,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        let mut group = match request {
            "-" => {
                tracing::debug!("collecting one input from stdin");
                Self::collect_from_stdin().await
            }
            request => {
                let path = Utf8Path::new(request);

                match path.metadata() {
                    Ok(metadata) => {
                        if metadata.is_dir() {
                            tracing::debug!("collecting all eligible inputs under '{path}'");
                            Self::collect_from_dir(path, options).await
                        } else {
                            tracing::debug!("collecting one input from '{path}'");
                            Self::collect_from_file(path, options).await
                        }
                    }
                    Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => {
                        let slug = InputSlug::from_str(request)?;
                        tracing::debug!("collecting all eligible inputs from remote '{slug}'");
                        Self::collect_from_repo_slug(slug, options, gh_client).await
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }?;

        tracing::debug!(
            "collected a group with {n} inputs (actions lockfile={lock})",
            n = group.inputs.len(),
            lock = group.lock.is_some()
        );

        if options.ignore_lockfile {
            tracing::debug!("explicitly ignoring a lockfile that was loaded for this group");
            group.lock = None;
        }

        if group.lock().is_some() {
            warn_once!(
                "one or more inputs uses a GitHub Actions workflow lockfile; see https://docs.zizmor.sh/usage/#workflow-lockfiles for details"
            );
        }

        Ok(group)
    }

    pub(crate) fn len(&self) -> usize {
        self.inputs.len()
    }
}

pub(crate) struct InputRegistry {
    // NOTE: We use a BTreeMap here to ensure that registered inputs
    // iterate in a deterministic order. This saves us a lot of pain
    // while snapshot testing across multiple input files, and makes
    // the user experience more predictable.
    pub(crate) groups: BTreeMap<GroupID, InputGroup>,
}

impl InputRegistry {
    pub(crate) fn new() -> Self {
        Self {
            groups: Default::default(),
        }
    }

    /// Return the total number of inputs registered across all groups
    /// in this registry.
    pub(crate) fn len(&self) -> usize {
        self.groups.values().map(|g| g.len()).sum()
    }

    pub(crate) async fn register_group(
        &mut self,
        name: &str,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<(), CollectionError> {
        // If the group has already been registered, then the user probably
        // duplicated the input multiple times on the command line by accident.
        // We just ignore any duplicate registrations.
        if let btree_map::Entry::Vacant(e) = self.groups.entry(GroupID(name.into())) {
            e.insert(InputGroup::collect(name, options, gh_client).await?);
        }

        Ok(())
    }

    /// Return an iterator over every input in the registry, along with the group it belongs to.
    pub(crate) fn iter_inputs(
        &self,
    ) -> impl Iterator<Item = (&InputGroup, &InputKey, &AuditInput)> {
        self.groups.values().flat_map(move |group| {
            group
                .inputs
                .iter()
                .map(move |(key, input)| (group, key, input))
        })
    }

    /// Get a reference to a registered input by its key.
    pub(crate) fn get_input(&self, key: &InputKey) -> &AuditInput {
        self.groups
            .get(key.group())
            .and_then(|group| group.inputs.get(key))
            .expect("API misuse: requested an un-registered input")
    }

    /// Get a reference to the configuration for a given input group.
    pub(crate) fn get_config(&self, group: &GroupID) -> &Config {
        &self
            .groups
            .get(group)
            .expect("API misuse: requested an un-registered input group")
            .config
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use camino::{Utf8Path, Utf8PathBuf};

    use crate::registry::input::root::Root;

    use super::{InputKey, InputSlug};

    #[test]
    fn test_input_key_display() {
        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", None, None);
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
        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", None, None);
        if cfg!(target_os = "windows") {
            assert_eq!(local.presentation_path(), "\\foo\\bar\\baz.yml");
        } else {
            assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");
        }

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"), None);
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
        let local = InputKey::local("fakegroup".into(), "bar/baz.yml", None, None);
        assert_eq!(local.best_identifier(), "bar/baz.yml");

        // Rootless with an absolute input passes through as-is.
        let absolute = if cfg!(windows) {
            Utf8Path::new(r"C:\foo\bar\baz.yml")
        } else {
            Utf8Path::new("/foo/bar/baz.yml")
        };
        let local = InputKey::local("fakegroup".into(), absolute, None, None);
        assert_eq!(local.best_identifier(), absolute);

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"), None);
        assert_eq!(local.best_identifier(), "bar/baz.yml");

        let local = InputKey::local(
            "fakegroup".into(),
            "/foo/bar/baz.yml",
            Some("/foo/bar/"),
            None,
        );
        assert_eq!(local.best_identifier(), "baz.yml");

        let local = InputKey::local(
            "fakegroup".into(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
            None,
        );
        assert_eq!(local.best_identifier(), ".github/workflows/baz.yml");

        let local = InputKey::local(
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
        std::fs::create_dir(temp_path.join(".git")).unwrap();

        let child = temp_path.join("foo/bar/baz.yml");
        std::fs::create_dir_all(child.parent().unwrap()).unwrap();
        std::fs::write(&child, "contents").unwrap();

        let local = InputKey::local(
            "fakegroup".into(),
            child,
            None,
            Some(Root::discover(&temp_path).unwrap()),
        );
        assert_eq!(local.best_identifier(), "foo/bar/baz.yml");
    }
}
