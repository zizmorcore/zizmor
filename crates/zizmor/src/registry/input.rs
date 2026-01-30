//! Input registry and associated types.

use std::{
    collections::{BTreeMap, btree_map},
    path::PathBuf,
    str::FromStr as _,
};

use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CollectionOptions,
    audit::AuditInput,
    config::{Config, ConfigError},
    github::{Client, ClientError},
    models::{action::Action, dependabot::Dependabot, workflow::Workflow},
};

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
    Model(#[from] serde_yaml::Error),

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
    NoGitHubClient(RepoSlug),

    /// An error occurred while processing ignore rules.
    #[error("error while processing ignore rules")]
    Ignore(#[from] ignore::Error),

    /// A single input file failed to load as a specific kind.
    #[error("failed to load {1} as {2}")]
    Inner(#[source] Box<CollectionError>, String, InputKind),

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
}

impl CollectionError {
    /// Returns the "innermost" variant of this [`CollectionError`].
    ///
    /// In practice this is always `&self` *unless* this is an
    /// `Inner` variant, in which case it recurses into the inner error.
    pub(crate) fn inner(&self) -> &Self {
        match self {
            CollectionError::Inner(inner, _, _) => inner.inner(),
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
}

impl std::fmt::Display for InputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputKind::Workflow => write!(f, "workflow"),
            InputKind::Action => write!(f, "action"),
            InputKind::Dependabot => write!(f, "dependabot config"),
        }
    }
}

/// A GitHub repository slug, i.e. `owner/repo[@ref]`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct RepoSlug {
    /// The owner of the repository.
    pub(crate) owner: String,
    /// The name of the repository.
    pub(crate) repo: String,
    /// An optional Git reference, e.g. a branch or tag name.
    pub(crate) git_ref: Option<String>,
}

impl std::str::FromStr for RepoSlug {
    type Err = CollectionError;

    /// NOTE: This is almost exactly the same as
    /// [`github_actions_models::common::RepositoryUses`],
    /// except that we don't require a git ref and we forbid subpaths.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, git_ref) = match s.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (s, None),
        };

        let components = path.split('/').collect::<Vec<_>>();

        match components.len() {
            2 => Ok(Self {
                owner: components[0].into(),
                repo: components[1].into(),
                git_ref: git_ref.map(|s| s.into()),
            }),
            x if x < 2 => Err(CollectionError::InvalidInput(s.into())),
            _ => Err(CollectionError::InvalidInput(s.into())),
        }
    }
}

impl std::fmt::Display for RepoSlug {
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
    group: Group,
    /// The path's nondeterministic prefix, if any.
    prefix: Option<Utf8PathBuf>,
    /// The given path to the input. This can be absolute or relative.
    pub(crate) given_path: Utf8PathBuf,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct RemoteKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: Group,
    slug: RepoSlug,
    /// The path to the input file within the repository.
    path: Utf8PathBuf,
}

/// A unique identifying "key" for an input in a given run of zizmor.
///
/// zizmor currently knows two different kinds of keys: local keys
/// are just canonical paths to files on disk, while remote keys are
/// relative paths within a referenced GitHub repository.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) enum InputKey {
    Local(LocalKey),
    Remote(RemoteKey),
}

impl std::fmt::Display for InputKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputKey::Local(local) => write!(f, "file://{path}", path = local.given_path),
            InputKey::Remote(remote) => {
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
        }
    }
}

impl InputKey {
    pub(crate) fn local<P: AsRef<Utf8Path>>(group: Group, path: P, prefix: Option<P>) -> Self {
        Self::Local(LocalKey {
            group,
            prefix: prefix.map(|p| p.as_ref().to_path_buf()),
            given_path: path.as_ref().to_path_buf(),
        })
    }

    pub(crate) fn remote(slug: &RepoSlug, path: String) -> Self {
        Self::Remote(RemoteKey {
            group: slug.into(),
            slug: slug.clone(),
            path: path.into(),
        })
    }

    /// Returns a path for this [`InputKey`] that's suitable for SARIF
    /// outputs.
    ///
    /// This is similar to [`InputKey::presentation_path`] in terms of being
    /// a relative path (if the input is relative), but it also strips
    /// the prefix from local paths, if one is present.
    ///
    /// For example, if the user runs `zizmor .`, then an input at
    /// `./.github/workflows/foo.yml` will be returned as `.github/workflows/foo.yml`,
    /// rather than `./.github/workflows/foo.yml`.
    ///
    /// This is needed for GitHub's interpretation of SARIF, which is brittle
    /// with absolute paths but _also_ doesn't like relative paths that
    /// start with relative directory markers.
    pub(crate) fn sarif_path(&self) -> &str {
        match self {
            InputKey::Local(local) => local
                .prefix
                .as_ref()
                .and_then(|pfx| local.given_path.strip_prefix(pfx).ok())
                .unwrap_or_else(|| &local.given_path)
                .as_str(),
            InputKey::Remote(remote) => remote.path.as_str(),
        }
    }

    /// Return a "presentation" path for this [`InputKey`].
    ///
    /// This will always be a relative path for remote keys,
    /// and will be the given path for local keys.
    pub(crate) fn presentation_path(&self) -> &str {
        match self {
            InputKey::Local(local) => local.given_path.as_str(),
            InputKey::Remote(remote) => remote.path.as_str(),
        }
    }

    /// Returns the filename component of this [`InputKey`].
    pub(crate) fn filename(&self) -> &str {
        // NOTE: Safe unwraps, since the presence of a filename component
        // is a construction invariant of all `InputKey` variants.
        match self {
            InputKey::Local(local) => local
                .given_path
                .file_name()
                .expect("expected input key to have a filename component"),
            InputKey::Remote(remote) => remote
                .path
                .file_name()
                .expect("expected input key to have a filename component"),
        }
    }

    /// Returns the group this input belongs to.
    pub(crate) fn group(&self) -> &Group {
        match self {
            InputKey::Local(local) => &local.group,
            InputKey::Remote(remote) => &remote.group,
        }
    }
}

/// An opaque identifier for a group of inputs.
#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Group(String);

impl From<&str> for Group {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<&RepoSlug> for Group {
    fn from(value: &RepoSlug) -> Self {
        Self(value.to_string())
    }
}

/// A group of inputs collected from the same source.
pub(crate) struct InputGroup {
    /// The collected inputs.
    inputs: BTreeMap<InputKey, AuditInput>,
    /// The configuration for this group.
    config: Config,
}

impl InputGroup {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            inputs: Default::default(),
            config,
        }
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
        tracing::debug!("registering {kind} input as with key {key}");

        let input: Result<AuditInput, CollectionError> = match kind {
            InputKind::Workflow => Workflow::from_string(contents, key.clone()).map(|wf| wf.into()),
            InputKind::Action => Action::from_string(contents, key.clone()).map(|a| a.into()),
            InputKind::Dependabot => {
                Dependabot::from_string(contents, key.clone()).map(|d| d.into())
            }
        };

        match input {
            Ok(input) => self.register_input(input),
            Err(CollectionError::Syntax(e)) if !strict => {
                tracing::warn!("failed to parse input: {e}");
                Ok(())
            }
            Err(e @ CollectionError::Schema { .. }) if !strict => {
                tracing::warn!("failed to validate input as {kind}: {e}");
                Ok(())
            }
            Err(e) => Err(CollectionError::Inner(e.into(), key.to_string(), kind)),
        }
    }

    async fn collect_from_file(
        path: &Utf8Path,
        options: &CollectionOptions,
    ) -> Result<Self, CollectionError> {
        let config = Config::discover(options, || Config::discover_local(path)).await?;

        // Workflows can be named anything, including `dependabot.yml`
        // (overlapping with Dependabot configs) and `action.yml` (overlapping
        // with action definitions). Consequently, we make a best effort
        // disambiguate them by looking at their parent path.
        // See: https://github.com/zizmorcore/zizmor/issues/1341
        let is_workflow_path = {
            let resolved = path.canonicalize_utf8()?;

            resolved
                .parent()
                .is_some_and(|parent| parent.ends_with(".github/workflows"))
        };

        let mut group = Self::new(config);

        // When collecting individual files, we don't know which part
        // of the input path is the prefix.
        let (key, kind) = match (path.file_stem(), path.extension()) {
            (Some("dependabot"), Some("yml" | "yaml")) if !is_workflow_path => (
                InputKey::local(Group(path.as_str().into()), path, None),
                InputKind::Dependabot,
            ),
            (Some("action"), Some("yml" | "yaml")) if !is_workflow_path => (
                InputKey::local(Group(path.as_str().into()), path, None),
                InputKind::Action,
            ),
            (Some(_), Some("yml" | "yaml")) => (
                InputKey::local(Group(path.as_str().into()), path, None),
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
        let config = Config::discover(options, || Config::discover_local(path)).await?;

        let mut group = Self::new(config);

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

        for entry in walker.build() {
            let entry = entry?;
            let entry = <&Utf8Path>::try_from(entry.path())
                .map_err(|e| CollectionError::InvalidPath(e, entry.path().into()))?;

            if options.mode_set.workflows()
                && entry.is_file()
                && matches!(entry.extension(), Some("yml" | "yaml"))
                && entry
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".github/workflows"))
            {
                let key = InputKey::local(Group(path.as_str().into()), entry, Some(path));
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
                && entry.is_file()
                && matches!(entry.file_name(), Some("action.yml" | "action.yaml"))
            {
                let key = InputKey::local(Group(path.as_str().into()), entry, Some(path));
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
                && entry.is_file()
                && matches!(
                    entry.file_name(),
                    Some("dependabot.yml" | "dependabot.yaml")
                )
            {
                let key = InputKey::local(Group(path.as_str().into()), entry, Some(path));
                let contents = std::fs::read_to_string(entry).map_err(|e| {
                    CollectionError::Inner(
                        CollectionError::Io(e).into(),
                        key.to_string(),
                        InputKind::Dependabot,
                    )
                })?;
                group.register(InputKind::Dependabot, contents, key, options.strict)?;
            }
        }

        Ok(group)
    }

    async fn collect_from_repo_slug(
        slug: RepoSlug,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        let client = gh_client.ok_or_else(|| CollectionError::NoGitHubClient(slug.clone()))?;

        let config = Config::discover(options, || Config::discover_remote(client, &slug)).await?;
        let mut group = Self::new(config);

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

            tracing::info!(
                "collected {len} inputs from {owner}/{repo}",
                owner = slug.owner,
                repo = slug.repo
            );
        }

        Ok(group)
    }

    pub(crate) async fn collect(
        request: &str,
        options: &CollectionOptions,
        gh_client: Option<&Client>,
    ) -> Result<Self, CollectionError> {
        let path = Utf8Path::new(request);

        if path.is_file() {
            Self::collect_from_file(path, options).await
        } else if path.is_dir() {
            Self::collect_from_dir(path, options).await
        } else {
            let slug = RepoSlug::from_str(request)?;
            Self::collect_from_repo_slug(slug, options, gh_client).await
        }
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
    pub(crate) groups: BTreeMap<Group, InputGroup>,
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
        if let btree_map::Entry::Vacant(e) = self.groups.entry(Group(name.into())) {
            e.insert(InputGroup::collect(name, options, gh_client).await?);
        }

        Ok(())
    }

    /// Return an iterator over all inputs in all groups in this registry.
    pub(crate) fn iter_inputs(&self) -> impl Iterator<Item = (&InputKey, &AuditInput)> {
        self.groups.values().flat_map(|group| group.inputs.iter())
    }

    /// Get a reference to a registered input by its key.
    pub(crate) fn get_input(&self, key: &InputKey) -> &AuditInput {
        self.groups
            .get(key.group())
            .and_then(|group| group.inputs.get(key))
            .expect("API misuse: requested an un-registered input")
    }

    /// Get a reference to the configuration for a given input group.
    pub(crate) fn get_config(&self, group: &Group) -> &Config {
        &self
            .groups
            .get(group)
            .expect("API misuse: requested config for an un-registered input")
            .config
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::{InputKey, RepoSlug};

    #[test]
    fn test_input_key_display() {
        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", None);
        assert_eq!(local.to_string(), "file:///foo/bar/baz.yml");

        // No ref
        let slug = RepoSlug::from_str("foo/bar").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into());
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/HEAD/.github/workflows/baz.yml"
        );

        // With a git ref
        let slug = RepoSlug::from_str("foo/bar@v1").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into());
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/v1/.github/workflows/baz.yml"
        );
    }

    #[test]
    fn test_input_key_local_presentation_path() {
        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", None);
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"));
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo/bar/"));
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local(
            "fakegroup".into(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
        );
        assert_eq!(
            local.presentation_path(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml"
        );
    }

    #[test]
    fn test_input_key_local_sarif_path() {
        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", None);
        assert_eq!(local.sarif_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo"));
        assert_eq!(local.sarif_path(), "bar/baz.yml");

        let local = InputKey::local("fakegroup".into(), "/foo/bar/baz.yml", Some("/foo/bar/"));
        assert_eq!(local.sarif_path(), "baz.yml");

        let local = InputKey::local(
            "fakegroup".into(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
        );
        assert_eq!(local.sarif_path(), ".github/workflows/baz.yml");

        let local = InputKey::local("fakegroup".into(), "./.github/workflows/baz.yml", Some("."));
        assert_eq!(local.sarif_path(), ".github/workflows/baz.yml");
    }
}
