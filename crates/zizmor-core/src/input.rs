//! Input registry and associated types.

use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;
use thiserror::Error;

use crate::{
    finding::location::{Routable, SymbolicLocation},
    models::{
        AsDocument,
        action::Action,
        dependabot::Dependabot,
        pre_commit::{PreCommitConfig, PreCommitHooks},
        repo_ref::Slug,
        workflow::Workflow,
    },
};
use yamlpath::Document;

/// Errors that can occur while parsing an input into a core model.
#[derive(Debug, Error)]
pub enum InputError {
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

    /// The input couldn't be parsed as one of our known input sources
    /// (file, directory, or GitHub repo).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub enum InputKind {
    /// A workflow file.
    Workflow,
    /// An action definition.
    Action,
    /// A Dependabot configuration file.
    Dependabot,
    /// A `.pre-commit-config.yml` file.
    PreCommitConfig,
    /// A `.pre-commit-hooks.yml` file.
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
pub struct InputSlug {
    /// The owner of the repository.
    pub owner: String,
    /// The name of the repository.
    pub repo: String,
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
    pub fn git_ref(&self) -> &str {
        self.git_ref.as_deref().unwrap_or("HEAD")
    }
}

impl std::str::FromStr for InputSlug {
    type Err = InputError;

    /// NOTE: This is almost exactly the same as
    /// [`github_actions_models::common::RepositoryUses`],
    /// except that we don't require a git ref and we forbid subpaths.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, git_ref) = match s.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (s, None),
        };

        let Some(slug) = Slug::parse(path) else {
            return Err(InputError::InvalidInput(s.into()));
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
pub struct LocalKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: Group,

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

    /// The "best" identifier for this input.
    ///
    /// This will always be a relative path (unless the input itself was absolute),
    /// and is the "best" in the sense that it attempts to be relative to the repository
    /// root (if present), rather than whatever relative path the user actually supplied.
    ///
    /// This identifier always uses Unix-style path separators.
    ///
    /// See [`InputKey::best_identifier`] for more information.
    #[serde(skip)]
    best_identifier: String,
}

impl LocalKey {
    /// Returns a real path to this [`LocalKey`]'s input, on disk.
    ///
    /// This path may be relative or absolute.
    pub fn path(&self) -> &Utf8Path {
        &self.verbatim_path
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub struct RemoteKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: Group,
    slug: InputSlug,
    /// The path to the input file within the repository.
    path: Utf8PathBuf,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub struct StdinKey {
    /// The group this input belongs to.
    #[serde(skip)]
    group: Group,
}

/// A unique identifying "key" for an input in a given run of zizmor.
///
/// zizmor currently knows three different kinds of keys: local keys
/// are canonical paths to files on disk, remote keys are relative
/// paths within a referenced GitHub repository, and stdin keys
/// represent input read from standard input.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub enum InputKey {
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
    /// Constructs a local InputKey from pre-collected path state.
    pub fn local<P: AsRef<Utf8Path>>(
        group: Group,
        verbatim_path: P,
        best_identifier: String,
    ) -> Self {
        let verbatim_path = verbatim_path.as_ref();

        Self::Local(LocalKey {
            group,
            verbatim_path: verbatim_path.to_path_buf(),
            native_path: verbatim_path.components().collect(),
            best_identifier,
        })
    }

    pub fn remote(slug: &InputSlug, path: String) -> Self {
        Self::Remote(RemoteKey {
            group: slug.into(),
            slug: slug.clone(),
            path: path.into(),
        })
    }

    pub fn stdin() -> Self {
        Self::Stdin(StdinKey {
            group: Group::from("-"),
        })
    }

    /// Returns the "best" identifier for this [`InputKey`].
    ///
    /// This returns an arbitrary identifier for the input which,
    /// depending on the input kind, may or may resemble a userful path
    /// on disk.
    pub fn best_identifier(&self) -> &str {
        match self {
            // Local keys: always use the "best" relative path,
            // which is opportunistically relative to the repo root
            // if possible.
            Self::Local(local) => local.best_identifier.as_str(),
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
    pub fn presentation_path(&self) -> &str {
        match self {
            Self::Local(local) => local.native_path.as_str(),
            Self::Remote(remote) => remote.path.as_str(),
            Self::Stdin(_) => "<stdin>",
        }
    }

    /// Returns the filename component of this [`InputKey`].
    pub fn filename(&self) -> &str {
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
    pub fn group(&self) -> &Group {
        match self {
            Self::Local(local) => &local.group,
            Self::Remote(remote) => &remote.group,
            Self::Stdin(stdin) => &stdin.group,
        }
    }
}

/// An opaque identifier for a group of inputs.
#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct Group(pub String);

impl From<&str> for Group {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<&InputSlug> for Group {
    fn from(value: &InputSlug) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug)]
pub enum AuditInput {
    Workflow(Workflow),
    Action(Action),
    Dependabot(Dependabot),
    PreCommitConfig(PreCommitConfig),
    PreCommitHooks(PreCommitHooks),
}

impl AuditInput {
    pub fn key(&self) -> &InputKey {
        match self {
            Self::Workflow(workflow) => &workflow.key,
            Self::Action(action) => &action.key,
            Self::Dependabot(dependabot) => &dependabot.key,
            Self::PreCommitConfig(pre_commit_config) => &pre_commit_config.key,
            Self::PreCommitHooks(pre_commit_hooks) => &pre_commit_hooks.key,
        }
    }

    pub fn link(&self) -> Option<&str> {
        match self {
            Self::Workflow(workflow) => workflow.link.as_deref(),
            Self::Action(action) => action.link.as_deref(),
            Self::Dependabot(dependabot) => dependabot.link.as_deref(),
            Self::PreCommitConfig(pre_commit_config) => pre_commit_config.link.as_deref(),
            Self::PreCommitHooks(pre_commit_hooks) => pre_commit_hooks.link.as_deref(),
        }
    }

    pub fn location(&self) -> SymbolicLocation<'_> {
        match self {
            Self::Workflow(workflow) => workflow.location(),
            Self::Action(action) => action.location(),
            Self::Dependabot(dependabot) => dependabot.location(),
            Self::PreCommitConfig(pre_commit_config) => pre_commit_config.location(),
            Self::PreCommitHooks(pre_commit_hooks) => pre_commit_hooks.location(),
        }
    }

    /// Returns whether this kind of input supports GitHub Actions' template syntax,
    /// i.e. "actions expressions."
    ///
    /// This exists because some `Audit::audit_raw` implementations exist to walk
    /// actions expressions, but not all raw inputs can actually contain those expressions.
    ///
    /// TODO: This is kind of goofy. Maybe we should do this by construction,
    /// i.e. have an `Audit::audit_raw_gha` instead.
    pub fn supports_gha_template_syntax(&self) -> bool {
        matches!(self, Self::Workflow(_) | Self::Action(_))
    }
}

impl<'a> AsDocument<'a, 'a> for AuditInput {
    fn as_document(&'a self) -> &'a Document {
        match self {
            Self::Workflow(workflow) => workflow.as_document(),
            Self::Action(action) => action.as_document(),
            Self::Dependabot(dependabot) => dependabot.as_document(),
            Self::PreCommitConfig(pre_commit_config) => pre_commit_config.as_document(),
            Self::PreCommitHooks(pre_commit_hooks) => pre_commit_hooks.as_document(),
        }
    }
}

impl<'a> Routable<'a, 'a> for AuditInput {
    fn route(&'a self) -> yamlpath::Route<'a> {
        match self {
            Self::Workflow(workflow) => workflow.location().route,
            Self::Action(action) => action.location().route,
            Self::Dependabot(dependabot) => dependabot.location().route,
            Self::PreCommitConfig(pre_commit_config) => pre_commit_config.location().route,
            Self::PreCommitHooks(pre_commit_hooks) => pre_commit_hooks.location().route,
        }
    }
}

impl From<Workflow> for AuditInput {
    fn from(value: Workflow) -> Self {
        Self::Workflow(value)
    }
}

impl From<Action> for AuditInput {
    fn from(value: Action) -> Self {
        Self::Action(value)
    }
}

impl From<Dependabot> for AuditInput {
    fn from(value: Dependabot) -> Self {
        Self::Dependabot(value)
    }
}

impl From<PreCommitConfig> for AuditInput {
    fn from(value: PreCommitConfig) -> Self {
        Self::PreCommitConfig(value)
    }
}

impl From<PreCommitHooks> for AuditInput {
    fn from(value: PreCommitHooks) -> Self {
        Self::PreCommitHooks(value)
    }
}
