//! Input registry and associated types.

use std::collections::{BTreeMap, btree_map};

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;
use thiserror::Error;

use crate::{
    audit::AuditInput,
    models::{action::Action, workflow::Workflow},
    tips,
};

#[derive(Error, Debug)]
pub(crate) enum InputError {
    /// The input's syntax is invalid.
    /// This typically indicates a user error.
    #[error("invalid YAML syntax: {0}")]
    Syntax(#[source] anyhow::Error),
    /// The input couldn't be converted into the expected model.
    /// This typically indicates a bug in `github-actions-models`.
    #[error("couldn't turn input into a an appropriate model")]
    Model(#[source] anyhow::Error),
    /// The input doesn't match the schema for the expected model.
    /// This typically indicates a user error.
    #[error("input does not match expected validation schema")]
    Schema(#[source] anyhow::Error),
    /// An I/O error occurred while loading the input.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The input's name is missing.
    #[error("invalid input: no filename component")]
    MissingName,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) enum InputKind {
    /// A workflow file.
    Workflow,
    /// An action definition.
    Action,
}

impl std::fmt::Display for InputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputKind::Workflow => write!(f, "workflow"),
            InputKind::Action => write!(f, "action"),
        }
    }
}

/// A GitHub repository slug, i.e. `owner/repo[@ref]`.
#[derive(Debug)]
pub(crate) struct RepoSlug {
    /// The owner of the repository.
    pub(crate) owner: String,
    /// The name of the repository.
    pub(crate) repo: String,
    /// An optional Git reference, e.g. a branch or tag name.
    pub(crate) git_ref: Option<String>,
}

impl std::str::FromStr for RepoSlug {
    type Err = anyhow::Error;

    /// NOTE: This is almost exactly the same as
    /// [`github_actions_models::common::RepositoryUses`],
    /// except that we don't require a git ref and we forbid subpaths.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, git_ref) = match s.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (s, None),
        };

        let components = path.splitn(2, '/').collect::<Vec<_>>();

        match components.len() {
            2 => Ok(Self {
                owner: components[0].into(),
                repo: components[1].into(),
                git_ref: git_ref.map(|s| s.into()),
            }),
            x if x < 2 => Err(anyhow::anyhow!(tips(
                "invalid repo slug (too short)",
                &["pass owner/repo or owner/repo@ref"]
            ))),
            _ => Err(anyhow::anyhow!(tips(
                "invalid repo slug (too many parts)",
                &["pass owner/repo or owner/repo@ref"]
            ))),
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct LocalKey {
    /// The path's nondeterministic prefix, if any.
    prefix: Option<Utf8PathBuf>,
    /// The given path to the input. This can be absolute or relative.
    pub(crate) given_path: Utf8PathBuf,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
pub(crate) struct RemoteKey {
    // TODO: Dedupe with RepoSlug above.
    owner: String,
    repo: String,
    git_ref: Option<String>,
    path: Utf8PathBuf,
}

/// A unique identifying "key" for a workflow file in a given run of zizmor.
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
                let git_ref = remote.git_ref.as_deref().unwrap_or("HEAD");
                write!(
                    f,
                    "https://github.com/{owner}/{repo}/blob/{git_ref}/{path}",
                    owner = remote.owner,
                    repo = remote.repo,
                    path = remote.path
                )
            }
        }
    }
}

impl InputKey {
    pub(crate) fn local<P: AsRef<Utf8Path>>(
        path: P,
        prefix: Option<P>,
    ) -> Result<Self, InputError> {
        // All keys must have a filename component.
        if path.as_ref().file_name().is_none() {
            return Err(InputError::MissingName);
        }

        Ok(Self::Local(LocalKey {
            prefix: prefix.map(|p| p.as_ref().to_path_buf()),
            given_path: path.as_ref().to_path_buf(),
        }))
    }

    pub(crate) fn remote(slug: &RepoSlug, path: String) -> Result<Self, InputError> {
        if Utf8Path::new(&path).file_name().is_none() {
            return Err(InputError::MissingName);
        }

        Ok(Self::Remote(RemoteKey {
            owner: slug.owner.clone(),
            repo: slug.repo.clone(),
            git_ref: slug.git_ref.clone(),
            path: path.into(),
        }))
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
            InputKey::Local(local) => local.given_path.file_name().unwrap(),
            InputKey::Remote(remote) => remote.path.file_name().unwrap(),
        }
    }
}

pub(crate) struct InputRegistry {
    strict: bool,
    // NOTE: We use a BTreeMap here to ensure that registered inputs
    // iterate in a deterministic order. This saves us a lot of pain
    // while snapshot testing across multiple input files, and makes
    // the user experience more predictable.
    pub(crate) inputs: BTreeMap<InputKey, AuditInput>,
}

impl InputRegistry {
    pub(crate) fn new(strict: bool) -> Self {
        Self {
            strict,
            inputs: Default::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.inputs.len()
    }

    pub(crate) fn register(
        &mut self,
        kind: InputKind,
        contents: String,
        key: InputKey,
    ) -> anyhow::Result<()> {
        tracing::debug!("registering {kind} input as with key {key}");

        let input: Result<AuditInput, InputError> = match kind {
            InputKind::Workflow => Workflow::from_string(contents, key.clone()).map(|wf| wf.into()),
            InputKind::Action => Action::from_string(contents, key.clone()).map(|a| a.into()),
        };

        match input {
            Ok(input) => self.register_input(input),
            Err(InputError::Syntax(e)) if !self.strict => {
                tracing::warn!("failed to parse input: {e}");
                Ok(())
            }
            Err(e @ InputError::Schema { .. }) if !self.strict => {
                tracing::warn!("failed to validate input as {kind}: {e}");
                Ok(())
            }
            Err(e) => {
                Err(anyhow::anyhow!(e)).with_context(|| format!("failed to load {key} as {kind}"))
            }
        }
    }

    /// Registers an already-loaded workflow or action definition.
    fn register_input(&mut self, input: AuditInput) -> anyhow::Result<()> {
        if self.inputs.contains_key(input.key()) {
            return Err(anyhow::anyhow!(
                "can't register {key} more than once",
                key = input.key()
            ));
        }

        self.inputs.insert(input.key().clone(), input);

        Ok(())
    }

    pub(crate) fn iter_inputs(&self) -> btree_map::Iter<'_, InputKey, AuditInput> {
        self.inputs.iter()
    }

    pub(crate) fn get_input(&self, key: &InputKey) -> &AuditInput {
        self.inputs
            .get(key)
            .expect("API misuse: requested an un-registered input")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::{InputKey, RepoSlug};

    #[test]
    fn test_input_key_display() {
        let local = InputKey::local("/foo/bar/baz.yml", None).unwrap();
        assert_eq!(local.to_string(), "file:///foo/bar/baz.yml");

        // No ref
        let slug = RepoSlug::from_str("foo/bar").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into()).unwrap();
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/HEAD/.github/workflows/baz.yml"
        );

        // With a git ref
        let slug = RepoSlug::from_str("foo/bar@v1").unwrap();
        let remote = InputKey::remote(&slug, ".github/workflows/baz.yml".into()).unwrap();
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/v1/.github/workflows/baz.yml"
        );
    }

    #[test]
    fn test_input_key_local_presentation_path() {
        let local = InputKey::local("/foo/bar/baz.yml", None).unwrap();
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("/foo/bar/baz.yml", Some("/foo")).unwrap();
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("/foo/bar/baz.yml", Some("/foo/bar/")).unwrap();
        assert_eq!(local.presentation_path(), "/foo/bar/baz.yml");

        let local = InputKey::local(
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
        )
        .unwrap();
        assert_eq!(
            local.presentation_path(),
            "/home/runner/work/repo/repo/.github/workflows/baz.yml"
        );
    }

    #[test]
    fn test_input_key_local_sarif_path() {
        let local = InputKey::local("/foo/bar/baz.yml", None).unwrap();
        assert_eq!(local.sarif_path(), "/foo/bar/baz.yml");

        let local = InputKey::local("/foo/bar/baz.yml", Some("/foo")).unwrap();
        assert_eq!(local.sarif_path(), "bar/baz.yml");

        let local = InputKey::local("/foo/bar/baz.yml", Some("/foo/bar/")).unwrap();
        assert_eq!(local.sarif_path(), "baz.yml");

        let local = InputKey::local(
            "/home/runner/work/repo/repo/.github/workflows/baz.yml",
            Some("/home/runner/work/repo/repo"),
        )
        .unwrap();
        assert_eq!(local.sarif_path(), ".github/workflows/baz.yml");

        let local = InputKey::local("./.github/workflows/baz.yml", Some(".")).unwrap();
        assert_eq!(local.sarif_path(), ".github/workflows/baz.yml");
    }
}
