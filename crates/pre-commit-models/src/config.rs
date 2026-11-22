//! Pre-commit configuration models, i.e. for `.pre-commit-config.yaml`.
//!
//! See: <https://pre-commit.com/#plugins>

use crate::common::{self, FilePattern, LanguageVersion};
use indexmap::IndexMap;
use serde::de::Error as _;

/// A single pre-commit configuration, containing one or more repositories,
/// each of which may reference one or more hooks.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// A list of repository mappings.
    #[serde(deserialize_with = "common::non_empty_vec")]
    pub repos: Vec<Repo>,
    /// An optional list of `--hook-types`.
    ///
    /// If not supplied, this defaults to `[pre-commit]`.
    ///
    // TODO: Model that?
    pub default_install_hook_types: Option<Vec<String>>,

    /// A mapping from language to the default language version that
    /// should be used for that language, if a hook does not supply its
    /// own `language_version`.
    #[serde(default)]
    pub default_language_version: IndexMap<String, LanguageVersion>,

    /// The `stages` property for a hook, if a hook does not supply its
    /// own `stages`.
    pub default_stages: Option<Vec<String>>,

    /// The global file include pattern.
    pub files: Option<FilePattern>,

    /// The global file exclude pattern.
    pub exclude: Option<FilePattern>,

    /// Whether to have pre-commit stop running hooks after the first
    /// failure.
    #[serde(default)]
    pub fail_fast: bool,

    /// The minimum version of pre-commit required.
    #[serde(default = "common::default_minimum_pre_commit_version")]
    pub minimum_pre_commit_version: String,
}

/// A repository, i.e. where to get one or more hooks from.
///
/// This concept is slightly overloaded in pre-commit, as there are
/// two special sentinel "repository" types, `local`, and `meta`, which
/// have a different shape than a normal Git repository.
#[derive(Debug, serde::Deserialize)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "snake_case",
    tag = "repo"
)]
pub enum Repo {
    /// A special 'local' repository, for hooks defined within the current Git repository.
    ///
    /// See: <https://pre-commit.com/#repository-local-hooks>
    // TODO: Fill this in. It's seemingly identical to a normal hook,
    // except without `rev`.
    Local {},
    /// A special 'meta' repository, for hooks defined by pre-commit itself.
    ///
    /// See: <https://pre-commit.com/#meta-hooks>
    // TODO: Fill this in, it's a fixed set of IDs for hooks.
    Meta {},
    /// A special 'builtin` repository, for hooks defined by prek itself.
    ///
    /// This is a prek-specific extension.
    ///
    /// See: <https://prek.j178.dev/builtin/#2-explicit-builtin-repository>
    Builtin {},
    #[serde(untagged)]
    Remote(RemoteRepo),
}

/// A remote repository, i.e. the home of one or more pre-commit hooks.
///
/// This is only "remote" in the sense that it's sourced via a "target".
/// See [`RemoteRepoTarget`] for more information.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteRepo {
    pub repo: RemoteRepoTarget,
    pub rev: String,
    #[serde(deserialize_with = "common::non_empty_vec")]
    pub hooks: Vec<Hook>,
}

/// A repository target in a "remote" pre-commit repository.
/// A target be a local URL (like a `file://`), or an HTTP(S) URL,
/// or anything else that Git accepts (like an SCP-style target).
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum RemoteRepoTarget {
    /// Covers all normal `scheme://` URLs.
    Url(url::Url),

    /// Covers SCP-style Git targets.
    Scp(Scp),

    /// Covers paths passed directly into Git, e.g. `.` or `../foo`.
    Path(RepoPath),
}

impl RemoteRepoTarget {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Url(url) => url.as_str(),
            Self::Scp(scp) => scp.raw(),
            Self::Path(path) => path.path.as_str(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct ScpInner<'a> {
    /// The SSH user, if present.
    user: Option<&'a str>,

    /// The remote hostname.
    host: &'a str,

    /// The remote path.
    path: &'a str,
}

impl<'a> ScpInner<'a> {
    fn from_str(raw: &'a str) -> Result<Self, &'static str> {
        // SCP targets aren't really standardized, but they look like this:
        // `[user@]host[:path]`. Git further strengthens this by requiring a path.
        let (user, rest) = match raw.split_once("@") {
            Some((user, rest)) => (Some(user), rest),
            None => (None, raw),
        };

        if user.is_some_and(|user| user.is_empty()) {
            return Err("invalid SCP Git target: empty user");
        }

        // Note: not an rsplit because hosts should not contain colons
        // but paths can.
        let (host, path) = rest
            .split_once(":")
            .ok_or("invalid SCP Git target: missing path")?;

        if host.is_empty() || path.is_empty() {
            return Err("invalid SCP Git target: empty host or path");
        }

        Ok(Self { user, host, path })
    }
}

self_cell::self_cell!(
    /// A SCP-style target, e.g. `[user@]host[:path]`.
    pub struct Scp {
        owner: String,

        #[covariant]
        dependent: ScpInner,
    }

    impl {Debug, PartialEq}
);

impl std::fmt::Display for Scp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw())
    }
}

impl<'de> serde::Deserialize<'de> for Scp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let uses = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(uses).map_err(serde::de::Error::custom)
    }
}

impl Scp {
    /// Parse an SCP-style Git target.
    pub fn parse(uses: impl Into<String>) -> Result<Self, &'static str> {
        Self::try_new(uses.into(), |s| {
            let inner = ScpInner::from_str(s)?;
            Ok(inner)
        })
    }

    /// Get the raw SCP-style target.
    pub fn raw(&self) -> &str {
        self.borrow_owner()
    }

    /// Get the username in the SCP-style target, if present.
    ///
    /// For example, this will be `foo` in `foo@host:/abcd`.
    pub fn user(&self) -> Option<&str> {
        self.borrow_dependent().user
    }

    /// Get the hostname in the SCP-style target.
    ///
    /// For example, this will be `example.com` in `foo@example.com:/abcd`.
    pub fn host(&self) -> &str {
        self.borrow_dependent().host
    }

    /// Get the path component in the SCP-style target.
    ///
    /// For example, this will be `/abcd` in `foo@example.com/abcd`.
    pub fn path(&self) -> &str {
        self.borrow_dependent().path
    }
}

/// A Git repository path, i.e. a bare bath passed to `repo: ...`.
///
/// We store a second copy of this path in `file://{path}` form as well.
#[derive(Debug, PartialEq)]
pub struct RepoPath {
    /// The verbatim path.
    pub path: String,

    /// The path, but in `file://` URL form.
    pub url: url::Url,
}

impl<'de> serde::Deserialize<'de> for RepoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;

        // Note: this is slightly pessimized. The first URL parse should always fail since
        // `RepoPath` is deserialized through `RemoteRepoTarget` and the URL variant matches before it.
        // However, trying it first ensures that we don't accidentally do `file://file://` or similar
        // by changing our callsites in the future.
        let url = url::Url::parse(&path)
            .or_else(|_| url::Url::parse(&format!("file://{path}")))
            .map_err(D::Error::custom)?;

        Ok(Self { path, url })
    }
}

/// A single hook.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Hook {
    /// The ID of the hook to use.
    pub id: String,

    /// An optional additional ID to use when referring to the hook.
    pub alias: Option<String>,

    /// Overrides the name of the hook, as shown during execution.
    pub name: Option<String>,

    /// Overrides the language version for the hook.
    pub language_version: Option<LanguageVersion>,

    /// Overrides the files pattern for the hook.
    pub files: Option<FilePattern>,

    /// Overrides the exclude pattern for the hook.
    pub exclude: Option<FilePattern>,

    /// Overrides the default file types to run on for the hook (AND).
    pub types: Option<Vec<String>>,

    /// Overrides the default file types to run on for the hook (OR).
    pub types_or: Option<Vec<String>>,

    /// Overrides the types to exclude for the hook.
    pub exclude_types: Option<Vec<String>>,

    /// Optional list of additional args to supply to the hook.
    #[serde(default)]
    pub args: Vec<String>,

    /// Overrides the set of stages to run the hook for.
    pub stages: Option<Vec<String>>,

    /// Additional dependencies to install into the hook's environment.
    #[serde(default)]
    pub additional_dependencies: Vec<String>,

    /// If true, run the hook even when there are no matching files.
    #[serde(default)]
    pub always_run: bool,

    /// If true, force the hook's output to be printed even if it passes.
    #[serde(default)]
    pub verbose: bool,

    /// If present, additionally append the hook's log output to this file.
    #[serde(default)]
    pub log_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::config::Scp;

    #[test]
    fn test_scp_parses() {
        // Ok: explicit git suffix.
        insta::assert_debug_snapshot!(
            &Scp::parse("git@github.com:org/repo.git"),
            @r#"
        Ok(
            Scp {
                owner: "git@github.com:org/repo.git",
                dependent: ScpInner {
                    user: Some(
                        "git",
                    ),
                    host: "github.com",
                    path: "org/repo.git",
                },
            },
        )
        "#
        );

        // Ok: no git suffix.
        insta::assert_debug_snapshot!(
            &Scp::parse("git@github.com:org/repo"),
            @r#"
        Ok(
            Scp {
                owner: "git@github.com:org/repo",
                dependent: ScpInner {
                    user: Some(
                        "git",
                    ),
                    host: "github.com",
                    path: "org/repo",
                },
            },
        )
        "#
        );

        // Ok: no user.
        insta::assert_debug_snapshot!(
            &Scp::parse("github.com:org/repo.git"),
            @r#"
        Ok(
            Scp {
                owner: "github.com:org/repo.git",
                dependent: ScpInner {
                    user: None,
                    host: "github.com",
                    path: "org/repo.git",
                },
            },
        )
        "#
        );

        // Not ok.
        for bad in [
            "@github.com:org/repo", // Empty user.
            "git@:org/repo",        // Empty host.
            "git@github.com",       // Missing path.
            "git@github.com:",      // Empty path.
        ] {
            assert!(Scp::parse(bad).is_err(), "expected {bad} to be invalid");
        }
    }
}
