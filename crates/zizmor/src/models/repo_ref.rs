//! Generic handling of "repository references," i.e. a reference to some Git
//! repository, potentially qualified in various ways.

use github_actions_models::common::RepositoryUses;
use pre_commit_models::config::RemoteRepo;
use url::Url;

use crate::{models::uses::RepositoryUsesPattern, utils::once::warn_once};

/// A GitHub `owner/repo` slug.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Slug<'doc> {
    /// The repo owner.
    owner: &'doc str,
    /// The repo name.
    repo: &'doc str,
    /// The full `owner/repo` slug.
    slug: &'doc str,
}

impl<'doc> Slug<'doc> {
    pub(crate) fn parse(slug: &'doc str) -> Option<Self> {
        let mut parts = slug.split('/');

        if let Some(owner) = parts.next()
            && let Some(repo) = parts.next()
            && let None = parts.next()
        {
            Some(Self::new(owner, repo, slug))
        } else {
            None
        }
    }

    /// Construct a new [`Slug`] from parts.
    ///
    /// Assumes that each part is well-formed.
    fn new(owner: &'doc str, repo: &'doc str, slug: &'doc str) -> Self {
        Self { owner, repo, slug }
    }

    pub(crate) fn owner(&self) -> &'doc str {
        self.owner
    }

    pub(crate) fn repo(&self) -> &'doc str {
        self.repo
    }

    pub(crate) fn slug(&self) -> &'doc str {
        self.slug
    }
}

impl<'doc> From<&'doc RepositoryUses> for Slug<'doc> {
    fn from(uses: &'doc RepositoryUses) -> Self {
        Self::new(uses.owner(), uses.repo(), uses.slug())
    }
}

impl std::fmt::Display for Slug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.slug())
    }
}

#[derive(Debug)]
pub(crate) enum RepoRef<'doc> {
    /// A repository reference from a `uses:` clause.
    Uses(&'doc RepositoryUses),
    /// A repository reference from a Git URL.
    Url {
        _url: &'doc Url,

        /// The GitHub `owner/repo` within the URL, if present.
        slug: Option<Slug<'doc>>,

        /// A Git tag or other reference for the repository, if present.
        git_ref: &'doc str,
    },
}

impl<'doc> RepoRef<'doc> {
    pub(crate) fn from_url(url: &'doc Url, git_ref: &'doc str) -> Self {
        // Opportunistically pull the slug out of the URL, if we know its shape.
        let slug = if url.host_str() == Some("github.com") {
            // We expect `https://github.com/owner/repo`, but
            // the user can naturally feed us nonsense.
            let path = url.path();
            let mut parts = path.split('/');

            // We expect an empty component first, since `path()`
            // returns a leading `/` for the URL shape we expect.
            if let Some("") = parts.next()
                && let Some(owner) = parts.next()
                && !owner.is_empty()
                && let Some(repo) = parts.next()
                && !repo.is_empty()
                && let None = parts.next()
            {
                Some(Slug::new(owner, repo, &path[1..]))
            } else {
                // Either too many or too few components.
                warn_once!("invalid looking GitHub repository URL: {url}");
                None
            }
        } else {
            None
        };

        Self::Url {
            _url: url,
            slug,
            git_ref,
        }
    }

    /// Returns the [`Slug`] for this [`RepoRef`], if it has one.
    pub(crate) fn slug(&self) -> Option<Slug<'doc>> {
        match self {
            RepoRef::Uses(uses) => Some(Slug::from(*uses)),
            RepoRef::Url { slug, .. } => slug.as_ref().copied(),
        }
    }

    /// Returns the subpath to the action within this repository, if it has one.
    ///
    /// Only a `uses:` clause can carry a subpath, as in
    /// `owner/repo/subpath@ref`. A Git URL reference has no notion of one,
    /// since the URL names the repository and nothing within it.
    pub(crate) fn subpath(&self) -> Option<&'doc str> {
        match self {
            RepoRef::Uses(uses) => uses.subpath(),
            RepoRef::Url { .. } => None,
        }
    }

    /// Return this repository reference's Git reference, if it has one.
    pub(crate) fn git_ref(&self) -> &'doc str {
        match self {
            RepoRef::Uses(uses) => uses.git_ref(),
            RepoRef::Url { git_ref, .. } => git_ref,
        }
    }

    /// Returns whether this repository reference has an exact "commit"
    /// reference, i.e. a 40-hexdigit object ID.
    ///
    /// Note that this is called a "commit" reference, but matches all Git
    /// object IDs including object IDs for tags.
    pub(crate) fn ref_is_commit(&self) -> bool {
        self.git_ref().len() == 40 && self.git_ref().chars().all(|c| c.is_ascii_hexdigit())
    }

    pub(crate) fn commit_ref(&self) -> Option<&'doc str> {
        match &self.git_ref() {
            git_ref if self.ref_is_commit() => Some(*git_ref),
            _ => None,
        }
    }

    pub(crate) fn symbolic_ref(&self) -> Option<&'doc str> {
        match &self.git_ref() {
            git_ref if !self.ref_is_commit() => Some(*git_ref),
            _ => None,
        }
    }

    /// Returns whether this repository reference matches the given pattern.
    ///
    /// This uses [`RepositoryUsesPattern`] under the hood, and follows the
    /// same matching rules.
    pub(crate) fn matches(&self, template: &str) -> bool {
        let Ok(pat) = template.parse::<RepositoryUsesPattern>() else {
            return false;
        };

        pat.matches(self)
    }
}

impl<'doc> From<&'doc RepositoryUses> for RepoRef<'doc> {
    fn from(uses: &'doc RepositoryUses) -> Self {
        Self::Uses(uses)
    }
}

impl<'doc> From<&'doc RemoteRepo> for RepoRef<'doc> {
    fn from(repo: &'doc RemoteRepo) -> Self {
        Self::from_url(&repo.repo, &repo.rev)
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::models::repo_ref::{RepoRef, Slug};

    #[test]
    fn test_slug_display() {
        let slug = Slug::new("foo", "bar", "foo/bar");
        assert_eq!(slug.to_string(), "foo/bar");
    }

    #[test]
    fn test_reporef_from_url() {
        // Non-GitHub URL: no additional information.
        let url = Url::parse("https://example.com/nonsense").unwrap();
        insta::assert_debug_snapshot!(RepoRef::from_url(&url, "v1"), @r#"
        Url {
            _url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "example.com",
                    ),
                ),
                port: None,
                path: "/nonsense",
                query: None,
                fragment: None,
            },
            slug: None,
            git_ref: "v1",
        }
        "#);

        // GitHub URL: owner/repo and slug get filled in.
        let url = Url::parse("https://github.com/foo/bar").unwrap();
        insta::assert_debug_snapshot!(RepoRef::from_url(&url, "v1"), @r#"
        Url {
            _url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "github.com",
                    ),
                ),
                port: None,
                path: "/foo/bar",
                query: None,
                fragment: None,
            },
            slug: Some(
                Slug {
                    owner: "foo",
                    repo: "bar",
                    slug: "foo/bar",
                },
            ),
            git_ref: "v1",
        }
        "#);

        // GitHub URL but nonsense: no extras get filled in.
        let url = Url::parse("https://github.com/foo/").unwrap();
        insta::assert_debug_snapshot!(RepoRef::from_url(&url, "v1"), @r#"
        Url {
            _url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "github.com",
                    ),
                ),
                port: None,
                path: "/foo/",
                query: None,
                fragment: None,
            },
            slug: None,
            git_ref: "v1",
        }
        "#);
    }
}
