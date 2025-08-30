//! A very minimal GitHub API client.
//!
//! Build on synchronous reqwest to avoid octocrab's need to taint
//! the whole codebase with async.

use std::{fmt::Display, io::Read, ops::Deref, str::FromStr};

use anyhow::{Context, Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use flate2::read::GzDecoder;
use http_cache_reqwest::{
    CACacheManager, Cache, CacheMode, CacheOptions, HttpCache, HttpCacheOptions,
};
use owo_colors::OwoColorize;
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, InvalidHeaderValue, USER_AGENT},
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, de::DeserializeOwned};
use tar::Archive;
use tracing::instrument;

use crate::{
    CollectionOptions,
    registry::input::{InputGroup, InputKey, InputKind, RepoSlug},
    utils::PipeSelf,
};

/// Represents different types of GitHub hosts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GitHubHost {
    Enterprise(String),
    Standard(String),
}

impl GitHubHost {
    pub(crate) fn new(hostname: &str) -> Result<Self, String> {
        let normalized = hostname.to_lowercase();

        // NOTE: ideally we'd do a full domain validity check here.
        // For now, this just checks the most likely kind of user
        // confusion (supplying a URL instead of a bare domain name).
        if normalized.starts_with("https://") || normalized.starts_with("http://") {
            return Err("must be a domain name, not a URL".into());
        }

        if normalized.eq_ignore_ascii_case("github.com") || normalized.ends_with(".ghe.com") {
            Ok(Self::Standard(hostname.into()))
        } else {
            Ok(Self::Enterprise(hostname.into()))
        }
    }

    fn to_api_url(&self) -> String {
        match self {
            Self::Enterprise(host) => format!("https://{host}/api/v3"),
            Self::Standard(host) => format!("https://api.{host}"),
        }
    }
}

impl Default for GitHubHost {
    fn default() -> Self {
        Self::Standard("github.com".into())
    }
}

impl Display for GitHubHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enterprise(host) => write!(f, "{host}"),
            Self::Standard(host) => write!(f, "{host}"),
        }
    }
}

impl FromStr for GitHubHost {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A sanitized GitHub access token.
#[derive(Clone)]
pub(crate) struct GitHubToken(String);

impl GitHubToken {
    pub(crate) fn new(token: &str) -> Result<Self, String> {
        let token = token.trim();
        if token.is_empty() {
            return Err("GitHub token cannot be empty".into());
        }
        Ok(Self(token.to_owned()))
    }

    fn to_header_value(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(&format!("Bearer {}", self.0))
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    api_base: String,
    host: GitHubHost,
    http: ClientWithMiddleware,
}

impl Client {
    pub(crate) fn new(
        host: GitHubHost,
        token: GitHubToken,
        cache_dir: Utf8PathBuf,
    ) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "zizmor".parse().unwrap());
        headers.insert(
            AUTHORIZATION,
            token
                .to_header_value()
                .context("couldn't build authorization header for GitHub client")?,
        );
        headers.insert("X-GitHub-Api-Version", "2022-11-28".parse().unwrap());
        headers.insert(ACCEPT, "application/vnd.github+json".parse().unwrap());

        let http = ClientBuilder::new(
            reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .expect("couldn't build GitHub client?"),
        )
        .with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager {
                path: cache_dir.into(),
                remove_opts: Default::default(),
            },
            options: HttpCacheOptions {
                cache_options: Some(CacheOptions {
                    // GitHub API requests made with an API token seem to
                    // always have `Cache-Control: private`, so we need to
                    // explicitly tell http-cache that our cache is not shared
                    // in order for things to cache correctly.
                    shared: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        }))
        .build();

        Ok(Self {
            api_base: host.to_api_url(),
            host,
            http,
        })
    }

    pub(crate) fn host(&self) -> &GitHubHost {
        &self.host
    }

    async fn paginate<T: DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> reqwest_middleware::Result<Vec<T>> {
        let mut dest = vec![];
        let url = format!("{api_base}/{endpoint}", api_base = self.api_base);

        // If we were nice, we would parse GitHub's `links` header and extract
        // the remaining number of pages. But this is annoying, and we are
        // not nice, so we simply request pages until GitHub bails on us
        // and returns empty results.
        let mut pageno = 0;
        loop {
            let resp = self
                .http
                .get(&url)
                .query(&[("page", pageno), ("per_page", 100)])
                .send()
                .await?
                .error_for_status()?;

            let page = resp.json::<Vec<T>>().await?;
            if page.is_empty() {
                break;
            }

            dest.extend(page);
            pageno += 1;
        }

        Ok(dest)
    }

    /// Maps the response to a `Result<bool>`, depending on whether
    /// the response's status indicates 200 or 404.
    ///
    /// The error variants communicate all other status codes,
    /// with additional context where helpful.
    fn resp_present(resp: Response) -> Result<bool> {
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            StatusCode::FORBIDDEN => Err(anyhow::Error::from(resp.error_for_status().unwrap_err())
                .context("request forbidden; token permissions may be insufficient")),
            _ => Err(resp.error_for_status().unwrap_err().into()),
        }
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_branches(&self, owner: &str, repo: &str) -> Result<Vec<Branch>> {
        self.paginate(&format!("repos/{owner}/{repo}/branches"))
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<Tag>> {
        self.paginate(&format!("repos/{owner}/{repo}/tags"))
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_branch(&self, owner: &str, repo: &str, branch: &str) -> Result<bool> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/ref/heads/{branch}",
            api_base = self.api_base
        );

        let resp = self.http.get(&url).send().await?;
        Client::resp_present(resp).with_context(|| {
            format!("{owner}/{repo}: error from the GitHub API while checking {branch}")
        })
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<bool> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/ref/tags/{tag}",
            api_base = self.api_base
        );

        let resp = self.http.get(&url).send().await?;
        Client::resp_present(resp).with_context(|| {
            format!("{owner}/{repo}: error from the GitHub API while checking {tag}")
        })
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn commit_for_ref(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<Option<String>> {
        // GitHub Actions generally resolves branches before tags, so try
        // the repo's branches first.
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/ref/heads/{git_ref}",
            api_base = self.api_base
        );

        let resp = self.http.get(url).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json::<GitRef>().await?.object.sha)),
            StatusCode::NOT_FOUND => {
                let url = format!(
                    "{api_base}/repos/{owner}/{repo}/git/ref/tags/{git_ref}",
                    api_base = self.api_base
                );

                let resp = self.http.get(url).send().await?;
                match resp.status() {
                    StatusCode::OK => Ok(Some(resp.json::<GitRef>().await?.object.sha)),
                    StatusCode::NOT_FOUND => Ok(None),
                    s => Err(anyhow!(
                        "{owner}/{repo}: error from GitHub API while accessing ref {git_ref}: {s}"
                    )),
                }
            }
            s => Err(anyhow!(
                "{owner}/{repo}: error from GitHub API while accessing ref {git_ref}: {s}"
            )),
        }
    }

    #[instrument(skip(self))]
    pub(crate) fn longest_tag_for_commit(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Option<Tag>> {
        // Annoying: GitHub doesn't provide a rev-parse or similar API to
        // perform the commit -> tag lookup, so we download every tag and
        // do it for them.
        // This could be optimized in various ways, not least of which
        // is not pulling every tag eagerly before scanning them.
        let tags = self
            .list_tags(owner, repo)
            .with_context(|| format!("couldn't retrieve tags for {owner}/{repo}@{commit}"))?;

        // Heuristic: there can be multiple tags for a commit, so we pick
        // the longest one. This isn't super sound, but it gets us from
        // `sha -> v1.2.3` instead of `sha -> v1`.
        Ok(tags
            .into_iter()
            .filter(|t| t.commit.sha == commit)
            .max_by_key(|t| t.name.len()))
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<Option<ComparisonStatus>> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/compare/{base}...{head}",
            api_base = self.api_base
        );

        let resp = self.http.get(url).send().await?;

        match resp.status() {
            StatusCode::OK => {
                Ok::<_, reqwest::Error>(Some(resp.json::<Comparison>().await?.status))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(resp.error_for_status().unwrap_err()),
        }
        .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn gha_advisories(
        &self,
        owner: &str,
        repo: &str,
        version: &str,
    ) -> Result<Vec<Advisory>> {
        // TODO: Paginate this as well.
        let url = format!("{api_base}/advisories", api_base = self.api_base);

        self.http
            .get(url)
            .query(&[
                ("ecosystem", "actions"),
                ("affects", &format!("{owner}/{repo}@{version}")),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Fetch a single file from the given remote repository slug.
    ///
    /// Returns the file contents as a `String` if the file exists,
    /// or `None` if the request produces a 404.
    #[instrument(skip(self, slug, file))]
    #[tokio::main]
    pub(crate) async fn fetch_single_file(
        &self,
        slug: &RepoSlug,
        file: &str,
    ) -> Result<Option<String>> {
        self.fetch_single_file_async(slug, file).await
    }

    pub(crate) async fn fetch_single_file_async(
        &self,
        slug: &RepoSlug,
        file: &str,
    ) -> Result<Option<String>> {
        tracing::debug!("fetching {file} from {slug}");

        let url = format!(
            "{api_base}/repos/{owner}/{repo}/contents/{file}",
            api_base = self.api_base,
            owner = slug.owner,
            repo = slug.repo,
            file = file
        );

        let resp = self
            .http
            .get(&url)
            .header(ACCEPT, "application/vnd.github.raw+json")
            .pipe(|req| match slug.git_ref.as_ref() {
                Some(g) => req.query(&[("ref", g)]),
                None => req,
            })
            .send()
            .await?;

        match resp.status() {
            StatusCode::OK => {
                let contents = resp.text().await?;

                Ok(Some(contents))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(resp.error_for_status().unwrap_err().into()),
        }
    }

    /// Collect all workflows (and only workflows) defined in the given remote
    /// repository slug into the given input group.
    ///
    /// This is an optimized variant of `fetch_audit_inputs` for the workflow-only
    /// collection case.
    #[instrument(skip(self, options, group))]
    #[tokio::main]
    pub(crate) async fn fetch_workflows(
        &self,
        slug: &RepoSlug,
        options: &CollectionOptions,
        group: &mut InputGroup,
    ) -> Result<()> {
        let owner = &slug.owner;
        let repo = &slug.repo;
        let git_ref = &slug.git_ref;

        tracing::debug!("fetching workflows for {slug}");

        // It'd be nice if the GitHub contents API allowed us to retrieve
        // all file contents with a directory listing, but it doesn't.
        // Instead, we make `N+1` API calls: one to list the workflows
        // directory, and `N` for the constituent workflow files.
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/contents/.github/workflows",
            api_base = self.api_base
        );
        let resp: Vec<File> = self
            .http
            .get(&url)
            .pipe(|req| match git_ref {
                Some(g) => req.query(&[("ref", g)]),
                None => req,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        for file in resp
            .into_iter()
            .filter(|file| file.name.ends_with(".yml") || file.name.ends_with(".yaml"))
        {
            let Some(contents) = self.fetch_single_file_async(slug, &file.path).await? else {
                // This can only happen if we have some kind of TOCTOU
                // discrepancy with the listing call above, e.g. a file
                // was deleted on a branch immediately after we listed it.
                anyhow::bail!(
                    "couldn't fetch workflow file {file} from {slug}",
                    file = file.name
                );
            };

            let key = InputKey::remote(slug, file.path)?;
            group.register(InputKind::Workflow, contents, key, options.strict)?;
        }

        Ok(())
    }

    /// Fetch all auditable inputs (both workflows and actions)
    /// from the given remote repository slug.
    ///
    /// This is much slower than `fetch_workflows`, since it involves
    /// retrieving the entire repository archive and decompressing it.
    #[instrument(skip(self, options, group))]
    #[tokio::main]
    pub(crate) async fn fetch_audit_inputs(
        &self,
        slug: &RepoSlug,
        options: &CollectionOptions,
        group: &mut InputGroup,
    ) -> Result<()> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/tarball/{git_ref}",
            api_base = self.api_base,
            owner = slug.owner,
            repo = slug.repo,
            git_ref = slug.git_ref.as_deref().unwrap_or("HEAD")
        );
        tracing::debug!("fetching repo: {url}");

        // TODO: Could probably make this slightly faster by
        // streaming asynchronously into the decompression,
        // probably with the async-compression crate.
        let resp = self.http.get(&url).send().await?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "failed to fetch {url}: {status}",
                status = resp.status().red()
            ));
        }

        let contents = resp.bytes().await?;
        let tar = GzDecoder::new(contents.deref());

        let mut archive = Archive::new(tar);
        for entry in archive.entries()? {
            let mut entry = entry?;

            if !entry.header().entry_type().is_file() {
                continue;
            }

            // GitHub's tarballs contain entries that are prefixed with
            // `{owner}-{repo}-{ref}`, where `{ref}` has been concretized
            // into a short hash. We strip this out to ensure that our
            // paths look like normal paths.
            let entry_path = entry.path()?;
            let file_path: &Utf8Path = {
                let mut components = entry_path.components();
                components.next();
                components.as_path().try_into()?
            };

            if matches!(file_path.extension(), Some("yaml" | "yml"))
                && file_path
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".github/workflows"))
            {
                let key = InputKey::remote(slug, file_path.to_string())?;
                let mut contents = String::with_capacity(entry.size() as usize);
                entry.read_to_string(&mut contents)?;
                group.register(InputKind::Workflow, contents, key, options.strict)?;
            } else if matches!(file_path.file_name(), Some("action.yml" | "action.yaml")) {
                let key = InputKey::remote(slug, file_path.to_string())?;
                let mut contents = String::with_capacity(entry.size() as usize);
                entry.read_to_string(&mut contents)?;
                group.register(InputKind::Action, contents, key, options.strict)?;
            }
        }

        Ok(())
    }
}

/// A single branch, as returned by GitHub's branches endpoints.
///
/// This model is intentionally incomplete.
///
/// See <https://docs.github.com/en/rest/branches/branches?apiVersion=2022-11-28>.
#[derive(Deserialize, Clone)]
pub(crate) struct Branch {
    pub(crate) name: String,
    pub(crate) commit: Object,
}

/// A single tag, as returned by GitHub's tags endpoints.
///
/// This model is intentionally incomplete.
#[derive(Deserialize, Clone)]
pub(crate) struct Tag {
    pub(crate) name: String,
    pub(crate) commit: Object,
}

/// Represents a git object.
#[derive(Deserialize, Clone)]
pub(crate) struct Object {
    pub(crate) sha: String,
}

#[derive(Deserialize)]
pub(crate) struct GitRef {
    pub(crate) object: Object,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ComparisonStatus {
    Ahead,
    Behind,
    Diverged,
    Identical,
}

/// The result of comparing two commits via GitHub's API.
///
/// See <https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28>
#[derive(Deserialize)]
pub(crate) struct Comparison {
    pub(crate) status: ComparisonStatus,
}

/// Represents a GHSA advisory.
#[derive(Deserialize)]
pub(crate) struct Advisory {
    pub(crate) ghsa_id: String,
    pub(crate) severity: String,
    pub(crate) vulnerabilities: Vec<Vulnerability>,
}

/// Represents a vulnerability within a GHSA advisory.
#[derive(Deserialize)]
pub(crate) struct Vulnerability {
    pub(crate) first_patched_version: Option<String>,
}

/// Represents a file listing from GitHub's contents API.
#[derive(Deserialize)]
pub(crate) struct File {
    name: String,
    path: String,
}

#[cfg(test)]
mod tests {
    use crate::github_api::{GitHubHost, GitHubToken};

    #[test]
    fn test_github_host() {
        for (host, expected) in [
            ("github.com", "https://api.github.com"),
            ("something.ghe.com", "https://api.something.ghe.com"),
            (
                "selfhosted.example.com",
                "https://selfhosted.example.com/api/v3",
            ),
        ] {
            assert_eq!(GitHubHost::new(host).unwrap().to_api_url(), expected);
        }
    }

    #[test]
    fn test_github_token() {
        for (token, expected) in [
            ("gha_testtest\n", "gha_testtest"),
            ("  gha_testtest  ", "gha_testtest"),
            ("gho_testtest", "gho_testtest"),
            ("gho_test\ntest", "gho_test\ntest"),
        ] {
            assert_eq!(GitHubToken::new(token).unwrap().0, expected);
        }
    }

    #[test]
    fn test_github_token_err() {
        for token in ["", " ", "\r", "\n", "\t", "     "] {
            assert!(GitHubToken::new(token).is_err());
        }
    }
}
