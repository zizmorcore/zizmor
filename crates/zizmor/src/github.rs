//! GitHub API client and related types.
//!
//! The [`Client`] type uses a mixture of GitHub's REST API and
//! direct Git access, depending on the operation being performed.

use std::{collections::HashSet, fmt::Display, io::Read, ops::Deref, str::FromStr, sync::Arc};

use camino::Utf8Path;
use flate2::read::GzDecoder;
use http_cache_reqwest::{
    CACacheManager, Cache, CacheManager, CacheMode, CacheOptions, HttpCache, HttpCacheOptions,
    MokaCache, MokaManager,
};
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, InvalidHeaderValue},
    retry,
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::Deserialize;
use tar::Archive;
use thiserror::Error;
use tracing::instrument;

use crate::{
    CollectionOptions,
    registry::input::{CollectionError, InputGroup, InputKey, InputKind, RepoSlug},
    utils::{PipeSelf, ZIZMOR_AGENT},
};

mod lineref;
mod pktline;

/// Represents different types of GitHub hosts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GitHubHost {
    Enterprise(String),
    Standard(String),
}

impl GitHubHost {
    pub(crate) fn new(hostname: &str) -> anyhow::Result<Self, String> {
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

    fn to_api_host(&self) -> String {
        match self {
            Self::Enterprise(host) => host.clone(),
            Self::Standard(host) => format!("api.{host}"),
        }
    }

    fn to_api_url(&self) -> String {
        match self {
            Self::Enterprise(_) => format!("https://{host}/api/v3", host = self.to_api_host()),
            Self::Standard(_) => format!("https://{host}", host = self.to_api_host()),
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

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A sanitized GitHub access token.
#[derive(Clone)]
pub(crate) struct GitHubToken(String);

impl GitHubToken {
    pub(crate) fn new(token: &str) -> anyhow::Result<Self, String> {
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

/// Errors that can occur while using the GitHub API client.
#[derive(Debug, Error)]
pub(crate) enum ClientError {
    /// An error originating from the underlying HTTP client.
    #[error("request error while accessing GitHub API")]
    Request(#[from] reqwest::Error),
    /// An error originating from the HTTP client (and its middleware).
    #[error("request error while accessing GitHub API")]
    Middleware(#[from] reqwest_middleware::Error),
    /// We couldn't turn the user's token into a valid header value.
    #[error("invalid token header")]
    InvalidTokenHeader(#[from] InvalidHeaderValue),
    /// An error originating from encoding or decoding Git pkt-lines.
    #[error("error while processing Git pkt-lines")]
    PktLint(#[from] pktline::PktLineError),
    /// An error originating from listing refs through direct
    /// Git access.
    #[error("error while listing Git references")]
    ListRefs(#[from] lineref::LineRefError),
    /// We couldn't list branches because of an underlying error.
    #[error("couldn't list branches for {owner}/{repo}")]
    ListBranches {
        #[source]
        source: Box<ClientError>,
        owner: String,
        repo: String,
    },
    /// We couldn't list tags because of an underlying error.
    #[error("couldn't list tags for {owner}/{repo}")]
    ListTags {
        #[source]
        source: Box<ClientError>,
        owner: String,
        repo: String,
    },
    /// We couldn't fetch a single file because it disappeared
    /// between listing and fetching it.
    #[error("couldn't fetch file {file} from {slug}: is the branch/tag being modified?")]
    FileTOCTOU { file: String, slug: String },
    /// An accessed repository is missing or private.
    #[error("can't access {owner}/{repo}: missing or you have no access")]
    RepoMissingOrPrivate { owner: String, repo: String },
    /// Any of the errors above, wrapped from concurrent contexts.
    #[error(transparent)]
    Inner(#[from] Arc<ClientError>),
}

#[derive(Clone, Copy, Debug)]
enum CacheType {
    File,
    Memory,
}

#[derive(Clone, Copy, Debug)]
enum CacheResult {
    Miss,
    Hit,
}

struct CacheLoggingMiddleware;

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for CacheLoggingMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        tracing::debug!("Request URL: {}", req.url());

        let res = next.run(req, extensions).await?;

        let cache_type = extensions
            .get::<CacheType>()
            .expect("internal error: expected CacheType");
        let cache_result = extensions
            .get::<CacheResult>()
            .expect("internal error: expected CacheResult");
        tracing::debug!("{:?} cache was {:?}", cache_type, cache_result);

        Ok(res)
    }
}

struct ChainedCache<T: CacheManager>(Cache<T>, CacheType);

#[async_trait::async_trait]
impl<T: CacheManager> reqwest_middleware::Middleware for ChainedCache<T> {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        extensions.insert(self.1);

        let res = self.0.handle(req, extensions, next).await;

        if let Ok(ref resp) = res
            && let Some(cache) = resp.headers().get("x-cache")
        {
            let cache_result = match cache
                .to_str()
                .expect("invalid x-cache header (not a string)")
            {
                "HIT" => CacheResult::Hit,
                _ => CacheResult::Miss,
            };
            extensions.get_or_insert(cache_result);
        }

        res
    }
}

#[derive(Clone)]
struct RemoteHead {
    name: String,
    oid: String,
}

#[derive(Clone)]
pub(crate) struct Client {
    api_base: String,
    _host: GitHubHost,
    token: GitHubToken,
    base_client: ClientWithMiddleware,
    api_client: ClientWithMiddleware,
    ref_cache: MokaCache<String, Vec<RemoteHead>>,
}

impl Client {
    pub(crate) fn new(
        host: &GitHubHost,
        token: &GitHubToken,
        cache_dir: &Utf8Path,
    ) -> Result<Self, ClientError> {
        // Base HTTP client for non-API requests, e.g. direct Git access.
        // This client currently has no middleware.
        let base_client = reqwest::Client::builder()
            .user_agent(ZIZMOR_AGENT)
            .build()
            // TODO: Add retries here too?
            .expect("couldn't build base HTTP client");

        // GitHub REST API client.
        let mut api_client_headers = HeaderMap::new();
        api_client_headers.insert(AUTHORIZATION, token.to_header_value()?);
        api_client_headers.insert("X-GitHub-Api-Version", "2022-11-28".parse()?);
        api_client_headers.insert(ACCEPT, "application/vnd.github+json".parse()?);

        let api_client = Self::default_middleware(
            cache_dir,
            reqwest::Client::builder()
                .user_agent(ZIZMOR_AGENT)
                .default_headers(api_client_headers)
                .retry(
                    retry::for_host(host.to_api_host())
                        .max_retries_per_request(3)
                        // NOTE(ww): No budget at the moment,
                        // since we cap at 3 retries anyway.
                        .no_budget()
                        .classify_fn(|req_rep| match req_rep.status() {
                            // NOTE(ww): At the moment we send only GETs,
                            // so we don't need to think about retry semantics
                            // on non-idempotent methods.

                            // NOTE(ww): In the context of the retry classifier,
                            // "success" means "don't retry".
                            Some(status) => {
                                if status.is_client_error() || status.is_server_error() {
                                    req_rep.retryable()
                                } else {
                                    req_rep.success()
                                }
                            }
                            None => req_rep.success(),
                        }),
                )
                .build()
                .expect("couldn't build GitHub client"),
        );

        Ok(Self {
            api_base: host.to_api_url(),
            _host: host.clone(),
            token: token.clone(),
            base_client: base_client.into(),
            api_client,
            ref_cache: MokaCache::new(100),
        })
    }

    fn default_middleware(cache_dir: &Utf8Path, client: reqwest::Client) -> ClientWithMiddleware {
        let http_cache_options = HttpCacheOptions {
            cache_options: Some(CacheOptions {
                // GitHub API requests made with an API token seem to
                // always have `Cache-Control: private`, so we need to
                // explicitly tell http-cache that our cache is not shared
                // in order for things to cache correctly.
                shared: false,
                ..Default::default()
            }),
            ..Default::default()
        };

        ClientBuilder::new(client)
            .with(CacheLoggingMiddleware)
            .with(ChainedCache(
                Cache(HttpCache {
                    mode: CacheMode::Default,
                    manager: CACacheManager {
                        path: cache_dir.into(),
                        remove_opts: Default::default(),
                    },
                    options: http_cache_options.clone(),
                }),
                CacheType::File,
            ))
            .with(ChainedCache(
                Cache(HttpCache {
                    mode: CacheMode::ForceCache,
                    manager: MokaManager::new(MokaCache::new(1000)),
                    options: http_cache_options,
                }),
                CacheType::Memory,
            ))
            .build()
    }

    async fn list_refs(&self, owner: &str, repo: &str) -> Result<Vec<RemoteHead>, ClientError> {
        let url = format!("https://github.com/{owner}/{repo}.git/git-upload-pack");

        let entry = self
            .ref_cache
            .entry(url.clone())
            .or_try_insert_with(async {
                // Build our `ls-refs` request.
                // This effectively mimics what `git ls-remote` does under the hood.
                // We additionally use the ref-prefix arguments to (hopefully) limit
                // the server's response to only branches and tags.
                let mut req = vec![];
                pktline::Packet::data("command=ls-refs\n".as_bytes())?.encode(&mut req)?;
                pktline::Packet::data(format!("agent={}\n", ZIZMOR_AGENT).as_bytes())?
                    .encode(&mut req)?;
                pktline::Packet::Delim.encode(&mut req)?;
                pktline::Packet::data("peel\n".as_bytes())?.encode(&mut req)?;
                pktline::Packet::data("ref-prefix refs/heads/\n".as_bytes())?.encode(&mut req)?;
                pktline::Packet::data("ref-prefix refs/tags/\n".as_bytes())?.encode(&mut req)?;
                pktline::Packet::Flush.encode(&mut req)?;

                let resp = self
                    .base_client
                    .post(&url)
                    .header("Git-Protocol", "version=2")
                    .body(req)
                    .basic_auth("x-access-token", Some(&self.token.0))
                    .send()
                    .await?;

                let resp = match resp.error_for_status() {
                    Ok(resp) => Ok(resp),
                    // NOTE: Versions of zizmor prior to 1.16.0 would silently
                    // skip private or missing repositories, as branch/tag lookups
                    // were done as a binary present/absent check. This caused
                    // false negatives.
                    Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
                        Err(ClientError::RepoMissingOrPrivate {
                            owner: owner.to_string(),
                            repo: repo.to_string(),
                        })
                    }
                    Err(e) => Err(e.into()),
                }?;

                let mut remote_refs = vec![];
                let content = resp.bytes().await?;

                for line_ref in lineref::LineRefIterator::new(content.as_ref()) {
                    let line_ref = line_ref?;

                    // We prefer the peeled object ID if present, since that
                    // gives us the commit ID for annotated tags.
                    remote_refs.push(RemoteHead {
                        name: line_ref.ref_name.to_string(),
                        oid: line_ref
                            .peeled_obj_id
                            .unwrap_or(line_ref.obj_id)
                            .to_string(),
                    });
                }

                Ok::<Vec<_>, ClientError>(remote_refs)
            })
            .await;

        match entry {
            Ok(heads) => Ok(heads.into_value()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_branches_internal(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<Branch>, ClientError> {
        self.list_refs(owner, repo)
            .await
            .map(|v| {
                v.iter()
                    .filter_map(|r| {
                        r.name.strip_prefix("refs/heads/").map(|name| Branch {
                            name: name.to_string(),
                            commit: Commit {
                                sha: r.oid.to_string(),
                            },
                        })
                    })
                    .collect()
            })
            .map_err(|e| ClientError::ListBranches {
                source: e.into(),
                owner: owner.to_string(),
                repo: repo.to_string(),
            })
    }

    #[instrument(skip(self))]
    pub(crate) async fn list_branches(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<Branch>, ClientError> {
        self.list_branches_internal(owner, repo).await
    }

    async fn list_tags_internal(&self, owner: &str, repo: &str) -> Result<Vec<Tag>, ClientError> {
        self.list_refs(owner, repo)
            .await
            .map(|v| {
                let mut tags: Vec<_> = v
                    .iter()
                    .filter_map(|r| {
                        r.name.strip_prefix("refs/tags/").map(|name| Tag {
                            name: name.to_string(),
                            commit: Commit {
                                sha: r.oid.to_string(),
                            },
                        })
                    })
                    .collect();

                // Tags may point to a commit or an annotation.
                // If we have an annotation, a tag suffixed with `^{}` holds the commit.
                // See: https://www.kernel.org/pub/software/scm/git/docs/gitrevisions.html
                let annotated_tags: HashSet<_> = tags
                    .iter()
                    .filter_map(|tag| tag.name.strip_suffix("^{}").map(|n| n.to_string()))
                    .collect();
                tags.retain_mut(|tag| {
                    if let Some(stripped_name) = tag.name.strip_suffix("^{}") {
                        tag.name = stripped_name.to_string();
                        true
                    } else {
                        !annotated_tags.contains(&tag.name)
                    }
                });

                tags
            })
            .map_err(|e| ClientError::ListTags {
                source: e.into(),
                owner: owner.to_string(),
                repo: repo.to_string(),
            })
    }

    #[instrument(skip(self))]
    pub(crate) async fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<Tag>, ClientError> {
        self.list_tags_internal(owner, repo).await
    }

    #[instrument(skip(self))]
    pub(crate) async fn has_branch(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<bool, ClientError> {
        Ok(self
            .list_branches_internal(owner, repo)
            .await?
            .iter()
            .any(|branch_ref| branch_ref.name == branch))
    }

    #[instrument(skip(self))]
    pub(crate) async fn has_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<bool, ClientError> {
        Ok(self
            .list_tags_internal(owner, repo)
            .await?
            .iter()
            .any(|tag_ref| tag_ref.name == tag))
    }

    #[instrument(skip(self))]
    pub(crate) async fn commit_for_ref(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<Option<String>, ClientError> {
        let branches = self.list_branches_internal(owner, repo).await?;
        let tags = self.list_tags_internal(owner, repo).await?;

        tracing::debug!("Finding commit for reference {git_ref}");

        // GitHub Actions resolves branches before tags.
        for branch in branches {
            if branch.name == git_ref {
                return Ok(Some(branch.commit.sha));
            }
        }

        for tag in tags {
            if tag.name == git_ref {
                return Ok(Some(tag.commit.sha));
            }
        }

        Ok(None)
    }

    #[instrument(skip(self))]
    pub(crate) async fn longest_tag_for_commit(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Option<Tag>, ClientError> {
        // Annoying: GitHub doesn't provide a rev-parse or similar API to
        // perform the commit -> tag lookup, so we download every tag and
        // do it for them.
        // This could be optimized in various ways, not least of which
        // is not pulling every tag eagerly before scanning them.
        let tags = self.list_tags(owner, repo).await?;

        // Heuristic: there can be multiple tags for a commit, so we pick
        // the longest one. This isn't super sound, but it gets us from
        // `sha -> v1.2.3` instead of `sha -> v1`.
        Ok(tags
            .into_iter()
            .filter(|t| t.commit.sha == commit)
            .max_by_key(|t| t.name.len()))
    }

    #[instrument(skip(self))]
    pub(crate) async fn branch_commits(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<BranchCommits, ClientError> {
        // NOTE(ww): This API is undocumented.
        // See: https://github.com/orgs/community/discussions/78161
        let url = format!("https://github.com/{owner}/{repo}/branch_commits/{commit}");

        // We ask GitHub for JSON, because it sends HTML by default for this endpoint.
        self.base_client
            .get(&url)
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    pub(crate) async fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<Option<ComparisonStatus>, ClientError> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/compare/{base}...{head}",
            api_base = self.api_base
        );

        let resp = self.api_client.get(url).send().await?;

        match resp.error_for_status() {
            Ok(resp) => {
                let comparison: Comparison = resp.json().await?;
                Ok(Some(comparison.status))
            }
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument(skip(self))]
    pub(crate) async fn gha_advisories(
        &self,
        owner: &str,
        repo: &str,
        version: &str,
    ) -> Result<Vec<Advisory>, ClientError> {
        // TODO: Paginate this as well.
        let url = format!("{api_base}/advisories", api_base = self.api_base);

        self.api_client
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
    pub(crate) async fn fetch_single_file(
        &self,
        slug: &RepoSlug,
        file: &str,
    ) -> Result<Option<String>, ClientError> {
        self.fetch_single_file_async(slug, file).await
    }

    async fn fetch_single_file_async(
        &self,
        slug: &RepoSlug,
        file: &str,
    ) -> Result<Option<String>, ClientError> {
        tracing::debug!("fetching {file} from {slug}");

        let url = format!(
            "{api_base}/repos/{owner}/{repo}/contents/{file}",
            api_base = self.api_base,
            owner = slug.owner,
            repo = slug.repo,
            file = file
        );

        let resp = self
            .api_client
            .get(&url)
            .header(ACCEPT, "application/vnd.github.raw+json")
            .pipe(|req| match slug.git_ref.as_ref() {
                Some(g) => req.query(&[("ref", g)]),
                None => req,
            })
            .send()
            .await?;

        match resp.error_for_status() {
            Ok(resp) => {
                let contents = resp.text().await?;

                Ok(Some(contents))
            }
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Collect all workflows (and only workflows) defined in the given remote
    /// repository slug into the given input group.
    ///
    /// This is an optimized variant of `fetch_audit_inputs` for the workflow-only
    /// collection case.
    #[instrument(skip(self, options, group))]
    pub(crate) async fn fetch_workflows(
        &self,
        slug: &RepoSlug,
        options: &CollectionOptions,
        group: &mut InputGroup,
    ) -> Result<(), CollectionError> {
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
            .api_client
            .get(&url)
            .pipe(|req| match git_ref {
                Some(g) => req.query(&[("ref", g)]),
                None => req,
            })
            .send()
            .await
            .map_err(ClientError::from)?
            .error_for_status()
            .map_err(|err| match err {
                // TODO: Disambiguate a 404 from missing repo vs missing workflows dir.
                e if e.status() == Some(StatusCode::NOT_FOUND) => {
                    CollectionError::RemoteWithoutWorkflows(ClientError::from(e), slug.to_string())
                }
                e => ClientError::from(e).into(),
            })?
            .json()
            .await
            .map_err(ClientError::from)?;

        for file in resp
            .into_iter()
            .filter(|file| file.name.ends_with(".yml") || file.name.ends_with(".yaml"))
        {
            let Some(contents) = self.fetch_single_file_async(slug, &file.path).await? else {
                // This can only happen if we have some kind of TOCTOU
                // discrepancy with the listing call above, e.g. a file
                // was deleted on a branch immediately after we listed it.
                return Err(ClientError::FileTOCTOU {
                    file: file.path,
                    slug: slug.to_string(),
                }
                .into());
            };

            let key = InputKey::remote(slug, file.path);
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
    pub(crate) async fn fetch_audit_inputs(
        &self,
        slug: &RepoSlug,
        options: &CollectionOptions,
        group: &mut InputGroup,
    ) -> Result<(), CollectionError> {
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
        let resp = self
            .api_client
            .get(&url)
            .send()
            .await
            .map_err(ClientError::from)?
            .error_for_status()
            .map_err(ClientError::from)?;

        let contents = resp.bytes().await.map_err(ClientError::from)?;
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
                components
                    .as_path()
                    .try_into()
                    .map_err(|e| CollectionError::InvalidPath(e, entry_path.clone().into_owned()))?
            };

            if matches!(file_path.extension(), Some("yaml" | "yml"))
                && file_path
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".github/workflows"))
            {
                let key = InputKey::remote(slug, file_path.to_string());
                let mut contents = String::with_capacity(entry.size() as usize);
                entry.read_to_string(&mut contents)?;
                group.register(InputKind::Workflow, contents, key, options.strict)?;
            } else if matches!(file_path.file_name(), Some("action.yml" | "action.yaml")) {
                let key = InputKey::remote(slug, file_path.to_string());
                let mut contents = String::with_capacity(entry.size() as usize);
                entry.read_to_string(&mut contents)?;
                group.register(InputKind::Action, contents, key, options.strict)?;
            } else if matches!(
                file_path.file_name(),
                Some("dependabot.yml" | "dependabot.yaml")
            ) {
                let key = InputKey::remote(slug, file_path.to_string());
                let mut contents = String::with_capacity(entry.size() as usize);
                entry.read_to_string(&mut contents)?;
                group.register(InputKind::Dependabot, contents, key, options.strict)?;
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
#[derive(Clone)]
pub(crate) struct Branch {
    pub(crate) name: String,
    pub(crate) commit: Commit,
}

/// A single tag, as returned by GitHub's tags endpoints.
///
/// This model is intentionally incomplete.
#[derive(Clone)]
pub(crate) struct Tag {
    pub(crate) name: String,
    pub(crate) commit: Commit,
}

/// A single commit, as returned by GitHub's commits endpoints.
///
/// This model is intentionally incomplete.
#[derive(Clone)]
pub(crate) struct Commit {
    pub(crate) sha: String,
}

/// The response structure from GitHub's undocumented `branch_commits` API.
///
/// This model is intentionally incomplete.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub(crate) struct BranchCommits {
    branches: Vec<serde_json::Value>,
    tags: Vec<String>,
}

impl BranchCommits {
    pub(crate) fn is_empty(&self) -> bool {
        self.branches.is_empty() && self.tags.is_empty()
    }
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
    use crate::github::{GitHubHost, GitHubToken};

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
