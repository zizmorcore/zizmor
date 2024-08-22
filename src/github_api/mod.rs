//! A very minimal GitHub API client.
//!
//! Build on synchronous reqwest to avoid octocrab's need to taint
//! the whole codebase with async.

use anyhow::{anyhow, Result};
use reqwest::{
    blocking,
    header::{HeaderMap, ACCEPT, AUTHORIZATION, USER_AGENT},
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize};

pub(crate) struct Client {
    api_base: &'static str,
    http: blocking::Client,
}

impl Client {
    pub(crate) fn new(token: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "zizmor".parse().unwrap());
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .expect("couldn't build authorization header for GitHub client?"),
        );
        headers.insert("X-GitHub-Api-Version", "2022-11-28".parse().unwrap());
        headers.insert(ACCEPT, "application/vnd.github+json".parse().unwrap());

        Self {
            api_base: "https://api.github.com",
            http: blocking::Client::builder()
                .default_headers(headers)
                .build()
                .expect("couldn't build GitHub client?"),
        }
    }

    fn paginate_into<T: DeserializeOwned>(&self, endpoint: &str, dest: &mut Vec<T>) -> Result<()> {
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
                .send()?
                .error_for_status()?;

            let page = resp.json::<Vec<T>>()?;
            if page.is_empty() {
                break;
            }

            dest.extend(page.into_iter());
            pageno += 1;
        }

        Ok(())
    }

    pub(crate) fn list_branches(&self, owner: &str, repo: &str) -> Result<Vec<Branch>> {
        let mut tags = vec![];
        self.paginate_into(&format!("repos/{owner}/{repo}/branches"), &mut tags)?;
        Ok(tags)
    }

    pub(crate) fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<Tag>> {
        let mut tags = vec![];
        // This API is seemingly undocumented?
        self.paginate_into(&format!("repos/{owner}/{repo}/tags"), &mut tags)?;
        Ok(tags)
    }

    pub(crate) fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<Option<Comparison>> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/compare/{base}..{head}",
            api_base = self.api_base
        );

        let resp = self.http.get(&url).send()?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json()?)),
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(anyhow!(
                "error from GitHub API while comparing commits: {s}"
            )),
        }
    }
}

/// A single branch, as returned by GitHub's branches endpoints.
///
/// This model is intentionally incomplete.
///
/// See <https://docs.github.com/en/rest/branches/branches?apiVersion=2022-11-28>.
#[derive(Deserialize)]
pub(crate) struct Branch {
    pub(crate) name: String,
}

/// A single tag, as returned by GitHub's tags endpoints.
///
/// This model is intentionally incomplete.
#[derive(Deserialize)]
pub(crate) struct Tag {
    pub(crate) name: String,
}

#[derive(Deserialize)]
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
