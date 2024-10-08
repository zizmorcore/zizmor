//! A bare-bones OSV client, using the schema from the `osv` crate.

use anyhow::Result;
use reqwest::{
    blocking,
    header::{HeaderMap, USER_AGENT},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Package<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

impl<'a> Package<'a> {
    fn from_gha(action: &'a str) -> Self {
        Self {
            name: &action,
            ecosystem: "GitHub Actions",
        }
    }
}

#[derive(Serialize)]
struct Query<'a> {
    package: Package<'a>,
    version: &'a str,
}

impl<'a> Query<'a> {
    fn from_gha(action: &'a str, version: &'a str) -> Self {
        Self {
            package: Package::from_gha(action),
            version,
        }
    }
}

#[derive(Deserialize, Debug)]
struct Response {
    vulns: Vec<osv::schema::Vulnerability>,
}

pub(crate) struct Client {
    http: blocking::Client,
}

impl Client {
    pub(crate) fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "zizmor".parse().unwrap());

        Self {
            http: blocking::Client::builder()
                .default_headers(headers)
                .build()
                .expect("couldn't build OSV client?"),
        }
    }

    pub(crate) fn query_gha(
        &self,
        action: &str,
        version: &str,
    ) -> Result<Vec<osv::schema::Vulnerability>> {
        log::debug!("querying OSV for {action}@{version} vulnerabilities");

        let query = Query::from_gha(action, version);

        // TODO(ww): Pagination. For the time being, we churlishly assume
        // that no GitHub Action + version combination has >1000
        // vulnerabilities.
        let resp = self
            .http
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()?
            .error_for_status()?
            .json::<Response>()?;

        Ok(resp.vulns)
    }
}
