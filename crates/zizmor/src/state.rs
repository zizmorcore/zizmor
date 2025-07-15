//! zizmor's runtime state, including application-level caching.

use std::path::PathBuf;

use etcetera::{AppStrategy, AppStrategyArgs, choose_app_strategy};

use crate::{
    App,
    config::Config,
    github_api::{Client, GitHubHost},
};

#[derive(Clone)]
pub(crate) struct AuditState<'a> {
    pub(crate) config: &'a Config,
    pub(crate) no_online_audits: bool,
    /// A cache-configured GitHub API client, if a GitHub API token is given.
    pub(crate) gh_client: Option<Client>,
    pub(crate) gh_hostname: GitHubHost,
}

impl<'a> AuditState<'a> {
    pub(crate) fn new(app: &App, config: &'a Config) -> anyhow::Result<Self> {
        let cache_dir = match &app.cache_dir {
            Some(cache_dir) => PathBuf::from(cache_dir),
            None => choose_app_strategy(AppStrategyArgs {
                top_level_domain: "io.github".into(),
                author: "woodruffw".into(),
                app_name: "zizmor".into(),
            })
            // NOTE: no point in failing gracefully here.
            .expect("failed to determine default cache directory")
            .cache_dir(),
        };

        tracing::debug!("using cache directory: {cache_dir:?}");

        let gh_client = app
            .gh_token
            .as_ref()
            .map(|token| Client::new(&app.gh_hostname, token, &cache_dir))
            .transpose()?;

        Ok(Self {
            config,
            no_online_audits: app.no_online_audits,
            gh_client,
            gh_hostname: app.gh_hostname.clone(),
        })
    }
}
