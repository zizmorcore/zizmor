use std::{collections::HashSet, sync::LazyLock};

use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Severity, location::Locatable as _},
    models::pre_commit,
    state::AuditState,
};

static INSECURE_SCHEMES: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "http",
        // Refers to `git://`, i.e. git's legacy plaintext transport.
        // GitHub and other major hosts don't support this protocol anymore,
        // but pre-commit supports arbitrary Git URLs and thus we check it.
        "git",
    ]
    .into_iter()
    .collect()
});

pub(crate) struct InsecureURLScheme;

audit_meta!(
    InsecureURLScheme,
    "insecure-url-scheme",
    "use of an insecure scheme within a URL"
);

#[async_trait::async_trait]
impl Audit for InsecureURLScheme {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_pre_commit_config_repo<'doc>(
        &self,
        repo: &pre_commit::Repo<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // `meta` and `local` "repos" don't have a useful `repo:` URL field.
        let Some(url) = repo.repo() else {
            return Ok(findings);
        };

        let Ok(parsed) = url::Url::parse(url) else {
            // TODO: Is this warning too aggressive? Maybe it's common to put
            // file paths (without `file://`) in `repo:`?
            tracing::warn!("couldn't parse URL in pre-commit `repo:` clause: {url:?}");
            return Ok(findings);
        };

        if !INSECURE_SCHEMES.contains(parsed.scheme()) {
            return Ok(findings);
        }

        // TODO: Consider doing some host checks here as well, e.g. we can consider
        // insecure protocols trustworhy if the origin is itself presumed to be secure,
        // like `localhost` or a local IP range.

        findings.push(
            Self::finding()
                .confidence(Confidence::High)
                .severity(Severity::High)
                .add_location(
                    repo.location()
                        .primary()
                        .with_keys(["repo".into()])
                        .annotated(format!(
                            "repository URL uses an insecure scheme: {scheme:?}",
                            scheme = parsed.scheme()
                        ))
                        .subfeature(Subfeature::new(0, url)),
                )
                .build(repo)?,
        );

        Ok(findings)
    }
}
