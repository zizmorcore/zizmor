//! Detects publicly disclosed action vulnerabilities.
//!
//! This audit uses GitHub's security advisories API as a source of
//! ground truth.
//!
//! See: <https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28>

use anyhow::{anyhow, Result};
use github_actions_models::workflow::{job::StepBody, Job};

use crate::{
    finding::{Confidence, Severity},
    github_api,
    models::Uses,
    AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct KnownVulnerableActions<'a> {
    pub(crate) _config: AuditConfig<'a>,
    client: github_api::Client,
}

impl<'a> KnownVulnerableActions<'a> {
    fn action_known_vulnerabilities(&self, uses: &Uses<'_>) -> Result<Vec<(Severity, String)>> {
        let version = match uses.git_ref {
            // Easy case: `uses:` is pinned to a non-sha ref, which we'll
            // treat as the version.
            // TODO: Handle edge case here where the ref is symbolic but
            // not version-y, e.g. `gh-action-pypi-publish@release/v1`
            Some(version) if !uses.ref_is_commit() => version.to_string(),
            // Annoying case: `uses:` is a sha-ref, so we need to find the
            // tag matching that ref. In theory the action's repo could do
            // something annoying like use branches for versions instead,
            // which we should also probably support.
            Some(commit_ref) => match self
                .client
                .tag_for_commit(uses.owner, uses.repo, commit_ref)?
            {
                Some(ref tag) => tag.name.clone(),
                // No corresponding tag means the user is maybe doing something
                // weird, like using a commit ref off of a branch that isn't
                // also tagged. Probably not good, but also not something
                // we can easily discover known vulns for.
                None => return Ok(vec![]),
            },
            // No version means the action runs the latest default branch
            // version. We could in theory query GHSA for this but it's
            // unlikely to be meaningful.
            // TODO: Maybe we need a separate (low-sev) audit for actions usage
            // on @master/@main/etc?
            None => return Ok(vec![]),
        };

        let vulns = self
            .client
            .gha_advisories(uses.owner, uses.repo, &version)?;

        let mut results = vec![];

        // No vulns means we need to try a bit harder.
        if vulns.is_empty() {
            log::debug!(
                "no vulnerabilities for {owner}/{repo}@{version:?}",
                owner = uses.owner,
                repo = uses.repo,
                version = uses.git_ref,
            );
        } else {
            for vuln in vulns {
                let severity = match vuln.severity.as_str() {
                    "low" => Severity::Unknown,
                    "medium" => Severity::Medium,
                    "high" => Severity::High,
                    "critical" => Severity::High,
                    _ => Severity::Unknown,
                };

                results.push((severity, vuln.ghsa_id));
            }
        }

        Ok(results)
    }
}

impl<'a> WorkflowAudit<'a> for KnownVulnerableActions<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "known-vulnerable-actions"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "action has a known vulnerability"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        if config.offline {
            return Err(anyhow!("offline audits only requested"));
        }

        let Some(gh_token) = config.gh_token else {
            return Err(anyhow!("can't audit without a GitHub API token"));
        };

        let client = github_api::Client::new(gh_token);

        Ok(Self {
            _config: config,
            client,
        })
    }

    fn audit<'w>(
        &mut self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(_) = *job else {
                continue;
            };

            for step in job.steps() {
                let StepBody::Uses { uses, .. } = &step.body else {
                    continue;
                };

                let Some(uses) = Uses::from_step(uses) else {
                    continue;
                };

                for (severity, id) in self.action_known_vulnerabilities(&uses)? {
                    findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(severity)
                            .add_location(step.location().with_keys(&["uses".into()]).annotated(id))
                            .build(workflow)?,
                    );
                }
            }
        }

        Ok(findings)
    }
}
