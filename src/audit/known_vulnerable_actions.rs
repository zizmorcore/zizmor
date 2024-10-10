//! Detects publicly disclosed action vulnerabilities.
//!
//! This audit uses GitHub's security advisories API as a source of
//! ground truth.
//!
//! See: <https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28>

use std::str::FromStr;

use anyhow::{anyhow, Result};
use github_actions_models::workflow::{job::StepBody, Job};

use crate::{
    finding::{Confidence, Severity},
    github_api, AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct KnownVulnerableActions<'a> {
    pub(crate) config: AuditConfig<'a>,
    client: github_api::Client,
}

impl<'a> KnownVulnerableActions<'a> {
    fn action_known_vulnerabilities(&self, uses: &str) -> Result<Vec<(Severity, String)>> {
        // There's no point in asking OSV about repo-relative actions.
        if uses.starts_with("./") {
            return Ok(vec![]);
        }

        // There's no point in querying for an action without a version.
        let Some((action, version)) = uses.split_once("@") else {
            return Ok(vec![]);
        };

        let version = if version.starts_with('v') {
            &version[1..]
        } else {
            version
        };

        let vulns = self.client.gha_advisories(action, version)?;

        let mut results = vec![];

        // No vulns means we need to try a bit harder.
        if vulns.is_empty() {
            log::debug!("no vulnerabilities for {action}@{version}");
        } else {
            for vuln in vulns {
                let severity = match vuln.severity.as_str() {
                    "low" => Severity::Unknown,
                    "medium" => Severity::Medium,
                    "high" => Severity::High,
                    "critical" => Severity::High,
                    "unknown" | _ => Severity::Unknown,
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

        Ok(Self { config, client })
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

                for (severity, id) in self.action_known_vulnerabilities(uses)? {
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
