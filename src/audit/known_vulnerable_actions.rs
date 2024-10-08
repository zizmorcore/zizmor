//! Detects publicly disclosed action vulnerabilities.
//!
//! This audit uses [OSV]'s vulnerability database as a source of ground truth.
//! Actions are audited based on their pinned version or commit ref. When an
//! action is pinned by commit, the audit will make an effort to determine
//! the oldest version it belongs to and use that version for the OSV lookup.
//!
//! [OSV]: https://osv.dev/

use std::str::FromStr;

use anyhow::{anyhow, Result};
use github_actions_models::workflow::{job::StepBody, Job};

use crate::{
    finding::{Confidence, Severity},
    github_api,
    osv::Client as OsvClient,
    AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct KnownVulnerableActions<'a> {
    pub(crate) config: AuditConfig<'a>,
    github: Option<github_api::Client>,
    osv: OsvClient,
}

impl<'a> KnownVulnerableActions<'a> {
    /// Convert one or more OSV severity schemata (in CVSS format) into
    /// a zizmor-level severity.
    fn cvss_sevs_to_severity(&self, sevs: &[osv::schema::Severity]) -> Severity {
        let Some(sev) = sevs
            .iter()
            .find(|s| matches!(s.severity_type, osv::schema::SeverityType::CVSSv3))
        else {
            // The cvss crate doesn't support v2 or v4 CVSS scores yet.
            // See: https://github.com/rustsec/rustsec/issues/1087
            return Severity::Unknown;
        };

        let Ok(cvss) = cvss::v3::Base::from_str(&sev.score) else {
            return Severity::Unknown;
        };

        match cvss.severity() {
            cvss::Severity::None => Severity::Informational,
            cvss::Severity::Low => Severity::Low,
            cvss::Severity::Medium => Severity::Medium,
            cvss::Severity::High => Severity::High,
            cvss::Severity::Critical => Severity::High,
        }
    }

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

        let vulns = self.osv.query_gha(action, version)?;

        let mut results = vec![];

        // No vulns means we need to try a bit harder.
        if vulns.is_empty() {
            log::debug!("no vulnerabilities for {action}@{version}");
        } else {
            for vuln in vulns {
                let severity = match &vuln.severity {
                    Some(sevs) => self.cvss_sevs_to_severity(sevs),
                    None => Severity::Unknown,
                };

                results.push((severity, vuln.id));
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

        let github = config.gh_token.map(|token| github_api::Client::new(token));

        Ok(Self {
            config,
            github,
            osv: OsvClient::new(),
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
