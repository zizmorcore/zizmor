use std::collections::HashMap;

use github_actions_models::{
    common::EnvValue,
    workflow::{job::StepBody, Job},
};

use crate::{
    finding::{Confidence, Determinations, Finding, Severity},
    models::AuditConfig,
};

use super::WorkflowAudit;

const KNOWN_PYTHON_TP_INDICES: &'static [&'static str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

pub(crate) struct UseTrustedPublishing<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> UseTrustedPublishing<'a> {
    fn pypi_publish_uses_manual_credentials(&self, with: &HashMap<String, EnvValue>) -> bool {
        // `password` implies the step isn't using Trusted Publishing,
        // but we also need to check `repository-url` to prevent false-positives
        // on third-party indices.
        let has_manual_credential = with.contains_key("password");

        match with
            .get("repository-url")
            .or_else(|| with.get("repository_url"))
        {
            Some(repo_url) => {
                has_manual_credential
                    && KNOWN_PYTHON_TP_INDICES.contains(&repo_url.to_string().as_str())
            }
            None => has_manual_credential,
        }
    }

    fn release_gem_uses_manual_credentials(&self, with: &HashMap<String, EnvValue>) -> bool {
        match with.get("setup-trusted-publisher") {
            Some(v) if v.to_string() == "true" => false,
            // Anything besides `true` means to *not* use trusted publishing.
            Some(_) => true,
            // Not set means the default, which is trusted publishing.
            None => false,
        }
    }

    fn rubygems_credential_uses_manual_credentials(
        &self,
        with: &HashMap<String, EnvValue>,
    ) -> bool {
        with.contains_key("api-token")
    }
}

impl<'a> WorkflowAudit<'a> for UseTrustedPublishing<'a> {
    fn ident() -> &'static str {
        "use-trusted-publishing"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self> {
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        log::debug!("audit: {} evaluating {}", Self::ident(), &workflow.filename);

        let mut findings = vec![];

        for job in workflow.jobs() {
            if !matches!(job.inner, Job::NormalJob(_)) {
                continue;
            }

            for step in job.steps() {
                let StepBody::Uses { uses, with } = &step.inner.body else {
                    continue;
                };

                if uses.starts_with("pypa/gh-action-pypi-publish") {
                    if self.pypi_publish_uses_manual_credentials(&with) {
                        findings.push(Finding {
                            ident: UseTrustedPublishing::ident(),
                            determinations: Determinations {
                                severity: Severity::Informational,
                                confidence: Confidence::High,
                            },
                            locations: vec![step.location()],
                        })
                    }
                } else if uses.starts_with("rubygems/release-gem") {
                    if self.release_gem_uses_manual_credentials(&with) {
                        findings.push(Finding {
                            ident: UseTrustedPublishing::ident(),
                            determinations: Determinations {
                                confidence: Confidence::High,
                                severity: Severity::Informational,
                            },
                            locations: vec![step.location()],
                        })
                    }
                } else if uses.starts_with("rubygems/configure-rubygems-credential") {
                    if self.rubygems_credential_uses_manual_credentials(&with) {
                        findings.push(Finding {
                            ident: UseTrustedPublishing::ident(),
                            determinations: Determinations {
                                confidence: Confidence::High,
                                severity: Severity::Informational,
                            },
                            locations: vec![step.location()],
                        })
                    }
                }
            }
        }

        log::debug!("audit: {} completed {}", Self::ident(), &workflow.filename);
        Ok(findings)
    }
}
