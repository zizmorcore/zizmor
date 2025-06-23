use github_actions_models::common::{EnvValue, Uses};
use indexmap::IndexMap;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{Confidence, Finding, Severity},
    models::{StepBodyCommon, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
};

const USES_MANUAL_CREDENTIAL: &str =
    "uses a manually-configured credential instead of Trusted Publishing";

const KNOWN_PYTHON_TP_INDICES: &[&str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

pub(crate) struct UseTrustedPublishing;

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        } = &step.body()
        else {
            return Ok(findings);
        };

        let candidate = Self::finding()
            .severity(Severity::Informational)
            .confidence(Confidence::High)
            .add_location(
                step.location()
                    .primary()
                    .with_keys(&["uses".into()])
                    .annotated("this step"),
            );

        if uses.matches("pypa/gh-action-pypi-publish")
            && self.pypi_publish_uses_manual_credentials(with)
        {
            findings.push(
                candidate
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["with".into(), "password".into()])
                            .annotated(USES_MANUAL_CREDENTIAL),
                    )
                    .build(step)?,
            );
        } else if ((uses.matches("rubygems/release-gem"))
            && self.release_gem_uses_manual_credentials(with))
            || (uses.matches("rubygems/configure-rubygems-credential")
                && self.rubygems_credential_uses_manual_credentials(with))
        {
            findings.push(
                candidate
                    .add_location(step.location().primary().annotated(USES_MANUAL_CREDENTIAL))
                    .build(step)?,
            );
        }

        Ok(findings)
    }

    fn pypi_publish_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
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

    fn release_gem_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
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
        with: &IndexMap<String, EnvValue>,
    ) -> bool {
        with.contains_key("api-token")
    }
}

impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }
}
