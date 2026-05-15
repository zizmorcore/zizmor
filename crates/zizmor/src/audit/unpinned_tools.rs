use std::sync::LazyLock;

use github_actions_models::common::{EnvValue, Uses, expr::LoE};
use subfeature::Subfeature;

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::github::Client;
use crate::models::StepBodyCommon;
use crate::models::uses::RepositoryUsesExt;
use crate::models::version::Version;
use crate::models::{StepCommon, action::CompositeStep, workflow::Step};
use crate::state::AuditState;
use crate::utils::ExtractedExpr;

use super::AuditLoadError;

/// List of actions that are known to install unpinned external tools, along with an optional
/// upper bound after which the action started pinning versions.
static KNOWN_UNPINNED_TOOLS_ACTIONS: LazyLock<Vec<(&str, Option<Version>)>> = LazyLock::new(|| {
    [
        (
            "aquasecurity/trivy-action",
            Some(Version::parse("v0.36").unwrap()),
        ),
        ("1password/load-secrets-action", None),
    ]
    .into()
});

pub(crate) struct UnpinnedTools {
    client: Option<Client>,
}

audit_meta!(
    UnpinnedTools,
    "unpinned-tools",
    "action installs an unpinned external tool"
);

impl UnpinnedTools {
    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with: LoE::Literal(with),
        } = step.body()
        else {
            return Ok(findings);
        };

        let Some((_, max_action_version)) = KNOWN_UNPINNED_TOOLS_ACTIONS
            .iter()
            .find(|action| uses.matches(action.0))
        else {
            return Ok(findings);
        };

        let (confidence, persona) = if let Some(max_action_version) = max_action_version {
            // We need to check whether we're using a version of the action that
            // still exhibits unpinned behavior.
            let uses_version = if !uses.ref_is_commit() {
                Some(uses.git_ref().to_string())
            } else {
                match self.client {
                    Some(ref client) => {
                        let tag = client
                            .longest_tag_for_commit(uses.owner(), uses.repo(), uses.git_ref())
                            .await
                            .map_err(Self::err)?;

                        match tag {
                            Some(tag) => Some(tag.name),
                            None => None,
                        }
                    }
                    None => None,
                }
            };

            if let Some(uses_version) = uses_version
                && let Ok(ref uses_version) = Version::parse(&uses_version)
            {
                if uses_version < max_action_version {
                    (Confidence::High, Persona::Regular)
                } else {
                    return Ok(findings);
                }
            } else {
                (Confidence::Low, Persona::Pedantic)
            }
        } else {
            (Confidence::High, Persona::Regular)
        };

        let finding = match with.get("version") {
            None => Some(
                Self::finding()
                    .confidence(confidence)
                    .persona(persona)
                    .severity(Severity::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("action implicitly uses an unpinned latest version"),
                    ),
            ),
            Some(EnvValue::String(v)) if v == "latest" => Some(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("this action"),
                    )
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["with".into(), "version".into()])
                            .annotated("specifies `version: latest` which is unpinned"),
                    ),
            ),
            Some(EnvValue::String(v)) if ExtractedExpr::from_fenced(v).is_some() => Some(
                Self::finding()
                    .confidence(Confidence::Low)
                    .severity(Severity::Medium)
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("this action"),
                    )
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["with".into(), "version".into()])
                            .annotated("specifies `version` dynamically, which may be unpinned"),
                    ),
            ),
            Some(_) => None,
        };

        if let Some(finding) = finding {
            findings.push(finding.build(step)?);
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedTools {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let client = if state.no_online_audits {
            None
        } else {
            state.gh_client.clone()
        };

        Ok(Self { client })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step).await
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step).await
    }
}
