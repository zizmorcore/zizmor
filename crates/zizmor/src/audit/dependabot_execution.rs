use github_actions_models::dependabot::v2::AllowDeny;

use crate::audit::{Audit, audit_meta};

audit_meta!(
    DependabotExecution,
    "dependabot-execution",
    "external code execution in Dependabot updates"
);

pub(crate) struct DependabotExecution;

impl Audit for DependabotExecution {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_dependabot<'doc>(
        &self,
        dependabot: &'doc crate::models::dependabot::Dependabot,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for (idx, update) in dependabot.updates.iter().enumerate() {
            if matches!(update.insecure_external_code_execution, AllowDeny::Allow) {
                findings.push(
                    Self::finding()
                        .confidence(crate::finding::Confidence::High)
                        .severity(crate::finding::Severity::High)
                        .add_location(
                            dependabot
                                .location()
                                .with_keys([
                                    "updates".into(),
                                    idx.into(),
                                    "insecure-external-code-execution".into(),
                                ])
                                .primary()
                                .annotated("enabled here"),
                        )
                        .add_location(
                            dependabot
                                .location()
                                .with_keys([
                                    "updates".into(),
                                    idx.into(),
                                    "package-ecosystem".into(),
                                ])
                                .annotated("this ecosystem"),
                        )
                        .build(dependabot)?,
                );
            }
        }

        Ok(findings)
    }
}
