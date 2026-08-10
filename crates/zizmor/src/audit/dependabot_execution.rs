use github_actions_models::dependabot::v2::AllowDeny;

use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{Fix, FixDisposition, location::Locatable as _},
};
use yamlpatch::{Op, Patch};

audit_meta!(
    DependabotExecution,
    "dependabot-execution",
    "external code execution in Dependabot updates"
);

pub(crate) struct DependabotExecution;

impl DependabotExecution {
    /// Creates a fix that changes insecure-external-code-execution from allow to deny
    fn create_set_deny_fix<'doc>(update: crate::models::dependabot::Update<'doc>) -> Fix<'doc> {
        Fix {
            title: "set insecure-external-code-execution to deny".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Unsafe,
            patches: vec![Patch {
                route: update
                    .location()
                    .route
                    .with_keys(["insecure-external-code-execution".into()]),
                operation: Op::Replace(yaml_serde::Value::String("deny".to_string())),
            }],
        }
    }
}

#[async_trait::async_trait]
impl Audit for DependabotExecution {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_dependabot<'doc>(
        &self,
        dependabot: &'doc crate::models::dependabot::Dependabot,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for update in dependabot.updates() {
            if matches!(update.insecure_external_code_execution, AllowDeny::Allow) {
                findings.push(
                    Self::finding()
                        .confidence(crate::finding::Confidence::High)
                        .severity(crate::finding::Severity::High)
                        .add_location(
                            update
                                .location()
                                .with_keys(["insecure-external-code-execution".into()])
                                .primary()
                                .annotated("enabled here"),
                        )
                        .add_location(update.location_with_grip())
                        .fix(Self::create_set_deny_fix(update))
                        .build(dependabot)?,
                );
            }
        }

        Ok(findings)
    }
}
