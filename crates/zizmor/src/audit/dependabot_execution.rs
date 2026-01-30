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
                operation: Op::Replace(serde_yaml::Value::String("deny".to_string())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        models::{AsDocument, dependabot::Dependabot},
        registry::input::InputKey,
        state::AuditState,
    };

    /// Macro for testing dependabot audits with common boilerplate
    macro_rules! test_dependabot_audit {
        ($audit_type:ty, $filename:expr, $dependabot_content:expr, $test_fn:expr) => {{
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>);
            let dependabot = Dependabot::from_string($dependabot_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit
                .audit_dependabot(&dependabot, &Config::default())
                .await
                .unwrap();

            $test_fn(&dependabot, findings)
        }};
    }

    #[tokio::test]
    async fn test_fix_allow_to_deny() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    insecure-external-code-execution: allow
"#;

        test_dependabot_audit!(
            DependabotExecution,
            "test_fix_allow_to_deny.yml",
            dependabot_content,
            |dependabot: &Dependabot, findings: Vec<crate::finding::Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
                let finding = &findings[0];
                assert!(!finding.fixes.is_empty(), "Expected fixes but got none");

                let fix = &finding.fixes[0];
                let fixed_document = fix.apply(dependabot.as_document()).unwrap();
                insta::assert_snapshot!(fixed_document.source(), @r"

                version: 2

                updates:
                  - package-ecosystem: pip
                    directory: /
                    schedule:
                      interval: daily
                    insecure-external-code-execution: deny
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_no_fix_needed_for_deny() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    insecure-external-code-execution: deny
"#;

        test_dependabot_audit!(
            DependabotExecution,
            "test_no_fix_needed_for_deny.yml",
            dependabot_content,
            |dependabot: &Dependabot, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 0, "Expected no findings");

                // Verify the document remains unchanged
                insta::assert_snapshot!(dependabot.as_document().source(), @r"

                version: 2

                updates:
                  - package-ecosystem: pip
                    directory: /
                    schedule:
                      interval: daily
                    insecure-external-code-execution: deny
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_no_fix_needed_when_omitted() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
"#;

        test_dependabot_audit!(
            DependabotExecution,
            "test_no_fix_needed_when_omitted.yml",
            dependabot_content,
            |dependabot: &Dependabot, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 0, "Expected no findings");

                // Verify the document remains unchanged
                insta::assert_snapshot!(dependabot.as_document().source(), @r"

                version: 2

                updates:
                  - package-ecosystem: pip
                    directory: /
                    schedule:
                      interval: daily
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_fix_multiple_updates() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    insecure-external-code-execution: allow

  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    insecure-external-code-execution: allow
"#;

        test_dependabot_audit!(
            DependabotExecution,
            "test_fix_multiple_updates.yml",
            dependabot_content,
            |dependabot: &Dependabot, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 2, "Expected 2 findings");

                // Apply all fixes and snapshot the result
                let mut document = dependabot.as_document().clone();
                for finding in &findings {
                    assert!(!finding.fixes.is_empty(), "Expected fixes but got none");
                    for fix in &finding.fixes {
                        document = fix.apply(&document).unwrap();
                    }
                }

                insta::assert_snapshot!(document.source(), @r"

                version: 2

                updates:
                  - package-ecosystem: pip
                    directory: /
                    schedule:
                      interval: daily
                    insecure-external-code-execution: deny

                  - package-ecosystem: npm
                    directory: /
                    schedule:
                      interval: weekly
                    insecure-external-code-execution: deny
                ");
            }
        );
    }
}
