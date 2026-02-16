use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{Confidence, Fix, FixDisposition, Severity, location::Locatable as _},
};
use yamlpatch::{Op, Patch};

audit_meta!(
    DependabotCooldown,
    "dependabot-cooldown",
    "insufficient cooldown in Dependabot updates"
);

pub(crate) struct DependabotCooldown;

impl DependabotCooldown {
    /// Creates a fix that adds default-days to an existing cooldown block
    fn create_add_default_days_fix<'doc>(
        update: crate::models::dependabot::Update<'doc>,
    ) -> Fix<'doc> {
        Fix {
            title: "add default-days to cooldown".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update.location().route.with_keys(["cooldown".into()]),
                operation: Op::Add {
                    key: "default-days".to_string(),
                    value: serde_yaml::Value::Number(7.into()),
                },
            }],
        }
    }

    /// Creates a fix that increases an insufficient default-days value
    fn create_increase_default_days_fix<'doc>(
        update: crate::models::dependabot::Update<'doc>,
    ) -> Fix<'doc> {
        Fix {
            title: "increase default-days to 7".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update
                    .location()
                    .route
                    .with_keys(["cooldown".into(), "default-days".into()]),
                operation: Op::Replace(serde_yaml::Value::Number(7.into())),
            }],
        }
    }

    /// Creates a fix that adds a cooldown block with default-days
    fn create_add_cooldown_fix<'doc>(update: crate::models::dependabot::Update<'doc>) -> Fix<'doc> {
        Fix {
            title: "add cooldown configuration".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update.location().route,
                operation: Op::Add {
                    key: "cooldown".to_string(),
                    value: serde_yaml::Value::Mapping({
                        let mut map = serde_yaml::Mapping::new();
                        map.insert(
                            serde_yaml::Value::String("default-days".to_string()),
                            serde_yaml::Value::Number(7.into()),
                        );
                        map
                    }),
                },
            }],
        }
    }
}

#[async_trait::async_trait]
impl Audit for DependabotCooldown {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_dependabot<'doc>(
        &self,
        dependabot: &'doc crate::models::dependabot::Dependabot,
        config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for update in dependabot.updates() {
            match &update.cooldown {
                // TODO(ww): Should we have opinions about the other
                // cooldown settings?
                Some(cooldown) => match cooldown.default_days {
                    // NOTE(ww): if not set, `default-days` is 0,
                    // which is equivalent to no cooldown by default.
                    // See: https://github.com/dependabot/dependabot-core/blob/01385be/updater/lib/dependabot/job.rb#L536-L547
                    None => findings.push(
                        Self::finding()
                            .add_location(
                                update
                                    .location()
                                    .with_keys(["cooldown".into()])
                                    .primary()
                                    .annotated("no default-days configured"),
                            )
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .fix(Self::create_add_default_days_fix(update))
                            .build(dependabot)?,
                    ),
                    Some(default_days)
                        if default_days < config.dependabot_cooldown_config.days.get() as u64 =>
                    {
                        findings.push(
                            Self::finding()
                                .add_location(
                                    update
                                        .location()
                                        .with_keys(["cooldown".into(), "default-days".into()])
                                        .primary()
                                        .annotated(format!("insufficient default-days configured (less than {days})", days = config.dependabot_cooldown_config.days)),
                                )
                                .confidence(Confidence::Medium)
                                .severity(Severity::Low)
                                .fix(Self::create_increase_default_days_fix(update))
                                .build(dependabot)?,
                        )
                    }
                    Some(_) => {}
                },
                None => findings.push(
                    Self::finding()
                        .add_location(
                            update
                                .location_with_grip()
                                .primary()
                                .annotated("missing cooldown configuration"),
                        )
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .fix(Self::create_add_cooldown_fix(update))
                        .build(dependabot)?,
                ),
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
    async fn test_fix_missing_cooldown() {
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
            DependabotCooldown,
            "test_fix_missing_cooldown.yml",
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
                    cooldown:
                      default-days: 7
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_fix_missing_default_days() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    cooldown: {}
    schedule:
      interval: daily
    insecure-external-code-execution: deny
"#;

        test_dependabot_audit!(
            DependabotCooldown,
            "test_fix_missing_default_days.yml",
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
                    cooldown: { default-days: 7 }
                    schedule:
                      interval: daily
                    insecure-external-code-execution: deny
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_fix_insufficient_default_days() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    cooldown:
      default-days: 2
    schedule:
      interval: daily
    insecure-external-code-execution: deny
"#;

        test_dependabot_audit!(
            DependabotCooldown,
            "test_fix_insufficient_default_days.yml",
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
                    cooldown:
                      default-days: 7
                    schedule:
                      interval: daily
                    insecure-external-code-execution: deny
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

  - package-ecosystem: npm
    directory: /
    cooldown:
      default-days: 1
    schedule:
      interval: weekly
"#;

        test_dependabot_audit!(
            DependabotCooldown,
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
                    cooldown:
                      default-days: 7

                  - package-ecosystem: npm
                    directory: /
                    cooldown:
                      default-days: 7
                    schedule:
                      interval: weekly
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_no_fix_needed_for_sufficient_cooldown() {
        let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    cooldown:
      default-days: 7
    schedule:
      interval: daily
"#;

        test_dependabot_audit!(
            DependabotCooldown,
            "test_no_fix_needed.yml",
            dependabot_content,
            |dependabot: &Dependabot, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 0, "Expected no findings");

                // Verify the document remains unchanged
                insta::assert_snapshot!(dependabot.as_document().source(), @r"

                version: 2

                updates:
                  - package-ecosystem: pip
                    directory: /
                    cooldown:
                      default-days: 7
                    schedule:
                      interval: daily
                ");
            }
        );
    }
}
