use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{Confidence, Fix, FixDisposition, Severity, location::Locatable as _},
    models::dependabot,
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
        update: dependabot::Update<'doc>,
        minimum_days: u64,
    ) -> Fix<'doc> {
        Fix {
            title: "add default-days to cooldown".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update.location().route.with_keys(["cooldown".into()]),
                operation: Op::Add {
                    key: "default-days".to_string(),
                    value: yaml_serde::Value::Number(minimum_days.into()),
                },
            }],
        }
    }

    /// Creates a fix that increases an insufficient default-days value
    fn create_increase_default_days_fix<'doc>(
        update: dependabot::Update<'doc>,
        minimum_days: u64,
    ) -> Fix<'doc> {
        Fix {
            title: format!("increase default-days to {minimum_days}"),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update
                    .location()
                    .route
                    .with_keys(["cooldown".into(), "default-days".into()]),
                operation: Op::Replace(yaml_serde::Value::Number(minimum_days.into())),
            }],
        }
    }

    /// Creates a fix that adds a cooldown block with default-days
    fn create_add_cooldown_fix<'doc>(
        update: dependabot::Update<'doc>,
        minimum_days: u64,
    ) -> Fix<'doc> {
        Fix {
            title: "add cooldown configuration".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update.location().route,
                operation: Op::Add {
                    key: "cooldown".to_string(),
                    value: yaml_serde::Value::Mapping({
                        let mut map = yaml_serde::Mapping::new();
                        map.insert(
                            yaml_serde::Value::String("default-days".to_string()),
                            yaml_serde::Value::Number(minimum_days.into()),
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
        dependabot: &'doc dependabot::Dependabot,
        config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let minimum_days = config.dependabot_cooldown_config.days.get() as u64;

        for update in dependabot.updates() {
            // If not set, `cooldown.default-days` is 3.
            // TODO: Should we have opinions about the other cooldown settings?
            let default_days = update
                .cooldown
                .as_ref()
                .map_or(3, |cooldown| cooldown.default_days.unwrap_or(3));

            // Nothing to do if the configured cooldown is at least our minimum.
            if default_days >= minimum_days {
                return Ok(findings);
            }

            // Otherwise, we need to build the right location and fix.
            let (location, fix) = match update.cooldown.as_ref() {
                Some(cooldown) => match cooldown.default_days {
                    // `cooldown.default-days` is present.
                    // Our fix needs to rewrite just the `default-days` value.
                    Some(_) => (
                        update
                            .location()
                            .with_keys(["cooldown".into(), "default-days".into()])
                            .primary()
                            .annotated(format!(
                                "insufficient default-days configured (less than {minimum_days})",
                            )),
                        Self::create_increase_default_days_fix(update, minimum_days),
                    ),
                    // `cooldown` is present, but `default-days` is not.
                    // Our fix needs to insert just `default-days` into the existing object.
                    None => (
                        update
                            .location()
                            .with_keys(["cooldown".into()])
                            .primary()
                            .annotated(format!(
                                "insufficient implicit default-days (less than {minimum_days})"
                            )),
                        Self::create_add_default_days_fix(update, minimum_days),
                    ),
                },
                // `cooldown` is not present.
                // Our fix needs to insert the entire `cooldown` object, not just `default-days`.
                None => (
                    update.location_with_grip().primary().annotated(format!(
                        "insufficient implicit default-days (less than {minimum_days})"
                    )),
                    Self::create_add_cooldown_fix(update, minimum_days),
                ),
            };

            findings.push(
                Self::finding()
                    .add_location(location)
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .fix(fix)
                    .build(dependabot)?,
            );
        }

        Ok(findings)
    }
}
