use crate::{
    audit::{Audit, audit_meta},
    finding::{Confidence, Severity, location::Locatable as _},
};

audit_meta!(
    DependabotCooldown,
    "dependabot-cooldown",
    "insufficient cooldown in Dependabot updates"
);

pub(crate) struct DependabotCooldown;

impl Audit for DependabotCooldown {
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
                            .build(dependabot)?,
                    ),
                    // We currently (arbitrarily) consider cooldowns under 4 days
                    // to be insufficient. The rationale here is that under 4 days
                    // can overlap with inopportune times like long weekends.
                    //
                    // TODO(ww): This should probably be configurable.
                    Some(default_days) if default_days < 4 => findings.push(
                        Self::finding()
                            .add_location(
                                update
                                    .location()
                                    .with_keys(["cooldown".into(), "default-days".into()])
                                    .primary()
                                    .annotated("insufficient default-days configured"),
                            )
                            .confidence(Confidence::Medium)
                            .severity(Severity::Low)
                            .build(dependabot)?,
                    ),
                    Some(_) => {}
                },
                None => findings.push(
                    Self::finding()
                        .add_location(
                            update
                                .location_with_name()
                                .primary()
                                .annotated("missing cooldown configuration"),
                        )
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .build(dependabot)?,
                ),
            }
        }

        Ok(findings)
    }
}
