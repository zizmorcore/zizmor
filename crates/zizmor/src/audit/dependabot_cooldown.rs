use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{
        Confidence, Finding, Fix, FixDisposition, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::dependabot::{self, Dependabot},
};
use github_actions_models::dependabot::v2::PackageEcosystem;
use yamlpatch::{Op, Patch};

audit_meta!(
    DependabotCooldown,
    "dependabot-cooldown",
    "insufficient cooldown in Dependabot updates"
);

pub(crate) struct DependabotCooldown;

impl DependabotCooldown {
    fn finding<'doc>(
        dependabot: &'doc Dependabot,
        location: SymbolicLocation<'doc>,
        fix: Fix<'doc>,
    ) -> Result<Finding<'doc>, AuditError> {
        <Self as AuditCore>::finding()
            .add_location(location)
            .confidence(Confidence::High)
            .severity(Severity::Medium)
            .fix(fix)
            .build(dependabot)
    }

    /// Returns whether this `update` directive supports semver-style cooldowns.
    ///
    /// Matches the table here:
    /// <https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#configuration-of-cooldown>
    fn supports_semver_cooldowns(update: &dependabot::Update<'_>) -> bool {
        match update.package_ecosystem {
            PackageEcosystem::Apm
            | PackageEcosystem::Bun
            | PackageEcosystem::Bundler
            | PackageEcosystem::Cargo
            | PackageEcosystem::Composer
            | PackageEcosystem::Conda
            | PackageEcosystem::Deno
            | PackageEcosystem::DotnetSdk
            | PackageEcosystem::Elm
            | PackageEcosystem::Gomod
            | PackageEcosystem::Gradle
            | PackageEcosystem::Julia
            | PackageEcosystem::Maven
            | PackageEcosystem::Mix
            | PackageEcosystem::Npm
            | PackageEcosystem::Nuget
            | PackageEcosystem::Pip
            | PackageEcosystem::Pub
            | PackageEcosystem::RustToolchain
            | PackageEcosystem::Sbt
            | PackageEcosystem::Swift
            | PackageEcosystem::Uv => true,
            PackageEcosystem::Bazel
            | PackageEcosystem::Devcontainers
            | PackageEcosystem::Docker
            | PackageEcosystem::DockerCompose
            | PackageEcosystem::Gitsubmodule
            | PackageEcosystem::GithubActions
            | PackageEcosystem::Helm
            | PackageEcosystem::Nix
            | PackageEcosystem::Opentofu
            | PackageEcosystem::PreCommit
            | PackageEcosystem::Terraform
            | PackageEcosystem::Vcpkg => false,
        }
    }

    /// Creates a fix that adds default-days to an existing cooldown block
    fn create_add_days_fix<'doc>(
        update: &dependabot::Update<'doc>,
        minimum_days: u64,
        days_key: &'static str,
    ) -> Fix<'doc> {
        Fix {
            title: "add default-days to cooldown".to_string(),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update.location().route.with_keys(["cooldown".into()]),
                operation: Op::Add {
                    key: days_key.to_string(),
                    value: yaml_serde::Value::Number(minimum_days.into()),
                },
            }],
        }
    }

    /// Creates a fix that increases an insufficient days value.
    fn create_increase_days_fix<'doc>(
        update: &dependabot::Update<'doc>,
        minimum_days: u64,
        days_key: &'static str,
    ) -> Fix<'doc> {
        Fix {
            title: format!("increase default-days to {minimum_days}"),
            key: update.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: update
                    .location()
                    .route
                    .with_keys(["cooldown".into(), days_key.into()]),
                operation: Op::Replace(yaml_serde::Value::Number(minimum_days.into())),
            }],
        }
    }

    /// Creates a fix that adds a cooldown block with default-days.
    fn create_add_cooldown_fix<'doc>(
        update: &dependabot::Update<'doc>,
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
        group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let minimum_days = group.config().dependabot_cooldown_config.days.get() as u64;

        for update in dependabot.updates() {
            let Some(cooldown) = &update.cooldown else {
                // No `cooldown` block.
                // As of 07-14-2026 the blanket cooldown in Dependabot is 3 days,
                // so we flag a missing block if zizmor's configured cooldown
                // is greater.
                // See: <https://github.blog/changelog/2026-07-14-dependabot-version-updates-introduce-default-package-cooldown/>
                if minimum_days > 3 {
                    findings.push(Self::finding(
                        dependabot,
                        update.location_with_grip().primary().annotated(format!(
                            "insufficient implicit default-days (less than {minimum_days})"
                        )),
                        Self::create_add_cooldown_fix(&update, minimum_days),
                    )?);
                }

                continue;
            };

            // TODO: Check for `cooldown.exclude: "*"` here, since
            // it effectively disables the cooldown entirely.

            // If not set, `cooldown.default-days` is 3.
            // TODO: Should we have opinions about the other cooldown settings?
            let default_days = cooldown.default_days.unwrap_or(3);

            let mut all_semver_cooldowns_present = false;
            if Self::supports_semver_cooldowns(&update) {
                // If this update group is for an ecosystem that supports
                // semver updates, then there are additional `cooldown.semver-*-days`
                // fields we need to check. These take precedence over `default-days`.
                all_semver_cooldowns_present = cooldown.semver_major_days.is_some()
                    && cooldown.semver_minor_days.is_some()
                    && cooldown.semver_patch_days.is_some();

                // Note: We don't flag missing `semver-*-days` keys with a finding and fix,
                // since we'll flag `default-days` as a baseline if any of the `semver-*-days`
                // keys are missing.

                if let Some(major_days) = cooldown.semver_major_days
                    && major_days < minimum_days
                {
                    findings.push(Self::finding(
                        dependabot,
                        update
                            .location()
                            .with_keys(["cooldown".into(), "semver-major-days".into()])
                            .primary(),
                        Self::create_increase_days_fix(&update, minimum_days, "semver-major-days"),
                    )?);
                }

                if let Some(minor_days) = cooldown.semver_minor_days
                    && minor_days < minimum_days
                {
                    findings.push(Self::finding(
                        dependabot,
                        update
                            .location()
                            .with_keys(["cooldown".into(), "semver-minor-days".into()])
                            .primary(),
                        Self::create_increase_days_fix(&update, minimum_days, "semver-minor-days"),
                    )?);
                }

                if let Some(patch_days) = cooldown.semver_patch_days
                    && patch_days < minimum_days
                {
                    findings.push(Self::finding(
                        dependabot,
                        update
                            .location()
                            .with_keys(["cooldown".into(), "semver-patch-days".into()])
                            .primary(),
                        Self::create_increase_days_fix(&update, minimum_days, "semver-patch-days"),
                    )?);
                }
            }

            // Nothing to do if we checked semver-specific cooldown settings above,
            // and all were present (since no fallback to `default-days` happens
            // in that case).
            if all_semver_cooldowns_present {
                tracing::debug!(
                    "update group for {ecosystem:?} uses uniform semver cooldowns",
                    ecosystem = update.package_ecosystem
                );
                continue;
            }

            // Nothing to do if the configured cooldown is at least our minimum.
            if default_days >= minimum_days {
                continue;
            }

            // Otherwise, we need to build the right location and fix.
            let (location, fix) = match cooldown.default_days {
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
                    Self::create_increase_days_fix(&update, minimum_days, "default-days"),
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
                    Self::create_add_days_fix(&update, minimum_days, "default-days"),
                ),
            };

            findings.push(Self::finding(dependabot, location, fix)?);
        }

        Ok(findings)
    }
}
