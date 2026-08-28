use std::sync::LazyLock;

use github_actions_models::common::{
    EnvValue, RepositoryUses, Uses,
    expr::{ExplicitExpr, LoE},
};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    audit::AuditError,
    finding::{Confidence, Finding, Fix, Persona, Severity, location::Routable as _},
    github::{Client, ClientError},
    models::{StepBodyCommon, StepCommon, uses::RepositoryUsesExt as _, version::Version},
    state::AuditState,
    utils::split_patterns,
};
use yamlpatch::{Op, Patch};

#[allow(clippy::unwrap_used)]
static V6: LazyLock<Version> = LazyLock::new(|| Version::parse("v6").unwrap());

pub(crate) struct Artipacked {
    client: Option<Client>,
}

audit_meta!(
    Artipacked,
    "artipacked",
    "credential persistence through GitHub Actions artifacts"
);

impl Artipacked {
    /// Determines if an `actions/checkout` usage is version 6 or higher.
    ///
    /// This takes two different paths:
    /// 1. If the ref is a symbolic ref (tag/branch), we use it for a direct version comparison.
    /// 2. If the ref is a commit SHA *and* we have a GitHub client, we match the commit
    ///    to its longest tag. We then use that tag for the version comparison.
    ///
    /// If we can't determine the version (e.g., commit SHA without client),
    /// we return `None`.
    async fn is_checkout_v6_or_higher(
        &self,
        uses: &RepositoryUses,
    ) -> Result<Option<bool>, ClientError> {
        let version = if !uses.ref_is_commit() {
            uses.git_ref().to_string()
        } else {
            match self.client {
                Some(ref client) => {
                    let tag = client
                        .longest_tag_for_commit(&uses.into(), uses.subpath(), uses.git_ref())
                        .await?;

                    match tag {
                        Some(tag) => tag.name,
                        None => return Ok(None),
                    }
                }
                None => return Ok(None),
            }
        };

        // Try to parse the ref as a version
        let Ok(version) = Version::parse(&version) else {
            // If we can't parse it as a version, assume it's not v6+
            return Ok(None);
        };

        Ok(Some(version >= *V6))
    }

    /// Determine the severity for an artipacked finding based on checkout version
    /// and whether there are vulnerable uploads.
    fn determine_severity(
        is_v6_or_higher: Option<bool>,
        has_no_vulnerable_uploads: bool,
    ) -> Severity {
        if is_v6_or_higher == Some(true) {
            // For checkout@v6+, downgrade severity since credentials are stored
            // in $RUNNER_TEMP instead of .git/config, reducing leakage risk.
            if has_no_vulnerable_uploads {
                Severity::Low
            } else {
                Severity::Medium
            }
        } else if has_no_vulnerable_uploads {
            Severity::Medium
        } else {
            Severity::High
        }
    }

    async fn process_steps<'doc>(
        &self,
        steps: impl Iterator<Item = impl StepCommon<'doc>>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // First, collect all vulnerable checkouts and upload steps independently.
        let mut vulnerable_checkouts = vec![];
        let mut vulnerable_uploads = vec![];
        for step in steps {
            let Some(StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            }) = &step.body()
            else {
                continue;
            };

            if uses.matches("actions/checkout") {
                let with = match with {
                    LoE::Literal(with) => with,
                    LoE::Expr(_) => {
                        // We don't emit a finding if the entire `with` block
                        // is an expression, since the `obfuscation` audit covers that.
                        continue;
                    }
                };

                let is_v6_or_higher = self
                    .is_checkout_v6_or_higher(uses)
                    .await
                    .map_err(Self::err)?;
                match with
                    .get("persist-credentials")
                    .map(|v| v.to_string())
                    .as_deref()
                {
                    Some("false") => continue,
                    Some("true") => {
                        // If a user explicitly sets `persist-credentials: true`,
                        // they probably mean it. Only report if in auditor mode.
                        vulnerable_checkouts.push((step, Persona::Auditor, is_v6_or_higher))
                    }
                    Some(v) if ExplicitExpr::from_curly(v).is_some() => {
                        vulnerable_checkouts.push((step, Persona::Pedantic, is_v6_or_higher));
                    }
                    _ => vulnerable_checkouts.push((step, Persona::default(), is_v6_or_higher)),
                }
            } else if uses.matches("actions/upload-artifact") {
                let LoE::Literal(with) = with else {
                    continue;
                };

                let Some(EnvValue::String(path)) = with.get("path") else {
                    continue;
                };

                let dangerous_paths = self.dangerous_artifact_patterns(path);
                if !dangerous_paths.is_empty() {
                    // TODO: plumb dangerous_paths into the annotation here.
                    vulnerable_uploads.push(step)
                }
            }
        }

        if vulnerable_uploads.is_empty() {
            // If we have no vulnerable uploads, then emit lower-confidence
            // findings for just the checkout steps.
            for (checkout, persona, is_v6_or_higher) in &vulnerable_checkouts {
                let severity =
                    Self::determine_severity(*is_v6_or_higher, vulnerable_uploads.is_empty());

                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(Confidence::Low)
                        .persona(*persona)
                        .add_location(
                            checkout
                                .location()
                                .primary()
                                .annotated("does not set persist-credentials: false"),
                        )
                        .fix(Self::create_persist_credentials_fix(checkout))
                        .build(checkout)?,
                );
            }
        } else {
            // Select only pairs where the vulnerable checkout precedes the
            // vulnerable upload. There are more efficient ways to do this than
            // a cartesian product, but this way is simple.
            for ((checkout, persona, is_v6_or_higher), upload) in vulnerable_checkouts
                .iter()
                .cartesian_product(vulnerable_uploads.iter())
            {
                if checkout.ord() < upload.ord() {
                    let severity =
                        Self::determine_severity(*is_v6_or_higher, vulnerable_uploads.is_empty());

                    findings.push(
                        Self::finding()
                            .severity(severity)
                            .confidence(Confidence::High)
                            .persona(*persona)
                            .add_location(
                                checkout
                                    .location()
                                    .primary()
                                    .annotated("does not set persist-credentials: false"),
                            )
                            .add_location(
                                upload
                                    .location()
                                    .annotated("may leak the credentials persisted above"),
                            )
                            .fix(Self::create_persist_credentials_fix(checkout))
                            .build(checkout)?,
                    );
                }
            }
        }

        Ok(findings)
    }

    fn dangerous_artifact_patterns<'b>(&self, path: &'b str) -> Vec<&'b str> {
        let mut patterns = vec![];
        for path in split_patterns(path) {
            match path {
                // TODO: this could be even more generic.
                "." | "./" | ".." | "../" => patterns.push(path),
                path => match ExplicitExpr::from_curly(path) {
                    Some(expr) if expr.as_bare().contains("github.workspace") => {
                        patterns.push(path)
                    }
                    // TODO: Other expressions worth flagging here?
                    Some(_) => continue,
                    _ => continue,
                },
            }
        }

        patterns
    }

    /// Create a Fix for setting persist-credentials: false
    fn create_persist_credentials_fix<'doc>(step: &impl StepCommon<'doc>) -> Fix<'doc> {
        Fix {
            title: "set persist-credentials: false".to_string(),
            key: step.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: step.route(),
                operation: Op::MergeInto {
                    key: "with".to_string(),
                    updates: indexmap::IndexMap::from_iter([(
                        "persist-credentials".to_string(),
                        yaml_serde::Value::Bool(false),
                    )]),
                },
            }],
        }
    }
}

#[async_trait::async_trait]
impl Audit for Artipacked {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError> {
        let client = if state.no_online_audits {
            None
        } else {
            state.gh_client.clone()
        };

        Ok(Self { client })
    }

    async fn audit_action<'doc>(
        &self,
        action: &'doc crate::models::action::Action,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(steps) = action.steps() else {
            return Ok(vec![]);
        };

        self.process_steps(steps).await
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_steps(job.steps()).await
    }
}

#[cfg(test)]
mod tests {
    use github_actions_models::common::RepositoryUses;

    use super::*;

    #[tokio::test]
    async fn test_is_checkout_v6_or_higher_offline() {
        // Test v6 and higher versions
        let v6 = RepositoryUses::parse("actions/checkout@v6").unwrap();
        let v6_0 = RepositoryUses::parse("actions/checkout@v6.0").unwrap();
        let v6_1_0 = RepositoryUses::parse("actions/checkout@v6.1.0").unwrap();
        let v7 = RepositoryUses::parse("actions/checkout@v7").unwrap();
        let v10 = RepositoryUses::parse("actions/checkout@v10").unwrap();

        let artipacked = Artipacked { client: None };

        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v6).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v6_0).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v6_1_0).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v7).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v10).await.unwrap(),
            Some(true)
        );

        // Test versions below v6
        let v4 = RepositoryUses::parse("actions/checkout@v4").unwrap();
        let v5 = RepositoryUses::parse("actions/checkout@v5").unwrap();
        let v5_9 = RepositoryUses::parse("actions/checkout@v5.9").unwrap();

        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v4).await.unwrap(),
            Some(false)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v5).await.unwrap(),
            Some(false)
        );
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&v5_9).await.unwrap(),
            Some(false)
        );

        // Test commit SHA (should return None when offline)
        let commit_sha =
            RepositoryUses::parse("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
                .unwrap();
        assert_eq!(
            artipacked
                .is_checkout_v6_or_higher(&commit_sha)
                .await
                .unwrap(),
            None
        );

        // Test invalid/unparseable refs (should return None)
        let invalid = RepositoryUses::parse("actions/checkout@main").unwrap();
        assert_eq!(
            artipacked.is_checkout_v6_or_higher(&invalid).await.unwrap(),
            None
        );
    }

    #[cfg(feature = "online-tests")]
    #[tokio::test]
    async fn test_is_checkout_v6_or_higher_online() {
        use crate::github;

        let artipacked = Artipacked {
            client: Some(
                Client::new(
                    &github::GitHubHost::default(),
                    &github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        };

        // Points to v6.0.0.
        let commit_sha_v6 =
            RepositoryUses::parse("actions/checkout@1af3b93b6815bc44a9784bd300feb67ff0d1eeb3")
                .unwrap();

        assert_eq!(
            artipacked
                .is_checkout_v6_or_higher(&commit_sha_v6)
                .await
                .unwrap(),
            Some(true)
        );

        // Points to v5.0.1.
        let commit_sha_v5 =
            RepositoryUses::parse("actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd")
                .unwrap();

        assert_eq!(
            artipacked
                .is_checkout_v6_or_higher(&commit_sha_v5)
                .await
                .unwrap(),
            Some(false)
        );
    }

    #[test]
    fn test_determine_severity() {
        const IS_V6_OR_HIGHER: Option<bool> = Some(true);
        const IS_OLDER_VERSION: Option<bool> = Some(false);
        const UNKNOWN_VERSION: Option<bool> = None;
        const HAS_NO_VULNERABLE_UPLOADS: bool = true;
        const HAS_VULNERABLE_UPLOADS: bool = false;

        // checkout@v6+ with no vulnerable uploads -> Low
        assert_eq!(
            Artipacked::determine_severity(IS_V6_OR_HIGHER, HAS_NO_VULNERABLE_UPLOADS),
            Severity::Low
        );

        // checkout@v6+ with vulnerable uploads -> Medium
        assert_eq!(
            Artipacked::determine_severity(IS_V6_OR_HIGHER, HAS_VULNERABLE_UPLOADS),
            Severity::Medium
        );

        // Older checkout versions with no vulnerable uploads -> Medium
        assert_eq!(
            Artipacked::determine_severity(IS_OLDER_VERSION, HAS_NO_VULNERABLE_UPLOADS),
            Severity::Medium
        );

        // Older checkout versions with vulnerable uploads -> High
        assert_eq!(
            Artipacked::determine_severity(IS_OLDER_VERSION, HAS_VULNERABLE_UPLOADS),
            Severity::High
        );

        // Unknown version (None) with no vulnerable uploads -> Medium (treated as older)
        assert_eq!(
            Artipacked::determine_severity(UNKNOWN_VERSION, HAS_NO_VULNERABLE_UPLOADS),
            Severity::Medium
        );

        // Unknown version (None) with vulnerable uploads -> High (treated as older)
        assert_eq!(
            Artipacked::determine_severity(UNKNOWN_VERSION, HAS_VULNERABLE_UPLOADS),
            Severity::High
        );
    }
}
