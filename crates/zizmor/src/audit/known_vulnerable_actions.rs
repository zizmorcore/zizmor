//! Detects publicly disclosed action vulnerabilities.
//!
//! This audit uses GitHub's security advisories API as a source of
//! ground truth.
//!
//! See: <https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28>

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Fix, Severity, location::Routable as _},
    github,
    models::{
        StepCommon, action::CompositeStep, repo_ref::RepoRef, uses::RepositoryUsesExt as _,
        workflow::Step,
    },
    state::AuditState,
};
use yamlpatch::{Op, Patch};

pub(crate) struct KnownVulnerableActions {
    client: github::Client,
}

audit_meta!(
    KnownVulnerableActions,
    "known-vulnerable-actions",
    "action has a known vulnerability"
);

impl KnownVulnerableActions {
    async fn action_known_vulnerabilities(
        &self,
        repo_ref: impl Into<RepoRef<'_>>,
    ) -> Result<Vec<(Severity, String, Option<String>)>, AuditError> {
        let repo_ref = repo_ref.into();
        let Some(slug) = repo_ref.slug() else {
            return Ok(vec![]);
        };

        let version = match &repo_ref.git_ref() {
            // If `uses` is pinned to a symbolic ref, we need to perform
            // feats of heroism to figure out what's going on.
            // In the "happy" case the symbolic ref is an exact version tag,
            // which we can then query directly for.
            // Besides that, there are two unhappy cases:
            // 1. The ref is a "version", but it's something like a "v3"
            //    branch or tag. These are obnoxious to handle, but we
            //    can do so with a heuristic: resolve the ref to a commit,
            //    then find the longest tag name that also matches that commit.
            //    For example, branch `v1` becomes tag `v1.2.3`.
            // 2. The ref is something version-y but not itself a version,
            //    like `gh-action-pypi-publish`'s `release/v1` branch.
            //    We use the same heuristic for these.
            //
            // To handle all of the above, we convert the ref into a commit
            // and then find the longest tag for that commit.
            version if !repo_ref.ref_is_commit() => {
                let Some(commit_ref) = self
                    .client
                    .lookup_ref(&slug, version)
                    .await
                    .map_err(Self::err)?
                else {
                    // No `ref -> commit` means that the action's version
                    // is probably just outright invalid.
                    return Ok(vec![]);
                };

                match self
                    .client
                    .longest_tag_for_commit(&slug, repo_ref.subpath(), commit_ref.commit())
                    .await
                    .map_err(Self::err)?
                {
                    Some(tag) => tag.name,
                    // Somehow we've round-tripped through a commit and ended
                    // up without a tag, which suggests we went
                    // `branch -> sha -> {no tag}`. In that case just use our
                    // original ref, since it's the best we have.
                    None => version.to_string(),
                }
            }
            // If `uses` is pinned to a sha-ref, we need to find the
            // tag matching that ref. In theory the action's repo could do
            // something annoying like use branches for versions instead,
            // which we should also probably support.
            commit_ref => {
                match self
                    .client
                    .longest_tag_for_commit(&slug, repo_ref.subpath(), commit_ref)
                    .await
                    .map_err(Self::err)?
                {
                    Some(tag) => tag.name,
                    // No corresponding tag means the user is maybe doing something
                    // weird, like using a commit ref off of a branch that isn't
                    // also tagged. Probably not good, but also not something
                    // we can easily discover known vulns for.
                    None => return Ok(vec![]),
                }
            }
        };

        let advisories = self
            .client
            .gha_advisories(&slug, &version)
            .await
            .map_err(Self::err)?;

        let mut results = vec![];

        for advisory in advisories {
            let severity = match advisory.severity.as_str() {
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::High,
                // Seems like a safe fallback.
                _ => Severity::High,
            };

            // Get the first patched version from the first matching vulnerability in the advisory.
            // NOTE: An advisory can contain multiple vulnerabilities, for multiple discrete packages,
            // so we need to filter the vulnerabilities by ecosystem and package name.
            // Example: https://github.com/advisories/GHSA-69fq-xp46-6x23
            // TODO: Rather that selecting the first patched version, maybe we should select
            // the highest patched version? Also, perhaps we should unify multiple advisories
            // for the same action into a single compatible patched version?
            let first_patched_version = advisory
                .vulnerabilities
                .iter()
                .find(|v| {
                    // TODO(ww): it'd be nice to have a well-typed comparison
                    // for repo slugs, rather than just case-insensitive string equality here.
                    v.package.ecosystem == "actions"
                        && v.package.name.eq_ignore_ascii_case(slug.slug())
                })
                .and_then(|v| v.first_patched_version.clone());

            results.push((severity, advisory.ghsa_id, first_patched_version));
        }

        Ok(results)
    }

    /// Create a fix to upgrade to a specific non-vulnerable version
    async fn create_upgrade_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        target_version: String,
        step: &impl StepCommon<'doc>,
    ) -> Result<Fix<'doc>, AuditError> {
        let mut uses_slug = format!("{}/{}", uses.owner(), uses.repo());
        if let Some(subpath) = &uses.subpath() {
            uses_slug.push_str(&format!("/{subpath}"));
        }

        let (bare_version, prefixed_version) = if let Some(bare) = target_version.strip_prefix('v')
        {
            (bare.into(), target_version)
        } else {
            let prefixed = format!("v{target_version}");
            (target_version, prefixed)
        };

        match uses.ref_is_commit() {
            // If `uses` is pinned to a commit, then we need two patches:
            // one to change the `uses` clause to the new version,
            // and another to replace any existing version comment.
            true => {
                // Annoying: GHSA will usually give us a fix version as `X.Y.Z`,
                // but GitHub Actions are conventionally tagged as `vX.Y.Z`.
                // We don't know whether a given action follows this
                // convention or not, so we have to try both.
                // We try the prefixed version first, since we expect it
                // to be more common.

                let target_ref = match self
                    .client
                    .lookup_ref(&uses.into(), &prefixed_version)
                    .await
                {
                    Ok(Some(commit_ref)) => Some(commit_ref),
                    Ok(None) | Err(_) => self
                        .client
                        .lookup_ref(&uses.into(), &bare_version)
                        .await
                        .map_err(Self::err)?,
                }
                .ok_or_else(|| {
                    Self::err(anyhow!(
                        "Cannot resolve version {bare_version} to commit hash for {}/{}",
                        uses.owner(),
                        uses.repo()
                    ))
                })?;

                let new_uses_value = format!(
                    "{uses_slug}@{target_commit}",
                    target_commit = target_ref.commit()
                );

                Ok(Fix {
                    title: format!(
                        "upgrade {uses_slug} to {target_ref}",
                        target_ref = target_ref.name()
                    ),
                    key: step.location().key,
                    disposition: Default::default(),
                    patches: vec![
                        Patch {
                            route: step.route().with_key("uses"),
                            operation: Op::Replace(new_uses_value.into()),
                        },
                        Patch {
                            route: step.route().with_key("uses"),
                            operation: Op::ReplaceComment {
                                new: format!("# {target_ref}", target_ref = target_ref.name())
                                    .into(),
                            },
                        },
                    ],
                })
            }
            // If `uses` is pinned to a symbolic ref, we only need to perform
            // a single patch.
            false => {
                // Like above, we don't know a priori whether the new tag should be
                // prefixed with `v` or not. Instead of trying to figure it out
                // via the GitHub API, we match the style of the current `uses`
                // clause.
                let target_version_tag = if uses.git_ref().starts_with('v') {
                    prefixed_version
                } else {
                    bare_version
                };

                let new_uses_value = format!("{uses_slug}@{target_version_tag}");
                Ok(Fix {
                    title: format!("upgrade {uses_slug} to {target_version_tag}"),
                    key: step.location().key,
                    disposition: Default::default(),
                    patches: vec![Patch {
                        route: step.route().with_key("uses"),
                        operation: Op::Replace(new_uses_value.into()),
                    }],
                })
            }
        }
    }

    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        for (severity, id, first_patched_version) in self.action_known_vulnerabilities(uses).await?
        {
            if config.known_vulnerable_actions_config.allow.contains(&id) {
                tracing::trace!("{id} is allowed in configuration; skipping");
                continue;
            }

            let mut finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(["uses".into()])
                        .with_url(format!("https://github.com/advisories/{id}", id = id))
                        .annotated(id),
                );

            // Add fix if available.
            // TODO(ww): In principle we could have multiple findings on a single
            // `uses:` clause, in which case our suggested fixes would potentially
            // overlap and partially cancel each other out. The end result of this
            // would be a lack of a single fixpoint, i.e. the user has to invoke
            // `zizmor` multiple times to fix all vulnerabilities.
            // To avoid that, we could probably collect each `first_patched_version`
            // and only apply the highest one. This would be moderately annoying
            // to do, since we'd have to decide which finding to attach that
            // fix to.
            if let Some(first_patched_version) = first_patched_version
                && let Ok(fix) = self
                    .create_upgrade_fix(uses, first_patched_version, step)
                    .await
            {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step).map_err(Self::err)?);
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for KnownVulnerableActions {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        state
            .gh_client
            .clone()
            .ok_or_else(|| AuditLoadError::Skip(anyhow!("can't run without a GitHub API token")))
            .map(|client| Self { client })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config).await
    }
}
