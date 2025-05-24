//! Detects publicly disclosed action vulnerabilities.
//!
//! This audit uses GitHub's security advisories API as a source of
//! ground truth.
//!
//! See: <https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28>

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Severity},
    github_api,
    models::{CompositeStep, JobExt as _, Step, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct KnownVulnerableActions {
    client: github_api::Client,
}

audit_meta!(
    KnownVulnerableActions,
    "known-vulnerable-actions",
    "action has a known vulnerability"
);

impl KnownVulnerableActions {
    fn action_known_vulnerabilities(
        &self,
        uses: &RepositoryUses,
    ) -> Result<Vec<(Severity, String)>> {
        let version = match &uses.git_ref {
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
            Some(version) if !uses.ref_is_commit() => {
                let Some(commit_ref) =
                    self.client
                        .commit_for_ref(&uses.owner, &uses.repo, version)?
                else {
                    // No `ref -> commit` means that the action's version
                    // is probably just outright invalid.
                    return Ok(vec![]);
                };

                match self
                    .client
                    .longest_tag_for_commit(&uses.owner, &uses.repo, &commit_ref)?
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
            Some(commit_ref) => {
                match self
                    .client
                    .longest_tag_for_commit(&uses.owner, &uses.repo, commit_ref)?
                {
                    Some(tag) => tag.name,
                    // No corresponding tag means the user is maybe doing something
                    // weird, like using a commit ref off of a branch that isn't
                    // also tagged. Probably not good, but also not something
                    // we can easily discover known vulns for.
                    None => return Ok(vec![]),
                }
            }
            // No version means the action runs the latest default branch
            // version. We could in theory query GHSA for this but it's
            // unlikely to be meaningful.
            // TODO: Maybe we need a separate (low-sev) audit for actions usage
            // on @master/@main/etc?
            None => return Ok(vec![]),
        };

        let vulns = self
            .client
            .gha_advisories(&uses.owner, &uses.repo, &version)?;

        let mut results = vec![];

        for vuln in vulns {
            let severity = match vuln.severity.as_str() {
                "low" => Severity::Unknown,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::High,
                _ => Severity::Unknown,
            };

            results.push((severity, vuln.ghsa_id));
        }

        Ok(results)
    }

    /// Create a fix to upgrade to a specific non-vulnerable version
    fn create_upgrade_fix(
        uses: &RepositoryUses,
        target_version: &str,
        path: &str,
        _is_composite: bool,
    ) -> Fix {
        let current_ref = uses.git_ref.as_deref().unwrap_or("latest");
        let action_name = format!("{}/{}", uses.owner, uses.repo);

        Fix {
            title: format!("Upgrade {} to {}", action_name, target_version),
            description: format!(
                "Upgrade {} from {} to {} to fix known vulnerability. This version contains security fixes that address the reported vulnerability.",
                action_name, current_ref, target_version
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path.to_string(),
                value: serde_yaml::Value::String(format!("{}@{}", action_name, target_version)),
            }]),
        }
    }

    /// Create a fix to upgrade to the latest version
    fn create_upgrade_to_latest_fix(
        uses: &RepositoryUses,
        _path: &str,
        _is_composite: bool,
    ) -> Fix {
        let current_ref = uses.git_ref.as_deref().unwrap_or("latest");
        let action_name = format!("{}/{}", uses.owner, uses.repo);

        Fix {
            title: format!("Upgrade {} to latest version", action_name),
            description: format!(
                "Upgrade {} from {} to the latest version to fix known vulnerability. Check the action's releases page for the most recent version and upgrade accordingly.",
                action_name, current_ref
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // For now, provide guidance but don't automatically change to "latest"
                // since that's not a good practice. Users should pin to specific versions.
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix to remove the vulnerable action step
    fn create_remove_step_fix(uses: &RepositoryUses, path: &str, is_composite: bool) -> Fix {
        let action_name = format!("{}/{}", uses.owner, uses.repo);
        let item_type = if is_composite {
            "composite step"
        } else {
            "workflow step"
        };

        Fix {
            title: format!("Remove vulnerable {} action", action_name),
            description: format!(
                "Remove the vulnerable {} action from this {}. This action has known security vulnerabilities and no fix is currently available. Consider finding an alternative action or implementing the functionality differently.",
                action_name, item_type
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: path.to_string(),
            }]),
        }
    }

    /// Create a fix suggesting manual review and alternative actions
    fn create_manual_review_fix(uses: &RepositoryUses, ghsa_id: &str) -> Fix {
        let action_name = format!("{}/{}", uses.owner, uses.repo);

        Fix {
            title: format!(
                "Review {} vulnerability and consider alternatives",
                action_name
            ),
            description: format!(
                "Manually review the security advisory {} for {} and consider the following options: \
                1) Upgrade to a newer version if available, \
                2) Use an alternative action that provides similar functionality, \
                3) Implement the functionality directly in your workflow, \
                4) Accept the risk if the vulnerability doesn't apply to your use case.",
                ghsa_id, action_name
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // No automatic fix, just guidance
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Get the best available fix for a vulnerable action
    fn get_vulnerability_fix(
        &self,
        uses: &RepositoryUses,
        ghsa_id: &str,
        path: &str,
        is_composite: bool,
    ) -> Result<Vec<Fix>> {
        let mut fixes = vec![];

        // Try to get the latest tag to suggest as an upgrade target
        match self.client.list_tags(&uses.owner, &uses.repo) {
            Ok(tags) if !tags.is_empty() => {
                // Use the first tag as the latest (GitHub API returns tags in descending order)
                let latest_tag = &tags[0];
                fixes.push(Self::create_upgrade_fix(
                    uses,
                    &latest_tag.name,
                    path,
                    is_composite,
                ));

                // Also offer manual review as an alternative
                fixes.push(Self::create_manual_review_fix(uses, ghsa_id));
            }
            Ok(_) => {
                // No tags found, suggest manual upgrade to latest
                fixes.push(Self::create_upgrade_to_latest_fix(uses, path, is_composite));
                fixes.push(Self::create_manual_review_fix(uses, ghsa_id));
            }
            Err(_) => {
                // API error, fall back to manual review and removal options
                fixes.push(Self::create_manual_review_fix(uses, ghsa_id));
                fixes.push(Self::create_remove_step_fix(uses, path, is_composite));
            }
        }

        Ok(fixes)
    }

    fn get_step_path(step: &Step, is_composite: bool) -> String {
        if is_composite {
            format!("/runs/steps/{}", step.index)
        } else {
            format!("/jobs/{}/steps/{}/uses", step.job().id(), step.index)
        }
    }

    fn get_composite_step_path(step: &CompositeStep) -> String {
        format!("/runs/steps/{}/uses", step.index)
    }

    fn process_workflow_step<'doc>(&self, step: &Step<'doc>) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        for (severity, id) in self.action_known_vulnerabilities(uses)? {
            let path = Self::get_step_path(step, false);

            let mut finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated(&id)
                        .with_url(format!("https://github.com/advisories/{id}")),
                );

            // Add fixes for this vulnerability
            match self.get_vulnerability_fix(uses, &id, &path, false) {
                Ok(fixes) => {
                    for fix in fixes {
                        finding_builder = finding_builder.fix(fix);
                    }
                }
                Err(_) => {
                    // If we can't get specific fixes, add a generic manual review fix
                    finding_builder =
                        finding_builder.fix(Self::create_manual_review_fix(uses, &id));
                }
            }

            findings.push(finding_builder.build(step)?);
        }

        Ok(findings)
    }

    fn process_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
    ) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        for (severity, id) in self.action_known_vulnerabilities(uses)? {
            let path = Self::get_composite_step_path(step);

            let mut finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated(&id)
                        .with_url(format!("https://github.com/advisories/{id}")),
                );

            // Add fixes for this vulnerability
            match self.get_vulnerability_fix(uses, &id, &path, true) {
                Ok(fixes) => {
                    for fix in fixes {
                        finding_builder = finding_builder.fix(fix);
                    }
                }
                Err(_) => {
                    // If we can't get specific fixes, add a generic manual review fix
                    finding_builder =
                        finding_builder.fix(Self::create_manual_review_fix(uses, &id));
                }
            }

            findings.push(finding_builder.build(step)?);
        }

        Ok(findings)
    }
}

impl Audit for KnownVulnerableActions {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        let Some(client) = state.github_client() else {
            return Err(AuditLoadError::Skip(anyhow!(
                "can't run without a GitHub API token"
            )));
        };

        Ok(Self { client })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> Result<Vec<Finding<'doc>>> {
        self.process_workflow_step(step)
    }

    fn audit_composite_step<'doc>(&self, step: &CompositeStep<'doc>) -> Result<Vec<Finding<'doc>>> {
        self.process_composite_step(step)
    }
}
