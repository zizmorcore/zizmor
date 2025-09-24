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
    config::Config,
    finding::{Confidence, Finding, Fix, Severity, location::Routable as _},
    github_api,
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesExt as _, workflow::Step},
    state::AuditState,
};
use yamlpatch::{Op, Patch};

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
    ) -> Result<Vec<(Severity, String, Option<String>)>> {
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
            version if !uses.ref_is_commit() => {
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
            commit_ref => {
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
        };

        let vulns = self
            .client
            .gha_advisories(&uses.owner, &uses.repo, &version)?;

        let mut results = vec![];

        for vuln in vulns {
            let severity = match vuln.severity.as_str() {
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::High,
                // Seems like a safe fallback.
                _ => Severity::High,
            };

            // Get the first patched version from the first vulnerability in the advisory
            let first_patched_version = vuln
                .vulnerabilities
                .first()
                .and_then(|v| v.first_patched_version.clone());

            results.push((severity, vuln.ghsa_id, first_patched_version));
        }

        Ok(results)
    }

    /// Create a fix to upgrade to a specific non-vulnerable version
    fn create_upgrade_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        target_version: String,
        step: &impl StepCommon<'doc>,
    ) -> Result<Fix<'doc>> {
        let mut uses_slug = format!("{}/{}", uses.owner, uses.repo);
        if let Some(subpath) = &uses.subpath {
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
                let (target_ref, target_commit) = self
                    .client
                    .commit_for_ref(&uses.owner, &uses.repo, &prefixed_version)
                    .map(|commit| commit.map(|commit| (&prefixed_version, commit)))
                    .or_else(|_| {
                        self.client
                            .commit_for_ref(&uses.owner, &uses.repo, &bare_version)
                            .map(|commit| commit.map(|commit| (&bare_version, commit)))
                    })?
                    .ok_or_else(|| {
                        anyhow!(
                            "Cannot resolve version {bare_version} to commit hash for {}/{}",
                            uses.owner,
                            uses.repo
                        )
                    })?;

                let new_uses_value = format!("{uses_slug}@{target_commit}");

                Ok(Fix {
                    title: format!("upgrade {uses_slug} to {target_ref}"),
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
                                new: format!("# {target_ref}").into(),
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
                let target_version_tag = if uses.git_ref.starts_with('v') {
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

    fn process_step<'doc>(&self, step: &impl StepCommon<'doc>) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        for (severity, id, first_patched_version) in self.action_known_vulnerabilities(uses)? {
            let mut finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(["uses".into()])
                        .annotated(&id)
                        .with_url(format!("https://github.com/advisories/{id}")),
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
            if let Some(fix) = first_patched_version
                .map(|patched_version| self.create_upgrade_fix(uses, patched_version, step))
                .transpose()?
            {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step)?);
        }

        Ok(findings)
    }
}

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
            .map(|client| KnownVulnerableActions { client })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>, _config: &Config) -> Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;

    use super::*;
    use crate::{
        models::{AsDocument, workflow::Workflow},
        registry::input::InputKey,
    };

    // Helper function to create a test KnownVulnerableActions instance
    fn create_test_audit() -> KnownVulnerableActions {
        let state = crate::state::AuditState::new(
            false,
            Some(
                github_api::Client::new(
                    &github_api::GitHubHost::default(),
                    &github_api::GitHubToken::new("fake").unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        );
        KnownVulnerableActions::new(&state).unwrap()
    }

    #[test]
    fn test_fix_upgrade_actions_checkout() {
        let workflow_content = r#"
name: Test Vulnerable Actions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with old version
        uses: actions/checkout@v2
      - name: Another step
        run: echo "hello"
"#;

        let key = InputKey::local("fakegroup".into(), "test_checkout.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        // Test the fix directly
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: "v2".to_string(),
            subpath: None,
        };

        let audit = create_test_audit();
        let fix = audit.create_upgrade_fix(&uses, "v4".into(), step).unwrap();
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test Vulnerable Actions
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout with old version
                uses: actions/checkout@v4
              - name: Another step
                run: echo "hello"
        "#);
    }

    #[test]
    fn test_fix_upgrade_actions_setup_node() {
        let workflow_content = r#"
name: Test Node Setup
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Setup Node
        uses: actions/setup-node@v1
        with:
          node-version: '18'
      - name: Install dependencies
        run: npm install
"#;

        let key = InputKey::local("fakegroup".into(), "test_setup_node.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        // Test the fix directly
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "setup-node".to_string(),
            git_ref: "v1".to_string(),
            subpath: None,
        };

        let audit = create_test_audit();
        let fix = audit.create_upgrade_fix(&uses, "v4".into(), step).unwrap();
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test Node Setup
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Setup Node
                uses: actions/setup-node@v4
                with:
                  node-version: '18'
              - name: Install dependencies
                run: npm install
        "#);
    }

    #[test]
    fn test_fix_upgrade_third_party_action() {
        let workflow_content = r#"
name: Test Third Party Action
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Upload to codecov
        uses: codecov/codecov-action@v1
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
      - name: Another step
        run: echo "test"
"#;

        let key =
            InputKey::local("fakegroup".into(), "test_third_party.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        // Test the fix directly
        let uses = RepositoryUses {
            owner: "codecov".to_string(),
            repo: "codecov-action".to_string(),
            git_ref: "v1".to_string(),
            subpath: None,
        };

        let audit = create_test_audit();
        let fix = audit.create_upgrade_fix(&uses, "v4".into(), step).unwrap();
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test Third Party Action
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Upload to codecov
                uses: codecov/codecov-action@v4
                with:
                  token: ${{ secrets.CODECOV_TOKEN }}
              - name: Another step
                run: echo "test"
        "#);
    }

    #[test]
    fn test_fix_upgrade_multiple_vulnerable_actions() {
        let workflow_content = r#"
name: Test Multiple Vulnerable Actions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Setup Node
        uses: actions/setup-node@v1
        with:
          node-version: '18'
      - name: Cache dependencies
        uses: actions/cache@v2
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
      - name: Install dependencies
        run: npm install
"#;

        let key = InputKey::local("fakegroup".into(), "test_multiple.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };

        // Apply fixes to each vulnerable action
        let mut current_document = workflow.as_document().clone();
        let audit = create_test_audit();

        // Fix checkout action
        let uses_checkout = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: "v2".to_string(),
            subpath: None,
        };
        let fix_checkout = audit
            .create_upgrade_fix(&uses_checkout, "v4".into(), &steps[0])
            .unwrap();
        current_document = fix_checkout.apply(&current_document).unwrap();

        // Fix setup-node action
        let uses_node = RepositoryUses {
            owner: "actions".to_string(),
            repo: "setup-node".to_string(),
            git_ref: "v1".to_string(),
            subpath: None,
        };
        let fix_node = audit
            .create_upgrade_fix(&uses_node, "v4".into(), &steps[1])
            .unwrap();
        current_document = fix_node.apply(&current_document).unwrap();

        // Fix cache action
        let uses_cache = RepositoryUses {
            owner: "actions".to_string(),
            repo: "cache".to_string(),
            git_ref: "v2".to_string(),
            subpath: None,
        };
        let fix_cache = audit
            .create_upgrade_fix(&uses_cache, "v4".into(), &steps[2])
            .unwrap();
        current_document = fix_cache.apply(&current_document).unwrap();

        insta::assert_snapshot!(current_document.source(), @r#"
        name: Test Multiple Vulnerable Actions
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@v4
              - name: Setup Node
                uses: actions/setup-node@v4
                with:
                  node-version: '18'
              - name: Cache dependencies
                uses: actions/cache@v4
                with:
                  path: ~/.npm
                  key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
              - name: Install dependencies
                run: npm install
        "#);
    }

    #[test]
    fn test_fix_upgrade_action_with_subpath() {
        let workflow_content = r#"
name: Test Action with Subpath
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Custom action
        uses: owner/repo/subpath@v1
        with:
          param: value
"#;

        let key = InputKey::local("fakegroup".into(), "test_subpath.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        // Test the fix with subpath
        let uses = RepositoryUses {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            git_ref: "v1".to_string(),
            subpath: Some("subpath".to_string()),
        };

        let audit = create_test_audit();
        let fix = audit.create_upgrade_fix(&uses, "v2".into(), step).unwrap();
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r"
        name: Test Action with Subpath
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Custom action
                uses: owner/repo/subpath@v2
                with:
                  param: value
        ");
    }

    #[test]
    fn test_first_patched_version_priority() {
        // This test verifies that first_patched_version is used when available
        let workflow_content = r#"
name: Test First Patched Version Priority
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable action
        uses: actions/checkout@v2
"#;

        let key =
            InputKey::local("fakegroup".into(), "test_first_patched.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: "v2".to_string(),
            subpath: None,
        };

        // Test that when first_patched_version is provided, it's used
        let audit = create_test_audit();
        let fix_with_patched_version = audit
            .create_upgrade_fix(&uses, "v3.1.0".into(), step)
            .unwrap();
        let fixed_document = fix_with_patched_version
            .apply(workflow.as_document())
            .unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test First Patched Version Priority
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Vulnerable action
                uses: actions/checkout@v3.1.0
        "#);
    }

    #[test]
    fn test_fix_symbolic_ref() {
        let workflow_content = r#"
name: Test Non-Commit Ref
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Tag pinned action
        uses: actions/checkout@v2 # this comment stays
"#;

        let key = InputKey::local("fakegroup".into(), "test_non_commit.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: "v2".to_string(),
            subpath: None,
        };

        let audit = create_test_audit();
        let fix = audit.create_upgrade_fix(&uses, "v4".into(), step).unwrap();

        let new_doc = fix.apply(workflow.as_document()).unwrap();

        assert_snapshot!(new_doc.source(), @r"
        name: Test Non-Commit Ref
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Tag pinned action
                uses: actions/checkout@v4 # this comment stays
        ");
    }

    #[test]
    fn test_offline_audit_state_creation() {
        // Test that we can create an audit state without a GitHub token
        let state = crate::state::AuditState::default();

        // This should fail because no GitHub token is provided
        let audit_result = KnownVulnerableActions::new(&state);
        assert!(audit_result.is_err());
    }

    #[cfg(feature = "gh-token-tests")]
    #[test]
    fn test_fix_commit_pin() {
        // Test with real GitHub API - requires GH_TOKEN environment variable
        let workflow_content = r#"
name: Test Commit Hash Pinning Real API
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Commit pinned action
        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4  # v4.0.0
"#;

        let key = InputKey::local("fakegroup".into(), "dummy.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState::new(
            false,
            Some(
                github_api::Client::new(
                    &github_api::GitHubHost::default(),
                    &github_api::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        );

        let audit = KnownVulnerableActions::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(KnownVulnerableActions::ident(), &input, &Config::default())
            .unwrap();
        assert_eq!(findings.len(), 1);

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        assert_snapshot!(new_doc.source(), @r"
        name: Test Commit Hash Pinning Real API
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Commit pinned action
                uses: actions/download-artifact@87c55149d96e628cc2ef7e6fc2aab372015aec85  # v4.1.3
        ");
    }

    // TODO: test_fix_commit_pin_subpath

    #[cfg(feature = "gh-token-tests")]
    #[test]
    fn test_fix_commit_pin_no_comment() {
        // Ensure that we don't rewrite a version comment
        // if the `uses:` clause doesn't already have one.
        let workflow_content = r#"
name: Test Commit Hash Pinning Real API
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Commit pinned action
        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4
"#;
        let key = InputKey::local("fakegroup".into(), "dummy.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState::new(
            false,
            Some(
                github_api::Client::new(
                    &github_api::GitHubHost::default(),
                    &github_api::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        );

        let audit = KnownVulnerableActions::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(KnownVulnerableActions::ident(), &input, &Config::default())
            .unwrap();
        assert_eq!(findings.len(), 1);

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        assert_snapshot!(new_doc.source(), @r"
        name: Test Commit Hash Pinning Real API
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Commit pinned action
                uses: actions/download-artifact@87c55149d96e628cc2ef7e6fc2aab372015aec85
        ");
    }
}
