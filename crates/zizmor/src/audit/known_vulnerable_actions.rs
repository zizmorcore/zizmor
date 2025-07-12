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
        uses: &RepositoryUses,
        target_version: &str,
        step: &impl StepCommon<'doc>,
    ) -> Fix<'doc> {
        let action_name = format!("{}/{}", uses.owner, uses.repo);
        let new_uses_value = format!("{action_name}@{target_version}");

        Fix {
            title: format!("upgrade {action_name} to {target_version}"),
            key: step.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: step.route().with_key("uses"),
                operation: Op::Replace(serde_yaml::Value::String(new_uses_value)),
            }],
        }
    }

    /// Get the best available fix for a vulnerable action
    fn get_vulnerability_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        _ghsa_id: &str,
        first_patched_version: Option<&str>,
        step: &impl StepCommon<'doc>,
    ) -> Option<Fix<'doc>> {
        // Use the first patched version from the advisory if available
        first_patched_version.map(|version| Self::create_upgrade_fix(uses, version, step))
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

            // Add fix if available
            if let Some(fix) =
                self.get_vulnerability_fix(uses, &id, first_patched_version.as_deref(), step)
            {
                finding_builder = finding_builder.fix(fix);
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
        self.process_step(step)
    }

    fn audit_composite_step<'doc>(&self, step: &CompositeStep<'doc>) -> Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{AsDocument, workflow::Workflow},
        registry::InputKey,
    };

    #[test]
    fn test_fix_creation_basic() {
        // Test fix creation function directly
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v2".to_string()),
            subpath: None,
        };

        let key = InputKey::local("test.yml", None::<&str>).unwrap();
        let workflow_content = r#"
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
"#;
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v4", step);

        assert_eq!(fix.title, "upgrade actions/checkout to v4");
        assert_eq!(fix.patches.len(), 1);

        // Test that the patch operation is correct
        match &fix.patches[0].operation {
            Op::Replace(value) => {
                assert_eq!(value.as_str().unwrap(), "actions/checkout@v4");
            }
            _ => panic!("Expected Replace operation"),
        }
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

        let key = InputKey::local("test_checkout.yml", None::<&str>).unwrap();
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
            git_ref: Some("v2".to_string()),
            subpath: None,
        };

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v4", step);
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

        let key = InputKey::local("test_setup_node.yml", None::<&str>).unwrap();
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
            git_ref: Some("v1".to_string()),
            subpath: None,
        };

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v4", step);
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

        let key = InputKey::local("test_third_party.yml", None::<&str>).unwrap();
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
            git_ref: Some("v1".to_string()),
            subpath: None,
        };

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v4", step);
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

        let key = InputKey::local("test_multiple.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };

        // Apply fixes to each vulnerable action
        let mut current_document = workflow.as_document().clone();

        // Fix checkout action
        let uses_checkout = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v2".to_string()),
            subpath: None,
        };
        let fix_checkout =
            KnownVulnerableActions::create_upgrade_fix(&uses_checkout, "v4", &steps[0]);
        current_document = fix_checkout.apply(&current_document).unwrap();

        // Fix setup-node action
        let uses_node = RepositoryUses {
            owner: "actions".to_string(),
            repo: "setup-node".to_string(),
            git_ref: Some("v1".to_string()),
            subpath: None,
        };
        let fix_node = KnownVulnerableActions::create_upgrade_fix(&uses_node, "v4", &steps[1]);
        current_document = fix_node.apply(&current_document).unwrap();

        // Fix cache action
        let uses_cache = RepositoryUses {
            owner: "actions".to_string(),
            repo: "cache".to_string(),
            git_ref: Some("v2".to_string()),
            subpath: None,
        };
        let fix_cache = KnownVulnerableActions::create_upgrade_fix(&uses_cache, "v4", &steps[2]);
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

        let key = InputKey::local("test_subpath.yml", None::<&str>).unwrap();
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
            git_ref: Some("v1".to_string()),
            subpath: Some("subpath".to_string()),
        };

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v2", step);
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test Action with Subpath
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Custom action
                uses: owner/repo@v2
                with:
                  param: value
        "#);
    }

    #[test]
    fn test_fix_upgrade_action_without_version() {
        let workflow_content = r#"
name: Test Action Without Version
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Action without version
        uses: actions/checkout
"#;

        let key = InputKey::local("test_no_version.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let job = workflow.jobs().next().unwrap();
        let steps: Vec<_> = match job {
            crate::models::workflow::Job::NormalJob(normal_job) => normal_job.steps().collect(),
            _ => panic!("Expected normal job"),
        };
        let step = &steps[0];

        // Test the fix for action without version
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: None,
            subpath: None,
        };

        let fix = KnownVulnerableActions::create_upgrade_fix(&uses, "v4", step);
        let fixed_document = fix.apply(workflow.as_document()).unwrap();

        insta::assert_snapshot!(fixed_document.source(), @r#"
        name: Test Action Without Version
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Action without version
                uses: actions/checkout@v4
        "#);
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

        let key = InputKey::local("test_first_patched.yml", None::<&str>).unwrap();
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
            git_ref: Some("v2".to_string()),
            subpath: None,
        };

        // Test that when first_patched_version is provided, it's used
        let fix_with_patched_version =
            KnownVulnerableActions::create_upgrade_fix(&uses, "v3.1.0", step);
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
}
