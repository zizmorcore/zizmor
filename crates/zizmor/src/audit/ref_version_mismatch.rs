use std::sync::LazyLock;

use anyhow::anyhow;
use github_actions_models::common::Uses;
use regex::Regex;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, AuditState, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Fix, Severity,
        location::{Comment, Feature, Location, Routable},
    },
    github,
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesExt, workflow::Step},
};

pub(crate) struct RefVersionMismatch {
    client: github::Client,
}

audit_meta!(
    RefVersionMismatch,
    "ref-version-mismatch",
    "detects commit SHAs that don't match their version comment tags"
);

#[allow(clippy::unwrap_used)]
static VERSION_COMMENT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Matches "# tag=v2.8.0" or "# tag=v1.2.3"
        Regex::new(r"#\s*tag\s*=\s*(v\d+(?:\.\d+)*(?:\.\d+)?)").unwrap(),
        // Matches "# v2.8.0"
        Regex::new(r"#\s*(v\d+(?:\.\d+)*(?:\.\d+)?)").unwrap(),
        // Matches version without 'v' prefix: "# tag=2.8.0"
        Regex::new(r"#\s*tag\s*=\s*(\d+(?:\.\d+)*(?:\.\d+)?)").unwrap(),
        // More flexible: "# version: 2.8.0"
        Regex::new(r"#\s*(?:version|ver)\s*[:=]\s*(v?\d+(?:\.\d+)*(?:\.\d+)?)").unwrap(),
    ]
});

impl RefVersionMismatch {
    fn extract_version_from_comments<'doc>(
        &self,
        comments: &'doc [Comment<'doc>],
    ) -> Option<&'doc str> {
        for comment in comments {
            for pattern in VERSION_COMMENT_PATTERNS.iter() {
                if let Some(captures) = pattern.captures(comment.as_ref())
                    && let Some(version_match) = captures.get(1)
                {
                    return Some(version_match.as_str());
                }
            }
        }
        None
    }

    /// Create a Fix for updating the version comment to match the pinned hash
    fn create_version_comment_fix<'doc, S: StepCommon<'doc>>(
        &self,
        step: &S,
        correct_tag: &str,
    ) -> Fix<'doc> {
        Fix {
            title: format!("update version comment to match pinned hash: {correct_tag}"),
            key: step.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: step.route().with_key("uses"),
                operation: Op::ReplaceComment {
                    new: format!("# {correct_tag}").into(),
                },
            }],
        }
    }

    async fn audit_step_common<'doc, S: StepCommon<'doc>>(
        &self,
        step: &S,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        // Only check steps that have commit refs (not symbolic refs like v1.0.0)
        let Some(commit_sha) = uses.commit_ref() else {
            return Ok(findings);
        };

        let step_location = step.location();
        let uses_location = step_location
            .with_keys(["uses".into()])
            .concretize(step.document())
            .map_err(Self::err)?;

        let Some(version_from_comment) =
            self.extract_version_from_comments(&uses_location.concrete.comments)
        else {
            return Ok(findings);
        };

        let Some(commit_for_ref) = self
            .client
            .commit_for_ref(uses.owner(), uses.repo(), version_from_comment)
            .await
            .map_err(Self::err)?
        else {
            // TODO(ww): Does it make sense to flag this as well?
            // This indicates a completely bogus version comment,
            // rather than a mismatch.
            return Ok(findings);
        };

        if commit_for_ref != commit_sha {
            let subfeature = Subfeature::new(
                uses_location.concrete.location.offset_span.end,
                version_from_comment,
            );

            let mut builder = Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .add_raw_location(Location::new(
                    // NOTE(ww): We trim the commit SHA to 12 characters
                    // for display purposes; 12 is a conservative length
                    // that avoids collisions in Linux-sized repositories.
                    uses_location.symbolic.clone().primary().annotated(format!(
                        "points to commit {short_commit}",
                        short_commit = &commit_for_ref[..12]
                    )),
                    Feature::from_subfeature(&subfeature, step),
                ));

            if let Some(suggestion) = self
                .client
                .longest_tag_for_commit(uses.owner(), uses.repo(), commit_sha)
                .await
                .map_err(Self::err)?
            {
                builder = builder.add_location(
                    uses_location
                        .symbolic
                        .annotated(format!("is pointed to by tag {tag}", tag = suggestion.name)),
                );
                // Add auto-fix to update the version comment to match the pinned hash
                builder = builder.fix(self.create_version_comment_fix(step, &suggestion.name));
            }
            findings.push(builder.build(step).map_err(Self::err)?);
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for RefVersionMismatch {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError> {
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
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.audit_step_common(step).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.audit_step_common(step).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comment_patterns() {
        let test_cases = vec![
            ("# tag=v2.8.0", Some("v2.8.0")),
            ("# v2.8.0", Some("v2.8.0")),
            ("# tag=2.8.0", Some("2.8.0")),
            ("# version: 2.8.0", Some("2.8.0")),
            ("# ver=1.0.0", Some("1.0.0")),
            ("# some other comment", None),
        ];

        for (comment, expected) in test_cases {
            // Test the pattern matching directly
            let comment_text = comment;
            let mut found_version = None;
            for pattern in VERSION_COMMENT_PATTERNS.iter() {
                if let Some(captures) = pattern.captures(comment_text) {
                    if let Some(version_match) = captures.get(1) {
                        found_version = Some(version_match.as_str());
                        break;
                    }
                }
            }
            assert_eq!(found_version, expected, "Failed for comment: {}", comment);
        }
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_version_comment_mismatch() {
        use crate::config::Config;
        use crate::{
            models::{AsDocument, workflow::Workflow},
            registry::input::InputKey,
        };

        let workflow_content = r#"
name: Test Version Comment Mismatch
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with mismatched version comment
        uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.0
"#;

        let key = InputKey::local(
            "fakegroup".into(),
            "test_version_mismatch.yml",
            None::<&str>,
        );
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState::new(
            false,
            Some(
                github::Client::new(
                    &github::GitHubHost::default(),
                    &github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        );

        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        // We expect at least one finding if there's a version mismatch
        assert!(!findings.is_empty(), "Expected to find version mismatch");

        // Only test the fix if one is available (depends on GitHub API response)
        if !findings[0].fixes.is_empty() {
            let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
            insta::assert_snapshot!(new_doc.source(), @r"
            name: Test Version Comment Mismatch
            on: push
            permissions: {}
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout with mismatched version comment
                    uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.2
            ");
        }
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_version_comment_different_formats() {
        use crate::config::Config;
        use crate::{
            models::{AsDocument, workflow::Workflow},
            registry::input::InputKey,
        };

        let workflow_content = r#"
name: Test Different Version Formats
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Tag format
        uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # tag=v3.0.0
      - name: Simple format
        uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.0
      - name: Version format
        uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # version: 3.0.0
"#;

        let key = InputKey::local(
            "fakegroup".into(),
            "test_different_formats.yml",
            None::<&str>,
        );
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState::new(
            false,
            Some(
                github::Client::new(
                    &github::GitHubHost::default(),
                    &github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        );

        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(!findings.is_empty(), "Expected to find version mismatch");

        // Only test the fix if one is available (depends on GitHub API response)
        if !findings[0].fixes.is_empty() {
            let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
            insta::assert_snapshot!(new_doc.source(), @r"
            name: Test Different Version Formats
            on: push
            permissions: {}
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - name: Tag format
                    uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.2
                  - name: Simple format
                    uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.0
                  - name: Version format
                    uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # version: 3.0.0
            ");
        }
    }
}
