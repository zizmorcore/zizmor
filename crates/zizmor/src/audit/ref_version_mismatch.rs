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
        Confidence, Finding, Fix, Persona, Severity,
        location::{Feature, Location, Routable},
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
    "action's hash pin has mismatched or missing version comment"
);

#[allow(clippy::unwrap_used)]
static VERSION_COMMENT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Matches "# tag=v2.8.0", "# tag=v6-beta", or any non-whitespace tag token.
        Regex::new(r"#\s*tag\s*=\s*(\S+)").unwrap(),
        // Matches "# v2.8.0" and prerelease forms like "# v1.2.3-rc.1", with or without the `v` suffix.
        Regex::new(r"#\s*(v?\d+(?:\.\d+)*(?:-?[\w.-]+)?)").unwrap(),
        // More flexible: "# version: 2.8.0"
        Regex::new(r"#\s*(?:version|ver)\s*[:=]\s*(v?\d+(?:\.\d+)*(?:-?[\w.-]+)?)").unwrap(),
    ]
});

impl RefVersionMismatch {
    fn extract_version_from_comment(comment: &str) -> Option<&str> {
        for pattern in VERSION_COMMENT_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(comment)
                && let Some(version_match) = captures.get(1)
            {
                return Some(version_match.as_str());
            }
        }
        None
    }

    /// Create a Fix for updating the version comment to match the pinned hash
    fn update_version_comment_fix<'doc, S: StepCommon<'doc>>(
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

    /// Create a Fix for adding a version comment where none exists
    fn add_version_comment_fix<'doc, S: StepCommon<'doc>>(step: &S, tag: &str) -> Fix<'doc> {
        Fix {
            title: format!("add version comment: {tag}"),
            key: step.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: step.route().with_key("uses"),
                operation: Op::EmplaceComment {
                    new: format!("# {tag}").into(),
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

        let comments = &uses_location.concrete.comments;

        // Try each comment as a potential ref candidate.
        // Track the first mismatch: (ref_candidate, resolved_commit).
        let mut first_mismatch: Option<(&str, Option<String>)> = None;

        for comment in comments {
            if !comment.is_meaningful() {
                continue;
            }

            // Prefer the regex-extracted version since there is a greater chance of intent.
            let (candidate, regex_matched) =
                match Self::extract_version_from_comment(comment.as_ref()) {
                    Some(version) => (version, true),
                    None => (
                        comment
                            .as_ref()
                            .strip_prefix('#')
                            .unwrap_or(comment.as_ref())
                            .trim(),
                        false,
                    ),
                };

            let commit = self
                .client
                .commit_for_ref(uses.owner(), uses.repo(), candidate)
                .await
                .map_err(Self::err)?;

            if commit.as_deref() == Some(commit_sha) {
                return Ok(findings);
            }

            if first_mismatch.is_none() && (regex_matched || commit.is_some()) {
                first_mismatch = Some((candidate, commit));
            }
        }

        if let Some((ref_candidate, commit_for_ref)) = first_mismatch {
            let subfeature = Subfeature::new(
                uses_location.concrete.location.offset_span.end,
                ref_candidate,
            );

            let annotation = match &commit_for_ref {
                Some(sha) => format!("points to commit {}", &sha[..12]),
                None => "points to unknown ref".into(),
            };

            let comment_location = Location::new(
                uses_location
                    .symbolic
                    .clone()
                    .primary()
                    .annotated(annotation),
                Feature::from_subfeature(&subfeature, step),
            );

            let mut builder = Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .add_raw_location(comment_location);

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
                builder = builder.fix(self.update_version_comment_fix(step, &suggestion.name));
            }

            findings.push(builder.build(step).map_err(Self::err)?);
            return Ok(findings);
        }

        // Could not resolve any comments to a SHA, so treat as missing version comments
        let Some(tag) = self
            .client
            .longest_tag_for_commit(uses.owner(), uses.repo(), commit_sha)
            .await
            .map_err(Self::err)?
        else {
            return Ok(findings);
        };

        let (annotation, tip, fix) = if comments.is_empty() {
            (
                "missing version comment",
                format!("add version comment '# {}'", tag.name),
                Some(Self::add_version_comment_fix(step, &tag.name)),
            )
        } else {
            (
                "comment does not contain a version",
                format!("rewrite comment to include '# {}'", tag.name),
                None,
            )
        };

        let mut builder = Self::finding()
            .severity(Severity::Low)
            .confidence(Confidence::High)
            .persona(Persona::Pedantic)
            .add_location(uses_location.symbolic.primary().annotated(annotation))
            .tip(tip);

        if let Some(fix) = fix {
            builder = builder.fix(fix);
        }

        findings.push(builder.build(step).map_err(Self::err)?);

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
    use crate::{
        finding::location::Locatable,
        models::{AsDocument, action::Action},
        registry::input::InputKey,
    };

    #[cfg(feature = "gh-token-tests")]
    use crate::{config::Config, models::workflow::Workflow};

    #[cfg(feature = "gh-token-tests")]
    fn workflow_from_string(workflow_content: &str, path: &str) -> Workflow {
        let key = InputKey::local("fakegroup".into(), path, None::<&str>);
        Workflow::from_string(workflow_content.to_string(), key).unwrap()
    }

    #[cfg(feature = "gh-token-tests")]
    fn audit_state() -> crate::state::AuditState {
        crate::state::AuditState::new(
            false,
            Some(
                github::Client::new(
                    &github::GitHubHost::default(),
                    &github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        )
    }

    #[test]
    fn test_version_comment_patterns() {
        let test_cases = vec![
            ("# tag=v2.8.0", Some("v2.8.0")),
            ("# tag=v6-beta", Some("v6-beta")),
            ("# tag=v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# tag=v1.2.3rc.1", Some("v1.2.3rc.1")),
            ("# tag=v6-beta-2", Some("v6-beta-2")),
            ("# tag=release-2024-01", Some("release-2024-01")),
            ("# v2.8.0", Some("v2.8.0")),
            ("# v6-beta", Some("v6-beta")),
            ("# v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# v1.2.3rc1", Some("v1.2.3rc1")),
            ("# v6-beta-2", Some("v6-beta-2")),
            ("# v1.0.0-rc-1", Some("v1.0.0-rc-1")),
            ("# v2.0-preview-3", Some("v2.0-preview-3")),
            ("# tag=2.8.0", Some("2.8.0")),
            ("# version: 2.8.0", Some("2.8.0")),
            ("# version: v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# version: v1.2.3rc.1", Some("v1.2.3rc.1")),
            ("# version: v6-beta-2", Some("v6-beta-2")),
            ("# version: v1.0.0-rc-1", Some("v1.0.0-rc-1")),
            ("# ver=1.0.0", Some("1.0.0")),
            ("# visit the docs", None),
            ("# some other comment", None),
        ];

        for (comment, expected) in test_cases {
            assert_eq!(
                RefVersionMismatch::extract_version_from_comment(comment),
                expected,
                "failed for comment: {comment}",
            );
        }
    }

    #[test]
    fn test_unrelated_comment_is_not_a_version() {
        let action_content = r#"
name: Test Missing Version Comment
description: Test Missing Version Comment
runs:
  using: composite
  steps:
    - name: Checkout with unrelated comment
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # some comment
"#;

        let key = InputKey::local("fakegroup".into(), "action.yml", None::<&str>);
        let action = Action::from_string(action_content.to_string(), key).unwrap();
        let step = action.steps().unwrap().next().unwrap();
        let uses_location = step
            .location()
            .with_keys(["uses".into()])
            .concretize(step.document())
            .unwrap();

        let comment = &uses_location.concrete.comments[0];
        assert_eq!(
            RefVersionMismatch::extract_version_from_comment(comment.as_ref()),
            None,
        );
    }

    #[test]
    fn test_add_version_comment_fix_for_composite_action() {
        let action_content = r#"
name: Test Missing Version Comment
description: Test Missing Version Comment
runs:
  using: composite
  steps:
    - name: Checkout without version comment
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"#;

        let key = InputKey::local("fakegroup".into(), "action.yml", None::<&str>);
        let action = Action::from_string(action_content.to_string(), key).unwrap();
        let step = action.steps().unwrap().next().unwrap();

        let fix = RefVersionMismatch::add_version_comment_fix(&step, "v4.2.2");
        let new_doc = fix.apply(action.as_document()).unwrap();

        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Missing Version Comment
        description: Test Missing Version Comment
        runs:
          using: composite
          steps:
            - name: Checkout without version comment
              uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_version_comment_mismatch() {
        let workflow_content = r#"
name: Test Version Comment Mismatch
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with mismatched version comment
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
"#;

        let workflow = workflow_from_string(workflow_content, "test_version_mismatch.yml");

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        // We expect at least one finding if there's a version mismatch
        assert!(!findings.is_empty(), "Expected to find version mismatch");

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Version Comment Mismatch
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout with mismatched version comment
                uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_missing_version_comment() {
        let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout without version comment
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"#;
        let workflow = workflow_from_string(&workflow_content, "test_missing_version_comment.yml");

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        // We expect a finding for the missing version comment
        assert!(
            !findings.is_empty(),
            "Expected to find missing version comment"
        );

        // The fix should add a version comment via EmplaceComment
        assert!(!findings[0].fixes.is_empty(), "Expected an auto-fix");

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Missing Version Comment
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout without version comment
                uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_missing_version_comment_crlf() {
        let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout without version comment
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"#
        .replace('\n', "\r\n");

        let workflow =
            workflow_from_string(&workflow_content, "test_missing_version_comment_crlf.yml");

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(
            !findings.is_empty(),
            "Expected to find missing version comment"
        );
        assert!(!findings[0].fixes.is_empty(), "Expected an auto-fix");

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Missing Version Comment
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout without version comment
                uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_missing_version_comment_bizarre_formatting() {
        let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      -
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"#;

        let workflow = workflow_from_string(
            &workflow_content,
            "test_missing_version_comment_bizarre_formatting.yml",
        );

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(
            !findings.is_empty(),
            "Expected to find missing version comment"
        );
        assert!(!findings[0].fixes.is_empty(), "Expected an auto-fix");

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Missing Version Comment
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              -
                uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_missing_version_comment_without_tag_has_no_finding() {
        let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout without version comment
        uses: actions/checkout@631c7dc4f80f88219c5ee78fee08c6b62fac8da1
"#;

        let workflow = workflow_from_string(
            &workflow_content,
            "test_missing_version_comment_without_tag.yml",
        );

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(
            findings.is_empty(),
            "Expected no finding for a commit with no matching tag"
        );
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_missing_version_comment_with_unrelated_comment_has_no_fix() {
        let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with unrelated comment
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # some comment
"#;

        let workflow = workflow_from_string(
            &workflow_content,
            "test_missing_version_comment_with_unrelated_comment.yml",
        );

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(
            !findings.is_empty(),
            "Expected to find missing version comment"
        );
        assert!(
            findings[0].fixes.is_empty(),
            "Expected no auto-fix when an unrelated comment already exists"
        );
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_version_comment_different_formats() {
        let workflow_content = r#"
name: Test Different Version Formats
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Tag format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # tag=v3.0.0
      - name: Simple format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
      - name: Version format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # version: v3.0.0
"#;

        let workflow = workflow_from_string(workflow_content, "test_different_formats.yml");

        let state = audit_state();
        let audit = RefVersionMismatch::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(RefVersionMismatch::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(!findings.is_empty(), "Expected to find version mismatch");

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        let new_doc = findings[1].fixes[0].apply(&new_doc).unwrap();
        let new_doc = findings[2].fixes[0].apply(&new_doc).unwrap();

        insta::assert_snapshot!(new_doc.source(), @"

        name: Test Different Version Formats
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Tag format
                uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
              - name: Simple format
                uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
              - name: Version format
                uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
        ");
    }

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_fix_nonexistent_ref() {
        use crate::config::Config;
        use crate::{
            models::{AsDocument, workflow::Workflow},
            registry::input::InputKey,
        };

        let workflow_content = r#"
            name: nonexistent

            on:
              push:

            permissions: {}

            jobs:
              test:
                name: test
                runs-on: ubuntu-latest
                steps:
                  - name: Setup Go
                    uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
        "#;

        let key = InputKey::local("fakegroup".into(), "test_nonexistent_ref.yml", None::<&str>);
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
        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @"

        name: nonexistent

        on:
          push:

        permissions: {}

        jobs:
          test:
            name: test
            runs-on: ubuntu-latest
            steps:
              - name: Setup Go
                uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v6.4.0
        ");
    }
}
