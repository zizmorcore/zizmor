use anyhow::anyhow;
use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, AuditState, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Comment, Feature, Location, Routable as _},
    },
    github,
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesExt as _, workflow::Step},
    utils::once::static_regex,
};

pub(crate) struct RefVersionMismatch {
    client: github::Client,
}

audit_meta!(
    RefVersionMismatch,
    "ref-version-mismatch",
    "action's hash pin has mismatched or missing version comment"
);

static_regex!(
    VERSION_COMMENT_PATTERN,
    r#"(?x)                             # verbose mode
    ^                                   # start of string
    \#                                  # start of comment
    \s*                                 # optional whitespace
    (?:                                 # start non-capturing group for version prefix
      (?:tag|version|ver)\s*[:=]\s*     # version prefix + `:` or `=`
    )?                                  # end optional non-capturing group
    (                                   # start capturing group for version
      \S+                               # one or more non-whitespace characters
    )                                   # end capturing group for version
    $                                   # end of string
    "#
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommentVersionState<'doc> {
    Missing,
    Version(&'doc str),
    NonVersionComments,
}

impl RefVersionMismatch {
    fn extract_version_from_comments<'doc>(comments: &'doc [Comment<'doc>]) -> Option<&'doc str> {
        for comment in comments {
            if let Some(captures) = VERSION_COMMENT_PATTERN.captures(comment.as_ref())
                && let Some(version_match) = captures.get(1)
            {
                return Some(version_match.as_str());
            }
        }
        None
    }

    fn comment_version_state<'doc>(comments: &'doc [Comment<'doc>]) -> CommentVersionState<'doc> {
        match Self::extract_version_from_comments(comments) {
            Some(version) => CommentVersionState::Version(version),
            None if comments.is_empty() => CommentVersionState::Missing,
            None => CommentVersionState::NonVersionComments,
        }
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

        let comment_version_state = Self::comment_version_state(&uses_location.concrete.comments);

        let version_from_comment = match comment_version_state {
            CommentVersionState::Version(version) => version,
            CommentVersionState::Missing | CommentVersionState::NonVersionComments => {
                // SHA-pinned action without a recognized version comment.
                let Some(tag) = self
                    .client
                    .longest_tag_for_commit(&uses.into(), commit_sha)
                    .await
                    .map_err(Self::err)?
                else {
                    return Ok(findings);
                };

                let (annotation, tip) = match comment_version_state {
                    CommentVersionState::Missing => (
                        "missing version comment",
                        format!("add version comment '# {}'", tag.name),
                    ),
                    CommentVersionState::NonVersionComments => (
                        "comment does not contain a version",
                        format!("rewrite comment to include '# {}'", tag.name),
                    ),
                    CommentVersionState::Version(_) => unreachable!(),
                };

                let mut builder = Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(step_location.hidden())
                    .add_location(uses_location.symbolic.primary().annotated(annotation))
                    .tip(tip);

                if matches!(comment_version_state, CommentVersionState::Missing) {
                    builder = builder.fix(Self::add_version_comment_fix(step, &tag.name));
                }

                findings.push(builder.build(step).map_err(Self::err)?);
                return Ok(findings);
            }
        };

        let commit_for_ref = self
            .client
            .commit_for_ref(&uses.into(), version_from_comment)
            .await
            .map_err(Self::err)?;

        // If the ref matches, there's nothing to do.
        if commit_for_ref.as_deref() == Some(commit_sha) {
            return Ok(findings);
        }

        let subfeature = Subfeature::new(
            uses_location.concrete.location.offset_span.end,
            version_from_comment,
        );

        let comment_location = match commit_for_ref {
            Some(commit_for_ref) => Location::new(
                uses_location.symbolic.clone().primary().annotated(format!(
                    "points to commit {short_commit}",
                    short_commit = &commit_for_ref[..12]
                )),
                Feature::from_subfeature(&subfeature, step),
            ),
            None => Location::new(
                uses_location
                    .symbolic
                    .clone()
                    .primary()
                    .annotated("points to unknown ref"),
                Feature::from_subfeature(&subfeature, step),
            ),
        };

        let mut builder = Self::finding()
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .add_raw_location(comment_location);

        if let Some(suggestion) = self
            .client
            .longest_tag_for_commit(&uses.into(), commit_sha)
            .await
            .map_err(Self::err)?
        {
            builder = builder.add_location(step_location.hidden()).add_location(
                uses_location
                    .symbolic
                    .annotated(format!("is pointed to by tag {tag}", tag = suggestion.name)),
            );
            // Add auto-fix to update the version comment to match the pinned hash
            builder = builder.fix(self.update_version_comment_fix(step, &suggestion.name));
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
        finding::location::Locatable as _, models::action::Action, registry::input::InputKey,
    };

    #[test]
    fn test_version_comment_pattern() {
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
            ("# zizmor: ignore[ref-version-mismatch]", None),
        ];

        for (comment, expected) in test_cases {
            // Test the pattern matching directly
            match (VERSION_COMMENT_PATTERN.captures(comment), expected) {
                (None, None) => (),
                (None, Some(expected)) => {
                    assert!(
                        false,
                        "Got no match in '{comment}', but expected {expected}"
                    )
                }
                (Some(caps), None) => {
                    assert!(false, "Got unexpected match: {caps:?}")
                }
                (Some(_), Some(_)) => (),
            }
        }
    }

    #[test]
    fn test_comment_version_state_with_unrelated_comment() {
        let action_content = r#"
name: Test Missing Version Comment
description: Test Missing Version Comment
runs:
  using: composite
  steps:
    - name: Checkout with unrelated comment
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # some comment
"#;

        let key = InputKey::local("fakegroup".into(), "action.yml", None, None);
        let action = Action::from_string(action_content.to_string(), key).unwrap();
        let step = action.steps().unwrap().next().unwrap();
        let uses_location = step
            .location()
            .with_keys(["uses".into()])
            .concretize(step.document())
            .unwrap();

        assert_eq!(
            RefVersionMismatch::comment_version_state(&uses_location.concrete.comments),
            CommentVersionState::NonVersionComments,
        );
    }
}
