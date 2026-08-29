use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, AuditState, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Comment, Feature, Locatable, Location, Routable as _},
    },
    github,
    models::{
        AsDocument, StepCommon,
        action::CompositeStep,
        uses::RepositoryUsesExt as _,
        version::RawVersion,
        workflow::{ReusableWorkflowCallJob, Step},
    },
};

pub(crate) struct RefVersionMismatch {
    client: github::Client,
}

audit_meta!(
    RefVersionMismatch,
    "ref-version-mismatch",
    "action's hash pin has mismatched or missing version comment"
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
            if let Some(version) = RawVersion::from_comment(comment) {
                return Some(version.as_raw());
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
    fn update_version_comment_fix<'a, 'doc, S>(&self, parent: &'a S, correct_tag: &str) -> Fix<'doc>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        Fix {
            title: format!("update version comment to match pinned hash: {correct_tag}"),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: parent.route().with_key("uses"),
                operation: Op::ReplaceComment {
                    new: format!("# {correct_tag}").into(),
                },
            }],
        }
    }

    /// Create a Fix for adding a version comment where none exists
    fn add_version_comment_fix<'a, 'doc, S>(parent: &'a S, tag: &str) -> Fix<'doc>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        Fix {
            title: format!("add version comment: {tag}"),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: parent.route().with_key("uses"),
                operation: Op::EmplaceComment {
                    new: format!("# {tag}").into(),
                },
            }],
        }
    }

    async fn process_uses<'a, 'doc, S>(
        &self,
        uses: &'doc RepositoryUses,
        parent: &'a S,
    ) -> Result<Option<Finding<'doc>>, AuditError>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        // Only check steps that have commit refs (not symbolic refs like v1.0.0)
        let Some(commit_sha) = uses.commit_ref() else {
            return Ok(None);
        };

        let parent_location = parent.location();
        let uses_location = parent_location
            .with_keys(["uses".into()])
            .concretize(parent.as_document())
            .map_err(Self::err)?;

        let comment_version_state = Self::comment_version_state(&uses_location.concrete.comments);

        let version_from_comment = match comment_version_state {
            CommentVersionState::Version(version) => version,
            CommentVersionState::Missing | CommentVersionState::NonVersionComments => {
                // SHA-pinned action without a recognized version comment.
                let Some(tag) = self
                    .client
                    .longest_tag_for_commit(&uses.into(), uses.subpath(), commit_sha)
                    .await
                    .map_err(Self::err)?
                else {
                    return Ok(None);
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
                    .add_location(parent_location.hidden())
                    .add_location(
                        uses_location
                            .symbolic
                            .primary()
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated(annotation),
                    )
                    .tip(tip);

                if matches!(comment_version_state, CommentVersionState::Missing) {
                    builder = builder.fix(Self::add_version_comment_fix(parent, &tag.name));
                }

                // findings.push(builder.build(step).map_err(Self::err)?);
                return Ok(Some(builder.build(parent).map_err(Self::err)?));
            }
        };

        let git_ref = self
            .client
            .lookup_ref(&uses.into(), version_from_comment)
            .await
            .map_err(Self::err)?;

        // If the ref matches, there's nothing to do.
        if git_ref.as_ref().map(|r| r.commit()) == Some(commit_sha) {
            return Ok(None);
        }

        let subfeature = Subfeature::new(
            uses_location.concrete.location.offset_span.end,
            version_from_comment,
        );

        let comment_location = match git_ref {
            Some(commit_for_ref) => Location::new(
                uses_location.symbolic.clone().primary().annotated(format!(
                    "{kind} points to commit {short_commit}",
                    kind = commit_for_ref.kind(),
                    short_commit = &commit_for_ref.commit()[..12]
                )),
                Feature::from_subfeature(&subfeature, parent),
            ),
            None => Location::new(
                uses_location
                    .symbolic
                    .clone()
                    .primary()
                    .annotated("points to unknown ref"),
                Feature::from_subfeature(&subfeature, parent),
            ),
        };

        let mut builder = Self::finding()
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .add_raw_location(comment_location);

        if let Some(suggestion) = self
            .client
            .longest_tag_for_commit(&uses.into(), uses.subpath(), commit_sha)
            .await
            .map_err(Self::err)?
        {
            builder = builder.add_location(parent_location.hidden()).add_location(
                uses_location
                    .symbolic
                    .subfeature(Subfeature::new(0, uses.raw()))
                    .annotated(format!("is pointed to by tag {tag}", tag = suggestion.name)),
            );
            // Add auto-fix to update the version comment to match the pinned hash
            builder = builder.fix(self.update_version_comment_fix(parent, &suggestion.name));
        }

        Ok(Some(builder.build(parent).map_err(Self::err)?))
    }

    async fn process_step<'doc, S: StepCommon<'doc>>(
        &self,
        step: &S,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(None);
        };

        self.process_uses(uses, step).await
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
        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Uses::Repository(uses) = &job.uses else {
            return Ok(vec![]);
        };

        Ok(self.process_uses(uses, job).await?.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{models::action::Action, registry::input::InputKey};

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
