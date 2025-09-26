use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use github_actions_models::common::Uses;
use regex::Regex;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditLoadError, AuditState, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Severity,
        location::{Comment, Feature, Location},
    },
    github_api,
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesExt, workflow::Step},
};

pub(crate) struct RefVersionMismatch {
    client: github_api::Client,
}

audit_meta!(
    RefVersionMismatch,
    "ref-version-mismatch",
    "detects commit SHAs that don't match their version comment tags"
);

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

    fn audit_step_common<'doc, S: StepCommon<'doc>>(
        &self,
        step: &S,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
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
            .concretize(step.document())?;

        let Some(version_from_comment) =
            self.extract_version_from_comments(&uses_location.concrete.comments)
        else {
            return Ok(findings);
        };

        let Some(commit_for_ref) =
            self.client
                .commit_for_ref(&uses.owner, &uses.repo, version_from_comment)?
        else {
            // TODO(ww): Does it make sense to flag this as well?
            // This indicates a completely bogus version comment,
            // rather than a mismatch.
            return Ok(findings);
        };

        if commit_for_ref != commit_sha {
            tracing::warn!("{commit_for_ref} != {commit_sha}");

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

            if let Some(suggestion) =
                self.client
                    .longest_tag_for_commit(&uses.owner, &uses.repo, commit_sha)?
            {
                builder = builder.add_location(
                    uses_location
                        .symbolic
                        .annotated(format!("is pointed to by tag {tag}", tag = suggestion.name)),
                );
            }
            findings.push(builder.build(step)?);
        }

        Ok(findings)
    }
}

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

    fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.audit_step_common(step)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.audit_step_common(step)
    }
}
