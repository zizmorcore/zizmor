use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::audit::AuditError;
use crate::config::{Config, UsesPolicy};
use crate::finding::location::{Locatable, Routable};
use crate::finding::{Confidence, Finding, Fix, Persona, Severity};
use crate::github;
use crate::models::uses::{RepositoryUsesExt, RepositoryUsesPattern};
use crate::models::workflow::ReusableWorkflowCallJob;
use crate::models::{
    AsDocument, StepCommon, action::CompositeStep, uses::UsesExt as _, workflow::Step,
};

pub(crate) struct UnpinnedUses {
    client: Option<github::Client>,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    async fn attempt_fix<'a, 'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        uses: &Uses,
    ) -> Option<Fix<'doc>> {
        // We need to be online to attempt fixes for this audit.
        let client = self.client.as_ref()?;

        // We can only fix repository uses for now.
        let Uses::Repository(uses) = uses else {
            return None;
        };

        // There's nothing to fix if the ref is already a commit SHA.
        if uses.ref_is_commit() {
            return None;
        }

        let commit = match client
            .commit_for_ref(uses.owner(), uses.repo(), uses.git_ref())
            .await
        {
            Ok(Some(commit)) => commit,
            Ok(None) => {
                tracing::warn!("no commit matching {uses}");
                return None;
            }
            Err(e) => {
                // TODO: hard-fail here instead?
                tracing::warn!(
                    "failed to look up commit for {uses}: {e}",
                    uses = uses.raw()
                );
                return None;
            }
        };

        // For the fix itself, we need to situate two patches:
        // 1. `uses: foo/bar@ref` -> `uses: foo/bar@hashhashhash`
        // 2. A `# <ref>` comment following the `uses:` clause.
        Some(Fix {
            title: format!("pin {slug}@{ref} to {commit}", slug = uses.slug(), ref = uses.git_ref()),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![
                Patch {
                    route: parent.route().with_key("uses"),
                    operation: Op::Replace(format!("{slug}@{commit}", slug = uses.slug()).into()),
                },
                Patch {
                    route: parent.route().with_key("uses"),
                    operation: Op::EmplaceComment {
                        new: format!("# {ref}", ref = uses.git_ref()).into(),
                    },
                },
            ],
        })
    }

    async fn evaluate_pinning<'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        uses: &'doc Uses,
        config: &Config,
    ) -> Option<(String, Severity, Persona, Option<Fix<'doc>>)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            // TODO: auditor-level findings instead, perhaps?
            Uses::Local(_) => None,
            // We don't have detailed policies for `uses: docker://` yet,
            // in part because evaluating the risk of a tagged versus hash-pinned
            // Docker image depends on the image and its registry).
            //
            // Instead, we produce a blanket finding for unpinned images,
            // and a pedantic-only finding for unhashed images.
            Uses::Docker(_) => {
                if uses.unpinned() {
                    Some((
                        "image is not pinned to a tag, branch, or hash ref".into(),
                        Severity::Medium,
                        Persona::default(),
                        None,
                    ))
                } else if uses.unhashed() {
                    Some((
                        "action is not pinned to a hash".into(),
                        Severity::Low,
                        Persona::Pedantic,
                        None,
                    ))
                } else {
                    None
                }
            }
            Uses::Repository(repo_uses) => {
                let (pattern, policy) = config.unpinned_uses_policies.get_policy(repo_uses);

                let pat_desc = match pattern {
                    Some(RepositoryUsesPattern::Any) | None => "blanket".into(),
                    Some(RepositoryUsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(RepositoryUsesPattern::InRepo { owner, repo }) => {
                        format!("{owner}/{repo}/*")
                    }
                    Some(RepositoryUsesPattern::ExactRepo { owner, repo }) => {
                        format!("{owner}/{repo}")
                    }
                    Some(RepositoryUsesPattern::ExactPath {
                        owner,
                        repo,
                        subpath,
                    }) => {
                        format!("{owner}/{repo}/{subpath}")
                    }
                    // Not allowed in this audit.
                    Some(RepositoryUsesPattern::ExactWithRef { .. }) => unreachable!(),
                };

                match policy {
                    UsesPolicy::Any => None,
                    UsesPolicy::RefPin => uses.unpinned().then_some((
                        format!(
                            "action is not pinned to a ref or hash (required by {pat_desc} policy)"
                        ),
                        Severity::High,
                        Persona::default(),
                        self.attempt_fix(parent, uses).await,
                    )),
                    UsesPolicy::HashPin => uses.unhashed().then_some((
                        format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                        Severity::High,
                        Persona::default(),
                        self.attempt_fix(parent, uses).await,
                    )),
                }
            }
        }
    }

    async fn process_uses<'a, 'doc, S>(
        &self,
        uses: &'doc Uses,
        parent: &'a S,
        config: &Config,
    ) -> Result<Option<Finding<'doc>>, AuditError>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        let Some((annotation, severity, persona, fix)) =
            self.evaluate_pinning(parent, uses, config).await
        else {
            return Ok(None);
        };

        let mut builder = Self::finding()
            .confidence(Confidence::High)
            .severity(severity)
            .persona(persona)
            .add_location(
                parent
                    .location()
                    .primary()
                    .with_keys(["uses".into()])
                    .subfeature(Subfeature::new(0, uses.raw()))
                    .annotated(annotation),
            );

        if let Some(fix) = fix {
            builder = builder.fix(fix);
        }

        Ok(Some(builder.build(parent)?))
    }

    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        Ok(self
            .process_uses(uses, step, config)
            .await?
            .into_iter()
            .collect())
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedUses {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self {
            client: state.gh_client.clone(),
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config).await
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step, config).await
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(self
            .process_uses(&job.uses, job, config)
            .await?
            .into_iter()
            .collect())
    }
}

#[cfg(feature = "gh-token-tests")]
#[cfg(test)]
mod tests {
    use crate::audit::unpinned_uses::UnpinnedUses;
    use crate::audit::{Audit as _, AuditCore as _};
    use crate::config::Config;
    use crate::github;
    use crate::{
        models::{AsDocument, workflow::Workflow},
        registry::input::InputKey,
    };

    #[tokio::test]
    async fn test_fix() {
        let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with ref-pin
        uses: actions/checkout@v6.0.1
"#;

        let key = InputKey::local("fakegroup".into(), "test_unpinned_uses.yml", None::<&str>);
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

        let audit = UnpinnedUses::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(UnpinnedUses::ident(), &input, &Config::default())
            .await
            .unwrap();

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @r"

        name: Test
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout with ref-pin
                uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        ");
    }

    #[tokio::test]
    async fn test_fix_crlf() {
        let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with ref-pin
        uses: actions/checkout@v6.0.1
"#;

        let workflow_content = workflow_content.replace("\n", "\r\n");

        let key = InputKey::local("fakegroup".into(), "test_unpinned_uses.yml", None::<&str>);
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

        let audit = UnpinnedUses::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(UnpinnedUses::ident(), &input, &Config::default())
            .await
            .unwrap();

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @r"

        name: Test
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout with ref-pin
                uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        ");
    }

    #[tokio::test]
    async fn test_fix_overwrites_comment() {
        let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
    test:
        runs-on: ubuntu-latest
        steps:
        - name: Checkout with ref-pin
          uses: actions/checkout@v6.0.1 # old comment
"#;

        let key = InputKey::local(
            "fakegroup".into(),
            "test_unpinned_uses_overwrites_comment.yml",
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

        let audit = UnpinnedUses::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit
            .audit(UnpinnedUses::ident(), &input, &Config::default())
            .await
            .unwrap();

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @r"

        name: Test
        on: push
        permissions: {}
        jobs:
            test:
                runs-on: ubuntu-latest
                steps:
                - name: Checkout with ref-pin
                  uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        ");
    }

    #[tokio::test]
    async fn test_fix_bizarre_formatting() {
        let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      -
        uses: actions/checkout@v6.0.1
"#;

        let key = InputKey::local("fakegroup".into(), "test_unpinned_uses.yml", None::<&str>);
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

        let audit = UnpinnedUses::new(&state).unwrap();

        let input = workflow.into();
        let findings = audit
            .audit(UnpinnedUses::ident(), &input, &Config::default())
            .await
            .unwrap();

        let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
        insta::assert_snapshot!(new_doc.source(), @r"

        name: Test
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              -
                uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        ");
    }

    #[tokio::test]
    async fn test_no_fix_for_already_pinned() {
        let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
        - name: Checkout with commit pin
          uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
"#;

        let key = InputKey::local(
            "fakegroup".into(),
            "test_no_fix_for_already_pinned.yml",
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

        let audit = UnpinnedUses::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit
            .audit(UnpinnedUses::ident(), &input, &Config::default())
            .await
            .unwrap();

        assert!(findings.is_empty());
    }
}
