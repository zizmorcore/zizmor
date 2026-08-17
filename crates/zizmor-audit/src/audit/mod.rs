//! Core namespace for zizmor's audits.

use thiserror::Error;
use tracing::instrument;

use zizmor_config::Config;
use zizmor_core::input::AuditInput;

use crate::{
    finding::{Finding, FindingBuilder},
    models::{
        action::{Action, CompositeStep, DockerAction},
        dependabot::Dependabot,
        pre_commit::{self, PreCommitConfig, PreCommitHooks},
        workflow::{Job, NormalJob, ReusableWorkflowCallJob, Step, Workflow},
    },
    state::AuditState,
};

pub mod adhoc_packages;
pub mod anonymous_definition;
pub mod archived_uses;
pub mod artipacked;
pub mod bot_conditions;
pub mod cache_poisoning;
pub mod concurrency_limits;
pub mod dangerous_triggers;
pub mod dependabot_cooldown;
pub mod dependabot_execution;
pub mod excessive_permissions;
pub mod forbidden_uses;
pub mod github_app;
pub mod github_env;
pub mod hardcoded_container_credentials;
pub mod impostor_commit;
pub mod insecure_commands;
pub mod insecure_url_scheme;
pub mod known_vulnerable_actions;
pub mod misfeature;
pub mod obfuscation;
pub mod overprovisioned_secrets;
pub mod ref_confusion;
pub mod ref_version_mismatch;
pub mod secrets_inherit;
pub mod secrets_outside_env;
pub mod self_hosted_runner;
pub mod self_repository;
pub mod stale_action_refs;
pub mod superfluous_actions;
pub mod template_injection;
pub mod typosquat_uses;
pub mod undocumented_permissions;
pub mod unpinned_images;
pub mod unpinned_tools;
pub mod unpinned_uses;
pub mod unredacted_secrets;
pub mod unsound_condition;
pub mod unsound_contains;
pub mod unsound_ternary;
pub mod use_trusted_publishing;

/// A supertrait for all audits.
///
/// Workflow audits, action audits, and all future audit types
/// must derive this trait, either manually or via the [`audit_meta`]
/// macro.
pub trait AuditCore {
    fn ident() -> &'static str
    where
        Self: Sized;

    fn desc() -> &'static str
    where
        Self: Sized;

    fn url() -> &'static str
    where
        Self: Sized;

    fn finding<'doc>() -> FindingBuilder<'doc>
    where
        Self: Sized,
    {
        FindingBuilder::new(Self::ident(), Self::desc(), Self::url())
    }

    fn err(error: impl Into<anyhow::Error>) -> AuditError
    where
        Self: Sized,
    {
        AuditError {
            ident: Self::ident(),
            source: error.into(),
        }
    }
}

/// A convenience macro for implementing [`AuditCore`] on a type.
///
/// Example use:
///
/// ```ignore
/// struct SomeAudit;
///
/// audit_meta!(SomeAudit, "some-audit", "brief description");
/// ```
macro_rules! audit_meta {
    ($t:ty, $id:literal, $desc:expr_2021) => {
        use crate::audit::AuditCore;

        impl AuditCore for $t {
            fn ident() -> &'static str {
                $id
            }

            fn desc() -> &'static str
            where
                Self: Sized,
            {
                $desc
            }

            fn url() -> &'static str {
                concat!("https://docs.zizmor.sh/audits/#", $id)
            }
        }
    };
}

pub(crate) use audit_meta;

#[derive(Error, Debug)]
pub enum AuditLoadError {
    /// The audit's initialization failed in a way that suggests it should
    /// be skipped, rather than failing the entire run.
    #[error("{0}")]
    Skip(anyhow::Error),
}

#[derive(Error, Debug)]
#[error("error in '{ident}' audit")]
pub struct AuditError {
    ident: &'static str,
    source: anyhow::Error,
}

impl AuditError {
    pub fn new(ident: &'static str, error: impl Into<anyhow::Error>) -> Self {
        Self {
            ident,
            source: error.into(),
        }
    }

    pub fn ident(&self) -> &'static str {
        self.ident
    }
}

/// Auditing trait.
///
/// Implementors of this trait can choose the level of specificity/context
/// they need for their kind(s) of input:
///
/// For workflows:
///
/// 1. [`Audit::audit_workflow`]: runs at the top of the workflow (most general)
/// 1. [`Audit::audit_normal_job`] and/or [`Audit::audit_reusable_job`]:
///    runs on each normal/reusable job definition
/// 1. [`Audit::audit_step`]: runs on each step within each normal job (most specific)
///
/// For actions:
///
/// 1. [`Audit::audit_docker_action`]: runs at the top of the Docker action (most general)
/// 1. [`Audit::audit_action`]: runs at the top of the composite action (most general)
/// 1. [`Audit::audit_composite_step`]: runs on each composite step within the
///    action (most specific)
///
/// For pre-commit inputs:
///
/// 1. [`Audit::audit_pre_commit_config`]: runs at the top of the pre-commit configuration (most general)
/// 1. [`Audit::audit_pre_commit_hooks`]: runs at the top of the pre-commit hooks definition (most general)
/// 1. [`Audit::audit_pre_commit_config_repo`]: runs on each `repo` definition within the pre-commit
///    configuration
///
/// For all:
///
/// 1. [`Audit::audit_raw`]: runs on the raw, unparsed YAML document source
///
/// Picking a higher specificity means that the lower methods are shadowed.
/// In other words, if an audit chooses to implement [`Audit::audit`], it should implement
/// **only** [`Audit::audit`] and not [`Audit::audit_normal_job`] or
/// [`Audit::audit_step`].
#[async_trait::async_trait]
pub trait Audit: AuditCore {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized;

    async fn audit_step<'doc>(
        &self,
        _step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut results = vec![];
        for step in job.steps() {
            results.extend(self.audit_step(&step, config).await?);
        }
        Ok(results)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        _job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut results = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    results.extend(self.audit_normal_job(&normal, config).await?);
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    results.extend(self.audit_reusable_job(&reusable, config).await?);
                }
            }
        }

        Ok(results)
    }

    async fn audit_docker_action<'doc>(
        &self,
        _docker: &DockerAction<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_composite_step<'doc>(
        &self,
        _step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_action<'doc>(
        &self,
        action: &'doc Action,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut results = vec![];

        if let Some(docker) = action.docker() {
            results.extend(self.audit_docker_action(&docker, config).await?);
        }

        if let Some(steps) = action.steps() {
            for step in steps {
                results.extend(self.audit_composite_step(&step, config).await?);
            }
        }

        Ok(results)
    }

    async fn audit_dependabot<'doc>(
        &self,
        _dependabot: &'doc Dependabot,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_pre_commit_config_repo<'doc>(
        &self,
        _repo: &pre_commit::Repo<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_pre_commit_config<'doc>(
        &self,
        pre_commit: &'doc PreCommitConfig,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut results = vec![];

        for repo in pre_commit.repos() {
            results.extend(self.audit_pre_commit_config_repo(&repo, config).await?);
        }

        Ok(results)
    }

    async fn audit_pre_commit_hooks<'doc>(
        &self,
        _hooks: &'doc PreCommitHooks,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    async fn audit_raw<'doc>(
        &self,
        _input: &'doc AuditInput,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    /// The top-level auditing function for all inputs.
    ///
    /// Implementors **should not** override this blanket implementation,
    /// since it's marked with tracing instrumentation.
    ///
    /// NOTE: This method takes the audit's own identifier as an argument,
    /// so that we can check whether the audit is disabled in the config.
    /// This is a little silly since the audit would ideally call Self::ident(),
    /// but this gets invoked through a trait object where `Self` is not `Sized`.
    ///
    /// TODO: This also means we effectively run the disablement check on every
    /// single input in a group, rather than just once per group.
    #[instrument(skip(self, ident, config))]
    async fn audit<'doc>(
        &self,
        ident: &'static str,
        input: &'doc AuditInput,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        if config.disables(ident) {
            tracing::debug!(
                "skipping: {ident} is disabled in config for group {group:?}",
                group = input.key().group()
            );
            return Ok(vec![]);
        }

        let mut results = match input {
            AuditInput::Workflow(workflow) => self.audit_workflow(workflow, config).await,
            AuditInput::Action(action) => self.audit_action(action, config).await,
            AuditInput::Dependabot(dependabot) => self.audit_dependabot(dependabot, config).await,
            AuditInput::PreCommitConfig(pre_commit) => {
                self.audit_pre_commit_config(pre_commit, config).await
            }
            AuditInput::PreCommitHooks(hooks) => self.audit_pre_commit_hooks(hooks, config).await,
        }?;

        results.extend(self.audit_raw(input, config).await?);

        Ok(results)
    }
}
