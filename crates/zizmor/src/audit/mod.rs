//! Core namespace for zizmor's audits.

use thiserror::Error;
use tracing::instrument;
use yamlpath::Document;

use crate::{
    config::Config,
    finding::{Finding, FindingBuilder, location::SymbolicLocation},
    models::{
        AsDocument,
        action::{Action, CompositeStep},
        dependabot::Dependabot,
        workflow::{Job, NormalJob, ReusableWorkflowCallJob, Step, Workflow},
    },
    registry::input::InputKey,
    state::AuditState,
};

pub(crate) mod anonymous_definition;
pub(crate) mod archived_uses;
pub(crate) mod artipacked;
pub(crate) mod bot_conditions;
pub(crate) mod cache_poisoning;
pub(crate) mod concurrency_limits;
pub(crate) mod dangerous_triggers;
pub(crate) mod dependabot_cooldown;
pub(crate) mod dependabot_execution;
pub(crate) mod excessive_permissions;
pub(crate) mod forbidden_uses;
pub(crate) mod github_env;
pub(crate) mod hardcoded_container_credentials;
pub(crate) mod impostor_commit;
pub(crate) mod insecure_commands;
pub(crate) mod known_vulnerable_actions;
pub(crate) mod obfuscation;
pub(crate) mod overprovisioned_secrets;
pub(crate) mod ref_confusion;
pub(crate) mod ref_version_mismatch;
pub(crate) mod secrets_inherit;
pub(crate) mod self_hosted_runner;
pub(crate) mod stale_action_refs;
pub(crate) mod template_injection;
pub(crate) mod undocumented_permissions;
pub(crate) mod unpinned_images;
pub(crate) mod unpinned_uses;
pub(crate) mod unredacted_secrets;
pub(crate) mod unsound_condition;
pub(crate) mod unsound_contains;
pub(crate) mod use_trusted_publishing;

#[derive(Debug)]
pub(crate) enum AuditInput {
    Workflow(Workflow),
    Action(Action),
    Dependabot(Dependabot),
}

impl AuditInput {
    pub(crate) fn key(&self) -> &InputKey {
        match self {
            AuditInput::Workflow(workflow) => &workflow.key,
            AuditInput::Action(action) => &action.key,
            AuditInput::Dependabot(dependabot) => &dependabot.key,
        }
    }

    pub(crate) fn link(&self) -> Option<&str> {
        match self {
            AuditInput::Workflow(workflow) => workflow.link.as_deref(),
            AuditInput::Action(action) => action.link.as_deref(),
            AuditInput::Dependabot(dependabot) => dependabot.link.as_deref(),
        }
    }

    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        match self {
            AuditInput::Workflow(workflow) => workflow.location(),
            AuditInput::Action(action) => action.location(),
            AuditInput::Dependabot(dependabot) => dependabot.location(),
        }
    }
}

impl<'a> AsDocument<'a, 'a> for AuditInput {
    fn as_document(&'a self) -> &'a Document {
        match self {
            AuditInput::Workflow(workflow) => workflow.as_document(),
            AuditInput::Action(action) => action.as_document(),
            AuditInput::Dependabot(dependabot) => dependabot.as_document(),
        }
    }
}

impl From<Workflow> for AuditInput {
    fn from(value: Workflow) -> Self {
        Self::Workflow(value)
    }
}

impl From<Action> for AuditInput {
    fn from(value: Action) -> Self {
        Self::Action(value)
    }
}

impl From<Dependabot> for AuditInput {
    fn from(value: Dependabot) -> Self {
        Self::Dependabot(value)
    }
}

/// A supertrait for all audits.
///
/// Workflow audits, action audits, and all future audit types
/// must derive this trait, either manually or via the [`audit_meta`]
/// macro.
pub(crate) trait AuditCore {
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
/// ```no_run
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
pub(crate) enum AuditLoadError {
    /// The audit's initialization failed in a way that suggests it should
    /// be skipped, rather than failing the entire run.
    #[error("{0}")]
    Skip(anyhow::Error),
}

#[derive(Error, Debug)]
#[error("error in '{ident}' audit")]
pub(crate) struct AuditError {
    ident: &'static str,
    source: anyhow::Error,
}

impl AuditError {
    pub(crate) fn new(ident: &'static str, error: impl Into<anyhow::Error>) -> Self {
        Self {
            ident,
            source: error.into(),
        }
    }

    pub(crate) fn ident(&self) -> &'static str {
        self.ident
    }
}

/// Auditing trait.
///
/// Implementors of this trait can choose the level of specificity/context
/// they need for workflows and/or action definitions:
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
/// 1. [`Audit::audit_action`]: runs at the top of the action (most general)
/// 2. [`Audit::audit_composite_step`]: runs on each composite step within the
///    action (most specific)
///
/// For both:
///
/// 1. [`Audit::audit_raw`]: runs on the raw, unparsed YAML document source
///
/// Picking a higher specificity means that the lower methods are shadowed.
/// In other words, if an audit chooses to implement [`Audit::audit`], it should implement
/// **only** [`Audit::audit`] and not [`Audit::audit_normal_job`] or
/// [`Audit::audit_step`].
#[async_trait::async_trait]
pub(crate) trait Audit: AuditCore {
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

    async fn audit_raw<'doc>(
        &self,
        _input: &'doc AuditInput,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(vec![])
    }

    /// The top-level auditing function for both workflows and actions.
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
        }?;

        results.extend(self.audit_raw(input, config).await?);

        Ok(results)
    }
}
