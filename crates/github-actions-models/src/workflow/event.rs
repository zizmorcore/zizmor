//! Workflow events.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::common::EnvValue;

/// "Bare" workflow event triggers.
///
/// These appear when a workflow is triggered with an event with no context,
/// e.g.:
///
/// ```yaml
/// on: push
/// ```
#[derive(Deserialize, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BareEvent {
    BranchProtectionRule,
    CheckRun,
    CheckSuite,
    Create,
    Delete,
    Deployment,
    DeploymentStatus,
    Discussion,
    DiscussionComment,
    Fork,
    Gollum,
    IssueComment,
    Issues,
    Label,
    MergeGroup,
    Milestone,
    PageBuild,
    Project,
    ProjectCard,
    ProjectColumn,
    Public,
    PullRequest,
    PullRequestComment,
    PullRequestReview,
    PullRequestReviewComment,
    PullRequestTarget,
    Push,
    RegistryPackage,
    Release,
    RepositoryDispatch,
    // NOTE: `schedule` is omitted, since it's never bare.
    Status,
    Watch,
    WorkflowCall,
    WorkflowDispatch,
    WorkflowRun,
}

/// Workflow event triggers, with bodies.
///
/// Like [`BareEvent`], but with per-event properties.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(default, rename_all = "snake_case")]
pub struct Events {
    pub branch_protection_rule: OptionalBody<GenericEvent>,
    pub check_run: OptionalBody<GenericEvent>,
    pub check_suite: OptionalBody<GenericEvent>,
    // NOTE: `create` and `delete` are omitted, since they are always bare.
    // NOTE: `deployment` and `deployment_status` are omitted, since they are always bare.
    pub discussion: OptionalBody<GenericEvent>,
    pub discussion_comment: OptionalBody<GenericEvent>,
    // NOTE: `fork` and `gollum` are omitted, since they are always bare.
    pub issue_comment: OptionalBody<GenericEvent>,
    pub issues: OptionalBody<GenericEvent>,
    pub label: OptionalBody<GenericEvent>,
    pub merge_group: OptionalBody<GenericEvent>,
    pub milestone: OptionalBody<GenericEvent>,
    // NOTE: `page_build` is omitted, since it is always bare.
    pub project: OptionalBody<GenericEvent>,
    pub project_card: OptionalBody<GenericEvent>,
    pub project_column: OptionalBody<GenericEvent>,
    // NOTE: `public` is omitted, since it is always bare.
    pub pull_request: OptionalBody<PullRequest>,
    pub pull_request_comment: OptionalBody<GenericEvent>,
    pub pull_request_review: OptionalBody<GenericEvent>,
    pub pull_request_review_comment: OptionalBody<GenericEvent>,
    // NOTE: `pull_request_target` appears to have the same trigger filters as `pull_request`.
    pub pull_request_target: OptionalBody<PullRequest>,
    pub push: OptionalBody<Push>,
    pub registry_package: OptionalBody<GenericEvent>,
    pub release: OptionalBody<GenericEvent>,
    pub repository_dispatch: OptionalBody<GenericEvent>,
    pub schedule: OptionalBody<Vec<Cron>>,
    // NOTE: `status` is omitted, since it is always bare.
    pub watch: OptionalBody<GenericEvent>,
    pub workflow_call: OptionalBody<WorkflowCall>,
    // TODO: Custom type.
    pub workflow_dispatch: OptionalBody<WorkflowDispatch>,
    pub workflow_run: OptionalBody<WorkflowRun>,
}

impl Events {
    /// Count the number of present event triggers.
    ///
    /// **IMPORTANT**: This must be kept in sync with the number of fields in `Events`.
    pub fn count(&self) -> u32 {
        // This is a little goofy, but it's faster than reflecting over the struct
        // or doing a serde round-trip.
        let mut count = 0;

        macro_rules! count_if_present {
            ($($field:ident),*) => {
                $(
                    if !matches!(self.$field, OptionalBody::Missing) {
                        count += 1;
                    }
                )*
            };
        }

        count_if_present!(
            branch_protection_rule,
            check_run,
            check_suite,
            discussion,
            discussion_comment,
            issue_comment,
            issues,
            label,
            merge_group,
            milestone,
            project,
            project_card,
            project_column,
            pull_request,
            pull_request_comment,
            pull_request_review,
            pull_request_review_comment,
            pull_request_target,
            push,
            registry_package,
            release,
            repository_dispatch,
            schedule,
            watch,
            workflow_call,
            workflow_dispatch,
            workflow_run
        );

        count
    }
}

/// A generic container type for distinguishing between
/// a missing key, an explicitly null key, and an explicit value `T`.
///
/// This is needed for modeling `on:` triggers, since GitHub distinguishes
/// between the non-presence of an event (no trigger) and the presence
/// of an empty event body (e.g. `pull_request:`), which means "trigger
/// with the defaults for this event type."
#[derive(Serialize, Debug, Default)]
pub enum OptionalBody<T> {
    Default,
    #[default]
    Missing,
    Body(T),
}

impl<'de, T> Deserialize<'de> for OptionalBody<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Into::into)
    }
}

impl<T> From<Option<T>> for OptionalBody<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => OptionalBody::Body(v),
            None => OptionalBody::Default,
        }
    }
}

/// A generic event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct GenericEvent {
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
    pub types: Vec<String>,
}

/// The body of a `pull_request` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct PullRequest {
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
    pub types: Vec<String>,

    #[serde(flatten)]
    pub branch_filters: Option<BranchFilters>,

    #[serde(flatten)]
    pub path_filters: Option<PathFilters>,
}

/// The body of a `push` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Push {
    #[serde(flatten)]
    pub branch_filters: Option<BranchFilters>,

    #[serde(flatten)]
    pub path_filters: Option<PathFilters>,

    #[serde(flatten)]
    pub tag_filters: Option<TagFilters>,
}

/// The body of a `cron` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Cron {
    pub cron: String,
}

/// The body of a `workflow_call` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowCall {
    #[serde(default)]
    pub inputs: IndexMap<String, WorkflowCallInput>,
    #[serde(default)]
    pub outputs: IndexMap<String, WorkflowCallOutput>,
    #[serde(default)]
    pub secrets: IndexMap<String, Option<WorkflowCallSecret>>,
}

/// A single input in a `workflow_call` event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowCallInput {
    pub description: Option<String>,
    // TODO: model `default`?
    #[serde(default)]
    pub required: bool,
    pub r#type: String,
}

/// A single output in a `workflow_call` event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowCallOutput {
    pub description: Option<String>,
    pub value: String,
}

/// A single secret in a `workflow_call` event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowCallSecret {
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// The body of a `workflow_dispatch` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowDispatch {
    #[serde(default)]
    pub inputs: IndexMap<String, WorkflowDispatchInput>, // TODO: WorkflowDispatchInput
}

/// A single input in a `workflow_dispatch` event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowDispatchInput {
    pub description: Option<String>,
    // TODO: model `default`?
    #[serde(default)]
    pub required: bool,
    // TODO: Model as boolean, choice, number, environment, string; default is string.
    pub r#type: Option<String>,
    // Only present when `type` is `choice`.
    #[serde(default)]
    pub options: Vec<EnvValue>,
}

/// The body of a `workflow_run` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowRun {
    pub workflows: Vec<String>,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(flatten)]
    pub branch_filters: Option<BranchFilters>,
}

/// Branch filtering variants for event trigger bodies.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum BranchFilters {
    Branches(Vec<String>),
    BranchesIgnore(Vec<String>),
}

/// Tag filtering variants for event trigger bodies.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum TagFilters {
    Tags(Vec<String>),
    TagsIgnore(Vec<String>),
}

/// Path filtering variants for event trigger bodies.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum PathFilters {
    Paths(Vec<String>),
    PathsIgnore(Vec<String>),
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_events_count() {
        let events = "
push:
pull_request:
workflow_dispatch:
issue_comment:";

        let events = serde_yaml::from_str::<super::Events>(events).unwrap();
        assert_eq!(events.count(), 4);
    }
}
