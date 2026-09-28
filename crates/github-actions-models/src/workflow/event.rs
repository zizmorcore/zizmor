//! Workflow events.
//!
//! See: <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>
//!
//! NOTE: [`BareEvent`] and [`Events`] include several events that GitHub has deprecated/removed
//! but that may still appear in older versions of GHES, like `project`, `project_card`,
//! and `project_column`. We may want to remove these at some point.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::common::EnvValue;

/// Constructs our various types/transformations for event triggers.
macro_rules! events {
    ($($(#[$attr:meta])* $field:ident: $body:ty $(=> $variant:ident)?),* $(,)?) => {
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
            $($($variant,)?)*
        }

        /// Normalized workflow event triggers, with optional bodies.
        #[derive(Deserialize, Serialize, Debug, Default)]
        #[serde(default, rename_all = "snake_case")]
        pub struct Events {
            $(
                $(#[$attr])*
                pub $field: OptionalBody<$body>,
            )*
        }

        impl Events {
            /// Count the number of present event triggers.
            pub fn count(&self) -> u32 {
                0 $(+ u32::from(self.$field.is_present()))*
            }
        }

        impl<'a> FromIterator<&'a BareEvent> for Events {
            fn from_iter<T: IntoIterator<Item = &'a BareEvent>>(iter: T) -> Self {
                let mut events = Self::default();
                for event in iter {
                    match event {
                        $($(
                            BareEvent::$variant => events.$field = OptionalBody::Default,
                        )?)*
                    }
                }
                events
            }
        }
    };
}

events! {
    branch_protection_rule: GenericEvent => BranchProtectionRule,
    check_run: GenericEvent => CheckRun,
    check_suite: GenericEvent => CheckSuite,
    create: GenericEvent => Create,
    delete: GenericEvent => Delete,
    deployment: GenericEvent => Deployment,
    deployment_status: GenericEvent => DeploymentStatus,
    discussion: GenericEvent => Discussion,
    discussion_comment: GenericEvent => DiscussionComment,
    fork: GenericEvent => Fork,
    gollum: GenericEvent => Gollum,
    image_version: ImageVersion => ImageVersion,
    issue_comment: GenericEvent => IssueComment,
    issues: GenericEvent => Issues,
    label: GenericEvent => Label,
    merge_group: GenericEvent => MergeGroup,
    milestone: GenericEvent => Milestone,
    page_build: GenericEvent => PageBuild,
    project: GenericEvent => Project,
    project_card: GenericEvent => ProjectCard,
    project_column: GenericEvent => ProjectColumn,
    public: GenericEvent => Public,
    pull_request: PullRequest => PullRequest,
    pull_request_review: GenericEvent => PullRequestReview,
    pull_request_review_comment: GenericEvent => PullRequestReviewComment,
    /// Uses the same trigger filters as `pull_request`.
    pull_request_target: PullRequest => PullRequestTarget,
    push: Push => Push,
    registry_package: GenericEvent => RegistryPackage,
    release: GenericEvent => Release,
    repository_dispatch: GenericEvent => RepositoryDispatch,
    // `schedule` has no bare form.
    schedule: Vec<Cron>,
    status: GenericEvent => Status,
    watch: GenericEvent => Watch,
    workflow_call: WorkflowCall => WorkflowCall,
    workflow_dispatch: WorkflowDispatch => WorkflowDispatch,
    workflow_run: WorkflowRun => WorkflowRun,
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

impl<T> OptionalBody<T> {
    /// Whether this event is enabled, with either default or explicit settings.
    pub fn is_present(&self) -> bool {
        !matches!(self, Self::Missing)
    }
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
            Some(v) => Self::Body(v),
            None => Self::Default,
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

/// The body of an `image_version` event trigger.
#[derive(Deserialize, Serialize, Debug)]
pub struct ImageVersion {
    pub names: Vec<String>,
    pub versions: Vec<String>,
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
    /// An IANA timezone name. GitHub defaults to UTC when omitted.
    pub timezone: Option<String>,
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
    pub r#type: WorkflowCallInputType,
}

/// The type of a `workflow_call` input, as specified in the `type` field.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowCallInputType {
    Boolean,
    Number,
    String,
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
    pub inputs: IndexMap<String, WorkflowDispatchInput>,
}

/// A single input in a `workflow_dispatch` event trigger body.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowDispatchInput {
    pub description: Option<String>,
    // TODO: model `default`?
    #[serde(default)]
    pub required: bool,
    /// The type of this `workflow_dispatch` input.
    #[serde(default)]
    pub r#type: WorkflowDispatchInputType,
    // Only present when `type` is `choice`.
    #[serde(default)]
    pub options: Vec<EnvValue>,
}

#[derive(Default, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowDispatchInputType {
    Boolean,
    Choice,
    Environment,
    Number,
    #[default]
    String,
}

/// The body of a `workflow_run` event trigger.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct WorkflowRun {
    pub workflows: Vec<String>,
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
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
    use crate::workflow::Trigger;

    #[test]
    fn test_events_count() {
        let events = "
push:
pull_request:
workflow_dispatch:
issue_comment:";

        let events = yaml_serde::from_str::<super::Events>(events).unwrap();
        assert_eq!(events.count(), 4);
    }

    #[test]
    fn test_image_version_trigger() {
        let trigger = r#"
image_version:
  names:
  - "MyNewImage"
  - "MyOtherImage"
  versions:
  - 1.*
  - 2.*
        "#;

        let trigger = yaml_serde::from_str::<Trigger>(trigger).unwrap();

        insta::assert_debug_snapshot!(trigger, @r#"
        Trigger {
            events: Events {
                branch_protection_rule: Missing,
                check_run: Missing,
                check_suite: Missing,
                create: Missing,
                delete: Missing,
                deployment: Missing,
                deployment_status: Missing,
                discussion: Missing,
                discussion_comment: Missing,
                fork: Missing,
                gollum: Missing,
                image_version: Body(
                    ImageVersion {
                        names: [
                            "MyNewImage",
                            "MyOtherImage",
                        ],
                        versions: [
                            "1.*",
                            "2.*",
                        ],
                    },
                ),
                issue_comment: Missing,
                issues: Missing,
                label: Missing,
                merge_group: Missing,
                milestone: Missing,
                page_build: Missing,
                project: Missing,
                project_card: Missing,
                project_column: Missing,
                public: Missing,
                pull_request: Missing,
                pull_request_review: Missing,
                pull_request_review_comment: Missing,
                pull_request_target: Missing,
                push: Missing,
                registry_package: Missing,
                release: Missing,
                repository_dispatch: Missing,
                schedule: Missing,
                status: Missing,
                watch: Missing,
                workflow_call: Missing,
                workflow_dispatch: Missing,
                workflow_run: Missing,
            },
            syntax: Mapping,
        }
        "#);
    }
}
