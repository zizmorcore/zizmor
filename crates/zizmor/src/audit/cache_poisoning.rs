use std::sync::LazyLock;

use github_actions_expressions::call::{Call, Function};
use github_actions_expressions::literal::Literal;
use github_actions_expressions::op::UnOp;
use github_actions_expressions::{Expr, SpannedExpr};
use github_actions_models::common::EnvValue;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::Trigger;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody};

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::location::{Locatable as _, Routable};
use crate::finding::{Confidence, Finding, Fix, FixDisposition, Severity};
use crate::models::coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle, Usage};
use crate::models::workflow::{JobCommon as _, NormalJob, Step, Steps};
use crate::models::{StepBodyCommon, StepCommon};
use crate::state::AuditState;
use crate::utils::ExtractedExpr;

use indexmap::IndexMap;
use yamlpatch::{Op, Patch};

use super::AuditLoadError;

const TAG_REF_PREFIX: &str = "refs/tags/";

/// The list of known cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
#[allow(clippy::unwrap_used)]
static KNOWN_CACHE_AWARE_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    vec![
        // https://github.com/actions/cache/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/cache".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/actions/setup-java/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-java".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        },
        // https://github.com/actions/setup-go/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-go".parse().unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
        // https://github.com/actions/setup-node/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-node".parse().unwrap(),
            control: ControlExpr::any([
                ControlExpr::single(
                    Toggle::OptIn,
                    "cache",
                    // https://github.com/actions/setup-node/blob/65d868f8d4/src/cache-utils.ts#L101-L111
                    ControlFieldType::Exact(&["npm", "yarn", "pnpm"]),
                    false,
                ),
                // NOTE: Added with `setup-node@v5`.
                ControlExpr::single(
                    Toggle::OptIn,
                    "package-manager-cache",
                    ControlFieldType::Boolean,
                    true,
                ),
            ]),
        },
        // https://github.com/actions/setup-python/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-python".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        },
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-dotnet".parse().unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, false),
        },
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "astral-sh/setup-uv".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "enable-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "Swatinem/rust-cache".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "ruby/setup-ruby".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "bundler-cache",
                ControlFieldType::Boolean,
                false,
            ),
        },
        // https://github.com/PyO3/maturin-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "PyO3/maturin-action".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "sccache",
                ControlFieldType::Boolean,
                false,
            ),
        },
        // https://github.com/mlugg/setup-zig/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "mlugg/setup-zig".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "use-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/oven-sh/setup-bun/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "oven-sh/setup-bun".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "no-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/DeterminateSystems/magic-nix-cache-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "DeterminateSystems/magic-nix-cache-action".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "use-gha-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/graalvm/setup-graalvm/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "graalvm/setup-graalvm".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        },
        // https://github.com/gradle/actions/blob/main/setup-gradle/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "gradle/actions/setup-gradle".parse().unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "cache-disabled",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/docker/setup-buildx-action/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "docker/setup-buildx-action".parse().unwrap(),
            control: ControlExpr::all([
                ControlExpr::single(
                    Toggle::OptIn,
                    "cache-binary",
                    ControlFieldType::Boolean,
                    true,
                ),
                ControlExpr::single(
                    Toggle::OptIn,
                    "version",
                    ControlFieldType::FreeString,
                    false,
                ),
            ]),
        },
        // https://github.com/actions-rust-lang/setup-rust-toolchain/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions-rust-lang/setup-rust-toolchain".parse().unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
        // https://github.com/Mozilla-Actions/sccache-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable("Mozilla-Actions/sccache-action".parse().unwrap()),
        // https://github.com/nix-community/cache-nix-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable("nix-community/cache-nix-action".parse().unwrap()),
        // https://github.com/jdx/mise-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "jdx/mise-action".parse().unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
        // https://github.com/ramsey/composer-install/blob/v3/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "ramsey/composer-install".parse().unwrap(),
            control: ControlExpr::Single {
                toggle: Toggle::OptOut,
                field_name: "ignore-cache",
                field_type: ControlFieldType::Exact(&["yes", "true", "1"]),
                satisfied_by_default: true,
            },
        },
        // https://github.com/awalsh128/cache-apt-pkgs-action/blob/master/action.yml
        ActionCoordinate::NotConfigurable("awalsh128/cache-apt-pkgs-action".parse().unwrap()),
    ]
});

/// A list of well-know publisher actions
/// In the future we can retrieve this list from the static API
#[allow(clippy::unwrap_used)]
static KNOWN_PUBLISHER_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    vec![
        // Public packages and/or binary distribution channels
        ActionCoordinate::NotConfigurable("pypa/gh-action-pypi-publish".parse().unwrap()),
        ActionCoordinate::NotConfigurable("rubygems/release-gem".parse().unwrap()),
        ActionCoordinate::NotConfigurable("jreleaser/release-action".parse().unwrap()),
        ActionCoordinate::NotConfigurable("goreleaser/goreleaser-action".parse().unwrap()),
        // Github releases
        ActionCoordinate::NotConfigurable("softprops/action-gh-release".parse().unwrap()),
        ActionCoordinate::NotConfigurable("release-drafter/release-drafter".parse().unwrap()),
        ActionCoordinate::NotConfigurable("googleapis/release-please-action".parse().unwrap()),
        // Container registries
        ActionCoordinate::Configurable {
            uses_pattern: "docker/build-push-action".parse().unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "push", ControlFieldType::Boolean, true),
        },
        ActionCoordinate::NotConfigurable("redhat-actions/push-to-registry".parse().unwrap()),
        // Cloud + Edge providers
        ActionCoordinate::NotConfigurable(
            "aws-actions/amazon-ecs-deploy-task-definition"
                .parse()
                .unwrap(),
        ),
        ActionCoordinate::NotConfigurable(
            "aws-actions/aws-cloudformation-github-deploy"
                .parse()
                .unwrap(),
        ),
        ActionCoordinate::NotConfigurable("Azure/aci-deploy".parse().unwrap()),
        ActionCoordinate::NotConfigurable("Azure/container-apps-deploy-action".parse().unwrap()),
        ActionCoordinate::NotConfigurable("Azure/functions-action".parse().unwrap()),
        ActionCoordinate::NotConfigurable("Azure/sql-action".parse().unwrap()),
        ActionCoordinate::NotConfigurable("cloudflare/wrangler-action".parse().unwrap()),
        ActionCoordinate::NotConfigurable(
            "google-github-actions/deploy-appengine".parse().unwrap(),
        ),
        ActionCoordinate::NotConfigurable("google-github-actions/deploy-cloudrun".parse().unwrap()),
        ActionCoordinate::NotConfigurable(
            "google-github-actions/deploy-cloud-functions"
                .parse()
                .unwrap(),
        ),
    ]
});

/// Kinds of triggers that are known to be used with release workflows.
enum ReleaseTrigger {
    /// Release triggered by pushing a tag.
    TagPush,
    /// Release triggered by pushing to a release branch.
    ReleaseBranchPush,
    /// Release triggered by the `release` event.
    ReleaseEvent,
}

/// The release 'scenario' in which a cache-aware step is used.
enum PublishingScenario<'doc> {
    /// The surrounding workflow is triggered by event(s) typically used for creating releases.
    UsingReleaseTriggers(Vec<ReleaseTrigger>),
    /// The release is performed by a well-known action like `pypa/gh-action-pypi-publish`.
    UsingReleaseAction(Step<'doc>),
}

/// An expression that controls the behavior of a cache-aware action,
/// typically within an action input.
///
/// This is used to provide (very rough) analysis of cases like
/// `enable-cache: ${{ ... }}`.
enum CacheControlExpr {
    /// A literal `${{ true }}` or `${{ false }}`.
    Bool(bool),
    // At the moment, this is the only combination of cache control expression and workflow trigger
    // that we recognize.
    StartsWithGithubRefTagPrefix,
    /// A negation of another cache control expression.
    Not(Box<CacheControlExpr>),
}

impl CacheControlExpr {
    fn parse(raw: &str) -> Option<Self> {
        let extracted = ExtractedExpr::from_fenced(raw)?;
        let parsed = Expr::parse(extracted.as_bare()).ok()?;
        Self::from_spanned(&parsed)
    }

    fn from_spanned(expr: &SpannedExpr) -> Option<Self> {
        match &expr.inner {
            Expr::Literal(Literal::Boolean(value)) => Some(Self::Bool(*value)),
            Expr::UnOp {
                op: UnOp::Not,
                expr,
            } => Some(Self::Not(Box::new(Self::from_spanned(expr)?))),
            Expr::Call(Call {
                func: Function::StartsWith,
                args,
            }) => {
                if let [lhs, rhs] = args.as_slice()
                    && let Expr::Context(ctx) = &lhs.inner
                    && ctx.matches("github.ref")
                    && let Expr::Literal(Literal::String(prefix)) = &rhs.inner
                    && prefix.eq_ignore_ascii_case(TAG_REF_PREFIX)
                {
                    Some(Self::StartsWithGithubRefTagPrefix)
                } else {
                    None
                }
            }
            // TODO: At some point we might want to add heuristics for `case(...)` here as well.
            _ => None,
        }
    }

    fn eval_for_tag_push(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Not(expr) => !expr.eval_for_tag_push(),
            Self::StartsWithGithubRefTagPrefix => true,
        }
    }
}

struct CacheControlField<'a> {
    toggle: Toggle,
    raw_value: &'a EnvValue,
}

impl<'a> CacheControlField<'a> {
    fn extract(coord: &'a ActionCoordinate, step: &'a impl StepCommon<'a>) -> Option<Self> {
        if let ActionCoordinate::Configurable { control, .. } = coord
            && let ControlExpr::Single {
                toggle,
                field_name,
                field_type: ControlFieldType::Boolean,
                ..
            } = control
            && let StepBodyCommon::Uses {
                with: LoE::Literal(with),
                ..
            } = step.body()
            && let Some(raw_value) = with.get(*field_name)
        {
            Some(CacheControlField {
                toggle: *toggle,
                raw_value,
            })
        } else {
            None
        }
    }
}

pub(crate) struct CachePoisoning;

audit_meta!(
    CachePoisoning,
    "cache-poisoning",
    "runtime artifacts potentially vulnerable to a cache poisoning attack"
);

impl CachePoisoning {
    fn triggers_used_when_publishing_artifacts(&self, trigger: &Trigger) -> Vec<ReleaseTrigger> {
        match trigger {
            Trigger::BareEvent(BareEvent::Release) => {
                vec![ReleaseTrigger::ReleaseEvent]
            }
            Trigger::BareEvents(events) if events.contains(&BareEvent::Release) => {
                vec![ReleaseTrigger::ReleaseEvent]
            }
            Trigger::Events(events) => {
                let mut triggers = vec![];

                if let OptionalBody::Body(body) = &events.push {
                    if body.tag_filters.is_some() {
                        triggers.push(ReleaseTrigger::TagPush);
                    }

                    if let Some(BranchFilters::Branches(branches)) = &body.branch_filters
                        && branches
                            .iter()
                            .any(|branch| branch.to_lowercase().contains("release"))
                    {
                        triggers.push(ReleaseTrigger::ReleaseBranchPush);
                    }
                }

                if !matches!(events.release, OptionalBody::Missing) {
                    triggers.push(ReleaseTrigger::ReleaseEvent);
                }

                triggers
            }
            _ => vec![],
        }
    }

    fn detected_well_known_publisher_step(steps: Steps) -> Option<Step> {
        steps.into_iter().find(|step| {
            // TODO: Specialize further here, and produce an appropriate
            // confidence/persona setting if the usage is conditional.
            KNOWN_PUBLISHER_ACTIONS
                .iter()
                .any(|publisher| publisher.usage(step).is_some())
        })
    }

    fn is_job_publishing_artifacts<'doc>(
        &self,
        trigger: &Trigger,
        steps: Steps<'doc>,
    ) -> Option<PublishingScenario<'doc>> {
        let triggers = self.triggers_used_when_publishing_artifacts(trigger);
        if !triggers.is_empty() {
            return Some(PublishingScenario::UsingReleaseTriggers(triggers));
        };

        let well_know_publisher = CachePoisoning::detected_well_known_publisher_step(steps)?;
        Some(PublishingScenario::UsingReleaseAction(well_know_publisher))
    }

    fn evaluate_cache_usage<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Option<(&'static ActionCoordinate, Usage)> {
        KNOWN_CACHE_AWARE_ACTIONS
            .iter()
            .find_map(|coord| coord.usage(step).map(|usage| (coord, usage)))
    }

    fn create_cache_disable_fix<'doc>(
        &self,
        coord: &ActionCoordinate,
        step: &Step<'doc>,
    ) -> Option<Fix<'doc>> {
        match coord {
            ActionCoordinate::NotConfigurable(_pattern) => {
                // For non-configurable actions, we can't provide automatic fixes
                None
            }
            ActionCoordinate::Configurable {
                uses_pattern,
                control,
            } => self.create_configurable_action_fix(uses_pattern, control, step),
        }
    }

    fn create_configurable_action_fix<'doc>(
        &self,
        _uses_pattern: &crate::models::uses::RepositoryUsesPattern,
        control: &ControlExpr,
        step: &Step<'doc>,
    ) -> Option<Fix<'doc>> {
        match control {
            ControlExpr::Single {
                toggle,
                field_name,
                field_type,
                ..
            } => {
                let (field_value, title, _description) = match (toggle, field_type) {
                    (Toggle::OptOut, ControlFieldType::Boolean) => (
                        serde_yaml::Value::Bool(true),
                        format!("Set {field_name}: true to disable caching"),
                        format!(
                            "Set '{field_name}' to 'true' to disable cache writes in this publishing workflow."
                        ),
                    ),
                    (Toggle::OptIn, ControlFieldType::Boolean) => (
                        serde_yaml::Value::Bool(false),
                        format!("Set {field_name}: false to disable caching"),
                        format!(
                            "Set '{field_name}' to 'false' to disable caching in this publishing workflow."
                        ),
                    ),
                    // String control fields are action-specific and we can't reliably know
                    // what value disables caching (e.g., setup-node expects '' not 'false')
                    (Toggle::OptIn, _) | (Toggle::OptOut, _) => {
                        return None;
                    }
                };

                Some(Fix {
                    title,
                    key: step.location().key,
                    disposition: FixDisposition::default(),
                    patches: vec![Patch {
                        route: step.route(),
                        operation: Op::MergeInto {
                            key: "with".to_string(),
                            updates: IndexMap::from([(field_name.to_string(), field_value)]),
                        },
                    }],
                })
            }
            // For complex control expressions (All/Any/Not), don't provide automatic fixes for now
            ControlExpr::All(_) | ControlExpr::Any(_) | ControlExpr::Not(_) => None,
        }
    }

    /// Apply heuristics to a `Usage::ConditionalOptIn` to attempt to refine it into
    /// a more precise usage.
    ///
    /// Returns `None` if the heuristics determine that caching is effectively disabled.
    fn conditional_cache_usage_heuristics<'doc>(
        &self,
        coord: &ActionCoordinate,
        step: &Step<'doc>,
        scenario: &PublishingScenario<'doc>,
        cache_usage: Usage,
    ) -> Option<Usage> {
        // Heuristic: if our release workflow is triggered by (only) a tag push and the
        // cache control field is driven by an expression like `${{ startsWith(github.ref, 'refs/tags/') }}`,
        // then we can infer that caching is effectively enabled in this workflow, and upgrade the usage
        // confidence accordingly.
        // TODO: We probably need to make this even more precise, e.g. for pushes with tag patterns.
        if let PublishingScenario::UsingReleaseTriggers(triggers) = scenario
            && triggers
                .iter()
                .all(|t| matches!(t, ReleaseTrigger::TagPush | ReleaseTrigger::ReleaseEvent))
            && let Some(control) = CacheControlField::extract(coord, step)
            && let Some(expr) = CacheControlExpr::parse(&control.raw_value.to_string())
        {
            let control_value = expr.eval_for_tag_push();

            let cache_enabled = match control.toggle {
                Toggle::OptIn => control_value,
                Toggle::OptOut => !control_value,
            };

            if cache_enabled {
                // Caching is enabled; upgrade the confidence.
                Some(Usage::DirectOptIn)
            } else {
                // Caching is disabled; rule out this usage.
                None
            }
        } else {
            // No heuristics apply; return the original usage.
            Some(cache_usage)
        }
    }

    fn uses_cache_aware_step<'doc>(
        &self,
        step: &Step<'doc>,
        scenario: &PublishingScenario<'doc>,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let Some((coord, cache_usage)) = self.evaluate_cache_usage(step) else {
            return Ok(None);
        };

        let cache_usage = if matches!(cache_usage, Usage::ConditionalOptIn) {
            self.conditional_cache_usage_heuristics(coord, step, scenario, cache_usage)
        } else {
            Some(cache_usage)
        };

        let Some(cache_usage) = cache_usage else {
            return Ok(None);
        };

        let locations = match cache_usage {
            Usage::ConditionalOptIn => vec![
                step.location().primary().with_keys(["uses".into()]),
                step.location()
                    .with_keys(["with".into()])
                    .annotated("may enable caching here"),
            ],
            Usage::DirectOptIn => vec![
                step.location().primary().with_keys(["uses".into()]),
                step.location()
                    .with_keys(["with".into()])
                    .annotated("enables caching explicitly here"),
            ],
            Usage::DefaultActionBehaviour => vec![
                step.location()
                    .primary()
                    .with_keys(["uses".into()])
                    .annotated("enables caching by default"),
            ],
            Usage::Always => vec![
                step.location()
                    .primary()
                    .with_keys(["uses".into()])
                    .annotated("always restores from cache"),
            ],
        };

        let mut finding_builder = match scenario {
            PublishingScenario::UsingReleaseTriggers(_) => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    step.workflow()
                        .location()
                        .with_keys(["on".into()])
                        .annotated("generally used when publishing artifacts generated at runtime"),
                ),
            PublishingScenario::UsingReleaseAction(publisher) => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    publisher
                        .location()
                        .with_keys(["uses".into()])
                        .annotated("runtime artifacts usually published here"),
                ),
        };

        for location in locations {
            finding_builder = finding_builder.add_location(location);
        }

        // Add a hidden location that spans the entire step, to ensure people
        // can put ignore comments anywhere in the step's body.
        finding_builder = finding_builder.add_location(step.location().hidden());

        // Add fix if available
        if let Some(fix) = self.create_cache_disable_fix(coord, step) {
            finding_builder = finding_builder.fix(fix);
        }

        Ok(Some(finding_builder.build(step)?))
    }
}

#[async_trait::async_trait]
impl Audit for CachePoisoning {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        let steps = job.steps();
        let trigger = &job.parent().on;

        let Some(scenario) = self.is_job_publishing_artifacts(trigger, steps) else {
            return Ok(findings);
        };

        for step in job.steps() {
            if let Some(finding) = self.uses_cache_aware_step(&step, &scenario)? {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config, models::workflow::Workflow, registry::input::InputKey, state::AuditState,
    };

    /// Macro for testing workflow audits with common boilerplate
    ///
    /// Usage: `test_workflow_audit!(AuditType, "filename.yml", workflow_yaml, |findings| { ... })`
    ///
    /// This macro:
    /// 1. Creates a test workflow from the provided YAML with the specified filename
    /// 2. Sets up the audit state
    /// 3. Creates and runs the audit
    /// 4. Executes the provided test closure with the findings
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>);
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit
                .audit_workflow(&workflow, &Config::default())
                .await
                .unwrap();

            $test_fn(findings)
        }};
    }

    /// Helper function to apply a fix and return the result for snapshot testing
    fn apply_fix_for_snapshot(workflow_content: &str, findings: Vec<Finding>) -> String {
        assert!(!findings.is_empty(), "Expected findings but got none");
        let finding = &findings[0];
        assert!(!finding.fixes.is_empty(), "Expected fixes but got none");

        let fix = &finding.fixes[0];

        // Parse the workflow content as a document
        let document = yamlpath::Document::new(workflow_content).unwrap();

        // Apply the fix and get the new document
        let fixed_document = fix.apply(&document).unwrap();

        // Return the source content
        fixed_document.source().to_string()
    }

    #[tokio::test]
    async fn test_cache_disable_fix_opt_out_boolean() {
        let workflow_content = r#"
name: Test Workflow
on: release

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      - uses: softprops/action-gh-release@v1
"#;

        test_workflow_audit!(
            CachePoisoning,
            "test_cache_disable_fix_opt_out_boolean.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_for_snapshot(workflow_content, findings);
                insta::assert_snapshot!(fixed_content, @"

                name: Test Workflow
                on: release

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/cache@v4
                        with:
                          path: |
                            ~/.cargo/registry
                            ~/.cargo/git
                          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
                          lookup-only: true
                      - uses: softprops/action-gh-release@v1
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_cache_disable_fix_opt_in_boolean() {
        let workflow_content = r#"
name: Test Workflow
on: release

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          cache: true
      - uses: softprops/action-gh-release@v1
"#;

        test_workflow_audit!(
            CachePoisoning,
            "test_cache_disable_fix_opt_in_boolean.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_for_snapshot(workflow_content, findings);
                insta::assert_snapshot!(fixed_content, @"

                name: Test Workflow
                on: release

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/setup-go@v4
                        with:
                          go-version: '1.21'
                          cache: false
                      - uses: softprops/action-gh-release@v1
                ");
            }
        );
    }

    #[tokio::test]
    async fn test_cache_disable_fix_opt_in_string() {
        let workflow_content = r#"
name: Test Workflow
on: release

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'
          cache: 'gradle'
      - uses: softprops/action-gh-release@v1
"#;

        test_workflow_audit!(
            CachePoisoning,
            "test_cache_disable_fix_opt_in_string.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let finding = &findings[0];
                // String control fields should not have fixes since we can't reliably
                // know what value disables caching for different actions
                assert!(finding.fixes.is_empty());
            }
        );
    }

    #[tokio::test]
    async fn test_cache_disable_fix_non_configurable() {
        let workflow_content = r#"
name: Test Workflow
on: release

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: Mozilla-Actions/sccache-action@v1
      - uses: softprops/action-gh-release@v1
"#;

        test_workflow_audit!(
            CachePoisoning,
            "test_cache_disable_fix_non_configurable.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let finding = &findings[0];
                // Non-configurable actions should not have fixes
                assert!(finding.fixes.is_empty());
            }
        );
    }
}
