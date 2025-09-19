use std::sync::LazyLock;

use github_actions_models::workflow::Trigger;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody};

use crate::audit::{Audit, audit_meta};
use crate::config::Config;
use crate::finding::location::{Locatable as _, Routable};
use crate::finding::{Confidence, Finding, Fix, FixDisposition, Severity};
use crate::models::StepCommon;
use crate::models::coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle, Usage};
use crate::models::workflow::{JobExt as _, NormalJob, Step, Steps};
use crate::state::AuditState;

use indexmap::IndexMap;
use yamlpatch::{Op, Patch};

use super::AuditLoadError;

/// The list of know cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
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
                ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::FreeString, false),
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
    ]
});

/// A list of well-know publisher actions
/// In the future we can retrieve this list from the static API
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

enum PublishingArtifactsScenario<'doc> {
    UsingTypicalWorkflowTrigger,
    UsingWellKnowPublisherAction(Step<'doc>),
}

pub(crate) struct CachePoisoning;

audit_meta!(
    CachePoisoning,
    "cache-poisoning",
    "runtime artifacts potentially vulnerable to a cache poisoning attack"
);

impl CachePoisoning {
    fn trigger_used_when_publishing_artifacts(&self, trigger: &Trigger) -> bool {
        match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::Release,
            Trigger::BareEvents(events) => events.contains(&BareEvent::Release),
            Trigger::Events(events) => match &events.push {
                OptionalBody::Body(body) => {
                    let pushing_new_tag = &body.tag_filters.is_some();
                    let pushing_to_release_branch =
                        if let Some(BranchFilters::Branches(branches)) = &body.branch_filters {
                            branches
                                .iter()
                                .any(|branch| branch.to_lowercase().contains("release"))
                        } else {
                            false
                        };

                    *pushing_new_tag || pushing_to_release_branch
                }
                _ => false,
            },
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
    ) -> Option<PublishingArtifactsScenario<'doc>> {
        if self.trigger_used_when_publishing_artifacts(trigger) {
            return Some(PublishingArtifactsScenario::UsingTypicalWorkflowTrigger);
        };

        let well_know_publisher = CachePoisoning::detected_well_known_publisher_step(steps)?;

        Some(PublishingArtifactsScenario::UsingWellKnowPublisherAction(
            well_know_publisher,
        ))
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

    fn uses_cache_aware_step<'doc>(
        &self,
        step: &Step<'doc>,
        scenario: &PublishingArtifactsScenario<'doc>,
    ) -> Option<Finding<'doc>> {
        let (coord, cache_usage) = self.evaluate_cache_usage(step)?;

        let (yaml_key, annotation) = match cache_usage {
            Usage::Always => ("uses", "caching always restored here"),
            Usage::DefaultActionBehaviour => ("uses", "cache enabled by default here"),
            Usage::DirectOptIn => ("with", "opt-in for caching here"),
            Usage::ConditionalOptIn => ("with", "opt-in for caching might happen here"),
        };

        let mut finding_builder = match scenario {
            PublishingArtifactsScenario::UsingTypicalWorkflowTrigger => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    step.workflow()
                        .location()
                        .with_keys(["on".into()])
                        .annotated("generally used when publishing artifacts generated at runtime"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys([yaml_key.into()])
                        .annotated(annotation),
                ),
            PublishingArtifactsScenario::UsingWellKnowPublisherAction(publisher) => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    publisher
                        .location()
                        .with_keys(["uses".into()])
                        .annotated("runtime artifacts usually published here"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys([yaml_key.into()])
                        .annotated(annotation),
                ),
        };

        // Add fix if available
        if let Some(fix) = self.create_cache_disable_fix(coord, step) {
            finding_builder = finding_builder.fix(fix);
        }

        finding_builder.build(step.workflow()).ok()
    }
}

impl Audit for CachePoisoning {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];
        let steps = job.steps();
        let trigger = &job.parent().on;

        let Some(scenario) = self.is_job_publishing_artifacts(trigger, steps) else {
            return Ok(findings);
        };

        for step in job.steps() {
            if let Some(finding) = self.uses_cache_aware_step(&step, &scenario) {
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
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>).unwrap();
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit.audit_workflow(&workflow, &Config::default()).unwrap();

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

    #[test]
    fn test_cache_disable_fix_opt_out_boolean() {
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
                insta::assert_snapshot!(fixed_content, @r"
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

    #[test]
    fn test_cache_disable_fix_opt_in_boolean() {
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
                insta::assert_snapshot!(fixed_content, @r"
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

    #[test]
    fn test_cache_disable_fix_opt_in_string() {
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

    #[test]
    fn test_cache_disable_fix_non_configurable() {
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
