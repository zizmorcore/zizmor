use crate::audit::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::{Step, Uses};
use crate::state::AuditState;
use github_actions_models::common::expr::ExplicitExpr;
use github_actions_models::common::Env;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::job::StepBody;
use github_actions_models::workflow::Trigger;
use std::ops::Deref;
use std::sync::LazyLock;

#[derive(PartialEq)]
enum ControlValue {
    Boolean,
    String,
}

enum CacheControl {
    OptIn(&'static str),
    OptOut(&'static str),
}

/// The general schema for a cache-aware actions
struct CacheAwareAction<'w> {
    /// The owner/repo part within the Action full coordinate
    uses: Uses<'w>,
    /// The input that controls caching behavior
    cache_control: CacheControl,
    /// The type of value used to opt-in/opt-out (Boolean, String)
    control_value: ControlValue,
    /// Whether this Action adopts caching as the default behavior
    caching_by_default: bool,
}

/// The list of know cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
static KNOWN_CACHE_AWARE_ACTIONS: LazyLock<Vec<CacheAwareAction>> = LazyLock::new(|| {
    vec![
        // https://github.com/actions/cache/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("actions/cache").unwrap(),
            cache_control: CacheControl::OptOut("lookup-only"),
            control_value: ControlValue::Boolean,
            caching_by_default: true,
        },
        CacheAwareAction {
            uses: Uses::from_step("actions/setup-java").unwrap(),
            cache_control: CacheControl::OptIn("cache"),
            control_value: ControlValue::String,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-go/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("actions/setup-go").unwrap(),
            cache_control: CacheControl::OptIn("cache"),
            control_value: ControlValue::String,
            caching_by_default: true,
        },
        // https://github.com/actions/setup-node/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("actions/setup-node").unwrap(),
            cache_control: CacheControl::OptIn("cache"),
            control_value: ControlValue::String,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-python/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("actions/setup-python").unwrap(),
            cache_control: CacheControl::OptIn("cache"),
            control_value: ControlValue::String,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("actions/setup-dotnet").unwrap(),
            cache_control: CacheControl::OptIn("cache"),
            control_value: ControlValue::Boolean,
            caching_by_default: false,
        },
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("astral-sh/setup-uv").unwrap(),
            cache_control: CacheControl::OptOut("enable-cache"),
            control_value: ControlValue::String,
            caching_by_default: true,
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        CacheAwareAction {
            uses: Uses::from_step("Swatinem/rust-cache").unwrap(),
            cache_control: CacheControl::OptOut("lookup-only"),
            control_value: ControlValue::Boolean,
            caching_by_default: true,
        },
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        CacheAwareAction {
            uses: Uses::from_step("ruby/setup-ruby").unwrap(),
            cache_control: CacheControl::OptIn("bundler-cache"),
            control_value: ControlValue::Boolean,
            caching_by_default: false,
        },
        // https://github.com/PyO3/maturin-action/blob/main/action.yml
        CacheAwareAction {
            uses: Uses::from_step("PyO3/maturin-action").unwrap(),
            cache_control: CacheControl::OptIn("sccache"),
            control_value: ControlValue::Boolean,
            caching_by_default: false,
        },
    ]
});

#[derive(PartialEq)]
enum CacheUsage {
    ConditionalOptIn,
    DirectOptIn,
    DefaultActionBehaviour,
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
                OptionalBody::Body(body) => body.tag_filters.is_some(),
                _ => false,
            },
        }
    }

    fn evaluate_default_action_behaviour(action: &CacheAwareAction) -> Option<CacheUsage> {
        if action.caching_by_default {
            Some(CacheUsage::DefaultActionBehaviour)
        } else {
            None
        }
    }

    fn evaluate_user_defined_opt_in(
        cache_control_input: &str,
        env: &Env,
        action: &CacheAwareAction,
    ) -> Option<CacheUsage> {
        match env.get(cache_control_input) {
            None => None,
            Some(value) => match value.to_string().as_str() {
                "true" if matches!(action.control_value, ControlValue::Boolean) => {
                    Some(CacheUsage::DirectOptIn)
                }
                "false" if matches!(action.control_value, ControlValue::Boolean) => {
                    // Explicitly opts out from caching
                    None
                }
                other => match ExplicitExpr::from_curly(other) {
                    None if matches!(action.control_value, ControlValue::String) => {
                        Some(CacheUsage::DirectOptIn)
                    }
                    None => None,
                    Some(_) => Some(CacheUsage::ConditionalOptIn),
                },
            },
        }
    }

    fn evaluate_cache_usage(&self, target_step: &str, env: &Env) -> Option<CacheUsage> {
        let known_action = KNOWN_CACHE_AWARE_ACTIONS.iter().find(|action| {
            let Uses::Repository(well_known_uses) = action.uses else {
                return false;
            };

            let Some(Uses::Repository(target_uses)) = Uses::from_step(target_step) else {
                return false;
            };

            target_uses.matches(well_known_uses)
        })?;

        let cache_control_input = env.keys().find(|k| match known_action.cache_control {
            CacheControl::OptIn(inner) => *k == inner,
            CacheControl::OptOut(inner) => *k == inner,
        });

        match cache_control_input {
            // when not using the specific Action input to control caching behaviour,
            // we evaluate whether it uses caching by default
            None => CachePoisoning::evaluate_default_action_behaviour(known_action),

            // otherwise, we infer from the value assigned to the cache control input
            Some(key) => {
                // first, we extract the value assigned to that input
                let declared_usage =
                    CachePoisoning::evaluate_user_defined_opt_in(key, env, known_action);

                // we now evaluate the extracted value against the opt-in semantics
                match &declared_usage {
                    Some(CacheUsage::DirectOptIn) => {
                        match known_action.cache_control {
                            // in this case, we just follow the opt-in
                            CacheControl::OptIn(_) => declared_usage,
                            // otherwise, the user opted for disabling the cache
                            // hence we don't return a CacheUsage
                            CacheControl::OptOut(_) => None,
                        }
                    }
                    // Because we can't evaluate expressions, there is nothing to do
                    // regarding CacheUsage::ConditionalOptIn
                    _ => declared_usage,
                }
            }
        }
    }
}

impl WorkflowAudit for CachePoisoning {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let trigger = &step.workflow().on;

        if !self.trigger_used_when_publishing_artifacts(trigger) {
            return Ok(findings);
        }

        let StepBody::Uses { ref uses, ref with } = &step.deref().body else {
            return Ok(findings);
        };

        let Some(cache_usage) = self.evaluate_cache_usage(uses, with) else {
            return Ok(findings);
        };

        let (yaml_key, annotation) = match cache_usage {
            CacheUsage::DefaultActionBehaviour => ("uses", "cache enabled by default here"),
            CacheUsage::DirectOptIn => ("with", "opt-in for caching here"),
            CacheUsage::ConditionalOptIn => ("with", "opt-in for caching might happen here"),
        };

        findings.push(
            Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    step.workflow()
                        .location()
                        .with_keys(&["on".into()])
                        .annotated("generally used when publishing artifacts generated at runtime"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow())?,
        );

        Ok(findings)
    }
}
