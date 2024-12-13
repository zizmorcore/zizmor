use crate::audit::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use github_actions_models::common::expr::ExplicitExpr;
use github_actions_models::common::{Env, EnvValue};
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::job::StepBody;
use github_actions_models::workflow::Trigger;
use std::ops::Deref;
use std::sync::LazyLock;

/// The possible toggle types for cache-aware Actions.
/// A boolean toggle means only one possible literal value (true)
/// to opt into the cache behavior, whereas a multi-value toggle means
/// two or more values defining opt in for caching
#[derive(PartialEq)]
enum CacheControlToggle {
    Boolean,
    MultiValue,
}

/// The general schema for a cache-aware actions
struct CacheAwareAction {
    /// The owner/repo part within the Action full coordinate
    reference: &'static str,
    /// The name of the input the toggle caching behavior
    cache_control_input_name: &'static str,
    /// Whether this input defines opt-in behavior
    cache_control_input_defines_opt_in: bool,
    /// The type of this toggle (Boolean, MultiValue)
    cache_control_input_toggle: CacheControlToggle,
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
            reference: "actions/cache",
            cache_control_input_name: "lookup-only",
            cache_control_input_defines_opt_in: false,
            cache_control_input_toggle: CacheControlToggle::Boolean,
            caching_by_default: true,
        },
        // https://github.com/actions/cache/blob/main/restore/action.yml
        CacheAwareAction {
            reference: "actions/cache/restore",
            cache_control_input_name: "lookup-only",
            cache_control_input_defines_opt_in: false,
            cache_control_input_toggle: CacheControlToggle::Boolean,
            caching_by_default: true,
        },
        // https://github.com/actions/setup-java/blob/main/action.yml
        CacheAwareAction {
            reference: "actions/setup-java",
            cache_control_input_name: "cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::MultiValue,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-go/blob/main/action.yml
        CacheAwareAction {
            reference: "actions/setup-go",
            cache_control_input_name: "cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::MultiValue,
            caching_by_default: true,
        },
        // https://github.com/actions/setup-node/blob/main/action.yml
        CacheAwareAction {
            reference: "actions/setup-node",
            cache_control_input_name: "cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::MultiValue,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-python/blob/main/action.yml
        CacheAwareAction {
            reference: "actions/setup-python",
            cache_control_input_name: "cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::MultiValue,
            caching_by_default: false,
        },
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        CacheAwareAction {
            reference: "actions/setup-dotnet",
            cache_control_input_name: "cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::Boolean,
            caching_by_default: false,
        },
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        CacheAwareAction {
            reference: "astral-sh/setup-uv",
            cache_control_input_name: "enable-cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::MultiValue,
            caching_by_default: true,
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        CacheAwareAction {
            reference: "Swatinem/rust-cache",
            cache_control_input_name: "lookup-only",
            cache_control_input_defines_opt_in: false,
            cache_control_input_toggle: CacheControlToggle::Boolean,
            caching_by_default: true,
        },
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        CacheAwareAction {
            reference: "ruby/setup-ruby",
            cache_control_input_name: "bundler-cache",
            cache_control_input_defines_opt_in: true,
            cache_control_input_toggle: CacheControlToggle::Boolean,
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
            Some(EnvValue::Boolean(value)) => {
                if action.cache_control_input_toggle == CacheControlToggle::Boolean {
                    if *value {
                        Some(CacheUsage::DirectOptIn)
                    } else {
                        // Explicitly opts out from caching
                        None
                    }
                } else {
                    None
                }
            }
            Some(EnvValue::Number(_)) => {
                // Not sure about what to do here!
                None
            }
            Some(EnvValue::String(value)) => match ExplicitExpr::from_curly(value) {
                None => {
                    if action.cache_control_input_toggle == CacheControlToggle::MultiValue {
                        Some(CacheUsage::DirectOptIn)
                    } else {
                        None
                    }
                }
                Some(_) => Some(CacheUsage::ConditionalOptIn),
            },
        }
    }

    fn evaluate_cache_usage(&self, uses: &str, env: &Env) -> Option<CacheUsage> {
        let (reference, _) = uses.split_once("@")?;

        let known_action = KNOWN_CACHE_AWARE_ACTIONS
            .iter()
            .find(|action| action.reference == reference)?;

        let cache_control_input = env
            .keys()
            .find(|k| *k == known_action.cache_control_input_name);

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
                        if known_action.cache_control_input_defines_opt_in {
                            declared_usage
                        } else {
                            // in this case, the user opted for disabling the cache
                            // hence we don't return a CacheUsage
                            None
                        }
                    }
                    // CachePoisoning::evaluate_user_defined_opt_in returns only
                    // CacheUsage::DirectOptIn and CacheUsage::ConditionalOptIn variants
                    //
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
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow())?,
        );

        Ok(findings)
    }
}
