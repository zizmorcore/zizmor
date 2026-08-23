use std::sync::LazyLock;

use github_actions_expressions::call::{Call, Function};
use github_actions_expressions::literal::Literal;
use github_actions_expressions::op::{BinExpr, BinOp, UnOp};
use github_actions_expressions::{Expr, SpannedExpr};
use github_actions_models::common::EnvValue;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::Trigger;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody};

use crate::audit::{Audit, AuditError, audit_meta};
use crate::config::Config;
use crate::finding::location::{Locatable as _, Routable as _};
use crate::finding::{Confidence, Finding, Fix, FixDisposition, Severity};
use crate::models::coordinate::{
    ActionCoordinate, ControlExpr, ControlFieldType, ControlOrigin, Toggle, Usage, VersionBound,
};
use crate::models::version::Version;
use crate::models::workflow::{JobCommon as _, NormalJob, Step, Steps};
use crate::models::{StepBodyCommon, StepCommon};
use crate::state::AuditState;
use crate::utils::ExtractedExpr;

use indexmap::IndexMap;
use yamlpatch::{Op, Patch};

use super::AuditLoadError;

const TAG_REF_PREFIX: &str = "refs/tags/";
/// A canonical parse for our [`CacheControlExpr::RefTypeTagPush`] heuristic below.
/// We don't match this verbatim; instead we decompose it for commutative comparisons.
static REF_TYPE_TAG_PUSH_GUARD: LazyLock<Expr> = LazyLock::new(|| {
    Expr::parse("github.event_name == 'push' && github.ref_type == 'tag'")
        .expect("impossible")
        .inner
});

/// Disable caching by setting a boolean action input explicitly.
struct CacheFix {
    field_name: &'static str,
    field_value: bool,
}

struct CacheAwareAction {
    coordinate: ActionCoordinate,
    fix: Option<CacheFix>,
}

impl From<ActionCoordinate> for CacheAwareAction {
    fn from(coordinate: ActionCoordinate) -> Self {
        let fix = match &coordinate {
            // Infer a fix. At the moment, the only inferrable fixes are for [`ActionCoordinate`]s
            // that only have a single top-level boolean control field.
            ActionCoordinate::Configurable {
                control:
                    ControlExpr::Field {
                        toggle,
                        field_name,
                        field_type: ControlFieldType::Boolean,
                        ..
                    },
                ..
            } => Some(CacheFix {
                field_name,
                field_value: matches!(toggle, Toggle::OptOut),
            }),
            _ => {
                // We can't infer fixes for other coordinates at the moment.
                //
                // TODO: We may be able to infer fixes for string control fields.
                //
                // Version bounds and compelx control expressions (All/Any/Not)
                // are probably not easy for us to infer in the future.
                None
            }
        };

        Self { coordinate, fix }
    }
}

/// The list of known cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
#[allow(clippy::unwrap_used)]
static KNOWN_CACHE_AWARE_ACTIONS: LazyLock<Vec<CacheAwareAction>> = LazyLock::new(|| {
    vec![
        // https://github.com/actions/cache/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/cache".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/actions/setup-java/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-java".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        }
        .into(),
        // https://github.com/actions/setup-go/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-go".parse().unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        }
        .into(),
        // https://github.com/actions/setup-node/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-node".parse().unwrap(),
            control: ControlExpr::any([
                ControlExpr::field(
                    Toggle::OptIn,
                    "cache",
                    // https://github.com/actions/setup-node/blob/65d868f8d4/src/cache-utils.ts#L101-L111
                    ControlFieldType::Exact(&["npm", "yarn", "pnpm"]),
                    false,
                ),
                // NOTE: Added with `setup-node@v5`.
                ControlExpr::field(
                    Toggle::OptIn,
                    "package-manager-cache",
                    ControlFieldType::Boolean,
                    true,
                ),
            ]),
        }
        .into(),
        // https://github.com/actions/setup-python/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-python".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        }
        .into(),
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions/setup-dotnet".parse().unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "cache", ControlFieldType::Boolean, false),
        }
        .into(),
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        CacheAwareAction {
            coordinate: ActionCoordinate::Configurable {
                uses_pattern: "astral-sh/setup-uv".parse().unwrap(),
                control: ControlExpr::any([
                    // Regardless of the version, setting `enable-cache: true`
                    // always explicitly enables the cache.
                    ControlExpr::field(
                        Toggle::OptIn,
                        "enable-cache",
                        ControlFieldType::Exact(&["true"]),
                        false,
                    ),
                    // For setup-uv below v10, any boolishly true `enable-cache`
                    // (including `enable-cache: auto`) is considered to enable the cache.
                    // This is slightly imprecise since `auto` actually disables the cache
                    // on self-hosted runners, but we don't have a good static way to
                    // detect those at the moment.
                    ControlExpr::all([
                        ControlExpr::VersionBound(VersionBound::LessThan(
                            Version::parse("v10").unwrap(),
                        )),
                        ControlExpr::field(
                            Toggle::OptIn,
                            "enable-cache",
                            ControlFieldType::Boolean,
                            true,
                        ),
                    ]),
                ]),
            },
            fix: Some(CacheFix {
                field_name: "enable-cache",
                field_value: false,
            }),
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "Swatinem/rust-cache".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "ruby/setup-ruby".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "bundler-cache",
                ControlFieldType::Boolean,
                false,
            ),
        }
        .into(),
        // https://github.com/PyO3/maturin-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "PyO3/maturin-action".parse().unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "sccache", ControlFieldType::Boolean, false),
        }
        .into(),
        // https://github.com/mlugg/setup-zig/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "mlugg/setup-zig".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "use-cache",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/oven-sh/setup-bun/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "oven-sh/setup-bun".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptOut,
                "no-cache",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/DeterminateSystems/magic-nix-cache-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "DeterminateSystems/magic-nix-cache-action".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "use-gha-cache",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/graalvm/setup-graalvm/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "graalvm/setup-graalvm".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptIn,
                "cache",
                ControlFieldType::FreeString,
                false,
            ),
        }
        .into(),
        // https://github.com/gradle/actions/blob/main/setup-gradle/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "gradle/actions/setup-gradle".parse().unwrap(),
            control: ControlExpr::field(
                Toggle::OptOut,
                "cache-disabled",
                ControlFieldType::Boolean,
                true,
            ),
        }
        .into(),
        // https://github.com/docker/setup-buildx-action/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "docker/setup-buildx-action".parse().unwrap(),
            control: ControlExpr::all([
                ControlExpr::field(
                    Toggle::OptIn,
                    "cache-binary",
                    ControlFieldType::Boolean,
                    true,
                ),
                ControlExpr::field(
                    Toggle::OptIn,
                    "version",
                    ControlFieldType::FreeString,
                    false,
                ),
            ]),
        }
        .into(),
        // https://github.com/actions-rust-lang/setup-rust-toolchain/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "actions-rust-lang/setup-rust-toolchain".parse().unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        }
        .into(),
        // https://github.com/Mozilla-Actions/sccache-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable("Mozilla-Actions/sccache-action".parse().unwrap()).into(),
        // https://github.com/nix-community/cache-nix-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable("nix-community/cache-nix-action".parse().unwrap()).into(),
        // https://github.com/jdx/mise-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "jdx/mise-action".parse().unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        }
        .into(),
        // https://github.com/ramsey/composer-install/blob/v3/action.yml
        ActionCoordinate::Configurable {
            uses_pattern: "ramsey/composer-install".parse().unwrap(),
            control: ControlExpr::Field {
                toggle: Toggle::OptOut,
                field_name: "ignore-cache",
                field_type: ControlFieldType::Exact(&["yes", "true", "1"]),
                satisfied_by_default: true,
            },
        }
        .into(),
        // https://github.com/awalsh128/cache-apt-pkgs-action/blob/master/action.yml
        ActionCoordinate::NotConfigurable("awalsh128/cache-apt-pkgs-action".parse().unwrap())
            .into(),
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
            control: ControlExpr::field(Toggle::OptIn, "push", ControlFieldType::Boolean, true),
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
    // An expression like `startsWith(github.ref, 'refs/tags/')`.
    StartsWithGithubRefTagPrefix,
    // An expression like `github.event_name == 'push' && github.ref_type == 'tag'`
    RefTypeTagPush,
    /// A negation of another cache control expression.
    Not(Box<Self>),
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
            Expr::UnExpr {
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
            expr @ Expr::BinExpr(BinExpr { op: BinOp::And, .. }) => {
                if expr.commutative_matches(&REF_TYPE_TAG_PUSH_GUARD) {
                    Some(Self::RefTypeTagPush)
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
            Self::RefTypeTagPush => true,
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
            && let ControlExpr::Field {
                toggle,
                field_name,
                field_type: ControlFieldType::Boolean,
                ..
            } = control
            && let Some(StepBodyCommon::Uses {
                with: LoE::Literal(with),
                ..
            }) = step.body()
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

        let well_know_publisher = Self::detected_well_known_publisher_step(steps)?;
        Some(PublishingScenario::UsingReleaseAction(well_know_publisher))
    }

    fn evaluate_cache_usage<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Option<(&'static CacheAwareAction, Usage)> {
        KNOWN_CACHE_AWARE_ACTIONS
            .iter()
            .find_map(|action| action.coordinate.usage(step).map(|usage| (action, usage)))
    }

    fn create_cache_disable_fix<'doc>(
        &self,
        action: &CacheAwareAction,
        step: &Step<'doc>,
    ) -> Option<Fix<'doc>> {
        let CacheFix {
            field_name,
            field_value,
        } = action.fix.as_ref()?;

        Some(Fix {
            title: format!("Set {field_name}: {field_value} to disable caching"),
            key: step.location().key,
            disposition: FixDisposition::default(),
            patches: vec![Patch {
                route: step.route(),
                operation: Op::MergeInto {
                    key: "with".to_string(),
                    updates: IndexMap::from([(
                        field_name.to_string(),
                        yaml_serde::Value::Bool(*field_value),
                    )]),
                },
            }],
        })
    }

    /// Apply heuristics to a [`Usage::Conditional`] to attempt to refine it into
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
                Some(match cache_usage {
                    Usage::Conditional(origins) => Usage::Enabled(origins),
                    usage => usage,
                })
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
        let Some((action, cache_usage)) = self.evaluate_cache_usage(step) else {
            return Ok(None);
        };
        let coord = &action.coordinate;

        let cache_usage = if matches!(&cache_usage, Usage::Conditional(_)) {
            self.conditional_cache_usage_heuristics(coord, step, scenario, cache_usage)
        } else {
            Some(cache_usage)
        };

        let Some(cache_usage) = cache_usage else {
            return Ok(None);
        };

        let locations = match &cache_usage {
            Usage::Conditional(origins) => {
                let version_is_conditional = origins.contains(&ControlOrigin::UsesRef);
                let mut uses_location = step.location().primary().with_keys(["uses".into()]);
                if version_is_conditional {
                    uses_location = uses_location.annotated("action version may enable caching");
                }

                let mut locations = vec![uses_location];
                for origin in origins {
                    match origin {
                        ControlOrigin::Input { field } => locations.push(
                            step.location()
                                .with_keys(["with".into(), (*field).into()])
                                .annotated("may enable caching here"),
                        ),
                        ControlOrigin::WithExpression => locations.push(
                            step.location()
                                .with_keys(["with".into()])
                                .annotated("may enable caching here"),
                        ),
                        ControlOrigin::Default { .. } | ControlOrigin::UsesRef => {}
                    }
                }

                locations
            }
            Usage::Enabled(origins) => {
                let has_explicit_origin = origins.iter().any(|origin| {
                    matches!(
                        origin,
                        ControlOrigin::Input { .. } | ControlOrigin::WithExpression
                    )
                });
                let default_fields = origins
                    .iter()
                    .filter_map(|origin| match origin {
                        ControlOrigin::Default { field } => Some(format!("`{field}`")),
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                let default_annotation = if default_fields.is_empty() {
                    (!has_explicit_origin).then(|| "enables caching by default".to_string())
                } else {
                    let version_qualifier = if origins.contains(&ControlOrigin::UsesRef) {
                        " for this action version"
                    } else {
                        ""
                    };
                    Some(format!(
                        "omitting {} enables caching{version_qualifier}",
                        default_fields.join(" and ")
                    ))
                };

                // TODO: use a subfeature here. We'll need to plumb the `&'doc Uses` here,
                // maybe by having `Usage` wrap it as part of `ActionCoordinate::usage`?
                let mut uses_location = step.location().primary().with_keys(["uses".into()]);
                if let Some(annotation) = default_annotation {
                    uses_location = uses_location.annotated(annotation);
                }

                let mut locations = vec![uses_location];
                for origin in origins {
                    match origin {
                        ControlOrigin::Input { field } => locations.push(
                            step.location()
                                .with_keys(["with".into(), (*field).into()])
                                .annotated("enables caching explicitly here"),
                        ),
                        ControlOrigin::WithExpression => locations.push(
                            step.location()
                                .with_keys(["with".into()])
                                .annotated("enables caching explicitly here"),
                        ),
                        ControlOrigin::Default { .. } | ControlOrigin::UsesRef => {}
                    }
                }

                locations
            }
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
        if let Some(fix) = self.create_cache_disable_fix(action, step) {
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
