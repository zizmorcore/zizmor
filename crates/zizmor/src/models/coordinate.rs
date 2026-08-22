//! Functionality for describing and matching `uses:` "coordinates."
//!
//! A "coordinate" is a set of conditions which a `uses:` step can match.
//! These conditions can be non-trivial, such as "match `actions/checkout`,
//! but only if `persist-credentials: false`" is present.
//!
//! Coordinates are useful building blocks for audits like `cache-poisoning`,
//! which need to check a diversity of different step "shapes" to accurately
//! flag potential cache poisoning patterns.

// TODO: We would ideally be even more expressive here and allow basic
// sentential logic and in-field matching. For example, we would ideally be
// able to express things like
// "match foo/bar if foo: A and not bar: B and baz: /abcd/"

use std::ops::{BitAnd, BitOr, Not};

use github_actions_models::common::{EnvValue, RepositoryUses, Uses, expr::LoE};
use indexmap::IndexMap;

use crate::{
    finding::location::Comment,
    models::{uses::RepositoryUsesExt as _, version::Version},
    utils::ExtractedExpr,
};

use super::{StepBodyCommon, StepCommon, uses::RepositoryUsesPattern};

pub(crate) enum ActionCoordinate {
    Configurable {
        /// The `uses:` pattern of the coordinate
        uses_pattern: RepositoryUsesPattern,
        /// The expression of fields that controls the coordinate
        control: ControlExpr<'static>,
    },
    NotConfigurable(RepositoryUsesPattern),
}

impl ActionCoordinate {
    pub(crate) fn uses_pattern(&self) -> &RepositoryUsesPattern {
        match self {
            Self::Configurable { uses_pattern, .. } => uses_pattern,
            Self::NotConfigurable(inner) => inner,
        }
    }

    /// Returns the semantic "usage" of the given step relative to the current coordinate.
    ///
    /// `None` indicates that the step is "unused" from the perspective of the coordinate,
    /// while the `Some(_)` variants indicate various (potential) usages (such as being implicitly
    /// enabled, or explicitly enabled, or potentially enabled by a template expansion that
    /// can't be directly analyzed).
    pub(crate) fn usage<'doc>(&self, step: &impl StepCommon<'doc>) -> Option<Usage> {
        let uses_pattern = self.uses_pattern();

        let Some(StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        }) = step.body()
        else {
            return None;
        };

        // If our coordinate's `uses:` template doesn't match the step's `uses:`,
        // then no usage semantics are possible.
        if !uses_pattern.matches(&uses.into()) {
            return None;
        }

        let step_location = step.location();
        let uses_location = step_location
            .with_keys(["uses".into()])
            .concretize(step.document())
            .ok()?;

        match self {
            Self::Configurable {
                uses_pattern: _,
                control,
            } => {
                let LoE::Literal(with) = with else {
                    return Some(Usage::conditional([ControlOrigin::WithExpression]));
                };
                let evaluation = control.eval(uses, &uses_location.concrete.comments, with);
                match evaluation.state {
                    ControlState::Satisfied => Some(Usage::enabled(evaluation.origins)),
                    ControlState::NotSatisfied => None,
                    ControlState::Conditional => Some(Usage::conditional(evaluation.origins)),
                }
            }
            // The mere presence of this `uses:` implies the expected usage semantics.
            Self::NotConfigurable(_) => Some(Usage::always()),
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) enum Toggle {
    /// Opt-in means that usage is **enabled** when the control value matches.
    OptIn,
    /// Opt-out means that usage is **disabled** when the control value matches.
    OptOut,
}

/// The type of value that controls the step's behavior.
#[derive(PartialEq)]
pub(crate) enum ControlFieldType {
    /// The behavior is controlled by a boolean field, e.g. `cache: true`.
    Boolean,
    /// The behavior is controlled by a "free" string field.
    ///
    /// This is effectively a "presence" check, i.e. is satisfied if
    /// the field is present and nonempty, regardless of its value.
    FreeString,
    /// The behavior is controlled by a "fixed" string field, i.e. only applies
    /// when the field matches one of the given values.
    Exact(&'static [&'static str]),
}

/// The logical result of evaluating a control expression.
#[derive(Copy, Clone, Debug, PartialEq)]
enum ControlState {
    /// The control expression is satisfied.
    Satisfied,
    /// The control expression is not satisfied.
    NotSatisfied,
    /// The result depends on an Actions expression or another value that can't
    /// be determined statically.
    Conditional,
}

/// The part of a step that determined a control expression's result.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum ControlOrigin {
    /// A missing input whose action-defined default determined the result.
    Default { field: &'static str },
    /// An explicitly configured action input.
    Input { field: &'static str },
    /// The action reference in `uses:`, such as its version.
    UsesRef,
    /// An expression that supplies the entire `with:` mapping.
    WithExpression,
}

/// The result of evaluating a control expression, including the evidence that
/// produced that result.
#[derive(Clone, Debug, PartialEq)]
struct ControlEvaluation {
    state: ControlState,
    origins: Vec<ControlOrigin>,
}

impl ControlEvaluation {
    fn new(state: ControlState, origin: ControlOrigin) -> Self {
        Self {
            state,
            origins: vec![origin],
        }
    }

    fn without_origins(state: ControlState) -> Self {
        Self {
            state,
            origins: vec![],
        }
    }

    fn decisive_origins(
        state: ControlState,
        evaluations: impl IntoIterator<Item = Self>,
    ) -> Vec<ControlOrigin> {
        let mut origins = vec![];

        for evaluation in evaluations {
            if evaluation.state != state {
                continue;
            }

            for origin in evaluation.origins {
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
        }

        origins
    }
}

impl Not for ControlEvaluation {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        self.state = match self.state {
            ControlState::Satisfied => ControlState::NotSatisfied,
            ControlState::NotSatisfied => ControlState::Satisfied,
            ControlState::Conditional => ControlState::Conditional,
        };

        self
    }
}

impl BitAnd for ControlEvaluation {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let state = match (self.state, rhs.state) {
            (ControlState::NotSatisfied, _) | (_, ControlState::NotSatisfied) => {
                ControlState::NotSatisfied
            }
            (ControlState::Conditional, _) | (_, ControlState::Conditional) => {
                ControlState::Conditional
            }
            (ControlState::Satisfied, ControlState::Satisfied) => ControlState::Satisfied,
        };

        Self {
            state,
            origins: Self::decisive_origins(state, [self, rhs]),
        }
    }
}

impl BitOr for ControlEvaluation {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let state = match (self.state, rhs.state) {
            (ControlState::Satisfied, _) | (_, ControlState::Satisfied) => ControlState::Satisfied,
            (ControlState::Conditional, _) | (_, ControlState::Conditional) => {
                ControlState::Conditional
            }
            (ControlState::NotSatisfied, ControlState::NotSatisfied) => ControlState::NotSatisfied,
        };

        Self {
            state,
            origins: Self::decisive_origins(state, [self, rhs]),
        }
    }
}

pub(crate) enum VersionBound<'a> {
    #[allow(dead_code)]
    Exact(Version<'a>),
    LessThan(Version<'a>),
    #[allow(dead_code)]
    GreaterThan(Version<'a>),
    // TODO: Not(Version)?
}

impl<'a> VersionBound<'a> {
    /// Evaluate a `uses:` clause (and its comments) against a version bound.
    ///
    /// This is currently offline to keep it fast. As a result, some evaluations
    /// are conditional, e.g. `uses: foo/bar@<commit>` with no version comment.
    /// In the future we could make it online.
    fn eval(&self, uses: &RepositoryUses, comments: &[Comment]) -> ControlEvaluation {
        let version = if let Some(sym_ref) = uses.symbolic_ref() {
            // We have a tag (or branch) reference, which we'll try and treat as a version.
            Version::parse(sym_ref).ok()
        } else {
            // We have a commit reference, which means we need to try and discover the version
            // in the comments.
            comments.iter().find_map(Version::from_comment)
        };

        let Some(ref version) = version else {
            // No detectable version; treat as conditional.
            return ControlEvaluation::new(ControlState::Conditional, ControlOrigin::UsesRef);
        };

        let state = match self {
            VersionBound::Exact(control) => {
                if version == control {
                    ControlState::Satisfied
                } else {
                    ControlState::NotSatisfied
                }
            }
            VersionBound::LessThan(control) => {
                if version < control {
                    ControlState::Satisfied
                } else {
                    ControlState::NotSatisfied
                }
            }
            VersionBound::GreaterThan(control) => {
                if version > control {
                    ControlState::Satisfied
                } else {
                    ControlState::NotSatisfied
                }
            }
        };

        ControlEvaluation::new(state, ControlOrigin::UsesRef)
    }
}

/// An "expression" of control fields.
///
/// This allows us to express basic quantified logic, such as
/// "all/any of these fields must be satisfied".
///
/// Evaluations also retain the origins that determined their logical result,
/// allowing consumers to distinguish inputs, defaults, and `uses:` constraints.
pub(crate) enum ControlExpr<'a> {
    /// A bound on the action's version.
    VersionBound(VersionBound<'a>),
    /// A single control field.
    Field {
        /// What kind of toggle the input is.
        toggle: Toggle,
        /// The field that controls the action's behavior.
        field_name: &'static str,
        /// The type of the field that controls the action's behavior.
        field_type: ControlFieldType,
        /// Whether this control is satisfied by default, if not present.
        satisfied_by_default: bool,
    },
    /// Universal quantification: all of the constraints must be satisfied.
    All(Vec<Self>),
    /// Existential quantification: any of the constraints must be satisfied.
    Any(Vec<Self>),
    /// Negation: the "opposite" of the expression's satisfaction.
    Not(Box<Self>),
}

impl<'a> ControlExpr<'a> {
    pub(crate) fn field(
        toggle: Toggle,
        field_name: &'static str,
        field_type: ControlFieldType,
        enabled_by_default: bool,
    ) -> Self {
        Self::Field {
            toggle,
            field_name,
            field_type,
            satisfied_by_default: enabled_by_default,
        }
    }

    pub(crate) fn all(exprs: impl IntoIterator<Item = Self>) -> Self {
        Self::All(exprs.into_iter().collect())
    }

    pub(crate) fn any(exprs: impl IntoIterator<Item = Self>) -> Self {
        Self::Any(exprs.into_iter().collect())
    }

    pub(crate) fn not(expr: Self) -> Self {
        Self::Not(Box::new(expr))
    }

    fn eval(
        &self,
        uses: &RepositoryUses,
        comments: &[Comment],
        with: &IndexMap<String, EnvValue>,
    ) -> ControlEvaluation {
        match self {
            Self::VersionBound(vb) => vb.eval(uses, comments),
            Self::Field {
                toggle,
                field_name,
                field_type,
                satisfied_by_default: enabled_by_default,
            } => {
                // If the controlling field is not present, the default dictates the semantics.
                let (state, origin) = if let Some(field_value) = with.get(*field_name) {
                    let state = match field_type {
                        // We expect a boolean control.
                        ControlFieldType::Boolean => match field_value.to_string().as_str() {
                            "true" => match toggle {
                                Toggle::OptIn => ControlState::Satisfied,
                                Toggle::OptOut => ControlState::NotSatisfied,
                            },
                            "false" => match toggle {
                                Toggle::OptIn => ControlState::NotSatisfied,
                                Toggle::OptOut => ControlState::Satisfied,
                            },
                            other => match ExtractedExpr::from_fenced(other) {
                                // We have something like `foo: ${{ expr }}`,
                                // which could evaluate either way.
                                Some(_) => ControlState::Conditional,
                                // We have something like `foo: bar`, but we
                                // were expecting a boolean. Assume pessimistically
                                // that the action coerces any non-`false` value to `true`.
                                None => match toggle {
                                    Toggle::OptIn => ControlState::Satisfied,
                                    Toggle::OptOut => ControlState::NotSatisfied,
                                },
                            },
                        },
                        // We expect a "free" string control, i.e. any value.
                        // Evaluate just the toggle.
                        ControlFieldType::FreeString => match field_value.is_empty() {
                            true => match toggle {
                                Toggle::OptIn => ControlState::NotSatisfied,
                                Toggle::OptOut => ControlState::Satisfied,
                            },
                            false => match toggle {
                                Toggle::OptIn => ControlState::Satisfied,
                                Toggle::OptOut => ControlState::NotSatisfied,
                            },
                        },
                        // We expect a "fixed" string control, i.e. one of a set of values.
                        ControlFieldType::Exact(items) => {
                            if items.contains(&field_value.to_string().as_str()) {
                                match toggle {
                                    Toggle::OptIn => ControlState::Satisfied,
                                    Toggle::OptOut => ControlState::NotSatisfied,
                                }
                            } else {
                                match toggle {
                                    Toggle::OptIn => ControlState::NotSatisfied,
                                    Toggle::OptOut => ControlState::Satisfied,
                                }
                            }
                        }
                    };

                    (state, ControlOrigin::Input { field: field_name })
                } else if *enabled_by_default {
                    (
                        ControlState::Satisfied,
                        ControlOrigin::Default { field: field_name },
                    )
                } else {
                    (
                        ControlState::NotSatisfied,
                        ControlOrigin::Default { field: field_name },
                    )
                };

                ControlEvaluation::new(state, origin)
            }
            Self::All(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(uses, comments, with))
                .fold(
                    ControlEvaluation::without_origins(ControlState::Satisfied),
                    |acc, expr| acc & expr,
                ),
            Self::Any(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(uses, comments, with))
                .fold(
                    ControlEvaluation::without_origins(ControlState::NotSatisfied),
                    |acc, expr| acc | expr,
                ),
            Self::Not(expr) => !expr.eval(uses, comments, with),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum UsageState {
    Enabled,
    Conditional,
    Always,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Usage {
    state: UsageState,
    origins: Vec<ControlOrigin>,
}

impl Usage {
    fn enabled(origins: impl IntoIterator<Item = ControlOrigin>) -> Self {
        Self {
            state: UsageState::Enabled,
            origins: origins.into_iter().collect(),
        }
    }

    fn conditional(origins: impl IntoIterator<Item = ControlOrigin>) -> Self {
        Self {
            state: UsageState::Conditional,
            origins: origins.into_iter().collect(),
        }
    }

    fn always() -> Self {
        Self {
            state: UsageState::Always,
            origins: vec![ControlOrigin::UsesRef],
        }
    }

    pub(crate) fn state(&self) -> UsageState {
        self.state
    }

    pub(crate) fn origins(&self) -> &[ControlOrigin] {
        &self.origins
    }

    pub(crate) fn into_enabled(mut self) -> Self {
        self.state = UsageState::Enabled;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use github_actions_models::common::{EnvValue, RepositoryUses};
    use indexmap::IndexMap;

    use super::{
        ActionCoordinate, ControlEvaluation, ControlExpr, ControlFieldType, ControlOrigin,
        ControlState, Toggle, Usage, VersionBound,
    };
    use crate::{
        models::{
            uses::RepositoryUsesPattern,
            version::Version,
            workflow::{Job, Workflow},
        },
        registry::input::InputKey,
    };

    /// Test evaluation for a `FreeString` control, specifically that empty
    /// strings are treated as "not set."
    #[test]
    fn test_freestring_control() {
        let optin_control =
            ControlExpr::field(Toggle::OptIn, "set-me", ControlFieldType::FreeString, false);
        let optout_control =
            ControlExpr::field(Toggle::OptOut, "set-me", ControlFieldType::FreeString, true);

        let uses = RepositoryUses::parse("foo/bar@doesnotmatter").unwrap();
        let with_enabled = IndexMap::from([("set-me".into(), EnvValue::String("anything".into()))]);
        let with_disabled = IndexMap::from([("set-me".into(), EnvValue::String("".into()))]);

        assert_eq!(
            optin_control.eval(&uses, &[], &with_enabled),
            ControlEvaluation::new(
                ControlState::Satisfied,
                ControlOrigin::Input { field: "set-me" }
            )
        );
        assert_eq!(
            optin_control.eval(&uses, &[], &with_disabled),
            ControlEvaluation::new(
                ControlState::NotSatisfied,
                ControlOrigin::Input { field: "set-me" }
            )
        );
        assert_eq!(
            optout_control.eval(&uses, &[], &with_enabled),
            ControlEvaluation::new(
                ControlState::NotSatisfied,
                ControlOrigin::Input { field: "set-me" }
            )
        );
        assert_eq!(
            optout_control.eval(&uses, &[], &with_disabled),
            ControlEvaluation::new(
                ControlState::Satisfied,
                ControlOrigin::Input { field: "set-me" }
            )
        );
    }

    #[test]
    fn test_version_bound_provenance() {
        let control = ControlExpr::all([
            ControlExpr::VersionBound(VersionBound::LessThan(Version::parse("v10").unwrap())),
            ControlExpr::field(
                Toggle::OptIn,
                "enable-cache",
                ControlFieldType::Boolean,
                true,
            ),
        ]);

        let v6 = RepositoryUses::parse("foo/bar@v6.5.0").unwrap();
        assert_eq!(
            control.eval(&v6, &[], &IndexMap::new()),
            ControlEvaluation {
                state: ControlState::Satisfied,
                origins: vec![
                    ControlOrigin::UsesRef,
                    ControlOrigin::Default {
                        field: "enable-cache"
                    },
                ],
            }
        );

        let explicit = IndexMap::from([("enable-cache".into(), EnvValue::Boolean(true))]);
        assert_eq!(
            control.eval(&v6, &[], &explicit),
            ControlEvaluation {
                state: ControlState::Satisfied,
                origins: vec![
                    ControlOrigin::UsesRef,
                    ControlOrigin::Input {
                        field: "enable-cache"
                    },
                ],
            }
        );

        let unknown =
            RepositoryUses::parse("foo/bar@d9e0f98d3fc6adb07d1e3d37f3043649ddad06a1").unwrap();
        assert_eq!(
            control.eval(&unknown, &[], &IndexMap::new()),
            ControlEvaluation::new(ControlState::Conditional, ControlOrigin::UsesRef)
        );
    }

    #[test]
    fn test_usage() {
        let workflow = r#"
    name: test_usage
    on: push
    jobs:
      test_usage:
        runs-on: ubuntu-latest
        steps:
          - uses: foo/bar@v1      # 0

          - uses: foo/bar@v1      # 1

          - uses: not/thesame@v1  # 2
            with:
              set-me: true

          - uses: not/thesame@v1  # 3

          - uses: foo/bar@v1      # 4
            with:
              set-me: true

          - uses: foo/bar@v1      # 5
            with:
              set-me: false

          - uses: foo/bar@v1      # 6
            with:
              disable-cache: true

          - uses: foo/bar@v1      # 7
            with:
              disable-cache: false

          - uses: foo/bar@v1      # 8
            with: ${{ fromJson(steps.setup.outputs.options) }}
    "#;

        let workflow = Workflow::from_string(
            workflow.into(),
            InputKey::local("fakegroup".into(), "dummy", None, None),
        )
        .unwrap();

        let Job::NormalJob(job) = workflow.jobs().next().unwrap() else {
            panic!("Expected a normal job");
        };

        let steps = job.steps().collect::<Vec<_>>();

        // Trivial case: no usage is possible, since the coordinate's `uses:`
        // does not match the step.
        let coord =
            ActionCoordinate::NotConfigurable(RepositoryUsesPattern::from_str("foo/bar").unwrap());
        let step = &steps[3];
        assert_eq!(coord.usage(step), None);

        // Trivial cases: coordinate is not configurable and matches the `uses:`.
        for step in &[&steps[0], &steps[1]] {
            assert_eq!(coord.usage(*step), Some(Usage::always()));
        }

        // Coordinate `uses:` matches but is not enabled by default and is
        // missing the needed control.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "set-me", ControlFieldType::Boolean, false),
        };
        let step = &steps[0];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step = &steps[4];
        assert_eq!(
            coord.usage(step),
            Some(Usage::enabled([ControlOrigin::Input { field: "set-me" }]))
        );

        // Coordinate `uses:` matches but is explicitly toggled off.
        let step = &steps[5];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and is enabled by default.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::field(Toggle::OptIn, "set-me", ControlFieldType::Boolean, true),
        };
        let step = &steps[0];
        assert_eq!(
            coord.usage(step),
            Some(Usage::enabled([ControlOrigin::Default { field: "set-me" }]))
        );

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step = &steps[4];
        assert_eq!(
            coord.usage(step),
            Some(Usage::enabled([ControlOrigin::Input { field: "set-me" }]))
        );

        // Coordinate `uses:` matches but is explicitly toggled off, despite default enablement.
        let step = &steps[5];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and has an opt-out toggle, which does not affect
        // the default.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::field(
                Toggle::OptOut,
                "disable-cache",
                ControlFieldType::Boolean,
                false,
            ),
        };
        let step = &steps[0];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and the opt-out inverts the match, clearing it.
        let step = &steps[6];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and the opt-out inverts the match, clearing it.
        let step = &steps[7];
        assert_eq!(
            coord.usage(step),
            Some(Usage::enabled([ControlOrigin::Input {
                field: "disable-cache"
            }]))
        );

        // Coordinate `uses:` matches but `with:` is an expression.
        let step = &steps[8];
        assert_eq!(
            coord.usage(step),
            Some(Usage::conditional([ControlOrigin::WithExpression]))
        );
    }
}
