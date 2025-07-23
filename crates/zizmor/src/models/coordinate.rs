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

use github_actions_models::common::{EnvValue, Uses};
use indexmap::IndexMap;

use crate::utils::ExtractedExpr;

use super::{StepBodyCommon, StepCommon, uses::RepositoryUsesPattern};

pub(crate) enum ActionCoordinate {
    Configurable {
        /// The `uses:` pattern of the coordinate
        uses_pattern: RepositoryUsesPattern,
        /// The expression of fields that controls the coordinate
        control: ControlExpr,
    },
    NotConfigurable(RepositoryUsesPattern),
}

impl ActionCoordinate {
    pub(crate) fn uses_pattern(&self) -> &RepositoryUsesPattern {
        match self {
            ActionCoordinate::Configurable { uses_pattern, .. } => uses_pattern,
            ActionCoordinate::NotConfigurable(inner) => inner,
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

        let StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        } = step.body()
        else {
            return None;
        };

        // If our coordinate's `uses:` template doesn't match the step's `uses:`,
        // then no usage semantics are possible.
        if !uses_pattern.matches(uses) {
            return None;
        }

        match self {
            ActionCoordinate::Configurable {
                uses_pattern: _,
                control,
            } => match control.eval(with) {
                ControlEvaluation::DefaultSatisfied => Some(Usage::DefaultActionBehaviour),
                ControlEvaluation::Satisfied => Some(Usage::DirectOptIn),
                ControlEvaluation::NotSatisfied => None,
                ControlEvaluation::Conditional => Some(Usage::ConditionalOptIn),
            },
            // The mere presence of this `uses:` implies the expected usage semantics.
            ActionCoordinate::NotConfigurable(_) => Some(Usage::Always),
        }
    }
}

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
    /// the field is present, regardless of its value.
    FreeString,
    /// The behavior is controlled by a "fixed" string field, i.e. only applies
    /// when the field matches one of the given values.
    Exact(&'static [&'static str]),
}

/// The result of evaluating a control expression.
#[derive(Copy, Clone, PartialEq)]
pub(crate) enum ControlEvaluation {
    /// The control expression is satisfied by default.
    DefaultSatisfied,
    /// The control expression is satisfied.
    Satisfied,
    /// The control expression is not satisfied.
    NotSatisfied,
    /// The control expression is conditionally satisfied,
    /// i.e. depends on an actions expression or similar.
    Conditional,
}

impl Not for ControlEvaluation {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            ControlEvaluation::DefaultSatisfied => ControlEvaluation::NotSatisfied,
            ControlEvaluation::Satisfied => ControlEvaluation::NotSatisfied,
            ControlEvaluation::NotSatisfied => ControlEvaluation::Satisfied,
            ControlEvaluation::Conditional => ControlEvaluation::Conditional,
        }
    }
}

impl BitAnd for ControlEvaluation {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        // NOTE: This could be done less literally, but I find it easier to read.
        match (self, rhs) {
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::Conditional
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::Conditional
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::Conditional, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Conditional, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Conditional
            }
            (ControlEvaluation::Conditional, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::Conditional, ControlEvaluation::Conditional) => {
                ControlEvaluation::Conditional
            }
        }
    }
}

impl BitOr for ControlEvaluation {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        // TODO: Does this mapping make sense?
        match (self, rhs) {
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::DefaultSatisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Satisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::NotSatisfied
            }
            (ControlEvaluation::NotSatisfied, ControlEvaluation::Conditional) => {
                ControlEvaluation::Conditional
            }
            (ControlEvaluation::Conditional, ControlEvaluation::DefaultSatisfied) => {
                ControlEvaluation::DefaultSatisfied
            }
            (ControlEvaluation::Conditional, ControlEvaluation::Satisfied) => {
                ControlEvaluation::Satisfied
            }
            (ControlEvaluation::Conditional, ControlEvaluation::NotSatisfied) => {
                ControlEvaluation::Conditional
            }
            (ControlEvaluation::Conditional, ControlEvaluation::Conditional) => {
                ControlEvaluation::Conditional
            }
        }
    }
}

/// An "expression" of control fields.
///
/// This allows us to express basic quantified logic, such as
/// "all/any of these fields must be satisfied".
///
/// This is made slightly more complicated by the fact that our logic is
/// four-valued: control fields can be default-satisfied, explicitly satisfied,
/// not satisfied, or conditionally satisfied.
pub(crate) enum ControlExpr {
    /// A single control field.
    Single {
        /// What kind of toggle the input is.
        toggle: Toggle,
        /// The field that controls the action's behavior.
        field_name: &'static str,
        /// The type of the field that controls the action's behavior.
        field_type: ControlFieldType,
        /// Whether this control is satisfied by default, if not present.
        satisfied_by_default: bool,
    },
    /// Universal quantification: all of the fields must be satisfied.
    All(Vec<ControlExpr>),
    /// Existential quantification: any of the fields must be satisfied.
    #[allow(dead_code)]
    Any(Vec<ControlExpr>),
    /// Negation: the "opposite" of the expression's satisfaction.
    Not(Box<ControlExpr>),
}

impl ControlExpr {
    pub(crate) fn single(
        toggle: Toggle,
        field_name: &'static str,
        field_type: ControlFieldType,
        enabled_by_default: bool,
    ) -> Self {
        Self::Single {
            toggle,
            field_name,
            field_type,
            satisfied_by_default: enabled_by_default,
        }
    }

    pub(crate) fn all(exprs: impl IntoIterator<Item = ControlExpr>) -> Self {
        Self::All(exprs.into_iter().collect())
    }

    pub(crate) fn not(expr: ControlExpr) -> Self {
        Self::Not(Box::new(expr))
    }

    pub(crate) fn eval(&self, with: &IndexMap<String, EnvValue>) -> ControlEvaluation {
        match self {
            ControlExpr::Single {
                toggle,
                field_name,
                field_type,
                satisfied_by_default: enabled_by_default,
            } => {
                // If the controlling field is not present, the default dictates the semantics.
                if let Some(field_value) = with.get(*field_name) {
                    match field_type {
                        // We expect a boolean control.
                        ControlFieldType::Boolean => match field_value.to_string().as_str() {
                            "true" => match toggle {
                                Toggle::OptIn => ControlEvaluation::Satisfied,
                                Toggle::OptOut => ControlEvaluation::NotSatisfied,
                            },
                            "false" => match toggle {
                                Toggle::OptIn => ControlEvaluation::NotSatisfied,
                                Toggle::OptOut => ControlEvaluation::Satisfied,
                            },
                            other => match ExtractedExpr::from_fenced(other) {
                                // We have something like `foo: ${{ expr }}`,
                                // which could evaluate either way.
                                Some(_) => ControlEvaluation::Conditional,
                                // We have something like `foo: bar`, but we
                                // were expecting a boolean. Assume pessimistically
                                // that the action coerces any non-`false` value to `true`.
                                None => match toggle {
                                    Toggle::OptIn => ControlEvaluation::Satisfied,
                                    Toggle::OptOut => ControlEvaluation::NotSatisfied,
                                },
                            },
                        },
                        // We expect a "free" string control, i.e. any value.
                        // Evaluate just the toggle.
                        ControlFieldType::FreeString => match toggle {
                            Toggle::OptIn => ControlEvaluation::Satisfied,
                            Toggle::OptOut => ControlEvaluation::NotSatisfied,
                        },
                        // We expect a "fixed" string control, i.e. one of a set of values.
                        ControlFieldType::Exact(items) => {
                            if items.contains(&field_value.to_string().as_str()) {
                                match toggle {
                                    Toggle::OptIn => ControlEvaluation::Satisfied,
                                    Toggle::OptOut => ControlEvaluation::NotSatisfied,
                                }
                            } else {
                                match toggle {
                                    Toggle::OptIn => ControlEvaluation::NotSatisfied,
                                    Toggle::OptOut => ControlEvaluation::Satisfied,
                                }
                            }
                        }
                    }
                } else if *enabled_by_default {
                    ControlEvaluation::DefaultSatisfied
                } else {
                    ControlEvaluation::NotSatisfied
                }
            }
            ControlExpr::All(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(with))
                .fold(ControlEvaluation::Satisfied, |acc, expr| acc & expr),
            ControlExpr::Any(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(with))
                .fold(ControlEvaluation::NotSatisfied, |acc, expr| acc | expr),
            ControlExpr::Not(expr) => !expr.eval(with),
        }
    }
}

#[derive(PartialEq, Debug)]
pub(crate) enum Usage {
    ConditionalOptIn,
    DirectOptIn,
    DefaultActionBehaviour,
    Always,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::ActionCoordinate;
    use crate::{
        models::{
            coordinate::{ControlExpr, ControlFieldType, Toggle, Usage},
            uses::RepositoryUsesPattern,
            workflow::{Job, Workflow},
        },
        registry::InputKey,
    };

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
    "#;

        let workflow =
            Workflow::from_string(workflow.into(), InputKey::local("dummy", None).unwrap())
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
            assert_eq!(coord.usage(*step), Some(Usage::Always));
        }

        // Coordinate `uses:` matches but is not enabled by default and is
        // missing the needed control.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "set-me", ControlFieldType::Boolean, false),
        };
        let step = &steps[0];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step = &steps[4];
        assert_eq!(coord.usage(step), Some(Usage::DirectOptIn));

        // Coordinate `uses:` matches but is explicitly toggled off.
        let step = &steps[5];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and is enabled by default.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "set-me", ControlFieldType::Boolean, true),
        };
        let step = &steps[0];
        assert_eq!(coord.usage(step), Some(Usage::DefaultActionBehaviour));

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step = &steps[4];
        assert_eq!(coord.usage(step), Some(Usage::DirectOptIn));

        // Coordinate `uses:` matches but is explicitly toggled off, despite default enablement.
        let step = &steps[5];
        assert_eq!(coord.usage(step), None);

        // Coordinate `uses:` matches and has an opt-out toggle, which does not affect
        // the default.
        let coord = ActionCoordinate::Configurable {
            uses_pattern: RepositoryUsesPattern::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(
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
        assert_eq!(coord.usage(step), Some(Usage::DirectOptIn));
    }
}
