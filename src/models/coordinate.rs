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

use std::ops::{BitAnd, BitOr};

use github_actions_models::common::{EnvValue, Uses, expr::ExplicitExpr};
use indexmap::IndexMap;

use super::{StepBodyCommon, StepCommon};
use crate::models::uses::RepositoryUsesExt as _;

pub(crate) enum ActionCoordinate {
    Configurable {
        /// The `uses:` clause of the coordinate
        uses: Uses,
        /// The expression of fields that controls the coordinate
        control: ControlExpr,
    },
    NotConfigurable(Uses),
}

impl ActionCoordinate {
    pub(crate) fn uses(&self) -> &Uses {
        match self {
            ActionCoordinate::Configurable { uses, .. } => uses,
            ActionCoordinate::NotConfigurable(inner) => inner,
        }
    }

    /// Returns the semantic "usage" of the given step relative to the current coordinate.
    ///
    /// `None` indicates that the step is "unused" from the perspective of the coordinate,
    /// while the `Some(_)` variants indicate various (potential) usages (such as being implicitly
    /// enabled, or explicitly enabled, or potentially enabled by a template expansion that
    /// can't be directly analyzed).
    pub(crate) fn usage<'s>(&self, step: &impl StepCommon<'s>) -> Option<Usage> {
        let Uses::Repository(template) = self.uses() else {
            return None;
        };
        let StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        } = step.body()
        else {
            return None;
        };

        // If our coordinate's `uses:` template doesn't match the step's `uses:`,
        // then no usage semantics are possible.
        if !uses.matches_uses(template) {
            return None;
        }

        match self {
            ActionCoordinate::Configurable { uses: _, control } => {
                match control.eval(with) {
                    ControlStatus::DefaultSatisfied => Some(Usage::DefaultActionBehaviour),
                    ControlStatus::Satisfied => Some(Usage::DirectOptIn),
                    ControlStatus::NotSatisfied => None,
                    ControlStatus::Conditional => Some(Usage::ConditionalOptIn),
                }
                // // We need to inspect this `uses:`'s configuration to determine its semantics.
                // match with.get(control.field_name) {
                //     Some(field_value) => {
                //         // The declared usage is whatever the user explicitly configured,
                //         // which might be inverted if the toggle semantics are opt-out instead.
                //         self.declared_usage(field_value, &control.toggle, &control.field_type)
                //     }
                //     None => {
                //         // If the controlling field is not present, the default dictates the semantics.
                //         if *enabled_by_default {
                //             Some(Usage::DefaultActionBehaviour)
                //         } else {
                //             None
                //         }
                //     }
                // }
            }
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
    /// The behavior is controlled by a string field, e.g. `cache: "pip"`.
    String,
}

/// The result of evaluating a control expression.
#[derive(Copy, Clone, PartialEq)]
pub(crate) enum ControlStatus {
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

impl BitAnd for ControlStatus {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        // NOTE: This could be done less literally, but I find it easier to read.
        match (self, rhs) {
            (ControlStatus::DefaultSatisfied, ControlStatus::DefaultSatisfied) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::DefaultSatisfied, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::DefaultSatisfied, ControlStatus::NotSatisfied) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::DefaultSatisfied, ControlStatus::Conditional) => {
                ControlStatus::Conditional
            }
            (ControlStatus::Satisfied, ControlStatus::DefaultSatisfied) => ControlStatus::Satisfied,
            (ControlStatus::Satisfied, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::Satisfied, ControlStatus::NotSatisfied) => ControlStatus::NotSatisfied,
            (ControlStatus::Satisfied, ControlStatus::Conditional) => ControlStatus::Conditional,
            (ControlStatus::NotSatisfied, ControlStatus::DefaultSatisfied) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::NotSatisfied, ControlStatus::Satisfied) => ControlStatus::NotSatisfied,
            (ControlStatus::NotSatisfied, ControlStatus::NotSatisfied) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::NotSatisfied, ControlStatus::Conditional) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::Conditional, ControlStatus::DefaultSatisfied) => {
                ControlStatus::Satisfied
            }
            (ControlStatus::Conditional, ControlStatus::Satisfied) => ControlStatus::Conditional,
            (ControlStatus::Conditional, ControlStatus::NotSatisfied) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::Conditional, ControlStatus::Conditional) => ControlStatus::Conditional,
        }
    }
}

impl BitOr for ControlStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        // TODO: Does this mapping make sense?
        match (self, rhs) {
            (ControlStatus::DefaultSatisfied, ControlStatus::DefaultSatisfied) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::DefaultSatisfied, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::DefaultSatisfied, ControlStatus::NotSatisfied) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::DefaultSatisfied, ControlStatus::Conditional) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::Satisfied, ControlStatus::DefaultSatisfied) => ControlStatus::Satisfied,
            (ControlStatus::Satisfied, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::Satisfied, ControlStatus::NotSatisfied) => ControlStatus::Satisfied,
            (ControlStatus::Satisfied, ControlStatus::Conditional) => ControlStatus::Satisfied,
            (ControlStatus::NotSatisfied, ControlStatus::DefaultSatisfied) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::NotSatisfied, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::NotSatisfied, ControlStatus::NotSatisfied) => {
                ControlStatus::NotSatisfied
            }
            (ControlStatus::NotSatisfied, ControlStatus::Conditional) => ControlStatus::Conditional,
            (ControlStatus::Conditional, ControlStatus::DefaultSatisfied) => {
                ControlStatus::DefaultSatisfied
            }
            (ControlStatus::Conditional, ControlStatus::Satisfied) => ControlStatus::Satisfied,
            (ControlStatus::Conditional, ControlStatus::NotSatisfied) => ControlStatus::Conditional,
            (ControlStatus::Conditional, ControlStatus::Conditional) => ControlStatus::Conditional,
        }
    }
}

/// An "expression" of control fields.
///
/// This allows us to express basic quantified logic, such as
/// "all/any of these fields must be satisfied".
///
/// This is made slightly more complicated by the fact that our logic is
/// three-valued: control fields can be satisfied, not satisfied, or conditionally
/// satisfied.
pub(crate) enum ControlExpr {
    Single {
        /// What kind of toggle the input is.
        toggle: Toggle,
        /// The field that controls the action's behavior.
        field_name: &'static str,
        /// The type of the field that controls the action's behavior.
        field_type: ControlFieldType,
        /// Whether this control is enabled by default, if not present.
        enabled_by_default: bool,
    },
    All(Vec<ControlExpr>),
    #[allow(dead_code)]
    Any(Vec<ControlExpr>),
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
            enabled_by_default,
        }
    }

    pub(crate) fn all(exprs: impl IntoIterator<Item = ControlExpr>) -> Self {
        Self::All(exprs.into_iter().collect())
    }

    pub(crate) fn eval(&self, with: &IndexMap<String, EnvValue>) -> ControlStatus {
        match self {
            ControlExpr::Single {
                toggle,
                field_name,
                field_type,
                enabled_by_default,
            } => {
                // If the controlling field is not present, the default dictates the semantics.
                if let Some(field_value) = with.get(*field_name) {
                    match field_value.to_string().as_str() {
                        "false" if matches!(field_type, ControlFieldType::Boolean) => {
                            match toggle {
                                Toggle::OptIn => ControlStatus::NotSatisfied,
                                Toggle::OptOut => ControlStatus::Satisfied,
                            }
                        }
                        other => match ExplicitExpr::from_curly(other) {
                            None => match toggle {
                                Toggle::OptIn => ControlStatus::Satisfied,
                                Toggle::OptOut => ControlStatus::NotSatisfied,
                            },
                            Some(_) => ControlStatus::Conditional,
                        },
                    }
                } else if *enabled_by_default {
                    ControlStatus::DefaultSatisfied
                } else {
                    ControlStatus::NotSatisfied
                }
            }
            ControlExpr::All(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(with))
                .fold(ControlStatus::Satisfied, |acc, expr| acc & expr),
            ControlExpr::Any(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(with))
                .fold(ControlStatus::NotSatisfied, |acc, expr| acc | expr),
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

    use github_actions_models::{common::Uses, workflow::job::Step};

    use super::{ActionCoordinate, StepCommon};
    use crate::models::coordinate::{ControlExpr, ControlFieldType, Toggle, Usage};

    // Test-only trait impl.
    impl<'s> StepCommon<'s> for Step {
        fn env_is_static(&self, _name: &str) -> bool {
            unimplemented!()
        }

        fn strategy(&self) -> Option<&github_actions_models::workflow::job::Strategy> {
            unimplemented!()
        }

        fn body(&self) -> super::StepBodyCommon {
            match &self.body {
                github_actions_models::workflow::job::StepBody::Uses { uses, with } => {
                    super::StepBodyCommon::Uses { uses, with }
                }
                github_actions_models::workflow::job::StepBody::Run {
                    run,
                    working_directory,
                    shell,
                    env,
                } => super::StepBodyCommon::Run {
                    run,
                    _working_directory: working_directory.as_deref(),
                    _shell: shell.as_deref(),
                    _env: env,
                },
            }
        }

        fn location(&self) -> crate::models::SymbolicLocation<'s> {
            unimplemented!()
        }
    }

    #[test]
    fn test_usage() {
        // Trivial case: no usage is possible, since the coordinate's `uses:`
        // does not match the step.
        let coord = ActionCoordinate::NotConfigurable(Uses::from_str("foo/bar").unwrap());
        let step: Step = serde_yaml::from_str("uses: not/thesame").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Trivial cases: coordinate is not configurable and matches the `uses:`.
        for step in &["uses: foo/bar", "uses: foo/bar@v1"] {
            let step: Step = serde_yaml::from_str(step).unwrap();
            assert_eq!(coord.usage(&step), Some(Usage::Always));
        }

        // Coordinate `uses:` matches but is not enabled by default and is
        // missing the needed control.
        let coord = ActionCoordinate::Configurable {
            uses: Uses::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "set-me", ControlFieldType::Boolean, false),
        };
        let step: Step = serde_yaml::from_str("uses: foo/bar").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step: Step = serde_yaml::from_str("uses: foo/bar\nwith:\n  set-me: true").unwrap();
        assert_eq!(coord.usage(&step), Some(Usage::DirectOptIn));

        // Coordinate `uses:` matches but is explicitly toggled off.
        let step: Step = serde_yaml::from_str("uses: foo/bar\nwith:\n  set-me: false").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Coordinate `uses:` matches and is enabled by default.
        let coord = ActionCoordinate::Configurable {
            uses: Uses::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "set-me", ControlFieldType::Boolean, true),
        };
        let step: Step = serde_yaml::from_str("uses: foo/bar").unwrap();
        assert_eq!(coord.usage(&step), Some(Usage::DefaultActionBehaviour));

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step: Step = serde_yaml::from_str("uses: foo/bar\nwith:\n  set-me: true").unwrap();
        assert_eq!(coord.usage(&step), Some(Usage::DirectOptIn));

        // Coordinate `uses:` matches but is explicitly toggled off, despite default enablement.
        let step: Step = serde_yaml::from_str("uses: foo/bar\nwith:\n  set-me: false").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Coordinate `uses:` matches and has an opt-out toggle, which does not affect
        // the default.
        let coord = ActionCoordinate::Configurable {
            uses: Uses::from_str("foo/bar").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "disable-cache",
                ControlFieldType::Boolean,
                false,
            ),
        };
        let step: Step = serde_yaml::from_str("uses: foo/bar").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Coordinate `uses:` matches and the opt-out inverts the match, clearing it.
        let step: Step =
            serde_yaml::from_str("uses: foo/bar\nwith:\n  disable-cache: true").unwrap();
        assert_eq!(coord.usage(&step), None);

        // Coordinate `uses:` matches and the opt-out inverts the match, clearing it.
        let step: Step =
            serde_yaml::from_str("uses: foo/bar\nwith:\n  disable-cache: false").unwrap();
        assert_eq!(coord.usage(&step), Some(Usage::DirectOptIn));
    }
}
