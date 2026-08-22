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
use indexmap::{IndexMap, IndexSet, indexset};

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

        // Only `uses:` clauses are analyzed at the moment.
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
                    return Some(Usage::Conditional(indexset! {
                        ControlOrigin::WithExpression
                    }));
                };
                match control.eval(uses, &uses_location.concrete.comments, with) {
                    ControlEvaluation::Satisfied(origins) => Some(Usage::Enabled(origins)),
                    ControlEvaluation::NotSatisfied(_) => None,
                    ControlEvaluation::Conditional(origins) => Some(Usage::Conditional(origins)),
                }
            }
            // The mere presence of this `uses:` implies the expected usage semantics.
            Self::NotConfigurable(_) => Some(Usage::Always),
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

/// The part of a step that determined a control expression's result.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ControlOrigin {
    /// A missing input whose action-defined default determined the result.
    ///
    /// For example, an action that has a default of `cache: true`, where usage
    /// of the action does not override `cache`.
    Default { field: &'static str },
    /// An explicitly configured action input.
    ///
    /// For example, a user explicitly setting `cache: true`.
    Input { field: &'static str },
    /// The `uses:` clause itself.
    ///
    /// For example, if we know that `actions/foo@v4` and earlier enable caching
    /// unconditionally, then we way that the `uses:` clause determines the overall
    /// result.
    UsesRef,
    /// An expression that supplies the entire `with:` mapping.
    ///
    /// This happens if the entire `with:` clause is opaque, e.g. `with: ${{ expr }}`.
    WithExpression,
}

/// The logical result of evaluating a control expression, together with the
/// evidence that produced that result.
#[derive(Clone, Debug, PartialEq)]
enum ControlEvaluation {
    /// The control expression is satisfied.
    Satisfied(IndexSet<ControlOrigin>),
    /// The control expression is not satisfied.
    NotSatisfied(IndexSet<ControlOrigin>),
    /// The result depends on an Actions expression or another value that can't
    /// be determined statically.
    Conditional(IndexSet<ControlOrigin>),
}

impl Not for ControlEvaluation {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Self::Satisfied(origins) => Self::NotSatisfied(origins),
            Self::NotSatisfied(origins) => Self::Satisfied(origins),
            Self::Conditional(origins) => Self::Conditional(origins),
        }
    }
}

impl BitAnd for ControlEvaluation {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::NotSatisfied(mut lhs), Self::NotSatisfied(rhs)) => {
                lhs.extend(rhs);
                Self::NotSatisfied(lhs)
            }
            (Self::NotSatisfied(origins), _) | (_, Self::NotSatisfied(origins)) => {
                Self::NotSatisfied(origins)
            }
            (Self::Conditional(mut lhs), Self::Conditional(rhs)) => {
                lhs.extend(rhs);
                Self::Conditional(lhs)
            }
            (Self::Conditional(origins), Self::Satisfied(_))
            | (Self::Satisfied(_), Self::Conditional(origins)) => Self::Conditional(origins),
            (Self::Satisfied(mut lhs), Self::Satisfied(rhs)) => {
                lhs.extend(rhs);
                Self::Satisfied(lhs)
            }
        }
    }
}

impl BitOr for ControlEvaluation {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Satisfied(mut lhs), Self::Satisfied(rhs)) => {
                lhs.extend(rhs);
                Self::Satisfied(lhs)
            }
            (Self::Satisfied(origins), _) | (_, Self::Satisfied(origins)) => {
                Self::Satisfied(origins)
            }
            (Self::Conditional(mut lhs), Self::Conditional(rhs)) => {
                lhs.extend(rhs);
                Self::Conditional(lhs)
            }
            (Self::Conditional(origins), Self::NotSatisfied(_))
            | (Self::NotSatisfied(_), Self::Conditional(origins)) => Self::Conditional(origins),
            (Self::NotSatisfied(mut lhs), Self::NotSatisfied(rhs)) => {
                lhs.extend(rhs);
                Self::NotSatisfied(lhs)
            }
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
            return ControlEvaluation::Conditional(indexset! { ControlOrigin::UsesRef });
        };

        let satisfied = match self {
            VersionBound::Exact(control) => version == control,
            VersionBound::LessThan(control) => version < control,
            VersionBound::GreaterThan(control) => version > control,
        };

        if satisfied {
            ControlEvaluation::Satisfied(indexset! { ControlOrigin::UsesRef })
        } else {
            ControlEvaluation::NotSatisfied(indexset! { ControlOrigin::UsesRef })
        }
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
                if let Some(field_value) = with.get(*field_name) {
                    let control_value = match field_type {
                        // We expect a boolean control.
                        ControlFieldType::Boolean => match field_value.to_string().as_str() {
                            "true" => Some(true),
                            "false" => Some(false),
                            other => match ExtractedExpr::from_fenced(other) {
                                // We have something like `foo: ${{ expr }}`,
                                // which could evaluate either way.
                                Some(_) => None,
                                // We have something like `foo: bar`, but we
                                // were expecting a boolean. Assume pessimistically
                                // that the action coerces any non-`false` value to `true`.
                                None => Some(true),
                            },
                        },
                        // We expect a "free" string control, i.e. any value.
                        // Evaluate just the toggle.
                        ControlFieldType::FreeString => Some(!field_value.is_empty()),
                        // We expect a "fixed" string control, i.e. one of a set of values.
                        ControlFieldType::Exact(items) => {
                            let value = field_value.to_string();
                            if ExtractedExpr::from_fenced(&value).is_some() {
                                // Like `ControlFieldType::Boolean`, this could
                                // evaluate any way.
                                None
                            } else {
                                Some(items.contains(&value.as_str()))
                            }
                        }
                    };

                    let origins = indexset! { ControlOrigin::Input { field: field_name } };
                    match (control_value, toggle) {
                        (None, _) => ControlEvaluation::Conditional(origins),
                        (Some(true), Toggle::OptIn) | (Some(false), Toggle::OptOut) => {
                            ControlEvaluation::Satisfied(origins)
                        }
                        (Some(false), Toggle::OptIn) | (Some(true), Toggle::OptOut) => {
                            ControlEvaluation::NotSatisfied(origins)
                        }
                    }
                } else if *enabled_by_default {
                    ControlEvaluation::Satisfied(indexset! {
                        ControlOrigin::Default { field: field_name }
                    })
                } else {
                    ControlEvaluation::NotSatisfied(indexset! {
                        ControlOrigin::Default { field: field_name }
                    })
                }
            }
            Self::All(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(uses, comments, with))
                .fold(
                    ControlEvaluation::Satisfied(IndexSet::new()),
                    |acc, expr| acc & expr,
                ),
            Self::Any(exprs) => exprs
                .iter()
                .map(|expr| expr.eval(uses, comments, with))
                .fold(
                    ControlEvaluation::NotSatisfied(IndexSet::new()),
                    |acc, expr| acc | expr,
                ),
            Self::Not(expr) => !expr.eval(uses, comments, with),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Usage {
    Enabled(IndexSet<ControlOrigin>),
    Conditional(IndexSet<ControlOrigin>),
    Always,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use github_actions_models::common::{EnvValue, RepositoryUses};
    use indexmap::{IndexMap, indexset};

    use super::{
        ActionCoordinate, ControlEvaluation, ControlExpr, ControlFieldType, ControlOrigin, Toggle,
        Usage, VersionBound,
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
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::Input { field: "set-me" }
            })
        );
        assert_eq!(
            optin_control.eval(&uses, &[], &with_disabled),
            ControlEvaluation::NotSatisfied(indexset! {
                ControlOrigin::Input { field: "set-me" }
            })
        );
        assert_eq!(
            optout_control.eval(&uses, &[], &with_enabled),
            ControlEvaluation::NotSatisfied(indexset! {
                ControlOrigin::Input { field: "set-me" }
            })
        );
        assert_eq!(
            optout_control.eval(&uses, &[], &with_disabled),
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::Input { field: "set-me" }
            })
        );
    }

    #[test]
    fn test_exact_control() {
        let control = ControlExpr::field(
            Toggle::OptIn,
            "set-me",
            ControlFieldType::Exact(&["yes"]),
            false,
        );
        let uses = RepositoryUses::parse("foo/bar@doesnotmatter").unwrap();

        for (value, expected) in [
            (
                EnvValue::String("yes".into()),
                ControlEvaluation::Satisfied(indexset! {
                    ControlOrigin::Input { field: "set-me" }
                }),
            ),
            (
                EnvValue::String("no".into()),
                ControlEvaluation::NotSatisfied(indexset! {
                    ControlOrigin::Input { field: "set-me" }
                }),
            ),
            (
                EnvValue::String("${{ expression }}".into()),
                ControlEvaluation::Conditional(indexset! {
                    ControlOrigin::Input { field: "set-me" }
                }),
            ),
        ] {
            let with = IndexMap::from([("set-me".into(), value)]);
            assert_eq!(control.eval(&uses, &[], &with), expected);
        }
    }

    #[test]
    fn test_version_bound_provenance() {
        let control = ControlExpr::any([
            ControlExpr::field(
                Toggle::OptIn,
                "enable-cache",
                ControlFieldType::Exact(&["true"]),
                false,
            ),
            ControlExpr::all([
                ControlExpr::VersionBound(VersionBound::LessThan(Version::parse("v10").unwrap())),
                ControlExpr::field(
                    Toggle::OptIn,
                    "enable-cache",
                    ControlFieldType::Boolean,
                    true,
                ),
            ]),
        ]);

        let v6 = RepositoryUses::parse("foo/bar@v6.5.0").unwrap();
        assert_eq!(
            control.eval(&v6, &[], &IndexMap::new()),
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::UsesRef,
                ControlOrigin::Default {
                    field: "enable-cache"
                },
            })
        );

        let explicit = IndexMap::from([("enable-cache".into(), EnvValue::Boolean(true))]);
        assert_eq!(
            control.eval(&v6, &[], &explicit),
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::Input {
                    field: "enable-cache"
                },
                ControlOrigin::UsesRef,
            })
        );

        let v10 = RepositoryUses::parse("foo/bar@v10.0.0").unwrap();
        assert_eq!(
            control.eval(&v10, &[], &explicit),
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::Input {
                    field: "enable-cache"
                }
            })
        );
        assert!(matches!(
            control.eval(&v10, &[], &IndexMap::new()),
            ControlEvaluation::NotSatisfied(_)
        ));

        let automatic = IndexMap::from([("enable-cache".into(), EnvValue::String("auto".into()))]);
        assert!(matches!(
            control.eval(&v10, &[], &automatic),
            ControlEvaluation::NotSatisfied(_)
        ));
        assert_eq!(
            control.eval(&v6, &[], &automatic),
            ControlEvaluation::Satisfied(indexset! {
                ControlOrigin::UsesRef,
                ControlOrigin::Input {
                    field: "enable-cache"
                },
            })
        );

        let disabled = IndexMap::from([("enable-cache".into(), EnvValue::Boolean(false))]);
        assert!(matches!(
            control.eval(&v6, &[], &disabled),
            ControlEvaluation::NotSatisfied(_)
        ));

        let unknown =
            RepositoryUses::parse("foo/bar@d9e0f98d3fc6adb07d1e3d37f3043649ddad06a1").unwrap();
        assert_eq!(
            control.eval(&unknown, &[], &IndexMap::new()),
            ControlEvaluation::Conditional(indexset! { ControlOrigin::UsesRef })
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
            assert_eq!(coord.usage(*step), Some(Usage::Always));
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
            Some(Usage::Enabled(indexset! {
                ControlOrigin::Input { field: "set-me" }
            }))
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
            Some(Usage::Enabled(indexset! {
                ControlOrigin::Default { field: "set-me" }
            }))
        );

        // Coordinate `uses:` matches and is explicitly toggled on.
        let step = &steps[4];
        assert_eq!(
            coord.usage(step),
            Some(Usage::Enabled(indexset! {
                ControlOrigin::Input { field: "set-me" }
            }))
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
            Some(Usage::Enabled(indexset! {
                ControlOrigin::Input {
                    field: "disable-cache"
                }
            }))
        );

        // Coordinate `uses:` matches but `with:` is an expression.
        let step = &steps[8];
        assert_eq!(
            coord.usage(step),
            Some(Usage::Conditional(indexset! {
                ControlOrigin::WithExpression
            }))
        );
    }
}
