//! Enriching/context-bearing wrappers over GitHub Actions models
//! from [`github_actions_models`].

use github_actions_expressions::{Evaluation, Expr, context};
use github_actions_models::common;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;

use crate::finding::location::{Locatable, SymbolicLocation};
use crate::models::inputs::HasInputs;
use crate::models::workflow::matrix::Matrix;
use crate::registry::input::CollectionError;
use crate::utils::ExtractedExpr;

use std::fmt::Write as _;

/// Returns whether the given `if:` condition is statically known to be false,
/// meaning the step (or job) it guards cannot execute.
///
/// This recognizes:
///
/// 1. The literal `if: false` (which deserializes as [`common::If::Bool(false)`]).
/// 2. Bare or fenced expressions that const-evaluate to a falsy boolean,
///    e.g. `if: ${{ false }}`, `if: false && something`.
///
/// More elaborate "never runs" conditions (e.g. `if: github.actor == 'no-one'`)
/// are intentionally out of scope; only conditions that we can prove falsy
/// without any runtime context are recognized.
pub(crate) fn if_is_statically_false(cond: &common::If) -> bool {
    match cond {
        common::If::Bool(b) => !*b,
        common::If::Expr(raw) => {
            let bare = ExtractedExpr::new(raw).as_bare();
            let Ok(expr) = Expr::parse(bare) else {
                return false;
            };
            matches!(expr.consteval(), Some(Evaluation::Boolean(false)))
        }
    }
}

pub(crate) mod action;
pub(crate) mod coordinate;
pub(crate) mod dependabot;
pub(crate) mod inputs;
pub(crate) mod pre_commit;
pub(crate) mod uses;
pub(crate) mod version;
pub(crate) mod workflow;

fn parse_validation_errors(errors: Vec<jsonschema::ErrorEntry<'_>>) -> anyhow::Error {
    let mut message = String::new();

    for error in errors {
        let description = error.error.to_string();
        // HACK: error descriptions are sometimes a long rats' nest
        // of JSON objects. We should render this in a palatable way
        // but doing so is nontrivial, so we just skip them for now.
        // NOTE: Experimentally, this seems to mostly happen when
        // the error for an unmatched "oneOf", so these errors are
        // typically less useful anyways.
        if !description.starts_with("{") {
            let location = error.instance_location.as_str();
            if location.is_empty() {
                writeln!(message, "{description}").expect("I/O on a String failed");
            } else {
                // Convert paths like `/foo/bar/baz` to `foo.bar.baz`,
                // removing the leading separator.
                let dotted_location = &location[1..].replace("/", ".");

                writeln!(message, "{dotted_location}: {description}")
                    .expect("I/O on a String failed");
            }
        }
    }

    anyhow::anyhow!(message)
}

/// A trait for models that are "validatable," i.e. satisfy three properties:
///
/// 1. They can deserialize into a "target" type, such as a GitHub Actions workflow model;
/// 2. They can deserialize into a "skeleton" type, such as a `Mapping` or `Sequence`;
/// 3. They can be validated against a JSON schema.
///
/// This trait helps zizmor distinguish between syntax errors (e.g. invalid YAML)
/// and semantic errors (valid YAML, but not the right shape for the input) as well
/// as provide more useful errors for the latter case.
pub(crate) trait Validatable<'de> {
    type Target: serde::Deserialize<'de>;
    type Skeleton: serde::Deserialize<'de> + serde::Serialize;

    fn validator() -> &'static jsonschema::Validator;

    fn validate(contents: &'de str) -> Result<Self::Target, CollectionError> {
        match yaml_serde::from_str::<Self::Target>(contents) {
            Ok(value) => Ok(value),
            Err(e) => {
                // Something a little wonky happens here: we want
                // to distinguish between syntax and semantic errors,
                // but serde-yaml doesn't give us an API to do that.
                // To approximate it, we re-parse the input as a
                // `Self::Skeleton`, then convert that `Self::Skeleton`
                // into a `serde_json::Value` and use it as an oracle -- a successful
                // re-parse indicates that the input is valid YAML and
                // that our error is semantic, while a failed re-parse
                // indicates a syntax error.
                //
                // We need to round-trip through a `Self::Skeleton` to ensure that
                // all of YAML's validity rules are preserved -- directly deserializing
                // into a `serde_json::Value` would miss some YAML-specific checks,
                // like duplicate keys within mappings. See #1395 for an example of this.
                //
                // We do this in a nested fashion to avoid re-parsing the input twice if we
                // can help it, and because the more obvious trick (`yaml_serde::from_value`)
                // doesn't work due to a lack of referential transparency.
                //
                // See: https://github.com/dtolnay/serde-yaml/issues/170
                // See: https://github.com/dtolnay/serde-yaml/issues/395

                match yaml_serde::from_str::<Self::Skeleton>(contents) {
                    // We know we have valid YAML, so one of two things happened here:
                    // 1. The input is semantically valid, but we have a bug in
                    //    `github-actions-models`.
                    // 2. The input is semantically invalid, and the user
                    //    needs to fix it.
                    // We the JSON schema `validator` to separate these.
                    Ok(raw_value) => {
                        let evaluation = Self::validator().evaluate(
                            &serde_json::to_value(&raw_value)
                                .map_err(|e| CollectionError::Syntax(e.into()))?,
                        );

                        if evaluation.flag().valid {
                            Err(e.into())
                        } else {
                            let errors = evaluation.iter_errors().collect::<Vec<_>>();
                            Err(CollectionError::Schema(parse_validation_errors(errors)))
                        }
                    }
                    // Syntax error.
                    Err(e) => Err(CollectionError::Syntax(e.into())),
                }
            }
        }
    }
}

pub(crate) trait AsDocument<'a, 'doc> {
    fn as_document(&'a self) -> &'doc yamlpath::Document;
}

/// Common fields between workflow and action step bodies.
pub(crate) enum StepBodyCommon<'s> {
    Uses {
        uses: &'s common::Uses,
        with: &'s LoE<Env>,
    },
    Run {
        run: &'s str,
        _working_directory: Option<&'s str>,
        _shell: Option<&'s LoE<String>>,
    },
}

/// Common interfaces between workflow and action steps.
pub(crate) trait StepCommon<'doc>: Locatable<'doc> + HasInputs {
    /// Returns an `Ord` implementation suitable for ordering two steps
    /// within the same job. Ordering across jobs is not defined.
    ///
    /// At the moment, a step's ordering is defined lexically, i.e.
    /// a step that appears lexically before another step is considered
    /// first, even if step-level parallelism may change their execution order.
    ///
    /// This is an API rather than a derivation for each `StepCommon`
    /// so that each implementation doesn't need to derive the entire
    /// stack of traits implied by ordering (`PartialEq`, `PartialOrd`, etc).
    fn ord(&self) -> impl Ord;

    /// Returns whether the given `env.name` environment access is "static,"
    /// i.e. is not influenced by another expression.
    fn env_is_static(&self, ctx: &context::Context) -> bool;

    /// Returns a [`common::Uses`] for this step, if it has one.
    fn uses(&self) -> Option<&'doc common::Uses>;

    /// Returns this step's job's computed matrix, if present.
    ///
    /// Composite action steps have no matrix.
    fn matrix(&self) -> Option<Matrix<'doc>>;

    /// Returns a [`StepBodyCommon`] for this step, if there is one.
    ///
    /// Not all steps have a common body across actions and workflows.
    /// For example, at the moment, bodies that control step parallelism
    /// are unique to workflows.
    fn body(&self) -> Option<StepBodyCommon<'doc>>;

    /// Returns the document which contains this step.
    fn document(&self) -> &'doc yamlpath::Document;

    /// Returns the effective shell for this step, if it can be determined.
    /// This includes the step's explicit shell, job defaults, workflow defaults,
    /// and runner defaults.
    ///
    /// Returns `None` if the shell cannot be statically determined, including
    /// if the shell is specified via an expression.
    fn shell(&self) -> Option<(&str, SymbolicLocation<'doc>)>;
}

impl<'a, 'doc, T: StepCommon<'doc>> AsDocument<'a, 'doc> for T {
    fn as_document(&'a self) -> &'doc yamlpath::Document {
        self.document()
    }
}

#[cfg(test)]
mod tests {
    use super::if_is_statically_false;
    use github_actions_models::common;

    #[test]
    fn test_if_is_statically_false() {
        // Literal false / true.
        assert!(if_is_statically_false(&common::If::Bool(false)));
        assert!(!if_is_statically_false(&common::If::Bool(true)));

        // Fenced and bare false expressions.
        for raw in &[
            "${{ false }}",
            "${{false}}",
            "false",
            "${{ true && false }}",
            "${{ !true }}",
            "${{ false || false }}",
        ] {
            assert!(
                if_is_statically_false(&common::If::Expr((*raw).into())),
                "expected statically false: {raw}"
            );
        }

        // Expressions that aren't statically false.
        for raw in &[
            "${{ true }}",
            "true",
            "${{ github.actor == 'foo' }}",
            "${{ inputs.something }}",
            // Non-Boolean falsy values are intentionally not matched.
            "${{ '' }}",
            "${{ null }}",
            // Unparseable expressions should not be treated as false.
            "${{ this is not valid",
        ] {
            assert!(
                !if_is_statically_false(&common::If::Expr((*raw).into())),
                "expected not statically false: {raw}"
            );
        }
    }
}
