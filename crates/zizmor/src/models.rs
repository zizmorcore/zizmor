//! Enriching/context-bearing wrappers over GitHub Actions models
//! from [`github_actions_models`].

use github_actions_expressions::{Evaluation, Expr, context};
use github_actions_models::common;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;

use crate::finding::location::{Locatable, SymbolicLocation};
use crate::models::inputs::HasInputs;
use crate::models::workflow::matrix::Matrix;
use crate::utils::ExtractedExpr;

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
