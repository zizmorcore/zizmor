use github_actions_models::common::{expr::ExplicitExpr, If};

use crate::{
    expr::{self, Expr},
    finding::{Confidence, Persona},
    models::JobExt,
};

use super::{audit_meta, Audit};

pub(crate) struct BotConditions;

audit_meta!(BotConditions, "bot-conditions", "spoofable bot actor check");

impl Audit for BotConditions {
    fn new(_state: super::AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(
        &self,
        job: &super::NormalJob<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        // TODO: Consider other triggers as well?
        // In practice we expect to mostly see this problem with `pull_request_target`
        // triggers inside of "automerge this Dependabot PR"-style workflows.
        if !job.parent().has_pull_request_target() {
            return Ok(vec![]);
        }

        if let Some(If::Expr(expr)) = &job.r#if {
            if let Some((confidence, persona)) = Self::bot_condition(expr) {
                todo!()
            }
        };

        todo!()
    }
}

impl BotConditions {
    fn walk_tree(expr: &Expr, dominating: bool) -> (bool, bool) {
        match expr {
            // We can't easily analyze the call's semantics, but we can
            // check to see if any of the call's arguments are
            // bot conditions. We treat a call as non-dominating always.
            Expr::Call { func: _, args } => args
                .iter()
                .map(|arg| Self::walk_tree(arg, false))
                .reduce(|(bc, _), (bc_next, _)| (bc || bc_next, false))
                .unwrap_or((false, dominating)),
            Expr::Index(expr) => Self::walk_tree(expr, dominating),
            Expr::Context { raw: _, components } => todo!(),
            Expr::BinOp { lhs, op, rhs } => match op {
                // && is non-dominating.
                expr::BinOp::And => todo!(),
                // || is dominating.
                expr::BinOp::Or => todo!(),
                // == is trivially dominating.
                expr::BinOp::Eq => todo!(),
                // Unclear.
                expr::BinOp::Neq => todo!(),
                expr::BinOp::Gt => todo!(),
                expr::BinOp::Ge => todo!(),
                expr::BinOp::Lt => todo!(),
                expr::BinOp::Le => todo!(),
            },
            Expr::UnOp { op, expr } => todo!(),
            _ => (false, dominating),
        }
    }

    fn bot_condition(expr: &str) -> Option<(Confidence, Persona)> {
        let Ok(expr) = (match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => Expr::parse(raw_expr.as_bare()),
            None => Expr::parse(expr),
        }) else {
            tracing::warn!("couldn't parse expression: {expr}");
            return None;
        };

        // We're looking for `github.actor == *[bot]` anywhere in the expression tree.
        // The bot condition is said to "dominate" if controls the entire
        // expression truth value. For example, `github.actor == 'dependabot[bot]' || foo`
        // has the bot condition as dominating, since regardless of `foo` the check
        // always passes if the actor is dependabot[bot].
        let (has_bot_condition, condition_dominates) = Self::walk_tree(&expr, true);

        None
    }
}
