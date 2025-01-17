use github_actions_models::common::{expr::ExplicitExpr, If};

use crate::{
    expr::Expr,
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
            if let Some((confidence, persona)) = self.bot_condition(expr) {
                todo!()
            }
        };

        todo!()
    }
}

impl BotConditions {
    fn bot_condition(&self, expr: &str) -> Option<(Confidence, Persona)> {
        let Ok(expr) = (match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => Expr::parse(raw_expr.as_bare()),
            None => Expr::parse(expr),
        }) else {
            tracing::warn!("couldn't parse expression: {expr}");
            return None;
        };

        // We're looking for `github.actor == *[bot]` anywhere in the
        // expression tree.

        None
    }
}
