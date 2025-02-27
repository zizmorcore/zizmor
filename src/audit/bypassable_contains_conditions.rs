use github_actions_models::common::{expr::ExplicitExpr, If};

use super::{audit_meta, Audit};
use crate::{
    expr::{self, Context, Expr},
    finding::{Confidence, Severity},
    models::JobExt,
};

pub(crate) struct BypassableContainsConditions;

audit_meta!(
    BypassableContainsConditions,
    "bypassable-contains-conditions",
    "bypassable contains conditions checks"
);

impl Audit for BypassableContainsConditions {
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
        let conditions = job
            .r#if
            .iter()
            .map(|cond| (cond, job.location()))
            .chain(
                job.steps()
                    .filter_map(|step| step.r#if.as_ref().map(|cond| (cond, step.location()))),
            )
            .filter_map(|(cond, loc)| {
                if let If::Expr(expr) = cond {
                    Some((expr.as_str(), loc))
                } else {
                    None
                }
            });

        conditions
            .filter_map(|(expr, loc)| {
                Self::insecure_contains(expr).map(|confidence| {
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(confidence)
                        .add_location(
                            loc.with_keys(&["if".into()])
                                .primary()
                                .annotated("contains condition can be bypassed"),
                        )
                        .build(job.parent())
                })
            })
            .collect()
    }
}

impl BypassableContainsConditions {
    fn walk_tree_for_insecure_contains(expr: &Expr) -> bool {
        match expr {
            Expr::Call {
                func: "contains",
                args: exprs,
            } => match exprs.as_slice() {
                [Expr::String(_), Expr::Context(_)] => true,
                args => args
                    .iter()
                    .any(|arg| Self::walk_tree_for_insecure_contains(arg)),
            },
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context {
                raw: _,
                components: exprs,
            }) => exprs
                .iter()
                .map(|arg| Self::walk_tree_for_insecure_contains(arg))
                .reduce(|bc, bc_next| (bc || bc_next))
                .unwrap_or(false),
            Expr::Index(expr) => Self::walk_tree_for_insecure_contains(expr),
            Expr::BinOp { lhs, op, rhs } => match op {
                expr::BinOp::Or => {
                    let bc_lhs = Self::walk_tree_for_insecure_contains(lhs);
                    let bc_rhs = Self::walk_tree_for_insecure_contains(rhs);

                    bc_lhs || bc_rhs
                }
                _ => {
                    let bc_lhs = Self::walk_tree_for_insecure_contains(lhs);
                    let bc_rhs = Self::walk_tree_for_insecure_contains(rhs);

                    bc_lhs || bc_rhs
                }
            },
            Expr::UnOp { op, expr } => match op {
                expr::UnOp::Not => Self::walk_tree_for_insecure_contains(expr),
            },
            _ => false,
        }
    }

    fn insecure_contains(expr: &str) -> Option<Confidence> {
        let bare = match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => raw_expr.as_bare().to_string(),
            None => expr.to_string(),
        };

        let Ok(expr) = Expr::parse(&bare) else {
            tracing::warn!("couldn't parse expression: {expr}");
            return None;
        };

        // We're looking for `contains("something", context)` anywhere in the expression tree.
        Self::walk_tree_for_insecure_contains(&expr).then_some(Confidence::High)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Confidence;

    #[test]
    fn test_bot_condition() {
        for (cond, confidence) in &[
            // Vulnerable conditions
            ("contains('refs/heads/main refs/heads/develop', github.ref)", Some(Confidence::High)),
            ("false || contains('main,develop', github.head_ref)", Some(Confidence::High)),
            ("!contains('main|develop', github.base_ref)", Some(Confidence::High)),
            ("contains(fromJSON('[true]'), contains('refs/heads/main refs/heads/develop', env.GITHUB_REF))", Some(Confidence::High)),
            // These are okay.
            ("github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'", None),
            ("contains(fromJSON('[\"refs/heads/main\", \"refs/heads/develop\"]'), github.ref)", None),
        ] {
            assert_eq!(BypassableContainsConditions::insecure_contains(cond), *confidence);
        }
    }
}
