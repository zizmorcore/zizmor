use github_actions_expressions::{
    Expr, SpannedExpr,
    op::{BinExpr, BinOp},
};
use subfeature::Subfeature;

use crate::{
    audit::AuditError,
    finding::{
        Confidence, Severity,
        location::{Feature, Location},
    },
    utils::parse_fenced_expressions_from_routable,
};

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct UnsoundTernary;

audit_meta!(
    UnsoundTernary,
    "unsound-ternary",
    "unsound pseudo-ternary expression"
);

#[async_trait::async_trait]
impl Audit for UnsoundTernary {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_raw<'doc>(
        &self,
        input: &'doc AuditInput,
        _config: &crate::config::Config,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if !input.supports_gha_template_syntax() {
            return Ok(findings);
        }

        for (expr, expr_span) in parse_fenced_expressions_from_routable(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for true_value in Self::unsound_true_values(&parsed) {
                let after = expr_span.start + true_value.origin.span.start;
                let subfeature = Subfeature::new(after, true_value.origin.raw);

                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("pseudo-ternary has falsy true value")
                                .primary(),
                            Feature::from_subfeature(&subfeature, input),
                        ))
                        .build(input)?,
                );
            }
        }

        Ok(findings)
    }
}

impl UnsoundTernary {
    fn unsound_true_values<'src>(expr: &'src SpannedExpr<'src>) -> Vec<&'src SpannedExpr<'src>> {
        if expr.constant_reducible() {
            return vec![];
        }

        let mut values = vec![];

        match &expr.inner {
            Expr::Call(call) => {
                for arg in &call.args {
                    values.extend(Self::unsound_true_values(arg));
                }
            }
            Expr::Context(context) => {
                for part in &context.parts {
                    values.extend(Self::unsound_true_values(part));
                }
            }
            Expr::BinExpr(BinExpr { op: BinOp::Or, .. }) => {
                let operands = Self::or_operands(expr);
                for operand in &operands[..operands.len() - 1] {
                    if let Expr::BinExpr(BinExpr {
                        op: BinOp::And,
                        rhs: true_value,
                        ..
                    }) = &operand.inner
                        && Self::is_falsy(true_value)
                    {
                        values.push(true_value);
                    }
                }

                for operand in operands {
                    values.extend(Self::unsound_true_values(operand));
                }
            }
            Expr::BinExpr(BinExpr { lhs, op: _, rhs }) => {
                values.extend(Self::unsound_true_values(lhs));
                values.extend(Self::unsound_true_values(rhs));
            }
            Expr::UnExpr { op: _, expr } => {
                values.extend(Self::unsound_true_values(expr));
            }
            Expr::Index(expr) => values.extend(Self::unsound_true_values(expr)),
            _ => {}
        }

        values
    }

    /// Recursively collects operands of `||` expressions.
    fn or_operands<'src>(expr: &'src SpannedExpr<'src>) -> Vec<&'src SpannedExpr<'src>> {
        let mut operands = vec![];

        if !expr.constant_reducible()
            && let Expr::BinExpr(BinExpr {
                lhs,
                op: BinOp::Or,
                rhs,
            }) = &expr.inner
        {
            operands.extend(Self::or_operands(lhs));
            operands.extend(Self::or_operands(rhs));
        } else {
            operands.push(expr);
        }

        operands
    }

    fn is_falsy(expr: &SpannedExpr) -> bool {
        expr.consteval()
            .is_some_and(|evaluation| !evaluation.as_boolean())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsound_true_values() {
        #[track_caller]
        fn case(expr: &str, expected: &[&str]) {
            let parsed = Expr::parse(expr).unwrap();
            let values = UnsoundTernary::unsound_true_values(&parsed)
                .into_iter()
                .map(|expr| expr.origin.raw)
                .collect::<Vec<_>>();

            assert_eq!(values, expected);
        }

        case("foo && '' || 'bar'", &["''"]);
        case("foo && ('') || 'bar'", &["('')"]);
        case("foo && 0 || 'bar'", &["0"]);
        case("foo && false || 'bar'", &["false"]);
        case("foo && null || 'bar'", &["null"]);
        case("foo && fromJSON('false') || 'bar'", &["fromJSON('false')"]);
        case("foo && format('{0}', '') || 'bar'", &["format('{0}', '')"]);
        case("foo || bar && '' || 'baz'", &["''"]);
        case("foo || (bar && '' || 'baz')", &["''"]);
        case("(foo && '' || 'bar') || baz", &["''"]);
        case("foo && '' || bar && 0 || 'baz'", &["''", "0"]);
        case("foo || (true && '' || 'bar')", &[]);
        case("!foo && 'bar' || ''", &[]);
        case("foo && 'bar' || ''", &[]);
        case("foo || bar && ''", &[]);
        case("true && '' || 'bar'", &[]);
    }
}
