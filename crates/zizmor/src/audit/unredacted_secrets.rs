use std::ops::Deref;

use github_actions_expressions::{Expr, SpannedExpr, context::Context};

use crate::{
    Confidence, Severity,
    finding::location::{Feature, Location},
    utils::parse_fenced_expressions_from_input,
};

use super::{Audit, AuditLoadError, AuditState, audit_meta};

pub(crate) struct UnredactedSecrets;

audit_meta!(
    UnredactedSecrets,
    "unredacted-secrets",
    "leaked secret values"
);

impl Audit for UnredactedSecrets {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(
        &self,
        input: &'doc super::AuditInput,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, span) in parse_fenced_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for _ in Self::secret_leakages(&parsed) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("bypasses secret redaction")
                                .primary(),
                            Feature::from_span(&span, input),
                        ))
                        .build(input)?,
                );
            }
        }

        findings.len();

        Ok(findings)
    }
}

impl UnredactedSecrets {
    fn secret_leakages(expr: &SpannedExpr) -> Vec<()> {
        let mut results = vec![];

        // We're looking for patterns like `fromJSON(secrets.foo)`,
        // since these mutate the secret value (e.g. by JSON decoding it)
        // and therefore bypass GitHub's redaction mechanism.

        match expr.deref() {
            Expr::Call { func, args } => {
                if func == "fromJSON"
                    && args.iter().any(
                        |arg| matches!(arg.deref(), Expr::Context(ctx) if ctx.child_of("secrets")),
                    )
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secret_leakages));
                }
            }
            Expr::Index(expr) => results.extend(Self::secret_leakages(expr)),
            Expr::Context(Context { parts, .. }) => {
                results.extend(parts.iter().flat_map(Self::secret_leakages))
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secret_leakages(lhs));
                results.extend(Self::secret_leakages(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secret_leakages(expr)),
            _ => (),
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    use crate::audit::unredacted_secrets;

    #[test]
    fn test_secret_leakages() {
        for (expr, count) in &[
            ("secrets", 0),
            ("secrets.foo", 0),
            ("fromJSON(notsecrets)", 0),
            ("fromJSON(notsecrets.secrets)", 0),
            ("fromJSON(secrets)", 1),
            ("fromjson(SECRETS)", 1),
            ("fromJSON(secrets.foo)", 1),
            ("fromJSON(secrets.foo).bar", 1),
            ("fromJSON(secrets.foo).bar.baz", 1),
            ("fromJSON(secrets.foo) && fromJSON(secrets.bar)", 2),
        ] {
            let expr = Expr::parse(expr).unwrap();
            assert_eq!(
                unredacted_secrets::UnredactedSecrets::secret_leakages(&expr).len(),
                *count
            );
        }
    }
}
