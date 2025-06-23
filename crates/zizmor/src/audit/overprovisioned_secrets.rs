use std::ops::Deref;

use github_actions_expressions::{Expr, SpannedExpr};

use crate::{
    finding::{
        Confidence, Severity,
        location::{Feature, Location},
    },
    utils::parse_expressions_from_input,
};

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct OverprovisionedSecrets;

audit_meta!(
    OverprovisionedSecrets,
    "overprovisioned-secrets",
    "excessively provisioned secrets"
);

impl Audit for OverprovisionedSecrets {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(
        &self,
        input: &'doc AuditInput,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for _ in Self::secrets_expansions(&parsed) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("injects the entire secrets context into the runner")
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

impl OverprovisionedSecrets {
    fn secrets_expansions(expr: &SpannedExpr) -> Vec<()> {
        let mut results = vec![];

        match &expr.inner {
            Expr::Call { func, args } => {
                // TODO: Consider any function call that accepts bare `secrets`
                // to be a finding? Are there any other functions that users
                // would plausibly call with the entire `secrets` object?
                if func == "toJSON"
                    && args.iter().any(
                        |arg| matches!(arg.deref(), Expr::Context(ctx) if ctx.matches("secrets")),
                    )
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secrets_expansions));
                }
            }
            Expr::Index(expr) => results.extend(Self::secrets_expansions(expr)),
            Expr::Context(ctx) => {
                match ctx.parts.as_slice() {
                    // Look for `secrets[...]` accesses where the index component
                    // is not a literal.
                    [
                        SpannedExpr {
                            inner: Expr::Identifier(ident),
                            ..
                        },
                        SpannedExpr {
                            inner: Expr::Index(idx),
                            ..
                        },
                    ] if ident == "secrets" && !idx.is_literal() => results.push(()),
                    _ => results.extend(ctx.parts.iter().flat_map(Self::secrets_expansions)),
                }
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secrets_expansions(lhs));
                results.extend(Self::secrets_expansions(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secrets_expansions(expr)),
            _ => (),
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    #[test]
    fn test_secrets_expansions() {
        for (expr, count) in &[
            ("secrets", 0),
            ("toJSON(secrets.foo)", 0),
            ("toJSON(secrets)", 1),
            ("tojson(secrets)", 1),
            ("toJSON(SECRETS)", 1),
            ("tOjSoN(sECrEtS)", 1),
            ("false || toJSON(secrets)", 1),
            ("toJSON(secrets) || toJSON(secrets)", 2),
            ("format('{0}', toJSON(secrets))", 1),
            ("secrets[format('GH_PAT_%s', matrix.env)]", 1),
            ("SECRETS[format('GH_PAT_%s', matrix.env)]", 1),
            ("SECRETS[something.else]", 1),
            ("SECRETS['literal']", 0),
        ] {
            let expr = Expr::parse(expr).unwrap();
            assert_eq!(
                super::OverprovisionedSecrets::secrets_expansions(&expr).len(),
                *count
            );
        }
    }
}
