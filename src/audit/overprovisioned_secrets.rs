use std::ops::Range;

use crate::{expr::Expr, utils::extract_expressions};

use super::{audit_meta, Audit};

pub(crate) struct OverprovisionedSecrets;

audit_meta!(
    OverprovisionedSecrets,
    "overprovisioned-secrets",
    "detects secrets that are overprovisioned"
);

impl Audit for OverprovisionedSecrets {
    fn new(_state: super::AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'w>(&self, raw: &'w str) -> anyhow::Result<Vec<super::Finding<'w>>> {
        for (expr, span) in extract_expressions(raw) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            todo!()
        }

        Ok(vec![])
    }
}

impl OverprovisionedSecrets {
    fn secrets_expansions(span: Range<usize>, expr: &Expr) -> Vec<Range<usize>> {
        todo!()
    }
}
