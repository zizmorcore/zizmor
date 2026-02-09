use github_actions_expressions::Expr;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Feature, Locatable, Location},
    },
    models::workflow::NormalJob,
    state::AuditState,
    utils::{once::warn_once, parse_fenced_expressions_from_routable},
};

pub(crate) struct SecretsOutsideEnvironment;

audit_meta!(
    SecretsOutsideEnvironment,
    "secrets-outside-env",
    "secrets referenced without a dedicated environment"
);

#[async_trait::async_trait]
impl Audit for SecretsOutsideEnvironment {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        if job.environment.is_some() {
            // If the job has an environment, then we assume that any secrets
            // used in the job are scoped to that environment.
            // This is not strictly true, since secrets that don't exist in
            // the environment will fall back to repository/org secrets, but
            // we don't currently has a low-privilege way of checking for that.
            // Consequently, we have a higher false-negative rate than is ideal here.
            return Ok(vec![]);
        }

        // Get every expression in the job's body, and look for accesses of the `secrets` context.
        // NOTE: In principle this is incomplete, since there are some places (like `if:`) where
        // GitHub Actions doesn't require fencing on expressions. In practice however GitHub Actions
        // doesn't allow users to reference secrets in `if:` clauses.
        let mut findings = vec![];
        for (expr, span) in parse_fenced_expressions_from_routable(job) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                warn_once!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for (context, origin) in parsed.contexts() {
                if !context.child_of("secrets") {
                    continue;
                }

                if context.matches("secrets.GITHUB_TOKEN") {
                    // GITHUB_TOKEN is always latently available, so we don't
                    // flag its usage outside of a dedicated environment.
                    continue;
                }

                let after = span.start + origin.span.start;
                let subfeature = Subfeature::new(after, origin.raw);

                findings.push(
                    Self::finding()
                        .persona(Persona::Regular)
                        .severity(Severity::Medium)
                        .confidence(Confidence::High)
                        .add_location(job.location().key_only())
                        .add_raw_location(Location::new(
                            job.location()
                                .primary()
                                .annotated("secret is accessed outside of a dedicated environment"),
                            Feature::from_subfeature(&subfeature, job),
                        ))
                        .build(job)?,
                );
            }
        }

        Ok(findings)
    }
}
