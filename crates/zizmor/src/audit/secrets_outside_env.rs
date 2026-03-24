use github_actions_expressions::Expr;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Feature, Locatable, Location, Routable},
    },
    models::{
        AsDocument,
        workflow::{JobCommon as _, NormalJob, ReusableWorkflowCallJob},
    },
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

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // Unlike normal jobs, jobs that call reusable workflows can't
        // activate an environment directly. This essentially means that any
        // secrets referenced by the caller are guaranteed to be outside of a
        // dedicated environment.
        let mut findings = vec![];
        for (secret, subfeature) in Self::secrets_in_routable(job) {
            if config
                .secrets_outside_env_policy
                .allow
                .contains(&secret.to_ascii_lowercase())
            {
                continue;
            }

            findings.push(
                Self::finding()
                    .persona(Persona::Auditor)
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

        Ok(findings)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        if job.parent().has_workflow_call() {
            // Reusable workflows and environments don't interact well, and are more or less
            // completely undocumented in terms of behavior. We don't flag any findings
            // for them, since users will discover that a reusable workflow that activates
            // an environment can't actually use that environment's secrets unless the
            // caller workflow passes `secrets: inherit`, which violates our `secrets-inherit`
            // audit.
            return Ok(vec![]);
        }

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
        for (secret, subfeature) in Self::secrets_in_routable(job) {
            if config
                .secrets_outside_env_policy
                .allow
                .contains(&secret.to_ascii_lowercase())
            {
                continue;
            }

            findings.push(
                Self::finding()
                    .persona(Persona::Auditor)
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

        Ok(findings)
    }
}

impl SecretsOutsideEnvironment {
    fn secrets_in_routable<'a, 'doc>(
        routable: &'a (impl Locatable<'doc> + AsDocument<'a, 'doc> + Routable<'a, 'doc>),
    ) -> Vec<(String, Subfeature<'doc>)> {
        parse_fenced_expressions_from_routable(routable)
            .iter()
            .flat_map(|(expr, span)| {
                let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                    warn_once!("couldn't parse expression: {expr}", expr = expr.as_bare());
                    return vec![];
                };

                parsed
                    .contexts()
                    .into_iter()
                    .filter_map(|(context, origin)| {
                        if context.child_of("secrets") {
                            // TODO(ww): Minor, but it would be nice to avoid this clone.
                            let name = context.single_tail()?.to_string();
                            let after = span.start + origin.span.start;
                            Some((name, Subfeature::new(after, origin.raw)))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
