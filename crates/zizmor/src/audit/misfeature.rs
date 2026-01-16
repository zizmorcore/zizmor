use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{
        StepBodyCommon, StepCommon, action::CompositeStep, uses::RepositoryUsesExt, workflow::Step,
    },
    state::AuditState,
    utils,
};

audit_meta!(
    Misfeature,
    "misfeature",
    "usage of GitHub Actions misfeatures"
);

pub(crate) struct Misfeature;

impl Misfeature {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        match step.body() {
            StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } => {
                if uses.matches("actions/setup-python") && with.contains_key("pip-install") {
                    // The `pip-install` input was added to setup-python in v6.1.0.
                    // Users should never use it, since it attempts to install directly
                    // into a global (user or system) Python environment, which will behave
                    // inconsistently across different runners, Python versions, etc.
                    findings.push(
                        Self::finding()
                            .add_location(
                                step.location()
                                    .with_keys(["uses".into()])
                                    .subfeature(Subfeature::new(0, uses.raw()))
                                    .annotated("this action"),
                            )
                            .add_location(
                                step.location()
                                    .primary()
                                    .with_keys(["with".into(), "pip-install".into()])
                                    .annotated("installs packages in a brittle manner"),
                            )
                            .tip("always use a virtual environment to manage Python packages")
                            .severity(Severity::Low)
                            .confidence(Confidence::High)
                            .build(step)?,
                    )
                }
            }
            StepBodyCommon::Run { .. } => {
                match step
                    .shell()
                    .map(|(shell, loc)| (utils::normalize_shell(shell), loc))
                {
                    // Well-known shells other than `cmd` are generally fine.
                    Some(("bash" | "pwsh" | "python" | "sh" | "powershell", _)) => {}
                    // `shell: cmd` is basically impossible to analyze: it has no formal
                    // grammar and has several line continuation mechanisms that stymie
                    // naive matching. It also hasn't been the default shell on Windows
                    // runners since 2019.
                    Some(("cmd" | "cmd.exe", shell_loc)) => {
                        findings.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Low)
                                .add_location(
                                    step.location_with_grip()
                                        .annotated("Windows CMD shell limits analysis"),
                                )
                                .add_location(shell_loc.primary())
                                .tip("use 'shell: pwsh' or 'shell: bash' for improved analysis")
                                .build(step)?,
                        );
                    }
                    // Flag any other non-well-known shell with an auditor finding.
                    // NOTE: This was originally pedantic, but it can be very noisy for
                    // users who intentioanlly use custom shells.
                    Some((_, shell_loc)) => {
                        findings.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Low)
                                .persona(Persona::Auditor)
                                .add_location(
                                    step.location().with_keys(["run".into()]).key_only().annotated("uses a non-well-known shell")
                                )
                                .add_location(shell_loc.primary())
                                .tip("use a shell that's well-known to GitHub Actions, like 'bash' or 'pwsh'")
                                .build(step)?,
                        );
                    }
                    _ => {}
                }
            }
            // No misfeature checks against non-actions `uses:` clauses, yet.
            StepBodyCommon::Uses { .. } => {}
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for Misfeature {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}
