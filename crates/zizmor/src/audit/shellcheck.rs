use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::anyhow;
use serde::Deserialize;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{StepBodyCommon, StepCommon, action::CompositeStep, workflow::Step},
    state::AuditState,
    utils,
};

pub(crate) struct ShellcheckAudit {
    executable: String,
}

audit_meta!(
    ShellcheckAudit,
    "shellcheck",
    "shellcheck finding in shell run block"
);

#[derive(Debug, Deserialize)]
struct ShellcheckOutput {
    comments: Vec<ShellcheckDiagnostic>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShellcheckDiagnostic {
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    level: String,
    code: usize,
    message: String,
}

impl ShellcheckAudit {

    fn sanitize_shellcheck_script(script: &str) -> String {
        // Removes template expressions like ${{ ... }} from the script.
        // Replaces them with whitespace of the same length,
        // so that the offsets of the remaining code are unchanged for accurate diagnostics.
        let mut sanitized = String::with_capacity(script.len());
        let mut cursor = 0;

        for (_, span) in utils::extract_fenced_expressions(script) {
            if span.start > cursor {
                sanitized.push_str(&script[cursor..span.start]);
            }
            
            sanitized.push_str(&"_".repeat(span.end - span.start));
            cursor = span.end;
        }

        if cursor < script.len() {
            sanitized.push_str(&script[cursor..]);
        }

        sanitized
    }

    fn supported_shell(shell: &str) -> bool {
        matches!(shell, "sh" | "bash" | "dash" | "ksh" | "zsh")
    }

    fn known_non_posix_shell(shell: &str) -> bool {
        matches!(shell, "pwsh" | "powershell" | "cmd")
    }

    fn shellcheck_shell(shell: &str) -> &str {
        match shell {
            // shellcheck doesn't support zsh mode directly; bash is the closest mode.
            "zsh" => "bash",
            other => other,
        }
    }

    fn severity_for_level(level: &str) -> Severity {
        match level {
            "error" => Severity::Medium,
            "warning" => Severity::Low,
            "info" | "style" => Severity::Informational,
            _ => Severity::Low,
        }
    }

    /// Convert shellcheck's 1-based line/column into a byte offset within
    /// the script content.
    fn diagnostic_span(script: &str, diagnostic: &ShellcheckDiagnostic) -> usize {
        let mut offset = 0usize;
        for (i, line) in script.lines().enumerate() {
            if i + 1 == diagnostic.line {
                return offset + diagnostic.column.saturating_sub(1);
            }
            offset += line.len() + 1;
        }
        0
    }

    fn resolved_shell<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Option<(
        String,
        Option<crate::finding::location::SymbolicLocation<'doc>>,
    )> {
        let detected = step.shell();

        let Some((shell, shell_location)) = detected else {
            if !config.shellcheck_config.check_unknown_shells {
                tracing::debug!(
                    "skipping shellcheck on run block: shell is unknown (not statically resolvable) and check-unknown-shells is disabled"
                );
                return None;
            }

            return Some(("bash".to_string(), None));
        };

        let normalized = utils::normalize_shell(shell);
        if Self::supported_shell(normalized) {
            return Some((
                Self::shellcheck_shell(normalized).to_string(),
                Some(shell_location),
            ));
        }

        if Self::known_non_posix_shell(normalized) {
            tracing::debug!(
                "skipping shellcheck on run block: shell '{normalized}' is a known non-POSIX shell not supported by shellcheck"
            );
            return None;
        }

        if !config.shellcheck_config.check_unknown_shells {
            tracing::debug!(
                "skipping shellcheck on run block: shell '{normalized}' is unknown and check-unknown-shells is disabled"
            );
            return None;
        }

        Some((
            "bash".to_string(),
            Some(shell_location.annotated("unknown shell treated as bash")),
        ))
    }

    fn run_shellcheck(
        &self,
        shell: &str,
        script: &str,
    ) -> Result<Vec<ShellcheckDiagnostic>, AuditError> {
        let mut child = Command::new(&self.executable)
            .args(["--format", "json1", "--shell", shell, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Self::err)?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes()).map_err(Self::err)?;
        }

        let output = child.wait_with_output().map_err(Self::err)?;
        let exit_code = output.status.code().unwrap_or(-1);

        if !output.status.success() && exit_code != 1 {
            tracing::debug!(
                "shellcheck returned non-diagnostic exit code {exit_code}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(vec![]);
        }

        if output.stdout.is_empty() {
            return Ok(vec![]);
        }

        let parsed: ShellcheckOutput = match serde_json::from_slice(&output.stdout) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::debug!(
                    "failed to parse shellcheck output: {error}; stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Ok(vec![]);
            }
        };

        Ok(parsed.comments)
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let StepBodyCommon::Run { run, .. } = step.body() else {
            return Ok(vec![]);
        };

        let Some((shellcheck_shell, shell_location)) = self.resolved_shell(step, config) else {
            return Ok(vec![]);
        };

        let shellcheck_script = Self::sanitize_shellcheck_script(run);

        let diagnostics = self
            .run_shellcheck(&shellcheck_shell, &shellcheck_script)
            .unwrap_or_else(|error| {
                tracing::debug!("shellcheck failed to run: {error}");
                vec![]
            });

        let run_location = step.location().primary().with_keys(["run".into()]);

        // Determine the indentation offset of the run: block.
        // It will be used to calculate the exact offset of findings below.
        let run_point = run_location
            .clone()
            .concretize(step.document())
            .map_err(Self::err)?
            .concrete
            .location
            .start_point;

        diagnostics
            .into_iter()
            .map(|diagnostic| {
                // find the code fragment inside the inspected shell script
                let offset = Self::diagnostic_span(run, &diagnostic);
                let end_offset = if diagnostic.end_line == diagnostic.line {
                    let line_start = offset.saturating_sub(diagnostic.column.saturating_sub(1));
                    line_start + diagnostic.end_column.saturating_sub(1)
                } else {
                    run[offset..].find('\n').map_or(run.len(), |n| offset + n)
                };
                let end_offset = end_offset.min(run.len());
                let fragment = &run[offset..end_offset];

                // shellcheck findings columns don't take YAML indentation into account.
                // Adjust the diagnostic offset using the position of the run block within the YAML document,
                // so that the correct occurrence of the fragment is found in the raw YAML text.
                let after =
                    (diagnostic.line.saturating_sub(1) * run_point.column).saturating_add(offset);

                let location = if !fragment.is_empty() {
                    run_location
                        .clone()
                        .subfeature(Subfeature::new(after, fragment))
                        .annotated(format!("SC{}: {}", diagnostic.code, diagnostic.message))
                } else {
                    run_location.clone().annotated(format!(
                        "SC{} at line {}, column {}: {}",
                        diagnostic.code, diagnostic.line, diagnostic.column, diagnostic.message
                    ))
                };

                let mut builder = Self::finding()
                    .severity(Self::severity_for_level(&diagnostic.level))
                    .confidence(Confidence::High)
                    .persona(Persona::Regular)
                    .add_location(location);

                if let Some(shell_location) = shell_location.clone() {
                    builder = builder.add_location(shell_location.key_only());
                }

                builder
                    .tip(format!(
                        "shellcheck rule reference: https://www.shellcheck.net/wiki/SC{}",
                        diagnostic.code
                    ))
                    .build(step)
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl Audit for ShellcheckAudit {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let executable = "shellcheck".into();

        match Command::new(&executable)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => Ok(Self { executable }),
            Ok(status) => Err(AuditLoadError::Skip(anyhow!(
                "`{executable} --version` exited with {status}"
            ))),
            Err(error) => Err(AuditLoadError::Skip(anyhow!(
                "`{executable}` unavailable ({error})"
            ))),
        }
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config)
    }
}
