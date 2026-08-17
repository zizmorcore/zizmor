use std::process::ExitCode;

use zizmor_audit::finding::{Finding, FixDisposition};
use zizmor_cli::FixMode;
use zizmor_collect::InputRegistry;
use zizmor_core::{
    finding::{Confidence, Persona, Severity},
    input::InputKey,
};

/// A registry of all findings discovered during a `zizmor` run.
pub(crate) struct FindingRegistry<'a> {
    input_registry: &'a InputRegistry,
    minimum_severity: Option<Severity>,
    minimum_confidence: Option<Confidence>,
    persona: Persona,
    no_ignores: bool,
    suppressed: Vec<Finding<'a>>,
    ignored: Vec<Finding<'a>>,
    findings: Vec<Finding<'a>>,
    highest_seen_severity: Option<Severity>,
}

impl<'a> FindingRegistry<'a> {
    pub(crate) fn new(
        input_registry: &'a InputRegistry,
        minimum_severity: Option<Severity>,
        minimum_confidence: Option<Confidence>,
        persona: Persona,
        no_ignores: bool,
    ) -> Self {
        Self {
            input_registry,
            minimum_severity,
            minimum_confidence,
            persona,
            no_ignores,
            suppressed: Default::default(),
            ignored: Default::default(),
            findings: Default::default(),
            highest_seen_severity: None,
        }
    }

    /// Adds one or more findings to the current findings set,
    /// filtering with the configuration in the process.
    pub(crate) fn extend(&mut self, results: Vec<Finding<'a>>) {
        // TODO: is it faster to iterate like this, or do `find_by_max`
        // and then `extend`?
        for mut finding in results {
            let config = self.input_registry.get_config(finding.input_group());

            finding.remap_severity(config);

            // A finding is ignored either if it's marked as ignored (i.e. via an ignore comment),
            // or the config for its input group ignores it, but only the user hasn't
            // overridden all ignores with `--no-ignores`.
            let ignored = (finding.ignored || finding.is_ignored_by(config)) && !self.no_ignores;

            if self.persona > finding.determinations.persona {
                self.suppressed.push(finding);
            } else if ignored
                || self
                    .minimum_severity
                    .is_some_and(|min| min > finding.determinations.severity)
                || self
                    .minimum_confidence
                    .is_some_and(|min| min > finding.determinations.confidence)
            {
                self.ignored.push(finding);
            } else {
                if self
                    .highest_seen_severity
                    .is_none_or(|s| finding.determinations.severity > s)
                {
                    self.highest_seen_severity = Some(finding.determinations.severity);
                }

                self.findings.push(finding);
            }
        }
    }

    /// The total count of all findings, regardless of status.
    pub(crate) fn count(&self) -> usize {
        self.findings.len() + self.ignored.len() + self.suppressed.len()
    }

    /// All non-ignored and non-suppressed findings.
    pub(crate) fn findings(&self) -> &[Finding<'a>] {
        &self.findings
    }

    /// Findings from [`FindingRegistry::findings`] that are fixable.
    ///
    /// A finding is considered fixable if it has at least one
    /// fix, and all fixes are local (i.e. they don't reference remote inputs).
    pub(crate) fn fixable_findings(&self) -> impl Iterator<Item = &Finding<'a>> {
        self.findings.iter().filter(|f| {
            !f.fixes.is_empty()
                && f.fixes
                    .iter()
                    .all(|fix| matches!(fix.key, InputKey::Local(_)))
        })
    }

    /// Checks if all findings have at least one fix matching the given fix mode.
    ///
    /// Returns true if every finding has at least one applicable fix based on the mode,
    /// meaning no manual intervention would be required if all fixes are applied successfully.
    pub(crate) fn all_findings_have_applicable_fixes(&self, fix_mode: FixMode) -> bool {
        if self.findings.is_empty() {
            return true;
        }

        self.findings.iter().all(|finding| {
            finding.fixes.iter().any(|fix| {
                let disposition_matches = match fix_mode {
                    FixMode::Safe => matches!(fix.disposition, FixDisposition::Safe),
                    FixMode::UnsafeOnly => matches!(fix.disposition, FixDisposition::Unsafe),
                    FixMode::All => true,
                };

                disposition_matches && matches!(fix.key, InputKey::Local(_))
            })
        })
    }

    /// All ignored findings.
    pub(crate) fn ignored(&self) -> &[Finding<'a>] {
        &self.ignored
    }

    /// All persona-suppressed findings.
    pub(crate) fn suppressed(&self) -> &[Finding<'a>] {
        &self.suppressed
    }

    /// Returns an appropriate exit code based on the registry's
    /// highest-seen severity.
    pub(crate) fn exit_code(&self) -> ExitCode {
        match self.highest_seen_severity {
            Some(sev) => match sev {
                Severity::Informational => ExitCode::from(11),
                Severity::Low => ExitCode::from(12),
                Severity::Medium => ExitCode::from(13),
                Severity::High => ExitCode::from(14),
            },
            None => ExitCode::SUCCESS,
        }
    }
}
