//! Functionality for registering and managing the lifecycles of
//! audits.

use std::process::ExitCode;

use indexmap::IndexMap;

use crate::{
    audit::{self, Audit, AuditLoadError},
    finding::{Confidence, Finding, Persona, Severity},
    registry::input::{InputKey, InputRegistry},
    state::AuditState,
};

pub(crate) mod input;

pub(crate) struct AuditRegistry {
    pub(crate) audits: IndexMap<&'static str, Box<dyn Audit + Send + Sync>>,
}

impl AuditRegistry {
    fn empty() -> Self {
        Self {
            audits: Default::default(),
        }
    }

    /// Constructs a new [`AuditRegistry`] with all default audits registered.
    pub(crate) fn default_audits(audit_state: &AuditState) -> anyhow::Result<Self> {
        let mut registry = Self::empty();

        macro_rules! register_audit {
            ($rule:path) => {{
                // HACK: https://github.com/rust-lang/rust/issues/48067
                use $rule as base;

                use crate::audit::AuditCore as _;
                match base::new(&audit_state) {
                    Ok(audit) => registry.register_audit(base::ident(), Box::new(audit)),
                    Err(AuditLoadError::Skip(e)) => {
                        tracing::debug!("skipping {audit}: {e}", audit = base::ident())
                    }
                }
            }};
        }

        register_audit!(audit::artipacked::Artipacked);
        register_audit!(audit::unsound_contains::UnsoundContains);
        register_audit!(audit::excessive_permissions::ExcessivePermissions);
        register_audit!(audit::dangerous_triggers::DangerousTriggers);
        register_audit!(audit::impostor_commit::ImpostorCommit);
        register_audit!(audit::ref_confusion::RefConfusion);
        register_audit!(audit::use_trusted_publishing::UseTrustedPublishing);
        register_audit!(audit::template_injection::TemplateInjection);
        register_audit!(audit::hardcoded_container_credentials::HardcodedContainerCredentials);
        register_audit!(audit::self_hosted_runner::SelfHostedRunner);
        register_audit!(audit::known_vulnerable_actions::KnownVulnerableActions);
        register_audit!(audit::unpinned_uses::UnpinnedUses);
        register_audit!(audit::undocumented_permissions::UndocumentedPermissions);
        register_audit!(audit::insecure_commands::InsecureCommands);
        register_audit!(audit::github_env::GitHubEnv);
        register_audit!(audit::cache_poisoning::CachePoisoning);
        register_audit!(audit::secrets_inherit::SecretsInherit);
        register_audit!(audit::bot_conditions::BotConditions);
        register_audit!(audit::overprovisioned_secrets::OverprovisionedSecrets);
        register_audit!(audit::unredacted_secrets::UnredactedSecrets);
        register_audit!(audit::forbidden_uses::ForbiddenUses);
        register_audit!(audit::obfuscation::Obfuscation);
        register_audit!(audit::stale_action_refs::StaleActionRefs);
        register_audit!(audit::unpinned_images::UnpinnedImages);
        register_audit!(audit::anonymous_definition::AnonymousDefinition);
        register_audit!(audit::unsound_condition::UnsoundCondition);
        register_audit!(audit::ref_version_mismatch::RefVersionMismatch);
        register_audit!(audit::dependabot_execution::DependabotExecution);
        register_audit!(audit::dependabot_cooldown::DependabotCooldown);
        register_audit!(audit::concurrency_limits::ConcurrencyLimits);
        register_audit!(audit::archived_uses::ArchivedUses);

        Ok(registry)
    }

    pub(crate) fn len(&self) -> usize {
        self.audits.len()
    }

    pub(crate) fn register_audit(
        &mut self,
        ident: &'static str,
        audit: Box<dyn Audit + Send + Sync>,
    ) {
        self.audits.insert(ident, audit);
    }

    pub(crate) fn iter_audits(
        &self,
    ) -> indexmap::map::Iter<'_, &'static str, Box<dyn Audit + Send + Sync>> {
        self.audits.iter()
    }
}

impl std::fmt::Debug for AuditRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditRegistry")
            .field("audits", &self.audits.len())
            .finish()
    }
}

/// A registry of all findings discovered during a `zizmor` run.
pub(crate) struct FindingRegistry<'a> {
    input_registry: &'a InputRegistry,
    minimum_severity: Option<Severity>,
    minimum_confidence: Option<Confidence>,
    persona: Persona,
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
    ) -> Self {
        Self {
            input_registry,
            minimum_severity,
            minimum_confidence,
            persona,
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
        for finding in results {
            if self.persona > finding.determinations.persona {
                self.suppressed.push(finding);
            } else if finding.ignored
                || self
                    .minimum_severity
                    .is_some_and(|min| min > finding.determinations.severity)
                || self
                    .minimum_confidence
                    .is_some_and(|min| min > finding.determinations.confidence)
                || self
                    .input_registry
                    .get_config(finding.input_group())
                    .ignores(&finding)
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
    pub(crate) fn all_findings_have_applicable_fixes(&self, fix_mode: crate::FixMode) -> bool {
        use crate::finding::FixDisposition;

        if self.findings.is_empty() {
            return true;
        }

        self.findings.iter().all(|finding| {
            finding.fixes.iter().any(|fix| {
                let disposition_matches = match fix_mode {
                    crate::FixMode::Safe => matches!(fix.disposition, FixDisposition::Safe),
                    crate::FixMode::UnsafeOnly => matches!(fix.disposition, FixDisposition::Unsafe),
                    crate::FixMode::All => true,
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
