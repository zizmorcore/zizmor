//! Models and APIs for handling findings and their locations.

use anyhow::anyhow;
use serde::Serialize;
use std::fmt;
use zizmor_config::Config;
use zizmor_core::finding::{
    Confidence, Determinations, Persona, Severity,
    location::{Location, LocationKind, SymbolicLocation},
};

use crate::{
    audit::AuditError,
    input::{Group, InputKey},
    models::AsDocument,
};
use yamlpatch::{self, Patch};

/// Represents the "disposition" of a fix.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FixDisposition {
    /// The fix is safe to apply automatically.
    Safe,
    /// The fix should be applied with manual oversight.
    #[default]
    Unsafe,
}

impl fmt::Display for FixDisposition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Safe => write!(f, "safe"),
            Self::Unsafe => write!(f, "unsafe"),
        }
    }
}

/// Represents a suggested fix for a finding.
///
/// A fix is associated with a specific input via its [`Fix::key`],
/// and contains one or more [`Patch`] operations to apply to the input.
pub struct Fix<'doc> {
    /// A short title describing the fix.
    pub title: String,
    /// The key back into the input registry that this fix applies to.
    pub key: &'doc InputKey,
    /// The fix's disposition.
    pub disposition: FixDisposition,
    /// One or more YAML patches to apply as part of this fix.
    pub patches: Vec<Patch<'doc>>,
}

impl Fix<'_> {
    /// Apply the fix to the given document.
    pub fn apply(&self, document: &yamlpath::Document) -> anyhow::Result<yamlpath::Document> {
        match yamlpatch::apply_yaml_patches(document, &self.patches) {
            Ok(new_document) => Ok(new_document),
            Err(e) => Err(anyhow!("fix failed: {e}")),
        }
    }
}

pub struct Finding<'doc> {
    /// The audit ID for this finding, e.g. `template-injection`.
    pub ident: &'static str,
    /// A short description of the finding, derived from the audit.
    pub desc: &'static str,
    /// A URL linking to the documentation for this finding's audit.
    pub url: &'static str,
    /// The confidence, severity, and persona of this finding.
    pub determinations: Determinations,
    /// This finding's locations.
    ///
    /// Each location has both a concrete and a symbolic representation,
    /// and carries metadata about how an output layer might choose to
    /// present it.
    pub locations: Vec<Location<'doc>>,
    /// A tip or recommendation associated with this finding.
    pub tip: Option<String>,
    /// Whether this finding is ignored, either via inline comments or
    /// through a user's configuration.
    pub ignored: bool,
    /// One or more suggested fixes for this finding. Because a finding
    /// can span multiple inputs, each fix is associated with a specific
    /// input via [`Fix::key`].
    pub fixes: Vec<Fix<'doc>>,
}

impl Finding<'_> {
    /// A basic Markdown representation of the finding's metadata.
    pub fn to_markdown(&self) -> String {
        format!(
            "`{ident}`: {desc}\n\nDocs: <{url}>",
            ident = self.ident,
            desc = self.desc,
            url = self.url
        )
    }

    pub fn visible_locations(&self) -> impl Iterator<Item = &Location<'_>> {
        self.locations.iter().filter(|l| !l.symbolic.is_hidden())
    }

    pub fn primary_location(&self) -> &Location<'_> {
        // NOTE: Safe unwrap because FindingBuilder::build ensures a primary location.
        self.locations
            .iter()
            .find(|l| l.symbolic.is_primary())
            .expect("internal error: finding has no primary location")
    }

    /// Return the input group for this finding's primary location.
    ///
    /// We assume that all locations in a finding belong to the same group,
    /// if not the same file within that group.
    pub fn input_group(&self) -> &Group {
        self.primary_location().symbolic.key.group()
    }

    /// Returns whether this finding is ignored by the given configuration.
    pub fn is_ignored_by(&self, config: &Config) -> bool {
        let ignore_rules = config.ignore_rules(self.ident);

        self.locations.iter().any(|location| {
            let filename = location.symbolic.key.filename();
            let point = location.concrete.location.start_point;
            let line = point.row + 1;
            let column = point.column + 1;

            ignore_rules.iter().any(|rule| {
                rule.filename == filename
                    && rule.line.is_none_or(|rule_line| rule_line == line)
                    && rule.column.is_none_or(|rule_column| rule_column == column)
            })
        })
    }

    /// Remaps this finding's severity according to the given configuration.
    pub fn remap_severity(&mut self, config: &Config) {
        if let Some(severity) = config.severity_remap_for(self.ident) {
            self.determinations.severity = severity;
        }
    }
}

pub struct FindingBuilder<'doc> {
    ident: &'static str,
    desc: &'static str,
    url: &'static str,
    severity: Severity,
    confidence: Confidence,
    persona: Persona,
    raw_locations: Vec<Location<'doc>>,
    locations: Vec<SymbolicLocation<'doc>>,
    tip: Option<String>,
    fixes: Vec<Fix<'doc>>,
}

impl<'doc> FindingBuilder<'doc> {
    pub fn new(ident: &'static str, desc: &'static str, url: &'static str) -> Self {
        Self {
            ident,
            desc,
            url,
            severity: Severity::Low,
            confidence: Confidence::Low,
            persona: Default::default(),
            raw_locations: vec![],
            locations: vec![],
            tip: None,
            fixes: vec![],
        }
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn persona(mut self, persona: Persona) -> Self {
        self.persona = persona;
        self
    }

    pub fn add_raw_location(mut self, location: Location<'doc>) -> Self {
        self.raw_locations.push(location);
        self
    }

    pub fn add_location(mut self, location: SymbolicLocation<'doc>) -> Self {
        self.locations.push(location);
        self
    }

    pub fn tip(mut self, tip: impl Into<String>) -> Self {
        self.tip = Some(tip.into());
        self
    }

    pub fn fix(mut self, fix: Fix<'doc>) -> Self {
        self.fixes.push(fix);
        self
    }

    pub fn build<'a>(
        self,
        document: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Finding<'doc>, AuditError> {
        let mut locations = self
            .locations
            .iter()
            .map(|l| l.clone().concretize(document.as_document()))
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|e| AuditError::new(self.ident, e))?;

        locations.extend(self.raw_locations);

        if locations.len() == 1
            && let Some(location) = locations.get_mut(0)
        {
            // If there's only one location, then it's primary by definition.
            location.symbolic.kind = LocationKind::Primary;
        } else if !locations.iter().any(|l| l.symbolic.is_primary()) {
            return Err(AuditError::new(
                self.ident,
                anyhow!("API misuse: at least one location must be marked with primary()"),
            ));
        }

        let should_ignore = Self::ignored_from_inlined_comment(&locations, self.ident);

        Ok(Finding {
            ident: self.ident,
            desc: self.desc,
            url: self.url,
            determinations: Determinations {
                confidence: self.confidence,
                severity: self.severity,
                persona: self.persona,
            },
            locations,
            tip: self.tip,
            ignored: should_ignore,
            fixes: self.fixes,
        })
    }

    fn ignored_from_inlined_comment(locations: &[Location], id: &str) -> bool {
        locations
            .iter()
            .flat_map(|l| &l.concrete.comments)
            .any(|c| c.ignores(id))
    }
}
