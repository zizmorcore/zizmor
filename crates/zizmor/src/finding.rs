//! Models and APIs for handling findings and their locations.

use anyhow::{Result, anyhow};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use self::location::{Location, SymbolicLocation};
use crate::{
    InputKey,
    models::AsDocument,
    yaml_patch::{self, Patch},
};

pub(crate) mod location;

/// Represents the expected "persona" that would be interested in a given
/// finding. This is used to model the sensitivity of different use-cases
/// to false positives.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    Serialize,
    Deserialize,
    ValueEnum,
)]
pub(crate) enum Persona {
    /// The "auditor" persona (false positives OK).
    ///
    /// This persona wants all results, including results that are likely
    /// to be false positives.
    Auditor,

    /// The "pedantic" persona (code smells OK).
    ///
    /// This persona wants findings that may or may not be problems,
    /// but are potential "code smells".
    Pedantic,

    /// The "regular" persona (minimal false positives).
    ///
    /// This persona wants actionable findings, and is sensitive to
    /// false positives.
    #[default]
    Regular,
}

#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    Serialize,
    Deserialize,
    ValueEnum,
)]
pub(crate) enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    Serialize,
    Deserialize,
    ValueEnum,
)]
pub(crate) enum Severity {
    #[default]
    Unknown,
    Informational,
    Low,
    Medium,
    High,
}

/// A finding's "determination," i.e. its various classifications.
#[derive(Serialize)]
pub(crate) struct Determinations {
    pub(crate) confidence: Confidence,
    pub(crate) severity: Severity,
    pub(super) persona: Persona,
}

/// Represents the "disposition" of a fix.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) enum FixDisposition {
    /// The fix is safe to apply automatically.
    #[allow(dead_code)]
    Safe,
    /// The fix should be applied with manual oversight.
    #[default]
    Unsafe,
}

/// Represents a suggested fix for a finding.
///
/// A fix is associated with a specific input via its [`Fix::key`],
/// and contains one or more [`Patch`] operations to apply to the input.
pub(crate) struct Fix<'doc> {
    /// A short title describing the fix.
    #[allow(dead_code)]
    pub(crate) title: String,
    /// The key back into the input registry that this fix applies to.
    pub(crate) key: &'doc InputKey,
    /// The fix's disposition.
    pub(crate) disposition: FixDisposition,
    /// One or more YAML patches to apply as part of this fix.
    pub(crate) patches: Vec<Patch<'doc>>,
}

impl Fix<'_> {
    /// Apply the fix to the given document.
    pub(crate) fn apply(
        &self,
        document: &yamlpath::Document,
    ) -> anyhow::Result<yamlpath::Document> {
        match yaml_patch::apply_yaml_patches(document, &self.patches) {
            Ok(new_document) => Ok(new_document),
            Err(e) => Err(anyhow!("fix failed: {e}")),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Finding<'doc> {
    /// The audit ID for this finding, e.g. `template-injection`.
    pub(crate) ident: &'static str,
    /// A short description of the finding, derived from the audit.
    pub(crate) desc: &'static str,
    /// A URL linking to the documentation for this finding's audit.
    pub(crate) url: &'static str,
    /// The confidence, severity, and persona of this finding.
    pub(crate) determinations: Determinations,
    /// This finding's locations.
    ///
    /// Each location has both a concrete and a symbolic representation,
    /// and carries metadata about how an output layer might choose to
    /// present it.
    pub(crate) locations: Vec<Location<'doc>>,
    /// Whether this finding is ignored, either via inline comments or
    /// through a user's configuration.
    pub(crate) ignored: bool,
    /// One or more suggested fixes for this finding. Because a finding
    /// can span multiple inputs, each fix is associated with a specific
    /// input via [`Fix::key`].
    #[serde(skip_serializing)]
    pub(crate) fixes: Vec<Fix<'doc>>,
}

impl Finding<'_> {
    /// A basic Markdown representation of the finding's metadata.
    pub(crate) fn to_markdown(&self) -> String {
        format!(
            "`{ident}`: {desc}\n\nDocs: <{url}>",
            ident = self.ident,
            desc = self.desc,
            url = self.url
        )
    }

    pub(crate) fn visible_locations(&self) -> impl Iterator<Item = &Location<'_>> {
        self.locations.iter().filter(|l| !l.symbolic.is_hidden())
    }

    pub(crate) fn primary_location(&self) -> &Location<'_> {
        // NOTE: Safe unwrap because FindingBuilder::build ensures a primary location.
        self.locations
            .iter()
            .find(|l| l.symbolic.is_primary())
            .unwrap()
    }
}

pub(crate) struct FindingBuilder<'doc> {
    ident: &'static str,
    desc: &'static str,
    url: &'static str,
    severity: Severity,
    confidence: Confidence,
    persona: Persona,
    raw_locations: Vec<Location<'doc>>,
    locations: Vec<SymbolicLocation<'doc>>,
    fixes: Vec<Fix<'doc>>,
}

impl<'doc> FindingBuilder<'doc> {
    pub(crate) fn new(ident: &'static str, desc: &'static str, url: &'static str) -> Self {
        Self {
            ident,
            desc,
            url,
            severity: Default::default(),
            confidence: Default::default(),
            persona: Default::default(),
            raw_locations: vec![],
            locations: vec![],
            fixes: vec![],
        }
    }

    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub(crate) fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub(crate) fn persona(mut self, persona: Persona) -> Self {
        self.persona = persona;
        self
    }

    pub(crate) fn add_raw_location(mut self, location: Location<'doc>) -> Self {
        self.raw_locations.push(location);
        self
    }

    pub(crate) fn add_location(mut self, location: SymbolicLocation<'doc>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn fix(mut self, fix: Fix<'doc>) -> Self {
        self.fixes.push(fix);
        self
    }

    pub(crate) fn build<'a>(
        self,
        document: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Finding<'doc>> {
        let mut locations = self
            .locations
            .iter()
            .map(|l| l.clone().concretize(document.as_document()))
            .collect::<Result<Vec<_>>>()?;

        locations.extend(self.raw_locations);

        if !locations.iter().any(|l| l.symbolic.is_primary()) {
            return Err(anyhow!(
                "API misuse: at least one location must be marked with primary()"
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
