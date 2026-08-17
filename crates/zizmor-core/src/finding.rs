//! Shared finding classifications and location primitives.

use serde::{Deserialize, Serialize};

pub mod location;

/// Represents the expected "persona" that would be interested in a given
/// finding. This is used to model the sensitivity of different use-cases
/// to false positives.
#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, Deserialize,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Persona {
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

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Severity {
    #[serde(rename(serialize = "Informational", deserialize = "informational"))]
    #[cfg_attr(feature = "schema", schemars(rename = "informational"))]
    Informational,
    #[serde(rename(serialize = "Low", deserialize = "low"))]
    #[cfg_attr(feature = "schema", schemars(rename = "low"))]
    Low,
    #[serde(rename(serialize = "Medium", deserialize = "medium"))]
    #[cfg_attr(feature = "schema", schemars(rename = "medium"))]
    Medium,
    #[serde(rename(serialize = "High", deserialize = "high"))]
    #[cfg_attr(feature = "schema", schemars(rename = "high"))]
    High,
}

/// A finding's "determination," i.e. its various classifications.
#[derive(Copy, Clone, Serialize)]
pub struct Determinations {
    pub confidence: Confidence,
    pub severity: Severity,
    pub persona: Persona,
}
