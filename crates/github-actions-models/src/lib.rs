//! High-quality data models for GitHub Actions and associated machinery.

#![deny(missing_debug_implementations)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::redundant_field_names)]
#![forbid(unsafe_code)]

pub mod action;
pub mod common;
pub mod dependabot;
pub mod workflow;
