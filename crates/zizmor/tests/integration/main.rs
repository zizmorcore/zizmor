// TODO: These modules could stand to be cleaned up a bit.

/// Basic acceptance tests.
mod acceptance;
/// Audit-specific tests.
mod audit;
/// Helpers.
mod common;
/// Configuration discovery tests.
mod config;
/// "Big picture" end-to-end tests, i.e. tests that typically exercise
/// more than one audit or complex CLI functionality.
mod e2e;
