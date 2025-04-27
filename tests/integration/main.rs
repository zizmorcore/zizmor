// TODO: These modules could stand to be cleaned up a bit.

/// Basic acceptance tests.
mod acceptance;
/// Helpers.
mod common;
/// "Big picture" end-to-end tests, i.e. tests that typically exercise
/// more than one audit or complex CLI functionality.
mod e2e;
/// General snapshot tests, including repro cases for specific audits.
mod snapshot;
