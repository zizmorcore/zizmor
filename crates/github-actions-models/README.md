github-actions-models
=====================

[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/github-actions-models)](https://crates.io/crates/github-actions-models)
[![docs.rs](https://img.shields.io/docsrs/github-actions-models)](https://docs.rs/github-actions-models)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

Unofficial, high-quality data models for GitHub Actions workflows, actions, and related components.

## Why?

I need these for [another tool], and generating them automatically from
[their JSON Schemas] wasn't working both for expressiveness and tool deficiency
reasons.

[another tool]: https://github.com/woodruffw/zizmor

[their JSON Schemas]: https://www.schemastore.org/json/

## License

MIT License.

The integration tests for this crate contain sample workflows collected from
various GitHub repositories; these contain comments linking them to their
original repositories and are licensed under the terms there.
