# crates

This directory contains `zizmor`'s various crates.

See the table and each subdirectory for more details on each crate.

| Crate | Version | Documentation | Description |
|-------|---------|---------------|-------------|
| [`zizmor`][zizmor-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor)][zizmor-crates] | [![docs.zizmor.sh](https://img.shields.io/badge/zizmor-docs.zizmor.sh-blue)][zizmor-docs] | The leaf crate for the `zizmor` command-line application. |
| [`zizmor-audit`][zizmor-audit-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-audit)][zizmor-audit-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-audit)][zizmor-audit-docs] | The audit engine and audit implementations for `zizmor`. |
| [`zizmor-cli`][zizmor-cli-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-cli)][zizmor-cli-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-cli)][zizmor-cli-docs] | Command-line argument models and related CLI support for `zizmor`. |
| [`zizmor-collect`][zizmor-collect-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-collect)][zizmor-collect-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-collect)][zizmor-collect-docs] | Local, standard input, and remote input collection for `zizmor`. |
| [`zizmor-config`][zizmor-config-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-config)][zizmor-config-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-config)][zizmor-config-docs] | Configuration parsing, loading, and discovery for `zizmor`. |
| [`zizmor-core`][zizmor-core-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-core)][zizmor-core-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-core)][zizmor-core-docs] | Shared models, foundational types, utilities, and GitHub client support for `zizmor`. |
| [`subfeature`][subfeature-dir] | [![Crates.io](https://img.shields.io/crates/v/subfeature)][subfeature-crates] | [![docs.rs](https://img.shields.io/docsrs/subfeature)][subfeature-docs] | Subfeature handling APIs. |
| [`yamlpath`][yamlpath-dir] | [![Crates.io](https://img.shields.io/crates/v/yamlpath)][yamlpath-crates] | [![docs.rs](https://img.shields.io/docsrs/yamlpath)][yamlpath-docs] | Format-preserving YAML feature extraction. |
| [`yamlpatch`][yamlpath-dir] | [![Crates.io](https://img.shields.io/crates/v/yamlpatch)][yamlpath-crates] | [![docs.rs](https://img.shields.io/docsrs/yamlpatch)][yamlpath-docs] | Comment and format-preserving YAML patch operations. |
| [`github-actions-models`][github-actions-models-dir] | [![Crates.io](https://img.shields.io/crates/v/github-actions-models)][github-actions-models-crates] | [![docs.rs](https://img.shields.io/docsrs/github-actions-models)][github-actions-models-docs] | Unofficial, high-quality data models for GitHub Actions workflows, actions, and related components. |
| [`github-actions-expressions`][github-actions-expressions-dir] | [![Crates.io](https://img.shields.io/crates/v/github-actions-expressions)][github-actions-expressions-crates] | [![docs.rs](https://img.shields.io/docsrs/github-actions-expressions)][github-actions-expressions-docs] | Parser and library for GitHub Actions expressions. |
| [`tree-sitter-iter`][tree-sitter-iter-dir] | [![Crates.io](https://img.shields.io/crates/v/tree-sitter-iter)][tree-sitter-iter-crates] | [![docs.rs](https://img.shields.io/docsrs/tree-sitter-iter)][tree-sitter-iter-docs] | A very simple pre-order iterator for tree-sitter CSTs. |
| [`zizmor-sarif`][zizmor-sarif-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor-sarif)][zizmor-sarif-crates] | [![docs.rs](https://img.shields.io/docsrs/zizmor-sarif)][zizmor-sarif-docs] | Minimal SARIF 2.1.0 data models used by `zizmor`. |
| [`pre-commit-models`][pre-commit-models-dir] | [![Crates.io](https://img.shields.io/crates/v/pre-commit-models)][pre-commit-models-crates] | [![docs.rs](https://img.shields.io/docsrs/pre-commit-models)][zizmor-sarif-docs] | Unofficial, high-quality data models for pre-commit. |

[zizmor-dir]: ./zizmor
[zizmor-crates]: https://crates.io/crates/zizmor
[zizmor-docs]: https://docs.zizmor.sh/

[zizmor-audit-dir]: ./zizmor-audit
[zizmor-audit-crates]: https://crates.io/crates/zizmor-audit
[zizmor-audit-docs]: https://docs.rs/zizmor-audit

[zizmor-cli-dir]: ./zizmor-cli
[zizmor-cli-crates]: https://crates.io/crates/zizmor-cli
[zizmor-cli-docs]: https://docs.rs/zizmor-cli

[zizmor-collect-dir]: ./zizmor-collect
[zizmor-collect-crates]: https://crates.io/crates/zizmor-collect
[zizmor-collect-docs]: https://docs.rs/zizmor-collect

[zizmor-config-dir]: ./zizmor-config
[zizmor-config-crates]: https://crates.io/crates/zizmor-config
[zizmor-config-docs]: https://docs.rs/zizmor-config

[zizmor-core-dir]: ./zizmor-core
[zizmor-core-crates]: https://crates.io/crates/zizmor-core
[zizmor-core-docs]: https://docs.rs/zizmor-core

[subfeature-dir]: ./subfeature
[subfeature-crates]: https://crates.io/crates/subfeature
[subfeature-docs]: https://docs.rs/subfeature

[yamlpath-dir]: ./yamlpath
[yamlpath-crates]: https://crates.io/crates/yamlpath
[yamlpath-docs]: https://docs.rs/yamlpath

[yamlpatch-dir]: ./yamlpatch
[yamlpatch-crates]: https://crates.io/crates/yamlpatch
[yamlpatch-docs]: https://docs.rs/yamlpatch

[github-actions-models-dir]: ./github-actions-models
[github-actions-models-crates]: https://crates.io/crates/github-actions-models
[github-actions-models-docs]: https://docs.rs/github-actions-models

[github-actions-expressions-dir]: ./github-actions-expressions
[github-actions-expressions-crates]: https://crates.io/crates/github-actions-expressions
[github-actions-expressions-docs]: https://docs.rs/github-actions-expressions

[tree-sitter-iter-dir]: ./tree-sitter-iter
[tree-sitter-iter-crates]: https://crates.io/crates/tree-sitter-iter
[tree-sitter-iter-docs]: https://docs.rs/tree-sitter-iter

[zizmor-sarif-dir]: ./zizmor-sarif
[zizmor-sarif-crates]: https://crates.io/crates/zizmor-sarif
[zizmor-sarif-docs]: https://docs.rs/zizmor-sarif

[pre-commit-models-dir]: ./pre-commit-models
[pre-commit-models-crates]: https://crates.io/crates/pre-commit-models
[pre-commit-models-docs]: https://docs.rs/pre-commit-models
