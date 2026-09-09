name: adhoc-packages

on: push

permissions: {}

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  vulnerable:
    name: vulnerable
    runs-on: ubuntu-latest
    steps:
      # NOT OK: ad-hoc `gem install`.
      - name: vulnerable-1
        run: gem install rake

      # NOT OK: ad-hoc `gem install` with multiple packages.
      - name: vulnerable-2
        run: gem install rake rspec

      # NOT OK: ad-hoc `gem install` with a version pin.
      - name: vulnerable-3
        run: gem install rake:13.0.6

      # NOT OK: ad-hoc `gem install` with a different kind of version pin.
      - name: vulnerable-4
        run: gem install rake -v 13.0.6

      # NOT OK: ad-hoc `gem install` with extra flags.
      - name: vulnerable-5
        run: gem install --no-document rake

      # NOT OK: `gem i` is an alias for `gem install`.
      - name: vulnerable-5a
        run: gem i rake

      # NOT OK: multiple ad-hoc `gem install` invocations in a multi-line `run:`.
      - name: vulnerable-6
        run: |
          echo "Hello"
          gem install foo
          gem install bar
          echo "Goodbye"

      # NOT OK: ad-hoc `npm install`.
      - name: vulnerable-7
        run: npm install lodash

      # NOT OK: ad-hoc `npm install` with a version pin.
      - name: vulnerable-8
        run: npm install oxlint@1.55.0
      - name: vulnerable-8a
        run: npm install oxlint@^1.55.0

      # NOT OK: ad-hoc `npm install` with extra flags.
      - name: vulnerable-9
        run: npm install --no-fund oxlint@1.55.0

      # NOT OK: `npm i` is an alias for `npm install`.
      - name: vulnerable-9a
        run: npm i lodash

      # NOT OK: `npm add` is also an alias for `npm install`.
      - name: vulnerable-9b
        run: npm add lodash

      # TODO: enable once `pip install` is covered.
      # # NOT OK: ad-hoc `pip install`.
      # - name: vulnerable-13
      #   run: pip install requests

  not-vulnerable:
    name: not-vulnerable
    runs-on: ubuntu-latest
    steps:
      # OK: `bundle install` uses the project's Gemfile.lock.
      - name: not-vulnerable-1
        run: bundle install

      # OK: other gem subcommands are not flagged.
      - name: not-vulnerable-2
        run: gem build foo.gemspec

      # OK: `gem install` without a package name is malformed,
      # but we don't flag it.
      - name: not-vulnerable-3
        run: gem install --help

      # OK: `npm ci` is lockfile-aware.
      - name: not-vulnerable-4
        run: npm ci

      - name: not-vulnerable-5
        run: npm install

      # OK: `npm install` without a package name uses the project's
      # package-lock.json.
      - name: not-vulnerable-6
        run: npm install --no-fund

  vulnerable-pwsh:
    name: vulnerable-pwsh
    runs-on: windows-latest
    steps:
      # NOT OK: ad-hoc `gem install` in pwsh.
      - name: vulnerable-pwsh-1
        run: gem install rake

      # NOT OK: ad-hoc `npm install` in pwsh.
      - name: vulnerable-pwsh-2
        run: npm install lodash

      # NOT OK: ad-hoc `npm install` in pwsh.
      - name: vulnerable-pwsh-3
        run: npm i lodash

      # NOT OK: ad-hoc `npm install` with version pin in pwsh.
      - name: vulnerable-pwsh-4
        run: npm install lodash@1.2.3
      - name: vulnerable-pwsh-4a
        run: npm install lodash@^1.2.3

      # NOT OK: multiline pwsh `run:` with a `gem install`.
      - name: vulnerable-pwsh-5
        run: |
          Write-Host "Hello"
          gem install foo
          Write-Host "Goodbye"

      # NOT OK: installing multiple gems.
      - name: vulnerable-pwsh-6
        run: gem install foo bar baz

      # NOT OK: installing a gem with a specific version.
      - name: vulnerable-pwsh-7
        run: gem install foo@1.2.3

  not-vulnerable-pwsh:
    name: not-vulnerable-pwsh
    runs-on: windows-latest
    steps:
      # OK: `npm ci` in pwsh.
      - name: not-vulnerable-pwsh-1
        run: npm ci

      # OK: `npm install` in pwsh.
      - name: not-vulnerable-pwsh-2
        run: npm install
      - name: not-vulnerable-pwsh-2a
        run: npm i

      # OK: `bundle install` is fine and lockfile-respecting.
      - name: not-vulnerable-pwsh-3
        run: bundle install# crates

This directory contains `zizmor`'s various crates.

See the table and each subdirectory for more details on each crate.
| Crate | Version | Documentation | Description |
|-------|---------|---------------|-------------|
| [`zizmor`][zizmor-dir] | [![Crates.io](https://img.shields.io/crates/v/zizmor)][zizmor-crates] | [![docs.zizmor.sh](https://img.shields.io/badge/zizmor-docs.zizmor.sh-blue)][zizmor-docs] | The `zizmor` CLI and core auditing functionality. |
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
