# yamlpatch

[![zizmor](https://img.shields.io/badge/%F0%9F%8C%88-zizmor-white?labelColor=white)](https://zizmor.sh/)
[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/yamlpatch)](https://crates.io/crates/yamlpatch)
[![docs.rs](https://img.shields.io/docsrs/yamlpatch)](https://docs.rs/yamlpatch)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

Comment and format-preserving YAML patch operations.

`yamlpatch` builds on [`yamlpath`] to provide surgical modification capabilities
while preserving comments, formatting, and structure.

[`yamlpath`]: https://github.com/zizmorcore/zizmor/tree/main/crates/yamlpath

> [!IMPORTANT]
>
> This is not a substitute for comprehensive YAML processing libraries.
> It's designed for targeted modifications that preserve the original
> document's formatting and comments.

## Why?

When working with YAML configuration files, it's often necessary to make
programmatic changes while preserving the human-readable aspects of the
file: comments, formatting, indentation, and style choices.

Traditional YAML processing involves parsing to a document model, making
changes, and re-serializing. This approach *destroys* the original formatting
and comments, making the result less suitable for version control and
human review.

`yamlpatch` solves this by providing targeted patch operations that:

- Preserve comments and their positioning
- Maintain original indentation and formatting
- Respect different YAML styles (block vs. flow, single vs. multi-line)
- Support precise fragment rewriting within string values
- Handle complex nested structures gracefully

## Operations

`yamlpatch` supports several types of patch operations:

- **Replace**: Replace a value at a specific path
- **Add**: Add new key-value pairs to mappings
- **Remove**: Remove keys or elements
- **MergeInto**: Merge values into existing mappings
- **RewriteFragment**: Rewrite portions of string values (useful for templating)

Each operation is designed to work with the existing document structure
and formatting, making minimal changes while achieving the desired result.

## License

MIT License.
