# yamlpath

[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/yamlpath)](https://crates.io/crates/yamlpath)
[![docs.rs](https://img.shields.io/docsrs/yamlpath)](https://docs.rs/yamlpath)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

Format-preserving YAML feature extraction.

`yamlpath` uses [`tree-sitter`] and [`tree-sitter-yaml`] under the hood.

[`tree-sitter`]: https://github.com/tree-sitter/tree-sitter

[`tree-sitter-yaml`]: https://github.com/tree-sitter-grammars/tree-sitter-yaml

> [!IMPORTANT]
>
> This is not a substitute for full-fledged query languages or tools
> like JSONPath or `jq`.

## Why?

YAML is an extremely popular configuration format, with an interior
data model that closely resembles JSON.

It's common to need to analyze YAML files, e.g. for a security tool that
needs to interpret the contents of a configuration file.

The normal way to do this is to parse the YAML into a document and interpret
that document. However, that parsing operation is *destructive*: in producing
a document model, it *erases* the comments and exact formatting of the YAML
input.

This can make it difficult to present intelligible actions to uses,
since users think in terms of changes needed on lines and columns and not
changes needed to a specific sub-object within a document's hierarchy.

`yamlpath` bridges the gap between these two views: it allows a program
to operate on the (optimal) document view, and then *translate* back to
a human's understanding of the YAML input.

## License

MIT License.
