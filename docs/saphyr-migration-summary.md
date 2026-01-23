# Migration from tree-sitter-yaml to saphyr

## Why Consider Saphyr

- **Pure Rust, purpose-built YAML 1.2 parser** - no C dependencies, no grammar generation
- **Modular architecture** - separates parsing, tree building, and querying concerns
- **Direct tree access** - exposes node IDs, anchor metadata, and internal structure
- **Lazy alias resolution** - more efficient for partial traversals
- **Active maintenance** - dedicated YAML library vs. generic parser adapted for YAML

## Local Fixes (in `saphyr/`)

- **Span tracking for opening elements** (`af66d3e`) - proper span computation for nested structures
- **`SafelyIndexMut` addition** (`719c168`) - safer index access patterns
- **`get` without panic on `MarkedYaml`** (`0dac51e`) - non-panicking accessors
- **Boolean parsing for `True`/`TRUE`** (`ab6ce04`) - YAML 1.1 compatibility

## Changes Needed Upstream

To use saphyr-parser as a dependency (rather than vendoring), these would need upstreaming:

1. **Public span/marker access** - expose `Marker` positions on all events
2. **Re-exports of internal types** - `MarkedEventReceiver` and related traits
3. **Node position tracking** - consistent byte offset reporting for start/end positions

## Hard Requirement: Comment Support

**saphyr-parser does not emit comment events.** Comments are skipped during scanning (`scanner.rs:861-863`) with no `Comment` variant in the `Event` enum.

To support comment extraction, one of:
- **Upstream change**: Add `Comment(Span)` event variant to saphyr-parser
- **Secondary pass**: Scan source separately for `#` comment positions
- **Hybrid approach**: Keep tree-sitter for comment-dependent code paths

This affects:
- `zizmor`: `offset_inside_comment()` - skip `${{ }}` expressions inside comments
- `zizmor`: `feature_comments()` - inline ignore directives (`# zizmor: ignore[rule]`)
- `zizmor`: version extraction from comments (`uses: foo@sha # v1.2.3`)
- `zizmor`: documentation checks (meaningful comments on permissions)
- `yamlpatch`: comment-aware patching

## What We Give Up

tree-sitter provides capabilities that require extra work with saphyr:

| Capability | tree-sitter | saphyr |
|------------|-------------|--------|
| Comment nodes | Built-in CST nodes | Not available |
| Line/column index | `line-index` crate integration | Must build separately |
| Incremental re-parsing | Native support | Full re-parse required |
| Generic AST queries | tree-sitter query language | Custom traversal code |
| Syntax error recovery | Partial parse on errors | Fails on invalid YAML |

## Recommendation

Saphyr is viable for the core yamlpath functionality (path queries, feature extraction, anchor handling). However, full migration requires solving the comment gap - either through upstream changes to saphyr-parser or a supplementary comment-detection layer.
