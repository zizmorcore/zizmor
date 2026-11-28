# yamlpatch

[![zizmor](https://img.shields.io/badge/%F0%9F%8C%88-zizmor-white?labelColor=white)](https://zizmor.sh/)
[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/yamlpatch)](https://crates.io/crates/yamlpatch)
[![docs.rs](https://img.shields.io/docsrs/yamlpatch)](https://docs.rs/yamlpatch)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

A fix is an ordered list of operations on YAML mapping keys and sequence
indices. Astral applies the list in one transaction. The caller receives the
rendered YAML when every operation succeeds.

```rust
use astral_yaml_serde::Value;
use yamlpatch::{Op, Patch, apply_yaml_patches};
use yamlpath::{Document, route};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = Document::new("permissions: write-all  # CI\n")?;
    let fixed = apply_yaml_patches(&input, &[Patch {
        route: route!("permissions"),
        operation: Op::Replace(Value::String("read-all".into())),
    }])?;
    let permissions: std::collections::HashMap<String, String> =
        astral_yaml_serde::from_str(&fixed)?;
    assert_eq!(permissions["permissions"], "read-all");
    Ok(())
}
```

The editor preserves YAML values and attached comments across edits. Rendering
can change indentation, quoting, collection style, and line endings. An edit
through an alias applies to that use. Editing a shared anchor definition returns
an error because it could change other uses.

## License

MIT License.
