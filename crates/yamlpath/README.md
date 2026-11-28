# yamlpath

[![zizmor](https://img.shields.io/badge/%F0%9F%8C%88-zizmor-white?labelColor=white)](https://zizmor.sh/)
[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/yamlpath)](https://crates.io/crates/yamlpath)
[![docs.rs](https://img.shields.io/docsrs/yamlpath)](https://docs.rs/yamlpath)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

A `Route` selects a YAML mapping key or sequence item. A `Document` resolves
the route against the original `astral-yaml` parse stream. The same stream
provides byte ranges, comments, and input for `astral_yaml_serde::from_stream`.

```rust
use yamlpath::{Document, route};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = Document::new("steps:\n  - run: 'make' # build\n")?;
    let run = route!("steps", 0, "run");
    assert_eq!(&doc.source()[doc.key_range(&run)?], "run");
    assert_eq!(&doc.source()[doc.value_range(&run)?.unwrap()], "'make'");
    let entry = doc.entry_range(&run)?;
    assert_eq!(&doc.source()[entry.clone()], "run: 'make'");
    assert_eq!(doc.comments(entry)[0].text, " build");
    Ok(())
}
```

Entry ranges point to the use site of an alias. Value ranges follow the alias
to its definition. Scalar value ranges exclude tags and anchors. An omitted mapping
value, such as `env:`, has a key and entry range and no value range.

## License

MIT License.
