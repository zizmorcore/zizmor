# `zizmor-sarif`

Minimal in-tree data models for [SARIF 2.1.0] — covering only the
fields that [`zizmor`] currently emits as output.

This crate is workspace-internal: it is not intended to be a general
SARIF library and only models the subset of the specification needed
to produce zizmor's `--format=sarif` output. If you need a complete
SARIF crate for parsing or generation outside zizmor, use one of the
existing community crates (e.g. `serde-sarif`).

[SARIF 2.1.0]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
[`zizmor`]: https://github.com/zizmorcore/zizmor
