# Hacking on `zizmor`

!!! important

    This page contains information on specific development processes.
    For more general information on *how* to contribute to `zizmor`, see our
    [CONTRIBUTING.md].

[CONTRIBUTING.md]: https://github.com/woodruffw/zizmor/blob/main/CONTRIBUTING.md

## Building `zizmor` locally

`zizmor` is a pure Rust codebase, and can be built with a single `cargo build`:

```bash
git clone https://github.com/woodruffw/zizmor && cd zizmor
cargo build
./target/debug/zizmor --help
```

Similarly, you can build the developer-only documentation with
`cargo doc`:

```bash
# build only
cargo doc

# build and open in the local browser
cargo doc --open
```

## Writing documentation

One of the best ways to help us with `zizmor` is to help us improve our
documentation!

Here are some things we could use help with:

* Improving the detail in our [audit documentation pages](./audits/).

More generally, see [issues labeled with `documentation`] for a potential
list of documentation efforts to contribute on.

[issues labeled with `documentation`]: https://github.com/woodruffw/zizmor/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen+label%3Adocumentation

## Adding or modifying an audit

These docs could use help.

For now, please run `cargo doc --open` and refer to our internal
documentation!

