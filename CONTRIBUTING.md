# Contributing to `zizmor`

Thank you for your interest in contributing to `zizmor`!

The information below will help you set up a local development environment,
as well as with performing common development tasks.

This is intended to be a "high-level" guide; for concrete development
goals (such as modifying an audit or contributing a new audit),
please see our [development docs](./docs/DEVELOPMENT.md).

## Requirements

`zizmor`'s only development requirement the Rust compiler.

You can install Rust by following the steps on [Rust's official website].

[Rust's official website]: https://www.rust-lang.org/tools/install

## Development steps

To get started, you'll need to clone the repository and perform a debug build:

```bash
git clone https://github.com/woodruffw/zizmor
cd zizmor
cargo build
```

Once `cargo build` completes, you should have a functional development
build of `zizmor`!

```bash
# cargo run -- --help also works
./target/debug/zizmor --help
```

## Linting

`zizmor` is linted with `cargo clippy` and auto-formatted with `cargo fmt`.
Our CI enforces both, but you should also run them locally to minimize
unnecessary review cycles:

```bash
cargo fmt
cargo clippy --fix
```

## Testing

`zizmor` uses `cargo test`:

```bash
cargo test
```

## Development practices

Here are some guidelines to follow if you're working on `zizmor`:

* *Document internal APIs*. `zizmor` doesn't have a public Rust API (yet),
  but the internal APIs should be documented *as if* they might become public
  one day. Plus, well-documented internals make life easier for new
  contributors.
* *Write unit tests*. It's easy for small changes in `zizmor`'s internals to
  percolate into large bugs (e.g. incorrect location information); help us
  catch these bugs earlier by testing your changes at the smallest unit of
  behavior.
* *Test on real inputs*. If you're contributing to or adding a new audit,
  make sure your analysis is reliable and accurate on non-sample inputs.
