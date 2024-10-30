# Hacking on `zizmor`

!!! important

    This page contains information on specific development processes.
    For more general information on *how and what* to contribute to `zizmor`,
    see our [CONTRIBUTING.md].

[CONTRIBUTING.md]: https://github.com/woodruffw/zizmor/blob/main/CONTRIBUTING.md

## General development practices

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

## Requirements

`zizmor`'s only development requirement the Rust compiler.

You can install Rust by following the steps on [Rust's official website].

[Rust's official website]: https://www.rust-lang.org/tools/install

## Building `zizmor` locally

`zizmor` is a pure Rust codebase, and can be built with a single `cargo build`:

```bash
git clone https://github.com/woodruffw/zizmor && cd zizmor
cargo build
# cargo run -- --help also works
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

### Linting

`zizmor` is linted with `cargo clippy` and auto-formatted with `cargo fmt`.
Our CI enforces both, but you should also run them locally to minimize
unnecessary review cycles:

```bash
cargo fmt
cargo clippy --fix
```

### Testing

`zizmor` uses `cargo test`:

```bash
cargo test
```

## Building the website

`zizmor`'s website is built with [MkDocs](https://www.mkdocs.org/), which
means you'll need a Python runtime to develop against it locally.

The easiest way to do this is to use [`uv`](https://github.com/astral-sh/uv),
which is what `zizmor`'s own CI uses. See
[the `uv` docs](https://docs.astral.sh/uv/getting-started/installation/) for
installation instructions.

Once you have `uv`, run `make site` in the repo root to build a local
copy of `zizmor`'s website in the `site_html` directory:

```bash
make site
```

Alternatively, for live development, you can run `make site-live`
to run a development server that'll monitor for changes to the docs:

```bash
make site-live
```

With `make site-live`, you should see something roughly like this:

```console
INFO    -  Building documentation...
INFO    -  Cleaning site directory
INFO    -  Documentation built in 0.40 seconds
INFO    -  [22:18:39] Watching paths for changes: 'docs', 'mkdocs.yml'
INFO    -  [22:18:39] Serving on http://127.0.0.1:9999/zizmor/
INFO    -  [22:18:40] Browser connected: http://127.0.0.1:9999/zizmor/development/
```

Visit the listed URL to see your live changes.

## Adding or modifying an audit

These docs could use help.

For now, please run `cargo doc --open` and refer to our internal
documentation!

