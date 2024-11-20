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
* *Use [conventional commits]*. These are not mandatory, but they make
  it easier to quickly visually scan the contents of a change. Help us
  out by using them!

[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/

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

### Before getting started

Before adding a new audit or changing an existing one, make it sure that you discussed required
details in a proper GitHub issue. Most likely there is a chance to uncover some implementation
details even before writing any code!

Some things that can be useful to discuss beforehand:

- Which criticality should we assign for this new finding?
- Which confidence should we assign for this new finding?
- Should this new audit be pedantic at all?
- Does this new audit require using the Github API, or is it entirely off-line?

When developing a new `zizmor` audit, there are a couple of implementation details to be aware of:

- All existing audits live in a Rust modules grouped under `src/audit` folder
- The expected behaviour for all audits is defined by the `WorkflowAudit` trait at `src/audit/mod.rs`
- The expected outcome of an executed audit is defined by the `Finding` struct at `src/finding/mod.rs`
- Any `WorkflowAudit` implementation can have access to an `AuditState` instance, as per `src/state.rs`
- If an audit requires data from the GitHub API, there is a `Client` implementation at `src/github_api.rs`
- All the audits must be registered at `src/main.rs` according to the `register_audit!` macro

Last but not least, it's useful to run the following checks before opening a Pull Request:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

### Adding a new audit

The general procedure for adding a new audit can be described as:

- Define a new file at `src/audit/my_new_audit.rs`
- Define a struct like `MyNewAudit` and implement the `WorkflowAudit` trait for it
- You may want to use both the `AuditState` and `github_api::Client` to get the job done
- Assign the proper YML `location` when creating a `Finding`, grabbing it from the proper `Workflow`, `Job` or `Step` instance
- Register `MyNewAudit` in the known audits at `src/main.rs`
- Add proper integration tests covering some scenarios at `tests/acceptance.rs`
- Add proper docs for this new audit at `docs/audits`. Please add related public information about the underlying vulnerability
- Raise your Pull Request!

!!! tip

    When in doubt, you can always refer to existing audit implementations as well!

### Changing an existing audit

The general procedure for changing an existing audit is:

- Locate the existing audit file at `src/audit`
- Change the behaviour to match new requirements there (e.g. consuming a new CLI info exposed through `AuditState`)
- Ensure that tests and samples at `tests/` reflect changed behaviour accordingly (e.g. the confidence for finding has changed)
- Ensure that `docs/audits` reflect changed behaviour accordingly (e.g. an audit that is no longer pedantic)
- Open your Pull Request

## Changing `zizmor`'s CLI

`zizmor` uses [clap] and [clap-derive] for its command-line interface.

`zizmor`'s documentation contains a copy of `zizmor --help`, which the CI
checks to ensure that it remains updated. If you change `zizmor`'s CLI,
you may need to regenerate the documentation snippets and check-in the results:

```bash
make snippets
```

[clap]: https://docs.rs/clap/latest/clap/index.html

[clap-derive]: https://docs.rs/clap/latest/clap/_derive/index.html
