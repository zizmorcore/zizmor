---
description: Development tasks and processes.
---

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

`zizmor`'s only development requirement is the Rust compiler.

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

## Formatting and linting

`zizmor` is linted with `cargo clippy` and auto-formatted with `cargo fmt`.
Our CI enforces both, but you should also run them locally to minimize
unnecessary review cycles:

```bash
cargo fmt
cargo clippy --fix
```

## Testing

`zizmor` has both unit and integration tests, and uses `cargo test` to
orchestrate both of them.

```bash
# run only unit tests
cargo test --bins

# run specific integration tests
cargo test --test acceptance
cargo test --test snapshot

# run all of the tests
cargo test
```

### Writing snapshot tests

`zizmor` uses @mitsuhiko/insta for snapshot testing.

The easiest way to use `insta` is to install `cargo-insta`:

```bash
cargo install --locked cargo-insta
```

Snapshot tests are useful for a handful of scenarios:

1. For cases when normal acceptance integration tests are too tedious to write;
1. For regression detection with specific user-submitted workflows;
1. For testing `zizmor`'s exact output/behavior on error scenarios.

To add a new snapshot test, edit `tests/snapshot.rs` and add (or modify)
an appropriate test function. You can use the existing ones for reference.

When a new snapshot test is added, `cargo test` will run it and then fail,
since the new snapshot has not yet been *accepted*. The easiest way to
accept the new snapshot (or accept changes to other snapshot tests)
is to use `cargo insta`, as installed above:

```bash
# run all the tests, generating new snapshots as necessary
cargo insta test

# review the new snapshots generated above
cargo insta review
```

or, as a shortcut:

```bash
cargo insta test --review
```

See [insta's documentation] for more details.

## Building the website

`zizmor`'s website is built with [MkDocs](https://www.mkdocs.org/), which
means you'll need a Python runtime to develop against it locally.

The easiest way to do this is to use @astral-sh/uv,
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

### Updating the snippets

`zizmor`'s website contains various static snippets. To update these:

```
make snippets
```

Most of the time, this should result in no changes, since the snippets
will already be up-to-date.

### Updating the trophy case

!!! tip

    Additions to the trophy case are welcome, but we currently limit them
    to repositories with 100 or more "stars" to keep things tractable.

The [Trophy Case](./trophy-case.md) is kept up-to-date through the data in
the `docs/snippets/trophies.txt` file.

To add a new trophy to the trophy case, add it to that file *in the same
format* as the other entries.

Then, regenerate the trophy case:

```
make trophies
```

## Adding or modifying an audit

### Before getting started

Before adding a new audit or changing an existing one, make it sure that you discussed required
details in a proper GitHub issue. Most likely there is a chance to uncover some implementation
details even before writing any code!

Some things that can be useful to discuss beforehand:

- Which criticality should we assign for this new finding?
- Which confidence should we assign for this new finding?
- Should this new audit be pedantic at all?
- Does this new audit require using the GitHub API, or is it entirely offline?

When developing a new `zizmor` audit, there are a couple of implementation details to be aware of:

- All existing audits live in a Rust modules grouped under `src/audit` folder
- The expected behavior for all audits is defined by the `WorkflowAudit` trait at `src/audit/mod.rs`
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

!!! tip

    `WorkflowAudit` has various default implementations that are useful if your
    audit only needs to look at individual jobs, steps, etc.

    For example, you may want to implement `WorkflowAudit::audit_step` to
    audit each step individually rather than having to iterate from the workflow
    downwards with `WorkflowAudit::audit`.

!!! tip

    When in doubt, refer to pre-existing audits for inspiration!

The general procedure for adding a new audit can be described as:

- Define a new file at `src/audit/my_new_audit.rs`
- Define a struct like `MyNewAudit`
- Use the `audit_meta!` macro to implement `Audit` for `MyNewAudit`
- Implement the `WorkflowAudit` trait for `MyNewAudit`
    - You may want to use both the `AuditState` and `github_api::Client` to get the job done
- Assign the proper `location` when creating a `Finding`, grabbing it from the
  proper `Workflow`, `Job` or `Step` instance
- Register `MyNewAudit` in the known audits at `src/main.rs`
- Add proper integration tests covering some scenarios at `tests/acceptance.rs`
- Add proper docs for this new audit at `docs/audits`. Please add related public
  information about the underlying vulnerability
- Open your Pull Request!

### Changing an existing audit

The general procedure for changing an existing audit is:

- Locate the existing audit file at `src/audit`
- Change the behaviour to match new requirements there (e.g. consuming a new CLI info exposed through `AuditState`)
- Ensure that tests and samples at `tests/` reflect changed behaviour accordingly (e.g. the confidence for finding has changed)
- Ensure that `docs/audits` reflect changed behaviour accordingly (e.g. an audit that is no longer pedantic)
- Open your Pull Request!

## Changing `zizmor`'s CLI

`zizmor` uses [clap] and [clap-derive] for its command-line interface.

`zizmor`'s documentation contains a copy of `zizmor --help`, which the CI
checks to ensure that it remains updated. If you change `zizmor`'s CLI,
you may need to [update the snippets](#updating-the-snippets).

[clap]: https://docs.rs/clap/latest/clap/index.html

[clap-derive]: https://docs.rs/clap/latest/clap/_derive/index.html

[insta's documentation]: https://insta.rs/docs/
