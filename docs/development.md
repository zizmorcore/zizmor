---
description: Development tasks and processes.
---

# Hacking on `zizmor`

!!! important

    This page contains information on specific development processes.
    For more general information on *how and what* to contribute to `zizmor`,
    see our [CONTRIBUTING.md].

[CONTRIBUTING.md]: https://github.com/zizmorcore/zizmor/blob/main/CONTRIBUTING.md

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
git clone https://github.com/zizmorcore/zizmor && cd zizmor
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

### Online tests

`zizmor` has some online tests that are ignored by default. These
tests are gated behind crate features:

- `gh-token-tests`: Enable online tests that use the GitHub API.
- `online-tests`: Enable all online tests, including `gh-token-tests`.

To run these successfully, you'll need to set the `GH_TOKEN` environment
variable and pass the `--features` flag to `cargo test`:

```bash
GH_TOKEN=$(gh auth token) cargo test --features online-tests
```

### TTY behavior tests

`zizmor` also has some tests that require a TTY to run. These tests are
gated behind the `tty-tests` feature. To run these tests, you'll need to
pass the `--features` flag to `cargo test`:

```bash
cargo test --features tty-tests
```

These tests use [`unbuffer`](https://linux.die.net/man/1/unbuffer)
from the [Expect project](https://core.tcl-lang.org/expect/index)
to provide a TTY-like environment.

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

# or, with online tests
GH_TOKEN=$(gh auth token) cargo insta test --review --features online-tests
```

After you accepted all snapshot differences, you can run insta with
`--force-update-snapshots` to make sure the meta information in the snapshot
files is up to date as well:

```bash
GH_TOKEN=$(gh auth token) cargo insta test --force-update-snapshots --features online-tests
```

See [insta's documentation] for more details.

## Benchmarking

`zizmor` currently uses [hyperfine](https://github.org/sharkdp/hyperfine)
for command-line benchmarking.

Benchmarks are stored in the top-level `bench/` directory, and can be
run locally with:

```bash
# run all benchmarks
make bench
```

We currently run benchmarks in the CI and report their results
to [Bencher](https://bencher.dev/). See
[our project page](https://bencher.dev/console/projects/zizmor/plots)
on Bencher for results and trends.

### Adding new benchmarks

`zizmor` currently orchestrates benchmarks with `bench/benchmark.py`,
which wraps `hyperfine` to add a planning phase.

Take a look at `bench/benchmarks.json` for the current benchmarks.
Observe that each benchmark tells `benchmark.py` how to retrieve its
input as well as provides a `stencil` that the benchmark runner will
expand to run the benchmark.

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

- All existing audits live in a Rust modules grouped under `crates/zizmor/src/audit` folder
- The expected behavior for all audits is defined by the `Audit` trait at `crates/zizmor/src/audit/mod.rs`
- The expected outcome of an executed audit is defined by the `Finding` struct at `crates/zizmor/src/finding/mod.rs`
- Any `Audit` implementation can have access to an `AuditState` instance, as per `crates/zizmor/src/state.rs`
- If an audit requires data from the GitHub API, there is a `Client` implementation at `crates/zizmor/src/github_api.rs`
- All the audits must be registered at `crates/zizmor/src/main.rs` according to the `register_audit!` macro

Last but not least, it's useful to run the following checks before opening a Pull Request:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

### Adding a new audit

!!! tip

    `Audit` has various default implementations that are useful if your
    audit only needs to look at individual jobs, steps, etc.

    For example, you may want to implement `Audit::audit_step` to
    audit each step individually rather than having to iterate from the workflow
    downwards with `Audit::audit`.

!!! tip

    When in doubt, refer to pre-existing audits for inspiration!

The general procedure for adding a new audit can be described as:

- Define a new file at `crates/zizmor/src/audit/my_new_audit.rs`
- Define a struct like `MyNewAudit`
- Use the `audit_meta!` macro to implement `AuditCore` for `MyNewAudit`
- Implement the `Audit` trait for `MyNewAudit`
    - You may want to use both the `AuditState` and `github_api::Client` to get the job done
- Assign the proper `location` when creating a `Finding`, grabbing it from the
  proper `Workflow`, `Job` or `Step` instance
- Add `MyNewAudit` to `AuditRegistry::default_audits` in `crates/zizmor/src/registry.rs`
- Add proper integration tests covering some scenarios to the snapshot tests
  in `crates/zizmor/tests/integration/snapshot.rs`
- Add proper docs for this new audit at `docs/audits`. Take care to add your new
  heading in alpha order relative to the other audit headings. Please include
  relevant public information about the underlying vulnerability
- Open your Pull Request!

#### Adding locations to an audit

Locations can be added to a finding via the `FindingBuilder::add_location`
method. Locations have a few different flavors that can be used in
different situations:

* "Primary" locations are subjectively the most important locations
  for a finding. In general, a finding should have exactly one primary location.
* "Related" locations are additional locations that are related to the
  finding, but not as important as the primary location. A finding can
  have multiple related locations.
* "Hidden" locations are used to mark a span as relevant to a finding,
  but are not shown in outputs like SARIF or the cargo-style "plain"
  output. These are useful marking spans as included in a finding e.g.
  so that `# zizmor: ignore` works in intuitive places.

In general, audit authors shouldn't need hidden locations at all.
They're only needed in specific cases where a finding's locations result
in "gaps" in the finding's spans, resulting in ignore comments not
working as expected.

### Changing an existing audit

The general procedure for changing an existing audit is:

- Locate the existing audit file at `crates/zizmor/src/audit`
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

## Repository maintenance tasks

### Dependabot

`zizmor` uses Dependabot to update dependencies in various ecosystems,
including Rust and GitHub Actions.

Dependencies are updated once weekly and in per-ecosystem batches to
keep PR volumes down.

### Updating actions documentation with `pinact`

`zizmor` uses [pinact] to update `uses:` clauses in its documentation.

You can install `pinact` locally via `brew`:

```bash
brew install pinact
```

Then, run `make pinact` to update the `uses:` clauses in the documentation.

[pinact]: https://github.com/suzuki-shunsuke/pinact
