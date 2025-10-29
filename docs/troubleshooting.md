This page documents some of the common issues that people run into when
installing or using `zizmor`.

!!! tip

    Don't see your issue here? Let us know by opening an issue,
    and consider contributing it!

## Installation issues

### `cargo install zizmor` fails

If you install `zizmor` from crates.io using `cargo install zizmor`, you
may occasionally run into build errors that look like this:

```
error: failed to compile `zizmor vA.B.C`, intermediate artifacts can be found at `/SOME/TEMP/DIR`.
To reuse those artifacts with a future compilation, set the environment variable `CARGO_TARGET_DIR` to that path.

Caused by:
  failed to select a version for the requirement `SOMEDEP = "^X.Y.Z"`
    version X.Y.Z is yanked
  location searched: crates.io index
  required by package `zizmor vA.B.C`
```

This happens when one or more of `zizmor`'s dependencies has a yanked version
that the requested version of `zizmor` depends on.

If you run into this issue, you have two options:

1. Install `zizmor` from one of the binary distributions sources
   recommended in the [installation docs](./installation.md).
   **This is the recommended option.**
2. Use the `--locked` flag with `cargo install`:

    ```bash
    cargo install --locked zizmor
    ```

    This will force `cargo` to use the exact dependencies specified in
    `zizmor`'s `Cargo.lock` file, overriding any yanked versions.

## Runtime errors

### "can't access ORG/REPO: missing or you have no access"

When running `zizmor` in an online mode, you might see an error like this:

```
fatal: no audit was performed
ref-confusion failed on https://github.com/example/repoA/.github/workflows/ci.yml

Caused by:
    0: couldn't list branches for example/repoB
    1: can't access example/repoB: missing or you have no access
```

This error means that `zizmor` was able to retrieve your inputs,
but that those inputs include a _reference_ (such as a `#!yaml uses:` clause)
that `zizmor` cannot access.

A common scenario that causes this is as follows:

1. You enable `zizmor` in GitHub Actions on `example/repoA` (public _or_
   private), via @zizmorcore/zizmor-action. This action uses the default
   `secrets.GITHUB_TOKEN` to perform online audits.
2. `example/repoA` has a workflow that uses an action or reusable workflow
from a different private repository, e.g. `example/repoB`.

    For example:

    ```yaml title="example/repoA/.github/workflows/ci.yml"
    - uses: example/repoB/some-internal-action@v1.0.0
    ```

3. `zizmor` tries to access `example/repoB` to analyze the referenced
   action, but the `GITHUB_TOKEN` provided to the action only has access
   to `example/repoA`, not `example/repoB`.

This happens because the default `GITHUB_TOKEN` provided to GitHub Actions
does not have private repository access across different repositories,
by design. See orgs/community?46566 for additional information on this
behavior.

If you run into this issue, you have two options:

1. You can run `zizmor` in offline mode, e.g. with `--offline` or
   `#!yaml online-audits: false` in the action's settings. This will prevent
   all online accesses that could fail across repository boundaries,
   at the cost of disabling online audits.

2. You can provide a custom PAT to `zizmor` that provides read access to the
   necessary repositories. You can do this by creating a new fine-grained PAT
   with only the "Contents: read-only" permission for the relevant repositories.

    This PAT can then be provided to `zizmor` via `--gh-token` or `GITHUB_TOKEN`
    on the command line, or via the `token` input to the GitHub Action
    (once you've added your PAT to your repository secrets).

    For example, if you've configured the PAT as `ZIZMOR_GH_TOKEN`
    in your repository secrets, you could do:

    ```yaml title="example/repoA/.github/workflows/ci.yml" hl_lines="3"
    - uses: zizmorcore/zizmor-action@e673c3917a1aef3c65c972347ed84ccd013ecda4 # v0.2.0
      with:
        token: ${{ secrets.ZIZMOR_GH_TOKEN }}
    ```

    !!! important

        The **only** permission that `zizmor` itself needs is "Contents: read-only".

        You should always reduce the risk of token leakage by granting
        **only the minimum** necessary permissions.
