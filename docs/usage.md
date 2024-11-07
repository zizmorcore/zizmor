# Usage Recipes

## Operating Modes

Some of `zizmor`'s audits require access to GitHub's API.
`zizmor` will perform online audits by default *if* the user has a `GH_TOKEN`
specified in their environment. If no `GH_TOKEN` is present, then `zizmor`
will operate in offline mode by default.

Both of these can be made explicit through their respective command-line flags:

```bash
# force offline, even if a GH_TOKEN is present
zizmor --offline workflow.yml

# passing a token explicitly will forcefully enable online mode
zizmor --gh-token ghp-... workflow.yml
```

## Output formats

`zizmor` always produces output on `stdout`. If a terminal is detected,
`zizmor` will default to a human-readable diagnostic output; if no terminal
is detected, `zizmor` will emit JSON.

Output formats can be controlled explicitly via the `--format` option:

```bash
# force diagnostic output, even if not a terminal
zizmor --format plain

# emit zizmor's own JSON format
zizmor --format json

# emit SARIF JSON instead of normal JSON
zizmor --format sarif
```

See [Integration](#integration) for suggestions on when to use each format.

## Exit codes

`zizmor` uses various exit codes to summarize the results of a run:

| Code | Meaning |
| ---- | ------- |
| 0    | Successful audit; no findings to report. |
| 1    | Error during audit; consult output. |
| 10   | One or more findings found; highest finding is "unknown" level. |
| 11   | One or more findings found; highest finding is "informational" level. |
| 12   | One or more findings found; highest finding is "low" level. |
| 13   | One or more findings found; highest finding is "medium" level. |
| 14   | One or more findings found; highest finding is "high" level. |

All other exit codes are currently reserved.

## Ignoring results

`zizmor`'s defaults are not always 100% right for every possible use case.

If you find that `zizmor` produces findings that aren't right for you
(and **aren't** false positives, which should be reported!), then you can
choose to *selectively ignore* results via a `zizmor.yml` configuration file.

Here's what a `zizmor.yml` file might look like:

```yaml title="zizmor.yml"
rules:
  template-injection:
    ignore:
      - safe.yml
      - somewhat-safe.yml:123
      - one-exact-spot.yml:123:456
```

Concretely, this `zizmor.yml` configuration declares three ignore rules,
all for the [`template-injection`](./audits.md#template-injection) audit:

1. Ignore all findings in `safe.yml`, regardless of line/column location
2. Ignore *any* findings in `somewhat-safe.yml` that occur on line 123
3. Ignore *one* finding in `one-exact-spot.yml` that occurs on line 123, column 456

More generally, the filename ignore syntax is `workflow.yml:line:col`, where
`line` and `col` are both optional and 1-based (meaning `foo.yml:1:1`
is the start of the file, not `foo.yml:0:0`).

To pass a configuration to `zizmor`, you can either place `zizmor.yml`
somewhere where `zizmor` [will discover it], or pass it explicitly via
the `--config` argument. With `--config`, the file can be named anything:

```bash
zizmor --config my-zizmor-config.yml /dir/to/audit
```

[will discover it]: ./configuration.md#discovery

See [Configuration: `rules.<id>.ignore`](./configuration.md#rulesidignore) for
more details on writing ignore rules.

## Integration

### Use in GitHub Actions

`zizmor` is designed to integrate with GitHub Actions. In particular,
`zizmor --format sarif` specifies [SARIF] as the output format, which GitHub's
code scanning feature uses.

You can integrate `zizmor` into your CI/CD however you please, but one
easy way to do it is with a workflow that connects to
[GitHub's code scanning functionality].

!!! important

    The workflow below performs a [SARIF] upload, which is available for public
    repositories and for GitHub Enterprise Cloud organizations that have
    [Advanced Security]. If neither of these apply to you, then you can
    adapt the workflow to emit JSON or diagnostic output via `--format json`
    or `--format plain` respectively.

```yaml title="zizmor.yml"
name: GitHub Actions Security Analysis with zizmor 🌈

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["**"]

jobs:
  zizmor:
    name: zizmor latest via Cargo
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      # required for workflows in private repositories
      contents: read
      actions: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Setup Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Get zizmor
        run: cargo install zizmor
      - name: Run zizmor 🌈
        run: zizmor --format sarif . > results.sarif
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} # (1)!
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: zizmor
```

1. Optional: Remove the `env:` block to only run `zizmor`'s offline audits.

For more inspiration, see `zizmor`'s own [repository workflow scan], as well
as  GitHub's example of [running ESLint] as a security workflow.

[SARIF]: https://sarifweb.azurewebsites.net/

[GitHub's code scanning functionality]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

[repository workflow scan]: https://github.com/woodruffw/zizmor/blob/main/.github/workflows/zizmor.yml

[running ESLint]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github#example-workflow-that-runs-the-eslint-analysis-tool

[Advanced Security]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security

### Use with `pre-commit`

`zizmor` can be used with the [`pre-commit`](https://pre-commit.com/) framework.
To do so, add the following to your `.pre-commit-config.yaml` `repos` section:

```yaml
-   repo: https://github.com/woodruffw/zizmor
    rev: v0.1.6 # (1)!
    hooks:
    - id: zizmor
```

1. Don't forget to update this version to the latest `zizmor` release!

This will run `zizmor` on every commit. If you want to run `zizmor` only on
specific files, you can use the `files` option:

```yaml
-   repo:
    ...
    hooks:
    - id: zizmor
      files: ^path/to/audit/.*\.yml$
```

See [`pre-commit`](https://pre-commit.com/) documentation for more information on how to configure
`pre-commit`.
