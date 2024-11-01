# Usage Recipes

## Online and offline use

Some of `zizmor`'s audits require access to GitHub's API. `zizmor` will perform
online audits by default *if* the user has a `GH_TOKEN` specified
in their environment. If no `GH_TOKEN` is present, then `zizmor` will operate
in offline mode by default.

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

## Integration

### Use in GitHub Actions

`zizmor` is designed to integrate with GitHub Actions. In particular,
`zizmor --format sarif` specifies [SARIF] as the output format, which GitHub's
code scanning feature also supports.

You can integrate `zizmor` into your CI/CD however you please, but one
easy way to do it is with a workflow that connects to
[GitHub's code scanning functionality].

The following is an example of such a workflow:

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
