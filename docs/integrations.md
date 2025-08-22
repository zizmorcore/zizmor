## GitHub Actions

`zizmor` is designed to integrate with GitHub Actions.

The easiest way to use `zizmor` in GitHub Actions is
with @zizmorcore/zizmor-action. However, expert users or those who want
more fine-grained control over their integration can also use the
[Manual integration](#manual-integration) steps further below.

### Via @zizmorcore/zizmor-action *&#8203;*{.chip .chip-recommended}

To get started with @zizmorcore/zizmor-action, you can use the following
workflow skeleton:

```yaml title="zizmor.yml"
name: GitHub Actions Security Analysis with zizmor 🌈

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["**"]

permissions: {}

jobs:
  zizmor:
    name: Run zizmor 🌈
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read # only needed for private repos
      actions: read # only needed for private repos
    steps:
      - name: Checkout repository
        uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        with:
          persist-credentials: false

      - name: Run zizmor 🌈
        uses: zizmorcore/zizmor-action@5ca5fc7a4779c5263a3ffa0e1f693009994446d1 # v0.1.2
```

See the action's [`inputs` documentation][inputs-documentation] for
additional configuration options.

[inputs-documentation]: https://github.com/zizmorcore/zizmor-action#inputs

### Manual integration *&#8203;*{.chip .chip-expert}

If you don't want to use @zizmorcore/zizmor-action, you can always
use `zizmor` directly in your GitHub Actions workflows.

All of the same functionality is available, but you'll need to do a bit
more explicit scaffolding.

There are two main ways to manually integrate `zizmor` into your
GitHub Actions setup:

1. With `--format=sarif` via Advanced Security *&#8203;*{.chip .chip-recommended}
2. With `--format=github` via GitHub Annotations

=== "With Advanced Security *&#8203;*{.chip .chip-recommended}"

    GitHub's Advanced Security and [code scanning functionality] supports
    [SARIF], which `zizmor` can produce via `--format=sarif`.

    !!! important

        The workflow below performs a [SARIF] upload, which is available for public
        repositories and for GitHub Enterprise Cloud organizations that have
        [Advanced Security]. If neither of these apply to you, then you can
        use `--format=github` or adapt the `--format=json` or `--format=plain`
        output formats to your needs.

    ```yaml title="zizmor.yml"
    name: GitHub Actions Security Analysis with zizmor 🌈

    on:
      push:
        branches: ["main"]
      pull_request:
        branches: ["**"]

    permissions: {}

    jobs:
      zizmor:
        name: zizmor latest via PyPI
        runs-on: ubuntu-latest
        permissions:
          security-events: write # needed for SARIF uploads
          contents: read # only needed for private repos
          actions: read # only needed for private repos
        steps:
          - name: Checkout repository
            uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
            with:
              persist-credentials: false

          - name: Install the latest version of uv
            uses: astral-sh/setup-uv@d9e0f98d3fc6adb07d1e3d37f3043649ddad06a1 # v6.5.0

          - name: Run zizmor 🌈
            run: uvx zizmor --format=sarif . > results.sarif # (2)!
            env:
              GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} # (1)!

          - name: Upload SARIF file
            uses: github/codeql-action/upload-sarif@96f518a34f7a870018057716cc4d7a5c014bd61c # v3.29.10
            with:
              sarif_file: results.sarif
              category: zizmor
    ```

    1. Optional: Remove the `env:` block to only run `zizmor`'s offline audits.

    2. This installs the [zizmor package from PyPI], since it's pre-compiled
       and therefore completes much faster. You could instead compile `zizmor`
       within CI/CD with `cargo install zizmor`.

    For more inspiration, see `zizmor`'s own [repository workflow scan], as well
    as GitHub's example of [running ESLint] as a security workflow.

    !!! important

        When using `--format=sarif`, `zizmor` does not use its
        [exit codes](usage.md/#exit-codes) to signal the presence of findings. As a result,
        `zizmor` will always exit with code `0` even if findings are present,
        **unless** an internal error occurs during the audit.

        As a result of this, the `zizmor.yml` workflow itself will always
        succeed, resulting in a green checkmark in GitHub Actions.
        This should **not** be confused with a lack of findings.

        To prevent a branch from being merged with findings present, you can
        use GitHub's rulesets feature. For more information, see
        [About code scanning alerts - Pull request check failures for code scanning alerts].

=== "With annotations"

    A simpler (but more limited) way to use `zizmor` in GitHub Actions is
    with annotations, which `zizmor` can produce via `--format=github`.

    This is a good option if:

    1. You don't have Advanced Security (or you don't want to use it)
    1. You don't want to run `zizmor` with `security-events: write`

    ```yaml title="zizmor.yml"
    name: GitHub Actions Security Analysis with zizmor 🌈

    on:Use with
      push:
        branches: ["main"]
      pull_request:
        branches: ["**"]

    jobs:
      zizmor:
        name: zizmor latest via PyPI
        runs-on: ubuntu-latest
        permissions:
          contents: read # only needed for private repos
          actions: read # only needed for private repos
        steps:
          - name: Checkout repository
            uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0

          - name: Install the latest version of uv
            uses: astral-sh/setup-uv@d9e0f98d3fc6adb07d1e3d37f3043649ddad06a1 # v6.5.0

          - name: Run zizmor 🌈
            run: uvx zizmor --format=github . # (2)!
            env:
              GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} # (1)!
    ```

    1. Optional: Remove the `env:` block to only run `zizmor`'s offline audits.

    2. This installs the [zizmor package from PyPI], since it's pre-compiled
       and therefore completes much faster. You could instead compile `zizmor`
       within CI/CD with `cargo install zizmor`.

    !!! warning

        GitHub Actions has a limit of 10 annotations per step.

        If your `zizmor` run produces more than 10 findings, only the first 10 will
        be rendered; all subsequent findings will be logged in the actions log but
        **will not be rendered** as annotations.

[zizmor package from PyPI]: https://pypi.org/p/zizmor

[SARIF]: https://sarifweb.azurewebsites.net/

[Workflow Commands for GitHub Actions]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions

[code scanning functionality]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

[repository workflow scan]: https://github.com/zizmorcore/zizmor/blob/main/.github/workflows/zizmor.yml

[running ESLint]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github#example-workflow-that-runs-the-eslint-analysis-tool

[Advanced Security]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security

[About code scanning alerts - Pull request check failures for code scanning alerts]: https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-code-scanning-alerts#pull-request-check-failures-for-code-scanning-alerts

## IDEs *&#8203;*{.chip .chip-experimental} { #ides }

!!! warning

    `zizmor`'s LSP support is currently **experimental** and subject to
    breaking changes.

    You **will** encounter bugs while experimenting with it;
    please [file them]!

    [file them]: https://github.com/zizmorcore/zizmor/issues/new?template=bug-report.yml

!!! note

    IDE integration via LSP is available in `v1.11.0` and later.

`zizmor` can be integrated directly into your IDE or editor of choice,
giving you real-time feedback on your workflows and action definitions.

### Visual Studio Code

`zizmor` has an official extension for Visual Studio Code!

You can install it from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=zizmor.zizmor-vscode).
The extension does *not* come with `zizmor` itself, so you will need to
[separately install](./installation.md) `zizmor` in order for the extension
to work.

See @zizmorcore/zizmor-vscode for full installation and configuration instructions.

### Generic LSP integration

`zizmor` can be integrated with any editor or IDE that supports LSP.

To run `zizmor` in LSP mode, you can use the `--lsp` flag:

```bash
zizmor --lsp
```

In this mode, `zizmor` takes no other arguments and will communicate
with the editor over `stdin` and `stdout`. No other transports are supported.

## `pre-commit`

`zizmor` can be used with the [`pre-commit`](https://pre-commit.com/) framework.
To do so, add the following to your `.pre-commit-config.yaml` `#!yaml repos:` section:

```yaml
- repo: https://github.com/zizmorcore/zizmor-pre-commit
  rev: v1.12.1 # (1)!
  hooks:
  - id: zizmor
```

1. Don't forget to update this version to the latest `zizmor` release!

This will run `zizmor` on every commit.

!!! tip

    If you want to run `zizmor` only on specific files, you can use the
    `files` option. This setting is *optional*, as `zizmor` will
    scan the entire repository by default.

    See [`pre-commit`](https://pre-commit.com/) documentation for more
    information on how to configure `pre-commit`.

## Tab completion { #integration-tab-completion }

!!! note

    Tab completion is available in `v1.7.0` and later.

`zizmor` comes with built-in tab completion support for many popular
shells. It supports all of the shells supported by
[`clap_complete`](https://crates.io/crates/clap_complete),
which includes popular shells like `bash`, `zsh`, and `fish`.

To enable tab completion, you can use the `--completions=<shell>` flag
to emit a completion script for the specified shell. For example,
to enable tab completion for `bash`, you can run:

```bash
zizmor --completions=bash > ~/.bash_completion.d/zizmor # (1)!
```

1. The correct location of your completion script will depend on your
   shell and its configuration. Consult your shell's documentation
   for more information.
