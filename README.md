# zizmor

A tool for finding security issues in GitHub Actions CI/CD setups.

> [!IMPORTANT]
> `zizmor` is currently in beta. You will encounter bugs; please file them!

Quick links:

* [Installation](#installation)
* [Quick start guide](#quickstart)
* [Usage](#usage)
  * [Online and offline use](#online-and-offline-use)
  * [Output formats](#output-formats)
  * [Audit documentation](./docs/audit/)
* [Integration](#integration)
  * [Use in GitHub Actions](#use-in-github-actions)
* [Technical details](#technical-details)
* [Contributing](#contributing)
* [The name?](#the-name)

Go right to the [Quickstart](#quickstart) or [Usage](#usage) to learn
how to use `zizmor` locally or in your CI/CD.

## Installation

You can install `zizmor` from <https://crates.io> via `cargo`:

```bash
cargo install zizmor
```

## Quickstart

You can run `zizmor` on any file(s) you have locally:

```bash
# audit a specific workflow
zizmor my-workflow.yml
# discovers .github/workflows/*.yml automatically
zizmor path/to/repo
```

By default, `zizmor` will emit a Rust-style human-friendly findings, e.g.:

```console
error[pull-request-target]: use of fundamentally insecure workflow trigger
  --> /home/william/devel/gha-hazmat/.github/workflows/pull-request-target.yml:20:1
   |
20 | / on:
21 | |   # NOT OK: pull_request_target should almost never be used
22 | |   pull_request_target:
   | |______________________^ triggers include pull_request_target, which is almost always used insecurely
   |

1 findings (0 unknown, 0 informational, 0 low, 0 medium, 1 high)
```

See the [Usage](#usage) for more examples, including examples of configuration.

## Usage

### Online and offline use

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

### Output formats

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

`zizmor` is trivial to use within GitHub Actions; you can run it just like
you would locally.

`zizmor` supports [SARIF] as an output format, which GitHub's code scanning
feature also supports. See [GitHub's documentation] for advice on how to
integrate `zizmor`'s results directly into a repository's scanning setup.

[SARIF]: https://sarifweb.azurewebsites.net/

[GitHub's documentation]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

## Technical details

## Contributing

See [our contributing guide!](./CONTRIBUTING.md)

## The name?

*[Now you can have beautiful clean workflows!]*

[Now you can have beautiful clean workflows!]: https://www.youtube.com/watch?v=ol7rxFCvpy8

[roadmap]: https://github.com/woodruffw/zizmor/issues/1
