# zizmor

A tool for finding security issues in GitHub Actions CI/CD setups.

At the moment, `zizmor` only supports workflow definitions, and only
detects a small subset of known issues. See the [roadmap]
for details on our plans.

## Usage

```bash
$ zizmor --help
Finds security issues in GitHub Actions workflows

Usage: zizmor [OPTIONS] <INPUT>

Arguments:
  <INPUT>  The workflow filename or directory to audit

Options:
  -p, --pedantic             Emit findings even when the context suggests an explicit security decision made by the user
  -o, --offline              Only perform audits that don't require network access
  -v, --verbose...           Increase logging verbosity
  -q, --quiet...             Decrease logging verbosity
      --gh-token <GH_TOKEN>  The GitHub API token to use [env: GH_TOKEN=]
      --format <FORMAT>      The output format to emit. By default, plain text will be emitted on an interactive terminal and JSON otherwise [possible values: plain, json, sarif]
  -h, --help                 Print help
```

## The name?

*[Now you can have beautiful clean workflows!]*

[Now you can have beautiful clean workflows!]: https://www.youtube.com/watch?v=ol7rxFCvpy8

[roadmap]: https://github.com/woodruffw/zizmor/issues/1
