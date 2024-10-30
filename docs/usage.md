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

`zizmor` is trivial to use within GitHub Actions; you can run it just like
you would locally.

`zizmor --format sarif` specifies [SARIF] as the output format, which GitHub's
code scanning feature also supports.

See [GitHub's documentation] for advice on how to integrate `zizmor`'s results
directly into a repository's scanning setup.

For a specific example, see `zizmor`'s own [repository workflow scan].
GitHub's example of [running ESLint] as a security workflow provides additional
relevant links.

[SARIF]: https://sarifweb.azurewebsites.net/

[GitHub's documentation]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

[repository workflow scan]: https://github.com/woodruffw/zizmor/blob/main/.github/workflows/zizmor.yml

[running ESLint]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github#example-workflow-that-runs-the-eslint-analysis-tool
