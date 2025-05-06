---
description: zizmor's configuration file and configurable behaviors.
---

# Configuration

!!! note

    Configuration support was added in `v0.2.0`.

`zizmor` supports a small amount of configuration via [YAML] config files,
typically named `zizmor.yml`.

[YAML]: https://learnxinyminutes.com/docs/yaml/

## Precedence

!!! note

    Configuration is *always* optional, and can always be disabled with
    `--no-config`. If `--no-config` is passed, no configuration is ever loaded.

`zizmor` will discover and load
configuration files in the following order of precedence:

1. Passed explicitly via `--config`, e.g. `--config my-config.yml`. When passed
   explicitly, the config file does *not* need to be named `zizmor.yml`.
1. `${CWD}/.github/zizmor.yml`
1. `${CWD}/zizmor.yml`

For the last two discovery methods, `${CWD}` is the current working directory,
i.e. the directory that `zizmor` was executed from.

Only one configuration file is ever loaded. In other words: if both
`${CWD}/.github/zizmor.yml` and `${CWD}/zizmor.yml` exist, only the former
will be loaded, per the precedence rules above.

## Settings

### `rules`

#### `rules.<id>`

##### `rules.<id>.ignore`

_Type_: `array`

Per-audit ignore rules, where `id` is the audit's name, e.g.
[`template-injection`](./audits.md#template-injection).

Each member of `rules.<id>.ignore` is a *workflow rule*, formatted as follows:

```
filename.yml:<line>?:<column>?
```

where `filename.yml` is the base filename of the workflow, and `line` and
`column` are both optional 1-based values indicating the exact line-and-column
location to ignore. If one or both are absent, then the rule applies to the
entire file or entire line.

!!! important

    Composite action findings cannot be ignored via `zizmor.yml` currently.

For example, here is a configuration file with two different audit ignore
rule groups:

```yaml title="zizmor.yml"
rules:
  template-injection:
    ignore:
      # ignore line 100 in ci.yml, any column
      - ci.yml:100
      # ignore all lines and columns in tests.yml
      - tests.yml
  use-trusted-publishing:
    ignore:
      # ignore line 12, column 10 on pypi.yml
      - pypi.yml:12:10
```

#### `rules.<id>.config`

_Type_: `object`

Per-audit configuration, where `id` is the audit's name, e.g.
[`unpinned-uses`](./audits.md#unpinned-uses).

Not all audits are configurable. See each audit's documentation for details.

## Patterns

Several audits support being configured with _patterns_, which can be used
to match things like `#!yaml uses:` clauses. These patterns share
common syntaxes, and are described here.

### Repository patterns

Repository patterns are used to match `#!yaml uses:` clauses.

The following patterns are supported, in order of specificity:

* `owner/repo/subpath@ref`: matches the exact repository, including
  subpath (if given) and ref. The subpath is optional.

    !!! example

        `github/codeql-action/init@v2` matches
        `#!yaml uses: github/codeql-action/init@v2`, but **not**
        `#!yaml uses: github/codeql-action/init@main`.

* `owner/repo/subpath`: match all `#!yaml uses:` clauses that are **exact** matches
  for the `owner/repo/subpath` pattern. The `subpath` can be an arbitrarily
  deep subpath, but is not optional. Any ref is matched.

    !!! example

        `github/codeql-action/init` matches
        `#!yaml uses: github/codeql-action/init@v2`,
        but **not** `#!yaml uses: github/codeql-action@v2`.

* `owner/repo`: match all `#!yaml uses:` clauses that are **exact** matches for the
  `owner/repo` pattern. Any ref is matched.

    !!! example

        `actions/cache` matches `#!yaml uses: actions/cache@v3`,
        but **not** `#!yaml uses: actions/cache/save@v3` or
        `#!yaml uses: actions/cache/restore@v3`.

* `owner/repo/*`: match all `#!yaml uses:` clauses that come from the given
  `owner/repo`. Any subpath or ref is matched.

    !!! example

        `github/codeql-action/*` matches
        `#!yaml uses: github/codeql-action/init@v2`,
        `#!yaml uses: github/codeql-action/upload-sarif@v2`, and
        `#!yaml uses: github/codeql-action@v2` itself.

* `owner/*`: match all `#!yaml uses:` clauses that have the given `owner`.
  Any repo, subpath, or ref is matched.

    !!! example

        `actions/*` matches both `#!yaml uses: actions/checkout@v4` and
        `#!yaml uses: actions/setup-node@v4`, but **not**
        `#!yaml uses: pypa/gh-action-pypi-publish@release/v1`.

* `*`: match all `#!yaml uses:` clauses.

    !!! example

        `*` matches `#!yaml uses: actions/checkout` and
        `#!yaml uses: pypa/gh-action-pypi-publish@release/v1`.
