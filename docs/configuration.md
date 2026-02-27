---
description: zizmor's configuration file and configurable behaviors.
---

# Configuration

!!! note

    Configuration support was added in `v0.2.0`.

`zizmor` supports a small amount of configuration via [YAML] config files,
typically named `zizmor.yml` or `zizmor.yaml`.

[YAML]: https://learnxinyminutes.com/docs/yaml/

## Discovery

!!! note

    Configuration is *always* optional, and can always be skipped with
    `--no-config`. If `--no-config` is passed, no configuration is ever loaded.

!!! tip

    `zizmor`'s configuration discovery behavior changed significantly
    in `v1.13.0`. See the [release notes](./release-notes.md) for details.

`zizmor` discovers configuration files in two conceptually distinct ways:

1. **Global** discovery: when explicitly given a configuration file via
   `--config` or `ZIZMOR_CONFIG`, that file is used for **all** inputs.

    In other words: when a global configuration file is used no other
    configuration files are discovered or loaded, even if they're present
    according to the local discovery rules below.

2. **Local** discovery: when no global configuration file is given, `zizmor`
   looks for configuration files *for each given input*. The rules for this
   discovery are as follows:

    * File inputs (e.g. `zizmor path/to/workflow.yml`): `zizmor` performs
      directory discovery starting in the directory containing the given file.

    * Directory inputs (e.g. `zizmor .`): `zizmor` looks for a `zizmor.yml`
      or `zizmor.yaml` file in the given directory, the `.github` child directory,
      or any parent, up to the filesystem root or the first `.git` directory.
      
        !!! example
        
            Given an invocation like `zizmor ./repo/`, `zizmor` will attempt
            to discover configuration files in the following order:
            
            1. `./repo/.github/zizmor.yml`
            2. `./repo/.github/zizmor.yaml`
            3. `./repo/zizmor.yml`
            4. `./repo/zizmor.yaml`
            5. `./repo/../.github/zizmor.yml`
            6. `./repo/../.github/zizmor.yaml`
            7. ...and so on, until the filesystem root or a `.git/` directory is found.
            
            
            

        !!! note

            `zizmor .github/workflows/` is a special case: in this case,
            discovery starts in `.github/`, the parent of the given directory.

            This is done to avoid confusion between a `zizmor.yml` config
            file and a `zizmor.yml` workflow file.

    * Remote repository inputs (e.g. `zizmor owner/repo`): `zizmor` looks for
      a `zizmor.yml` or `.github/zizmor.yml` in the root of the repository.

In general, **most users will want to use local discovery**, which is the
default behavior. Global discovery only takes precedence when explicitly
requested with `--config` or `ZIZMOR_CONFIG`.

## Settings

### `rules.<id>.disable`

_Type_: `boolean`

Disables the audit entirely if `true`.

!!! important

    `rules.<id>.disable` was added in `v1.13.0`.

!!! warning

    For most users, disabling audits should be a **measure of last resort**.
    Disabled rules don't show up in ignored or suppressed finding counts,
    making it **very easy** to accidentally miss important new findings.

    Before disabling an audit entirely, consider one of the following
    alternatives:

    1. Ignoring specific findings via [`rules.<id>.ignore`](#rulesidignore).
    1. Changing your [persona](./usage.md#using-personas) to a less sensitive
       one. For example, consider removing `--persona=pedantic`
       or `--persona=auditor` if you're using one of those.

When set, inputs covered by this configuration file will not be
analyzed by the given audit.

For example, here is a configuration file that disables the
[`template-injection`](./audits.md#template-injection) audit:

```yaml title="zizmor.yml"
rules:
  template-injection:
    disable: true
```

Multiple audits can be disabled as well:

```yaml title="zizmor.yml"
rules:
  template-injection:
    disable: true
  unpinned-uses:
    disable: true
```

### `rules.<id>.ignore`

_Type_: `array`

Per-audit ignore rules.

Each member of `rules.<id>.ignore` is a *workflow rule*, formatted as follows:

```
filename.yml[:line[:column]]
```

where `filename.yml` is the base filename of the workflow, and `line` and
`column` are both optional 1-based values indicating the exact line-and-column
location to ignore. If one or both are absent, then the rule applies to the
entire file or entire line.

!!! important

    Composite action findings cannot be ignored via `zizmor.yml` currently,
    They can be ignored inline [with comments](./usage.md#ignoring-results).

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

### `rules.<id>.config`

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

The following patterns are supported, in order of specificity (most specific first).
When multiple patterns match a `#!yaml uses:` clause, the most specific pattern
takes precedence.

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

* `owner/prefix-*`, `owner/*-suffix`, `owner/prefix-*-suffix`: match repos where
  the repo name matches the given prefix and/or suffix. A single `*` acts as a
  wildcard matching any characters. No subpath is matched.

    !!! example

        `myorg/action-*` matches `#!yaml uses: myorg/action-checkout@v1`
        and `#!yaml uses: myorg/action-setup@v2`, but **not**
        `#!yaml uses: myorg/action-checkout/subdir@v1` (which has a subpath).

        `myorg/*-action` matches `#!yaml uses: myorg/checkout-action@v1`
        and `#!yaml uses: myorg/setup-action@v2`.

* `owner/prefix-*/*`: match repos where the repo name matches the prefix,
  including any subpath.

    !!! example

        `myorg/action-*/*` matches `#!yaml uses: myorg/action-checkout@v1`,
        `#!yaml uses: myorg/action-checkout/subdir@v1`, and
        `#!yaml uses: myorg/action-setup/init@v2`.

* `owner/prefix-*/subpath`, `owner/repo/subpath-*`, `owner/prefix-*/subpath-*`:
  match using wildcards in the repo name, subpath, or both.

    !!! example

        `github/codeql-*/init` matches `#!yaml uses: github/codeql-action/init@v3`
        and `#!yaml uses: github/codeql-bundle/init@v2`.

        `github/codeql-action/init-*` matches
        `#!yaml uses: github/codeql-action/init-db@v3` but **not**
        `#!yaml uses: github/codeql-action/upload@v3`.

        `myorg/action-*/init-*` matches `#!yaml uses: myorg/action-db/init-schema@v1`
        and `#!yaml uses: myorg/action-cache/init-store@v2`.

* `owner/prefix-*@ref`: match repos where the repo name matches the prefix,
  with an exact ref.

    !!! example

        `myorg/action-*@v1` matches `#!yaml uses: myorg/action-checkout@v1`
        but **not** `#!yaml uses: myorg/action-checkout@v2`.

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

!!! warning

    Multiple wildcards within a single segment are **not** supported.
    For example, `owner/foo-*-*` is invalid (two `*` characters in the repo segment).
