---
description: Audit rules, examples, and remediations.
---

# Audit Rules

This page documents each of the audits currently implemented in `zizmor`.

See each audit's section for its scope, behavior, and other information.

Legend:

| Type     | Examples         | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action, Dependabot | Links to vulnerable examples | Added to `zizmor` in this version | The audit works with `--offline` | The audit supports auto-fixes when used in the `--fix` mode | The audit supports custom configuration |

## `anonymous-definition`

| Type            | Examples         | Introduced in | Works offline | Auto-fixes available | Configurable |
|-----------------|------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action | N/A              | v1.10.0       | ✅             | ❌                 | ❌            |

Detects workflows or action definitions that lack a `name:` field.

GitHub explicitly allows workflows to omit the `name:` field, and allows (but
doesn't document) the same for action definitions. When `name:` is omitted, the
workflow or action is rendered anonymously in the GitHub Actions UI, making it
harder to understand which definition is running.

!!! note

    This is a `--pedantic` only audit, due to a lack of security impact.

### Remediation

Add a `name:` field to your workflow or action.

=== "Before :warning:"

    ```yaml title="anonymous-definition.yml"
    on: push

    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo "Hello!"
    ```

=== "After :white_check_mark:"

    ```yaml title="anonymous-definition.yml" hl_lines="1"
    name: Echo Test
    on: push

    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo "Hello!"
    ```

## `archived-uses`

| Type     | Examples         | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action | [archived-uses.yml] | v1.19.0        | ✅             | ❌                 | ❌           |

[archived-uses.yml]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/archived-uses.yml


Detects `#!yaml uses:` clauses that reference [archived repositories].

[archived repositories]: https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories

Archival on GitHub makes a repository read-only, and indicates that the
repository is no longer maintained. Using actions or reusable workflows from archived
represents a supply chain risk:

- Unmaintained repositories are more likely to accumulate indirect vulnerabilties,
  including in any dependencies that have been vendored into JavaScript actions
  (or that are used indirectly through transitive dependencies that have gone
  stale).

- Any vulnerabilities discovered in the action or reusable workflow *itself*
  are unlikely to be fixed, since the repository is read-only.
  
Consequently, users are encouraged to avoid dependening on archived repositories
for actions or reusable workflows.

### Remediation

Depending on the archived repository's functionality, you may be able to:

- _Remove_ the action/reusable workflow entirely. Actions @actions-rs/cargo,
  for example, can be replaced by directly invoking the correct `#!bash cargo ...`
  command in a `#!yaml run:` step.
  
- _Replace_ the archived action/reusable workflow with a maintained alternative.
  For example, @actions/setup-ruby can be replaced with @ruby/setup-ruby.
  
!!! tip

    Many archived actions are thin wrappers around GitHub's REST and GraphQL
    APIs. In most cases, you can replace these actions with usage of the
    [`gh` CLI](https://cli.github.com/), which is pre-installed on GitHub-hosted
    runners.
    
    For more information, see [Using GitHub CLI in workflows].
    
    [Using GitHub CLI in workflows]: https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-github-cli

## `artipacked`

| Type     | Examples         | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|------------------|---------------|----------------|--------------------| -------------|
| Workflow  | [artipacked.yml] | v0.1.0        | ✅             | ✅               | ❌           |

[artipacked.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/artipacked.yml

Detects local filesystem `git` credential storage on GitHub Actions, as well as
potential avenues for unintentional persistence of credentials in artifacts.

By default, using @actions/checkout causes a credential to be persisted on disk.
Versions below v6.0.0 store the credential directly in the checked-out repo's
`.git/config`, while v6.0.0 and later store it under `$RUNNER_TEMP`.

Subsequent steps may accidentally publicly persist the credential, e.g. by
including it in a publicly accessible artifact via @actions/upload-artifact.

However, even without this, persisting the credential on disk is non-ideal
unless actually needed.

!!! note "Behavior change"

    Starting with zizmor v1.17.0, this audit produces lower-severity findings
    when v6.0.0 or higher of @actions/checkout is used. This reflects a
    change in v6.0.0's credential persistence behavior towards a more
    misuse-resistant location.
    
    See orgs/community?179107 for additional information.

Other resources:

* [ArtiPACKED: Hacking Giants Through a Race Condition in GitHub Actions Artifacts]

### Remediation

Unless needed for `git` operations, @actions/checkout should be used with
`#!yaml persist-credentials: false`.

If the persisted credential is needed, it should be made explicit
with `#!yaml persist-credentials: true`.

=== "Before :warning:"

    ```yaml title="artipacked.yml" hl_lines="7"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    ```

=== "After :white_check_mark:"

    ```yaml title="artipacked.yml" hl_lines="7-9"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
            with:
              persist-credentials: false
    ```


## `bot-conditions`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [bot-conditions.yml]   | v1.2.0      | ✅             | ✅                 | ❌  |

[bot-conditions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/bot-conditions.yml

Detects potentially spoofable bot conditions.

Many workflows allow trustworthy bots (such as [Dependabot](https://github.com/dependabot))
to bypass checks or otherwise perform privileged actions. This is often done
with a `github.actor` check, e.g.:

```yaml
if: github.actor == 'dependabot[bot]'
```

However, this condition is spoofable: `github.actor` refers to the *last* actor
to perform an "action" on the triggering context, and not necessarily
the actor actually causing the trigger. An attacker can take
advantage of this discrepancy to create a PR where the `HEAD` commit
has `github.actor == 'dependabot[bot]'` but the rest of the branch history
contains attacker-controlled code, bypassing the actor check.

Other resources:

* [GitHub Actions exploitations: Dependabot]

### Remediation

In general, checking a trigger's authenticity via `github.actor` is
insufficient. Instead, most users should use `github.event.pull_request.user.login`
or similar, since that context refers to the actor that *created* the Pull Request
rather than the last one to modify it.

More generally,
[GitHub's documentation recommends](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions)
not using `pull_request_target` for auto-merge workflows.

!!! example

    === "Before :warning:"

        ```yaml title="bot-conditions.yml" hl_lines="1 6"
        on: pull_request_target

        jobs:
          automerge:
            runs-on: ubuntu-latest
            if: github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
            steps:
              - run: gh pr merge --auto --merge "$PR_URL"
                env:
                  PR_URL: ${{ github.event.pull_request.html_url }}
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        ```

    === "After :white_check_mark:"

        ```yaml title="bot-conditions.yml" hl_lines="1 6"
        on: pull_request

        jobs:
          automerge:
            runs-on: ubuntu-latest
            if: github.event.pull_request.user.login == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
            steps:
              - run: gh pr merge --auto --merge "$PR_URL"
                env:
                  PR_URL: ${{ github.event.pull_request.html_url }}
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        ```


## `cache-poisoning`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [cache-poisoning.yml]   | v0.10.0       | ✅             | ✅               | ❌  |

[cache-poisoning.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/cache-poisoning.yml

Detects potential cache-poisoning scenarios in release workflows.

Caching and restoring build state is a process eased by utilities provided
by GitHub, in particular @actions/cache and its "save" and "restore"
sub-actions. In addition, many of the setup-like actions provided
by GitHub come with built-in caching functionality, like @actions/setup-node,
@actions/setup-java and others.

Furthermore, there are many examples of community-driven Actions with built-in
caching functionality, like @ruby/setup-ruby, @astral-sh/setup-uv,
@Swatinem/rust-cache. In general, most of them build on top of @actions/toolkit
for the sake of easily integrate with GitHub cache server at Workflow runtime.

This vulnerability happens when release workflows leverage build state cached
from previous workflow executions, in general on top of the aforementioned
actions or  similar ones. The publication of artifacts usually happens driven
by trigger events like `release` or events with path filters like `push`
(e.g. for tags).

In such scenarios, an attacker with access to a valid `GITHUB_TOKEN` can use it
to poison the repository's GitHub Actions caches. That compounds with the
default behavior of @actions/toolkit during cache restorations, allowing an
attacker to retrieve payloads from poisoned cache entries, hence achieving code
execution at Workflow runtime, potentially compromising ready-to-publish
artifacts.

Other resources:

* [The Monsters in Your Build Cache – GitHub Actions Cache Poisoning]
* [Cacheract: The Monster in your Build Cache]

### Remediation

In general, you should avoid using previously cached CI state within workflows
intended to publish build artifacts:

* Remove cache-aware actions like @actions/cache from workflows that produce
  releases, *or*
* Disable cache-aware actions with an `#!yaml if:` condition based on the trigger at
  the step level, *or*
* Set an action-specific input to disable cache restoration when appropriate,
  such as `lookup-only` in @Swatinem/rust-cache.

## `concurrency-limits`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow | [concurrency-limits/]   | v1.16.0       | ✅             | ❌                 | ❌  |

[concurrency-limits/]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/concurrency-limits/

Detects insufficient concurrency limits in workflows.

By default, GitHub Actions allows multiple instances of the same workflow to run
concurrently, even when the new runs fully supersede the old. This can be a
resource waste vector for attackers, particularly on billed runners. Separately,
it can be a source of subtle race conditions when attempting to locate artifacts
by workflow and job identifiers, rather than run IDs.

Other resources:

* [Guidelines on green software practices for GitHub Actions CI workflows]

### Remediation

Include a `concurrency` setting in your workflow that sets the
`cancel-in-progress` option either to `true` or to an expression that will be
true in most cases. Specifying `false` would allow separate instances of the
workflows to run concurrently, whereas `true` will imply that running jobs are
cancelled as soon as the workflow is re-triggered.

!!! example

    ```yaml title="cancel-true.yml"
    concurrency:
      group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
      cancel-in-progress: true
    ```

## `dangerous-triggers`

| Type     | Examples                  | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|---------------------------|---------------|----------------|--------------------|--------------|
| Workflow  | [pull-request-target.yml] | v0.1.0        | ✅             | ❌                 | ❌         |

[pull-request-target.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pull-request-target.yml

Detects fundamentally dangerous GitHub Actions workflow triggers.

Many of GitHub's workflow triggers are difficult to use securely.
This audit checks for some of the biggest offenders:

* `pull_request_target`
* `workflow_run`

These triggers are dangerous because they run in the context of the
*target repository* rather than the *fork repository*, while also being
typically triggerable by the latter. This can lead to attacker controlled
code execution or unexpected action runs with context controlled by a malicious
fork.

Many online resources suggest that `pull_request_target` and other
dangerous triggers can be used securely by ensuring that the PR's code
is not executed, but this is **not true**: an attacker can often find
ways to execute code in the context of the target repository, even if
the workflow doesn't explicitly run any code from the PR. Common vectors
for this include argument injection (e.g. with `xargs`), environment injection
(e.g. `LD_PRELOAD`), and local file inclusion (e.g. relinking files
to the runner's credentials file or similar).

Other resources:

* [Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests]
* [Keeping your GitHub Actions and workflows secure Part 4: New vulnerability patterns and mitigation strategies]
* [Vulnerable GitHub Actions Workflows Part 1: Privilege Escalation Inside Your CI/CD Pipeline]
* [Pwning the Entire Nix Ecosystem]

### Remediation

The use of dangerous triggers can be difficult to remediate, since they don't
always have an immediate replacement.

Replacing a dangerous trigger with a safer one (or keeping the dangerous
trigger, but eliminating the risk of code execution) requires case-by-case
consideration.

Some general pointers:

* Replace `workflow_run` triggers with `workflow_call`: this will require
  re-tooling the workflow to be a [reusable workflow].
* Replace `pull_request_target` with `pull_request`, unless you *absolutely*
  need repository write permissions (e.g. to leave a comment or make
  other changes to the upstream repo).

    `pull_request_target` is only needed to perform privileged actions on
    pull requests from external forks. If you only expect pull requests from
    branches within the same repository, or if you are fine with some functionality
    not working for external pull requests, prefer `pull_request`.

* Automation for Dependabot pull requests can be implemented using `pull_request`,
  but requires setting dedicated [Dependabot secrets]
  and [explicitly specifying needed permissions].

* **Never** run PR-controlled code in the context of a
  `pull_request_target`-triggered workflow.

* Avoid attacker-controllable flows into `GITHUB_ENV` in both `workflow_run`
  and `pull_request_target` workflows, since these can lead to arbitrary
  code execution.

* If you really have to use `pull_request_target`, consider adding a
  [branch filter] to only run the workflow for matching target branches.
  `pull_request_target` uses the workflow file of the target branch of the pull
  request, therefore restricting the target branches reduces the risk of
  a vulnerable `pull_request_target` in a stale or abandoned branch.

* If you really have to use `pull_request_target`, consider adding a
  `github.repository == ...` check to only run for your repository but not in
  forks of your repository (in case the user has enabled Actions there). This
  avoids exposing forks to danger in case you fix a vulnerability in the
  workflow but the fork still contains an old vulnerable version.

    !!! important

        Checking `github.repository == ...` is **not** effective on
        `workflow_run`, since a `workflow_run` **always** runs in the context of
        the target repository.

[reusable workflow]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows

## `dependabot-cooldown`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Dependabot  | [dependabot-cooldown/]       | v1.15.0       | ✅             | ✅                 | ✅  |

[dependabot-cooldown/]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/dependabot-cooldown/

Detects missing or insufficient `cooldown` settings in Dependabot configuration
files.

!!! note
    Some package ecosystems do not support cooldown configuration in Dependabot.
    This audit will not produce findings for those ecosystems.

By default, Dependabot does not perform any "cooldown" on dependency updates.
In other words, a regularly scheduled Dependabot run may perform an update on a
dependency that was just released moments before the run began. This presents
both stability and supply-chain security risks:

* **Stability**: updating to the newest version of a dependency immediately after its
  release increases the risk of breakage, since new releases may contain
  regressions or other issues that other users have not yet discovered.
* **Supply-chain security**: package compromises are frequently *opportunistic*,
  meaning that the attacker expects to have their compromised version taken
  down by the packaging ecosystem relatively quickly. Updating immediately to
  a newly released version increases the risk of automatically pulling in
  a compromised version before it can be taken down.

To mitigate these risks, Dependabot supports per-updater `cooldown` settings.
However, these settings are not enabled by default; users **must** explicitly
enable them.

Other resources:

* [Dependabot options reference - `cooldown`](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#cooldown-)
* [We should all be using Dependency cooldowns](https://blog.yossarian.net/2025/11/21/We-should-all-be-using-dependency-cooldowns)

### Configuration

#### `rules.dependabot-cooldown.config.days`

Type: number

The `rules.dependabot-cooldown.config.days` setting controls the minimum acceptable
`default-days` value for Dependabot's `cooldown` setting. Settings beneath this
value will produce findings.

The default value is `7`.

### Remediation

In general, you should enable `cooldown` for all updaters.

!!! example

    === "Before :warning:"

        ```yaml title="dependabot.yml"
        version: 2
        updates:
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "daily"
        ```

    === "After :white_check_mark:"

        ```yaml title="dependabot.yml" hl_lines="7-8"
        version: 2
        updates:
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "daily"
            cooldown:
              default-days: 7
        ```

## `dependabot-execution`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Dependabot  | [dependabot-execution/]       | v1.15.0       | ✅             | ✅                | ❌  |

[dependabot-execution/]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/dependabot-execution/

Detects usages of `insecure-external-code-execution` in Dependabot configuration
files.

By default, Dependabot does not execute code from dependency manifests
during updates. However, users can opt in to this behavior by setting
`#!yaml insecure-external-code-execution: allow` in their Dependabot
configuration.

Some ecosystems (including but not limited to Python, Ruby, and JavaScript)
depend partially on code execution during dependency resolution.

In these ecosystems fully avoiding build-time code execution is impossible.
However, build-time code execution *should* be avoided in automated dependency
update contexts like Dependabot, since a compromised dependency may be able
to obtain credentials or private source access automatically through
a Dependabot job.

Other resources:

* [`insecure-external-code-execution` documentation](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#insecure-external-code-execution--)
* [Dependabot: Allowing external code execution](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/configuring-access-to-private-registries-for-dependabot#allowing-external-code-execution)

### Remediation

In general, automatic dependency updates should be limited to only updates
that do not require code execution at resolution time.

In practice, this means that users should set
`#!yaml insecure-external-code-execution: deny` **or** omit the field entirely
(and rely on the default of `deny`).

!!! example

    === "Before :warning:"

        ```yaml title="dependabot.yml" hl_lines="7"
        version: 2
        updates:
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "daily"
            insecure-external-code-execution: allow
        ```

    === "After :white_check_mark:"

        ```yaml title="dependabot.yml" hl_lines="7"
        version: 2
        updates:
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "daily"
            insecure-external-code-execution: deny
        ```

## `excessive-permissions`

| Type     | Examples                    | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-----------------------------|---------------|----------------|--------------------|---------------|
| Workflow  | [excessive-permissions.yml] | v0.1.0        | ✅             | ❌                 | ❌         |

[excessive-permissions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/excessive-permissions.yml

Detects excessive permissions in workflows, both at the workflow level and
individual job levels.

Users frequently over-scope their workflow and job permissions,
or set broad workflow-level permissions without realizing that
all jobs inherit those permissions.

Furthermore, users often don't realize that the
[*default* `GITHUB_TOKEN` permissions can be very broad](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token),
meaning that workflows that don't configure any permissions at all can *still*
provide excessive credentials to their individual jobs.

### Remediation

In general, permissions should be declared as minimally as possible, and
as close to their usage site as possible.

In practice, this means that workflows should almost always set
`#!yaml permissions: {}` at the workflow level to disable all permissions
by default, and then set specific job-level permissions as needed.

!!! tip

    @GitHubSecurityLab/actions-permissions can help find the minimally required
    permissions.

!!! example

    === "Before :warning:"

        ```yaml title="excessive-permissions.yml" hl_lines="8-9"
        on:
          release:
            types:
              - published

        name: release

        permissions:
          id-token: write # trusted publishing + attestations

        jobs:
          build:
            name: Build distributions 📦
            runs-on: ubuntu-latest
            steps:
              - # omitted for brevity

          publish:
            name: Publish Python 🐍 distributions 📦 to PyPI
            runs-on: ubuntu-latest
            needs: [build]

            steps:
              - name: Download distributions
                uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
                with:
                  name: distributions
                  path: dist/

              - name: publish
                uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc # v1.12.4
        ```

    === "After :white_check_mark:"

        ```yaml title="excessive-permissions.yml" hl_lines="8 21-22"
        on:
          release:
            types:
              - published

        name: release

        permissions: {}

        jobs:
          build:
            name: Build distributions 📦
            runs-on: ubuntu-latest
            steps:
              - # omitted for brevity

          publish:
            name: Publish Python 🐍 distributions 📦 to PyPI
            runs-on: ubuntu-latest
            needs: [build]
            permissions:
              id-token: write # trusted publishing + attestations

            steps:
              - name: Download distributions
                uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
                with:
                  name: distributions
                  path: dist/

              - name: publish
                uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc # v1.12.4
        ```

## `forbidden-uses`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | N/A            | v1.6.0        | ✅             | ❌                |  ✅ |

An *opt-in* audit for denylisting/allowlisting specific `#!yaml uses:` clauses.
This is not enabled by default; you must
[configure it](#forbidden-uses-configuration) to use it.

!!! warning

    This audit comes with several limitations that are important to understand:

    * This audit is *opt-in*. You must configure it to use it; it
      **does nothing** by default.
    * This audit (currently) operates on *repository* `#!yaml uses:` clauses,
      e.g. `#!yaml uses: actions/checkout@v4`. It does not operate on Docker
      `#!yaml uses:` clauses, e.g. `#!yaml uses: docker://ubuntu:24.04`. This limitation
      may be lifted in the future.
    * This audit operates on `#!yaml uses:` clauses *as they appear* in the workflow
      and action files. In other words, in *cannot* detect
      [impostor commits](#impostor-commit) or indirect usage of actions
      via manual `git clone` and local path usage.

### Configuration { #forbidden-uses-configuration }

#### `rules.forbidden-uses.config.<allow|deny>`

_Type_: `list`

The `forbidden-uses` audit operates on either an allowlist or denylist
basis:

* In allowlist mode, only the listed `#!yaml uses:` patterns are allowed. All
  non-matching `#!yaml uses:` clauses result in a finding.

    Intended use case: only allowing "known good" actions to be used,
    and forbidding everything else.

* In denylist mode, only the listed `#!yaml uses:` patterns are disallowed. All
  matching `#!yaml uses:` clauses result in a finding.

    Intended use case: permitting all `#!yaml uses:` by default, but explicitly
    forbidding "known bad" actions.

Regardless of the mode, the patterns used are repository patterns.
See [Configuration - Repository patterns](./configuration.md#repository-patterns)
for details.

!!! example

    The following configuration would allow only actions owned by
    the @actions organization, plus any actions defined in @github/codeql-action:

    ```yaml title="zizmor.yml"
    rules:
      forbidden-uses:
        config:
          allow:
            - actions/*
            - github/codeql-action/*
    ```

!!! example

    The following would allow all actions except for those in the
    @actions organization or defined in @github/codeql-action:

    ```yaml title="zizmor.yml"
    rules:
      forbidden-uses:
        config:
          deny:
            - actions/*
            - github/codeql-action/*
    ```

### Remediation

Either remove the offending `#!yaml uses:` clause or, if intended, add it to
your [configuration](#forbidden-uses-configuration).

## `github-env`

| Type     | Examples           | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|--------------------|---------------|----------------|--------------------| --------------|
| Workflow, Action  | [github-env.yml]   | v0.6.0        | ✅             | ❌       | ❌  |

[github-env.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/github-env.yml

Detects dangerous writes to the `GITHUB_ENV` and `GITHUB_PATH` environment variables.

When used in workflows with dangerous triggers (such as `pull_request_target` and `workflow_run`),
`GITHUB_ENV` and `GITHUB_PATH` can be an arbitrary code execution risk:

* If the attacker is able to set arbitrary variables or variable contents via
  `GITHUB_ENV`, they may be able to set `LD_PRELOAD` or otherwise induce code
  execution implicitly within subsequent steps.
* If the attacker is able to add an arbitrary directory to the `$PATH` via
  `GITHUB_PATH`, they may be able to execute arbitrary code by shadowing
  ordinary system executables (such as `ssh`).

Other resources:

* [GitHub Actions exploitation: environment manipulation]
* [GHSL-2024-177: Environment Variable injection in an Actions workflow of Litestar]
* [Google & Apache Found Vulnerable to GitHub Environment Injection]
* [Hacking with Environment Variables]

### Remediation

In general, you should avoid modifying `GITHUB_ENV` and `GITHUB_PATH` within
sensitive workflows that are attacker-triggered, like `pull_request_target`.

If you absolutely must use `GITHUB_ENV` or `GITHUB_PATH`, avoid passing
attacker-controlled values into either. Stick with literal strings and
values computed solely from trusted sources.

If you need to pass state between steps, consider using `GITHUB_OUTPUT` instead.


## `hardcoded-container-credentials`

| Type     | Examples                    | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-----------------------------|---------------|----------------|--------------------|---------------|
| Workflow  | [hardcoded-credentials.yml] | v0.1.0        | ✅             | ❌               | ❌         |

[hardcoded-credentials.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml

Detects Docker credentials (usernames and passwords) hardcoded in various places
within workflows.

### Remediation

Use [encrypted secrets] instead of hardcoded credentials.

[encrypted secrets]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions

!!! example

    === "Before :warning:"

        ```yaml title="hardcoded-container-credentials.yml" hl_lines="11 17"
        on:
          push:

        jobs:
          test:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example
              credentials:
                username: user
                password: hackme
            services:
              service-1:
                image: fake.example.com/anotherexample
                credentials:
                  username: user
                  password: hackme
            steps:
              - run: echo 'hello!'
        ```

    === "After :white_check_mark:"

        ```yaml title="hardcoded-container-credentials.yml" hl_lines="11 17"
        on:
          push:

        jobs:
          test:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example
              credentials:
                username: user
                password: ${{ secrets.REGISTRY_PASSWORD }}
            services:
              service-1:
                image: fake.example.com/anotherexample
                credentials:
                  username: user
                  password: ${{ secrets.REGISTRY_PASSWORD }} # (1)!
            steps:
              - run: echo 'hello!'
        ```

        1. This may or may not be the same credential as above, depending on your configuration.


## `impostor-commit`

| Type     | Examples              | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-----------------------|---------------|----------------|--------------------|---------------|
| Workflow, Action  | [impostor-commit.yml] | v0.1.0        | ❌             | ✅                 | ❌  |

[impostor-commit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml

Detects commits within a repository action's network that are not present on
the repository itself, also known as "impostor" commits.

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

GitHub's network-of-forks design can be used to obscure a commit's true origin
in a fully-pinned `#!yaml uses:` workflow reference. This can be used by an attacker
to surreptitiously introduce a backdoored action into a victim's workflows(s).

A notable historical example of this is github/dmca@565ece486c7c1652754d7b6d2b5ed9cb4097f9d5,
which appears to be on @github/dmca is but really on a fork (with an impersonated
commit author).

Other resources:

* [What the fork? Imposter commits in GitHub Actions and CI/CD]

### Remediation

Impostor commits are **visually indistinguishable** from normal best-practice
hash-pinned actions.

Always **carefully review** external PRs that add or change
hash-pinned actions by consulting the claimant repository and confirming that
the commit actually exists within it.

The only remediation, once discovered, is to replace the impostor commit
within an authentic commit (or an authentic tag/branch reference).

## `insecure-commands`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [insecure-commands.yml] | v0.5.0        | ✅             | ✅       | ❌  |

[insecure-commands.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/insecure-commands.yml

Detects opt-in for executing insecure workflow commands.

Workflow commands (like `::set-env` and `::add-path`)
[were deprecated by GitHub] in 2020 due to their inherent weaknesses
(e.g., allowing any command with the ability to emit to `stdout`
to inject environment variables and therefore obtain code execution).

However, users can explicitly re-enable them by setting the
`ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable at the workflow,
job, or step level.

Other resources:

* [Semgrep audit]

### Remediation

In general, users should use [GitHub Actions environment files]
(like `GITHUB_PATH` and `GITHUB_OUTPUT`) instead of using workflow commands.

!!! example

    === "Before :warning:"

        ```yaml title="insecure-commands" hl_lines="3"
        - name: Setup my-bin
          run: |
            echo "::add-path::$HOME/.local/my-bin"
          env:
            ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        ```

    === "After :white_check_mark:"

        ```yaml title="insecure-commands" hl_lines="3"
        - name: Setup my-bin
          run: |
            echo "$HOME/.local/my-bin" >> "$GITHUB_PATH"
        ```

## `known-vulnerable-actions`

| Type             | Examples                       | Introduced in | Works offline  | Auto-fixes available | Configurable |
|------------------|--------------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action | [known-vulnerable-actions.yml] | v0.1.0        | ❌             | ✅                 | ❌  |

[known-vulnerable-actions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/known-vulnerable-actions.yml

Detects actions with known, publicly disclosed vulnerabilities that are tracked
in the [GitHub Advisories database]. Examples of commonly disclosed
vulnerabilities in GitHub Actions include [credential disclosure] and code
injection via [template injection].

[GitHub Advisories database]: https://github.com/advisories

[credential disclosure]: #artipacked

[template injection]: #template-injection

### Remediation

If the vulnerability is applicable to your use: upgrade to a fixed version of
the action if one is available, or remove the action's usage entirely.

## `misfeature`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | N/A   | v1.21.0        | ✅             | ✅                 | ❌  |

Checks for usages of GitHub Actions features that are considered "misfeatures."

Misfeatures include:

* Use of the `pip-install` input on @actions/setup-python. This input injects
  dependencies directly into a global (user or system-level) environment,
  which is both difficult to audit and is likely to cause broken
  resolutions.
  
    !!! note
  
        See actions/setup-python#1201 and [PEP 668](https://peps.python.org/pep-0668/)
        for additional context.

* Use of the Windows CMD shell, i.e. `#!yaml shell: cmd` and similar.
  The CMD shell has no formal grammar, making it difficult to accurately
  analyze. Moreover, it has not been the default shell on Windows runners
  since 2019.

    !!! note
  
        Prior to `v1.21.0`, this check was performed by the [`obfuscation`](#obfuscation) audit.

* Use of non-"well-known" shells, i.e. shells other than those
  [documented by GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#defaultsrunshell).
  These shells may not be available on all runners, and are generally
  impossible to analyze with any confidence.

    !!! note

        These findings are only shown when running with the "auditor"
        [persona](./usage.md#using-personas), as they can be very noisy.

### Remediation

Address the misfeature by removing or replacing its usage.

!!! example

    === "Before :warning:"

        ```yaml title="misfeature.yml" hl_lines="8"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Setup Python
                uses: actions/setup-python@v6
                with:
                  pip-install: '.[dev]'
        ```

    === "After :white_check_mark:"

        ```yaml title="misfeature.yml" hl_lines="9-11"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Setup Python
                uses: actions/setup-python@v6
              
              - name: Install package
                run: |
                  python -m venv .env
                  ./.env/bin/pip install .[dev]
        ```

## `obfuscation`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | N/A   | v1.7.0        | ✅             | ✅                 | ❌  |

Checks for obfuscated usages of GitHub Actions features.

This audit primarily serves to "unstick" other audits, which may fail to detect
functioning but obfuscated usages of GitHub Actions features.

This audit detects a variety of obfuscated usages, including:

* Obfuscated paths within `#!yaml uses:` clauses, including redundant `/`
  separators and uses of `.` or `..` in path segments.
* Obfuscated GitHub expressions, including no-op patterns like
  `fromJSON(toJSON(...))` and calls to `format(...)` where all
  arguments are literal values.

!!! note

    Prior to `v1.21.1`, this audit also detected uses of the Windows CMD shell.
    This check has been moved to the [`misfeature`](#misfeature) audit.

### Remediation

Address the source of obfuscation by simplifying the expression,
`#!yaml uses:` clause, or other obfuscated feature.

!!! example

    === "Before :warning:"

        ```yaml title="obfuscation.yml" hl_lines="8"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
                with:
                  repository: ${{ format('{0}/{1}', 'octocat', 'hello-world') }}
        ```

    === "After :white_check_mark:"

        ```yaml title="obfuscation.yml" hl_lines="8"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
                with:
                  repository: octocat/hello-world
        ```


## `overprovisioned-secrets`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [overprovisioned-secrets.yml]   | v1.3.0      | ✅     | ❌         | ❌  |

[overprovisioned-secrets.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/overprovisioned-secrets.yml

Detects excessive sharing of the `secrets` context.

Typically, users access the `secrets` context via its individual members:

```yaml
env:
  SECRET_ONE: ${{ secrets.SECRET_ONE }}
  SECRET_TWO: ${{ secrets.SECRET_TWO }}
```

This allows the Actions runner to only expose the secrets actually used by
the workflow to the job environment.

However, if the user instead accesses the *entire* `secrets` context:

```yaml
env:
  SECRETS: ${{ toJson(secrets) }}
```

...then the entire `secrets` context is exposed to the runner, even if
only a single secret is actually needed.

### Remediation

In general, users should avoid loading the entire `secrets` context.
Secrets should be accessed individually by name.

!!! example

    === "Before :warning:"

        ```yaml title="overprovisioned.yml" hl_lines="7"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
                env:
                  SECRETS: ${{ toJSON(secrets) }}
        ```

    === "After :white_check_mark:"

        ```yaml title="overprovisioned.yml" hl_lines="7-8"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
                env:
                  SECRET_ONE: ${{ secrets.SECRET_ONE }}
                  SECRET_TWO: ${{ secrets.SECRET_TWO }}
        ```


## `ref-confusion`

| Type             | Examples            | Introduced in | Works offline  | Auto-fixes available | Configurable |
|------------------|---------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action | [ref-confusion.yml] | v0.1.0        | ❌             | ❌                 | ❌  |


[ref-confusion.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml

Detects actions that are pinned to confusable symbolic refs (i.e. branches
or tags).

Like with [impostor commits], actions that are used with a symbolic ref
in their `#!yaml uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: #impostor-commit

### Remediation

Switch to hash-pinned actions.

## `ref-version-mismatch`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [ref-version-mismatch.yml] | v1.14.0       | ✅             | ✅                 | ❌  |

[ref-version-mismatch.yml]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/ref-version-mismatch.yml

Detects `#!yaml uses:` clauses where the action is hash-pinned, but the associated
tag comment (used by tools like Dependabot) does not match the pinned commit.

This can happen innocently when a user (or automation) updates a
hash-pinned `#!yaml uses:` clause to a newer commit, but fails to update the
associated tag comment. When this happens, tools like Dependabot will silently
ignore the comment instead of refreshing it on subsequent updates, making
it progressively more out-of-date over time.

### Remediation

Update the tag comment to match the pinned commit. Tools like
@suzuki-shunsuke/pinact may be able to do this automatically for you.

!!! example

    === "Before :warning:"

        ```yaml title="ref-version-mismatch.yml" hl_lines="5"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v4.2.2
        ```

    === "After :white_check_mark:"

        ```yaml title="ref-version-mismatch.yml" hl_lines="5"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        ```

## `secrets-inherit`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [secrets-inherit.yml]   | v1.1.0      | ✅             | ❌                 | ❌  |

[secrets-inherit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/secrets-inherit.yml

Detects excessive secret inheritance between calling workflows and reusable
(called) workflows.

[Reusable workflows] can be given secrets by their calling workflow either
explicitly, or in a blanket fashion with `#!yaml secrets: inherit`. The latter
should almost never be used, as it makes it violates the
[Principle of Least Authority] and makes it impossible to determine which exact
secrets a reusable workflow was executed with.

### Remediation

In general, `#!yaml secrets: inherit` should be replaced with a `#!yaml secrets:` block
that explicitly forwards each secret actually needed by the reusable workflow.

!!! example

    === "Before :warning:"

        ```yaml title="reusable.yml" hl_lines="4"
        jobs:
          pass-secrets-to-workflow:
            uses: ./.github/workflows/called-workflow.yml
            secrets: inherit
        ```

    === "After :white_check_mark:"

        ```yaml title="reusable.yml" hl_lines="4-6"
        jobs:
          pass-secrets-to-workflow:
            uses: ./.github/workflows/called-workflow.yml
            secrets:
              forward-me: ${{ secrets.forward-me }}
              me-too: ${{ secrets.me-too }}
        ```

## `secrets-outside-env`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [secrets-outside-env.yml]   | v1.23.0      | ✅             | ❌                 | ❌  |

[secrets-outside-env.yml]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/secrets-outside-env.yml

Detects usage of the `secrets` context in jobs without a dedicated environment.

GitHub Actions allows secrets to be configured at the organization, repository,
or environment level. The first two of these expose the configured secrets
to an entire repository (or repositories), while the last one allows secrets to be
scoped to specific conditions *within* a repository, as defined by the
environment's [protection rules].

[protection rules]: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments#creating-an-environment

Consequently, configuring secrets at the environment level ensures that they're
only exposed to jobs that meet the environment's protection rules, mitigating
the risk of secrets being exposed to untrusted code or compromised workflows.

### Remediation

In general, secrets should be configured at the environment level, and only
the job or jobs that need a secret should use the corresponding environment.

!!! important

    You **must** move your secrets into the environment's secrets (and remove
    them from the repo/org-wide secrets) in order for this to be effective.

!!! example

    === "Before :warning:"

        ```yaml title="secrets-outside-env.yml" hl_lines="7"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
                env:
                  API_KEY: ${{ secrets.API_KEY }}
        ```

    === "After :white_check_mark:"

        ```yaml title="secrets-outside-env.yml" hl_lines="4 8"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
                env:
                  API_KEY: ${{ secrets.API_KEY }}
        ```

## `self-hosted-runner`

| Type     | Examples            | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|---------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [self-hosted.yml] | v0.1.0        | ✅             | ❌                 | ❌  |

[self-hosted.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/self-hosted.yml

!!! note

    This is a `--pedantic` only audit, due to `zizmor`'s limited ability
    to analyze runner configurations themselves. See #34 for more details.

Detects self-hosted runner usage within workflows.

GitHub supports self-hosted runners, which behave similarly to GitHub-hosted
runners but use client-managed compute resources.

Self-hosted runners are very hard to secure by default, which is why
GitHub does not recommend their use in public repositories.

Other resources:

* [Self-hosted runner security]

### Remediation

In general, self-hosted runners should only be used on private repositories.
Exposing self-hosted runners to potential public use is *always* a security
risk.

In practice, there are many cases (such as custom host configurations) where
a self-hosted runner is needed on a public repository. In these cases,
there are steps you can take to minimize their risk:

1. Require manual approval on workflows for all external contributors.
   This can be configured at repository, workflow, or enterprise-wide
   levels. See [GitHub's docs] for more information.
1. Use only [ephemeral ("just-in-time") runners]. These runners are
   created just-in-time to perform one job and are destroyed immediately
   afterwards, making it harder (but not impossible) for an attacker to
   maintain persistence.

[GitHub's docs]: https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks

[ephemeral ("just-in-time") runners]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-just-in-time-runners

## `stale-action-refs`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action  | N/A            | v1.7.0        | ❌            | ❌                | ❌          |

Checks for `#!yaml uses:` clauses which pin an action using a SHA reference,
but where that reference does not point to a Git tag.

When using an action commit which is not a Git tag / release version, that commit
might contain bugs or vulnerabilities which have not been publicly documented
because they might have been fixed before the subsequent release. Additionally,
because changelogs are usually only published for releases, it is difficult to
tell which changes of the subsequent release the pinned commit includes.

!!! note

    This is a `--pedantic` only audit because the detected situation is not
    a vulnerability per se. But it might be worth investigating which commit
    the SHA reference points to, and why not a SHA reference pointing to a
    Git tag is used.

    Some action repositories use a "rolling release branch" strategy where
    all commits on a certain branch are considered releases. In such a case
    findings of this audit can likely be ignored.

### Remediation

Change the `#!yaml uses:` clause to pin the action using a SHA reference
which points to a Git tag.


## `template-injection`

| Type     | Examples                 | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|--------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [template-injection.yml] | v0.1.0        | ✅             | ✅        | ❌  |

[template-injection.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/template-injection.yml

Detects potential sources of code injection via template expansion.

GitHub Actions allows workflows to define *template expansions*, which
occur within special `${{ ... }}` delimiters. These expansions happen
before workflow and job execution, meaning the expansion
of a given expression appears verbatim in whatever context it was performed in.

Template expansions aren't syntax-aware, meaning that they can result in
unintended shell injection vectors. This is especially true when they're
used with attacker-controllable expression contexts, such as
`github.event.issue.title` (which the attacker can fully control by supplying
a new issue title).

!!! tip

    When used with a "pedantic" or "auditor"
    [persona](./usage.md#using-personas), this audit will flag *all* template
    expansions in code contexts, even ones that are likely safe.

    This is because `zizmor` considers all template expansions in code contexts
    to be code smells, and attempting to selectively permit them is more
    error-prone than forbidding them in a blanket fashion.

Other resources:

* [Keeping your GitHub Actions and workflows secure Part 2: Untrusted input]

### Remediation

The most common forms of template injection are in `run:` and similar
code-execution blocks. In these cases, an inline template expansion
can typically be replaced by an environment variable whose value comes
from the expanded template.

This avoids the vulnerability, since variable expansion is subject to normal
shell quoting/expansion rules.

!!! tip

    To fully remediate the vulnerability, you **should not** use
    `${{ env.VARNAME }}`, since that is still a template expansion.
    Instead, you should use `${VARNAME}` to ensure that the shell *itself*
    performs the variable expansion.


!!! tip

    When switching to `${VARNAME}`, keep in mind that different shells have
    different environment variable syntaxes. In particular, Powershell (the
    default shell on Windows runners) uses `${env:VARNAME}`.

    To avoid having to specialize your handling for different runners,
    you can set `#!yaml shell: sh` or `#!yaml shell: bash`.

!!! example

    === "Before :warning:"

        ```yaml title="template-injection.yml" hl_lines="3"
        - name: Check title
          run: |
            title="${{ github.event.issue.title }}"
            if [[ ! $title =~ ^.*:\ .*$ ]]; then
              echo "Bad issue title"
              exit 1
            fi
        ```

    === "After :white_check_mark:"

        ```yaml title="template-injection.yml" hl_lines="3 8-9"
        - name: Check title
          run: |
            title="${ISSUE_TITLE}"
            if [[ ! $title =~ ^.*:\ .*$ ]]; then
              echo "Bad issue title"
              exit 1
            fi
          env:
            ISSUE_TITLE: ${{ github.event.issue.title }}
        ```

## `undocumented-permissions`

| Type     | Examples         | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|------------------|---------------|----------------|--------------------|--------------|
| Workflow | [undocumented-permissions.yml] | v1.13.0          | ✅                 | ❌            | ❌            |

[undocumented-permissions.yml]: https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/tests/integration/test-data/undocumented-permissions.yml

Detects explicit permissions blocks that lack explanatory comments.

This audit recommends adding comments to document the purpose of each permission
in explicit permissions blocks. Well-documented permissions help prevent
over-scoping and make workflows more maintainable by explaining why specific
permissions are needed.

The audit does not flag `contents: read`, as this is a common, self-explanatory
permission.

!!! note

    This is a `--pedantic` only audit, as it focuses on code quality and
    maintainability rather than security vulnerabilities.

### Remediation

Add inline comments explaining why each permission is needed:

=== "Before :warning:"

    ```yaml title="undocumented-permissions.yml" hl_lines="2-4"
    permissions:
      contents: write
      packages: read
      issues: write
    ```

=== "After :white_check_mark:"

    ```yaml title="undocumented-permissions.yml" hl_lines="2-4"
    permissions:
      contents: write  # Needed to create releases and update files
      packages: read   # Needed to read existing package metadata
      issues: write    # Needed to create and update issue comments
    ```

## `unpinned-images`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action  | [unpinned-images.yml] | v1.7.0        | ✅            | ❌                | ❌          |

[unpinned-images.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned-images.yml

Checks for `container.image` values where the image is not pinned by either a tag (other than `latest`) or SHA256.

When image references are unpinned or are pinned to a mutable tag, the
workflow is at risk because the image used will be unpredictable over time.
Changes made to the OCI registry used to source the image may result in untrusted
images gaining access to your workflow.

This can be a security risk:

1. Registries may not consistently enforce immutable image tags
2. Completely unpinned images can be changed at any time by the OCI registry.

By default, this audit applies the following policy:

* Regular findings are created for all image references missing a tag

    ```yaml
    container:
      image: foo/bar
    ```

    or using the `latest` tag:

    ```yaml
    container:
      image: foo/bar:latest
    ```

* Pedantic findings are created for all image references using a tag (`!= latest`) rather than SHA256 hash.

    ```yaml
    container:
      image: foo/bar:not-a-sha256
    ```

Other resources:

- [Aqua: The Challenges of Uniquely Identifying Your Images]
- [GitHub: Safeguard your containers with new container signing capability in GitHub Actions]



### Remediation

Pin the `#!yaml container.image:` value to a specific SHA256 image registry hash.

Many popular registries will display the hash value in their web console or you
can use the command line to determine the hash of an image you have previously pulled
by running `#!bash docker inspect redis:7.4.3 --format='{{.RepoDigests}}'`.

!!! example

    === "Before :warning:"

        ```yaml title="unpinned-images.yml" hl_lines="7-8"
        name: unpinned-images
        on: [push]

        jobs:
          unpinned-image:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example
            steps:
              - run: "echo unpinned container!"
        ```

    === "After :white_check_mark:"

        ```yaml title="unpinned-images.yml" hl_lines="7-8"
        name: unpinned-images
        on: [push]

        jobs:
          unpinned-image:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
            steps:
              - run: "echo pinned container!"
        ```

## `unpinned-uses`

| Type             | Examples         | Introduced in | Works offline  | Auto-fixes available | Configurable |
|------------------|------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action | [unpinned.yml]   | v0.4.0        | ✅             | ✅                | ✅           |

[unpinned.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned.yml

Detects "unpinned" `#!yaml uses:` clauses.

When a `#!yaml uses:` clause is not pinned by branch, tag, or SHA reference,
GitHub Actions will use the latest commit on the referenced repository's
default branch (or, in the case of Docker actions, the `:latest` tag).

Similarly, if a `#!yaml uses:` clause is pinned via branch or tag (i.e. a "symbolic
reference") instead of a SHA reference, GitHub Actions will use whatever
commit is at the tip of that branch or tag. GitHub does not have immutable
branches or tags, meaning that the action can change without the symbolic
reference changing.

This can be a security risk:

1. Completely unpinned actions can be changed at any time by the upstream
   repository.
2. Tag- or branch-pinned actions can be changed by the upstream repository,
   either by force-pushing over the tag or updating the branch.

If the upstream repository is trusted, then symbolic references are
often suitable. However, if the upstream repository is not trusted, then
actions should be pinned by SHA reference.

By default, this audit applies a blanket hash-pinning policy:
all actions must be pinned by SHA reference.

!!! note "Behavior change"

    Starting with zizmor v1.20.0, the default policy for `unpinned-uses`
    is to require hash-pinning on *all* actions, not just third-party ones.
    The previous behavior (of allowing `actions/*` and similar to be ref-pinned)
    is no longer the default but can be re-enabled via configuration;
    see the configuration section below for details.

This audit can be configured with a custom set of rules, e.g. to
allow symbolic references for trusted repositories or entire namespaces
(e.g. `foocorp/*`). See
[`unpinned-uses` - Configuration](#unpinned-uses-configuration) for details.

Specifying a configuration overrides the default policy above.

Other resources:

* [Palo Alto Networks Unit42: tj-actions/changed-files incident]

### Configuration { #unpinned-uses-configuration }

!!! note

    `unpinned-uses` is configurable in `v1.6.0` and later.

If the default `unpinned-uses` rules isn't suitable for your use case,
you can override it with a custom set of policies.

#### `rules.unpinned-uses.config.policies`

_Type_: `object`

The `rules.unpinned-uses.config.policies` object defines your `unpinned-uses`
policies.

Each member is a `#!yaml pattern: policy` rule, where `pattern` describes which
`#!yaml uses:` clauses to match and `policy` describes how to treat them.

The `pattern` is a repository pattern; see
[Configuration - Repository patterns](./configuration.md#repository-patterns)
for details.

The valid policies are:

* `hash-pin`: any `#!yaml uses:` clauses that match the associated pattern must be
  fully pinned by SHA reference.
* `ref-pin`: any `#!yaml uses:` clauses that match the associated pattern must be
  pinned either symbolic or SHA reference.
* `any`: no pinning is required for any `#!yaml uses:` clauses that match the associated
  pattern.

    !!! tip

        For repository `#!yaml uses` clauses like `#!yaml uses: actions/checkout@v4`
        this is equivalent to `ref-pin`, as GitHub Actions does not permit
        completely unpinned repository actions.

If a `#!yaml uses:` clauses matches multiple rules, the most specific one is used
regardless of definition order.

!!! example

    The following configuration contains two rules that could match
    @actions/checkout, but the first one is more specific and therefore gets applied:

    ```yaml title="zizmor.yml"
    rules:
      unpinned-uses:
        config:
          policies:
            actions/checkout: hash-pin
            actions/*: ref-pin
    ```

    In plain English, this policy set says "anything that `#!yaml uses: actions/*` must
    be at least ref-pinned, but @actions/checkout in particular must be hash-pinned."

!!! example

    ```yaml title="zizmor.yml"
    rules:
      unpinned-uses:
        config:
          policies:
            "example/*": hash-pin
            "*": ref-pin
    ```

    In plain English, this policy set says "anything that `#!yaml uses: example/*` must
    be hash-pinned, and anything else must be at least ref-pinned."


!!! important

    If a `#!yaml uses:` clause does not match any rules, then an implicit
    `#!yaml "*": hash-pin` rule is applied. Users can override this implicit rule
    by adding their own `*` rule or a more precise rule, e.g.
    `#!yaml "github/*": ref-pin` for actions under the @github organization.

### Remediation

!!! tip

    You can use `zizmor`'s [fix mode](./usage.md#auto-fixing-results) to
    automatically hash-pin your workflows and actions.
  
    Alternatively, there are several third-party tools that can automatically
    hash-pin your workflows and actions for you:

    - :simple-go: @suzuki-shunsuke/pinact: supports updating and hash-pinning
      workflows, actions, and arbitrary inputs.
    - :simple-python: @davidism/gha-update: supports updating and hash-pinning
      workflow definitions.
    - :simple-go: @stacklok/frizbee: supports hash-pinning (but not updating)
      workflow definitions.

        See also stacklok/frizbee#184 for current usage caveats.

!!! tip

    Once your workflows and actions are hash-pinned, consider using
    [Dependabot] or [Renovate] to keep them up-to-date automatically.

For repository actions (like @actions/checkout): add a branch, tag, or SHA
reference.

For Docker actions (like `docker://ubuntu`): add an appropriate
`:{version}` suffix.

!!! example

    === "Before :warning:"

        ```yaml title="unpinned-uses.yml" hl_lines="8 12"
        name: unpinned-uses
        on: [push]

        jobs:
          unpinned-uses:
              runs-on: ubuntu-latest
              steps:
                - uses: pypa/gh-action-pypi-publish@v1.12.4
                  with:
                    persist-credentials: false

                - uses: docker://ubuntu
                  with:
                    entrypoint: /bin/echo
                    args: hello!
        ```

    === "After :white_check_mark:"

        ```yaml title="unpinned-uses.yml" hl_lines="8 12"
        name: unpinned-uses
        on: [push]

        jobs:
          unpinned-uses:
              runs-on: ubuntu-latest
              steps:
                - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc  # v1.12.4
                  with:
                    persist-credentials: false

                - uses: docker://ubuntu:24.04
                  with:
                    entrypoint: /bin/echo
                    args: hello!
        ```

## `unredacted-secrets`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [unredacted-secrets.yml]   | v1.4.0      | ✅   | ❌                 | ❌  |

[unredacted-secrets.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unredacted-secrets.yml

Detects potential secret leakage via redaction failures.

Typically, users access the `secrets` context via its individual members:

```yaml
env:
  PASSWORD: ${{ secrets.PASSWORD }}
```

This allows the Actions runner to redact the secret values from the job logs,
as it knows the exact string value of each secret.

However, if the user instead treats the secret as a structured value,
e.g. JSON:

```yaml
env:
  PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
```

...then the `password` field is not redacted, as the runner does not
treat arbitrary substrings of secrets as secret values.

Other resources:

* [Using secrets in GitHub Actions]

### Remediation

In general, users should avoid treating secrets as structured values.
For example, instead of storing a JSON object in a secret, store the
individual fields as separate secrets.

!!! example

    === "Before :warning:"

        ```yaml title="unredacted-secrets.yml" hl_lines="7-8"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
                env:
                  USERNAME: ${{ fromJSON(secrets.MY_SECRET).username }}
                  PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
        ```

    === "After :white_check_mark:"

        ```yaml title="unredacted-secrets.yml" hl_lines="7-8"
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
                env:
                  USERNAME: ${{ secrets.MY_SECRET_USERNAME }}
                  PASSWORD: ${{ secrets.MY_SECRET_PASSWORD }}
        ```


## `unsound-condition`

| Type     | Examples                | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [unsound-condition.yml]   | v1.12.0      | ✅             | ✅                 | ❌  |

[unsound-condition.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unsound-condition.yml

Detects conditions that are inadvertently always true despite containing
an expression that should control the evaluation.

A common source of these is an unintentional interaction
between multi-line YAML strings and fenced GitHub Actions expressions.
For example, the following condition always evaluates to `true`, despite
appearing to evaluate to `false`:

```yaml
if: |
  ${{ false }}
```

This happens because YAML's "block" scalars include a trailing newline
by default, which is left *outside* of the GitHub Actions expression.
This results in an expansion like `'false\n'` instead of `'false'`,
which GitHub Actions interprets as a truthy value.

### Remediation

There are two ways to remediate this:

* Avoid fenced expressions in `#!yaml if:` conditions. Instead, write
  the expression as a "bare" expression.

    This will still include the trailing newline, but it will be *inside*
    of the expression as seen from the GitHub Actions expression parser.

    !!! example

        === "Before :warning:"

            ```yaml title="unsound-condition.yml" hl_lines="6-7"
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "This will incorrectly always run"
                    if: |
                      ${{ false }}
            ```

        === "After :white_check_mark:"

            ```yaml title="unsound-condition.yml" hl_lines="6-7"
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "This will correctly not run"
                    if: |
                      false
            ```

* Use fenced expressions, but use a YAML block scalar that does not
  include a trailing newline. Either `|-` or `>-` is appropriate for
  this purpose.

    !!! example

        === "Before :warning:"

            ```yaml title="unsound-condition.yml" hl_lines="6-7"
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "This will incorrectly always run"
                    if: |
                      ${{ false }}
            ```

        === "After :white_check_mark:"

            ```yaml title="unsound-condition.yml" hl_lines="6-7"
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "This will correctly not run"
                    if: |-
                      ${{ false }}
            ```

## `unsound-contains`

| Type     | Examples                            | Introduced in | Works offline | Auto-fixes available | Configurable |
|----------|-------------------------------------|---------------|---------------|--------------------|--------------|
| Workflow | [unsound-contains.yml]              | v1.7.0        | ✅            | ❌                 | ❌           |

[unsound-contains.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unsound-contains.yml

Detects conditions that use the `contains()` function in a way that can be bypassed.

Some workflows use `contains()` to check if a context variable is in a list of
values (e.g., if the the `push` that triggered the job targeted a certain
branch), and then bypass checks or otherwise perform privileged actions:

```yaml
if: contains('refs/heads/main refs/heads/develop', github.ref)
```

However, this condition will not only evaluate to `true` if either
`refs/heads/main` or `refs/heads/develop` is passed, but also for substrings of
those values. For example, if someone pushes to a branch named `mai`, then
`github.ref` would contain the string `refs/heads/mai` and the job would also
execute.

### Remediation

To check if a value is contained in a list of strings, the first argument to
`contains()` should be an actual list, not a string. This can be done by using
the `fromJSON()` function:

```yaml
if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
```

Alternatively, it's possible to check for equality individually and combine the
results using the logical "or" operator:

```yaml
if: github.ref == "refs/heads/main" || github.ref == "refs/heads/develop"
```

Other resources:

* [GitHub Docs: Evaluate expressions in workflows and actions - Example matching an array of strings]

!!! example

    === "Before :warning:"

        ```yaml title="unsound-contains.yml" hl_lines="9 10"
        on: push

        jobs:
          tf-deploy:
            runs-on: ubuntu-latest
            steps:
              - run: terraform init -input=false
              - run: terraform plan -out=tfplan -input=false
              - run: terraform apply -input=false tfplan
                if: contains('refs/heads/main refs/heads/develop', github.ref)
        ```

    === "After :white_check_mark:"

        ```yaml title="unsound-contains.yml" hl_lines="9 10"
        on: push

        jobs:
          tf-deploy:
            runs-on: ubuntu-latest
            steps:
              - run: terraform init -input=false
              - run: terraform plan -out=tfplan -input=false
              - run: terraform apply -input=false tfplan
                if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
        ```


## `use-trusted-publishing`

| Type     | Examples                     | Introduced in | Works offline  | Auto-fixes available | Configurable |
|----------|------------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [pypi-manual-credential.yml] | v0.1.0        | ✅             | ❌                 | ❌  |

[pypi-manual-credential.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pypi-manual-credential.yml

Detects packaging workflows that could use [Trusted Publishing].

Some packaging ecosystems/indices (like [PyPI] and [RubyGems]) support
"Trusted Publishing," which is an OIDC-based "tokenless" authentication
mechanism for uploading to the index from within a CI/CD workflow.

This "tokenless" flow has significant security benefits over a traditional
manually configured API token, and should be preferred wherever supported
and possible.

[Trusted Publishing]: https://repos.openssf.org/trusted-publishers-for-all-package-repositories.html

[PyPI]: https://pypi.org

[RubyGems]: https://rubygems.org

Other resources:

* [Trusted Publishers for All Package Repositories]
* [Trusted publishing: a new benchmark for packaging security]

### Remediation

In general, enabling Trusted Publishing requires a one-time change to your
package's configuration on its associated index (e.g. PyPI or RubyGems).

Each ecosystem has its own resources for using a Trusted Publisher
once it's configured:

<div class="grid cards" markdown>
-   :simple-pypi:{.lg .middle} Python (PyPI)

    ---

    Usage: @pypa/gh-action-pypi-publish

    See: [Publishing to PyPI with a Trusted Publisher]

-   :simple-rubygems:{.lg .middle} Ruby (RubyGems)

    ---

    Usage: @rubygems/release-gem

    See: [Trusted Publishing - RubyGems Guides]

-   :material-language-rust:{.lg .middle} Rust (crates.io)

    ---

    Usage: @rust-lang/crates-io-auth-action.

    See: [Trusted Publishing - crates.io]

-   :simple-dart:{.lg .middle} Dart (pub.dev)

    ---

    See: [Automated publishing of packages to pub.dev]

-   :material-npm:{.lg .middle} JavaScript (npm)

    ---

    See: [Trusted publishing for npm packages]
    
-   :simple-nuget:{.lg .middle} .NET (nuget.org)

    ---
    
    Usage: @NuGet/login

    See: [Trusted publishing for nuget.org]
</div>

[Dependabot]: https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/keeping-your-actions-up-to-date-with-dependabot

[Renovate]: https://docs.renovatebot.com/modules/manager/github-actions/

[ArtiPACKED: Hacking Giants Through a Race Condition in GitHub Actions Artifacts]: https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
[Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests]: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
[Keeping your GitHub Actions and workflows secure Part 4: New vulnerability patterns and mitigation strategies]: https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/
[What the fork? Imposter commits in GitHub Actions and CI/CD]: https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd
[Self-hosted runner security]: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security
[Keeping your GitHub Actions and workflows secure Part 2: Untrusted input]: https://securitylab.github.com/resources/github-actions-untrusted-input/
[Publishing to PyPI with a Trusted Publisher]: https://docs.pypi.org/trusted-publishers/
[Trusted Publishing - RubyGems Guides]: https://guides.rubygems.org/trusted-publishing/
[Trusted Publishing - crates.io]: https://crates.io/docs/trusted-publishing
[Automated publishing of packages to pub.dev]: https://dart.dev/tools/pub/automated-publishing
[Trusted publishing for npm packages]: https://docs.npmjs.com/trusted-publishers
[Trusted publishing for nuget.org]: https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing
[Trusted publishing: a new benchmark for packaging security]: https://blog.trailofbits.com/2023/05/23/trusted-publishing-a-new-benchmark-for-packaging-security/
[Trusted Publishers for All Package Repositories]: https://repos.openssf.org/trusted-publishers-for-all-package-repositories.html
[were deprecated by GitHub]: https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/
[GitHub Actions environment files]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#environment-files
[Semgrep audit]: https://semgrep.dev/r?q=yaml.github-actions.security.allowed-unsecure-commands.allowed-unsecure-commands
[GitHub Actions exploitation: environment manipulation]: https://www.synacktiv.com/en/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation
[GitHub Docs: Evaluate expressions in workflows and actions - Example matching an array of strings]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/evaluate-expressions-in-workflows-and-actions#example-matching-an-array-of-strings
[GHSL-2024-177: Environment Variable injection in an Actions workflow of Litestar]: https://securitylab.github.com/advisories/GHSL-2024-177_Litestar/
[Vulnerable GitHub Actions Workflows Part 1: Privilege Escalation Inside Your CI/CD Pipeline]: https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability
[Google & Apache Found Vulnerable to GitHub Environment Injection]: https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability-0
[Hacking with Environment Variables]: https://www.elttam.com/blog/env/
[The Monsters in Your Build Cache – GitHub Actions Cache Poisoning]: https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
[reusable workflows]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows
[Principle of Least Authority]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[Cacheract: The Monster in your Build Cache]: https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/
[GitHub Actions exploitations: Dependabot]: https://www.synacktiv.com/publications/github-actions-exploitation-dependabot
[Using secrets in GitHub Actions]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
[Palo Alto Networks Unit42: tj-actions/changed-files incident]: https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
[Dependabot secrets]: https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions#accessing-secrets
[explicitly specifying needed permissions]: https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions#changing-github_token-permissions
[branch filter]: https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#running-your-pull_request_target-workflow-based-on-the-head-or-base-branch-of-a-pull-request
[Aqua: The Challenges of Uniquely Identifying Your Images]: https://www.aquasec.com/blog/docker-image-tags/
[GitHub: Safeguard your containers with new container signing capability in GitHub Actions]: https://github.blog/security/supply-chain-security/safeguard-container-signing-capability-actions/
[Pwning the Entire Nix Ecosystem]: https://ptrpa.ws/nixpkgs-actions-abuse
[Guidelines on green software practices for GitHub Actions CI workflows]: https://github.com/Cambridge-ICCS/green-ci
