# Audit Rules

This page documents each of the audits currently implemented in `zizmor`.

See each audit's section for its scope, behavior, and other information.

Legend:

| Type     | Examples         | Introduced in | Works offline  | Enabled by default |
|----------|------------------|---------------|----------------|--------------------|
| The kind of audit ("Workflow" or "Action") | Links to vulnerable examples | Added to `zizmor` in this version | The audit works with `--offline` | The audit needs to be explicitly enabled with `--pedantic` |

## `artipacked`

| Type     | Examples         | Introduced in | Works offline  | Enabled by default |
|----------|------------------|---------------|----------------|--------------------|
| Workflow  | [artipacked.yml] | v0.1.0        | ✅             | ✅                 |

[artipacked.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/artipacked.yml

Detects local filesystem `git` credential storage on GitHub Actions, as well as
potential avenues for unintentional persistence of credentials in artifacts.

By default, using @actions/checkout causes a credential to be persisted
in the checked-out repo's `.git/config`, so that subsequent `git` operations
can be authenticated.

Subsequent steps may accidentally publicly persist `.git/config`, e.g. by
including it in a publicly accessible artifact via @actions/upload-artifact.

However, even without this, persisting the credential in the `.git/config`
is non-ideal unless actually needed.

Other resources:

* <https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/>

### Remediation

Unless needed for `git` operations, @actions/checkout should be used with
`#!yaml persist-credentials: false`.

If the persisted credential is needed, it should be made explicit
with `#!yaml persist-credentials: true`.

=== "Before"

    ```yaml title="artipacked.yml" hl_lines="7"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
    ```

=== "After"

    ```yaml title="artipacked.yml" hl_lines="7-9"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              persist-credentials: false
    ```

## `dangerous-triggers`

| Type     | Examples                  | Introduced in | Works offline  | Enabled by default |
|----------|---------------------------|---------------|----------------|--------------------|
| Workflow  | [pull-request-target.yml] | v0.1.0        | ✅             | ✅                 |

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

Other resources:

* <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>

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
* Never run PR-controlled code in the context of a
  `pull_request_target`-triggered workflow.
* Avoid attacker-controllable flows into `GITHUB_ENV` in both `workflow_run`
  and `pull_request_target` workflows, since these can lead to arbitrary
  code execution.

[reusable workflow]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows

## `excessive-permissions`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [excessive-permissions.yml] | v0.1.0        | ✅             | ✅                 |

[excessive-permissions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/excessive-permissions.yml

Detects excessive permissions in workflows, both at the workflow level and
individual job levels.

Users frequently over-scope their workflow and job permissions,
or set broad workflow-level permissions without realizing that
all jobs inherit those permissions.

### Remediation

TODO

## `hardcoded-container-credentials`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [hardcoded-credentials.yml] | v0.1.0        | ✅             | ✅                 |

[hardcoded-credentials.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml

### What

GitHub Actions allows Docker credentials (usernames and passwords)
to be hardcoded in various places within workflows.

### Why

Hardcoding credentials is bad.

## `impostor-commit`

| Type     | Examples              | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------|---------------|----------------|--------------------|
| Workflow  | [impostor-commit.yml] | v0.1.0        | ❌             | ✅                 |

[impostor-commit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml

### What

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

### Why

GitHub's network-of-forks design can be used to obscure a commit's true origin
in a fully-pinned `uses:` workflow reference. This can be used by an attacker
to surreptitiously introduce a backdoored action into a victim's workflows(s).

### Other resources

* <https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd>

## `known-vulnerable-actions`

| Type     | Examples                       | Introduced in | Works offline  | Enabled by default |
|----------|--------------------------------|---------------|----------------|--------------------|
| Workflow  | [known-vulnerable-actions.yml] | v0.1.0        | ❌             | ✅                 |

[known-vulnerable-actions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/known-vulnerable-actions.yml

### What

Actions with known, publicly disclosed vulnerabilities are tracked in the
[GitHub Advisories database]. Examples of commonly disclosed vulnerabilities
in GitHub Actions include [credential disclosure] and code injection
via [template injection].

### Why

You shouldn't use actions with known vulnerabilities.

[GitHub Advisories database]: https://github.com/advisories

[credential disclosure]: #artipacked

[template injection]: #template-injection

## `ref-confusion`

| Type     | Examples            | Introduced in | Works offline  | Enabled by default |
|----------|---------------------|---------------|----------------|--------------------|
| Workflow  | [ref-confusion.yml] | v0.1.0        | ❌             | ✅                 |

[ref-confusion.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml

### What

Like with [impostor commits], actions that are used with a symbolic ref
in their `uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

### Why

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: #impostor-commit

## `self-hosted-runner`

| Type     | Examples            | Introduced in | Works offline  | Enabled by default |
|----------|---------------------|---------------|----------------|--------------------|
| Workflow  | [self-hosted.yml] | v0.1.0        | ✅             | ❌                 |

[self-hosted.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/self-hosted.yml

!!! note

    This is a `--pedantic` only audit, due to `zizmor`'s limited ability
    to analyze runner configurations themselves. See #34 for more details.

### What

GitHub supports self-hosted runners, which behave similarly to GitHub-hosted
runners but use client-managed compute resources.

### Why

Self-hosted runners are very hard to secure by default, which is why
GitHub does not recommend their use in public repositories.

### Other resources

* <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>

## `template-injection`

| Type     | Examples                 | Introduced in | Works offline  | Enabled by default |
|----------|--------------------------|---------------|----------------|--------------------|
| Workflow  | [template-injection.yml] | v0.1.0        | ✅             | ✅                 |

[template-injection.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/template-injection.yml

### What

GitHub Actions allows workflows to define *template expansions*, which
occur within special `${{ ... }}` delimiters. These expansions happen
before workflow and job execution, meaning the expansion
of a given expression appears verbatim in whatever context it was performed in.

### Why

Template expansions aren't syntax-aware, meaning that they can result in
unintended shell injection vectors. This is especially true when they're
used with attacker-controllable expression contexts, such as
`github.event.issue.title` (which the attacker can fully control by supplying
a new issue title).

### Other resources

* <https://securitylab.github.com/resources/github-actions-untrusted-input/>

## `use-trusted-publishing`

| Type     | Examples                     | Introduced in | Works offline  | Enabled by default |
|----------|------------------------------|---------------|----------------|--------------------|
| Workflow  | [pypi-manual-credential.yml] | v0.1.0        | ✅             | ✅                 |

[pypi-manual-credential.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pypi-manual-credential.yml

### What

Some packaging ecosystems/indices (like PyPI and RubyGems) support
"Trusted Publishing," which is an OIDC-based "tokenless" authentication
mechanism for uploading to the index from within a CI/CD workflow.

### Why

This "tokenless" flow has significant security benefits over a traditional
manually configured API token, and should be preferred wherever supported
and possible.

### Other resources

* <https://docs.pypi.org/trusted-publishers/>
* <https://guides.rubygems.org/trusted-publishing/>
* <https://blog.trailofbits.com/2023/05/23/trusted-publishing-a-new-benchmark-for-packaging-security/>

## `unpinned-uses`

| Type     | Examples                     | Introduced in | Works offline  | Enabled by default |
|----------|------------------------------|---------------|----------------|--------------------|
| Workflow  | [unpinned.yml]              | v0.4.0        | ✅             | ✅                 |

[unpinned.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned.yml

Detects "unpinned" `uses:` clauses.

When a `uses:` clause is not pinned by branch, tag, or SHA reference,
GitHub Actions will use the latest commit on the referenced repository
(or, in the case of Docker actions, the `:latest` tag).

This can represent a (small) security risk, as it leaves the calling workflow
at the mercy of the callee action's default branch.

### Remediation

For repository actions (like @actions/checkout): add a branch, tag, or SHA
reference.

For Docker actions (like `docker://ubuntu`): add an appropriate
`:{version}` suffix.

A before/after example is shown below.

=== "Before"

    ```yaml title="unpinned-uses.yml" hl_lines="8 12"
    name: unpinned-uses
    on: [push]

    jobs:
    unpinned-uses:
        runs-on: ubuntu-latest
        steps:
        - uses: actions/checkout
          with:
          persist-credentials: false

        - uses: docker://ubuntu
          with:
          entrypoint: /bin/echo
          args: hello!
    ```

=== "After"

    ```yaml title="unpinned-uses.yml" hl_lines="8 12"
    name: unpinned-uses
    on: [push]

    jobs:
    unpinned-uses:
        runs-on: ubuntu-latest
        steps:
        - uses: actions/checkout@v4 # (1)!
          with:
          persist-credentials: false

        - uses: docker://ubuntu:24.04
          with:
          entrypoint: /bin/echo
          args: hello!
    ```

    1. Or `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` for a SHA-pinned action.
