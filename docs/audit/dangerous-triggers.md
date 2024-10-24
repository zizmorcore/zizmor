# `dangerous-triggers`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `dangerous-triggers` | Workflow | [`pull-request-target.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pull-request-target.yml)

## What

Fundamentally dangerous GitHub Actions workflow triggers.

## Why

Many of GitHub's workflow triggers are difficult to use security.
This audit checks for some of the biggest offenders:

* `pull_request_target`
* `workflow_run`

These triggers are dangerous because they run in the context of the
*target repository* rather than the *fork repository*, while also being
typically triggerable by the latter. This can lead to attacker controlled
code execution or unexpected action runs with context controlled by a malicious
fork.

## Other resources

* <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
