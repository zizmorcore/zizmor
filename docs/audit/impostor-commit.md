# `impostor-commit`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `impostor-commit` | Workflow | [`impostor-commit.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml)

## What

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

## Why

GitHub's network design can be used to obscure a commit's true origin
in a fully-pinned `uses:` workflow reference. This can be used by an attacker
to surreptitiously introduce a backdoored action into a victim's workflows(s).

## Other resources

* <https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd>
