# `ref-confusion`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `ref-confusion` | Workflow | [`ref-confusion.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml)

## What

Like with [impostor commits], actions that are used with a symbolic ref
in their `uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

## Why

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: ./impostor-commit.md
