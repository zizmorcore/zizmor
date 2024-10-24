# `hardcoded-container-credentials`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `hardcoded-container-credentials` | Workflow | [`hardcoded-credentials.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml)

## What

GitHub Actions allows Docker credentials (usernames and passwords)
to be hardcoded in various places within workflows.

## Why

Hardcoding credentials is bad.
