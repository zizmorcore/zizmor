# `excessive-permissions`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `excessive-permissions` | Workflow | [`excessive-permissions.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/excessive-permissions.yml)

## What

Looks for excessive permissions in workflows, both at
the workflow level and individual job levels.

## Why

Users frequently over-scope their workflow and job permissions,
or set broad workflow-level permissions without realizing that
all jobs inherit those permissions.
