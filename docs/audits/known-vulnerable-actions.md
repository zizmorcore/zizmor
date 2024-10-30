# `known-vulnerable-actions`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `known-vulnerable-actions` | Workflow | [`known-vulnerable-actions.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/known-vulnerable-actions.yml)

## What

Actions with known, publicly disclosed vulnerabilities are tracked in the
[GitHub Advisories database]. Examples of commonly disclosed vulnerabilities
in GitHub Actions include [credential disclosure] and code injection
via [template injection].

## Why

You shouldn't use actions with known vulnerabilities.

[GitHub Advisories database]: https://github.com/advisories

[credential disclosure]: ./artipacked.md

[template injection]: ./template-injection.md
