# `use-trusted-publishing`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `use-trusted-publishing` | Workflow | [`pypi-manual-credential.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pypi-manual-credential.yml)

## What

Some packaging ecosystems/indices (like PyPI and RubyGems) support
"Trusted Publishing," which is an OIDC-based "tokenless" authentication
mechanism for uploading to the index from within a CI/CD workflow.

## Why

This "tokenless" flow has significant security benefits over a traditional
manually configured API token, and should be preferred wherever supported
and possible.

## Other resources

* <https://docs.pypi.org/trusted-publishers/>
* <https://guides.rubygems.org/trusted-publishing/>
* <https://blog.trailofbits.com/2023/05/23/trusted-publishing-a-new-benchmark-for-packaging-security/>
