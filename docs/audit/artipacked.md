# `artipacked`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `artipacked` | Workflow | [`artipacked.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/artipacked.yml)

## What

Unexpected credential use and potential credential persistence,
typically via GitHub Actions artifact creation or action logs.

## Why

The default checkout action is [`actions/checkout`].

By default, using `actions/checkout` causes a credential to be persisted
in the checked-out repo's `.git/config`, so that subsequent `git` operations
can be authenticated.

Subsequent steps may accidentally publicly persist `.git/config`, e.g. by
including it in a publicly accessible artifact via [`actions/upload-artifact`].

However, even without this, persisting the credential in the `.git/config`
is non-ideal and should be disabled with `persist-credentials: false` unless
the job actually needs the persisted credential.

## Other resources

* <https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/>

[`actions/checkout`]: https://github.com/actions/checkout

[`actions/upload-artifact`]: https://github.com/actions/upload-artifact
