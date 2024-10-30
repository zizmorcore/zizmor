# `self-hosted-runner`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `self-hosted-runner` | Workflow | [`self-hosted.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/self-hosted-runner.yml)

## What

GitHub supports self-hosted runners, which behave similarly to GitHub-hosted
runners but use client-managed compute resources.

## Why

Self-hosted runners are very hard to secure by default, which is why
GitHub does not recommend their use in public repositories.

## Other resources

* <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>
