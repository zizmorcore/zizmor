# `template-injection`

| Audit ID | Type | Examples |
| -------- | ---- | -------- |
| `template-injection` | Workflow | [`self-hosted.yml`](https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/template-injection.yml)

## What

GitHub Actions allows workflows to define *template expansions*, which
occur within special `${{ ... }}` delimiters. These expansions happen
before workflow and job execution, meaning the expansion
of a given expression appears verbatim in whatever context it was performed in.

## Why

Template expansions aren't syntax-aware, meaning that they can result in
unintended shell injection vectors. This is especially true when they're
used with attacker-controllable expression contexts, such as
`github.event.issue.title` (which the attacker can fully control by supplying
a new issue title).

## Other resources

* <https://securitylab.github.com/resources/github-actions-untrusted-input/>
