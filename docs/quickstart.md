# Quickstart

You can run `zizmor` on any file(s) you have locally:

```bash
# audit a specific workflow
zizmor my-workflow.yml
# discovers .github/workflows/*.yml automatically
zizmor path/to/repo
```

By default, `zizmor` will emit a Rust-style human-friendly findings, e.g.:

```console
error[pull-request-target]: use of fundamentally insecure workflow trigger
  --> /home/william/devel/gha-hazmat/.github/workflows/pull-request-target.yml:20:1
   |
20 | / on:
21 | |   # NOT OK: pull_request_target should almost never be used
22 | |   pull_request_target:
   | |______________________^ triggers include pull_request_target, which is almost always used insecurely
   |

1 findings (0 unknown, 0 informational, 0 low, 0 medium, 1 high)
```

See [Usage](./usage.md) for more examples, including examples of configuration.
