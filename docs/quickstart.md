# Quickstart

First, run `zizmor -h` to make sure your [installation](./installation.md) succeeded.

You should see something like this:

```console
--8<-- "help.txt"
```

!!! tip

    Run `zizmor --help` for a longer and more detailed version of `zizmor -h`.

## Running `zizmor`

Here are some different ways you can run `zizmor` locally:

=== "On one or more workflows"

    You can run `zizmor` on one or more workflows or composite actions as
    explicit inputs:

    ```bash
    zizmor ci.yml tests.yml lint.yml action.yml
    ```

    These can be in any directory as well:

    ```
    zizmor ./subdir/ci.yml ../sibling/tests.yml ./action/action.yml
    ```

=== "On one or more local repositories"

    !!! tip

        Composite action support was added in v1.0.0.

    !!! tip

        Pass `--collect=workflows` to avoid collecting anything except
        workflow definitions.

    When given one or more local directories, `zizmor` will treat each as a
    GitHub repository and attempt to discover workflows defined under the
    `.github/workflows` subdirectory for each. `zizmor` will also walk each
    directory to find composite action definitions (`action.yml` in any
    subdirectory) and Dependabot configuration files
    (`.github/dependabot.yml`).

    ```bash
    # repo-a/ contains .github/workflows/{ci,tests}.yml
    # as well as custom-action/action.yml
    zizmor repo-a/

    # or with multiple directories
    zizmor repo-a/ ../../repo-b/

    # collect only workflows, not composite actions or Dependabot configs
    zizmor --collect=workflows
    ```

=== "On one or more remote repositories"

    !!! tip

        Private repositories can also be audited remotely, as long
        as your GitHub API token has sufficient permissions.

    !!! tip

        Pass `--collect=workflows` to disable collecting anything except
        workflow definitions.

    `zizmor` can also fetch workflows and actions directly from GitHub, if
    given a GitHub API token via `GH_TOKEN` or `--gh-token`:

    ```bash
    # audit all workflows and composite actions in zizmorcore/zizmor
    # assumes you have `gh` installed
    zizmor --gh-token=$(gh auth token) zizmorcore/zizmor
    ```

    Multiple repositories will also work:

    ```bash
    zizmor --gh-token=$(gh auth token) zizmorcore/zizmor zizmorcore/gha-hazmat
    ```

See [Usage](./usage.md) for more examples, including examples of configuration.

## Fixing findings

Some findings can be fixed automatically by running `zizmor` with `--fix`.

For findings that can't be fixed automatically, consult the documentation for the relevant [audit
rule](./audits.md). In many modern terminals, the audit rule name in the terminal output is a link
that goes directly to that rule's documentation. For example, in this output:

```console
error[template-injection]: code injection via template expansion
```

`template-injection` within the square brackets is a clickable link that takes you to
the [template-injection](./audits#template-injection) audit documentation. See [Audit documentation
links](./usage#audit-documentation-links) for more detail.

For findings that aren't right for your use case that you want to ignore, you can add a `# zizmor:
ignore[rulename]` comment to the relevant line. More details, including how to ignore multiple
findings or entire files by using a `zizmor.yml` configuration file, are in the [Ignoring
results](./usage#ignoring-results) section.
