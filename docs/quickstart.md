# Quickstart

First, run `zizmor -h` to make sure your installation succeeded.

You should see something like this:

```console
--8<-- "help.txt"
```

!!! tip

    Run `zizmor --help` for a longer and more detailed version of `zizmor -h`.

## Running `zizmor`

Here are some different ways you can run `zizmor` locally:

=== "On one or more files"

    You can run `zizmor` on one or more workflows as explicit inputs:

    ```bash
    zizmor ci.yml tests.yml lint.yml
    ```

    These can be in any directory as well:

    ```
    zizmor ./subdir/ci.yml ../sibling/tests.yml
    ```

=== "On one or more directories"

    If you have multiple workflows in a single directory, `zizmor` will
    discover them:

    ```bash
    # somewhere/ contains ci.yml and tests.yml
    zizmor somewhere/
    ```

    Moreover, if the specified directory contains a `.github/workflows`
    subdirectory, `zizmor` will discover workflows there:

    ```bash
    # my-local-repo/ contains .github/workflows/{ci,tests}.yml
    zizmor my-local-repo/
    ```

=== "On one or more remote repositories"

    !!! tip

        Private repositories can also be audited remotely, as long
        as your GitHub API token has sufficient permissions.

    `zizmor` can also fetch workflows directly from GitHub, if given a
    GitHub API token via `GH_TOKEN` or `--gh-token`:

    ```bash
    # audit all workflows in woodruffw/zizmor
    # assumes you have `gh` installed
    zizmor --gh-token=$(gh auth token) woodruffw/zizmor
    ```

    Multiple repositories will also work:

    ```bash
    zizmor --gh-token=$(gh auth token) woodruffw/zizmor woodruffw/gha-hazmat
    ```

See [Usage](./usage.md) for more examples, including examples of configuration.
