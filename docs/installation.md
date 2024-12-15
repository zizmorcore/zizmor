---
description: Installation instructions for zizmor.
---

# Installation

## From package managers

`zizmor` is available within several packaging ecosystems.

=== ":simple-rust: crates.io"

    You can install `zizmor` from <https://crates.io> with `cargo`:

    ```bash
    cargo install zizmor
    ```

=== ":simple-homebrew: Homebrew"

    `zizmor` is provided by [Homebrew](https://brew.sh/):

    ```bash
    brew install zizmor
    ```

=== ":simple-pypi: PyPI"

    !!! tip

        Despite being available on PyPI, `zizmor` is a compiled binary
        and has no Python or Python package dependencies.


    `zizmor` is available on [PyPI](https://pypi.org) and can be installed
    with any Python package installer:

    ```bash
    # with pip
    pip install zizmor

    # with pipx
    pipx install zizmor

    # with uv
    uv tool install zizmor

    # or, shortcut:
    uvx zizmor --help
    ```

=== ":simple-anaconda: Conda"

    !!! note

        This is a community-maintained package.

    `zizmor` is available on Anaconda's conda-forge:

    ```bash
    conda install conda-forge::zizmor
    ```

    See [conda-forge/zizmor](https://anaconda.org/conda-forge/zizmor)
    for additional information.


=== ":material-nix: Nix"

    !!! note

        This is a community-maintained package.

    ```bash
    # without flakes
    nix-env -iA nixos.zizmor

    # with flakes
    nix profile install nixpkgs#zizmor
    ```

=== "Other ecosystems"

    !!! info

        Are you interested in packaging `zizmor` for another ecosystem?
        Let us know by [filing an issue](https://github.com/woodruffw/zizmor/issues/new)!

    The badge below tracks `zizmor`'s overall packaging status.

    [![Packaging status](https://repology.org/badge/vertical-allrepos/zizmor.svg)](https://repology.org/project/zizmor/versions)



## From source

!!! warning

    Most ordinary users **should not** install directly from `zizmor`'s
    source repository. No stability or correctness guarantees are made about
    direct source installations.

You can install the latest unstable `zizmor` directly from GitHub with `cargo`:

```bash
cargo install --git https://github.com/woodruffw/zizmor
```
