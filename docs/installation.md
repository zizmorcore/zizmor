---
description: Installation instructions for zizmor.
---

# Installation

## From package managers

`zizmor` is available within several packaging ecosystems.

=== ":simple-rust: crates.io"

    ![Crates.io Version](https://img.shields.io/crates/v/zizmor)

    You can install `zizmor` from <https://crates.io> with `cargo`:

    ```bash
    cargo install --locked zizmor
    ```

=== ":simple-homebrew: Homebrew"

    ![Homebrew Formula Version](https://img.shields.io/homebrew/v/zizmor)

    `zizmor` is provided by [Homebrew](https://brew.sh/):

    ```bash
    brew install zizmor
    ```

=== ":simple-pypi: PyPI"

    ![PyPI - Version](https://img.shields.io/pypi/v/zizmor)

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

    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/version.svg)](https://anaconda.org/conda-forge/zizmor)
    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/latest_release_date.svg)](https://anaconda.org/conda-forge/zizmor)
    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/platforms.svg)](https://anaconda.org/conda-forge/zizmor)

    !!! note

        This is a community-maintained package.

    `zizmor` is available on Anaconda's conda-forge:

    ```bash
    conda install conda-forge::zizmor
    ```

    See [conda-forge/zizmor](https://anaconda.org/conda-forge/zizmor)
    for additional information.


=== ":material-nix: Nix"

    [![nixpkgs unstable package](https://repology.org/badge/version-for-repo/nix_unstable/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    ```bash
    # without flakes
    nix-env -iA nixos.zizmor

    # with flakes
    nix profile install nixpkgs#zizmor
    ```

=== ":simple-archlinux: Arch Linux"

    [![Arch Linux package](https://repology.org/badge/version-for-repo/arch/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    ```bash
    # zizmor-git is also available in the AUR
    pacman -S zizmor
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
