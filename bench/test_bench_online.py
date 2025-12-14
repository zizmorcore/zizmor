import os

import pytest

from bench.common import zizmor


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
@pytest.mark.benchmark
def test_zizmor_online_gha_hazmat_da3c3cd():
    """
    Runs `zizmor --format=plain --no-exit-codes --no-config woodruffw/gha-hazmat@da3c3cd`
    """

    zizmor(
        [
            "--format=plain",
            "--no-exit-codes",
            "--no-config",
            "woodruffw/gha-hazmat@da3c3cd",
        ],
        check=True,
    )


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
@pytest.mark.benchmark
def test_zizmor_online_cpython_48f88310044c():
    """
    Runs `zizmor --format=plain --no-exit-codes --no-config python/cpython@48f88310044c`
    """

    zizmor(
        [
            "--format=plain",
            "--no-exit-codes",
            "--no-config",
            "python/cpython@48f88310044c",
        ],
        check=True,
    )
