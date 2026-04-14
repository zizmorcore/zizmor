import os

import pytest

from bench.common import zizmor


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
def test_zizmor_online_gha_hazmat_da3c3cd(benchmark):
    """
    Runs `zizmor --format=plain --no-exit-codes --no-config woodruffw/gha-hazmat@da3c3cd`
    """

    benchmark.pedantic(
        zizmor,
        args=(
            [
                "--format=plain",
                "--no-exit-codes",
                "--no-config",
                "woodruffw/gha-hazmat@da3c3cd",
            ],
        ),
        warmup_rounds=2,
        iterations=10,
    )


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
def test_zizmor_online_cpython_48f88310044c(benchmark):
    """
    Runs `zizmor --format=plain --no-exit-codes --no-config python/cpython@48f88310044c`
    """

    benchmark.pedantic(
        zizmor,
        args=(
            [
                "--format=plain",
                "--no-exit-codes",
                "--no-config",
                "python/cpython@48f88310044c",
            ],
        ),
        warmup_rounds=2,
        iterations=10,
    )


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
def test_zizmor_online_collect_workflows_fast_path(benchmark):
    """
    Tests the performance of the `--collect=workflows` fast path, which should
    be much faster than retrieving the entire repository.
    """

    benchmark.pedantic(
        zizmor,
        args=(
            [
                "--collect=workflows",
                "--format=plain",
                "--no-exit-codes",
                "--no-config",
                "python/cpython@48f88310044c",
            ],
        ),
        warmup_rounds=2,
        iterations=10,
    )
