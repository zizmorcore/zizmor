import os

import pytest

from bench.common import zizmor


@pytest.mark.skipif("GH_TOKEN" not in os.environ, reason="GH_TOKEN not set")
def test_zizmor_online_grafana_9f212d11d0ac(benchmark):
    """
    Runs `zizmor --format=plain --no-exit-codes --no-config grafana/grafana@9f212d11d0ac`
    """

    benchmark.pedantic(
        zizmor,
        args=(
            [
                "--format=plain",
                "--no-exit-codes",
                "--no-config",
                "grafana/grafana@9f212d11d0ac",
            ],
        ),
        warmup_rounds=2,
        iterations=10,
    )


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
