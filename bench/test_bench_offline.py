import io
import zipfile
from pathlib import Path

import pytest
import urllib3

from bench.common import zizmor


@pytest.fixture(scope="session")
def grafana(tmp_path_factory) -> Path:
    archive = "https://github.com/grafana/grafana/archive/9f212d11d0ac9c38ada62a7db830844bb9b02905.zip"
    raw_zip = urllib3.PoolManager().request("GET", archive).data

    path = tmp_path_factory.mktemp("grafana")

    zipfile.ZipFile(io.BytesIO(raw_zip)).extractall(path)

    return path


@pytest.fixture(scope="session")
def cpython(tmp_path_factory) -> Path:
    archive = "https://github.com/python/cpython/archive/48f88310044c6ef877f3b0761cf7afece2f8fb3a.zip"
    raw_zip = urllib3.PoolManager().request("GET", archive).data

    path = tmp_path_factory.mktemp("cpython")

    zipfile.ZipFile(io.BytesIO(raw_zip)).extractall(path)

    return path


@pytest.mark.benchmark
def test_zizmor_offline_grafana_9f212d11d0(grafana: Path):
    """
    Runs `zizmor --offline --format=plain --no-exit-codes --no-config <path-to-grafana-source>`
    """

    zizmor(
        [
            "--offline",
            "--format=plain",
            "--no-exit-codes",
            "--no-config",
            str(grafana),
        ],
        check=True,
    )


@pytest.mark.benchmark
def test_zizmor_offline_cpython_48f88310044c(cpython: Path):
    """
    Runs `zizmor --offline --format=plain --no-exit-codes --no-config <path-to-cpython-source>`
    """

    zizmor(
        [
            "--offline",
            "--format=plain",
            "--no-exit-codes",
            "--no-config",
            str(cpython),
        ],
        check=True,
    )
