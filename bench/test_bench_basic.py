import pytest

from .common import zizmor


@pytest.mark.benchmark
def test_zizmor_startup():
    zizmor(["--version"])


@pytest.mark.benchmark
def test_zizmor_help():
    zizmor(["--help"])
