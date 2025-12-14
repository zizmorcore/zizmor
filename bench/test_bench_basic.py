import pytest

from .common import zizmor


@pytest.mark.benchmark
def test_zizmor_startup():
    zizmor(["--version"])
