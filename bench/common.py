import subprocess
from pathlib import Path

_HERE = Path(__file__).parent
_ZIZMOR = _HERE.parent / "target" / "release" / "zizmor"


def zizmor(args: list[str], *, check: bool = False) -> None:
    assert _ZIZMOR.is_file(), (
        f"zizmor binary not found at {_ZIZMOR}, run prepare() first"
    )
    subprocess.run([str(_ZIZMOR), *args], check=check)
