#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
from pathlib import Path

_HERE = Path(__file__).parent
_ARCHIVED_ACTION_REPOS = _HERE / "archived-action-repos.txt"

assert _ARCHIVED_ACTION_REPOS.is_file(), f"Missing {_ARCHIVED_ACTION_REPOS}"

_OUT = _HERE.parent / "crates" / "zizmor" / "data" / "archived-repos.txt"


def main() -> None:
    lines = []
    for line in _ARCHIVED_ACTION_REPOS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        lines.append(line.lower())

    lines.sort()

    with _OUT.open("w") as io:
        print("\n".join(lines), file=io)


if __name__ == "__main__":
    main()
