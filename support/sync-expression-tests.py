#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///


"""
Syncs expression test data from GitHub's actions/languageservices repository.
The expression test suite is there:
https://github.com/actions/languageservices/tree/main/expressions/testdata
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_UPSTREAM_REPO = "https://github.com/actions/languageservices.git"
_UPSTREAM_PATH = "expressions/testdata"
_OUTPUT_DIR = Path("crates/github-actions-expressions/tests/testdata")


def _debug(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result


def _clone_testdata(temp_dir: Path) -> Path:
    _debug("Cloning languageservices repository with sparse checkout...")

    repo_path = temp_dir / "languageservices"
    repo_path.mkdir()

    _git(
        [
            "clone",
            "--filter=tree:0",
            "--no-checkout",
            "--depth=1",
            "--sparse",
            _UPSTREAM_REPO,
            ".",
        ],
        cwd=repo_path,
    )

    _git(
        [
            "sparse-checkout",
            "add",
            _UPSTREAM_PATH,
        ],
        cwd=repo_path,
    )

    _git(
        [
            "checkout",
        ],
        cwd=repo_path,
    )

    _debug("Successfully cloned languageservices repository")
    return repo_path


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            repo_path = _clone_testdata(Path(temp_dir))

            testdata_dir = repo_path / _UPSTREAM_PATH
            _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

            count = 0
            for src in testdata_dir.iterdir():
                if src.suffix != ".json":
                    continue

                dest = _OUTPUT_DIR / src.name
                shutil.copy2(src, dest)
                count += 1

            _debug(f"synced {count} files to {_OUTPUT_DIR}")

        except subprocess.CalledProcessError as e:
            _debug(f"Git command failed: {e.cmd}: {e.stderr}")
            raise


if __name__ == "__main__":
    main()
