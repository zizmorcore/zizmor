#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
# ]
# ///


"""
Syncs expression test data from GitHub's actions/languageservices repository.

Downloads JSON test files from the upstream expressions/testdata directory
and writes them to crates/github-actions-expressions/tests/testdata/.
"""

import hashlib
import sys
from pathlib import Path

import requests

_UPSTREAM_REPO = "actions/languageservices"
_UPSTREAM_PATH = "expressions/testdata"
_OUTPUT_DIR = Path("crates/github-actions-expressions/tests/testdata")
_SHA_FILE = _OUTPUT_DIR / ".upstream-sha"
_API_BASE = "https://api.github.com"


def _git_blob_sha(data: bytes) -> str:
    """Compute the git blob SHA-1 for the given content."""
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def _log(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def _get(url: str) -> requests.Response:
    resp = requests.get(url)
    resp.raise_for_status()
    return resp


def main() -> None:
    # Read last-synced SHA if it exists
    last_sha = None
    if _SHA_FILE.exists():
        last_sha = _SHA_FILE.read_text().strip()
        _log(f"last synced SHA: {last_sha}")

    # Get the latest commit SHA touching testdata
    commits_url = (
        f"{_API_BASE}/repos/{_UPSTREAM_REPO}/commits"
        f"?path={_UPSTREAM_PATH}&per_page=1"
    )
    commits = _get(commits_url).json()
    latest_sha = commits[0]["sha"]
    _log(f"latest upstream SHA: {latest_sha}")

    if last_sha == latest_sha:
        _log("already up to date")
        return

    # List files in the testdata directory
    contents_url = (
        f"{_API_BASE}/repos/{_UPSTREAM_REPO}/contents/{_UPSTREAM_PATH}"
    )
    entries = _get(contents_url).json()

    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    count = 0
    for entry in entries:
        name = entry["name"]
        if not name.endswith(".json"):
            continue

        dest = _OUTPUT_DIR / name
        upstream_sha = entry["sha"]

        if dest.exists() and _git_blob_sha(dest.read_bytes()) == upstream_sha:
            _log(f"skipping {name} (unchanged)")
            continue

        download_url = entry["download_url"]
        _log(f"downloading {name}")
        content = _get(download_url).text

        dest.write_text(content)
        count += 1

    # Write the new SHA
    _SHA_FILE.write_text(latest_sha + "\n")

    _log(f"synced {count} files to {_OUTPUT_DIR}")


if __name__ == "__main__":
    main()
