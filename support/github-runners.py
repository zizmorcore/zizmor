#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///


"""
Updates our list of official GitHub runners from GitHub's documentation.

Annoyingly, GitHub does not provide a machine-readable source for these.
Instead, we pull them from GitHub's documentation (as Markdown) with a
small `html.parser` adapter.
"""

import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

_SOURCES = [
    # This page lists the "normal" ubuntu/windows/macos labels.
    "https://docs.github.com/api/article/body?pathname=/en/actions/reference/runners/github-hosted-runners",
    # This page lists the `-large`/`-xlarge` variant labels.
    "https://docs.github.com/api/article/body?pathname=/en/actions/reference/runners/larger-runners",
]

_OUTPUT_FILE = Path("crates/zizmor/data/github-runners.txt")

# Every GitHub-hosted runner label starts with a known OS prefix.
_KNOWN_OS_PREFIXES = ("ubuntu", "macos", "windows")

# A well-formed runner label is a known OS prefix followed by lowercase
# alphanumeric segments joined by single dots or dashes.
_LABEL_RE = re.compile(
    r"(?:" + "|".join(_KNOWN_OS_PREFIXES) + r")-[a-z0-9]+(?:[.-][a-z0-9]+)*"
)


def _debug(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


class _CodeCollector(HTMLParser):
    """Collects the text content of every `<code>` element."""

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._current: list[str] = []
        self.codes: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag == "code":
            if self._depth == 0:
                self._current = []
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._depth > 0:
            self._depth -= 1
            if self._depth == 0:
                self.codes.append("".join(self._current).strip())

    def handle_data(self, data: str) -> None:
        if self._depth > 0:
            self._current.append(data)


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")


def _runner_labels() -> list[str]:
    labels: set[str] = set()
    for url in _SOURCES:
        _debug(f"fetching {url}")
        parser = _CodeCollector()
        parser.feed(_fetch(url))
        for code in parser.codes:
            if not code:
                continue
            if not _LABEL_RE.fullmatch(code):
                raise ValueError(
                    f"unexpected runner label {code!r} from {url}; "
                    "GitHub's docs format may have changed"
                )
            labels.add(code)

    if not labels:
        raise ValueError(
            "found no runner labels; GitHub's docs format may have changed"
        )

    return sorted(labels)


def main() -> None:
    labels = _runner_labels()
    _OUTPUT_FILE.write_text(
        "".join(f"{label}\n" for label in labels),
        encoding="utf-8",
    )
    _debug(f"wrote {len(labels)} runner labels to {_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
