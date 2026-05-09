#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# ///

# render-trophies: take trophies.txt and produce a pretty
# mkdocs-material card grid list from it.
#
# As a side effect, normalizes GitHub URLs and sorts trophies.txt in place
# (case-insensitively).

import re
from collections import defaultdict
from pathlib import Path

_TROPHIES = Path(__file__).parent / "trophies.txt"

_URL_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/(pull|commit)/([^/?#\s]+)/?$"
)

_TEMPLATE = """
-   ![](https://github.com/{org}.png?size=40){{ width=\"40\" loading=lazy align=left }} {org}

    ---

    ??? example "Examples"
{trophies}
"""


def normalize(entry: str) -> str:
    m = _URL_RE.match(entry)
    if not m:
        return entry
    org, repo, kind, ident = m.groups()
    sep = "#" if kind == "pull" else "@"
    return f"{org}/{repo}{sep}{ident}"


def normalize_and_sort_in_place() -> list[str]:
    header: list[str] = []
    entries: set[str] = set()
    in_header = True
    for line in _TROPHIES.read_text().splitlines():
        stripped = line.strip()
        if in_header and (not stripped or stripped.startswith("#")):
            header.append(line)
            continue
        in_header = False
        if stripped and not stripped.startswith("#"):
            entries.add(normalize(stripped))

    sorted_entries = sorted(entries, key=str.lower)
    _TROPHIES.write_text("\n".join(header + sorted_entries) + "\n")
    return sorted_entries


by_org = defaultdict(list)

for trophy in normalize_and_sort_in_place():
    org, rest = trophy.split("/")
    if "#" in rest:
        repo, _ = rest.split("#")
    else:
        repo, _ = rest.split("@")

    by_org[org].append(trophy)


for org, trophies in sorted(by_org.items(), key=lambda t: t[0].lower()):
    # NOTE: We request 40x40 from GitHub, but sometimes it gives us a bigger one.
    # Consequently, we also style with `width` to keep things consistent.
    trophies = [f"        - {trophy}" for trophy in trophies]
    print(_TEMPLATE.format(org=org, trophies="\n".join(trophies)))
