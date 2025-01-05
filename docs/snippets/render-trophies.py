#!/usr/bin/env python

# render-trophies: take trophies.txt and produce a pretty
# mkdocs-material card grid list from it

from collections import defaultdict
from pathlib import Path

_TROPHIES = Path(__file__).parent / "trophies.txt"

_TEMPLATE = """
-   ![](https://github.com/{org}.png?size=40){{ width=\"40\" loading=lazy align=left }} {org}

    ---

    ??? example "Examples"
{trophies}
"""

by_org = defaultdict(list)

for trophy in _TROPHIES.open().readlines():
    trophy = trophy.strip()
    if not trophy or trophy.startswith("#"):
        continue

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
