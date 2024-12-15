#!/usr/bin/env python

# render-trophies: take trophies.txt and produce a pretty
# mkdocs-material card grid list from it

from pathlib import Path

_TROPHIES = Path(__file__).parent / "trophies.txt"

_TEMPLATE = """
-   ![](https://github.com/{org}.png?size=40){{ width=\"40\" loading=lazy align=left }} {org}/{repo}

    ---

    {trophy}"""

for trophy in sorted(_TROPHIES.open().readlines()):
    trophy = trophy.strip()
    if not trophy or trophy.startswith("#"):
        continue

    org, rest = trophy.split("/")
    if "#" in rest:
        repo, _ = rest.split("#")
    else:
        repo, _ = rest.split("@")

    # NOTE: We request 40x40 from GitHub, but sometimes it gives us a bigger one.
    # Consequently, we also style with `width` to keep things consistent.
    print(_TEMPLATE.format(org=org, repo=repo, trophy=trophy))
