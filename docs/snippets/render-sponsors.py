#!/usr/bin/env -S uv run --script --locked
# /// script
# requires-python = ">=3.13"
# ///

# render-sponsors: take sponsors.json and produce pretty tables
# in the README and website index for each of our wonderful sponsors

import json
import re
from itertools import batched
from pathlib import Path

_SPONSORS_HTML = """
<!-- @@begin-sponsors@@ -->
<table width="100%">
<caption>Logo-level sponsors</caption>
<tbody>
{logo_sponsors}
</tbody>
</table>
<hr align="center">
<table width="100%">
<caption>Name-level sponsors</caption>
<tbody>
<tr>
{name_sponsors}
</tr>
</tbody>
</table>
<!-- @@end-sponsors@@ -->
"""

_SPONSOR_NAME_HTML = """
<td align="center" valign="top">
<a href="{url}">
{name}
</a>
</td>
"""

_SPONSOR_LOGO_HTML = """
<td align="center" valign="top" width="25%" colspan="2">
<a href="{url}">
<img src="{img}" width="100px">
<br>
{name}
</a>
</td>
"""

_HERE = Path(__file__).parent

_SPONSORS = json.loads((_HERE / "sponsors.json").read_bytes())
_README = _HERE.parent.parent / "README.md"

assert _README.is_file()

logo_sponsors = []
name_sponsors = []
for sponsor in _SPONSORS:
    if sponsor.get("former", False):
        continue  # skip former sponsors
    if "img" in sponsor:
        logo_sponsors.append(_SPONSOR_LOGO_HTML.format(**sponsor).strip())
    else:
        name_sponsors.append(_SPONSOR_NAME_HTML.format(**sponsor).strip())

# Each logo spans two of eight columns, allowing half-cell padding on either side.
logo_rows = []
for row in batched(logo_sponsors, 4):
    cells = "\n".join(row)
    padding = 4 - len(row)
    if padding:
        spacer = f'<td colspan="{padding}" width="{padding * 12.5:g}%"></td>'
        cells = f"{spacer}\n{cells}\n{spacer}"
    logo_rows.append(f"<tr>\n{cells}\n</tr>")

sponsors_html = _SPONSORS_HTML.format(
    logo_sponsors="\n".join(logo_rows), name_sponsors="\n".join(name_sponsors)
).strip()

readme = _README.read_text()

readme = re.sub(
    r"<!-- @@begin-sponsors@@ -->.+<!-- @@end-sponsors@@ -->",
    sponsors_html,
    readme,
    count=1,
    flags=re.S,
)

_README.write_text(readme)

print(sponsors_html)
