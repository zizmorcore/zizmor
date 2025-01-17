#!/usr/bin/env python

# render-sponsors: take sponsors.json and produce pretty tables
# in the README and website index for each of our wonderful sponsors

import json
import re
from pathlib import Path

_SPONSORS_HTML = """
<!-- @@begin-sponsors@@ -->
<table>
<tbody>
<tr>
{all_sponsors}
</tr>
</tbody>
</table>
<!-- @@end-sponsors@@ -->
"""

_SPONSOR_HTML = """
<td align="center" valign="top" width="15%">
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

all_sponsors = "\n".join(
    [_SPONSOR_HTML.format(**sponsor).strip() for sponsor in _SPONSORS]
)
sponsors_html = _SPONSORS_HTML.format(all_sponsors=all_sponsors).strip()

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
