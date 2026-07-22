#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "referencing>=0.37.0",
#     "urllib3>=2.7.0",
# ]
# ///

# fetch-schemas.py: fetch each of our JSON schemas,
# dereference any remote references, and save the
# dereferenced (local-only) schema for use.

import functools
import sys
import json
import urllib3
import referencing

from referencing.jsonschema import DRAFT7
from pathlib import Path

_SCHEMAS: list[tuple[str, str]] = [
    ("https://www.schemastore.org/github-workflow.json", "github-workflow.json"),
    ("https://www.schemastore.org/github-action.json", "github-action.json"),
    ("https://www.schemastore.org/dependabot-2.0.json", "dependabot-2.0.json"),
    ("https://www.schemastore.org/pre-commit-config.json", "pre-commit-config.json"),
    ("https://www.schemastore.org/pre-commit-hooks.json", "pre-commit-hooks.json"),
]

_HERE = Path(__file__).parent # .../support dir
_TARGET_DIR = _HERE.parent / "crates/zizmor/src/data"

assert _TARGET_DIR.is_dir()

def _log(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def _fetch(url: str) -> bytes:
    resp = urllib3.request("GET", url)
    if resp.status != 200:
        raise RuntimeError(f"failed to fetch {url}: HTTP {resp.status}")
    return resp.data


# NB: cached because `referencing.Registry` is immutable and doesn't
# retain retrieved resources across top-level lookups.
@functools.cache
def _retrieve(uri: str) -> referencing.Resource:
    _log(f"Fetching remote reference target: {uri}")
    return referencing.Resource.from_contents(
        json.loads(_fetch(uri)), default_specification=DRAFT7
    )


def _dereference(node, resolver, *, inline_local: bool, stack: tuple = ()):
    """
    Recursively walk `node`, inlining every remote `$ref`.

    Same-document refs (`#/...`) are left intact in the root schema,
    since their targets ship with the document. Inside an inlined remote
    subtree (`inline_local=True`) even "local" refs are inlined, since
    they point into the remote document, not the host document.
    """
    match node:
        case {"$ref": str(ref)} if inline_local or not ref.startswith("#"):
            resolved = resolver.lookup(ref)
            key = id(resolved.contents)
            if key in stack:
                raise RuntimeError(f"circular remote reference via {ref!r}")
            inlined = _dereference(
                resolved.contents,
                resolved.resolver,
                inline_local=True,
                stack=(*stack, key),
            )
            # Preserve any annotation siblings of the $ref (e.g. description).
            siblings = {
                k: _dereference(v, resolver, inline_local=inline_local, stack=stack)
                for k, v in node.items()
                if k != "$ref"
            }
            if siblings and isinstance(inlined, dict):
                inlined = {**inlined, **siblings}
            return inlined
        case dict():
            return {
                k: _dereference(v, resolver, inline_local=inline_local, stack=stack)
                for k, v in node.items()
            }
        case list():
            return [
                _dereference(v, resolver, inline_local=inline_local, stack=stack)
                for v in node
            ]
        case _:
            return node


def main() -> None:
    registry = referencing.Registry(retrieve=_retrieve)

    for schema_url, schema_basename in _SCHEMAS:
        _log(f"Performing fetch: {schema_basename} ({schema_url!r})")
        raw = _fetch(schema_url)
        raw_schema = json.loads(raw)

        resource = referencing.Resource.from_contents(
            raw_schema, default_specification=DRAFT7
        )
        resolver = registry.resolver_with_root(resource)

        schema = _dereference(raw_schema, resolver, inline_local=False)

        target = _TARGET_DIR / schema_basename
        if schema == raw_schema:
            _log("No changes during unrolling, emitting upstream schema verbatim")
            # Nothing was inlined; keep upstream's bytes exactly so that
            # regeneration diffs show only genuine upstream changes.
            target.write_bytes(raw)
        else:
            with target.open("w", encoding="utf-8") as io:
                json.dump(schema, io, indent=2, ensure_ascii=False)
                io.write("\n")
        _log(f"Wrote {target}")


if __name__ == "__main__":
    main()
