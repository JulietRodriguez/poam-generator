"""Validate OSCAL JSON against NIST's published OSCAL JSON Schema.

Usage:
    python tools/validate_oscal.py --schema <schema.json> <document.json>

Schemas come from the OSCAL v1.1.2 GitHub release
(https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2). CI downloads the one it needs.

Why the regex rewrite: NIST's schema uses Unicode property escapes such as
``\\p{L}`` (letters) and ``\\p{N}`` (numbers) in token patterns. Python's ``re``
module, which the ``jsonschema`` library uses, doesn't support ``\\p{...}``, so
we translate those two classes to equivalent ``re`` classes before validating:
``\\p{L}`` -> ``[^\\W\\d_]`` (any Unicode letter) and ``\\p{N}`` -> ``\\d``.
Every other keyword in the schema is used as published.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator

_REWRITES = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def _rewrite(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                for src, dst in _REWRITES.items():
                    v = v.replace(src, dst)
            out[k] = _rewrite(v)
        return out
    if isinstance(node, list):
        return [_rewrite(v) for v in node]
    return node


def load_validator(schema_path: str | Path) -> Draft7Validator:
    schema = _rewrite(json.loads(Path(schema_path).read_text(encoding="utf-8")))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def validate(schema_path: str | Path, doc_path: str | Path) -> list[str]:
    validator = load_validator(schema_path)
    doc = json.loads(Path(doc_path).read_text(encoding="utf-8"))
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schema", required=True, help="path to the OSCAL JSON schema file")
    ap.add_argument("documents", nargs="+")
    args = ap.parse_args(argv)
    failed = False
    for doc in args.documents:
        errors = validate(args.schema, doc)
        if errors:
            failed = True
            print(f"FAIL {doc}: {len(errors)} schema error(s)")
            for e in errors[:50]:
                print(f"  - {e}")
        else:
            print(f"OK   {doc}: valid per {Path(args.schema).name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
