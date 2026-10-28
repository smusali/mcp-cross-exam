#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from mcp_cross_exam import VersionFacts
from mcp_cross_exam.findings import Report
from mcp_cross_exam.runner import ProbeRecord
from mcp_cross_exam.schema_audit import Snapshot

_DIRECTORY = Path("schemas")
_BASE = "https://github.com/smusali/mcp-cross-exam/blob/main/schemas"


def render() -> dict[str, str]:
    documents: dict[str, dict[str, object]] = {
        "report": Report.model_json_schema(),
        "snapshot": Snapshot.model_json_schema(),
        "probes": TypeAdapter(list[ProbeRecord]).json_schema(),
        "version": TypeAdapter(VersionFacts).json_schema(),
    }
    rendered: dict[str, str] = {}
    for name, schema in documents.items():
        schema["$id"] = f"{_BASE}/{name}.schema.json"
        rendered[name] = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    return rendered


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (sys.argv[1:] if argv is None else argv)
    documents = render()
    if not check:
        _DIRECTORY.mkdir(exist_ok=True)
    for name, payload in documents.items():
        path = _DIRECTORY / f"{name}.schema.json"
        if check:
            current = path.read_text(encoding="utf-8") if path.is_file() else ""
            if current != payload:
                print(f"{path} does not match the models", file=sys.stderr)
                return 1
            continue
        path.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
