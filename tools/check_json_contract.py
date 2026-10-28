#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp_cross_exam.transport.base import json_value

V1_FIELDS = frozenset(
    {
        "schema_version",
        "tool",
        "target",
        "server",
        "run",
        "coverage",
        "score",
        "score_version",
        "findings",
    }
)


def main() -> int:
    root = Path.cwd()
    schema_path = root / "mcp_cross_exam" / "report.v1.json"
    schema = json_value(json.loads(schema_path.read_text(encoding="utf-8")))
    if not isinstance(schema, dict):
        print("report schema is not an object", file=sys.stderr)
        return 1
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        print("report schema is missing properties", file=sys.stderr)
        return 1
    names = frozenset(key for key in properties if isinstance(key, str))
    version = properties.get("schema_version")
    if isinstance(version, dict) and version.get("const") == 1 and names != V1_FIELDS:
        print("schema_version 1 fields changed", file=sys.stderr)
        return 1
    from mcp_cross_exam.findings import Report

    model_fields = frozenset(Report.model_fields)
    if model_fields != names:
        print("report model and schema fields differ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
