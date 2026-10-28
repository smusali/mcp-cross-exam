#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

_HEADING = re.compile(r"(?m)^## (.+?)\s*$")
_ROW = re.compile(r"(?m)^\| (\d+) \| (.+?) \|$")


def main() -> int:
    root = Path.cwd()
    return _methodology(root) or _exits(root)


def _methodology(root: Path) -> int:
    from mcp_cross_exam.probes.base import Probe
    from mcp_cross_exam.runner import load_probes

    text = (root / "METHODOLOGY.md").read_text(encoding="utf-8")
    headings = set(_HEADING.findall(text))
    missing = [
        probe.id for probe in load_probes() if isinstance(probe, Probe) and probe.id not in headings
    ]
    if missing:
        print("methodology missing: " + ", ".join(missing), file=sys.stderr)
        return 1
    return 0


def _exits(root: Path) -> int:
    from mcp_cross_exam.exit_codes import EXIT_MEANINGS, ExitCode

    text = (root / "docs" / "USAGE.md").read_text(encoding="utf-8")
    found = {int(code): meaning.strip() for code, meaning in _ROW.findall(text)}
    expected = {int(code): meaning for code, meaning in EXIT_MEANINGS.items()}
    if set(found) != {int(code) for code in ExitCode} or found != expected:
        print("exit code table does not match the enum", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
