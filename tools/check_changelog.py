#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

_VERSION = re.compile(r'(?m)^__version__ = "([^"]+)"')
_UNRELEASED = re.compile(r"(?m)^## \[Unreleased\]\s*$")


def read_version(root: Path) -> str:
    init = (root / "mcp_cross_exam" / "__init__.py").read_text(encoding="utf-8")
    match = _VERSION.search(init)
    if match is None:
        raise SystemExit("__version__ missing from mcp_cross_exam/__init__.py")
    return match.group(1)


def section(changelog: str, version: str) -> str | None:
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(changelog)
    if match is None:
        return None
    return match.group(1)


def main(argv: list[str]) -> int:
    root = Path.cwd()
    args = argv[1:]
    notes = False
    if args and args[0] == "--notes":
        notes = True
        args = args[1:]
    tag = args[0] if args else None
    version = read_version(root)
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if _UNRELEASED.search(changelog) is None:
        print("CHANGELOG.md has no Unreleased section", file=sys.stderr)
        return 1
    if tag is None:
        return 0
    if tag != f"v{version}":
        print(f"tag {tag} does not match version {version}", file=sys.stderr)
        return 1
    body = section(changelog, version)
    if body is None:
        print(f"CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    if notes:
        sys.stdout.write(body.strip() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
