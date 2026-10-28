#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_VERSION = re.compile(r'(?m)^__version__ = "([^"]+)"')
_UNRELEASED = re.compile(r"(?m)^## \[Unreleased\]\s*$")
_SECTIONS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
_LIMIT = 120
_CODE = re.compile(r"`[^`]*`")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def read_version(root: Path) -> str:
    init = (root / "src" / "mcp_cross_exam" / "__init__.py").read_text(encoding="utf-8")
    match = _VERSION.search(init)
    if match is None:
        raise SystemExit("__version__ missing from src/mcp_cross_exam/__init__.py")
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


def lint_text(changelog: str) -> list[str]:
    errors: list[str] = []
    if _UNRELEASED.search(changelog) is None:
        errors.append("missing Unreleased section")
    for part in re.split(r"(?m)^## ", changelog)[1:]:
        errors.extend(_release(part))
    return errors


def _release(body: str) -> list[str]:
    errors: list[str] = []
    names: list[str] = []
    for chunk in re.split(r"(?m)^### ", body)[1:]:
        lines = chunk.splitlines()
        name = lines[0].strip()
        names.append(name)
        if name not in _SECTIONS:
            errors.append(f"unknown section {name}")
            continue
        errors.extend(_section(name, lines[1:]))
    known = [name for name in names if name in _SECTIONS]
    if known != sorted(known, key=_SECTIONS.index):
        errors.append("sections are out of Keep a Changelog order")
    return errors


def _section(name: str, lines: list[str]) -> list[str]:
    bullets = [line[2:].strip() for line in lines if line.startswith("- ")]
    prose = [line for line in lines if line.strip() and not line.startswith("- ")]
    errors: list[str] = []
    if not bullets and not prose:
        errors.append(f"{name} is empty")
    if prose and bullets:
        errors.append(f"{name} mixes a sentence with a list")
    if len(bullets) == 1:
        errors.append(f"{name} is a one-item list")
    for bullet in bullets:
        if len(bullet) > _LIMIT:
            errors.append(f"{name} entry is longer than {_LIMIT} characters")
        plain = _CODE.sub("", bullet).strip()
        sentences = [part for part in _SENTENCE.split(plain) if part.strip()]
        if len(sentences) != 1 or not plain.endswith("."):
            errors.append(f"{name} entry must be one sentence")
    return errors


def main(argv: list[str]) -> int:
    root = Path.cwd()
    args = argv[1:]
    notes = False
    if args and args[0] == "--notes":
        notes = True
        args = args[1:]
    version = read_version(root)
    changelog = (root / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    errors = lint_text(changelog)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    tag = os.environ.get("REF_NAME")
    if tag is None and args:
        tag = args[0]
    if tag is None:
        if notes:
            print("REF_NAME is not set", file=sys.stderr)
            return 1
        return 0
    if tag != f"v{version}":
        print(f"tag {tag} does not match version {version}", file=sys.stderr)
        return 1
    body = section(changelog, version)
    if body is None:
        print(f"docs/CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    if notes:
        sys.stdout.write(body.strip() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
