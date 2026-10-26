#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from pathlib import Path

_VERSION = re.compile(r'(?m)^__version__ = "([^"]+)"')
_ALLOWED_FILES = {
    "pyproject.toml",
    "PKG-INFO",
    ".gitignore",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
}
_ALLOWED_PREFIXES = ("mcp_cross_exam/", "tests/")
_REQUIRED_URLS = (
    "https://github.com/smusali/mcp-cross-exam",
    "https://github.com/smusali/mcp-cross-exam/issues",
    "https://github.com/smusali/mcp-cross-exam/blob/main/CHANGELOG.md",
)


def _version(root: Path) -> str:
    init = (root / "mcp_cross_exam" / "__init__.py").read_text(encoding="utf-8")
    match = _VERSION.search(init)
    if match is None:
        print("__version__ missing from mcp_cross_exam/__init__.py", file=sys.stderr)
        raise SystemExit(1)
    return match.group(1)


def _check_wheel(wheel: Path, version: str) -> int:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if "mcp_cross_exam/py.typed" not in names:
            print("wheel is missing mcp_cross_exam/py.typed", file=sys.stderr)
            return 1
        meta_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(meta_names) != 1:
            print("wheel is missing METADATA", file=sys.stderr)
            return 1
        meta = archive.read(meta_names[0]).decode("utf-8")
    lines = meta.splitlines()
    required = [
        f"Version: {version}",
        "License-Expression: MIT",
        "Requires-Python: >=3.11",
    ]
    for item in required:
        if item not in lines:
            print(f"wheel METADATA missing {item}", file=sys.stderr)
            return 1
    for url in _REQUIRED_URLS:
        if url not in meta:
            print(f"wheel METADATA missing {url}", file=sys.stderr)
            return 1
    return 0


def _relative_sdist_paths(archive: tarfile.TarFile) -> list[str]:
    names = archive.getnames()
    if not names:
        return []
    top = names[0].split("/", 1)[0]
    prefix = f"{top}/"
    relative: list[str] = []
    for name in names:
        if name == top:
            continue
        if name.startswith(prefix):
            relative.append(name[len(prefix) :])
        else:
            relative.append(name)
    return relative


def _allowed(path: str) -> bool:
    if path in _ALLOWED_FILES or path in {item.rstrip("/") for item in _ALLOWED_PREFIXES}:
        return True
    return any(path.startswith(prefix) for prefix in _ALLOWED_PREFIXES)


def _check_sdist(sdist: Path) -> int:
    with tarfile.open(sdist) as archive:
        relative = _relative_sdist_paths(archive)
    blocked = ("docs/", "tools/", ".github/")
    for path in relative:
        if path.startswith(blocked) or not _allowed(path):
            print(f"sdist contains unexpected path {path}", file=sys.stderr)
            return 1
    return 0


def main(root: Path) -> int:
    version = _version(root)
    wheels = list((root / "dist").glob("mcp_cross_exam-*-py3-none-any.whl"))
    sdists = list((root / "dist").glob("mcp_cross_exam-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected one wheel and one sdist, found {wheels} {sdists}", file=sys.stderr)
        return 1
    return _check_wheel(wheels[0], version) or _check_sdist(sdists[0])


if __name__ == "__main__":
    raise SystemExit(main(Path.cwd()))
