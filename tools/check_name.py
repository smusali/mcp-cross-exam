"""Re-run the name checks recorded in docs/adr/0001-name.md.

Usage:

    python tools/check_name.py [NAME ...]

With no arguments, it checks the chosen name and the fallback. It needs
network access to pypi.org, test.pypi.org, registry.npmjs.org, and github.com.
It exits 1 if any check finds the name taken, and 0 otherwise. A check that
cannot get an answer (for example, a proxy returns 403) prints "unknown" and
does not fail the run.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from http import HTTPStatus

CHOSEN = "mcp-cross-exam"
FALLBACK = "mcp-scrutineer"

USER_AGENT = "mcp-cross-exam-name-check"
SIMPLE_INDEX = "https://pypi.org/simple/"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


def ultranormalize(name: str) -> str:
    """Return the key PyPI uses to reject a new name as too similar.

    This mirrors Warehouse's ``ultranormalize_name``: lowercase, map ``o`` to
    ``0`` and ``l`` and ``i`` to ``1``, then drop ``-``, ``_``, and ``.``.
    A new project is rejected if any existing project has the same key.
    """
    lowered = name.lower().translate(str.maketrans("oli", "011"))
    return re.sub(r"[-_.]+", "", lowered)


def http_status(url: str) -> int:
    """Return the HTTP status of a GET, including error statuses."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def pypi_keys() -> dict[str, list[str]]:
    """Map every PyPI project's ultranormalized key to its names."""
    request = urllib.request.Request(
        SIMPLE_INDEX, headers={"Accept": SIMPLE_JSON, "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        projects = json.load(response)["projects"]
    keys: dict[str, list[str]] = {}
    for project in projects:
        keys.setdefault(ultranormalize(project["name"]), []).append(project["name"])
    return keys


def verdict(status: int) -> str:
    """Read a registry lookup: 404 means free, 200 means taken."""
    if status == HTTPStatus.NOT_FOUND:
        return "free"
    if status == HTTPStatus.OK:
        return "taken"
    return f"unknown (HTTP {status})"


def check(name: str, keys: dict[str, list[str]]) -> bool:
    """Print one row per namespace and return True if nothing is taken."""
    key = ultranormalize(name)
    similar = keys.get(key, [])
    rows = [
        (
            f"PyPI near-match ({key})",
            f"taken by {', '.join(similar)}" if similar else "free",
        ),
        ("PyPI project", verdict(http_status(f"https://pypi.org/pypi/{name}/json"))),
        (
            "TestPyPI project",
            verdict(http_status(f"https://test.pypi.org/pypi/{name}/json")),
        ),
        ("npm package", verdict(http_status(f"https://registry.npmjs.org/{name}"))),
        (
            "Actions Marketplace slug",
            verdict(http_status(f"https://github.com/marketplace/actions/{name}")),
        ),
        ("GitHub user or org", verdict(http_status(f"https://github.com/{name}"))),
    ]
    print(name)
    for label, result in rows:
        print(f"  {label:<34} {result}")
    return not any(result.startswith("taken") for _, result in rows)


def main(argv: list[str]) -> int:
    """Check each name given, or the chosen name and the fallback."""
    names = argv or [CHOSEN, FALLBACK]
    keys = pypi_keys()
    print(f"PyPI projects indexed: {sum(len(v) for v in keys.values())}")
    results = [check(name, keys) for name in names]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
