#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from http import HTTPStatus
from urllib.parse import quote

CHOSEN = "mcp-cross-exam"
FALLBACK = "mcp-scrutineer"
OWN_REPOSITORY = "smusali/mcp-cross-exam"

USER_AGENT = "mcp-cross-exam-name-check"
SIMPLE_INDEX = "https://pypi.org/simple/"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


def ultranormalize(name: str) -> str:
    lowered = name.lower().translate(str.maketrans("oli", "011"))
    return re.sub(r"[-_.]+", "", lowered)


def http_status(url: str) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def read_json(url: str, accept: str) -> tuple[int, object]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": accept},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return int(response.status), json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def pypi_keys() -> dict[str, list[str]]:
    request = urllib.request.Request(
        SIMPLE_INDEX,
        headers={"Accept": SIMPLE_JSON, "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise TypeError("PyPI index is not an object")
    projects = payload.get("projects")
    if not isinstance(projects, list):
        raise TypeError("PyPI index has no project list")
    keys: dict[str, list[str]] = {}
    for project in projects:
        if not isinstance(project, dict):
            continue
        name = project.get("name")
        if not isinstance(name, str):
            continue
        keys.setdefault(ultranormalize(name), []).append(name)
    return keys


def verdict(status: int) -> str:
    if status == HTTPStatus.NOT_FOUND:
        return "free"
    if status == HTTPStatus.OK:
        return "taken"
    return f"unknown (HTTP {status})"


def github_repositories(name: str) -> str:
    found: list[str] = []
    for page in range(1, 6):
        url = (
            "https://api.github.com/search/repositories"
            f"?q={quote(name)}+in:name&per_page=100&page={page}"
        )
        status, payload = read_json(url, "application/vnd.github+json")
        if status != HTTPStatus.OK or not isinstance(payload, dict):
            return f"unknown (HTTP {status})"
        items = payload.get("items")
        if not isinstance(items, list):
            return "unknown (HTTP 200)"
        for item in items:
            if not isinstance(item, dict):
                continue
            repo_name = item.get("name")
            full_name = item.get("full_name")
            if repo_name != name or not isinstance(full_name, str):
                continue
            if full_name == OWN_REPOSITORY:
                continue
            found.append(full_name)
        total = payload.get("total_count")
        if not isinstance(total, int) or page * 100 >= total:
            break
    if found:
        return "taken by " + ", ".join(sorted(set(found)))
    return "free"


def check(name: str, keys: dict[str, list[str]]) -> bool:
    key = ultranormalize(name)
    similar = keys.get(key, [])
    rows = [
        (
            f"PyPI near-match ({key})",
            f"taken by {', '.join(similar)}" if similar else "free",
        ),
        (
            "PyPI project",
            verdict(http_status(f"https://pypi.org/pypi/{quote(name)}/json")),
        ),
        (
            "npm package",
            verdict(http_status(f"https://registry.npmjs.org/{quote(name)}")),
        ),
        (
            "GitHub user or org",
            verdict(http_status(f"https://api.github.com/users/{quote(name)}")),
        ),
        ("GitHub repositories", github_repositories(name)),
    ]
    print(name)
    for label, result in rows:
        print(f"  {label:<34} {result}")
    return not any(result.startswith("taken") for _, result in rows)


def main(argv: list[str]) -> int:
    names = argv or [CHOSEN, FALLBACK]
    keys = pypi_keys()
    print(f"PyPI projects indexed: {sum(len(projects) for projects in keys.values())}")
    results = [check(name, keys) for name in names]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
