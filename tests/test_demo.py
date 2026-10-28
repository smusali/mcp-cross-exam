from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from mcp_cross_exam.transport.base import JsonValue, json_value

ROOT = Path(__file__).resolve().parents[1]
_SESSION = "session.expired-empty-success"
_SCHEMA = "schema.undeclared-required-arg"


def test_demo_matches_expected_findings(tmp_path: Path) -> None:
    out = tmp_path / "out"
    env = os.environ.copy()
    env["DEMO_OUT"] = str(out)
    env["NO_COLOR"] = "1"
    env.pop("DEMO_PAUSE", None)
    env.pop("DEMO_PORT", None)
    result = subprocess.run(
        [_bash(), str(ROOT / "demo" / "run.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 3, result.stderr
    rows = _rows(out / "report.json")
    found = {probe_id for probe_id, _name in rows}
    text = (ROOT / "demo" / "expected-findings.txt").read_text(encoding="utf-8")
    expected = {line.strip() for line in text.splitlines() if line.strip()}
    assert {_SESSION, _SCHEMA} <= found
    assert found == expected
    tools = {probe_id: name for probe_id, name in rows}
    assert tools[_SESSION] == "get_ticket"
    assert tools[_SCHEMA] == "create_ticket"


def _bash() -> str:
    found = shutil.which("bash")
    if found is not None:
        return found
    if sys.platform == "win32":
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            return str(git_bash)
    raise AssertionError("bash is required")


def _rows(path: Path) -> list[tuple[str, str]]:
    loaded = json_value(json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        raise AssertionError("report")
    raw = loaded.get("findings")
    if not isinstance(raw, list):
        raise AssertionError("findings")
    rows: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise AssertionError("finding")
        probe_id = item.get("probe_id")
        if not isinstance(probe_id, str):
            raise AssertionError("probe_id")
        rows.append((probe_id, _tool(item)))
    return rows


def _tool(item: dict[str, JsonValue]) -> str:
    tool = item.get("tool")
    if isinstance(tool, str) and tool:
        return tool
    repro = item.get("repro")
    if not isinstance(repro, dict):
        raise AssertionError("tool")
    command = repro.get("command")
    if not isinstance(command, str):
        raise AssertionError("tool")
    parts = command.split()
    flag = "--tool"
    if flag not in parts:
        raise AssertionError("tool")
    index = parts.index(flag)
    if index + 1 >= len(parts):
        raise AssertionError("tool")
    return parts[index + 1]
