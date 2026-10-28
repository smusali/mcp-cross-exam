from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path

import anyio
import hypothesis.strategies as st
import pytest
from hypothesis import assume, given
from hypothesis import settings as hypothesis_settings
from mcp_cross_exam.cli import main
from mcp_cross_exam.evidence import (
    BODY_LIMIT,
    bound_body,
    build_exchanges,
    curl_command,
    placeholder,
    redact_text,
    sweep_tree,
)
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.fixture import VALID_TOKEN
from mcp_cross_exam.transport.base import JsonValue, json_value, make_frame
from mcp_cross_exam.transport.http import open_http

from tests.conftest import start_fixture

_SECRET = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=8, max_size=24)
_NOISE = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=0, max_size=20)


@given(secret=_SECRET, noise=_NOISE)
@hypothesis_settings(max_examples=40, deadline=None)
def test_secret_windows_do_not_survive(secret: str, noise: str) -> None:
    marker = placeholder(secret)
    windows = [
        secret[index : index + size]
        for size in range(8, len(secret) + 1)
        for index in range(len(secret) - size + 1)
    ]
    assume(all(window not in marker for window in windows))
    cleaned = redact_text(json.dumps({"authorization": secret, "note": noise}), [secret])
    assert cleaned == redact_text(cleaned, [secret])
    for window in windows:
        assert window not in cleaned


def test_truncation_keeps_the_full_hash() -> None:
    body = b'{"blob":"' + (b"a" * (BODY_LIMIT + 32)) + b'"}'
    kept, truncated, size, digest = bound_body(body)
    assert truncated
    assert size == len(body)
    assert digest == hashlib.sha256(body).hexdigest()
    assert kept == body[:BODY_LIMIT]
    records = build_exchanges(
        (make_frame(direction="outbound", body=body),),
        (),
        probe_id="transport.unknown-method",
        start=1,
    )
    request = records[0]["request"]
    assert isinstance(request, dict)
    assert request["truncated"] is True
    assert request["original_size"] == len(body)
    assert request["body_sha256"] == digest


def test_curl_uses_the_env_name() -> None:
    text = curl_command(
        url="http://127.0.0.1/mcp",
        method="POST",
        headers={"Authorization": f"Bearer {VALID_TOKEN}", "Accept": "application/json"},
        body=f'{{"token":"{VALID_TOKEN}"}}'.encode(),
        bearer_env="MCP_TOKEN",
        header_envs={},
        secrets=(VALID_TOKEN,),
    )
    assert VALID_TOKEN not in text
    assert "$MCP_TOKEN" in text


def test_bearer_bytes_do_not_survive_the_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_TOKEN", VALID_TOKEN)
    with start_fixture() as port:
        with pytest.raises(SystemExit) as caught:
            main(["--bearer-env", "MCP_TOKEN", f"http://127.0.0.1:{port}/mcp"])
        assert caught.value.code == ExitCode.SUCCESS
    blob = b"".join(path.read_bytes() for path in (tmp_path / "runs").rglob("*") if path.is_file())
    assert VALID_TOKEN.encode() not in blob


def test_sweep_replaces_secret_bytes(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("prefix fixture-valid suffix", encoding="utf-8")
    sweep_tree(tmp_path, (VALID_TOKEN,))
    assert VALID_TOKEN not in path.read_text(encoding="utf-8")


def test_golden_repro_repeats_the_call(tmp_path: Path) -> None:
    with start_fixture(defects="session.expired-empty-success") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        with pytest.raises(SystemExit) as caught:
            main(["--probe", "session.expired-empty-success", url])
        assert caught.value.code == ExitCode.FINDINGS
        original = _only_run(tmp_path)
        saved = _object((original / "report.json").read_text(encoding="utf-8"))
        findings = saved.get("findings")
        assert isinstance(findings, list)
        commands: list[str] = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            repro = item.get("repro")
            if not isinstance(repro, dict):
                continue
            command = repro.get("command")
            if isinstance(command, str):
                commands.append(command)
        assert commands
        probe_id = "session.expired-empty-success"
        expected = _calls(original, probe_id)
        assert expected
        for command in commands:
            before = set(_run_dirs(tmp_path))
            parts = shlex.split(command)
            assert parts[0] == "mcp-cross-exam"
            with pytest.raises(SystemExit) as again:
                main(parts[1:])
            assert again.value.code == ExitCode.FINDINGS
            created = set(_run_dirs(tmp_path)) - before
            assert len(created) == 1
            assert _calls(created.pop(), probe_id) == expected


def test_replay_matches_then_differs_and_reports_usage(tmp_path: Path) -> None:
    with start_fixture() as port:
        url = f"http://127.0.0.1:{port}/mcp"
        result = anyio.run(_tools, url, tmp_path / "grab")
        transcript = tmp_path / "tools.jsonl"
        _write_transcript(transcript, result)
        with pytest.raises(SystemExit) as matched:
            main(["replay", str(transcript), url])
        assert matched.value.code == ExitCode.SUCCESS
        changed = dict(result)
        changed["tools"] = []
        _write_transcript(tmp_path / "changed.jsonl", changed)
        with pytest.raises(SystemExit) as differed:
            main(["replay", str(tmp_path / "changed.jsonl"), url])
        assert differed.value.code == ExitCode.FINDINGS
    with pytest.raises(SystemExit) as missing:
        main(["replay", str(tmp_path / "missing.jsonl"), "http://127.0.0.1:9/mcp"])
    assert missing.value.code == ExitCode.CONFIG
    with pytest.raises(SystemExit) as offline:
        main(["replay", str(transcript), "http://127.0.0.1:9/mcp"])
    assert offline.value.code == ExitCode.UNREACHABLE


async def _tools(url: str, directory: Path) -> dict[str, JsonValue]:
    transport = open_http(url, run_dir=directory)
    await transport.connect()
    try:
        result = await transport.request("tools/list", {})
    finally:
        await transport.close()
    if not isinstance(result, dict):
        raise AssertionError("tools/list")
    return result


def _write_transcript(path: Path, result: dict[str, JsonValue]) -> None:
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    response = {"jsonrpc": "2.0", "id": 1, "result": result}
    path.write_text(json.dumps(request) + "\n" + json.dumps(response) + "\n", encoding="utf-8")


def _only_run(tmp_path: Path) -> Path:
    runs = _run_dirs(tmp_path)
    assert len(runs) == 1
    return runs[0]


def _run_dirs(tmp_path: Path) -> list[Path]:
    root = tmp_path / "runs"
    return sorted(path for path in root.iterdir() if path.is_dir())


def _calls(run: Path, probe_id: str) -> list[JsonValue]:
    path = run / "evidence.jsonl"
    if not path.is_file():
        return []
    found: list[JsonValue] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        row = _object(line)
        if row.get("probe_id") != probe_id:
            continue
        request = row.get("request")
        if not isinstance(request, dict):
            continue
        body = request.get("json")
        if isinstance(body, dict) and body.get("method") == "tools/call":
            found.append(body.get("params"))
    return found


def _object(text: str) -> dict[str, JsonValue]:
    loaded = json_value(json.loads(text))
    if not isinstance(loaded, dict):
        raise AssertionError("expected an object")
    return loaded
