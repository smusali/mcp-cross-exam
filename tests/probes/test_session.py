from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path

import anyio
import pytest

from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.fixture import (
    EXPIRED_TOKEN,
    VALID_TOKEN,
    FixtureApp,
    FixtureState,
    Reply,
)
from mcp_cross_exam.probes import is_empty_success
from mcp_cross_exam.probes.base import Observation, Probe, ProbeContext, ToolView
from mcp_cross_exam.runner import examine
from mcp_cross_exam.transport import Finding
from mcp_cross_exam.transport.base import JsonValue, json_value
from mcp_cross_exam.transport.http import open_http
from tests.probes.conftest import audit_http, audit_stdio, finding_ids, free_port
from tests.support.asgi import StreamingASGITransport

Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def test_empty_success_table() -> None:
    documented = ToolView("get_ticket", _schema(), True, False)
    plain = ToolView("get_ticket", None, True, False)
    empty = json_value({"content": [], "isError": False})
    spaces = json_value({"content": [{"type": "text", "text": " \n"}], "isError": False})
    text = json_value({"content": [{"type": "text", "text": "ticket-1"}], "isError": False})
    errored = json_value({"content": [], "isError": True})
    structured = json_value(
        {"content": [], "structuredContent": {"id": "ticket-1"}, "isError": False}
    )
    assert is_empty_success(empty, plain)
    assert is_empty_success(spaces, plain)
    assert is_empty_success(text, documented)
    assert not is_empty_success(errored, documented)
    assert not is_empty_success(text, plain)
    assert not is_empty_success(structured, documented)


def test_expired_session_status(tmp_path: Path) -> None:
    findings = audit_http(tmp_path, "2025-11-25", "session.expired-not-404")
    assert finding_ids(findings) == {"session.expired-not-404"}
    finding = findings[0]
    assert finding.agent_impact == "agent silently degrades"
    assert finding.classification == "read"
    assert finding.severity == "high"
    assert len(finding.frames) == 2


def test_expired_session_empty_body(tmp_path: Path) -> None:
    findings = audit_http(tmp_path, "2025-11-25", "session.expired-empty-success")
    assert finding_ids(findings) == {"session.expired-empty-success"}
    assert findings[0].agent_impact == "agent silently degrades"
    assert EXPIRED_TOKEN not in findings[0].summary


def test_modern_and_stdio_skip_session_expiry(tmp_path: Path) -> None:
    modern = finding_ids(audit_http(tmp_path, "2026-07-28", "session.expired-empty-success"))
    stdio = finding_ids(
        audit_stdio(tmp_path / "stdio", "2025-11-25", "session.expired-empty-success")
    )
    assert "session.expired-empty-success" not in modern
    assert "session.expired-not-404" not in modern
    assert "session.expired-empty-success" not in stdio


def test_expired_bearer_on_http(tmp_path: Path) -> None:
    findings = audit_http(
        tmp_path,
        "2025-11-25",
        "session.token-expired-empty-success",
        bearer=VALID_TOKEN,
        expired=EXPIRED_TOKEN,
    )
    assert finding_ids(findings) == {"session.token-expired-empty-success"}
    finding = findings[0]
    assert finding.agent_impact == "agent silently degrades"
    assert EXPIRED_TOKEN not in finding.summary
    assert any("rfc6750" in ref for ref in finding.spec_refs)
    assert any("rfc9728" in ref for ref in finding.spec_refs)


def test_clean_bearer_challenge_is_quiet(tmp_path: Path) -> None:
    found = finding_ids(
        audit_http(
            tmp_path,
            "2026-07-28",
            "none",
            bearer=VALID_TOKEN,
            expired=EXPIRED_TOKEN,
        )
    )
    assert "session.token-expired-empty-success" not in found


def test_challenge_names_the_resource_from_2025_06_18() -> None:
    later = _challenge("2025-11-25")
    earlier = _challenge("2025-03-26")
    assert b'error="invalid_token"' in later
    assert b"resource_metadata=" in later
    assert b'error="invalid_token"' in earlier
    assert b"resource_metadata=" not in earlier


def test_expire_hook_keeps_evidence_in_order(tmp_path: Path) -> None:
    findings = _live(tmp_path)
    finding = next(item for item in findings if item.item_id == "session.expired-empty-success")
    assert len(finding.frames) == 3
    assert b"ticket-1" in finding.frames[0].body
    assert finding.frames[1].status == 200
    assert b"ok" in finding.frames[1].body
    assert finding.frames[2].status == 200
    assert "session.expired-not-404" not in finding_ids(findings)


def test_expire_hook_refuses_a_remote_client() -> None:
    allowed, refused, reset_allowed, reset_refused = anyio.run(_control_hosts)
    assert allowed == 200
    assert refused == 403
    assert reset_allowed == 200
    assert reset_refused == 403


def test_negative_token_ttl_is_config() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["fixture", "serve", "--stdio", "--token-ttl-s", "-1"])
    assert caught.value.code == ExitCode.CONFIG


def test_zero_token_ttl_expires_immediately() -> None:
    state = FixtureState(
        "2025-11-25",
        frozenset(),
        token="http",
        token_ttl_s=0,
        clock=lambda: 1.0,
    )
    assert _bearer_reply(state).status == 401


def test_lapsed_bearer_is_an_empty_success_when_that_defect_is_on() -> None:
    state = FixtureState(
        "2025-11-25",
        frozenset({"session.token-expired-empty-success"}),
        token="http",
        token_ttl_s=0,
        clock=lambda: 1.0,
    )
    reply = _bearer_reply(state)
    assert reply.status == 200
    assert b'"content": []' in reply.body


def test_reset_restarts_the_token_clock() -> None:
    times = [0.0]

    def clock() -> float:
        return times[0]

    app = FixtureApp("2025-11-25", frozenset(), token_ttl_s=5)
    app.state.clock = clock
    app.state.issued_at = 0.0
    app.state.events.append(("1", b"{}"))
    times[0] = 5.0
    assert _bearer_reply(app.state).status == 401
    assert anyio.run(_post, app, ("127.0.0.1", 9), "/__fixture/reset") == 200
    assert app.state.events == []
    assert _bearer_reply(app.state).status == 200


def test_mint_token_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["fixture", "mint-token"])
    assert caught.value.code == ExitCode.SUCCESS
    assert capsys.readouterr().out.strip() == VALID_TOKEN


def test_mint_expired_token_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["fixture", "mint-token", "--expired"])
    assert caught.value.code == ExitCode.SUCCESS
    assert capsys.readouterr().out.strip() == EXPIRED_TOKEN


def test_unknown_defect_is_config() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["fixture", "serve", "--stdio", "--defects", "not-a-probe"])
    assert caught.value.code == ExitCode.CONFIG


def test_expired_bearer_env_is_http_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CROSS_EXAM_EXPIRED", "fixture-expired")
    with pytest.raises(SystemExit) as caught:
        main(["--expired-bearer-env", "CROSS_EXAM_EXPIRED", "--", "true"])
    assert caught.value.code == ExitCode.CONFIG


def test_expired_bearer_env_rejects_a_break(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CROSS_EXAM_EXPIRED", "fixture\nexpired")
    with pytest.raises(SystemExit) as caught:
        main(["--expired-bearer-env", "CROSS_EXAM_EXPIRED", "http://127.0.0.1:9/mcp"])
    assert caught.value.code == ExitCode.CONFIG
    assert "fixture" not in str(caught.value)


def test_probe_error_does_not_stop_later_probes(tmp_path: Path) -> None:
    async def _go(stage: str, directory: Path) -> tuple[list[Finding], bool]:
        teardown_ran = False

        class _Boom(Probe):
            id = "boom"
            default_severity = "high"
            revisions = ("2025-11-25",)

            async def setup(self, ctx: ProbeContext) -> None:
                if stage == "setup":
                    raise RuntimeError("nope")

            async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
                if stage == "run":
                    raise RuntimeError("nope")
                return Observation(ctx.revision or "2025-11-25", tool, ())

            def assert_(self, observation: Observation) -> list[Finding]:
                if stage == "assert_":
                    raise RuntimeError("nope")
                return []

            async def teardown(self, ctx: ProbeContext) -> None:
                nonlocal teardown_ran
                teardown_ran = True
                if stage == "teardown":
                    raise RuntimeError("nope")

        class _Later(Probe):
            id = "later"
            default_severity = "info"
            revisions = ("2025-11-25",)

            async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
                return Observation(ctx.revision or "2025-11-25", tool, ())

            def assert_(self, observation: Observation) -> list[Finding]:
                return [
                    Finding(
                        item_id="later.ok",
                        severity="info",
                        summary="later",
                        evidence=None,
                    )
                ]

        app = FixtureApp("2025-11-25", frozenset())
        transport = open_http(
            "http://127.0.0.1:9/mcp",
            network=StreamingASGITransport(app),
            run_dir=directory,
        )
        context = await transport.connect()
        try:
            findings = await examine(
                ProbeContext(
                    transport=transport,
                    run=context,
                    http=True,
                    endpoint="http://127.0.0.1:9/mcp",
                    expired_bearer=None,
                    legacy=False,
                ),
                probes=(_Boom(), _Later()),
            )
        finally:
            await transport.close()
        return findings, teardown_ran

    for stage in ("setup", "run", "assert_", "teardown"):
        findings, teardown_ran = anyio.run(_go, stage, tmp_path / stage)
        ids = [item.item_id for item in findings]
        assert "probe.error" in ids
        assert "later.ok" in ids
        assert teardown_ran
        detail = next(item.detail for item in findings if item.item_id == "probe.error")
        assert detail is not None
        assert "Traceback" in detail


def _challenge(era: str) -> bytes:
    state = FixtureState(era, frozenset(), token="http")
    state.sessions.add("session")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_ticket", "arguments": {}},
        }
    ).encode()
    headers = {
        "authorization": f"Bearer {EXPIRED_TOKEN}",
        "mcp-session-id": "session",
        "mcp-protocol-version": era,
    }
    reply = state.answer(
        body, headers, http=True, origin="http://127.0.0.1:9", require_session=True
    )
    assert reply.status == 401
    return reply.headers[0][1]


def _live(tmp: Path) -> list[Finding]:
    port = free_port()
    command = (
        sys.executable,
        "-m",
        "mcp_cross_exam",
        "fixture",
        "serve",
        "--http",
        f"127.0.0.1:{port}",
        "--era",
        "2025-11-25",
        "--defects",
        "session.expired-empty-success",
    )
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        _wait_port(port)
        return anyio.run(_audit_port, tmp, port)
    finally:
        process.terminate()
        process.wait(timeout=5)


async def _audit_port(tmp: Path, port: int) -> list[Finding]:
    url = f"http://127.0.0.1:{port}/mcp"
    transport = open_http(url, run_dir=tmp)
    context = await transport.connect()
    try:
        return await examine(
            ProbeContext(
                transport=transport,
                run=context,
                http=True,
                endpoint=url,
                expired_bearer=None,
                legacy=False,
            )
        )
    finally:
        await transport.close()


def _wait_port(port: int) -> None:
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
            continue
    raise RuntimeError("fixture did not start")


def _schema() -> dict[str, JsonValue]:
    loaded = json_value({"type": "object"})
    if not isinstance(loaded, dict):
        raise AssertionError("schema")
    return loaded


def _bearer_reply(state: FixtureState) -> Reply:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_ticket", "arguments": {}},
        }
    ).encode()
    return state.answer(
        body,
        {"authorization": f"Bearer {VALID_TOKEN}", "mcp-protocol-version": state.era},
        http=True,
        origin="http://127.0.0.1:9",
        require_session=False,
    )


async def _control_hosts() -> tuple[int, int, int, int]:
    app = FixtureApp("2025-11-25", frozenset())
    allowed = await _post(app, ("127.0.0.1", 9), "/__fixture/expire-session")
    refused = await _post(app, ("8.8.8.8", 9), "/__fixture/expire-session")
    reset_allowed = await _post(app, ("127.0.0.1", 9), "/__fixture/reset")
    reset_refused = await _post(app, ("8.8.8.8", 9), "/__fixture/reset")
    return allowed, refused, reset_allowed, reset_refused


async def _post(app: FixtureApp, client: tuple[str, int], path: str) -> int:
    sent = False
    status = 0

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"{}", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal status
        if message.get("type") != "http.response.start":
            return
        code = message.get("status")
        if isinstance(code, int):
            status = code

    scope: Message = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "scheme": "http",
        "server": ("127.0.0.1", 9),
        "client": client,
        "root_path": "",
    }
    await app(scope, receive, send)
    return status
