from __future__ import annotations

import asyncio
import ctypes
import json
import os
import sys
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, MutableMapping
from contextlib import suppress
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anyio
import httpx2
import pytest
import typer
from anyio.streams.memory import MemoryObjectReceiveStream
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_cross_exam.cli import app, bind_stdio, main, release_stdio
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.transport.base import (
    ConnectFailed,
    HandshakeFailed,
    JsonValue,
    ProtocolError,
    ServerState,
    Timeout,
    TransportClosed,
    TransportFailure,
    collapse,
    failure_from,
    json_value,
)
from mcp_cross_exam.transport.http import HttpTransport, open_http, path_is_sse
from mcp_cross_exam.transport.stdio import StdioTransport, child_environment, open_stdio
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT
from pydantic import ValidationError
from typer.testing import CliRunner

RUNNER = CliRunner()
TOOLS: dict[str, object] = {
    "tools": [{"name": "echo", "inputSchema": {"type": "object"}}],
    "resultType": "complete",
    "ttlMs": 0,
    "cacheScope": "public",
}
CALL: dict[str, object] = {"content": [{"type": "text", "text": "hi"}], "resultType": "complete"}
SECRET = "hunter2-secret"
Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def _invoke(argv: list[str]) -> typer.testing.Result:
    left, token = bind_stdio(argv)
    try:
        return RUNNER.invoke(app, left)
    finally:
        release_stdio(token)


def _server() -> MCPServer:
    server = MCPServer("fixture", version="1.0.0", instructions="be brief")

    @server.tool()
    def echo(text: str) -> str:
        return text

    return server


def _stdio_script(path: Path, *, noise: bool) -> None:
    prefix = (
        'print("noise", flush=True)\nprint("ready", file=sys.stderr, flush=True)\n' if noise else ""
    )
    path.write_text(
        "import sys\n"
        + prefix
        + "import anyio\n"
        + "from mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('fixture', version='1.0.0', instructions='be brief')\n"
        + "@server.tool()\n"
        + "def echo(text: str) -> str:\n"
        + "    return text\n"
        + "anyio.run(server.run_stdio_async)\n",
        encoding="utf-8",
    )


def _names(result: JsonValue) -> list[str]:
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    names: list[str] = []
    for tool in tools:
        if isinstance(tool, dict):
            name = tool.get("name")
            if isinstance(name, str):
                names.append(name)
    return names


async def _exercise(transport: HttpTransport | StdioTransport, *, sse: bool) -> ServerState:
    context = await transport.connect()
    listed = await transport.request("tools/list", {})
    called = await transport.request(
        "tools/call",
        {"name": "echo", "arguments": {"text": "hi"}},
    )
    await transport.notify("notifications/initialized", {})
    await transport.raw.send_bytes(b"{}", headers={"X-Raw": "1"}, timeout=5)
    with anyio.move_on_after(1):
        async for _chunk in transport.raw.stream():
            break
    await transport.raw.drop()
    await transport.close()
    assert context.server is not None
    assert context.server.revision == "2026-07-28"
    assert _names(listed) == ["echo"]
    encoded = json.dumps(called)
    assert "hi" in encoded
    assert any(frame.direction == "outbound" for frame in transport.recorder.frames)
    assert any(frame.direction == "inbound" for frame in transport.recorder.frames)
    findings = [item.item_id for item in context.findings]
    if sse:
        assert findings.count("transport.deprecated-sse") == 1
        assert context.findings[0].severity == "info"
        assert context.findings[0].evidence is not None
    else:
        assert "transport.deprecated-sse" not in findings
    return context.server


async def _contract(kind: str, tmp_path: Path) -> None:
    server = _server()
    if kind == "stdio":
        script = tmp_path / "server.py"
        _stdio_script(script, noise=False)
        stdio = open_stdio(
            (sys.executable, str(script)), run_dir=tmp_path / "run", grace_seconds=0.2
        )
        await _exercise(stdio, sse=False)
        return
    app = server.sse_app() if kind == "sse" else server.streamable_http_app()
    url = "http://127.0.0.1:9/sse" if kind == "sse" else "http://127.0.0.1:9/mcp"
    async with app.router.lifespan_context(app):
        http = open_http(
            url,
            legacy=kind == "sse",
            run_dir=tmp_path / "run",
            network=StreamingASGITransport(app=app),
        )
        await _exercise(http, sse=kind == "sse")


@pytest.mark.parametrize("kind", ["stdio", "http", "sse"])
def test_contract_against_each_adapter(kind: str, tmp_path: Path) -> None:
    anyio.run(_contract, kind, tmp_path)


def _loads(body: bytes) -> dict[str, object]:
    loaded = json.loads(body or b"{}")
    if not isinstance(loaded, dict):
        raise AssertionError(body)
    parsed: dict[str, object] = {}
    for key, value in loaded.items():
        if isinstance(key, str):
            parsed[key] = value
    return parsed


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


class _LiveBody(httpx2.AsyncByteStream):
    def __init__(
        self,
        chunks: MemoryObjectReceiveStream[bytes | None],
        disconnect: asyncio.Event,
        task: asyncio.Task[None],
    ) -> None:
        self._chunks = chunks
        self._disconnect = disconnect
        self._task = task
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._chunks:
                if chunk is None:
                    return
                yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._disconnect.set()
        await self._chunks.aclose()
        try:
            await asyncio.wait_for(self._task, timeout=2)
        except (TimeoutError, asyncio.CancelledError):
            self._task.cancel()
            with suppress(Exception):
                await self._task


class StreamingASGITransport(httpx2.AsyncBaseTransport):
    def __init__(self, app: Callable[[Message, Receive, Send], Awaitable[None]]) -> None:
        self._app = app

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = request.content if isinstance(request.content, bytes) else b""
        sent = False
        disconnect = asyncio.Event()
        started = asyncio.Event()
        status = 500
        headers: list[tuple[bytes, bytes]] = []
        failed: list[BaseException] = []
        outgoing, incoming = anyio.create_memory_object_stream[bytes | None](256)

        async def receive() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            nonlocal status, headers
            kind = message.get("type")
            if kind == "http.response.start":
                code = message.get("status")
                status = code if isinstance(code, int) else 500
                raw_headers = message.get("headers")
                if isinstance(raw_headers, list):
                    headers = []
                    for item in raw_headers:
                        pair = _byte_pair(item)
                        if pair is not None:
                            headers.append(pair)
                started.set()
                return
            if kind != "http.response.body":
                return
            payload = message.get("body")
            if isinstance(payload, bytes) and payload and request.method != "HEAD":
                await outgoing.send(payload)
            if not message.get("more_body"):
                await outgoing.send(None)

        async def run() -> None:
            scope: Message = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": request.method,
                "headers": [(key.lower(), value) for key, value in request.headers.raw],
                "scheme": request.url.scheme,
                "path": request.url.path,
                "raw_path": request.url.raw_path.split(b"?")[0],
                "query_string": request.url.query,
                "server": (request.url.host, request.url.port),
                "client": ("127.0.0.1", 123),
                "root_path": "",
            }
            try:
                await self._app(scope, receive, send)
            except Exception as exc:
                failed.append(exc)
            finally:
                started.set()
                with suppress(Exception):
                    await outgoing.send(None)
                await outgoing.aclose()

        task = asyncio.create_task(run())
        await started.wait()
        if failed and not headers and status == 500:
            await incoming.aclose()
            raise failed[0]
        return httpx2.Response(
            status,
            headers=headers,
            stream=_LiveBody(incoming, disconnect, task),
        )


class Peer:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls: list[str] = []
        self.offers: list[str] = []
        self.authorization: str | None = None
        self.seen_headers: list[str] = []
        self.list_calls = 0
        self.ready = False

    async def __call__(self, scope: Message, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            return
        method = _text(scope.get("method"))
        path = _text(scope.get("path"))
        headers = _header_map(scope.get("headers"))
        if "authorization" in headers:
            self.authorization = headers["authorization"]
        if "x-test" in headers:
            self.seen_headers.append(headers["x-test"])
        if method != "POST":
            await _reply(send, 405, "text/plain", b"method not allowed")
            return
        body = await _read_body(receive)
        if self.mode == "plain-404":
            await _reply(send, 404, "text/plain", b"missing")
            return
        message = _loads(body)
        name = _text(message.get("method"))
        self.calls.append(name)
        if name == "initialize":
            params = message.get("params")
            if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
                self.offers.append(params["protocolVersion"])
        status, content_type, payload = self._answer(message, path)
        await _reply(send, status, content_type, payload)

    def _answer(self, message: dict[str, object], path: str) -> tuple[int, str, bytes]:
        name = _text(message.get("method"))
        rpc_id = message.get("id")
        if name == "notifications/initialized" or "id" not in message:
            return 202, "text/plain", b""
        if self.mode == "jsonrpc-404":
            return 404, "application/json", _error(rpc_id, -32601, "Method not found")
        if self.mode == "reject" or name == "":
            return 200, "application/json", _error(rpc_id, -32601, "Method not found")
        if name == "server/discover":
            if self.mode in {"modern", "split"}:
                return 200, "application/json", _ok(rpc_id, _discover())
            return 200, "application/json", _error(rpc_id, -32601, "Method not found")
        if name == "tools/list":
            self.list_calls += 1
            if not self.ready and self.mode not in {"tools", "split", "modern"}:
                return 200, "application/json", _error(rpc_id, -32601, "Method not found")
            result = dict(TOOLS)
            if self.mode == "split" and self.list_calls > 1:
                return 200, "text/event-stream", _sse(rpc_id, result)
            return 200, "application/json", _ok(rpc_id, result)
        if name == "tools/call":
            if self.mode == "split":
                return 200, "text/event-stream", _sse(rpc_id, CALL)
            return 200, "application/json", _ok(rpc_id, CALL)
        if name == "initialize":
            answer = self._initialize(message, rpc_id)
            if b"protocolVersion" in answer[2]:
                self.ready = True
            return answer
        if self.mode == "plain-404" or path.endswith("/sse"):
            return 404, "text/plain", b"missing"
        return 200, "application/json", _error(rpc_id, -32601, "Method not found")

    def _initialize(self, message: dict[str, object], rpc_id: object) -> tuple[int, str, bytes]:
        params = message.get("params")
        offered = "2025-11-25"
        if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
            offered = params["protocolVersion"]
        if self.mode == "narrow" and offered != "2025-03-26":
            return 200, "application/json", _unsupported(rpc_id, offered, ["2025-03-26"])
        if self.mode in {"counter", "mismatch"}:
            return 200, "application/json", _initialized(rpc_id, "2025-06-18")
        if self.mode == "reject":
            return 200, "application/json", _error(rpc_id, -32601, "Method not found")
        return 200, "application/json", _initialized(rpc_id, offered)


def _discover() -> dict[str, object]:
    return {
        "supportedVersions": ["2026-07-28"],
        "capabilities": {"tasks": {}, "extensions": {"com.example/widgets": {}}},
        "instructions": "be brief",
        "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "peer", "version": "1"}},
    }


def _initialized(rpc_id: object, version: str) -> bytes:
    return _ok(
        rpc_id,
        {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "peer", "version": "1"},
            "instructions": "legacy",
        },
    )


def _ok(rpc_id: object, result: Mapping[str, object]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": dict(result)}).encode()


def _error(rpc_id: object, code: int, message: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
    ).encode()


def _unsupported(rpc_id: object, requested: str, supported: list[str]) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {"supported": supported, "requested": requested},
            },
        }
    ).encode()


def _byte_pair(item: object) -> tuple[bytes, bytes] | None:
    if not isinstance(item, tuple) or len(item) != 2:
        return None
    key, value = item
    if isinstance(key, bytes) and isinstance(value, bytes):
        return key, value
    return None


def _sse(rpc_id: object, result: Mapping[str, object]) -> bytes:
    payload = _ok(rpc_id, result).decode()
    return f"event: message\ndata: {payload}\n\n".encode()


def _header_map(value: object) -> dict[str, str]:
    mapped: dict[str, str] = {}
    if not isinstance(value, list):
        return mapped
    for item in value:
        pair = _byte_pair(item)
        if pair is None:
            continue
        key, raw = pair
        mapped[key.decode().lower()] = raw.decode()
    return mapped


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        body = message.get("body", b"")
        if isinstance(body, bytes):
            chunks.append(body)
        if message.get("more_body") is not True:
            return b"".join(chunks)


async def _reply(send: Send, status: int, content_type: str, payload: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _connect_peer(
    mode: str,
    tmp_path: Path,
    *,
    protocol_version: str | None = None,
    headers: dict[str, str] | None = None,
    bearer: str | None = None,
    legacy: bool = False,
    url: str = "http://127.0.0.1:9/mcp",
) -> tuple[HttpTransport, Peer]:
    peer = Peer(mode)
    transport = open_http(
        url,
        legacy=legacy,
        protocol_version=protocol_version,
        headers=headers,
        bearer=bearer,
        run_dir=tmp_path / "run",
        network=StreamingASGITransport(app=peer),
    )
    return transport, peer


def test_tools_list_matches_across_json_and_sse(tmp_path: Path) -> None:
    anyio.run(_json_and_sse, tmp_path)


async def _json_and_sse(tmp_path: Path) -> None:
    transport, _peer = await _connect_peer("split", tmp_path)
    await transport.connect()
    first = await transport.request("tools/list", {})
    second = await transport.request("tools/list", {}, headers={"X-Test": "visible"})
    called = await transport.request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    await transport.close()
    assert first == second
    assert _names(first) == ["echo"]
    assert "hi" in json.dumps(called)
    assert "visible" in _peer.seen_headers


def test_era_negotiation(tmp_path: Path) -> None:
    anyio.run(_eras, tmp_path)


async def _eras(tmp_path: Path) -> None:
    modern, _peer = await _connect_peer("modern", tmp_path)
    context = await modern.connect()
    assert context.server is not None
    assert context.server.revision == "2026-07-28"
    assert context.server.instructions == "be brief"
    assert context.server.server_info is not None
    assert context.server.server_info.get("name") == "peer"
    assert "com.example/widgets" in context.server.extensions
    assert "io.modelcontextprotocol/tasks" in context.server.extensions
    await modern.close()

    tools_only, _tools_peer = await _connect_peer("tools", tmp_path / "tools")
    tools_context = await tools_only.connect()
    assert tools_context.server is not None
    assert tools_context.server.revision == "2026-07-28"
    assert tools_context.server.capabilities == {}
    assert tools_context.server.extensions == ()
    await tools_only.close()

    handshake, handshake_peer = await _connect_peer(
        "handshake",
        tmp_path / "handshake",
        protocol_version="2025-11-25",
    )
    handshake_context = await handshake.connect()
    assert handshake_context.server is not None
    assert handshake_context.server.revision == "2025-11-25"
    assert handshake_context.server.instructions == "legacy"
    assert handshake_peer.offers == ["2025-11-25"]
    listed = await handshake.request("tools/list", {})
    called = await handshake.request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    assert _names(listed) == ["echo"]
    assert "hi" in json.dumps(called)
    await handshake.close()

    narrow, narrow_peer = await _connect_peer("narrow", tmp_path / "narrow")
    narrow_context = await narrow.connect()
    assert narrow_context.server is not None
    assert narrow_context.server.revision == "2025-03-26"
    assert narrow_peer.offers == ["2025-11-25", "2025-03-26"]
    await narrow.close()

    counter, _counter_peer = await _connect_peer("counter", tmp_path / "counter")
    counter_context = await counter.connect()
    assert counter_context.server is not None
    assert counter_context.server.revision == "2025-06-18"
    await counter.close()

    pinned, pinned_peer = await _connect_peer(
        "handshake",
        tmp_path / "pinned",
        protocol_version="2025-06-18",
    )
    pinned_context = await pinned.connect()
    assert pinned_context.server is not None
    assert pinned_context.server.revision == "2025-06-18"
    assert pinned_peer.offers == ["2025-06-18"]
    await pinned.close()


def test_forced_revision_and_total_rejection_fail(tmp_path: Path) -> None:
    anyio.run(_rejections, tmp_path)


async def _rejections(tmp_path: Path) -> None:
    mismatch, _peer = await _connect_peer("mismatch", tmp_path, protocol_version="2025-11-25")
    with pytest.raises(HandshakeFailed) as caught:
        await mismatch.connect()
    await mismatch.close()
    assert "2025-11-25" in str(caught.value)
    assert "2025-06-18" in str(caught.value)

    modern, modern_peer = await _connect_peer(
        "reject", tmp_path / "modern", protocol_version="2026-07-28"
    )
    with pytest.raises(HandshakeFailed) as modern_failure:
        await modern.connect()
    await modern.close()
    assert "2026-07-28" in str(modern_failure.value)
    assert "initialize" not in modern_peer.calls

    rejected, _rejected_peer = await _connect_peer("reject", tmp_path / "all")
    with pytest.raises(HandshakeFailed):
        await rejected.connect()
    await rejected.close()


def test_sse_fallback_and_modern_error(tmp_path: Path) -> None:
    anyio.run(_fallback, tmp_path)


async def _fallback(tmp_path: Path) -> None:
    assert path_is_sse("http://127.0.0.1:9/sse")
    assert not path_is_sse("https://example.com/ssep")
    server = _server()
    app = server.sse_app()
    async with app.router.lifespan_context(app):
        transport = open_http(
            "http://127.0.0.1:9/sse",
            run_dir=tmp_path / "fallback",
            network=StreamingASGITransport(app=app),
        )
        context = await transport.connect()
        assert context.server is not None
        assert [item.item_id for item in context.findings] == ["transport.deprecated-sse"]
        await transport.close()

    blocked, _peer = await _connect_peer(
        "jsonrpc-404", tmp_path / "blocked", url="http://127.0.0.1:9/sse"
    )
    with pytest.raises(TransportFailure):
        await blocked.connect()
    await blocked.close()
    assert blocked._context.findings == []


def test_bearer_stays_out_of_the_run_directory(tmp_path: Path) -> None:
    anyio.run(_bearer, tmp_path)


async def _bearer(tmp_path: Path) -> None:
    transport, peer = await _connect_peer("modern", tmp_path, bearer=SECRET)
    await transport.connect()
    await transport.close()
    assert peer.authorization == f"Bearer {SECRET}"
    text = "\n".join(
        item.read_text(encoding="utf-8", errors="replace")
        for item in (tmp_path / "run").rglob("*")
        if item.is_file()
    )
    assert SECRET not in text


def test_stdout_pollution_is_medium(tmp_path: Path) -> None:
    anyio.run(_pollution, tmp_path)


async def _pollution(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    _stdio_script(script, noise=True)
    run_dir = tmp_path / "run"
    transport = open_stdio((sys.executable, str(script)), run_dir=run_dir, grace_seconds=0.2)
    context = await transport.connect()
    await transport.close()
    findings = [item for item in context.findings if item.item_id == "transport.stdout-pollution"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence is not None
    assert findings[0].evidence.body == b"noise"
    assert "ready" in "".join(context.logs.stderr)
    assert "ready" in context.logs.path.read_text(encoding="utf-8")


def test_pollution_stays_below_the_default_fail_on(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    _stdio_script(script, noise=True)
    args = ["--skip", "transport.version-negotiation", "--", sys.executable, str(script)]
    noisy = _invoke(args)
    quiet = _invoke(["--quiet", *args])
    held = _invoke(["--exit-zero", *args])
    assert noisy.exit_code == ExitCode.SUCCESS
    assert "transport.stdout-pollution" in noisy.stderr
    assert quiet.exit_code == ExitCode.SUCCESS
    assert "transport.stdout-pollution" not in quiet.stderr
    assert held.exit_code == ExitCode.SUCCESS


def test_env_allowlist_and_env_from(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CROSS_EXAM_SECRET", SECRET)
    script = tmp_path / "keys.py"
    script.write_text(
        "import os, sys\nfrom pathlib import Path\n"
        "Path(sys.argv[1]).write_text('\\n'.join(sorted(os.environ)), encoding='utf-8')\n",
        encoding="utf-8",
    )
    denied = tmp_path / "denied.txt"
    allowed = tmp_path / "allowed.txt"
    anyio.run(_env_case, tmp_path, script, denied, None)
    anyio.run(_env_case, tmp_path / "with", script, allowed, "CROSS_EXAM_SECRET")
    denied_text = denied.read_text(encoding="utf-8")
    allowed_text = allowed.read_text(encoding="utf-8")
    assert "CROSS_EXAM_SECRET" not in denied_text
    assert SECRET not in denied_text
    assert "CROSS_EXAM_SECRET" in allowed_text.splitlines()
    assert SECRET not in allowed_text


async def _env_case(tmp_path: Path, script: Path, output: Path, env_from: str | None) -> None:
    extra = {env_from: SECRET} if env_from is not None else {}
    transport = open_stdio(
        (sys.executable, str(script), str(output)),
        env=extra,
        run_dir=tmp_path / "run",
        grace_seconds=0.2,
    )
    with pytest.raises(TransportFailure):
        await transport.connect()
    await transport.close()
    blob = "\n".join(
        item.read_text(encoding="utf-8", errors="replace")
        for item in (tmp_path / "run").rglob("*")
        if item.is_file()
    )
    assert SECRET not in blob


def test_process_group_is_reaped_when_connect_is_cancelled(tmp_path: Path) -> None:
    anyio.run(_reap, tmp_path)


async def _reap(tmp_path: Path) -> None:
    script = tmp_path / "sleep.py"
    pidfile = tmp_path / "pids.txt"
    script.write_text(
        "import os, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "Path(sys.argv[1]).write_text(f'{os.getpid()}\\n{child.pid}', encoding='utf-8')\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    transport = open_stdio(
        (sys.executable, str(script), str(pidfile)),
        run_dir=tmp_path / "run",
        grace_seconds=0.1,
    )

    async def _connect() -> None:
        await transport.connect()

    async with anyio.create_task_group() as group:
        group.start_soon(_connect)
        while not pidfile.exists():
            await anyio.sleep(0.01)
        group.cancel_scope.cancel()
    await transport.close()
    parent_text, child_text = pidfile.read_text(encoding="utf-8").splitlines()
    parent = int(parent_text)
    child = int(child_text)
    if sys.platform == "win32":
        with anyio.move_on_after(2):
            while _alive(parent) or _alive(child):
                await anyio.sleep(0.05)
    assert not _alive(parent)
    assert not _alive(child)


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        return _windows_alive(pid)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _windows_alive(pid: int) -> bool:
    process_query_limited_information = 0x1000
    still_active = 259
    error_access_denied = 5
    kernel32 = _windows_kernel32()
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetLastError.argtypes = ()
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        last_error: int = kernel32.GetLastError()
        return last_error == error_access_denied
    code = wintypes.DWORD()
    try:
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _windows_kernel32() -> ctypes.CDLL:
    load = getattr(ctypes, "WinDLL", ctypes.CDLL)
    library: ctypes.CDLL = load("kernel32")
    return library


def test_stdio_usage_and_http_usage_never_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BAD_HEADER", "line\nbreak")
    cases = [
        ["--env", "A=B", "http://127.0.0.1:9/mcp"],
        ["--env-from", "MISSING_CROSS_EXAM_ENV", "--", sys.executable, "-c", "raise SystemExit(0)"],
        ["--protocol-version", "2024-11-05", "http://127.0.0.1:9/mcp"],
        ["--protocol-version", "1999-01-01", "http://127.0.0.1:9/mcp"],
        ["--ca-bundle", str(tmp_path / "missing.pem"), "http://127.0.0.1:9/mcp"],
        ["--cwd", str(tmp_path / "missing"), "--", sys.executable, "-c", "raise SystemExit(0)"],
        ["--env", "NOEQUALS", "--", sys.executable, "-c", "raise SystemExit(0)"],
        ["--bearer-env", "MISSING_CROSS_EXAM_ENV", "http://127.0.0.1:9/mcp"],
        ["--header-env", "X-Api-Key=BAD_HEADER", "http://127.0.0.1:9/mcp"],
        ["--bearer-env", "BAD_HEADER", "--", sys.executable, "-c", "raise SystemExit(0)"],
    ]
    for argv in cases:
        assert _invoke(argv).exit_code == ExitCode.CONFIG, argv


def test_rejected_offer_exits_unreachable() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RejectHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(SystemExit) as caught:
            main(["--protocol-version", "2025-11-25", f"http://127.0.0.1:{port}/mcp"])
        assert caught.value.code == ExitCode.UNREACHABLE
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _RejectHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        message = _loads(raw)
        payload = _error(message.get("id", 1), -32601, "Method not found")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self.send_response(405)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_reset_appends_frames(tmp_path: Path) -> None:
    anyio.run(_reset, tmp_path)


async def _reset(tmp_path: Path) -> None:
    transport, _peer = await _connect_peer("modern", tmp_path)
    await transport.connect()
    count = len(transport.recorder.frames)
    await transport.reset()
    assert len(transport.recorder.frames) > count
    await transport.close()
    await transport.close()


def test_typed_failures_keep_their_meaning() -> None:
    assert isinstance(failure_from(Timeout("timed out")), Timeout)
    assert isinstance(failure_from(MCPError(REQUEST_TIMEOUT, "slow")), Timeout)
    assert isinstance(failure_from(MCPError(CONNECTION_CLOSED, "gone")), TransportClosed)
    assert isinstance(failure_from(MCPError(-32601, "missing")), ProtocolError)
    assert isinstance(failure_from(TimeoutError()), Timeout)
    assert isinstance(failure_from(anyio.EndOfStream()), TransportClosed)
    assert isinstance(failure_from(OSError()), ConnectFailed)
    assert isinstance(failure_from(RuntimeError()), ProtocolError)
    try:
        raise ValidationError.from_exception_data("Result", [])
    except ValidationError as exc:
        assert isinstance(failure_from(exc), ProtocolError)
    assert isinstance(collapse(ExceptionGroup("g", [HandshakeFailed("no")])), HandshakeFailed)
    try:
        json_value({1: "a"})
    except ProtocolError as exc:
        assert "key" in str(exc)
    try:
        json_value(object())
    except ProtocolError as exc:
        assert "json" in str(exc)


def test_child_environment_keeps_the_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CROSS_EXAM_SECRET", SECRET)
    monkeypatch.setenv("PATH", "/usr/bin")
    child = child_environment({"VISIBLE": "1"})
    assert child["PATH"] == "/usr/bin"
    assert child["VISIBLE"] == "1"
    assert "CROSS_EXAM_SECRET" not in child
