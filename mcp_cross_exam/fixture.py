from __future__ import annotations

import json
import secrets
import sys
import time
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass

from mcp_types import PROTOCOL_VERSION_META_KEY
from mcp_types.jsonrpc import (
    HEADER_MISMATCH,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    UNSUPPORTED_PROTOCOL_VERSION,
)

from mcp_cross_exam.transport.base import JsonValue, ProtocolError, json_value

Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

MODERN = "2026-07-28"
ERAS = (MODERN, "2025-11-25")
VALID_TOKEN = "fixture-valid"
EXPIRED_TOKEN = "fixture-expired"
DEFECT_IDS = (
    "transport.version-negotiation",
    "transport.capabilities-honesty",
    "transport.required-headers",
    "transport.unknown-method",
    "transport.reconnect-fails",
    "transport.resume-gap",
    "session.expired-not-404",
    "session.expired-empty-success",
    "session.token-expired-empty-success",
)
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class FixtureError(Exception):
    pass


def parse_defects(value: str, *, clean: bool) -> frozenset[str]:
    if clean or value == "none":
        return frozenset()
    if value == "all":
        return frozenset(DEFECT_IDS)
    names = frozenset(part.strip() for part in value.split(",") if part.strip())
    unknown = names - frozenset(DEFECT_IDS)
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise FixtureError(f"unknown defect {joined}")
    return names


def parse_era(value: str) -> str:
    if value not in ERAS:
        raise FixtureError("unsupported fixture era")
    return value


def parse_bind(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise FixtureError("expected HOST:PORT")
    number = int(port)
    if number <= 0 or number > 65535:
        raise FixtureError("expected HOST:PORT")
    return host, number


@dataclass(frozen=True, slots=True)
class Reply:
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[bytes, bytes], ...] = ()
    chunks: tuple[bytes, bytes] | None = None
    prefix: bytes = b""


class FixtureState:
    def __init__(self, era: str, defects: frozenset[str], *, token: str) -> None:
        self.era = era
        self.defects = defects
        self.token = token
        self.sse_token: str | None = None
        self.generation = 0
        self.sessions: set[str] = set()
        self.events: list[tuple[str, bytes]] = []

    def mint_sse(self) -> str:
        self.sse_token = secrets.token_hex(4)
        self.generation += 1
        return self.sse_token

    def answer(
        self,
        raw: bytes,
        headers: dict[str, str],
        *,
        http: bool,
        origin: str,
        require_session: bool = False,
    ) -> Reply:
        message = _object(raw)
        if message is None:
            return _error_reply(None, 400, -32700, "Parse error")
        if "id" not in message:
            return Reply(202, "text/plain", b"")
        rpc_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return _error_reply(rpc_id, 400, -32600, "Invalid request")
        params = message.get("params")
        params_object = params if isinstance(params, dict) else {}
        auth = _auth(self, headers, method, rpc_id, origin)
        if auth is not None:
            return auth
        checked = _version_gate(self, method, rpc_id, params_object, headers, http=http)
        if checked is not None:
            return checked
        if require_session and self.era != MODERN and method != "initialize":
            gated = _session_gate(self, headers, rpc_id)
            if gated is not None:
                return gated
        return _dispatch(self, method, rpc_id, params_object, http=http)

    def resume(self, last: str) -> bytes:
        ids = [event_id for event_id, _data in self.events]
        tail = list(self.events) if last not in ids else self.events[ids.index(last) + 1 :]
        if "transport.resume-gap" in self.defects and tail:
            tail = tail[1:] if len(tail) >= 2 else [(last, b"{}"), *tail]
        return b"".join(_event(event_id, data) for event_id, data in tail)

    def ticket_id(self) -> str:
        if "transport.reconnect-fails" not in self.defects:
            return "ticket-1"
        mark = self.sse_token or self.token
        return f"ticket-{mark}-{self.generation}"


def _auth(
    state: FixtureState,
    headers: dict[str, str],
    method: str,
    rpc_id: JsonValue | None,
    origin: str,
) -> Reply | None:
    token = _bearer(headers.get("authorization", ""))
    if token is None:
        return None
    if token == VALID_TOKEN:
        return None
    if (
        token == EXPIRED_TOKEN
        and method == "tools/call"
        and "session.token-expired-empty-success" in state.defects
    ):
        return _result_reply(rpc_id, _empty_result())
    challenge = 'Bearer error="invalid_token"'
    if state.era >= "2025-06-18":
        challenge += f', resource_metadata="{origin}/.well-known/oauth-protected-resource"'
    return Reply(
        401,
        "application/json",
        _error_body(rpc_id, -32600, "invalid token"),
        headers=((b"www-authenticate", challenge.encode()),),
    )


def _version_gate(
    state: FixtureState,
    method: str,
    rpc_id: JsonValue | None,
    params: dict[str, JsonValue],
    headers: dict[str, str],
    *,
    http: bool,
) -> Reply | None:
    header_version = headers.get("mcp-protocol-version")
    meta_version = _meta_version(params)
    if state.era == MODERN:
        if (
            "transport.version-negotiation" not in state.defects
            and header_version
            and meta_version
            and header_version != meta_version
        ):
            return _error_reply(rpc_id, 400, HEADER_MISMATCH, "Header mismatch")
        offered = header_version or meta_version
        if (
            "transport.version-negotiation" not in state.defects
            and offered
            and offered != state.era
        ):
            return _unsupported(rpc_id, offered, state.era)
        if http and "transport.required-headers" not in state.defects:
            if "mcp-method" not in headers:
                return _error_reply(rpc_id, 400, HEADER_MISMATCH, "Header mismatch")
            if method == "tools/call" and "mcp-name" not in headers:
                return _error_reply(rpc_id, 400, HEADER_MISMATCH, "Header mismatch")
        return None
    if (
        http
        and method != "initialize"
        and header_version
        and header_version != state.era
        and "transport.version-negotiation" not in state.defects
    ):
        session_id = headers.get("mcp-session-id")
        if not session_id or session_id not in state.sessions:
            return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")
        return _error_reply(rpc_id, 400, INVALID_PARAMS, "Unsupported protocol version")
    return None


def _session_gate(
    state: FixtureState,
    headers: dict[str, str],
    rpc_id: JsonValue | None,
) -> Reply | None:
    session_id = headers.get("mcp-session-id")
    if not session_id:
        return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")
    if session_id in state.sessions:
        return None
    if "session.expired-empty-success" in state.defects:
        return _result_reply(rpc_id, _empty_result())
    if "session.expired-not-404" in state.defects:
        return _error_reply(rpc_id, 400, -32600, "expired")
    return _error_reply(rpc_id, 404, -32600, "Session not found")


def _dispatch(
    state: FixtureState,
    method: str,
    rpc_id: JsonValue | None,
    params: dict[str, JsonValue],
    *,
    http: bool,
) -> Reply:
    if method == "initialize":
        return _initialize(state, rpc_id, params)
    if method == "server/discover":
        return _discover(state, rpc_id, params)
    if method == "tools/list":
        if state.era != MODERN and not state.sessions:
            return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")
        return _result_reply(rpc_id, _tools_result())
    if method in {"resources/list", "prompts/list"}:
        return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")
    if method == "tools/call":
        return _call(state, rpc_id, params, http=http)
    if "transport.unknown-method" in state.defects:
        if http:
            return Reply(500, "text/plain", b"internal")
        return _result_reply(rpc_id, {"ok": True})
    return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")


def _initialize(
    state: FixtureState,
    rpc_id: JsonValue | None,
    params: dict[str, JsonValue],
) -> Reply:
    offered = params.get("protocolVersion")
    chosen = state.era
    if (
        isinstance(offered, str)
        and offered == "1999-01-01"
        and "transport.version-negotiation" in state.defects
    ):
        chosen = offered
    state.generation += 1
    session_id = secrets.token_hex(16)
    state.sessions.add(session_id)
    caps = _capabilities(state)
    result: dict[str, JsonValue] = {
        "protocolVersion": chosen,
        "capabilities": caps,
        "serverInfo": {"name": "fixture", "version": "1"},
        "instructions": "fixture",
    }
    return Reply(
        200,
        "application/json",
        _result_body(rpc_id, result),
        headers=((b"mcp-session-id", session_id.encode()),),
    )


def _discover(
    state: FixtureState,
    rpc_id: JsonValue | None,
    params: dict[str, JsonValue],
) -> Reply:
    if state.era != MODERN:
        return _error_reply(rpc_id, 200, METHOD_NOT_FOUND, "Method not found")
    state.generation += 1
    versions: list[JsonValue] = [state.era]
    offered = _meta_version(params)
    if offered == "1999-01-01" and "transport.version-negotiation" in state.defects:
        versions.append(offered)
    result: dict[str, JsonValue] = {
        "supportedVersions": versions,
        "capabilities": _capabilities(state),
        "instructions": "fixture",
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "private",
    }
    return _result_reply(rpc_id, result)


def _call(
    state: FixtureState,
    rpc_id: JsonValue | None,
    params: dict[str, JsonValue],
    *,
    http: bool,
) -> Reply:
    name = params.get("name")
    arguments = params.get("arguments")
    if name == "list_tickets":
        return _result_reply(rpc_id, _ticket_list())
    if name == "slow_report":
        return _slow_report(rpc_id, arguments)
    if name == "create_ticket":
        return _result_reply(rpc_id, _created())
    if name != "get_ticket":
        return _error_reply(rpc_id, 200, INVALID_PARAMS, "Unknown tool")
    if isinstance(arguments, dict) and arguments.get("stream") is True:
        if http:
            first, second = _stream(state)
            return Reply(200, "text/event-stream", b"", chunks=(first, second))
        line = _result_body(rpc_id, _ticket(state)) + b"\n"
        return Reply(200, "application/json", line[32:], prefix=line[:32])
    return _result_reply(rpc_id, _ticket(state))


def _stream(state: FixtureState) -> tuple[bytes, bytes]:
    first_data = b'{"n":1}'
    second_data = b'{"n":2}'
    third_data = b'{"n":3}'
    state.events = [("1", first_data), ("2", second_data), ("3", third_data)]
    first = _event("1", first_data)
    rest = _event("2", second_data) + _event("3", third_data)
    return first, rest


def _ticket(state: FixtureState) -> dict[str, JsonValue]:
    ticket_id = state.ticket_id()
    return {
        "content": [{"type": "text", "text": ticket_id}],
        "structuredContent": {"id": ticket_id},
        "isError": False,
    }


def _empty_result() -> dict[str, JsonValue]:
    return {"content": [], "isError": False}


def _ticket_list() -> dict[str, JsonValue]:
    return {
        "content": [{"type": "text", "text": "ticket-1"}],
        "structuredContent": {"tickets": ["ticket-1"]},
        "isError": False,
    }


def _created() -> dict[str, JsonValue]:
    return {
        "content": [{"type": "text", "text": "created"}],
        "structuredContent": {"id": "ticket-created"},
        "isError": False,
    }


def _delay(arguments: JsonValue) -> float:
    if not isinstance(arguments, dict):
        return 0.0
    raw = arguments.get("delay")
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return 0.0
    return min(float(raw), 30.0)


def _slow_report(rpc_id: JsonValue | None, arguments: JsonValue) -> Reply:
    delay = _delay(arguments)
    if delay > 0:
        time.sleep(delay)
    return _result_reply(
        rpc_id,
        {"content": [{"type": "text", "text": "ok"}], "isError": False},
    )


def _tools_result() -> dict[str, JsonValue]:
    ticket: dict[str, JsonValue] = {
        "name": "get_ticket",
        "description": "Read a ticket.",
        "inputSchema": {"type": "object", "properties": {"stream": {"type": "boolean"}}},
        "outputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }
    listed: dict[str, JsonValue] = {
        "name": "list_tickets",
        "description": "List tickets.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    }
    slow: dict[str, JsonValue] = {
        "name": "slow_report",
        "description": "Read a slow report.",
        "inputSchema": {"type": "object", "properties": {"delay": {"type": "number"}}},
        "annotations": {"readOnlyHint": True},
    }
    created: dict[str, JsonValue] = {
        "name": "create_ticket",
        "description": "Create a ticket.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    return {
        "tools": [ticket, listed, slow, created],
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "private",
    }


def _capabilities(state: FixtureState) -> dict[str, JsonValue]:
    if "transport.capabilities-honesty" in state.defects:
        return {}
    return {"tools": {}}


def _bearer(value: str) -> str | None:
    prefix = "bearer "
    if value.lower().startswith(prefix):
        return value[len(prefix) :]
    return None


def _meta_version(params: dict[str, JsonValue]) -> str | None:
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    version = meta.get(PROTOCOL_VERSION_META_KEY)
    if isinstance(version, str):
        return version
    return None


def _unsupported(rpc_id: JsonValue | None, offered: str, era: str) -> Reply:
    body = _error_body(
        rpc_id,
        UNSUPPORTED_PROTOCOL_VERSION,
        "Unsupported protocol version",
        {"supported": [era], "requested": offered},
    )
    return Reply(400, "application/json", body)


def _error_reply(rpc_id: JsonValue | None, status: int, code: int, message: str) -> Reply:
    return Reply(status, "application/json", _error_body(rpc_id, code, message))


def _result_reply(rpc_id: JsonValue | None, result: dict[str, JsonValue]) -> Reply:
    return Reply(200, "application/json", _result_body(rpc_id, result))


def _result_body(rpc_id: JsonValue | None, result: dict[str, JsonValue]) -> bytes:
    payload: dict[str, JsonValue] = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
    return json.dumps(payload).encode()


def _error_body(
    rpc_id: JsonValue | None,
    code: int,
    message: str,
    data: dict[str, JsonValue] | None = None,
) -> bytes:
    error: dict[str, JsonValue] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    payload: dict[str, JsonValue] = {"jsonrpc": "2.0", "id": rpc_id, "error": error}
    return json.dumps(payload).encode()


def _event(event_id: str, data: bytes) -> bytes:
    return f"id: {event_id}\ndata: ".encode() + data + b"\n\n"


def _object(raw: bytes) -> dict[str, JsonValue] | None:
    try:
        loaded = json.loads(raw or b"null")
    except json.JSONDecodeError:
        return None
    try:
        mapped = json_value(loaded)
    except ProtocolError:
        return None
    if isinstance(mapped, dict):
        return mapped
    return None


class FixtureApp:
    def __init__(self, era: str, defects: frozenset[str]) -> None:
        self.state = FixtureState(era, defects, token="http")

    async def __call__(self, scope: Message, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await _lifespan(receive, send)
            return
        if kind != "http":
            return
        method = scope.get("method")
        path = scope.get("path")
        method_text = method if isinstance(method, str) else ""
        path_text = path if isinstance(path, str) else ""
        if path_text in {"/__fixture/expire-session", "/__fixture/reset"}:
            await _control(self.state, path_text, method_text, scope, send)
            return
        if method_text == "GET" and path_text in {"/mcp", "/sse"}:
            await _get(self.state, path_text, scope, receive, send)
            return
        if method_text != "POST" or path_text.rstrip("/") not in {"/mcp", "/sse", "/messages"}:
            await _plain(send, 404, b"missing")
            return
        body = await _read_body(receive)
        require = path_text.rstrip("/") == "/mcp"
        reply = self.state.answer(
            body,
            _headers(scope),
            http=True,
            origin=_origin(scope),
            require_session=require,
        )
        await _write(send, reply)


def serve_stdio(era: str, defects: frozenset[str]) -> None:
    state = FixtureState(era, defects, token=secrets.token_hex(4))
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return
        reply = state.answer(line.strip(), {}, http=False, origin="stdio")
        if reply.prefix:
            sys.stdout.buffer.write(reply.prefix)
            sys.stdout.buffer.flush()
        if reply.status == 202 or not reply.body:
            continue
        payload = reply.body if reply.body.endswith(b"\n") else reply.body + b"\n"
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()


def serve_http(host: str, port: int, *, era: str, defects: frozenset[str]) -> None:
    import uvicorn

    uvicorn.run(
        FixtureApp(era, defects), host=host, port=port, log_level="warning", access_log=False
    )


async def _control(state: FixtureState, path: str, method: str, scope: Message, send: Send) -> None:
    if _client_host(scope) not in _LOOPBACK:
        await _plain(send, 403, b'{"error":"forbidden"}')
        return
    if method != "POST":
        await _plain(send, 405, b"")
        return
    state.sessions.clear()
    if path.endswith("/reset"):
        state.generation = 0
        state.sse_token = None
    await _plain(send, 200, b'{"ok":true}', "application/json")


async def _get(
    state: FixtureState,
    path: str,
    scope: Message,
    receive: Receive,
    send: Send,
) -> None:
    last = _headers(scope).get("last-event-id")
    if last:
        await _plain(send, 200, state.resume(last), "text/event-stream")
        return
    if path == "/sse":
        session_id = state.mint_sse()
        await _start(send, 200, "text/event-stream", ())
        await _chunk(
            send, f"event: endpoint\ndata: /messages/?session_id={session_id}\n\n".encode(), True
        )
        await _wait_disconnect(receive, send)
        return
    await _start(send, 200, "text/event-stream", ())
    await _chunk(send, b": idle\n\n", True)
    await _wait_disconnect(receive, send)


async def _lifespan(receive: Receive, send: Send) -> None:
    while True:
        message = await receive()
        kind = message.get("type")
        if kind == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif kind == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _write(send: Send, reply: Reply) -> None:
    if reply.chunks is not None:
        await _start(send, reply.status, reply.content_type, reply.headers)
        await _chunk(send, reply.chunks[0], True)
        await _chunk(send, reply.chunks[1], False)
        return
    await _start(send, reply.status, reply.content_type, reply.headers, length=len(reply.body))
    await _chunk(send, reply.body, False)


async def _plain(
    send: Send,
    status: int,
    payload: bytes,
    content_type: str = "text/plain",
) -> None:
    await _start(send, status, content_type, (), length=len(payload))
    await _chunk(send, payload, False)


async def _start(
    send: Send,
    status: int,
    content_type: str,
    extra: tuple[tuple[bytes, bytes], ...],
    *,
    length: int | None = None,
) -> None:
    headers: list[tuple[bytes, bytes]] = [(b"content-type", content_type.encode())]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    headers.extend(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})


async def _chunk(send: Send, payload: bytes, more: bool) -> None:
    await send({"type": "http.response.body", "body": payload, "more_body": more})


async def _wait_disconnect(receive: Receive, send: Send) -> None:
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            await _chunk(send, b"", False)
            return


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            return b"".join(chunks)
        body = message.get("body", b"")
        if isinstance(body, bytes):
            chunks.append(body)
        if message.get("more_body") is not True:
            return b"".join(chunks)


def _headers(scope: Message) -> dict[str, str]:
    raw = scope.get("headers")
    mapped: dict[str, str] = {}
    if not isinstance(raw, list):
        return mapped
    for item in raw:
        pair = _byte_pair(item)
        if pair is None:
            continue
        key, value = pair
        mapped[key.decode().lower()] = value.decode()
    return mapped


def _byte_pair(item: object) -> tuple[bytes, bytes] | None:
    if not isinstance(item, tuple) or len(item) != 2:
        return None
    key, value = item
    if isinstance(key, bytes) and isinstance(value, bytes):
        return key, value
    return None


def _client_host(scope: Message) -> str:
    client = scope.get("client")
    if isinstance(client, tuple) and client and isinstance(client[0], str):
        return client[0]
    return ""


def _origin(scope: Message) -> str:
    scheme = scope.get("scheme")
    server = scope.get("server")
    scheme_text = scheme if isinstance(scheme, str) else "http"
    if (
        isinstance(server, tuple)
        and len(server) == 2
        and isinstance(server[0], str)
        and isinstance(server[1], int)
    ):
        return f"{scheme_text}://{server[0]}:{server[1]}"
    return "http://127.0.0.1"
