from __future__ import annotations

import json
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

import anyio
import httpx2
from mcp_types import PROTOCOL_VERSION_META_KEY
from mcp_types.jsonrpc import HEADER_MISMATCH, METHOD_NOT_FOUND, UNSUPPORTED_PROTOCOL_VERSION

from mcp_cross_exam import SUPPORTED_PROTOCOL_REVISIONS
from mcp_cross_exam.probes.base import (
    Call,
    Observation,
    Probe,
    ProbeContext,
    ToolView,
    is_empty_success,
    tool_class,
)
from mcp_cross_exam.transport import Finding, Frame, Timeout, TransportFailure
from mcp_cross_exam.transport.base import MODERN_VERSION, JsonValue, make_frame

BOGUS = "1999-01-01"
UNKNOWN_SESSION = "unknown-session-id"
DROP_AT = 16
CALL_TIMEOUT = 5.0
SILENT = "agent silently degrades"
_HANDSHAKE = tuple(item for item in SUPPORTED_PROTOCOL_REVISIONS if item != MODERN_VERSION)
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_EVENT_ID = re.compile(rb"(?m)^id:[ \t]*([^\r\n]+)")
_RFC_6750 = "https://www.rfc-editor.org/rfc/rfc6750"
_RFC_9728 = "https://www.rfc-editor.org/rfc/rfc9728"


class VersionNegotiation(Probe):
    id = "transport.version-negotiation"
    default_severity = "high"
    revisions = SUPPORTED_PROTOCOL_REVISIONS

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        offered = await _offer_bogus(ctx)
        checked = await _offer_mismatch(ctx) if ctx.http else None
        calls = (offered,) if checked is None else (offered, checked)
        frames = tuple(call.inbound for call in calls if call.inbound is not None)
        return Observation(
            ctx.revision,
            tool,
            frames,
            calls=calls,
            saw_header_check=checked is not None,
        )

    def assert_(self, observation: Observation) -> list[Finding]:
        if not observation.calls:
            return []
        version_ok = _version_ok(observation.calls[0], observation.revision)
        header_ok = True
        if observation.saw_header_check and len(observation.calls) > 1:
            header_ok = _header_ok(observation.calls[1], observation.revision)
        if version_ok and header_ok:
            return []
        return [
            _finding(
                self,
                observation,
                "protocol version negotiation does not match this revision",
                _refs(observation.revision, "both"),
            )
        ]

    async def teardown(self, ctx: ProbeContext) -> None:
        if not ctx.http:
            await ctx.transport.reset()


class CapabilitiesHonesty(Probe):
    id = "transport.capabilities-honesty"
    default_severity = "high"
    revisions = SUPPORTED_PROTOCOL_REVISIONS

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        calls = (
            await _invoke(ctx, "tools/list", {}),
            await _invoke(ctx, "resources/list", {}),
            await _invoke(ctx, "prompts/list", {}),
        )
        frames = tuple(call.inbound for call in calls if call.inbound is not None)
        capabilities = None if ctx.server is None else ctx.server.capabilities
        return Observation(ctx.revision, tool, frames, calls=calls, capabilities=capabilities)

    def assert_(self, observation: Observation) -> list[Finding]:
        declared = observation.capabilities or {}
        names = {"tools/list": "tools", "resources/list": "resources", "prompts/list": "prompts"}
        for method, call in zip(names, observation.calls, strict=True):
            if call.error_code == METHOD_NOT_FOUND or call.result is None:
                continue
            if names[method] not in declared:
                return [
                    _finding(
                        self,
                        observation,
                        "server answered a feature it did not declare",
                        _refs(observation.revision, "lifecycle"),
                    )
                ]
        return []


class RequiredHeaders(Probe):
    id = "transport.required-headers"
    default_severity = "high"
    revisions = (MODERN_VERSION,)

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.http and not ctx.legacy

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        call = await _raw_json(
            ctx,
            _dump("tools/call", {"name": "get_ticket", "arguments": {}}, 77011),
            {"mcp-protocol-version": ctx.revision},
        )
        frames = () if call.inbound is None else (call.inbound,)
        return Observation(ctx.revision, tool, frames, calls=(call,))

    def assert_(self, observation: Observation) -> list[Finding]:
        if observation.calls and observation.calls[0].status == 400:
            return []
        return [
            _finding(
                self,
                observation,
                "server accepted a tool call without required routing headers",
                _refs(observation.revision, "transport"),
            )
        ]


class UnknownMethod(Probe):
    id = "transport.unknown-method"
    default_severity = "high"
    revisions = SUPPORTED_PROTOCOL_REVISIONS

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        call = await _invoke(ctx, "x/not-a-method", {}, timeout=CALL_TIMEOUT)
        frames = () if call.inbound is None else (call.inbound,)
        return Observation(ctx.revision, tool, frames, calls=(call,))

    def assert_(self, observation: Observation) -> list[Finding]:
        if observation.calls and _unknown_ok(observation.calls[0]):
            return []
        return [
            _finding(
                self,
                observation,
                "server did not reject an unknown method",
                _refs(observation.revision, "both"),
            )
        ]


class TokenExpired(Probe):
    id = "session.token-expired-empty-success"
    default_severity = "high"
    revisions = SUPPORTED_PROTOCOL_REVISIONS

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.http and ctx.expired_bearer is not None

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        token = ctx.expired_bearer or ""
        call = await _invoke(
            ctx,
            "tools/call",
            _ticket_params(),
            headers={"Authorization": f"Bearer {token}"},
        )
        frames = () if call.inbound is None else (call.inbound,)
        return Observation(ctx.revision, tool, frames, calls=(call,))

    def assert_(self, observation: Observation) -> list[Finding]:
        if not observation.calls or not _empty_call(observation.calls[-1], observation.tool):
            return []
        return [
            _finding(
                self,
                observation,
                "expired bearer returned an empty tool result",
                _token_refs(observation.revision),
                impact=SILENT,
            )
        ]


class SessionExpiredNot404(Probe):
    id = "session.expired-not-404"
    default_severity = "high"
    revisions = _HANDSHAKE

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.http and not ctx.legacy

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        return await _session_observation(ctx, tool)

    def assert_(self, observation: Observation) -> list[Finding]:
        return _expired_finding(self, observation, want_empty=False)


class SessionExpiredEmptySuccess(Probe):
    id = "session.expired-empty-success"
    default_severity = "high"
    revisions = _HANDSHAKE

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.http and not ctx.legacy

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        return await _session_observation(ctx, tool)

    def assert_(self, observation: Observation) -> list[Finding]:
        return _expired_finding(self, observation, want_empty=True)


class ResumeGap(Probe):
    id = "transport.resume-gap"
    default_severity = "medium"
    revisions = _HANDSHAKE

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.http

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        await ctx.transport.reset()
        seen = await _dropped_stream(ctx)
        seen_ids = _ids(seen)
        resumed = b""
        if seen_ids:
            resumed = await _resume(ctx, seen_ids[-1])
        frames = (
            make_frame(direction="inbound", body=seen),
            make_frame(direction="inbound", body=resumed),
        )
        return Observation(
            ctx.revision,
            tool,
            frames,
            seen_ids=seen_ids,
            resumed_ids=_ids(resumed),
        )

    def assert_(self, observation: Observation) -> list[Finding]:
        if not observation.seen_ids or not _resume_bad(
            observation.seen_ids, observation.resumed_ids
        ):
            return []
        return [
            _finding(
                self,
                observation,
                "server replayed a stream with a gap or a repeated event id",
                _refs(observation.revision, "transport"),
            )
        ]


class ReconnectFails(Probe):
    id = "transport.reconnect-fails"
    default_severity = "high"
    revisions = SUPPORTED_PROTOCOL_REVISIONS

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        if ctx.http:
            await ctx.transport.reset()
        before = await _invoke(ctx, "tools/call", _ticket_params(), timeout=CALL_TIMEOUT)
        await _dropped_stream(ctx)
        await ctx.transport.reset()
        after = await _invoke(ctx, "tools/call", _ticket_params(), timeout=CALL_TIMEOUT)
        frames = tuple(call.inbound for call in (before, after) if call.inbound is not None)
        return Observation(ctx.revision, tool, frames, calls=(before, after))

    def assert_(self, observation: Observation) -> list[Finding]:
        if len(observation.calls) < 2:
            return []
        before, after = observation.calls
        if after.timed_out or after.error_code is not None or after.result != before.result:
            return [
                _finding(
                    self,
                    observation,
                    "server did not resume the same result after reconnect",
                    _refs(observation.revision, "transport"),
                )
            ]
        return []


PROBES: tuple[Probe, ...] = (
    VersionNegotiation(),
    CapabilitiesHonesty(),
    RequiredHeaders(),
    UnknownMethod(),
    TokenExpired(),
    SessionExpiredNot404(),
    SessionExpiredEmptySuccess(),
    ResumeGap(),
    ReconnectFails(),
)


def _ticket_params() -> dict[str, JsonValue]:
    return {"name": "get_ticket", "arguments": {}}


def _spec(revision: str, section: str) -> str:
    if section == "transport" and revision == MODERN_VERSION:
        section = "basic/transports/streamable-http"
    elif section == "transport":
        section = "basic/transports"
    else:
        section = f"basic/{section}"
    return f"https://modelcontextprotocol.io/specification/{revision}/{section}"


def _refs(revision: str, kind: str) -> tuple[str, ...]:
    if kind == "both":
        return (_spec(revision, "lifecycle"), _spec(revision, "transport"))
    return (_spec(revision, kind),)


def _token_refs(revision: str) -> tuple[str, ...]:
    refs = [_spec(revision, "authorization"), _RFC_6750]
    if revision >= "2025-06-18":
        refs.append(_RFC_9728)
    return tuple(refs)


def _finding(
    probe: Probe,
    observation: Observation,
    summary: str,
    refs: tuple[str, ...],
    *,
    impact: str | None = None,
) -> Finding:
    tool = observation.tool
    return Finding(
        item_id=probe.id,
        severity=probe.default_severity,
        summary=summary,
        evidence=observation.frames[-1] if observation.frames else None,
        frames=observation.frames,
        spec_refs=refs,
        agent_impact=impact,
        classification=None if impact is None or tool is None else tool_class(tool),
    )


def _version_ok(call: Call, revision: str) -> bool:
    if _echoed(call):
        return False
    if revision == MODERN_VERSION:
        failed = call.error_code == UNSUPPORTED_PROTOCOL_VERSION and call.status in {None, 400}
        return failed
    if call.error_code is not None:
        return True
    result = call.result
    if not isinstance(result, dict):
        return False
    version = result.get("protocolVersion")
    if isinstance(version, str):
        return version != BOGUS
    versions = result.get("supportedVersions")
    return isinstance(versions, list) and bool(versions) and BOGUS not in versions


def _header_ok(call: Call, revision: str) -> bool:
    if revision == MODERN_VERSION:
        return call.status == 400 and call.error_code == HEADER_MISMATCH
    return call.status == 400


def _echoed(call: Call) -> bool:
    result = call.result
    if not isinstance(result, dict):
        return False
    if result.get("protocolVersion") == BOGUS:
        return True
    versions = result.get("supportedVersions")
    return isinstance(versions, list) and BOGUS in versions


def _unknown_ok(call: Call) -> bool:
    if call.timed_out or (call.status is not None and call.status >= 500):
        return False
    return call.error_code == METHOD_NOT_FOUND


def _empty_call(call: Call, tool: ToolView | None) -> bool:
    return (
        call.status == 200
        and tool is not None
        and call.result is not None
        and is_empty_success(call.result, tool)
    )


def _expired_finding(probe: Probe, observation: Observation, *, want_empty: bool) -> list[Finding]:
    if not observation.calls:
        return []
    follow = observation.calls[-1]
    if follow.status == 404 or _empty_call(follow, observation.tool) != want_empty:
        return []
    summary = (
        "expired session returned an empty tool result"
        if want_empty
        else "expired session was not rejected with not found"
    )
    return [
        _finding(
            probe,
            observation,
            summary,
            _refs(observation.revision, "transport"),
            impact=SILENT,
        )
    ]


def _resume_bad(seen: tuple[str, ...], resumed: tuple[str, ...]) -> bool:
    if not resumed:
        return False
    if any(item in seen for item in resumed):
        return True
    previous = _number(seen[-1])
    for item in resumed:
        current = _number(item)
        if previous is not None and current is not None and current > previous + 1:
            return True
        if current is not None:
            previous = current
    return False


def _number(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    return None


def _ids(payload: bytes) -> tuple[str, ...]:
    return tuple(match.group(1).decode().strip() for match in _EVENT_ID.finditer(payload))


async def _session_observation(ctx: ProbeContext, tool: ToolView | None) -> Observation:
    cached = ctx.cache.get("session")
    if cached is not None:
        return cached
    success = await _invoke(ctx, "tools/call", _ticket_params())
    hook = await _expire_hook(ctx)
    calls: tuple[Call, ...]
    if hook is None:
        follow = await _invoke(
            ctx,
            "tools/call",
            _ticket_params(),
            headers={"mcp-session-id": UNKNOWN_SESSION},
        )
        calls = (success, follow)
    else:
        follow = await _invoke(ctx, "tools/call", _ticket_params())
        calls = (success, hook, follow)
    frames = tuple(call.inbound for call in calls if call.inbound is not None)
    observation = Observation(ctx.revision, tool, frames, calls=calls)
    ctx.cache["session"] = observation
    return observation


async def _expire_hook(ctx: ProbeContext) -> Call | None:
    target = _control_url(ctx.endpoint)
    if target is None:
        return None
    try:
        async with httpx2.AsyncClient(timeout=2.0, trust_env=False) as client:
            response = await client.post(target)
    except (httpx2.HTTPError, OSError):
        return None
    frame = make_frame(
        direction="inbound",
        body=response.content,
        status=response.status_code,
        headers={str(key).lower(): str(value) for key, value in response.headers.items()},
    )
    if response.status_code >= 400:
        return None
    return _interpreted(frame)


def _control_url(endpoint: str | None) -> str | None:
    if endpoint is None:
        return None
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or host not in _LOOPBACK:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}/__fixture/expire-session"


async def _offer_bogus(ctx: ProbeContext) -> Call:
    if ctx.revision == MODERN_VERSION:
        params: dict[str, JsonValue] = {"_meta": {PROTOCOL_VERSION_META_KEY: BOGUS}}
        method = "server/discover"
    else:
        params = {
            "protocolVersion": BOGUS,
            "capabilities": {},
            "clientInfo": {"name": "mcp-cross-exam", "version": "0"},
        }
        method = "initialize"
    body = _dump(method, params, 77001)
    headers = {"mcp-protocol-version": BOGUS, "mcp-method": method}
    if ctx.http:
        return await _raw_json(ctx, body, headers)
    _payload, call = await _stdio_exchange(ctx, body, newline=True)
    return call


async def _offer_mismatch(ctx: ProbeContext) -> Call:
    params: dict[str, JsonValue] = {}
    if ctx.revision == MODERN_VERSION:
        params["_meta"] = {PROTOCOL_VERSION_META_KEY: ctx.revision}
    headers = {"mcp-protocol-version": BOGUS, "mcp-method": "tools/list"}
    session = _session_id(ctx)
    if session is not None:
        headers["mcp-session-id"] = session
    return await _raw_json(ctx, _dump("tools/list", params, 77002), headers)


async def _dropped_stream(ctx: ProbeContext) -> bytes:
    params: dict[str, JsonValue] = {"name": "get_ticket", "arguments": {"stream": True}}
    body = _dump("tools/call", params, 77021)
    if not ctx.http:
        payload, _call = await _stdio_exchange(ctx, body, newline=False)
        await _drop(ctx)
        return payload
    headers = _routing(ctx, "tools/call", "get_ticket")
    return await _http_payload(ctx, body, headers, stop_early=True)


async def _resume(ctx: ProbeContext, last: str) -> bytes:
    headers = {
        "last-event-id": last,
        "accept": "text/event-stream",
        "mcp-protocol-version": ctx.revision,
    }
    return await _http_payload(ctx, b"", headers, stop_early=False, method="GET")


async def _invoke(
    ctx: ProbeContext,
    method: str,
    params: Mapping[str, JsonValue],
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> Call:
    start = len(ctx.transport.recorder.frames)
    result: JsonValue | None = None
    timed_out = False
    try:
        result = await ctx.transport.request(method, params, headers=headers, timeout=timeout)
    except Timeout:
        timed_out = True
    except TransportFailure:
        result = None
    return _interpreted(_new_inbound(ctx.transport.recorder.frames, start), result, timed_out)


async def _raw_json(ctx: ProbeContext, body: bytes, headers: Mapping[str, str]) -> Call:
    start = len(ctx.transport.recorder.frames)
    await _http_payload(ctx, body, headers, stop_early=False)
    return _interpreted(_new_inbound(ctx.transport.recorder.frames, start))


async def _http_payload(
    ctx: ProbeContext,
    body: bytes,
    headers: Mapping[str, str],
    *,
    stop_early: bool,
    method: str = "POST",
) -> bytes:
    payload = bytearray()
    await ctx.transport.raw.send_bytes(
        body, headers=dict(headers), timeout=CALL_TIMEOUT, method=method
    )
    try:
        with anyio.move_on_after(CALL_TIMEOUT):
            async for chunk in ctx.transport.raw.stream():
                payload.extend(chunk)
                if stop_early and _stream_ready(payload):
                    break
    finally:
        await _drop(ctx)
    return bytes(payload)


async def _stdio_exchange(ctx: ProbeContext, body: bytes, *, newline: bool) -> tuple[bytes, Call]:
    payload = bytearray()
    done = anyio.Event()

    async def collect() -> None:
        try:
            async for chunk in ctx.transport.raw.stream():
                payload.extend(chunk)
                if _stdio_ready(payload, newline=newline):
                    return
        finally:
            done.set()

    start = len(ctx.transport.recorder.frames)
    async with anyio.create_task_group() as group:
        group.start_soon(collect)
        await anyio.sleep(0)
        outbound = body if body.endswith(b"\n") else body + b"\n"
        await ctx.transport.raw.send_bytes(outbound)
        with anyio.move_on_after(CALL_TIMEOUT):
            await done.wait()
        group.cancel_scope.cancel()
    frame: Frame | None = None
    for _ in range(20):
        frame = _new_inbound(ctx.transport.recorder.frames, start)
        if frame is not None or not newline:
            break
        await anyio.sleep(0.01)
    if frame is None and payload.strip():
        frame = make_frame(direction="inbound", body=bytes(payload.splitlines()[0]))
    return bytes(payload), _interpreted(frame)


def _stdio_ready(payload: bytearray, *, newline: bool) -> bool:
    if newline:
        return b"\n" in payload
    return len(payload) >= DROP_AT


def _stream_ready(payload: bytearray) -> bool:
    complete = b"\n\n" in payload or b"\r\n\r\n" in payload
    return len(payload) >= DROP_AT and complete


async def _drop(ctx: ProbeContext) -> None:
    try:
        await ctx.transport.raw.drop()
    except (TransportFailure, RuntimeError, anyio.ClosedResourceError):
        return


def _routing(ctx: ProbeContext, method: str, name: str | None) -> dict[str, str]:
    headers = {"mcp-protocol-version": ctx.revision, "mcp-method": method}
    if name is not None:
        headers["mcp-name"] = name
    session = _session_id(ctx)
    if session is not None:
        headers["mcp-session-id"] = session
    return headers


def _session_id(ctx: ProbeContext) -> str | None:
    for frame in reversed(ctx.transport.recorder.frames):
        for key, value in frame.headers.items():
            if key.lower() == "mcp-session-id" and value:
                return value
    return None


def _new_inbound(frames: tuple[Frame, ...], start: int) -> Frame | None:
    chosen: Frame | None = None
    for frame in frames[start:]:
        if frame.direction == "inbound" and frame.body.strip():
            chosen = frame
    return chosen


def _interpreted(
    frame: Frame | None, result: JsonValue | None = None, timed_out: bool = False
) -> Call:
    parsed = None if frame is None else frame.parsed
    if result is None and isinstance(parsed, dict) and "result" in parsed:
        result = parsed["result"]
    code: int | None = None
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict):
            raw_code = error.get("code")
            if isinstance(raw_code, int) and not isinstance(raw_code, bool):
                code = raw_code
    headers = {}
    status = None
    if frame is not None:
        status = frame.status
        headers = {key.lower(): value for key, value in frame.headers.items()}
    return Call(status, headers, result, code, frame, timed_out)


def _dump(method: str, params: Mapping[str, JsonValue], rpc_id: int) -> bytes:
    payload: dict[str, JsonValue] = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": dict(params),
    }
    return json.dumps(payload).encode()
