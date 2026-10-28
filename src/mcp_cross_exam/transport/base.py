from __future__ import annotations

import json
import time
from collections import deque
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn, Protocol

import anyio
import mcp_types as types
from mcp import Client
from mcp.client.session import ClientSession
from mcp.shared.dispatcher import CallOptions
from mcp.shared.exceptions import MCPError
from mcp.shared.inbound import MCP_METHOD_HEADER, MCP_PROTOCOL_VERSION_HEADER
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    CONNECTION_CLOSED,
    METHOD_NOT_FOUND,
    PROTOCOL_VERSION_META_KEY,
    REQUEST_TIMEOUT,
    Implementation,
)
from pydantic import BaseModel, ConfigDict, ValidationError

from mcp_cross_exam import DISTRIBUTION_NAME, __version__
from mcp_cross_exam.transport.sdk import (
    SdkTransport,
    build_session,
    cancel_scope,
    dispatcher,
    entered,
    scope_chain,
    set_entered,
    set_exit_stack,
    set_session,
    set_stamp,
)
from mcp_cross_exam.transport.sdk import (
    client_info as session_client_info,
)
from mcp_cross_exam.transport.sdk import (
    stamp as session_stamp,
)
from mcp_cross_exam.types import (
    HANDSHAKE_LADDER,
    DataError,
)
from mcp_cross_exam.types import (
    MODERN_VERSION as MODERN_VERSION,
)
from mcp_cross_exam.types import (
    OFFERED_VERSIONS as OFFERED_VERSIONS,
)
from mcp_cross_exam.types import (
    Direction as Direction,
)
from mcp_cross_exam.types import (
    Frame as Frame,
)
from mcp_cross_exam.types import Hit as Hit
from mcp_cross_exam.types import (
    JsonValue as JsonValue,
)
from mcp_cross_exam.types import (
    Severity as Severity,
)
from mcp_cross_exam.types import (
    json_value as json_value,
)

Finding = Hit

TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
DEFAULT_REQUEST_TIMEOUT = 30.0

call_headers: ContextVar[Mapping[str, str] | None] = ContextVar("call_headers", default=None)


class TransportFailure(Exception):
    pass


class ConnectFailed(TransportFailure):
    pass


class HandshakeFailed(TransportFailure):
    pass


class ProtocolError(TransportFailure):
    pass


class TransportClosed(TransportFailure):
    pass


class Timeout(TransportFailure):
    pass


class _NextEra(Exception):
    def __init__(self, supported: tuple[str, ...], answer: str) -> None:
        super().__init__(answer)
        self.supported = supported
        self.answer = answer


class LooseParams(types.RequestParams):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class LooseRequest(types.Request[LooseParams, str]):
    method: str
    params: LooseParams


class LooseResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class FrameRecorder:
    def __init__(self) -> None:
        self._frames: list[Frame] = []

    def add(self, frame: Frame) -> int:
        self._frames.append(frame)
        return len(self._frames) - 1

    @property
    def frames(self) -> tuple[Frame, ...]:
        return tuple(self._frames)


@dataclass(frozen=True, slots=True)
class Skip:
    probe_id: str
    tool: str | None
    reason: str


@dataclass(slots=True)
class RunLogs:
    path: Path
    stderr: deque[str] = field(default_factory=lambda: deque(maxlen=256))


@dataclass(frozen=True, slots=True)
class ServerState:
    revision: str
    server_info: dict[str, JsonValue] | None
    capabilities: dict[str, JsonValue]
    extensions: tuple[str, ...]
    instructions: str | None


@dataclass(slots=True)
class RunContext:
    recorder: FrameRecorder
    logs: RunLogs
    findings: list[Finding] = field(default_factory=list)
    server: ServerState | None = None
    skips: list[Skip] = field(default_factory=list)
    guard: str = "local"
    evidence_dropped: int = 0
    seed: int = 0
    run_id: str = ""


class RawChannel(Protocol):
    async def send_bytes(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        method: str = "POST",
    ) -> None: ...

    async def drop(self) -> None: ...

    def stream(self) -> AsyncIterator[bytes]: ...


class Transport(Protocol):
    recorder: FrameRecorder
    raw: RawChannel

    async def connect(self) -> RunContext: ...

    async def request(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> JsonValue: ...

    async def notify(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
    ) -> None: ...

    async def close(self) -> None: ...

    async def reset(self) -> RunContext: ...


def client_info() -> Implementation:
    return Implementation(name=DISTRIBUTION_NAME, version=__version__)


def make_context(run_dir: Path, recorder: FrameRecorder) -> RunContext:
    run_dir.mkdir(parents=True, exist_ok=True)
    return RunContext(recorder=recorder, logs=RunLogs(path=run_dir / "stderr.log"))


def json_object(value: object) -> dict[str, JsonValue]:
    dumped = json_value(value)
    if not isinstance(dumped, dict):
        raise DataError("response is not a json object")
    return dumped


def parse_json_bytes(body: bytes) -> JsonValue | None:
    stripped = body.strip()
    if not stripped:
        return None
    try:
        loaded = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    try:
        return json_value(loaded)
    except DataError:
        return None


def frame_identity(parsed: JsonValue | None) -> tuple[str | int | None, str | None]:
    if not isinstance(parsed, dict):
        return None, None
    raw_id = parsed.get("id")
    rpc_id = raw_id if isinstance(raw_id, str | int) and not isinstance(raw_id, bool) else None
    method = parsed.get("method")
    return rpc_id, method if isinstance(method, str) else None


def make_frame(
    *,
    direction: Direction,
    body: bytes,
    parsed: JsonValue | None = None,
    status: int | None = None,
    headers: Mapping[str, str] | None = None,
) -> Frame:
    if parsed is None:
        parsed = parse_json_bytes(body)
    rpc_id, method = frame_identity(parsed)
    return Frame(
        direction=direction,
        at=time.monotonic(),
        rpc_id=rpc_id,
        method=method,
        status=status,
        headers=dict(headers or {}),
        body=body,
        parsed=parsed,
    )


def modern_error(parsed: JsonValue | None) -> bool:
    if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
        return False
    error = parsed.get("error")
    if not isinstance(error, dict):
        return False
    code = error.get("code")
    return isinstance(code, int) and not isinstance(code, bool)


def failure_from(exc: Exception) -> TransportFailure:
    if isinstance(exc, TransportFailure):
        return exc
    if isinstance(exc, MCPError):
        if exc.code == REQUEST_TIMEOUT:
            return Timeout(exc.message)
        if exc.code == CONNECTION_CLOSED:
            return TransportClosed(exc.message)
        return ProtocolError(exc.message)
    if isinstance(exc, TimeoutError):
        return Timeout("timed out")
    if isinstance(exc, (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream)):
        return TransportClosed("connection closed")
    if isinstance(exc, ValidationError):
        return ProtocolError("response did not match the protocol")
    if isinstance(exc, OSError):
        return ConnectFailed("could not connect")
    return ProtocolError(f"transport failed: {type(exc).__name__}")


def passthrough(exc: BaseException) -> bool:
    return isinstance(exc, (KeyboardInterrupt, SystemExit, anyio.get_cancelled_exc_class()))


def collapse(exc: BaseException) -> BaseException:
    if not isinstance(exc, BaseExceptionGroup):
        return exc
    flattened = [collapse(item) for item in exc.exceptions]
    for item in flattened:
        if isinstance(item, TransportFailure):
            return item
    for item in flattened:
        if isinstance(item, Exception):
            return item
    for item in flattened:
        if passthrough(item):
            return item
    return exc


def translate(exc: BaseException) -> BaseException:
    current = collapse(exc)
    if isinstance(current, TransportFailure) or passthrough(current):
        return current
    if isinstance(current, Exception):
        return failure_from(current)
    return current


def raise_translated(exc: BaseException) -> NoReturn:
    mapped = translate(exc)
    if mapped is not exc:
        raise mapped from exc
    raise exc


@asynccontextmanager
async def shielded(start: anyio.CancelScope | None) -> AsyncIterator[None]:
    previous = [(scope, scope.shield) for scope in scope_chain(start)]
    for scope, _enabled in previous:
        scope.shield = True
    try:
        yield
    finally:
        for scope, enabled in previous:
            scope.shield = enabled


def _fatal(exc: MCPError) -> None:
    if exc.code == REQUEST_TIMEOUT:
        raise Timeout(exc.message) from exc
    if exc.code == CONNECTION_CLOSED:
        raise TransportClosed(exc.message) from exc


def _supported(exc: MCPError) -> tuple[str, ...]:
    try:
        data = types.UnsupportedProtocolVersionErrorData.model_validate(exc.data)
    except ValidationError:
        return ()
    return tuple(data.supported)


def _loose_params(
    params: Mapping[str, JsonValue] | None,
    meta: Mapping[str, JsonValue] | None,
) -> LooseParams:
    merged: dict[str, JsonValue] = dict(params or {})
    if meta:
        existing = merged.get("_meta")
        base = dict(existing) if isinstance(existing, dict) else {}
        base.update(meta)
        merged["_meta"] = base
    return LooseParams.model_validate(merged)


def _result_json(result: LooseResult) -> JsonValue:
    return json_value(result.model_dump(mode="json", by_alias=True, exclude_none=True))


def _merge_headers(opts: CallOptions, headers: Mapping[str, str]) -> None:
    slot = opts.setdefault("headers", {})
    slot.update(headers)


async def session_request(
    session: ClientSession,
    method: str,
    params: Mapping[str, JsonValue] | None,
    *,
    meta: Mapping[str, JsonValue] | None,
    headers: Mapping[str, str] | None,
    timeout: float | None,
) -> JsonValue:
    request = LooseRequest(method=method, params=_loose_params(params, meta))
    token = call_headers.set(dict(headers) if headers else None)
    original = session_stamp(session)

    def stamp(data: dict[str, object], opts: CallOptions) -> None:
        original(data, opts)
        if headers:
            _merge_headers(opts, headers)

    set_stamp(session, stamp)
    try:
        result = await session.send_request(
            request,
            LooseResult,
            request_read_timeout_seconds=timeout,
        )
        return _result_json(result)
    finally:
        set_stamp(session, original)
        call_headers.reset(token)


async def session_notify(
    session: ClientSession,
    method: str,
    params: Mapping[str, JsonValue] | None,
    *,
    meta: Mapping[str, JsonValue] | None,
) -> None:
    dumped = _loose_params(params, meta).model_dump(by_alias=True, exclude_none=True, mode="json")
    data: dict[str, object] = {"method": method, "params": dumped}
    opts: CallOptions = {}
    session_stamp(session)(data, opts)
    stamped = data.get("params")
    await dispatcher(session).notify(method, stamped if isinstance(stamped, dict) else None, opts)


def _dump_model(model: BaseModel) -> dict[str, JsonValue]:
    return json_object(model.model_dump(mode="json", by_alias=True, exclude_none=True))


def server_state(client: Client) -> ServerState:
    revision = client.protocol_version
    info = client.server_info
    capabilities = client.server_capabilities
    dumped = _dump_model(capabilities)
    names: list[str] = []
    extensions = dumped.get("extensions")
    if isinstance(extensions, dict):
        names.extend(sorted(extensions))
    if "tasks" in dumped and TASKS_EXTENSION not in names:
        names.append(TASKS_EXTENSION)
    return ServerState(
        revision=revision,
        server_info=None if info is None else _dump_model(info),
        capabilities=dumped,
        extensions=tuple(names),
        instructions=client.instructions,
    )


async def _tools_probe(session: ClientSession) -> None:
    info = _dump_model(session_client_info(session))
    params: dict[str, object] = {
        "_meta": {
            PROTOCOL_VERSION_META_KEY: MODERN_VERSION,
            CLIENT_INFO_META_KEY: info,
            CLIENT_CAPABILITIES_META_KEY: {},
        }
    }
    opts: CallOptions = {
        "headers": {
            MCP_PROTOCOL_VERSION_HEADER: MODERN_VERSION,
            MCP_METHOD_HEADER: "tools/list",
        },
        "timeout": DEFAULT_REQUEST_TIMEOUT,
    }
    raw = await dispatcher(session).send_raw_request("tools/list", params, opts)
    LooseResult.model_validate(raw)
    session.adopt(
        types.DiscoverResult(
            supported_versions=[MODERN_VERSION],
            capabilities=types.ServerCapabilities(),
        )
    )


async def _probe_tools(session: ClientSession, exc: MCPError) -> None:
    missing = exc.code in {METHOD_NOT_FOUND, types.UNSUPPORTED_PROTOCOL_VERSION}
    parent = _supported(exc)
    try:
        await _tools_probe(session)
    except MCPError as probe_error:
        _fatal(probe_error)
        hinted = _supported(probe_error)
        if not hinted and missing:
            hinted = parent
        raise _NextEra(hinted, probe_error.message) from probe_error
    except ValidationError as probe_error:
        raise _NextEra(parent if missing else (), exc.message) from probe_error


async def _modern(session: ClientSession) -> None:
    try:
        raw = await session.send_discover(MODERN_VERSION)
    except MCPError as exc:
        _fatal(exc)
        if exc.code == types.UNSUPPORTED_PROTOCOL_VERSION and MODERN_VERSION in _supported(exc):
            try:
                raw = await session.send_discover(MODERN_VERSION)
            except MCPError as retry:
                _fatal(retry)
                raise _NextEra(_supported(retry), retry.message) from retry
        else:
            await _probe_tools(session, exc)
            return
    try:
        result = types.DiscoverResult.model_validate(raw)
    except ValidationError as exc:
        raise ProtocolError("response did not match the protocol") from exc
    modern = [item for item in result.supported_versions if item == MODERN_VERSION]
    if modern:
        session.adopt(result)
        return
    handshake = tuple(item for item in result.supported_versions if item in HANDSHAKE_LADDER)
    raise _NextEra(handshake, "server did not offer 2026-07-28")


async def _initialize(session: ClientSession, version: str) -> types.InitializeResult:
    return await session.send_request(
        types.InitializeRequest(
            params=types.InitializeRequestParams(
                protocol_version=version,
                capabilities=types.ClientCapabilities(),
                client_info=session_client_info(session),
            )
        ),
        types.InitializeResult,
    )


async def _handshake(
    session: ClientSession,
    *,
    forced: str | None,
    supported: tuple[str, ...],
    answer: str,
) -> None:
    if forced is not None:
        pending = [forced]
    else:
        hinted = [item for item in HANDSHAKE_LADDER if item in supported]
        pending = hinted if hinted else list(HANDSHAKE_LADDER)
    tried: set[str] = set()
    last = answer or "server rejected the handshake"
    while pending:
        version = pending.pop(0)
        if version in tried:
            continue
        tried.add(version)
        try:
            result = await _initialize(session, version)
        except MCPError as exc:
            _fatal(exc)
            last = exc.message
            if forced is None:
                hinted = [item for item in HANDSHAKE_LADDER if item in _supported(exc)]
                if hinted:
                    pending = [item for item in hinted if item not in tried]
            continue
        chosen = result.protocol_version
        if chosen not in HANDSHAKE_LADDER:
            raise HandshakeFailed(f"server selected unsupported protocol version {chosen}")
        if forced is not None and chosen != forced:
            raise HandshakeFailed(f"server selected {chosen} instead of {forced}")
        session.adopt(result)
        await session.send_notification(types.InitializedNotification())
        return
    offered = forced if forced is not None else ", ".join(HANDSHAKE_LADDER)
    raise HandshakeFailed(f"server rejected protocol version {offered}: {last}")


async def negotiate(session: ClientSession, *, forced: str | None) -> None:
    if forced is not None and forced not in OFFERED_VERSIONS:
        raise HandshakeFailed(
            f"server rejected protocol version {forced}: unsupported protocol version"
        )
    if forced in HANDSHAKE_LADDER:
        await _handshake(session, forced=forced, supported=(), answer="")
        return
    try:
        await _modern(session)
    except _NextEra as exc:
        if forced == MODERN_VERSION:
            raise HandshakeFailed(
                f"server rejected protocol version {MODERN_VERSION}: {exc.answer}"
            ) from exc
        await _handshake(session, forced=None, supported=exc.supported, answer=exc.answer)


class SessionClient(Client):
    def __init__(self, server: SdkTransport, *, forced: str | None) -> None:
        super().__init__(
            server,
            cache=None,
            client_info=client_info(),
            mode="auto",
            read_timeout_seconds=DEFAULT_REQUEST_TIMEOUT,
        )
        self.forced = forced

    async def __aenter__(self) -> SessionClient:
        if entered(self):
            raise RuntimeError("Client is already entered; cannot reenter")
        set_entered(self, True)
        exit_stack = AsyncExitStack()
        await exit_stack.__aenter__()
        opened: ClientSession | None = None
        try:
            built = await build_session(self, exit_stack)
            opened = await exit_stack.enter_async_context(built)
            await negotiate(opened, forced=self.forced)
            set_session(self, opened)
            set_exit_stack(self, exit_stack.pop_all())
            return self
        except BaseException:
            async with shielded(cancel_scope(opened)):
                await exit_stack.__aexit__(None, None, None)
            raise
