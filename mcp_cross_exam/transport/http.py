from __future__ import annotations

import os
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from pathlib import Path
from typing import NoReturn
from urllib.parse import urljoin, urlsplit

import anyio
import httpx2
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client._transport import TransportStreams
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import stream_within_origin
from mcp.shared.message import ClientMessageMetadata, SessionMessage
from mcp_types import jsonrpc_message_adapter
from pydantic import ValidationError

from mcp_cross_exam.transport.base import (
    DEFAULT_REQUEST_TIMEOUT,
    ConnectFailed,
    Finding,
    Frame,
    FrameRecorder,
    JsonValue,
    RawChannel,
    RunContext,
    SessionClient,
    Timeout,
    TransportClosed,
    TransportFailure,
    call_headers,
    collapse,
    failure_from,
    make_context,
    make_frame,
    modern_error,
    passthrough,
    server_state,
    session_notify,
    session_request,
    session_scope,
    shielded,
)

_REDIRECTS = {301, 302, 303, 307, 308}
_FALLBACK = {400, 404, 405}
_ACCEPT = "application/json, text/event-stream"


def path_is_sse(url: str) -> bool:
    return urlsplit(url).path.rstrip("/").endswith("/sse")


def header_map(headers: httpx2.Headers) -> dict[str, str]:
    return {str(key): str(value) for key, value in headers.items()}


def content_type(headers: Mapping[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value
    return ""


def take_events(buffer: bytes) -> tuple[list[tuple[str, bytes]], bytes]:
    events: list[tuple[str, bytes]] = []
    while True:
        found = _boundary(buffer)
        if found is None:
            return events, buffer
        index, length = found
        events.append(_event(buffer[:index]))
        buffer = buffer[index + length :]


def _boundary(buffer: bytes) -> tuple[int, int] | None:
    found: list[tuple[int, int]] = []
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = buffer.find(separator)
        if index != -1:
            found.append((index, len(separator)))
    if not found:
        return None
    return min(found)


def _event(block: bytes) -> tuple[str, bytes]:
    name = "message"
    data: list[bytes] = []
    for raw in block.splitlines():
        if not raw or raw.startswith(b":"):
            continue
        if b":" in raw:
            field, value = raw.split(b":", 1)
            if value.startswith(b" "):
                value = value[1:]
        else:
            field, value = raw, b""
        if field == b"event":
            name = value.decode("utf-8", errors="replace")
        elif field == b"data":
            data.append(value)
    return name, b"\n".join(data)


def _last_inbound(recorder: FrameRecorder) -> Frame | None:
    for frame in reversed(recorder.frames):
        if frame.direction == "inbound":
            return frame
    return None


def _http_failure(exc: BaseException) -> BaseException:
    current = collapse(exc)
    if isinstance(current, TransportFailure) or passthrough(current):
        return current
    if isinstance(current, httpx2.TimeoutException):
        return Timeout("timed out")
    if isinstance(current, httpx2.TransportError):
        return ConnectFailed("could not connect")
    if isinstance(current, Exception):
        return failure_from(current)
    return current


def _raise_http(exc: BaseException) -> NoReturn:
    mapped = _http_failure(exc)
    if mapped is not exc:
        raise mapped from exc
    raise exc


class RecordingStream(httpx2.AsyncByteStream):
    def __init__(
        self,
        inner: httpx2.AsyncByteStream,
        *,
        recorder: FrameRecorder,
        status: int,
        headers: Mapping[str, str],
    ) -> None:
        self._inner = inner
        self._recorder = recorder
        self._status = status
        self._headers = dict(headers)
        self._sse = "text/event-stream" in content_type(self._headers).lower()
        self._buffer = bytearray()
        self._pending = b""
        self._events = 0
        self._finished = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._inner:
                self._buffer.extend(chunk)
                if self._sse:
                    self._pending += chunk
                    events, self._pending = take_events(self._pending)
                    for _name, data in events:
                        self._events += 1
                        self._record(data)
                yield chunk
        finally:
            self._finish()

    async def aclose(self) -> None:
        self._finish()
        await self._inner.aclose()

    def _finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        if self._sse:
            if self._pending:
                self._record(self._pending)
            elif self._events == 0:
                self._record(bytes(self._buffer))
            return
        self._record(bytes(self._buffer))

    def _record(self, body: bytes) -> None:
        self._recorder.add(
            make_frame(
                direction="inbound",
                body=body,
                status=self._status,
                headers=self._headers,
            )
        )


class RecordingTransport(httpx2.AsyncBaseTransport):
    def __init__(self, inner: httpx2.AsyncBaseTransport, recorder: FrameRecorder) -> None:
        self._inner = inner
        self._recorder = recorder
        self.current: RecordingStream | None = None

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        extra = call_headers.get()
        if extra:
            request.headers.update(extra)
        body = request.content if isinstance(request.content, bytes) else b""
        self._recorder.add(
            make_frame(direction="outbound", body=body, headers=header_map(request.headers))
        )
        response = await self._inner.handle_async_request(request)
        stream = response.stream
        if not isinstance(stream, httpx2.AsyncByteStream):
            raise TransportClosed("connection closed")
        wrapped = RecordingStream(
            stream,
            recorder=self._recorder,
            status=response.status_code,
            headers=header_map(response.headers),
        )
        response.stream = wrapped
        self.current = wrapped
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class HttpRaw:
    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    async def send_bytes(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        method: str = "POST",
    ) -> None:
        await self._transport.send_raw(body, headers=headers, timeout=timeout, method=method)

    async def drop(self) -> None:
        await self._transport.drop_raw()

    async def stream(self) -> AsyncIterator[bytes]:
        response = self._transport.raw_response
        if response is None:
            raise TransportClosed("connection closed")
        async for chunk in response.aiter_raw():
            yield chunk


class HttpTransport:
    def __init__(
        self,
        url: str,
        *,
        legacy: bool,
        bearer: str | None,
        headers: Mapping[str, str],
        verify: bool | str,
        protocol_version: str | None,
        run_dir: os.PathLike[str] | str,
        network: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = url
        self._legacy = legacy
        self._bearer = bearer
        self._extra = dict(headers)
        self._verify = verify
        self._protocol = protocol_version
        self._network = network
        self.recorder = FrameRecorder()
        self._context = make_context(Path(run_dir), self.recorder)
        self.raw: RawChannel = HttpRaw(self)
        self._closed = False
        self._http: httpx2.AsyncClient | None = None
        self._recording: RecordingTransport | None = None
        self._session: SessionClient | None = None
        self._group: anyio.abc.TaskGroup | None = None
        self._ready: anyio.Event | None = None
        self._endpoint: str | None = None
        self._reader_error: Exception | None = None
        self._read_send: MemoryObjectSendStream[SessionMessage | Exception] | None = None
        self._read_recv: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None
        self._write_send: MemoryObjectSendStream[SessionMessage] | None = None
        self._write_recv: MemoryObjectReceiveStream[SessionMessage] | None = None
        self._raw_cm: AbstractAsyncContextManager[httpx2.Response] | None = None
        self.raw_response: httpx2.Response | None = None
        self._endpoint_frame: Frame | None = None
        self._default_timeout = httpx2.Timeout(DEFAULT_REQUEST_TIMEOUT, read=300.0)

    async def connect(self) -> RunContext:
        if self._session is not None and not self._closed:
            return self._context
        self._closed = False
        try:
            await self._open()
        except BaseException as exc:
            await self.close()
            _raise_http(exc)
        return self._context

    async def request(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> JsonValue:
        try:
            async with self._timeout(timeout):
                return await session_request(
                    self._require(),
                    method,
                    params,
                    meta=meta,
                    headers=headers,
                    timeout=timeout,
                )
        except BaseException as exc:
            _raise_http(exc)

    async def notify(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
    ) -> None:
        try:
            await session_notify(self._require(), method, params, meta=meta)
        except BaseException as exc:
            _raise_http(exc)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        start = session_scope(self._session)
        if start is None and self._group is not None:
            start = self._group.cancel_scope
        async with shielded(start):
            await self._shutdown()

    async def reset(self) -> RunContext:
        await self.close()
        self._closed = False
        self._session = None
        return await self.connect()

    async def send_raw(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None,
        timeout: float | None,
        method: str = "POST",
    ) -> None:
        client = self._http
        if self._closed or client is None:
            raise TransportClosed("connection closed")
        await self._finish_raw()
        merged = {"Content-Type": "application/json", "Accept": _ACCEPT}
        if headers:
            merged.update(headers)
        token = call_headers.set(merged)
        try:
            async with self._timeout(timeout):
                if method == "GET":
                    manager = stream_within_origin(client, method, self._url, headers=merged)
                else:
                    manager = stream_within_origin(
                        client, method, self._url, content=body, headers=merged
                    )
                self._raw_cm = manager
                self.raw_response = await manager.__aenter__()
        finally:
            call_headers.reset(token)

    async def drop_raw(self) -> None:
        recording = self._recording
        if recording is not None and recording.current is not None:
            await recording.current.aclose()
        await self._finish_raw()

    @asynccontextmanager
    async def _timeout(self, timeout: float | None) -> AsyncIterator[None]:
        client = self._http
        if client is None or timeout is None:
            yield
            return
        previous = client.timeout
        client.timeout = httpx2.Timeout(timeout)
        try:
            yield
        finally:
            client.timeout = previous

    @asynccontextmanager
    async def _bridge(self) -> AsyncIterator[TransportStreams]:
        if self._read_recv is None or self._write_send is None:
            raise TransportClosed("connection closed")
        yield self._read_recv, self._write_send

    def _require(self) -> ClientSession:
        if self._closed or self._session is None:
            raise TransportClosed("connection closed")
        return self._session.session

    async def _open(self) -> None:
        await self._open_client()
        if self._legacy:
            await self._connect_sse()
            return
        try:
            await self._connect_streamable()
        except Exception as exc:
            if not self._can_fallback():
                raise
            await self._discard_session()
            try:
                await self._connect_sse()
            except TransportFailure:
                raise
            except Exception:
                raise exc from None

    async def _open_client(self) -> None:
        inner = self._network or httpx2.AsyncHTTPTransport(verify=self._verify, trust_env=False)
        self._recording = RecordingTransport(inner, self.recorder)
        headers = {"Accept": _ACCEPT}
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        headers.update(self._extra)
        self._http = httpx2.AsyncClient(
            transport=self._recording,
            headers=headers,
            timeout=self._default_timeout,
            follow_redirects=False,
            trust_env=False,
        )
        await self._http.__aenter__()

    async def _connect_streamable(self) -> None:
        client = self._http
        if client is None:
            raise TransportClosed("connection closed")
        self._session = SessionClient(
            streamable_http_client(self._url, http_client=client, terminate_on_close=True),
            forced=self._protocol,
        )
        await self._session.__aenter__()
        self._context.server = server_state(self._session)

    async def _connect_sse(self) -> None:
        self._prepare_streams()
        self._endpoint = None
        self._reader_error = None
        self._ready = anyio.Event()
        self._group = anyio.create_task_group()
        await self._group.__aenter__()
        self._group.start_soon(self._read_sse)
        with anyio.fail_after(DEFAULT_REQUEST_TIMEOUT):
            await self._ready.wait()
        if self._endpoint is None:
            _raise_http(self._reader_error or TransportClosed("connection closed"))
        self._group.start_soon(self._write_sse)
        self._session = SessionClient(self._bridge(), forced=self._protocol)
        await self._session.__aenter__()
        self._context.server = server_state(self._session)

    def _prepare_streams(self) -> None:
        self._read_send, self._read_recv = anyio.create_memory_object_stream[
            SessionMessage | Exception
        ](32)
        self._write_send, self._write_recv = anyio.create_memory_object_stream[SessionMessage](32)

    def _can_fallback(self) -> bool:
        if self._legacy or not path_is_sse(self._url):
            return False
        inbound = [frame for frame in self.recorder.frames if frame.direction == "inbound"]
        terminal = [frame for frame in inbound if frame.status not in _REDIRECTS]
        if not terminal or any(frame.status not in _FALLBACK for frame in terminal):
            return False
        return not any(modern_error(frame.parsed) for frame in inbound)

    async def _read_sse(self) -> None:
        client = self._http
        ready = self._ready
        if client is None or ready is None:
            return
        headers = {"Accept": "text/event-stream", "Cache-Control": "no-store"}
        try:
            async with stream_within_origin(client, "GET", self._url, headers=headers) as response:
                if response.status_code >= 400:
                    await response.aread()
                    self._reader_error = TransportClosed("connection closed")
                    ready.set()
                    return
                pending = b""
                async for chunk in response.aiter_raw():
                    pending += chunk
                    events, pending = take_events(pending)
                    for name, data in events:
                        await self._on_sse(name, data, str(response.url))
                if self._endpoint is None:
                    self._reader_error = TransportClosed("connection closed")
                    ready.set()
        except Exception as exc:
            self._reader_error = exc
            ready.set()
        finally:
            if self._read_send is not None:
                await self._read_send.aclose()

    async def _on_sse(self, name: str, data: bytes, base: str) -> None:
        if name == "endpoint" and self._endpoint is None:
            self._endpoint = urljoin(base, data.decode("utf-8", errors="replace").strip())
            self._endpoint_frame = _last_inbound(self.recorder)
            self._note_sse()
            if self._ready is not None:
                self._ready.set()
            return
        if name == "message" and data.strip():
            await self._forward(data)

    async def _forward(self, data: bytes) -> None:
        if self._read_send is None:
            return
        try:
            message = jsonrpc_message_adapter.validate_json(data, by_name=False)
        except (ValidationError, ValueError):
            return
        await self._read_send.send(SessionMessage(message))

    async def _write_sse(self) -> None:
        if self._write_recv is None or self._endpoint is None:
            return
        try:
            async for message in self._write_recv:
                await self._post_message(message)
        except (
            anyio.EndOfStream,
            anyio.ClosedResourceError,
            anyio.BrokenResourceError,
            TransportClosed,
        ):
            return

    async def _post_message(self, message: SessionMessage) -> None:
        client = self._http
        endpoint = self._endpoint
        if client is None or endpoint is None:
            raise TransportClosed("connection closed")
        headers = {"Content-Type": "application/json", "Accept": _ACCEPT}
        meta = message.metadata
        if isinstance(meta, ClientMessageMetadata) and meta.headers:
            headers.update(meta.headers)
        body = message.message.model_dump_json(by_alias=True, exclude_unset=True).encode()
        async with stream_within_origin(
            client, "POST", endpoint, content=body, headers=headers
        ) as response:
            if response.status_code >= 400:
                await response.aread()
                return
            if response.status_code == 202:
                await response.aread()
                return
            payload = await response.aread()
            if content_type(header_map(response.headers)).lower().startswith("application/json"):
                await self._forward(payload)

    def _note_sse(self) -> None:
        if any(item.item_id == "transport.deprecated-sse" for item in self._context.findings):
            return
        self._context.findings.append(
            Finding(
                item_id="transport.deprecated-sse",
                severity="info",
                summary="HTTP+SSE is deprecated. Migrate the server to streamable HTTP.",
                evidence=self._endpoint_frame,
            )
        )

    async def _discard_session(self) -> None:
        session = self._session
        self._session = None
        if session is None or session._exit_stack is None:
            return
        with suppress(Exception):
            await session.__aexit__(None, None, None)

    async def _finish_raw(self) -> None:
        manager = self._raw_cm
        self.raw_response = None
        self._raw_cm = None
        if manager is None:
            return
        with suppress(Exception):
            await manager.__aexit__(None, None, None)

    async def _shutdown(self) -> None:
        with suppress(Exception):
            await self._finish_raw()
        with suppress(Exception):
            await self._close_session()
        with suppress(Exception):
            await self._stop_group()
        with suppress(Exception):
            if self._http is not None:
                await self._http.aclose()
        self._http = None
        self._session = None

    async def _stop_group(self) -> None:
        group = self._group
        self._group = None
        if group is None:
            return
        group.cancel_scope.cancel()
        group.cancel_scope.shield = True
        await group.__aexit__(None, None, None)

    async def _close_session(self) -> None:
        session = self._session
        if session is None or session._exit_stack is None:
            return
        await session.__aexit__(None, None, None)


def open_http(
    url: str,
    *,
    legacy: bool = False,
    bearer: str | None = None,
    headers: Mapping[str, str] | None = None,
    verify: bool | str = True,
    protocol_version: str | None = None,
    run_dir: os.PathLike[str] | str,
    network: httpx2.AsyncBaseTransport | None = None,
) -> HttpTransport:
    return HttpTransport(
        url,
        legacy=legacy,
        bearer=bearer,
        headers=headers or {},
        verify=verify,
        protocol_version=protocol_version,
        run_dir=run_dir,
        network=network,
    )
