from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import suppress

import anyio
import httpx2
from anyio.streams.memory import MemoryObjectReceiveStream

Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def _byte_pair(item: object) -> tuple[bytes, bytes] | None:
    if not isinstance(item, tuple) or len(item) != 2:
        return None
    key, value = item
    if isinstance(key, bytes) and isinstance(value, bytes):
        return key, value
    return None


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
        body = request.content
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
