from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import TextIO

import anyio
from anyio.abc import ByteReceiveStream, Process
from anyio.streams.file import FileReadStream
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client._transport import TransportStreams
from mcp.client.session import ClientSession
from mcp.os.posix.utilities import terminate_posix_process_tree
from mcp.os.win32.utilities import (
    ServerProcess,
    close_process_job,
    create_windows_process,
    terminate_windows_process_tree,
)
from mcp.shared.message import SessionMessage
from mcp_types import jsonrpc_message_adapter
from pydantic import ValidationError

from mcp_cross_exam.transport.base import (
    ConnectFailed,
    Finding,
    FrameRecorder,
    JsonValue,
    RawChannel,
    RunContext,
    SessionClient,
    TransportClosed,
    make_context,
    make_frame,
    raise_translated,
    server_state,
    session_notify,
    session_request,
)

_ALLOWED_ENV = ("PATH", "HOME", "LANG", "TMPDIR", "TEMP", "SYSTEMROOT")


def child_environment(extra: Mapping[str, str]) -> dict[str, str]:
    child: dict[str, str] = {}
    for key in _ALLOWED_ENV:
        value = os.environ.get(key)
        if value is not None and not value.startswith("()"):
            child[key] = value
    child.update(extra)
    return child


class _Fan:
    def __init__(self) -> None:
        self._senders: list[MemoryObjectSendStream[bytes | None]] = []

    def subscribe(self) -> MemoryObjectReceiveStream[bytes | None]:
        send, receive = anyio.create_memory_object_stream[bytes | None](256)
        self._senders.append(send)
        return receive

    def publish(self, chunk: bytes | None) -> None:
        for sender in self._senders:
            try:
                sender.send_nowait(chunk)
            except (anyio.WouldBlock, anyio.BrokenResourceError, anyio.ClosedResourceError):
                continue


class StdioRaw:
    def __init__(self, transport: StdioTransport) -> None:
        self._transport = transport

    async def send_bytes(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        method: str = "POST",
    ) -> None:
        del headers, timeout, method
        await self._transport.write_out(body)

    async def drop(self) -> None:
        self._transport.stdout_scope.cancel()

    async def stream(self) -> AsyncIterator[bytes]:
        receive = self._transport.fan.subscribe()
        try:
            while True:
                item = await receive.receive()
                if item is None:
                    return
                yield item
        finally:
            await receive.aclose()


class StdioTransport:
    def __init__(
        self,
        command: tuple[str, ...],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        protocol_version: str | None,
        run_dir: os.PathLike[str] | str,
        grace_seconds: float = 2.0,
    ) -> None:
        self._command = command
        self._cwd = cwd
        self._env = dict(env)
        self._protocol = protocol_version
        self._grace = grace_seconds
        self.recorder = FrameRecorder()
        self._context = make_context(Path(run_dir), self.recorder)
        self.raw: RawChannel = StdioRaw(self)
        self.fan = _Fan()
        self.stdout_scope = anyio.CancelScope()
        self._stdin_lock = anyio.Lock()
        self._closed = False
        self._process: ServerProcess | None = None
        self._stderr_stream: ByteReceiveStream | None = None
        self._session: SessionClient | None = None
        self._group: anyio.abc.TaskGroup | None = None
        self._log: TextIO | None = None
        self._read_send: MemoryObjectSendStream[SessionMessage | Exception] | None = None
        self._read_recv: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None
        self._write_send: MemoryObjectSendStream[SessionMessage] | None = None
        self._write_recv: MemoryObjectReceiveStream[SessionMessage] | None = None

    async def connect(self) -> RunContext:
        if self._session is not None and not self._closed:
            return self._context
        self._closed = False
        try:
            await self._open()
        except BaseException as exc:
            await self.close()
            raise_translated(exc)
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
        del headers
        try:
            return await session_request(
                self._require(),
                method,
                params,
                meta=meta,
                headers=None,
                timeout=timeout,
            )
        except BaseException as exc:
            raise_translated(exc)

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
            raise_translated(exc)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with anyio.CancelScope(shield=True):
            with suppress(Exception):
                await self._close_stdin()
            with suppress(Exception):
                await self._wait_exit()
            with suppress(Exception):
                await self._reap()
        await self._shutdown()

    async def reset(self) -> RunContext:
        await self.close()
        self._closed = False
        self._session = None
        self._process = None
        return await self.connect()

    async def write_out(self, payload: bytes) -> None:
        process = self._process
        if self._closed or process is None or process.stdin is None:
            raise TransportClosed("connection closed")
        async with self._stdin_lock:
            await process.stdin.send(payload)
        self.recorder.add(make_frame(direction="outbound", body=payload))

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
        self._prepare_streams()
        await self._spawn()
        self._log = self._context.logs.path.open("a", encoding="utf-8")
        self.stdout_scope = anyio.CancelScope()
        self._group = anyio.create_task_group()
        await self._group.__aenter__()
        self._group.start_soon(self._stdout_loop)
        self._group.start_soon(self._stderr_loop)
        self._group.start_soon(self._stdin_loop)
        self._session = SessionClient(self._bridge(), forced=self._protocol)
        await self._session.__aenter__()
        self._context.server = server_state(self._session)

    def _prepare_streams(self) -> None:
        self._read_send, self._read_recv = anyio.create_memory_object_stream[
            SessionMessage | Exception
        ](32)
        self._write_send, self._write_recv = anyio.create_memory_object_stream[SessionMessage](32)

    async def _spawn(self) -> None:
        env = child_environment(self._env)
        try:
            if sys.platform == "win32":
                process, stderr_stream = await _spawn_windows(self._command, env, self._cwd)
                self._stderr_stream = stderr_stream
            else:
                process = await _spawn_posix(self._command, env, self._cwd)
                self._stderr_stream = process.stderr
            self._process = process
        except OSError as exc:
            raise ConnectFailed(f"could not start {self._command[0]}") from exc

    async def _stdout_loop(self) -> None:
        process = self._process
        if process is None or process.stdout is None or self._read_send is None:
            return
        buffer = bytearray()
        try:
            with self.stdout_scope:
                while True:
                    chunk = await process.stdout.receive()
                    self.fan.publish(chunk)
                    buffer.extend(chunk)
                    while b"\n" in buffer:
                        newline = buffer.index(b"\n")
                        line = bytes(buffer[:newline]).rstrip(b"\r")
                        del buffer[: newline + 1]
                        await self._handle_line(line)
        except anyio.EndOfStream:
            if buffer.strip():
                await self._handle_line(bytes(buffer).rstrip(b"\r"))
        finally:
            self.fan.publish(None)
            await self._read_send.aclose()

    async def _handle_line(self, line: bytes) -> None:
        if not line.strip() or self._read_send is None:
            return
        frame = make_frame(direction="inbound", body=line)
        self.recorder.add(frame)
        try:
            message = jsonrpc_message_adapter.validate_json(line, by_name=False)
        except (ValidationError, ValueError):
            self._context.findings.append(
                Finding(
                    item_id="transport.stdout-pollution",
                    severity="medium",
                    summary="stdout line is not JSON-RPC",
                    evidence=frame,
                )
            )
            return
        await self._read_send.send(SessionMessage(message))

    async def _stderr_loop(self) -> None:
        stream = self._stderr_stream
        if stream is None:
            return
        buffer = bytearray()
        try:
            while True:
                chunk = await stream.receive()
                buffer.extend(chunk)
                while b"\n" in buffer:
                    newline = buffer.index(b"\n")
                    self._remember_stderr(bytes(buffer[:newline]).rstrip(b"\r"))
                    del buffer[: newline + 1]
        except anyio.EndOfStream:
            if buffer.strip():
                self._remember_stderr(bytes(buffer).rstrip(b"\r"))

    def _remember_stderr(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace")
        self._context.logs.stderr.append(text)
        if self._log is not None:
            self._log.write(text + "\n")
            self._log.flush()

    async def _stdin_loop(self) -> None:
        if self._write_recv is None:
            return
        try:
            async for message in self._write_recv:
                payload = message.message.model_dump_json(
                    by_alias=True, exclude_unset=True
                ).encode()
                await self.write_out(payload + b"\n")
        except (
            anyio.EndOfStream,
            anyio.ClosedResourceError,
            anyio.BrokenResourceError,
            TransportClosed,
            OSError,
        ):
            return

    async def _shutdown(self) -> None:
        with suppress(Exception):
            await self._close_session()
        with suppress(Exception):
            await self._stop_group()
        if self._log is not None:
            self._log.close()
            self._log = None
        self._session = None
        self._process = None

    async def _close_stdin(self) -> None:
        process = self._process
        if process is None or process.stdin is None:
            return
        async with self._stdin_lock:
            await process.stdin.aclose()

    async def _wait_exit(self) -> None:
        process = self._process
        if process is None:
            return
        with anyio.move_on_after(self._grace):
            while process.returncode is None:
                await anyio.sleep(0.01)

    async def _reap(self) -> None:
        process = self._process
        if process is None or process.returncode is not None:
            if process is not None and sys.platform == "win32":
                close_process_job(process)
            return
        if sys.platform == "win32":
            await terminate_windows_process_tree(process)
            close_process_job(process)
            return
        if isinstance(process, Process):
            await terminate_posix_process_tree(process, timeout_seconds=self._grace)

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


async def _spawn_posix(
    command: tuple[str, ...],
    env: dict[str, str],
    cwd: str | None,
) -> Process:
    return await anyio.open_process(
        list(command),
        env=env,
        cwd=cwd,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


async def _spawn_windows(  # pragma: no cover
    command: tuple[str, ...],
    env: dict[str, str],
    cwd: str | None,
) -> tuple[ServerProcess, ByteReceiveStream]:
    read_fd, write_fd = os.pipe()
    write_text = os.fdopen(write_fd, "w", encoding="utf-8", errors="replace")
    try:
        process = await create_windows_process(
            command[0],
            list(command[1:]),
            env=env,
            errlog=write_text,
            cwd=cwd,
        )
    finally:
        write_text.close()
    return process, FileReadStream(os.fdopen(read_fd, "rb"))


def open_stdio(
    command: tuple[str, ...],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    protocol_version: str | None = None,
    run_dir: os.PathLike[str] | str,
    grace_seconds: float = 2.0,
) -> StdioTransport:
    return StdioTransport(
        command,
        cwd=cwd,
        env=env or {},
        protocol_version=protocol_version,
        run_dir=run_dir,
        grace_seconds=grace_seconds,
    )
