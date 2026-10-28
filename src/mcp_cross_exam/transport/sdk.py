from __future__ import annotations

from collections.abc import Callable
from contextlib import AsyncExitStack
from typing import Protocol

import anyio
from mcp import Client
from mcp.client._transport import Transport as SdkTransport
from mcp.client._transport import TransportStreams
from mcp.client.session import ClientSession
from mcp.shared._httpx_utils import stream_within_origin
from mcp.shared.dispatcher import CallOptions
from mcp_types import Implementation

__all__ = [
    "SdkTransport",
    "TransportStreams",
    "build_session",
    "cancel_scope",
    "client_info",
    "dispatcher",
    "entered",
    "scope_chain",
    "session_scope",
    "set_entered",
    "set_exit_stack",
    "set_session",
    "set_stamp",
    "stamp",
    "stream_within_origin",
]

Stamp = Callable[[dict[str, object], CallOptions], None]


class RawDispatcher(Protocol):
    async def notify(
        self,
        method: str,
        params: dict[str, object] | None,
        opts: CallOptions,
    ) -> None: ...

    async def send_raw_request(
        self,
        method: str,
        params: dict[str, object],
        opts: CallOptions,
    ) -> object: ...


def scope_chain(start: anyio.CancelScope | None) -> list[anyio.CancelScope]:
    chain: list[anyio.CancelScope] = []
    current = start
    while current is not None:
        chain.append(current)
        parent = getattr(current, "_parent_scope", None)
        current = parent if isinstance(parent, anyio.CancelScope) else None
    return chain


def session_scope(session: object | None) -> anyio.CancelScope | None:
    inner = getattr(session, "_session", None)
    return cancel_scope(inner) if isinstance(inner, ClientSession) else None


def stamp(session: ClientSession) -> Stamp:
    return session._stamp


def set_stamp(session: ClientSession, replacement: Stamp) -> None:
    session._stamp = replacement


def dispatcher(session: ClientSession) -> RawDispatcher:
    return session._dispatcher


def client_info(session: ClientSession) -> Implementation:
    return session._client_info


def entered(client: Client) -> bool:
    return client._entered


def set_entered(client: Client, value: bool) -> None:
    client._entered = value


def set_session(client: Client, session: ClientSession | None) -> None:
    client._session = session


def set_exit_stack(client: Client, stack: AsyncExitStack) -> None:
    client._exit_stack = stack


def cancel_scope(session: ClientSession | None) -> anyio.CancelScope | None:
    if session is None or session._task_group is None:
        return None
    return session._task_group.cancel_scope


async def build_session(client: Client, stack: AsyncExitStack) -> ClientSession:
    return await client._build_session(stack)
