from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_cross_exam.transport import RunContext, Transport
from mcp_cross_exam.transport.http import open_http
from mcp_cross_exam.transport.stdio import open_stdio

if TYPE_CHECKING:
    from mcp_cross_exam.cli.app import Flags


@asynccontextmanager
async def open_session(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
    run_dir: Path,
) -> AsyncIterator[tuple[Transport, RunContext]]:
    transport = _open_transport(flags, endpoint, command, run_dir)
    try:
        context = await transport.connect()
        yield transport, context
    finally:
        await transport.close()


def _open_transport(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
    run_dir: Path,
) -> Transport:
    from mcp_cross_exam.cli.app import UsageFailure, _child_env, _env_value, _header_values

    if command is not None:
        return open_stdio(
            command,
            cwd=flags.cwd,
            env=_child_env(flags),
            protocol_version=flags.protocol_version,
            run_dir=run_dir,
        )
    url = flags.sse if flags.sse is not None else endpoint
    if url is None:
        raise UsageFailure("missing endpoint")
    verify: bool | str = flags.ca_bundle if flags.ca_bundle is not None else True
    bearer = _env_value(flags.bearer_env) if flags.bearer_env is not None else None
    return open_http(
        url,
        legacy=flags.sse is not None,
        bearer=bearer,
        headers=_header_values(flags),
        verify=verify,
        protocol_version=flags.protocol_version,
        run_dir=run_dir,
    )
