from __future__ import annotations

import socket
import sys
from pathlib import Path

import anyio

from mcp_cross_exam.fixture import FixtureApp, parse_defects
from mcp_cross_exam.probes.base import ProbeContext
from mcp_cross_exam.runner import examine
from mcp_cross_exam.transport import Finding
from mcp_cross_exam.transport.http import open_http
from mcp_cross_exam.transport.stdio import open_stdio
from tests.support.asgi import StreamingASGITransport


def finding_ids(findings: list[Finding]) -> set[str]:
    return {item.item_id for item in findings}


def audit_http(
    tmp: Path,
    era: str,
    defects: str,
    *,
    legacy: bool = False,
    bearer: str | None = None,
    expired: str | None = None,
) -> list[Finding]:
    app = FixtureApp(era, parse_defects(defects, clean=False))
    url = "http://127.0.0.1:9/sse" if legacy else "http://127.0.0.1:9/mcp"

    async def _go() -> list[Finding]:
        transport = open_http(
            url,
            legacy=legacy,
            bearer=bearer,
            network=StreamingASGITransport(app),
            run_dir=tmp,
        )
        context = await transport.connect()
        try:
            return await examine(
                ProbeContext(
                    transport=transport,
                    run=context,
                    http=True,
                    endpoint=url,
                    expired_bearer=expired,
                    legacy=legacy,
                )
            )
        finally:
            await transport.close()

    return anyio.run(_go)


def audit_stdio(tmp: Path, era: str, defects: str) -> list[Finding]:
    command = (
        sys.executable,
        "-m",
        "mcp_cross_exam",
        "fixture",
        "serve",
        "--stdio",
        "--era",
        era,
        "--defects",
        defects,
    )

    async def _go() -> list[Finding]:
        transport = open_stdio(command, run_dir=tmp, grace_seconds=1.0)
        context = await transport.connect()
        try:
            return await examine(
                ProbeContext(
                    transport=transport,
                    run=context,
                    http=False,
                    endpoint=None,
                    expired_bearer=None,
                    legacy=False,
                )
            )
        finally:
            await transport.close()

    return anyio.run(_go)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if not isinstance(port, int):
            raise RuntimeError("missing port")
        return port
