from __future__ import annotations

import socket
import sys
import threading

import anyio
import pytest

from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from tests.support.echo_server import server


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if not isinstance(port, int):
            raise RuntimeError("missing port")
        return port


def _audit(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == ExitCode.SUCCESS


def test_clean_sdk_stdio() -> None:
    _audit(["--", sys.executable, "-m", "tests.support.echo_server"])


def test_clean_strict_stdio() -> None:
    _audit(
        [
            "--protocol-version",
            "2025-11-25",
            "--",
            sys.executable,
            "-m",
            "tests.support.strict_server",
        ]
    )


async def _http(port: int) -> None:
    await server.run_streamable_http_async(host="127.0.0.1", port=port)


def test_clean_sdk_http() -> None:
    port = _port()

    def serve() -> None:
        anyio.run(_http, port)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            thread.join(0.05)
    _audit(["--protocol-version", "2025-11-25", f"http://127.0.0.1:{port}/mcp"])
