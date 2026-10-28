from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from mcp_cross_exam.cli import app, bind_stdio, release_stdio


@pytest.fixture(autouse=True)
def _runs_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MCP_CROSS_EXAM_RUNS", str(tmp_path / "runs"))


def invoke_cli(argv: list[str]) -> typer.testing.Result:
    left, token = bind_stdio(argv)
    try:
        return CliRunner().invoke(app, left)
    finally:
        release_stdio(token)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if not isinstance(port, int):
            raise RuntimeError("missing port")
        return port


@contextmanager
def start_fixture(era: str = "2025-11-25", defects: str = "none") -> Iterator[int]:
    port = free_port()
    command = (
        sys.executable,
        "-m",
        "mcp_cross_exam",
        "fixture",
        "serve",
        "--http",
        f"127.0.0.1:{port}",
        "--era",
        era,
        "--defects",
        defects,
    )
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_port(port)
        yield port
    finally:
        process.terminate()
        process.wait(timeout=5)


def _wait_port(port: int) -> None:
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fixture did not start")
