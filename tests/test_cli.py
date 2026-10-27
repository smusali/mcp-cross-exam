from __future__ import annotations

import json
import socket
import sys
from importlib.metadata import version
from pathlib import Path

import jsonschema
import pytest
import typer
from mcp_cross_exam import __version__
from mcp_cross_exam.cli import app, bind_stdio, main, release_stdio
from mcp_cross_exam.exit_codes import ExitCode, exit_with, set_exit_zero
from pytest_socket import SocketConnectBlockedError
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()


def _invoke(argv: list[str]) -> typer.testing.Result:
    left, token = bind_stdio(argv)
    try:
        return RUNNER.invoke(app, left)
    finally:
        release_stdio(token)


def test_streamable_http_and_run_alias() -> None:
    bare = _invoke(["http://127.0.0.1:9/mcp"])
    via_run = _invoke(["run", "http://127.0.0.1:9/mcp"])
    plain = _invoke(["http://127.0.0.1:9/health"])
    assert bare.exit_code == ExitCode.UNREACHABLE
    assert via_run.exit_code == ExitCode.UNREACHABLE
    assert plain.exit_code == ExitCode.UNREACHABLE
    assert bare.stdout == ""


def test_sse_and_stdio_forms() -> None:
    sse = _invoke(["--sse", "http://127.0.0.1:9/sse"])
    via_run = _invoke(["run", "--sse", "http://127.0.0.1:9/sse"])
    stdio = _invoke(["--", sys.executable, "-c", "raise SystemExit(0)"])
    via_run_stdio = _invoke(["run", "--", sys.executable, "-c", "raise SystemExit(0)"])
    assert sse.exit_code == ExitCode.UNREACHABLE
    assert via_run.exit_code == ExitCode.UNREACHABLE
    assert stdio.exit_code == ExitCode.UNREACHABLE
    assert via_run_stdio.exit_code == ExitCode.UNREACHABLE


def test_usage_errors_exit_config() -> None:
    cases = [
        ["ftp://example.com/mcp"],
        ["not-a-url"],
        ["http://"],
        ["--"],
        ["https://example.com/mcp", "--sse", "https://example.com/sse"],
        ["https://example.com/mcp", "--", "python", "server.py"],
        ["--sse", "https://example.com/sse", "--", "python"],
        ["--sse", "https://one.example/sse", "run", "--sse", "https://two.example/sse"],
        ["https://one.example/mcp", "https://two.example/mcp"],
        ["run"],
        ["--bogus"],
    ]
    for argv in cases:
        result = _invoke(argv)
        assert result.exit_code == ExitCode.CONFIG, argv


def test_version_text_and_json() -> None:
    text = _invoke(["--version"])
    assert text.exit_code == 0
    lines = text.stdout.splitlines()
    assert lines[0] == f"mcp-cross-exam {__version__}"
    assert lines[1].startswith("mcp ")
    assert lines[2].startswith("Python ")
    assert lines[3].index("2026-07-28") < lines[3].index("2024-11-05")

    schema_path = ROOT / "mcp_cross_exam" / "version.v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    for argv in (["--version", "--json"], ["--json", "--version"]):
        result = _invoke(argv)
        assert result.exit_code == 0, argv
        payload = json.loads(result.stdout)
        jsonschema.validate(payload, schema)
        assert payload["version"] == __version__


def test_installed_version_matches_package() -> None:
    assert version("mcp-cross-exam") == __version__


def test_flags_are_accepted() -> None:
    quiet = _invoke(["--quiet", "--json", "--no-color", "http://127.0.0.1:9/mcp"])
    held = _invoke(["--exit-zero", "http://127.0.0.1:9/mcp"])
    assert quiet.exit_code == ExitCode.UNREACHABLE
    assert quiet.stdout == ""
    assert held.exit_code == ExitCode.UNREACHABLE


def test_help_lists_only_the_run_command() -> None:
    result = _invoke(["--help"])
    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "not implemented" not in result.stdout.lower()


def test_empty_invocation_shows_help() -> None:
    result = _invoke([])
    assert result.exit_code == 0
    assert "run" in result.stdout


def test_exit_zero_rewrites_only_findings() -> None:
    set_exit_zero(True)
    try:
        with pytest.raises(SystemExit) as findings:
            exit_with(ExitCode.FINDINGS)
        assert findings.value.code == ExitCode.SUCCESS
        with pytest.raises(SystemExit) as unreachable:
            exit_with(ExitCode.UNREACHABLE)
        assert unreachable.value.code == ExitCode.UNREACHABLE
    finally:
        set_exit_zero(False)
    with pytest.raises(SystemExit) as plain:
        exit_with(ExitCode.FINDINGS)
    assert plain.value.code == ExitCode.FINDINGS


def test_main_maps_interrupts_usage_and_bugs(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(_argv: list[str]) -> None:
        raise KeyboardInterrupt

    def broken(_argv: list[str]) -> None:
        raise RuntimeError("boom")

    def usage(_argv: list[str]) -> None:
        raise typer.BadParameter("nope")

    def finished(_argv: list[str]) -> None:
        raise typer.Exit(code=0)

    def rejected(_argv: list[str]) -> None:
        raise typer.Exit(code=2)

    monkeypatch.setattr("mcp_cross_exam.cli.dispatch", interrupt)
    with pytest.raises(SystemExit) as interrupted:
        main([])
    assert interrupted.value.code == ExitCode.INTERRUPTED

    monkeypatch.setattr("mcp_cross_exam.cli.dispatch", broken)
    with pytest.raises(SystemExit) as internal:
        main([])
    assert internal.value.code == ExitCode.INTERNAL

    monkeypatch.setattr("mcp_cross_exam.cli.dispatch", usage)
    with pytest.raises(SystemExit) as config:
        main([])
    assert config.value.code == ExitCode.CONFIG

    monkeypatch.setattr("mcp_cross_exam.cli.dispatch", finished)
    with pytest.raises(SystemExit) as success:
        main([])
    assert success.value.code == ExitCode.SUCCESS

    monkeypatch.setattr("mcp_cross_exam.cli.dispatch", rejected)
    with pytest.raises(SystemExit) as rejected_exit:
        main([])
    assert rejected_exit.value.code == ExitCode.CONFIG


def test_main_runs_a_valid_endpoint() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["http://127.0.0.1:9/mcp"])
    assert caught.value.code == ExitCode.UNREACHABLE


def test_non_loopback_socket_is_blocked() -> None:
    with pytest.raises(SocketConnectBlockedError):
        socket.socket().connect(("1.1.1.1", 443))
