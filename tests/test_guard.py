from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Literal

import pytest
from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.guard import decide
from mcp_cross_exam.transport.base import json_value

from tests.conftest import start_fixture

_V4 = tuple[Literal[socket.AddressFamily.AF_INET], socket.SocketKind, int, str, tuple[str, int]]
_V6 = tuple[
    Literal[socket.AddressFamily.AF_INET6],
    socket.SocketKind,
    int,
    str,
    tuple[str, int, int, int] | tuple[int, bytes],
]
_AddrInfo = list[_V4 | _V6]


def _public(host: str) -> tuple[str, ...]:
    del host
    return ("93.184.216.34",)


def _refuse(host: str) -> tuple[str, ...] | None:
    raise AssertionError(host)


def test_loopback_literals_are_local() -> None:
    for host in ("127.0.0.1", "127.0.0.2", "::1"):
        decision = decide(stdio=False, host=host, resolve=_refuse)
        assert decision.allowed
        assert decision.guard == "local"


def test_mapped_loopback_is_local_and_mapped_public_is_refused() -> None:
    local = decide(stdio=False, host="mapped.example", resolve=lambda host: ("::ffff:127.0.0.1",))
    public = decide(stdio=False, host="mapped.example", resolve=lambda host: ("::ffff:8.8.8.8",))
    assert local.allowed and local.guard == "local"
    assert not public.allowed
    assert "not loopback" in public.reason


def test_mixed_answers_are_refused() -> None:
    decision = decide(
        stdio=False,
        host="mixed.example",
        resolve=lambda host: ("127.0.0.1", "8.8.8.8"),
    )
    assert not decision.allowed
    assert "not loopback" in decision.reason


def test_wildcard_allow_is_case_insensitive() -> None:
    decision = decide(
        stdio=False,
        host="A.B.Fixtures.Local",
        allow=("*.fixtures.local",),
        resolve=_public,
    )
    assert decision.allowed
    assert decision.guard == "allow"
    bare = decide(stdio=False, host="fixtures.local", allow=("*.fixtures.local",), resolve=_public)
    assert not bare.allowed


def test_localhost_in_the_name_is_not_enough() -> None:
    refused = decide(stdio=False, host="localhost.example.com", resolve=_public)
    allowed = decide(
        stdio=False,
        host="localhost.example.com",
        resolve=lambda host: ("127.0.0.1",),
    )
    assert not refused.allowed
    assert "not loopback" in refused.reason
    assert allowed.allowed
    assert allowed.guard == "local"


def test_unresolved_allow_entry_does_not_connect() -> None:
    decision = decide(
        stdio=False,
        host="fixture.local",
        allow=("fixture.local",),
        resolve=lambda host: None,
    )
    assert not decision.allowed
    assert decision.reason == "refused: host did not resolve"


def test_override_needs_an_allow_match() -> None:
    refused = decide(stdio=False, host="api.example.com", override=True, resolve=_public)
    allowed = decide(
        stdio=False,
        host="api.example.com",
        allow=("API.Example.Com",),
        override=True,
        resolve=_public,
    )
    assert not refused.allowed
    assert "--target-is-not-production" in refused.reason
    assert allowed.allowed
    assert allowed.guard == "overridden"


def test_stdio_is_local() -> None:
    decision = decide(stdio=True, host=None, resolve=_refuse)
    assert decision.allowed
    assert decision.guard == "local"


def test_public_name_is_refused_without_a_socket(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def resolve(
        host: bytes | str | None,
        port: bytes | str | int | None = None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> _AddrInfo:
        del port, family, type, proto, flags
        if host == "api.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise AssertionError(host)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(SystemExit) as caught:
        main(["https://api.example.com/mcp"])
    assert caught.value.code == ExitCode.CONFIG
    assert "not loopback" in capsys.readouterr().err


def test_public_literal_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def resolve(
        host: bytes | str | None,
        port: bytes | str | int | None = None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> _AddrInfo:
        del host, port, family, type, proto, flags
        raise AssertionError("dns")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(SystemExit) as caught:
        main(["https://1.1.1.1/mcp"])
    assert caught.value.code == ExitCode.CONFIG
    assert "not loopback" in capsys.readouterr().err


@pytest.mark.allow_hosts(["127.0.0.1", "::1", "fixture.local"])
def test_override_warning_and_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = socket.getaddrinfo

    def resolve(
        host: bytes | str | None,
        port: bytes | str | int | None = None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> _AddrInfo:
        name = host.decode() if isinstance(host, bytes) else host
        target = "127.0.0.1" if name == "fixture.local" else host
        return original(target, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    config = tmp_path / "audit.toml"
    config.write_text('[target]\nallow = ["fixture.local"]\n', encoding="utf-8")
    with start_fixture() as port:
        with pytest.raises(SystemExit) as caught:
            main(
                [
                    "--config",
                    str(config),
                    "--target-is-not-production",
                    "probes",
                    "plan",
                    f"http://fixture.local:{port}/mcp",
                ]
            )
        assert caught.value.code == ExitCode.SUCCESS
        assert 'target.guard = "overridden"' in capsys.readouterr().err
        runs = list((tmp_path / "runs").iterdir())
        assert len(runs) == 1
        saved = json_value(json.loads((runs[0] / "report.json").read_text(encoding="utf-8")))
        assert isinstance(saved, dict)
        target = saved.get("target")
        assert isinstance(target, dict)
        assert target.get("guard") == "overridden"
