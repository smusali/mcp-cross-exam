from __future__ import annotations

import time
from pathlib import Path

import pytest

from mcp_cross_exam.cli import main
from mcp_cross_exam.config import ConfigError, load_settings
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.fixture import FixtureApp
from mcp_cross_exam.probes.base import Observation, Probe, ProbeContext, RunBudget, ToolView
from mcp_cross_exam.runner import BUDGET_SKIP, examine
from mcp_cross_exam.transport import Finding
from mcp_cross_exam.transport.http import open_http
from tests.conftest import start_fixture
from tests.probes.conftest import audit_http
from tests.support.asgi import StreamingASGITransport


def test_each_config_section(tmp_path: Path) -> None:
    path = tmp_path / "audit.toml"
    path.write_text(
        "\n".join(
            [
                "[target]",
                'transport = "http"',
                'url = "http://127.0.0.1:9/mcp"',
                'protocol_version = "2025-11-25"',
                'allow = ["*.fixtures.local"]',
                "",
                "[auth]",
                'bearer_env = "MCP_TOKEN"',
                'expired_bearer_env = "MCP_EXPIRED"',
                "",
                "[auth.header_env]",
                'X-Request = "MCP_REQUEST"',
                "",
                "[probes]",
                'select = ["session.*"]',
                'skip = ["session.expired-not-404"]',
                "",
                "[probes.severity]",
                '"session.expired-empty-success" = "info"',
                "",
                "[budget]",
                "wall_clock_s = 15",
                "max_calls_per_tool = 3",
                "call_timeout_s = 4",
                "",
                "[tools.get_ticket]",
                'effect = "read"',
                'observer = "reader"',
                'scope = "user"',
                "",
                "[tools.get_ticket.args]",
                'ticket = "1"',
            ]
        ),
        encoding="utf-8",
    )
    settings = load_settings(path)
    assert settings.target.url == "http://127.0.0.1:9/mcp"
    assert settings.target.allow == ["*.fixtures.local"]
    assert settings.auth.bearer_env == "MCP_TOKEN"
    assert settings.auth.header_env["X-Request"] == "MCP_REQUEST"
    assert settings.probes.select == ["session.*"]
    assert settings.probes.severity["session.expired-empty-success"] == "info"
    assert settings.budget.max_calls_per_tool == 3
    hint = settings.tools["get_ticket"]
    assert hint.effect == "read"
    assert hint.args == {"ticket": "1"}
    assert hint.scope == "user"


def test_unknown_key_names_the_path(tmp_path: Path) -> None:
    path = tmp_path / "audit.toml"
    path.write_text("[budget]\nwal_clock_s = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"budget\.wal_clock_s"):
        load_settings(path)


def test_config_show_prints_names_not_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MCP_TOKEN", "super-secret-value")
    path = tmp_path / "mcp-cross-exam.toml"
    path.write_text('[auth]\nbearer_env = "MCP_TOKEN"\n', encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        main(["config", "show"])
    assert caught.value.code == ExitCode.SUCCESS
    text = capsys.readouterr().out
    assert "MCP_TOKEN" in text
    assert "super-secret-value" not in text


def test_cli_probe_overrides_config_select(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "mcp-cross-exam.toml"
    path.write_text('[probes]\nselect = ["missing.probe"]\n', encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        main(["--probe", "transport.unknown-method", "http://127.0.0.1:9/mcp"])
    assert caught.value.code == ExitCode.UNREACHABLE


def test_config_init_loads_without_freezing_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    with start_fixture() as port:
        with pytest.raises(SystemExit) as caught:
            main(["config", "init", f"http://127.0.0.1:{port}/mcp"])
        assert caught.value.code == ExitCode.SUCCESS
    settings = load_settings(tmp_path / "mcp-cross-exam.toml")
    assert set(settings.tools) == {"get_ticket", "list_tickets", "slow_report", "create_ticket"}
    assert all(hint.effect is None for hint in settings.tools.values())
    with pytest.raises(SystemExit) as again:
        main(["config", "init", "http://127.0.0.1:9/mcp"])
    assert again.value.code == ExitCode.CONFIG


def test_slow_report_exhausts_the_budget(tmp_path: Path) -> None:
    assert "budget.later" in _budget(tmp_path)


def _budget(tmp_path: Path) -> list[str]:
    import anyio

    return anyio.run(_budget_async, tmp_path)


async def _budget_async(tmp_path: Path) -> list[str]:
    app = FixtureApp("2025-11-25", frozenset())
    transport = open_http(
        "http://127.0.0.1:9/mcp",
        network=StreamingASGITransport(app),
        run_dir=tmp_path,
    )
    context = await transport.connect()
    later = _Later()
    try:
        ctx = ProbeContext(
            transport=transport,
            run=context,
            http=True,
            endpoint="http://127.0.0.1:9/mcp",
            expired_bearer=None,
            legacy=False,
            budget=RunBudget(wall_clock_s=0.4, max_calls_per_tool=50, call_timeout_s=5),
        )
        await examine(ctx, probes=(_Slow(), later))
    finally:
        await transport.close()
    assert later.ran is False
    assert any(
        item.reason == BUDGET_SKIP and item.probe_id == "budget.later" for item in context.skips
    )
    return [item.probe_id for item in context.skips]


class _Slow(Probe):
    id = "budget.slow"
    default_severity = "info"
    revisions = ("2025-11-25",)

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        await ctx.transport.request(
            "tools/call",
            {"name": "slow_report", "arguments": {"delay": 0.6}},
        )
        return Observation(ctx.revision, tool, ())

    def assert_(self, observation: Observation) -> list[Finding]:
        del observation
        return []


class _Later(Probe):
    id = "budget.later"
    default_severity = "info"
    revisions = ("2025-11-25",)
    ran = False

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        type(self).ran = True
        return Observation(ctx.revision, tool, ())

    def assert_(self, observation: Observation) -> list[Finding]:
        del observation
        return []


def test_registered_audit_finishes_quickly(tmp_path: Path) -> None:
    started = time.monotonic()
    findings = audit_http(tmp_path, "2025-11-25", "none")
    assert time.monotonic() - started < 45
    assert findings == []
