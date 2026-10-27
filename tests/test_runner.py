from __future__ import annotations

import json
from pathlib import Path

import anyio
import jsonschema
import pytest
from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.fixture import FixtureApp
from mcp_cross_exam.probes.base import (
    _REGISTRY,
    Observation,
    Probe,
    ProbeContext,
    ToolView,
    classify_tool,
    observation_from_json,
    register,
)
from mcp_cross_exam.probes.transport import SessionExpiredEmptySuccess
from mcp_cross_exam.runner import REVISION_SKIP, SelectionError, examine, load_probes, select_probes
from mcp_cross_exam.transport import Finding, Frame, RunContext
from mcp_cross_exam.transport.base import json_value, parse_json_bytes
from mcp_cross_exam.transport.http import HttpTransport, open_http

from tests.conftest import start_fixture
from tests.test_transport import StreamingASGITransport

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = {
    "transport.version-negotiation",
    "transport.capabilities-honesty",
    "transport.required-headers",
    "transport.unknown-method",
    "session.token-expired-empty-success",
    "session.expired-not-404",
    "session.expired-empty-success",
    "transport.resume-gap",
    "transport.reconnect-fails",
    "schema.lint.invalid-schema",
    "schema.lint.root-not-object",
    "schema.lint.required-not-declared",
    "schema.lint.missing-description",
    "schema.lint.name-invalid",
    "schema.lint.duplicate-name",
    "schema.lint.annotation-contradiction",
    "schema.lint.unbounded-string",
    "schema.lint.hidden-instructions",
    "schema.undeclared-required-arg",
    "schema.required-not-enforced",
    "schema.extra-args-silently-accepted",
    "schema.silent-coercion",
    "schema.constraint-not-enforced",
    "schema.error-shape.unknown-tool",
    "schema.error-shape.validation-as-protocol-error",
    "schema.error-shape.unactionable",
    "schema.error-shape.internal-leak",
    "schema.output-nonconformant",
    "schema.description-param-mismatch",
    "schema.description-contract-broken",
    "schema.example-fails",
    "schema.annotation-readonly-violated",
    "schema.tool-list-unstable",
    "schema.tool-set-unstable",
    "schema.tool-order-unstable",
    "schema.pagination-broken",
    "schema.list-cache-hints-invalid",
    "schema.list-changed-not-notified",
    "schema.definition-drift",
}


def test_selection_glob_and_skip() -> None:
    chosen = select_probes(
        load_probes(),
        include=("session.*",),
        families=(),
        skip=("session.token-expired-empty-success",),
    )
    assert {probe.id for probe in chosen} == {
        "session.expired-not-404",
        "session.expired-empty-success",
    }


def test_unknown_probe_exits_config(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SelectionError):
        select_probes(load_probes(), include=("missing.probe",), families=(), skip=())
    with pytest.raises(SystemExit) as caught:
        main(["--probe", "missing.probe", "http://127.0.0.1:9/mcp"])
    assert caught.value.code == ExitCode.CONFIG
    assert "unknown probe" in capsys.readouterr().err


def test_probe_list_matches_the_schema(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["probes", "list", "--json"])
    assert caught.value.code == ExitCode.SUCCESS
    payload = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "mcp_cross_exam" / "probes.v1.json").read_text(encoding="utf-8"))
    jsonschema.validate(payload, schema)
    assert {item["id"] for item in payload} == SHIPPED


def test_classification_precedence() -> None:
    contradictory = ToolView("get_ticket", None, True, True)
    assert _effect(contradictory) == ("read", "annotation")
    assert _effect(ToolView("drop_db", None, None, True)) == ("destructive", "annotation")
    assert _effect(ToolView("delete_row", None, None, False)) == ("write", "annotation")
    assert _effect(ToolView("delete_row", None, None, None)) == ("destructive", "heuristic")
    assert _effect(ToolView("create_ticket", None, None, None)) == ("write", "heuristic")
    assert _effect(ToolView("get_ticket", None, None, None)) == ("read", "heuristic")
    assert _effect(ToolView("slow_report", None, None, None)) == ("write", "default")
    configured = classify_tool(ToolView("get_ticket", None, True, True), effect="write")
    assert (configured.effect, configured.source) == ("write", "config")


def test_plan_prints_sources(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "audit.toml"
    config.write_text('[tools.list_tickets]\neffect = "write"\n', encoding="utf-8")
    with start_fixture() as port:
        url = f"http://127.0.0.1:{port}/mcp"
        with pytest.raises(SystemExit) as caught:
            main(["probes", "plan", url])
        assert caught.value.code == ExitCode.SUCCESS
        text = capsys.readouterr().out
        assert "tool get_ticket read annotation" in text
        assert "tool list_tickets read annotation" in text
        assert "tool slow_report read annotation" in text
        assert "tool create_ticket write heuristic" in text
        with pytest.raises(SystemExit) as overridden:
            main(["--config", str(config), "probes", "plan", url])
        assert overridden.value.code == ExitCode.SUCCESS
        planned = capsys.readouterr().out
        assert "tool list_tickets write config" in planned
        with pytest.raises(SystemExit) as selected:
            main(
                [
                    "--probe",
                    "session.*",
                    "--skip",
                    "session.token-expired-empty-success",
                    "probes",
                    "plan",
                    url,
                ]
            )
        assert selected.value.code == ExitCode.SUCCESS
        chosen = capsys.readouterr().out
        assert "session.expired-not-404" in chosen
        assert "session.expired-empty-success" in chosen
        assert "session.token-expired-empty-success" not in chosen
        assert "transport.unknown-method" not in chosen


def test_read_only_blocks_the_write_before_it_is_recorded(tmp_path: Path) -> None:
    blocked = anyio.run(_writes, tmp_path / "blocked", True)
    allowed = anyio.run(_writes, tmp_path / "allowed", False)
    assert blocked == 0
    assert allowed >= 1
    skipped = anyio.run(_scoped, tmp_path / "scoped")
    assert skipped is False


def test_revision_miss_is_a_skip(tmp_path: Path) -> None:
    findings, reasons = anyio.run(_modern, tmp_path)
    assert "session.expired-empty-success" not in {item.item_id for item in findings}
    assert reasons["session.expired-empty-success"] == REVISION_SKIP


def test_frozen_empty_success_observation() -> None:
    raw = (ROOT / "tests" / "empty-success.json").read_text(encoding="utf-8")
    loaded = json_value(json.loads(raw))
    observation = observation_from_json(loaded)
    found = SessionExpiredEmptySuccess().assert_(observation)
    assert [item.item_id for item in found] == ["session.expired-empty-success"]


def test_duplicate_probe_id_is_rejected() -> None:
    class _One(Probe):
        id = "test.duplicate-id"
        default_severity = "info"
        revisions = ("2025-11-25",)

        async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
            return Observation("2025-11-25", tool, ())

        def assert_(self, observation: Observation) -> list[Finding]:
            del observation
            return []

    class _Two(_One):
        id = "test.duplicate-id"

    register(_One)
    try:
        with pytest.raises(RuntimeError, match="duplicate probe id"):
            register(_Two)
    finally:
        _REGISTRY.pop("test.duplicate-id", None)


def _effect(tool: ToolView) -> tuple[str, str]:
    item = classify_tool(tool)
    return item.effect, item.source


async def _writes(directory: Path, read_only: bool) -> int:
    transport, context = await _connect(directory)
    try:
        ctx = _context(transport, context, read_only=read_only)
        await examine(ctx, probes=(_Create(),))
        return _named(transport.recorder.frames, "create_ticket")
    finally:
        await transport.close()


async def _scoped(directory: Path) -> bool:
    transport, context = await _connect(directory)
    probe = _Scoped()
    try:
        ctx = _context(transport, context, read_only=True)
        await examine(ctx, probes=(probe,))
        return probe.ran
    finally:
        await transport.close()


async def _modern(directory: Path) -> tuple[list[Finding], dict[str, str]]:
    app = FixtureApp("2026-07-28", frozenset())
    transport = open_http(
        "http://127.0.0.1:9/mcp",
        network=StreamingASGITransport(app),
        run_dir=directory,
    )
    context = await transport.connect()
    try:
        ctx = _context(transport, context, read_only=False)
        findings = await examine(ctx)
        reasons = {item.probe_id: item.reason for item in context.skips}
        return findings, reasons
    finally:
        await transport.close()


async def _connect(directory: Path) -> tuple[HttpTransport, RunContext]:
    app = FixtureApp("2025-11-25", frozenset())
    transport = open_http(
        "http://127.0.0.1:9/mcp",
        network=StreamingASGITransport(app),
        run_dir=directory,
    )
    context = await transport.connect()
    return transport, context


def _context(transport: HttpTransport, context: RunContext, *, read_only: bool) -> ProbeContext:
    return ProbeContext(
        transport=transport,
        run=context,
        http=True,
        endpoint="http://127.0.0.1:9/mcp",
        expired_bearer=None,
        legacy=False,
        read_only=read_only,
    )


def _named(frames: tuple[Frame, ...], name: str) -> int:
    count = 0
    for frame in frames:
        parsed = parse_json_bytes(frame.body)
        if frame.direction != "outbound" or not isinstance(parsed, dict):
            continue
        if parsed.get("method") != "tools/call":
            continue
        params = parsed.get("params")
        if isinstance(params, dict) and params.get("name") == name:
            count += 1
    return count


class _Create(Probe):
    id = "gate.create"
    default_severity = "info"
    revisions = ("2025-11-25",)

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        await ctx.transport.request("tools/call", {"name": "create_ticket", "arguments": {}})
        return Observation(ctx.revision, tool, ())

    def assert_(self, observation: Observation) -> list[Finding]:
        del observation
        return []


class _Scoped(Probe):
    id = "gate.scoped"
    default_severity = "info"
    revisions = ("2025-11-25",)
    ran = False

    def applies_to(self, tool: ToolView) -> bool:
        return tool.name == "create_ticket"

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        self.ran = True
        await ctx.transport.request("tools/call", {"name": "create_ticket", "arguments": {}})
        return Observation(ctx.revision, tool, ())

    def assert_(self, observation: Observation) -> list[Finding]:
        del observation
        return []
