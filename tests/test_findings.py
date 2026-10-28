from __future__ import annotations

import json
import shlex
from pathlib import Path

import hypothesis.strategies as st
import jsonschema
import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.findings import (
    IMPACTS,
    BlastRadius,
    Finding,
    Repro,
    apply_penalties,
    blast_radius,
    fingerprint_for,
    promote,
)
from mcp_cross_exam.probes.base import ClassifiedTool, ToolView
from mcp_cross_exam.report import is_partial
from mcp_cross_exam.runner import load_probes
from mcp_cross_exam.transport import Finding as Draft
from mcp_cross_exam.transport.base import JsonValue, Severity, json_value

from tests.conftest import start_fixture

_SCHEMA = Path(__file__).parents[1] / "mcp_cross_exam" / "report.v1.json"


def test_round_trip_and_fingerprint_ignore_volatile_fields() -> None:
    draft = _draft({"path": "description", "tool": "get_ticket", "started_at": "2020"})
    finding = promote(draft, classifications=(), scopes={}, severities={}, command="cmd")
    again = Finding.model_validate(finding.model_dump(mode="json"))
    assert again == finding
    same = promote(
        _draft({"tool": "get_ticket", "path": "description", "rpc_id": 9}),
        classifications=(),
        scopes={},
        severities={},
        command="cmd",
    )
    assert same.fingerprint == finding.fingerprint
    other = promote(
        _draft({"tool": "get_ticket", "path": "title"}),
        classifications=(),
        scopes={},
        severities={},
        command="cmd",
    )
    assert other.fingerprint != finding.fingerprint
    left = fingerprint_for("schema.lint.missing-description", "get_ticket", {"path": "a"})
    right = fingerprint_for("schema.lint.missing-description", "list_tickets", {"path": "a"})
    assert left != right


def test_schema_gaps_and_config_severity() -> None:
    draft = _draft(
        {
            "declared_required": ["id"],
            "observed_required": ["id", "title"],
            "tool": "create_ticket",
        }
    )
    finding = promote(
        draft,
        classifications=(),
        scopes={"create_ticket": "global"},
        severities={"schema.lint.missing-description": "critical"},
        command="cmd",
    )
    assert finding.declared == {"declared_required": ["id"]}
    assert finding.observed == {
        "observed_required": ["id", "title"],
        "tool": "create_ticket",
    }
    assert finding.severity == "critical"
    assert finding.severity_source == "config"
    assert finding.blast_radius.scope == "global"
    assert finding.blast_radius.scope_source == "configured"
    plain = promote(
        Draft(item_id="transport.unknown-method", severity="high", summary="no", evidence=None),
        classifications=(),
        scopes={},
        severities={},
        command="cmd",
    )
    assert plain.declared is None
    assert plain.observed is None
    assert plain.severity_source == "default"
    overridden = promote(
        Draft(
            item_id="transport.stdout-pollution",
            severity="medium",
            summary="noise",
            evidence=None,
        ),
        classifications=(),
        scopes={},
        severities={"transport.stdout-pollution": "high"},
        command="cmd",
    )
    assert overridden.severity == "high"
    assert overridden.severity_source == "config"
    failed = promote(
        Draft(
            item_id="probe.error",
            severity="high",
            summary="boom",
            evidence=None,
            data={"probe_id": "schema.lint.missing-description", "tool": "get_ticket"},
        ),
        classifications=(),
        scopes={},
        severities={"schema.lint.missing-description": "low"},
        command="cmd",
    )
    assert failed.probe_id == "schema.lint.missing-description"
    assert failed.severity == "high"
    assert failed.severity_source == "default"
    assert failed.declared == {}
    assert failed.observed == {"probe_id": "schema.lint.missing-description", "tool": "get_ticket"}
    assert failed.blast_radius.agent_impact == "the probe stopped before it could finish"


def test_blast_radius_table() -> None:
    hinted = ToolView(
        "get_ticket",
        None,
        True,
        None,
        annotations={"openWorldHint": True, "readOnlyHint": True},
    )
    configured = blast_radius(
        "get_ticket",
        (ClassifiedTool(hinted, "write", "config"),),
        {},
        "impact",
    )
    assert configured.effect == "write"
    assert configured.effect_source == "configured"
    external = blast_radius(
        "get_ticket",
        (ClassifiedTool(hinted, "read", "annotation"),),
        {"get_ticket": "tenant"},
        "impact",
    )
    assert external.effect == "external"
    assert external.effect_source == "declared"
    assert external.scope == "tenant"
    assert external.scope_source == "configured"
    created = blast_radius("create_ticket", (), {}, "impact")
    assert created.effect == "write"
    assert created.effect_source == "observed"
    fallback = blast_radius("ticket", (), {}, "impact")
    assert fallback.effect == "write"
    assert fallback.effect_source == "default"
    bare = blast_radius(None, (), {}, "impact")
    assert bare.effect == "read"
    assert bare.scope == "user"
    assert bare.scope_source == "default"
    destructive = blast_radius(
        "drop_ticket",
        (
            ClassifiedTool(
                ToolView("drop_ticket", None, False, True),
                "destructive",
                "annotation",
            ),
        ),
        {},
        "impact",
    )
    assert destructive.effect == "destructive"
    assert destructive.effect_source == "declared"


def test_score_examples_and_identity() -> None:
    high = _scored(0, 10, tool="get_ticket")
    medium = _scored(1, 4, tool="get_ticket")
    score, ranked = apply_penalties((high,), 1)
    assert score == 90
    assert ranked[0].penalty == 10
    score, ranked = apply_penalties((high, medium), 1)
    assert score == 88
    assert sorted(item.penalty for item in ranked) == [2, 10]
    critical = _scored(2, 300, tool="create_ticket", severity="critical")
    score, ranked = apply_penalties((critical,), 40)
    assert score == 75
    assert ranked[0].penalty == 25
    assert ranked[0].raw_penalty == 300
    empty, rows = apply_penalties((), 4)
    assert empty == 100
    assert rows == []
    scaled = [
        _scored(index, 10, tool="get_ticket", family=family)
        for index, family in enumerate(("schema", "transport", "session"))
    ]
    score, ranked = apply_penalties(scaled, 40)
    assert score == 75
    assert sum(item.penalty for item in ranked) == 25
    wide = [_scored(index, 300, tool=f"tool-{index}", severity="critical") for index in range(5)]
    score, ranked = apply_penalties(wide, 5)
    assert score == 0
    assert sum(item.penalty for item in ranked) == 100


@given(raws=st.lists(st.integers(min_value=0, max_value=40), max_size=6))
@hypothesis_settings(max_examples=25, deadline=None)
def test_score_is_monotone_and_order_independent(raws: list[int]) -> None:
    rows = [_scored(index, raw) for index, raw in enumerate(raws)]
    score, ranked = apply_penalties(rows, 4)
    assert sum(item.penalty for item in ranked) == 100 - score
    other, other_ranked = apply_penalties(list(reversed(rows)), 4)
    assert other == score
    assert [(item.fingerprint, item.penalty) for item in ranked] == [
        (item.fingerprint, item.penalty) for item in other_ranked
    ]
    running = 100
    built: list[Finding] = []
    for item in rows:
        built.append(item)
        current, _ranked = apply_penalties(built, 4)
        assert current <= running
        running = current


def test_partial_reasons() -> None:
    assert is_partial(("budget exhausted",), ())
    assert is_partial((), ("probe.error",))
    assert not is_partial(("read-only", "write gate", "revision"), ())


def test_impacts_cover_registered_probes() -> None:
    missing = [probe.id for probe in load_probes() if probe.id not in IMPACTS]
    assert missing == []
    assert "transport.stdout-pollution" in IMPACTS
    assert "transport.deprecated-sse" in IMPACTS


def test_fixture_fingerprints_survive_a_replay(tmp_path: Path) -> None:
    with start_fixture(defects="session.expired-empty-success") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        args = ["--seed", "7", "--probe", "session.expired-empty-success", url]
        first = _audit(tmp_path, args)
        second = _audit(tmp_path, args)
        before = _dirs(tmp_path)
        with pytest.raises(SystemExit) as caught:
            main(_argv(_repro(first)))
        assert caught.value.code == ExitCode.FINDINGS
        created = _dirs(tmp_path) - before
    assert len(created) == 1
    third = _load(created.pop() / "report.json")
    assert _fingerprints(first) == _fingerprints(second) == _fingerprints(third)
    _validate(first)


def test_fixture_scores(tmp_path: Path) -> None:
    with start_fixture() as port:
        clean = _audit(tmp_path, ["--seed", "1", f"http://127.0.0.1:{port}/mcp"])
    assert clean["score"] == 100
    coverage = clean["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["status"] == "complete"
    assert clean["findings"] == []
    _validate(clean)
    with start_fixture(defects="all") as port:
        dirty_dir = _run(tmp_path, ["--seed", "1", f"http://127.0.0.1:{port}/mcp"])
    dirty = _load(dirty_dir / "report.json")
    score = dirty["score"]
    assert isinstance(score, int)
    assert score < 50
    assert sum(_penalties(dirty)) == 100 - score
    assert (dirty_dir / "report.html").stat().st_size < 2 * 1024 * 1024
    _validate(dirty)


def _draft(data: dict[str, JsonValue]) -> Draft:
    return Draft(
        item_id="schema.lint.missing-description",
        severity="low",
        summary="get_ticket has no description",
        evidence=None,
        spec_refs=("https://example.invalid/tools",),
        data=data,
    )


def _scored(
    index: int,
    raw: int,
    *,
    tool: str = "get_ticket",
    severity: Severity = "high",
    family: str = "schema",
) -> Finding:
    return Finding(
        probe_id=f"{family}.example-{index}",
        family=family,
        tool=tool,
        severity=severity,
        severity_source="default",
        title="example",
        detail=None,
        declared=None,
        observed=None,
        evidence=[],
        repro=Repro(command="mcp-cross-exam", transcript=None),
        blast_radius=BlastRadius(
            effect="read",
            effect_source="default",
            scope="user",
            scope_source="default",
            agent_impact="impact",
        ),
        spec_refs=[],
        fingerprint=f"{index:064x}",
        raw_penalty=raw,
        penalty=0,
    )


def _audit(tmp_path: Path, argv: list[str]) -> dict[str, JsonValue]:
    return _load(_run(tmp_path, argv) / "report.json")


def _run(tmp_path: Path, argv: list[str]) -> Path:
    before = _dirs(tmp_path)
    with pytest.raises(SystemExit):
        main(argv)
    created = _dirs(tmp_path) - before
    assert len(created) == 1
    return created.pop()


def _dirs(tmp_path: Path) -> set[Path]:
    root = tmp_path / "runs"
    if not root.is_dir():
        return set()
    return {path for path in root.iterdir() if path.is_dir()}


def _load(path: Path) -> dict[str, JsonValue]:
    loaded = json_value(json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        raise AssertionError("report")
    return loaded


def _validate(report: dict[str, JsonValue]) -> None:
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)


def _fingerprints(report: dict[str, JsonValue]) -> list[str]:
    findings = report["findings"]
    if not isinstance(findings, list):
        raise AssertionError("findings")
    found: list[str] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, str):
            found.append(fingerprint)
    return found


def _penalties(report: dict[str, JsonValue]) -> list[int]:
    findings = report["findings"]
    if not isinstance(findings, list):
        raise AssertionError("findings")
    found: list[int] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        penalty = item.get("penalty")
        if isinstance(penalty, int):
            found.append(penalty)
    return found


def _repro(report: dict[str, JsonValue]) -> str:
    findings = report["findings"]
    if not isinstance(findings, list) or not findings or not isinstance(findings[0], dict):
        raise AssertionError("repro")
    repro = findings[0].get("repro")
    if not isinstance(repro, dict):
        raise AssertionError("repro")
    command = repro.get("command")
    if not isinstance(command, str):
        raise AssertionError("repro")
    return command


def _argv(command: str) -> list[str]:
    parts = shlex.split(command)
    assert parts[0] == "mcp-cross-exam"
    return parts[1:]
