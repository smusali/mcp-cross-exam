from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from random import Random

import anyio
import hypothesis.strategies as st
import jsonschema
import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings

from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.fixture import DEFECT_IDS, FixtureApp, parse_defects
from mcp_cross_exam.probes.base import Probe, ProbeContext, observation_from_json, probe_family
from mcp_cross_exam.probes.schema import collect_definitions
from mcp_cross_exam.runner import examine, load_probes
from mcp_cross_exam.schema_audit import (
    argument_examples,
    cache_hints_invalid,
    compare_tool_lists,
    contract_claims,
    extra_arguments,
    field_diff,
    generated_value,
    instance_valid,
    lint_hits,
    load_snapshot,
    minimal_arguments,
    mutations,
    offending_argument,
    param_mismatches,
    result_size,
    result_text,
    schema_issue,
    snapshot_drift,
    string_property,
    without_required,
    write_snapshot,
    wrong_value,
)
from mcp_cross_exam.transport import Finding, Frame
from mcp_cross_exam.transport.base import JsonValue
from mcp_cross_exam.transport.http import open_http
from mcp_cross_exam.transport.stdio import open_stdio
from tests.conftest import start_fixture
from tests.probes.conftest import finding_ids
from tests.support.asgi import StreamingASGITransport
from tests.support.invoke import invoke as _invoke

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "data"
ERAS = ("2025-11-25", "2026-07-28")
MODERN = "2026-07-28"
_OBSERVER = "schema.annotation-readonly-violated"
_LISTS = (
    "schema.tool-list-unstable",
    "schema.tool-set-unstable",
    "schema.tool-order-unstable",
    "schema.pagination-broken",
    "schema.list-cache-hints-invalid",
    "schema.list-changed-not-notified",
)
_SEVERITY = {
    "schema.lint.invalid-schema": "high",
    "schema.lint.root-not-object": "medium",
    "schema.lint.required-not-declared": "high",
    "schema.lint.missing-description": "low",
    "schema.lint.name-invalid": "low",
    "schema.lint.duplicate-name": "high",
    "schema.lint.annotation-contradiction": "medium",
    "schema.lint.unbounded-string": "info",
    "schema.lint.hidden-instructions": "info",
    "schema.undeclared-required-arg": "high",
    "schema.required-not-enforced": "medium",
    "schema.extra-args-silently-accepted": "medium",
    "schema.silent-coercion": "high",
    "schema.constraint-not-enforced": "medium",
    "schema.error-shape.unknown-tool": "low",
    "schema.error-shape.validation-as-protocol-error": "medium",
    "schema.error-shape.unactionable": "medium",
    "schema.error-shape.internal-leak": "medium",
    "schema.output-nonconformant": "high",
    "schema.description-param-mismatch": "medium",
    "schema.description-contract-broken": "medium",
    "schema.example-fails": "medium",
    "schema.tool-list-unstable": "high",
    "schema.tool-set-unstable": "high",
    "schema.pagination-broken": "medium",
    "schema.list-cache-hints-invalid": "low",
    "schema.list-changed-not-notified": "medium",
}
DEFECTS = tuple(item for item in DEFECT_IDS if item.startswith("schema.") and item != _OBSERVER)


def _selected(probe_ids: Sequence[str]) -> tuple[Probe, ...]:
    wanted = set(probe_ids)
    chosen = tuple(probe for probe in load_probes() if probe.id in wanted)
    assert {probe.id for probe in chosen} == wanted
    return chosen


def _schema_ids() -> tuple[str, ...]:
    return tuple(probe.id for probe in load_probes() if probe_family(probe) == "schema")


def examine_http(
    tmp: Path,
    era: str,
    defects: str,
    probe_ids: Sequence[str],
    *,
    observers: Mapping[str, str] | None = None,
    snapshot: Path | None = None,
) -> tuple[list[Finding], tuple[Frame, ...]]:
    app = FixtureApp(era, parse_defects(defects, clean=False))
    url = "http://127.0.0.1:9/mcp"

    async def _go() -> tuple[list[Finding], tuple[Frame, ...]]:
        transport = open_http(url, network=StreamingASGITransport(app), run_dir=tmp)
        context = await transport.connect()
        try:
            ctx = ProbeContext(
                transport=transport,
                run=context,
                http=True,
                endpoint=url,
                expired_bearer=None,
                legacy=False,
            )
            if observers is not None:
                ctx.observers = dict(observers)
            if snapshot is not None:
                ctx.snapshot = str(snapshot)
            found = await examine(ctx, _selected(probe_ids))
            return found, transport.recorder.frames
        finally:
            await transport.close()

    return anyio.run(_go)


def examine_stdio(
    tmp: Path,
    era: str,
    defects: str,
    probe_ids: Sequence[str],
) -> list[Finding]:
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
                ),
                _selected(probe_ids),
            )
        finally:
            await transport.close()

    return anyio.run(_go)


def _object(path: Path) -> dict[str, JsonValue]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(path.name)
    return loaded


def _rows(value: JsonValue | None) -> list[JsonValue]:
    if not isinstance(value, list):
        raise AssertionError(value)
    return value


def test_lint_corpus_matches_the_rules() -> None:
    document = _object(CORPUS / "lint.json")
    for case in _rows(document.get("cases")):
        if not isinstance(case, dict):
            raise AssertionError(case)
        tools = case.get("tools")
        expected = case.get("rules")
        if not isinstance(tools, list) or not isinstance(expected, list):
            raise AssertionError(case.get("name"))
        definitions = [item for item in tools if isinstance(item, dict)]
        assert [hit.rule for hit in lint_hits(definitions)] == expected


def test_mutation_corpus_is_invalid() -> None:
    document = _object(CORPUS / "mutations.json")
    for case in _rows(document.get("cases")):
        if not isinstance(case, dict):
            raise AssertionError(case)
        schema = case.get("schema")
        expected = case.get("mutations")
        if not isinstance(schema, dict) or not isinstance(expected, list):
            raise AssertionError("mutation case")
        found = [
            {"kind": item.kind, "name": item.name, "value": item.value}
            for item in mutations(schema)
        ]
        assert found == expected
        properties = schema.get("properties")
        assert isinstance(properties, dict)
        for item in found:
            name = item["name"]
            assert isinstance(name, str)
            prop = properties.get(name)
            assert isinstance(prop, dict)
            assert not instance_valid(prop, item["value"])


def test_description_corpus() -> None:
    document = _object(CORPUS / "descriptions.json")
    for case in _rows(document.get("mismatches")):
        assert isinstance(case, dict)
        names = case.get("properties")
        description = case.get("description")
        assert isinstance(names, list)
        assert isinstance(description, str)
        properties: dict[str, JsonValue] = {}
        for name in names:
            if isinstance(name, str):
                properties[name] = {"type": "string"}
        schema: dict[str, JsonValue] = {"properties": properties, "type": "object"}
        assert [item.quote for item in param_mismatches(description, schema)] == case["quotes"]
    for case in _rows(document.get("contracts")):
        assert isinstance(case, dict)
        description = case.get("description")
        assert isinstance(description, str)
        claims = [[item.kind, item.quote, item.limit] for item in contract_claims(description)]
        assert claims == case["claims"]
    for case in _rows(document.get("examples")):
        assert isinstance(case, dict)
        description = case.get("description")
        examples = case.get("examples")
        assert isinstance(description, str)
        assert isinstance(examples, list)
        example_schema: dict[str, JsonValue] = {"examples": examples, "type": "object"}
        assert list(argument_examples(description, example_schema)) == case["values"]


def test_saved_observations() -> None:
    document = _object(CORPUS / "observations.json")
    probes = {probe.id: probe for probe in load_probes()}
    for case in _rows(document.get("cases")):
        assert isinstance(case, dict)
        probe_id = case.get("id")
        assert isinstance(probe_id, str)
        found = probes[probe_id].assert_(  # noqa: PT009
            observation_from_json(case.get("observation"))
        )
        if case.get("expect") is True:
            assert finding_ids(found) == {probe_id}
            severity = case.get("severity")
            if isinstance(severity, str):
                assert {item.severity for item in found} == {severity}
        else:
            assert not found


def test_generation_snapshot_and_schema_edges(tmp_path: Path) -> None:
    rng = Random(1)
    dialect = "https://json-schema.org/draft/2020-12/schema"
    assert schema_issue("nope") == "schema is not an object"
    assert schema_issue({"$schema": dialect, "type": "object"}) is None
    assert schema_issue({"$schema": "https://example.invalid/schema", "type": "object"}) == (
        "schema dialect is not supported"
    )
    assert not instance_valid({"$schema": "https://example.invalid/schema", "type": "object"}, {})
    required: dict[str, JsonValue] = {
        "properties": {"title": {"type": "string"}},
        "required": ["title"],
        "type": "object",
    }
    assert offending_argument(required, {}) == "title"
    assert offending_argument(required, {"title": "ok"}) is None
    assert generated_value({"const": "fixed"}, rng) == "fixed"
    assert generated_value({"enum": ["a", "b"]}, rng) in {"a", "b"}
    assert generated_value({"examples": ["sample"]}, rng) == "sample"
    assert generated_value({"default": 3}, rng) == 3
    assert generated_value({"format": "email", "type": "string"}, rng) == "user@example.com"
    dated = generated_value({"format": "date-time", "type": "string"}, rng)
    assert dated == "2020-01-02T03:04:05Z"
    assert generated_value({"format": "uri", "type": "string"}, rng) == "https://example.com"
    short = generated_value({"maxLength": 2, "minLength": 2, "type": "string"}, rng)
    assert isinstance(short, str)
    assert len(short) == 2
    assert generated_value({"maximum": 4, "minimum": 4, "type": "integer"}, rng) == 4
    assert isinstance(generated_value({"type": "number"}, rng), int)
    assert generated_value({"type": "boolean"}, rng) in {False, True}
    assert generated_value({"minItems": 1, "type": "array"}, rng) == ["item"]
    nested: dict[str, JsonValue] = {
        "properties": {"id": {"const": "t"}},
        "required": ["id"],
        "type": "object",
    }
    assert generated_value(nested, rng) == {"id": "t"}
    assert generated_value({"type": "null"}, rng) is None
    assert generated_value({}, rng) is None
    assert minimal_arguments({"type": "string"}, rng, None) is None
    missing: dict[str, JsonValue] = {
        "properties": {},
        "required": ["missing"],
        "type": "object",
    }
    assert minimal_arguments(missing, rng, None) is None
    assert extra_arguments({"type": "object"}, {"title": "ok"}, 1) is None
    closed: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {"title": {"type": "string"}},
        "type": "object",
    }
    extra = extra_arguments(closed, {"title": "ok"}, 3)
    assert extra is not None
    assert extra["crossexam_extra_3"] == "x"
    base: dict[str, JsonValue] = {"other": 1, "title": "ok"}
    dropped = without_required({"required": ["title"], "type": "object"}, base)
    assert dropped == (("title", {"other": 1}),)
    dated_schema: dict[str, JsonValue] = {
        "properties": {
            "at": {"format": "date-time", "type": "string"},
            "note": {"type": "string"},
        },
        "type": "object",
    }
    assert string_property(dated_schema) == "at"
    assert wrong_value({"type": "string"}) == 1
    assert wrong_value({"type": "integer"}) == "nope"
    message: dict[str, JsonValue] = {
        "content": [{"text": "hi", "type": "text"}],
        "message": "more",
    }
    assert result_text(message) == "hi\nmore"
    assert result_size({"structuredContent": {"rows": [1, 2, 3]}}) == 3
    assert not cache_hints_invalid({"cacheScope": "public", "tools": [], "ttlMs": 0})
    assert cache_hints_invalid({"cacheScope": "public", "ttlMs": True})
    assert cache_hints_invalid({"cacheScope": "shared", "ttlMs": 1})
    assert compare_tool_lists(())["order"] is False
    assert field_diff({"a": 1}, {"a": 2})
    hidden = lint_hits(
        [
            {
                "description": "Read \U000e0001",
                "inputSchema": {"type": "object"},
                "name": "get_ticket",
            }
        ]
    )
    assert any(hit.rule == "schema.lint.hidden-instructions" for hit in hidden)
    kept: dict[str, JsonValue] = {"description": "a", "name": "keep"}
    changed: dict[str, JsonValue] = {"description": "b", "name": "keep"}
    previous: dict[str, JsonValue] = {
        "tools": [
            {"definition": kept, "hash": "0", "name": "keep"},
            {"definition": {"name": "gone"}, "hash": "0", "name": "gone"},
        ],
    }
    added: dict[str, JsonValue] = {"name": "new"}
    live = [changed, added]
    drifted = {item.name: item.kind for item in snapshot_drift(live, previous)}
    assert drifted == {"gone": "removed", "keep": "changed", "new": "added"}
    stored: dict[str, JsonValue] = {"tools": [{"definition": kept, "name": "keep"}]}
    assert snapshot_drift([kept], stored) == ()
    path = tmp_path / "snapshot.json"
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        load_snapshot(path)
    path.write_text('{"hash": "abc", "tools": "no"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        load_snapshot(path)


def test_same_seed_builds_the_same_call() -> None:
    schema: dict[str, JsonValue] = {
        "properties": {
            "status": {"enum": ["open", "closed", "pending"], "type": "string"},
        },
        "required": ["status"],
        "type": "object",
    }
    first = minimal_arguments(schema, Random(7), None)
    second = minimal_arguments(schema, Random(7), None)
    assert first is not None
    assert second is not None
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert minimal_arguments(schema, Random(7), {"status": "open"}) == {"status": "open"}


@given(
    prop=st.one_of(
        st.just({"type": "integer"}),
        st.fixed_dictionaries(
            {
                "maximum": st.integers(4, 12),
                "minimum": st.integers(-3, 3),
                "type": st.just("integer"),
            }
        ),
        st.just({"type": "boolean"}),
        st.fixed_dictionaries(
            {
                "enum": st.lists(
                    st.sampled_from(["open", "closed", "pending"]),
                    min_size=1,
                    max_size=3,
                    unique=True,
                ),
                "type": st.just("string"),
            }
        ),
        st.fixed_dictionaries(
            {"format": st.sampled_from(["date-time", "email", "uri"]), "type": st.just("string")}
        ),
        st.fixed_dictionaries(
            {
                "items": st.just({"type": "string"}),
                "maxItems": st.integers(0, 3),
                "type": st.just("array"),
            }
        ),
    )
)
@hypothesis_settings(max_examples=25, deadline=None)
def test_every_mutation_is_invalid(prop: dict[str, JsonValue]) -> None:
    schema: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {"field": prop},
        "type": "object",
    }
    for item in mutations(schema):
        assert item.name == "field"
        assert not instance_valid(prop, item.value)


def test_snapshot_bytes_match_the_golden(tmp_path: Path) -> None:
    golden = (CORPUS / "snapshot.golden.json").read_bytes()
    document = json.loads(golden)
    schema = json.loads((ROOT / "schemas" / "snapshot.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)
    assert isinstance(document, dict)
    tools = document.get("tools")
    assert isinstance(tools, list)
    definitions = []
    for item in tools:
        assert isinstance(item, dict)
        definition = item.get("definition")
        assert isinstance(definition, dict)
        definitions.append(definition)
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_snapshot(first, definitions)
    write_snapshot(second, definitions)
    assert first.read_bytes() == second.read_bytes() == golden


@pytest.mark.parametrize("era", ERAS)
def test_clean_schema_is_quiet(tmp_path: Path, era: str) -> None:
    http, _frames = examine_http(tmp_path, era, "none", _schema_ids())
    stdio = examine_stdio(tmp_path / era, era, "none", _schema_ids())
    assert not http
    assert not stdio
    assert len(_schema_ids()) == 30
    assert len(DEFECTS) == 28


@pytest.mark.parametrize("era", ERAS)
@pytest.mark.parametrize("defect", DEFECTS)
def test_fixture_defect(tmp_path: Path, era: str, defect: str) -> None:
    found, _frames = examine_http(tmp_path, era, defect, (defect,))
    if defect == "schema.list-cache-hints-invalid" and era != MODERN:
        assert not found
        return
    assert finding_ids(found) == {defect}
    if defect == "schema.tool-order-unstable":
        severity = "medium" if era == MODERN else "low"
    else:
        severity = _SEVERITY[defect]
    assert {item.severity for item in found} == {severity}
    if defect == "schema.list-cache-hints-invalid":
        assert any(ref.endswith("/server/utilities/caching") for ref in found[0].spec_refs)
    if defect != "schema.undeclared-required-arg":
        return
    assert len(found) == 1
    data = found[0].data
    assert data is not None
    assert data["declared_required"] == []
    assert data["observed_required"] == ["title"]
    assert len(found[0].frames) == 2


@pytest.mark.parametrize("era", ERAS)
def test_readonly_annotation_needs_an_observer(tmp_path: Path, era: str) -> None:
    quiet, _frames = examine_http(tmp_path, era, _OBSERVER, (_OBSERVER,))
    watched, _frames = examine_http(
        tmp_path / "watched",
        era,
        _OBSERVER,
        (_OBSERVER,),
        observers={"get_ticket": "list_tickets"},
    )
    assert not quiet
    assert finding_ids(watched) == {_OBSERVER}
    assert {item.severity for item in watched} == {"high"}


@pytest.mark.parametrize("era", ERAS)
def test_static_and_list_probes_do_not_call_tools(tmp_path: Path, era: str) -> None:
    lint = tuple(probe.id for probe in load_probes() if probe.id.startswith("schema.lint."))
    listed, frames = examine_http(tmp_path, era, "none", lint)
    methods = {frame.method for frame in frames}
    assert not listed
    assert "tools/call" not in methods
    assert "tools/list" in methods
    listed, frames = examine_http(tmp_path / "lists", era, "none", _LISTS)
    methods = {frame.method for frame in frames}
    assert not listed
    assert "tools/call" not in methods
    assert "tools/list" in methods


@pytest.mark.parametrize("era", ERAS)
def test_definition_drift_after_a_description_change(tmp_path: Path, era: str) -> None:
    path = tmp_path / "tools.json"
    app = FixtureApp(era, parse_defects("none", clean=False))

    async def _capture() -> None:
        transport = open_http(
            "http://127.0.0.1:9/mcp",
            network=StreamingASGITransport(app),
            run_dir=tmp_path / "capture",
        )
        await transport.connect()
        try:
            write_snapshot(path, await collect_definitions(transport))
        finally:
            await transport.close()

    anyio.run(_capture)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    tools = loaded.get("tools")
    assert isinstance(tools, list)
    edited = False
    for item in tools:
        if not isinstance(item, dict) or item.get("name") != "get_ticket":
            continue
        definition = item.get("definition")
        assert isinstance(definition, dict)
        definition["description"] = "Changed."
        edited = True
    assert edited
    path.write_text(json.dumps(loaded, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    found, _frames = examine_http(
        tmp_path / "drift",
        era,
        "none",
        ("schema.definition-drift",),
        snapshot=path,
    )
    assert len(found) == 1
    assert found[0].item_id == "schema.definition-drift"
    data = found[0].data
    assert data is not None
    assert data["tool"] == "get_ticket"
    assert data["kind"] == "changed"
    assert isinstance(data["diff"], str)
    assert "Changed." in data["diff"]


def test_missing_snapshot_is_a_config_error(tmp_path: Path) -> None:
    result = _invoke(["--snapshot", str(tmp_path / "missing.json"), "http://127.0.0.1:9/mcp"])
    assert result.exit_code == ExitCode.CONFIG
    assert "snapshot not found" in result.output


def test_snapshot_command_stays_a_command() -> None:
    result = _invoke(["snapshot", "--help"])
    assert result.exit_code == 0
    assert "write" in result.stdout


def test_snapshot_write_is_byte_stable(tmp_path: Path) -> None:
    schema = json.loads((ROOT / "schemas" / "snapshot.schema.json").read_text(encoding="utf-8"))
    with start_fixture() as port:
        url = f"http://127.0.0.1:{port}/mcp"
        first = tmp_path / "first.json"
        second = tmp_path / "second.json"
        for path in (first, second):
            result = _invoke(["snapshot", "write", "--out", str(path), url])
            assert result.exit_code == ExitCode.SUCCESS
        assert first.read_bytes() == second.read_bytes()
        jsonschema.Draft202012Validator(schema).validate(json.loads(first.read_text()))


@pytest.mark.parametrize(
    ("defect", "code"),
    [
        ("schema.lint.unbounded-string", ExitCode.SUCCESS),
        ("schema.lint.missing-description", ExitCode.SUCCESS),
        ("schema.lint.invalid-schema", ExitCode.FINDINGS),
    ],
)
def test_low_findings_do_not_fail_ci(defect: str, code: ExitCode) -> None:
    with start_fixture(defects=defect) as port:
        result = _invoke(["--probe", defect, f"http://127.0.0.1:{port}/mcp"])
    assert result.exit_code == code
