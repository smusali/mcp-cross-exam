from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import ClassVar

from mcp_cross_exam import SUPPORTED_PROTOCOL_REVISIONS
from mcp_cross_exam.probes.base import (
    Call,
    Observation,
    Probe,
    ProbeContext,
    ToolView,
    is_empty_success,
    register,
)
from mcp_cross_exam.probes.transport import _invoke
from mcp_cross_exam.schema_audit import (
    ContractClaim,
    Drift,
    LintHit,
    Mutation,
    argument_examples,
    cache_hints_invalid,
    compare_tool_lists,
    contract_claims,
    extra_arguments,
    generated_value,
    instance_valid,
    leaks_internal,
    lint_hits,
    load_snapshot,
    minimal_arguments,
    mutations,
    offending_argument,
    param_mismatches,
    result_size,
    result_text,
    snapshot_drift,
    string_property,
    tool_hash,
    undeclared_name,
    without_required,
    wrong_value,
)
from mcp_cross_exam.transport import Finding, Frame, Skip, Transport
from mcp_cross_exam.transport.base import MODERN_VERSION, JsonValue, Severity

_PAGES = 16
_SAMPLES = 3
_UNKNOWN = "crossexam_unknown_tool"
_LIST_CHANGED = "notifications/tools/list_changed"
_MODERN_ERRORS = "2025-11-25"
_Rows = list[tuple[str, dict[str, JsonValue]]]
Fetch = Callable[[dict[str, JsonValue]], Awaitable[JsonValue]]


class _Cap(Exception):
    pass


class _SchemaProbe(Probe):
    revisions = SUPPORTED_PROTOCOL_REVISIONS
    family = "schema"
    mutates = False


class _LintProbe(_SchemaProbe):
    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        return await _lint_observation(ctx, tool)

    def assert_(self, observation: Observation) -> list[Finding]:
        return _findings_for(self, observation, _lint_hits(self, observation))


class _ListProbe(_SchemaProbe):
    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        return await _list_observation(ctx, tool)

    def assert_(self, observation: Observation) -> list[Finding]:
        return _findings_for(self, observation, _list_hits(self, observation))

    async def teardown(self, ctx: ProbeContext) -> None:
        if "schema.list.closed" in ctx.cache:
            return
        ctx.run = await ctx.transport.reset()
        ctx.cache["schema.list.closed"] = Observation(ctx.revision, None, ())


class _ToolProbe(_SchemaProbe):
    def applies_to(self, tool: ToolView) -> bool:
        del tool
        return True

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        if tool is None:
            return Observation(ctx.revision, None, ())
        collected = await _collection(ctx, tool, self.id)
        return _focus(collected, self.id)

    def assert_(self, observation: Observation) -> list[Finding]:
        return _findings_for(self, observation, _tool_hits(self, observation))


class _UnknownTool(_SchemaProbe):
    id = "schema.error-shape.unknown-tool"
    default_severity: ClassVar[Severity] = "low"

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        call = await _invoke(ctx, "tools/call", {"name": _UNKNOWN, "arguments": {}})
        frames = () if call.inbound is None else (call.inbound,)
        code = call.error_code
        return Observation(
            ctx.revision,
            tool,
            frames,
            calls=(call,),
            payload={"error_code": code},
        )

    def assert_(self, observation: Observation) -> list[Finding]:
        payload = _payload(observation)
        if payload.get("error_code") == -32602:
            return []
        return [_emit(self, observation, f"unknown tool {_UNKNOWN} was not rejected with -32602")]


class _Drift(_SchemaProbe):
    id = "schema.definition-drift"
    default_severity: ClassVar[Severity] = "medium"

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del tools
        return ctx.snapshot is not None

    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation:
        path = ctx.snapshot
        if path is None:
            return Observation(ctx.revision, tool, ())
        previous = load_snapshot(Path(path))
        listed, _broken, calls = await _sample(ctx)
        drifts = snapshot_drift(listed, previous)
        payload: dict[str, JsonValue] = {"drifts": [_drift_row(item) for item in drifts]}
        frames = tuple(call.inbound for call in calls if call.inbound is not None)
        return Observation(ctx.revision, tool, frames, calls=tuple(calls), payload=payload)

    def assert_(self, observation: Observation) -> list[Finding]:
        found: list[Finding] = []
        for item in _rows(_payload(observation).get("drifts")):
            name = item.get("name")
            if not isinstance(name, str):
                continue
            kind = item.get("kind")
            diff = item.get("diff")
            data: dict[str, JsonValue] = {
                "diff": diff if isinstance(diff, str) else "",
                "kind": kind if isinstance(kind, str) else "",
                "tool": name,
            }
            found.append(_emit(self, observation, f"{name} definition drifted", data))
        return found


def probes() -> tuple[Probe, ...]:
    from mcp_cross_exam.probes.base import registered_instances

    return registered_instances()


async def collect_definitions(transport: Transport) -> list[dict[str, JsonValue]]:
    listed, _broken, _calls = await _walk(transport)
    return listed


async def _lint_observation(ctx: ProbeContext, tool: ToolView | None) -> Observation:
    cached = ctx.cache.get("schema.lint")
    if cached is not None:
        return cached
    definitions = [
        item.tool.definition for item in ctx.classifications if item.tool.definition is not None
    ]
    hits: list[JsonValue] = []
    for item in lint_hits(definitions):
        hits.append(_hit_row(item))
    observation = Observation(ctx.revision, tool, (), payload={"hits": hits})
    ctx.cache["schema.lint"] = observation
    return observation


async def _list_observation(ctx: ProbeContext, tool: ToolView | None) -> Observation:
    cached = ctx.cache.get("schema.list")
    if cached is not None:
        return cached
    samples: list[JsonValue] = []
    hints: list[JsonValue] = []
    calls: list[Call] = []
    broken = False
    for _index in range(_SAMPLES):
        ctx.run = await ctx.transport.reset()
        listed, page_broken, page_calls, result = await _sample_result(ctx)
        page: list[JsonValue] = []
        for item in listed:
            page.append(item)
        samples.append(page)
        hints.append(result)
        calls.extend(page_calls)
        broken = broken or page_broken
    changed, notified, extra = await _changed_list(ctx, samples)
    calls.extend(extra)
    payload: dict[str, JsonValue] = {
        "hints": hints,
        "list_changed": changed,
        "notified": notified,
        "pagination": broken,
        "samples": samples,
    }
    frames = tuple(call.inbound for call in calls if call.inbound is not None)
    observation = Observation(ctx.revision, tool, frames, calls=tuple(calls), payload=payload)
    ctx.cache["schema.list"] = observation
    return observation


async def _collection(ctx: ProbeContext, tool: ToolView, probe_id: str) -> Observation:
    key = f"schema.tool.{tool.name}"
    cached = ctx.cache.get(key)
    if cached is not None:
        return cached
    observation = await _gather(ctx, tool)
    ctx.cache[key] = observation
    reason = None if observation.payload is None else observation.payload.get("skip")
    if isinstance(reason, str):
        ctx.run.skips.append(Skip(probe_id, tool.name, reason))
    return observation


async def _gather(ctx: ProbeContext, tool: ToolView) -> Observation:
    schema = tool.input_schema or {}
    hints = ctx.arguments.get(tool.name)
    payload: dict[str, JsonValue] = {
        "contracts": [],
        "examples": [],
        "extra_accepted": None,
        "groups": {},
        "mismatches": [
            _mismatch_row(item.quote, item.path)
            for item in param_mismatches(tool.description, schema)
        ],
        "mutations": [],
        "unenforced": [],
    }
    groups = payload["groups"]
    caller = _Caller(ctx, _limit(ctx))
    minimal = minimal_arguments(schema, ctx.rng, hints)
    if minimal is None:
        payload["skip"] = "missing args hint"
        _static_examples(tool, schema, payload)
        return _done(ctx, tool, caller, payload)
    try:
        await _exercise(ctx, tool, schema, minimal, caller, payload, groups)
    except _Cap:
        payload["skip"] = "max calls"
    return _done(ctx, tool, caller, payload)


async def _exercise(
    ctx: ProbeContext,
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal: dict[str, JsonValue],
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    observer = ctx.observers.get(tool.name) if tool.read_only is True else None
    before: Call | None = None
    if observer is not None:
        before = await caller.call(observer, {}, fresh=True)
    started = len(caller.calls)
    minimal_call = await caller.call(tool.name, minimal)
    _remember(groups, "schema.output-nonconformant", started, caller.calls)
    if observer is not None and before is not None:
        after = await caller.call(observer, {}, fresh=True)
        payload["observer_changed"] = before.result != after.result
        _remember(groups, "schema.annotation-readonly-violated", started - 1, caller.calls)
    else:
        payload["observer_changed"] = None
    await _required_checks(tool, schema, minimal, minimal_call, caller, payload, groups)
    await _mutate(ctx, tool, schema, minimal, caller, payload, groups)
    await _invalid_call(tool, schema, minimal, caller, payload, groups)
    payload["output_ok"] = _output_ok(minimal_call, tool)
    await _contracts(tool, schema, minimal_call, caller, payload)
    await _examples(tool, schema, caller, payload, groups)


async def _required_checks(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal: Mapping[str, JsonValue],
    minimal_call: Call,
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    declared = _strings(schema.get("required"))
    if not _accepted(minimal_call):
        name = undeclared_name(_call_text(minimal_call), schema)
        if name is not None:
            await _repair(
                tool,
                schema,
                minimal,
                minimal_call,
                name,
                declared,
                caller,
                payload,
                groups,
            )
    unenforced: list[JsonValue] = []
    started = len(caller.calls)
    for name, arguments in without_required(schema, minimal):
        call = await caller.call(tool.name, arguments)
        if _accepted(call):
            unenforced.append(name)
    payload["unenforced"] = unenforced
    _remember(groups, "schema.required-not-enforced", started, caller.calls)
    extra = extra_arguments(schema, minimal, caller.ctx.seed)
    if extra is None:
        return
    started = len(caller.calls)
    call = await caller.call(tool.name, extra)
    payload["extra_accepted"] = _accepted(call)
    _remember(groups, "schema.extra-args-silently-accepted", started, caller.calls)


async def _repair(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal: Mapping[str, JsonValue],
    failed: Call,
    name: str,
    declared: Sequence[str],
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    prop = properties.get(name)
    if not isinstance(prop, dict):
        return
    value = generated_value(prop, caller.ctx.rng)
    if value is None:
        return
    arguments = dict(minimal)
    arguments[name] = value
    if not instance_valid(schema, arguments):
        return
    started = len(caller.calls)
    repaired = await caller.call(tool.name, arguments)
    if not _accepted(repaired):
        return
    observed: list[JsonValue] = []
    for item in declared:
        observed.append(item)
    observed.append(name)
    declared_values: list[JsonValue] = []
    for item in declared:
        declared_values.append(item)
    payload["undeclared"] = {
        "declared_required": declared_values,
        "observed_required": observed,
    }
    fail_at = caller.calls.index(failed)
    _remember(groups, "schema.undeclared-required-arg", fail_at, caller.calls[: fail_at + 1])
    _remember(groups, "schema.undeclared-required-arg", started, caller.calls)


def _remember(groups: JsonValue, name: str, started: int, calls: Sequence[Call]) -> None:
    if not isinstance(groups, dict) or started < 0:
        return
    current = groups.get(name)
    indexes = list(current) if isinstance(current, list) else []
    indexes.extend(range(started, len(calls)))
    groups[name] = indexes


async def _mutate(
    ctx: ProbeContext,
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal: Mapping[str, JsonValue],
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    del ctx
    rows: list[JsonValue] = []
    started = len(caller.calls)
    for item in mutations(schema):
        arguments = dict(minimal)
        arguments[item.name] = item.value
        call = await caller.call(tool.name, arguments)
        if not _accepted(call):
            continue
        if item.kind == "constraint":
            rows.append({"kind": "constraint", "name": item.name, "value": item.value})
            continue
        recorded = await _coercion(tool, minimal, item, call, caller)
        if recorded is not None:
            rows.append(recorded)
    payload["mutations"] = rows
    _remember(groups, "schema.silent-coercion", started, caller.calls)
    _remember(groups, "schema.constraint-not-enforced", started, caller.calls)


async def _coercion(
    tool: ToolView,
    minimal: Mapping[str, JsonValue],
    item: Mutation,
    call: Call,
    caller: _Caller,
) -> dict[str, JsonValue] | None:
    canonical_args = dict(minimal)
    canonical_args[item.name] = item.canonical
    canonical = await caller.call(tool.name, canonical_args)
    if not _accepted(canonical) or canonical.result is None:
        return None
    severity: Severity = "low"
    if item.opposite is not None:
        opposite_args = dict(minimal)
        opposite_args[item.name] = item.opposite
        opposite = await caller.call(tool.name, opposite_args)
        opposite_hit = opposite.result == call.result and opposite.result != canonical.result
        if _accepted(opposite) and opposite_hit:
            severity = "high"
        elif call.result != canonical.result:
            severity = "low"
    return {
        "canonical": canonical.result,
        "kind": "type",
        "name": item.name,
        "observed": call.result,
        "severity": severity,
    }


async def _invalid_call(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal: Mapping[str, JsonValue],
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        return
    name = sorted(key for key in properties if isinstance(key, str))[0]
    prop = properties.get(name)
    if not isinstance(prop, dict):
        return
    arguments = dict(minimal)
    arguments[name] = wrong_value(prop)
    if instance_valid(schema, arguments):
        return
    started = len(caller.calls)
    call = await caller.call(tool.name, arguments)
    argument = offending_argument(schema, arguments) or name
    payload["invalid"] = _invalid_row(call, argument)
    _remember(groups, "schema.error-shape.validation-as-protocol-error", started, caller.calls)
    _remember(groups, "schema.error-shape.unactionable", started, caller.calls)
    _remember(groups, "schema.error-shape.internal-leak", started, caller.calls)


async def _contracts(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal_call: Call,
    caller: _Caller,
    payload: dict[str, JsonValue],
) -> None:
    rows: list[JsonValue] = []
    for claim in contract_claims(tool.description):
        broken = await _broken_claim(tool, schema, minimal_call, caller, claim)
        if broken is None:
            continue
        rows.append({"broken": broken, "kind": claim.kind, "quote": claim.quote})
    payload["contracts"] = rows


async def _broken_claim(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    minimal_call: Call,
    caller: _Caller,
    claim: ContractClaim,
) -> bool | None:
    if claim.kind == "limit":
        if not _accepted(minimal_call) or claim.limit is None:
            return None
        return result_size(minimal_call.result) > claim.limit
    name = string_property(schema)
    if name is None:
        return None
    arguments = {name: "2020-01-01"}
    call = await caller.call(tool.name, arguments)
    return not _accepted(call)


async def _examples(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    caller: _Caller,
    payload: dict[str, JsonValue],
    groups: JsonValue,
) -> None:
    rows: list[JsonValue] = []
    started = len(caller.calls)
    for example in argument_examples(tool.description, schema):
        if not instance_valid(schema, example):
            rows.append({"ok": False})
            continue
        if tool.read_only is not True:
            continue
        call = await caller.call(tool.name, example)
        rows.append({"ok": _accepted(call)})
    payload["examples"] = rows
    _remember(groups, "schema.example-fails", started, caller.calls)


def _static_examples(
    tool: ToolView,
    schema: Mapping[str, JsonValue],
    payload: dict[str, JsonValue],
) -> None:
    rows: list[JsonValue] = []
    for example in argument_examples(tool.description, schema):
        if not instance_valid(schema, example):
            rows.append({"ok": False})
    if rows:
        payload["examples"] = rows


def _output_ok(call: Call, tool: ToolView) -> bool | None:
    schema = tool.output_schema
    result = call.result
    if schema is None or not _accepted(call) or not isinstance(result, dict):
        return None
    if "structuredContent" in result:
        return instance_valid(schema, result["structuredContent"])
    return not is_empty_success(result, tool)


def _done(
    ctx: ProbeContext,
    tool: ToolView,
    caller: _Caller,
    payload: dict[str, JsonValue],
) -> Observation:
    frames = tuple(call.inbound for call in caller.calls if call.inbound is not None)
    return Observation(ctx.revision, tool, frames, calls=tuple(caller.calls), payload=payload)


class _Caller:
    def __init__(self, ctx: ProbeContext, limit: int) -> None:
        self.ctx = ctx
        self.limit = limit
        self.calls: list[Call] = []
        self._cache: dict[str, Call] = {}

    async def call(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        fresh: bool = False,
    ) -> Call:
        ordered = {key: arguments[key] for key in sorted(arguments)}
        key = name + "\0" + json.dumps(ordered, sort_keys=True)
        if not fresh:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        if len(self.calls) >= self.limit:
            raise _Cap
        call = await _guarded(self.ctx, name, ordered)
        self.calls.append(call)
        self._cache[key] = call
        return call


async def _guarded(ctx: ProbeContext, name: str, arguments: dict[str, JsonValue]) -> Call:
    from mcp_cross_exam.runner import BudgetExceeded, WriteBlocked

    try:
        return await _invoke(ctx, "tools/call", {"name": name, "arguments": arguments})
    except WriteBlocked:
        raise
    except BudgetExceeded:
        if _exhausted(ctx):
            raise
        raise _Cap from None


def _exhausted(ctx: ProbeContext) -> bool:
    budget = ctx.budget
    started = ctx.started_at
    if budget is None or started is None:
        return False
    return ctx.clock() - started >= budget.wall_clock_s


def _limit(ctx: ProbeContext) -> int:
    if ctx.budget is None:
        return 50
    return ctx.budget.max_calls_per_tool


async def _sample(ctx: ProbeContext) -> tuple[list[dict[str, JsonValue]], bool, list[Call]]:
    listed, broken, calls, _result = await _sample_result(ctx)
    return listed, broken, calls


async def _sample_result(
    ctx: ProbeContext,
) -> tuple[list[dict[str, JsonValue]], bool, list[Call], dict[str, JsonValue]]:
    calls: list[Call] = []

    async def fetch(params: dict[str, JsonValue]) -> JsonValue:
        call = await _invoke(ctx, "tools/list", params)
        calls.append(call)
        if isinstance(call.result, dict):
            return call.result
        return {}

    listed, broken, result = await _pages(fetch)
    return listed, broken, calls, result


async def _walk(
    transport: Transport,
) -> tuple[list[dict[str, JsonValue]], bool, list[Call]]:
    async def fetch(params: dict[str, JsonValue]) -> JsonValue:
        return await transport.request("tools/list", params)

    listed, broken, _result = await _pages(fetch)
    return listed, broken, []


async def _pages(
    fetch: Fetch,
) -> tuple[list[dict[str, JsonValue]], bool, dict[str, JsonValue]]:
    cursor: str | None = None
    seen: set[str] = set()
    ordered: list[str] = []
    found: dict[str, dict[str, JsonValue]] = {}
    first: dict[str, JsonValue] = {}
    opened = False
    broken = False
    for _page in range(_PAGES):
        params: dict[str, JsonValue] = {} if cursor is None else {"cursor": cursor}
        result = await fetch(params)
        page = result if isinstance(result, dict) else {}
        if not opened:
            opened = True
            first = page
        for tool in _tool_rows(page):
            name = tool.get("name")
            if isinstance(name, str) and name not in found:
                found[name] = tool
                ordered.append(name)
        nxt = page.get("nextCursor")
        if not isinstance(nxt, str) or not nxt:
            break
        if nxt in seen:
            broken = True
            break
        seen.add(nxt)
        cursor = nxt
    else:
        broken = True
    return [found[name] for name in ordered], broken, first


async def _changed_list(
    ctx: ProbeContext,
    samples: Sequence[JsonValue],
) -> tuple[bool, bool, list[Call]]:
    caps = {} if ctx.server is None else ctx.server.capabilities
    tools = caps.get("tools")
    if not isinstance(tools, dict) or tools.get("listChanged") is not True:
        return False, False, []
    start = len(ctx.transport.recorder.frames)
    listed, _broken, calls = await _sample(ctx)
    notified = _saw(ctx.transport.recorder.frames[start:])
    previous = _sample_rows(samples[-1]) if samples else []
    return _identity(listed) != _identity(previous), notified, calls


def _identity(tools: Sequence[Mapping[str, JsonValue]]) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    for tool in tools:
        name = tool.get("name")
        if isinstance(name, str):
            rows.append((name, tool_hash(tool)))
    return tuple(sorted(rows))


def _saw(frames: Sequence[Frame]) -> bool:
    return any(frame.method == _LIST_CHANGED for frame in frames)


def _lint_hits(probe: Probe, observation: Observation) -> _Rows:
    found: _Rows = []
    for item in _rows(_payload(observation).get("hits")):
        if item.get("rule") != probe.id:
            continue
        summary = item.get("summary")
        data = item.get("data")
        if isinstance(summary, str) and isinstance(data, dict):
            found.append((summary, data))
    return found


def _list_hits(probe: Probe, observation: Observation) -> _Rows:
    payload = _payload(observation)
    if probe.id == "schema.tool-list-unstable":
        return _unstable_hits(payload)
    if probe.id == "schema.tool-set-unstable":
        return _set_hits(payload)
    if probe.id == "schema.tool-order-unstable":
        return _order_hits(probe, observation, payload)
    if probe.id == "schema.pagination-broken":
        if payload.get("pagination") is True:
            return [("tools/list repeated a cursor", {})]
        return []
    if probe.id == "schema.list-cache-hints-invalid":
        return _hint_hits(observation, payload)
    if probe.id == "schema.list-changed-not-notified":
        return _changed_hits(observation, payload)
    return []


def _unstable_hits(payload: Mapping[str, JsonValue]) -> _Rows:
    compared = compare_tool_lists(_sample_lists(payload.get("samples")))
    unstable = compared.get("unstable")
    if not isinstance(unstable, list) or not unstable:
        return []
    names = [
        item.get("name")
        for item in unstable
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    if not names:
        return []
    label = ", ".join(str(name) for name in names)
    return [(f"{label} definition changed across connections", {"tools": unstable})]


def _set_hits(payload: Mapping[str, JsonValue]) -> _Rows:
    compared = compare_tool_lists(_sample_lists(payload.get("samples")))
    absent = compared.get("absent")
    if not isinstance(absent, list) or not absent:
        return []
    names = [item for item in absent if isinstance(item, str)]
    if not names:
        return []
    label = ", ".join(names)
    tools: list[JsonValue] = []
    for item in names:
        tools.append(item)
    return [(f"{label} was missing from a connection", {"tools": tools})]


def _order_hits(
    probe: Probe,
    observation: Observation,
    payload: Mapping[str, JsonValue],
) -> _Rows:
    del probe
    compared = compare_tool_lists(_sample_lists(payload.get("samples")))
    if compared.get("order") is not True:
        return []
    severity: Severity = "medium" if observation.revision == MODERN_VERSION else "low"
    return [("tool order changed across connections", {"severity": severity})]


def _hint_hits(
    observation: Observation,
    payload: Mapping[str, JsonValue],
) -> _Rows:
    if observation.revision != MODERN_VERSION:
        return []
    for item in _rows(payload.get("hints")):
        if "tools" in item and cache_hints_invalid(item):
            return [("tools/list cache hints are missing or invalid", {})]
    return []


def _changed_hits(
    observation: Observation,
    payload: Mapping[str, JsonValue],
) -> _Rows:
    if payload.get("list_changed") is not True:
        return []
    if payload.get("notified") is True or _saw(observation.frames):
        return []
    return [("tools/list changed without notifications/tools/list_changed", {})]


def _tool_hits(probe: Probe, observation: Observation) -> _Rows:
    payload = _payload(observation)
    name = None if observation.tool is None else observation.tool.name
    label = name or "tool"
    if probe.id == "schema.undeclared-required-arg":
        return _undeclared_hits(label, payload)
    if probe.id == "schema.required-not-enforced":
        return _unenforced_hits(label, payload)
    if probe.id == "schema.extra-args-silently-accepted":
        if payload.get("extra_accepted") is True:
            return [(f"{label} accepted an undeclared argument", {"tool": label})]
        return []
    if probe.id == "schema.silent-coercion":
        return _coercion_hits(label, payload)
    if probe.id == "schema.constraint-not-enforced":
        return _constraint_hits(label, payload)
    if probe.id == "schema.error-shape.validation-as-protocol-error":
        return _protocol_hits(label, observation, payload)
    if probe.id == "schema.error-shape.unactionable":
        return _unactionable_hits(label, payload)
    if probe.id == "schema.error-shape.internal-leak":
        return _leak_hits(label, payload)
    if probe.id == "schema.output-nonconformant":
        if payload.get("output_ok") is False:
            return [(f"{label} structuredContent does not match outputSchema", {"tool": label})]
        return []
    if probe.id == "schema.description-param-mismatch":
        return _mismatch_hits(label, payload)
    if probe.id == "schema.description-contract-broken":
        return _contract_hits(label, payload)
    if probe.id == "schema.example-fails":
        return _example_hits(label, payload)
    if probe.id == "schema.annotation-readonly-violated":
        if payload.get("observer_changed") is True:
            return [(f"{label} changed another tool despite readOnlyHint", {"tool": label})]
        return []
    return []


def _undeclared_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    raw = payload.get("undeclared")
    if not isinstance(raw, dict):
        return []
    declared = raw.get("declared_required")
    observed = raw.get("observed_required")
    if not isinstance(declared, list) or not isinstance(observed, list):
        return []
    return [
        (
            f"{label} requires an argument it does not declare",
            {"declared_required": declared, "observed_required": observed, "tool": label},
        )
    ]


def _unenforced_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    names = payload.get("unenforced")
    if not isinstance(names, list) or not names:
        return []
    shown = ", ".join(item for item in names if isinstance(item, str))
    return [
        (
            f"{label} accepts a call without required {shown}",
            {"arguments": names, "tool": label},
        )
    ]


def _coercion_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    found: _Rows = []
    for item in _rows(payload.get("mutations")):
        if item.get("kind") != "type":
            continue
        name = item.get("name")
        severity = item.get("severity")
        if not isinstance(name, str) or severity not in {"low", "high"}:
            continue
        data = {
            "argument": name,
            "canonical": item.get("canonical"),
            "observed": item.get("observed"),
            "severity": severity,
            "tool": label,
        }
        found.append((f"{label} coerced {name}", data))
    return found


def _constraint_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    found: _Rows = []
    for item in _rows(payload.get("mutations")):
        if item.get("kind") != "constraint":
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        found.append(
            (
                f"{label} did not enforce {name}",
                {"argument": name, "tool": label, "value": item.get("value")},
            )
        )
    return found


def _protocol_hits(
    label: str,
    observation: Observation,
    payload: Mapping[str, JsonValue],
) -> _Rows:
    raw = payload.get("invalid")
    if not isinstance(raw, dict) or raw.get("protocol") is not True:
        return []
    if observation.revision < _MODERN_ERRORS:
        return []
    argument = raw.get("argument")
    name = argument if isinstance(argument, str) else "argument"
    summary = f"{label} returned a validation failure as a protocol error"
    return [(summary, {"argument": name, "tool": label})]


def _unactionable_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    raw = payload.get("invalid")
    if not isinstance(raw, dict) or raw.get("protocol") is True or raw.get("is_error") is not True:
        return []
    text = raw.get("text")
    argument = raw.get("argument")
    if not isinstance(text, str) or not isinstance(argument, str):
        return []
    if text.strip() and argument in text:
        return []
    summary = f"{label} validation error does not name the argument"
    return [(summary, {"argument": argument, "tool": label})]


def _leak_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    raw = payload.get("invalid")
    if not isinstance(raw, dict):
        return []
    text = raw.get("text")
    if not isinstance(text, str) or not leaks_internal(text):
        return []
    return [(f"{label} error includes an internal trace", {"tool": label})]


def _mismatch_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    found: _Rows = []
    for item in _rows(payload.get("mismatches")):
        quote = item.get("quote")
        path = item.get("path")
        if not isinstance(quote, str) or not isinstance(path, str):
            continue
        data: dict[str, JsonValue] = {"path": path, "quote": quote, "tool": label}
        found.append((f"{label} description says `{quote}`", data))
    return found


def _contract_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    found: _Rows = []
    for item in _rows(payload.get("contracts")):
        if item.get("broken") is not True:
            continue
        quote = item.get("quote")
        if not isinstance(quote, str):
            continue
        summary = f"{label} description contract {quote} failed"
        found.append((summary, {"quote": quote, "tool": label}))
    return found


def _example_hits(label: str, payload: Mapping[str, JsonValue]) -> _Rows:
    rows = payload.get("examples")
    failed = isinstance(rows, list) and any(
        isinstance(item, dict) and item.get("ok") is False for item in rows
    )
    if not failed:
        return []
    return [(f"{label} example failed", {"tool": label})]


def _findings_for(
    probe: Probe,
    observation: Observation,
    rows: Sequence[tuple[str, dict[str, JsonValue]]],
) -> list[Finding]:
    found: list[Finding] = []
    for summary, data in rows:
        chosen = _severity(data.get("severity"))
        if chosen is not None:
            data = {key: value for key, value in data.items() if key != "severity"}
        cache = probe.id == "schema.list-cache-hints-invalid"
        found.append(_emit(probe, observation, summary, data, severity=chosen, cache=cache))
    return found


def _severity(value: JsonValue | None) -> Severity | None:
    if value == "info":
        return "info"
    if value == "low":
        return "low"
    if value == "medium":
        return "medium"
    if value == "high":
        return "high"
    return None


def _emit(
    probe: Probe,
    observation: Observation,
    summary: str,
    data: dict[str, JsonValue] | None = None,
    *,
    severity: Severity | None = None,
    cache: bool = False,
) -> Finding:
    return Finding(
        item_id=probe.id,
        severity=probe.default_severity if severity is None else severity,
        summary=summary,
        evidence=observation.frames[-1] if observation.frames else None,
        frames=observation.frames,
        spec_refs=_refs(observation.revision, cache=cache),
        data=data,
    )


def _refs(revision: str, *, cache: bool) -> tuple[str, ...]:
    refs = [f"https://modelcontextprotocol.io/specification/{revision}/server/tools"]
    if cache and revision == MODERN_VERSION:
        refs.append(
            f"https://modelcontextprotocol.io/specification/{revision}/server/utilities/caching"
        )
    return tuple(refs)


def _focus(observation: Observation, probe_id: str) -> Observation:
    payload = _payload(observation)
    groups = payload.get("groups")
    indexes: list[int] = []
    if isinstance(groups, dict):
        raw = groups.get(probe_id)
        if isinstance(raw, list):
            indexes = [item for item in raw if isinstance(item, int) and not isinstance(item, bool)]
    chosen = [index for index in indexes if 0 <= index < len(observation.calls)]
    calls = tuple(observation.calls[index] for index in chosen)
    frames = tuple(call.inbound for call in calls if call.inbound is not None)
    return Observation(
        observation.revision,
        observation.tool,
        frames,
        calls=calls,
        payload=payload,
    )


def _payload(observation: Observation) -> dict[str, JsonValue]:
    if observation.payload is None:
        return {}
    return observation.payload


def _accepted(call: Call) -> bool:
    if call.error_code is not None:
        return False
    result = call.result
    if not isinstance(result, dict):
        return False
    return result.get("isError") is not True


def _call_text(call: Call) -> str:
    parts = [result_text(call.result)]
    frame = call.inbound
    parsed = None if frame is None else frame.parsed
    if isinstance(parsed, dict):
        error = parsed.get("error")
        message = error.get("message") if isinstance(error, dict) else None
        if isinstance(message, str):
            parts.append(message)
    return "\n".join(part for part in parts if part)


def _invalid_row(call: Call, argument: str) -> dict[str, JsonValue]:
    result = call.result
    return {
        "argument": argument,
        "is_error": isinstance(result, dict) and result.get("isError") is True,
        "protocol": call.error_code is not None,
        "text": _call_text(call),
    }


def _hit_row(item: LintHit) -> dict[str, JsonValue]:
    return {"data": item.data, "rule": item.rule, "summary": item.summary}


def _mismatch_row(quote: str, path: str) -> dict[str, JsonValue]:
    return {"path": path, "quote": quote}


def _drift_row(item: Drift) -> dict[str, JsonValue]:
    return {"diff": item.diff, "kind": item.kind, "name": item.name}


def _tool_rows(result: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    raw = result.get("tools")
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, JsonValue]] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            rows.append(item)
    return rows


def _sample_lists(value: JsonValue | None) -> list[list[dict[str, JsonValue]]]:
    if not isinstance(value, list):
        return []
    return [_sample_rows(item) for item in value]


def _sample_rows(value: JsonValue | None) -> list[dict[str, JsonValue]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _rows(value: JsonValue | None) -> list[dict[str, JsonValue]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: JsonValue | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _register_lint() -> None:
    catalog: tuple[tuple[str, Severity], ...] = (
        ("schema.lint.invalid-schema", "high"),
        ("schema.lint.root-not-object", "medium"),
        ("schema.lint.required-not-declared", "high"),
        ("schema.lint.missing-description", "low"),
        ("schema.lint.name-invalid", "low"),
        ("schema.lint.duplicate-name", "high"),
        ("schema.lint.annotation-contradiction", "medium"),
        ("schema.lint.unbounded-string", "info"),
        ("schema.lint.hidden-instructions", "info"),
    )
    for probe_id, severity in catalog:
        _bind(probe_id, severity, _LintProbe)


def _register_lists() -> None:
    catalog: tuple[tuple[str, Severity], ...] = (
        ("schema.tool-list-unstable", "high"),
        ("schema.tool-set-unstable", "high"),
        ("schema.tool-order-unstable", "low"),
        ("schema.pagination-broken", "medium"),
        ("schema.list-cache-hints-invalid", "low"),
        ("schema.list-changed-not-notified", "medium"),
    )
    for probe_id, severity in catalog:
        _bind(probe_id, severity, _ListProbe)


def _register_tools() -> None:
    catalog: tuple[tuple[str, Severity], ...] = (
        ("schema.undeclared-required-arg", "high"),
        ("schema.required-not-enforced", "medium"),
        ("schema.extra-args-silently-accepted", "medium"),
        ("schema.silent-coercion", "high"),
        ("schema.constraint-not-enforced", "medium"),
        ("schema.error-shape.validation-as-protocol-error", "medium"),
        ("schema.error-shape.unactionable", "medium"),
        ("schema.error-shape.internal-leak", "medium"),
        ("schema.output-nonconformant", "high"),
        ("schema.description-param-mismatch", "medium"),
        ("schema.description-contract-broken", "medium"),
        ("schema.example-fails", "medium"),
        ("schema.annotation-readonly-violated", "high"),
    )
    for probe_id, severity in catalog:
        _bind(probe_id, severity, _ToolProbe)


def _bind(probe_id: str, severity: Severity, base: type[_SchemaProbe]) -> None:
    name = "Probe_" + probe_id.replace(".", "_").replace("-", "_")
    bound = type(name, (base,), {"default_severity": severity, "id": probe_id})
    if not issubclass(bound, Probe):
        raise RuntimeError(probe_id)
    register(bound)


_register_lint()
register(_UnknownTool)
_register_lists()
register(_Drift)
_register_tools()
