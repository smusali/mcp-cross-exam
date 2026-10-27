from __future__ import annotations

import json
import traceback
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from random import Random

import anyio

from mcp_cross_exam.evidence import (
    EvidenceLog,
    build_exchanges,
    curl_for_frames,
    redact_text,
    repro_command,
    request_method,
    request_params,
    transcript_for,
)
from mcp_cross_exam.probes.base import (
    ClassifiedTool,
    Probe,
    ProbeContext,
    ToolView,
    classify_tool,
    probe_family,
    target_tool,
    tool_views,
)
from mcp_cross_exam.transport import (
    Finding,
    Frame,
    RawChannel,
    RunContext,
    Skip,
    Transport,
    TransportFailure,
)
from mcp_cross_exam.transport.base import JsonValue, parse_json_bytes

REVISION_SKIP = "not applicable to negotiated revision"
BUDGET_SKIP = "budget exhausted"


class SelectionError(Exception):
    pass


class UnknownTool(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class WriteBlocked(Exception):
    def __init__(self, tool: str) -> None:
        super().__init__(tool)
        self.tool = tool


class BudgetExceeded(Exception):
    pass


@dataclass
class _Halt:
    budget: bool = False


def load_probes() -> tuple[Probe, ...]:
    from mcp_cross_exam.probes.transport import probes as transport_probes

    transport_probes()
    from mcp_cross_exam.probes.schema import probes as schema_probes

    return schema_probes()


def select_probes(
    probes: Sequence[Probe],
    *,
    include: Sequence[str],
    families: Sequence[str],
    skip: Sequence[str],
) -> tuple[Probe, ...]:
    known = {probe.id for probe in probes}
    chosen = list(probes)
    if include:
        matched: list[Probe] = []
        seen: set[str] = set()
        for pattern in include:
            hits = [probe for probe in probes if fnmatchcase(probe.id, pattern)]
            if not hits:
                raise SelectionError(f"unknown probe {pattern}")
            for probe in hits:
                if probe.id not in seen:
                    matched.append(probe)
                    seen.add(probe.id)
        chosen = matched
    if families:
        known_families = {probe_family(probe) for probe in probes}
        for name in families:
            if name not in known_families:
                raise SelectionError(f"unknown family {name}")
        wanted = set(families)
        chosen = [probe for probe in chosen if probe_family(probe) in wanted]
    if skip:
        for probe_id in skip:
            if probe_id not in known:
                raise SelectionError(f"unknown probe {probe_id}")
        skipped = set(skip)
        chosen = [probe for probe in chosen if probe.id not in skipped]
    return tuple(chosen)


def list_payload(probes: Sequence[Probe]) -> list[dict[str, JsonValue]]:
    rows: list[dict[str, JsonValue]] = []
    for probe in probes:
        rows.append(
            {
                "id": probe.id,
                "family": probe_family(probe),
                "default_severity": probe.default_severity,
                "mutates": probe.mutates,
                "revisions": list(probe.revisions),
            }
        )
    return rows


def list_text(probes: Sequence[Probe]) -> str:
    lines = ["id family severity mutates revisions"]
    for probe in probes:
        revisions = ",".join(probe.revisions)
        flag = "true" if probe.mutates else "false"
        family = probe_family(probe)
        lines.append(f"{probe.id} {family} {probe.default_severity} {flag} {revisions}")
    return "\n".join(lines) + "\n"


def plan_lines(ctx: ProbeContext, probes: Sequence[Probe]) -> list[str]:
    lines = [f"tool {item.tool.name} {item.effect} {item.source}" for item in ctx.classifications]
    views = tuple(item.tool for item in ctx.classifications)
    target = target_tool(views)
    for probe in probes:
        if _tool_scoped(probe):
            matched = [item for item in ctx.classifications if probe.applies_to(item.tool)]
            if ctx.only_tool is not None:
                matched = [item for item in matched if item.tool.name == ctx.only_tool]
            if not matched:
                lines.append(f"probe {probe.id} - skip not applicable")
                continue
            for item in matched:
                lines.append(_plan_row(ctx, probe, item.tool, views))
            continue
        lines.append(_plan_row(ctx, probe, target, views))
    return lines


async def examine(ctx: ProbeContext, probes: Sequence[Probe] | None = None) -> list[Finding]:
    selected = tuple(probes) if probes is not None else load_probes()
    ctx.rng = Random(ctx.seed)
    ctx.run.seed = ctx.seed
    ctx.run.guard = ctx.guard
    if ctx.started_at is None:
        ctx.started_at = ctx.clock()
    original = ctx.transport
    ctx.transport = GuardedTransport(original, ctx)
    if ctx.evidence is None:
        directory = ctx.run.logs.path.parent
        ctx.evidence = EvidenceLog(directory / "evidence.jsonl", ctx.secrets)
    try:
        if not ctx.revision:
            return []
        await classify_listed(ctx)
        views = tuple(item.tool for item in ctx.classifications)
        findings: list[Finding] = []
        halt = _Halt()
        server = [probe for probe in selected if not _tool_scoped(probe)]
        scoped = [probe for probe in selected if _tool_scoped(probe)]
        target = target_tool(views)
        for index, probe in enumerate(server):
            findings.extend(await _execute(ctx, probe, target, views, halt))
            if halt.budget:
                _skip_rest(ctx, server[index + 1 :], BUDGET_SKIP)
                _skip_rest(ctx, scoped, BUDGET_SKIP)
                return findings
        if scoped:
            await _scoped(ctx, scoped, views, findings, halt)
        return findings
    finally:
        ctx.transport = original
        if ctx.evidence is not None:
            ctx.run.evidence_dropped = ctx.evidence.dropped


def write_result(
    ctx: ProbeContext,
    findings: Sequence[Finding],
    selected: Sequence[Probe],
) -> None:
    payload: dict[str, JsonValue] = {
        "guard": ctx.run.guard,
        "seed": ctx.seed,
        "run_id": ctx.run.run_id,
        "evidence_dropped": ctx.run.evidence_dropped,
        "selected": [probe.id for probe in selected],
        "findings": [_public(item) for item in findings],
        "skips": [_skip_row(item) for item in ctx.run.skips],
        "tools": [_tool_row(item) for item in ctx.classifications],
    }
    text = redact_text(json.dumps(payload, indent=2, sort_keys=True), ctx.secrets)
    path = ctx.run.logs.path.parent / "result.json"
    path.write_text(text + "\n", encoding="utf-8")


class GuardedTransport:
    def __init__(self, inner: Transport, ctx: ProbeContext) -> None:
        self._inner = inner
        self._ctx = ctx
        self._counts: dict[str, int] = {}
        self._lock = anyio.Lock()
        self.recorder = inner.recorder
        self.raw: RawChannel = _GuardedRaw(inner.raw, self)

    async def connect(self) -> RunContext:
        return await self._inner.connect()

    async def request(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> JsonValue:
        async with self._lock:
            self.prepare(method, params)
            if timeout is None and self._ctx.budget is not None:
                timeout = self._ctx.budget.call_timeout_s
            return await self._inner.request(
                method,
                params,
                meta=meta,
                headers=headers,
                timeout=timeout,
            )

    async def notify(
        self,
        method: str,
        params: Mapping[str, JsonValue] | None = None,
        *,
        meta: Mapping[str, JsonValue] | None = None,
    ) -> None:
        async with self._lock:
            await self._inner.notify(method, params, meta=meta)

    async def close(self) -> None:
        await self._inner.close()

    async def reset(self) -> RunContext:
        async with self._lock:
            context = await self._inner.reset()
            self.recorder = self._inner.recorder
            return context

    async def send_raw(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        method: str = "POST",
    ) -> None:
        async with self._lock:
            self.prepare_body(body)
            await self._inner.raw.send_bytes(body, headers=headers, timeout=timeout, method=method)

    def prepare(self, method: str, params: Mapping[str, JsonValue] | None) -> None:
        if _over_budget(self._ctx):
            raise BudgetExceeded
        if method != "tools/call":
            return
        name = _tool_name(params)
        if name is None:
            return
        if not _writes_allowed(self._ctx) and _effect(self._ctx, name) in {"write", "destructive"}:
            raise WriteBlocked(name)
        budget = self._ctx.budget
        if budget is None:
            return
        used = self._counts.get(name, 0)
        if used >= budget.max_calls_per_tool:
            raise BudgetExceeded
        self._counts[name] = used + 1

    def prepare_body(self, body: bytes) -> None:
        parsed = parse_json_bytes(body)
        if not isinstance(parsed, dict):
            return
        method = request_method(parsed)
        if method is None:
            return
        self.prepare(method, request_params(parsed))


class _GuardedRaw:
    def __init__(self, inner: RawChannel, gate: GuardedTransport) -> None:
        self._inner = inner
        self._gate = gate

    async def send_bytes(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        method: str = "POST",
    ) -> None:
        await self._gate.send_raw(body, headers=headers, timeout=timeout, method=method)

    async def drop(self) -> None:
        await self._inner.drop()

    def stream(self) -> AsyncIterator[bytes]:
        return self._inner.stream()


def _classify(ctx: ProbeContext, tool: ToolView) -> ClassifiedTool:
    return classify_tool(tool, effect=ctx.effects.get(tool.name))


async def classify_listed(ctx: ProbeContext) -> None:
    views = await _listed(ctx)
    if ctx.only_tool is not None:
        views = tuple(tool for tool in views if tool.name == ctx.only_tool)
        if not views:
            raise UnknownTool(ctx.only_tool)
    ctx.classifications = tuple(_classify(ctx, tool) for tool in views)


async def _listed(ctx: ProbeContext) -> tuple[ToolView, ...]:
    try:
        result = await ctx.transport.request("tools/list", {})
    except TransportFailure:
        return _views_from_frames(ctx.transport.recorder.frames)
    return tool_views(result)


def _views_from_frames(frames: Sequence[Frame]) -> tuple[ToolView, ...]:
    for frame in reversed(frames):
        parsed = frame.parsed
        if not isinstance(parsed, dict):
            continue
        result = parsed.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return tool_views(result)
    return ()


async def _scoped(
    ctx: ProbeContext,
    probes: Sequence[Probe],
    views: tuple[ToolView, ...],
    findings: list[Finding],
    halt: _Halt,
) -> None:
    limiter = anyio.CapacityLimiter(max(1, ctx.jobs))
    lock = anyio.Lock()

    async def one(probe: Probe, tool: ToolView) -> None:
        async with limiter, lock:
            if halt.budget:
                _skip(ctx, probe, tool.name, BUDGET_SKIP)
                return
            findings.extend(await _execute(ctx, probe, tool, views, halt))

    async with anyio.create_task_group() as group:
        for probe in probes:
            matched = [item.tool for item in ctx.classifications if probe.applies_to(item.tool)]
            for tool in matched:
                group.start_soon(one, probe, tool)


async def _execute(
    ctx: ProbeContext,
    probe: Probe,
    tool: ToolView | None,
    views: tuple[ToolView, ...],
    halt: _Halt,
) -> list[Finding]:
    label = None if tool is None else tool.name
    if halt.budget or _over_budget(ctx):
        halt.budget = True
        _skip(ctx, probe, label, BUDGET_SKIP)
        return []
    reason = _skip_reason(ctx, probe, tool, views)
    if reason is not None:
        if reason != "quiet":
            _skip(ctx, probe, label, reason)
        return []
    found: list[Finding] = []
    before = tuple(ctx.transport.recorder.frames)
    try:
        await probe.setup(ctx)
        observation = await probe.run(ctx, tool)
        drafts = probe.assert_(observation)
        after = tuple(ctx.transport.recorder.frames)
        found.extend(_finish(ctx, probe, tool, drafts, before, after, observation.frames))
    except BudgetExceeded:
        halt.budget = True
        _store(ctx, probe, before, tuple(ctx.transport.recorder.frames), ())
        _skip(ctx, probe, label, BUDGET_SKIP)
    except WriteBlocked:
        _store(ctx, probe, before, tuple(ctx.transport.recorder.frames), ())
        gate = "read-only" if ctx.read_only else "write gate"
        _skip(ctx, probe, label, gate)
    except Exception as exc:
        _store(ctx, probe, before, tuple(ctx.transport.recorder.frames), ())
        found.append(_error(ctx, probe, tool, exc))
    try:
        await probe.teardown(ctx)
    except Exception as exc:
        found.append(_error(ctx, probe, tool, exc))
    return found


def _finish(
    ctx: ProbeContext,
    probe: Probe,
    tool: ToolView | None,
    drafts: Sequence[Finding],
    before: tuple[Frame, ...],
    after: tuple[Frame, ...],
    extra: tuple[Frame, ...],
) -> list[Finding]:
    stored = _store(ctx, probe, before, after, extra)
    command = _command(ctx, probe, tool)
    transcript = transcript_for(stored)
    curl = _curl(ctx, _fresh(before, after, extra))
    severity = ctx.severities.get(probe.id)
    ids = tuple(item for item in (_exchange_id(record) for record in stored) if item)
    finished: list[Finding] = []
    for finding in drafts:
        updated = finding
        if severity is not None and finding.item_id != "probe.error":
            updated = replace(updated, severity=severity)
        finished.append(
            replace(
                updated,
                repro_command=command,
                repro_transcript=transcript or None,
                repro_curl=curl or None,
                exchange_ids=ids,
            )
        )
    return finished


def _store(
    ctx: ProbeContext,
    probe: Probe,
    before: tuple[Frame, ...],
    after: tuple[Frame, ...],
    extra: tuple[Frame, ...],
) -> list[dict[str, JsonValue]]:
    fresh = _fresh(before, after, extra)
    log = ctx.evidence
    if log is None or not fresh:
        return []
    records = build_exchanges(fresh, ctx.secrets, probe_id=probe.id, start=log.written + 1)
    kept: list[dict[str, JsonValue]] = []
    for record in records:
        if log.add(record) is not None:
            kept.append(record)
    ctx.run.evidence_dropped = log.dropped
    return kept


def _error(ctx: ProbeContext, probe: Probe, tool: ToolView | None, exc: Exception) -> Finding:
    summary = f"{probe.id} failed: {type(exc).__name__}: {exc}"
    return Finding(
        item_id="probe.error",
        severity="medium",
        summary=summary,
        evidence=None,
        detail=traceback.format_exc(),
        repro_command=_command(ctx, probe, tool),
    )


def _command(ctx: ProbeContext, probe: Probe, tool: ToolView | None) -> str:
    return repro_command(
        endpoint=ctx.endpoint,
        probe_id=probe.id,
        tool=None if tool is None else tool.name,
        seed=ctx.seed,
        protocol=ctx.revision or None,
        bearer_env=ctx.bearer_env,
        expired_bearer_env=ctx.expired_bearer_env,
        header_envs=ctx.header_envs,
        legacy=ctx.legacy,
        command=ctx.command,
    )


def _curl(ctx: ProbeContext, frames: Sequence[Frame]) -> str:
    if not ctx.http or ctx.endpoint is None:
        return ""
    return curl_for_frames(
        frames,
        url=ctx.endpoint,
        bearer_env=ctx.bearer_env,
        header_envs=ctx.header_envs,
        secrets=ctx.secrets,
    )


def _skip_reason(
    ctx: ProbeContext,
    probe: Probe,
    tool: ToolView | None,
    views: tuple[ToolView, ...],
) -> str | None:
    if ctx.revision not in probe.revisions:
        return REVISION_SKIP
    if not probe.applies(ctx, views):
        return "quiet"
    effect = None if tool is None else _effect(ctx, tool.name)
    if _gated(probe, effect) and not _writes_allowed(ctx):
        if ctx.read_only:
            return "read-only"
        return "write gate"
    return None


def _plan_row(
    ctx: ProbeContext,
    probe: Probe,
    tool: ToolView | None,
    views: tuple[ToolView, ...],
) -> str:
    name = "-" if tool is None else tool.name
    reason = _skip_reason(ctx, probe, tool, views)
    if reason is None:
        return f"probe {probe.id} {name} call"
    if reason == "quiet":
        return f"probe {probe.id} {name} skip not applicable"
    return f"probe {probe.id} {name} skip {reason}"


def _skip(ctx: ProbeContext, probe: Probe, tool: str | None, reason: str) -> None:
    ctx.run.skips.append(Skip(probe.id, tool, reason))


def _skip_rest(ctx: ProbeContext, probes: Sequence[Probe], reason: str) -> None:
    for probe in probes:
        _skip(ctx, probe, ctx.only_tool, reason)


def _over_budget(ctx: ProbeContext) -> bool:
    budget = ctx.budget
    started = ctx.started_at
    if budget is None or started is None:
        return False
    return ctx.clock() - started >= budget.wall_clock_s


def _writes_allowed(ctx: ProbeContext) -> bool:
    if ctx.read_only:
        return False
    if ctx.guard == "overridden":
        return ctx.allow_writes
    return True


def _gated(probe: Probe, effect: str | None) -> bool:
    if type(probe).mutates:
        return True
    return effect in {"write", "destructive"}


def _effect(ctx: ProbeContext, name: str) -> str:
    for item in ctx.classifications:
        if item.tool.name == name:
            return item.effect
    hinted = ctx.effects.get(name)
    if hinted is not None:
        return hinted
    if ctx.classifications:
        return "read"
    return classify_tool(ToolView(name, None, None, None)).effect


def _tool_scoped(probe: Probe) -> bool:
    return type(probe).applies_to is not Probe.applies_to


def _tool_name(params: Mapping[str, JsonValue] | None) -> str | None:
    if params is None:
        return None
    name = params.get("name")
    if isinstance(name, str):
        return name
    return None


def _fresh(
    before: tuple[Frame, ...],
    after: tuple[Frame, ...],
    extra: tuple[Frame, ...],
) -> tuple[Frame, ...]:
    seen = {id(frame) for frame in before}
    fresh = [frame for frame in after if id(frame) not in seen]
    known = {id(frame) for frame in fresh}
    for frame in extra:
        if id(frame) not in known:
            fresh.append(frame)
    return tuple(fresh)


def _exchange_id(record: Mapping[str, JsonValue]) -> str:
    value = record.get("id")
    if isinstance(value, str):
        return value
    return ""


def _public(finding: Finding) -> dict[str, JsonValue]:
    refs: list[JsonValue] = list(finding.spec_refs)
    ids: list[JsonValue] = list(finding.exchange_ids)
    return {
        "id": finding.item_id,
        "severity": finding.severity,
        "summary": finding.summary,
        "detail": finding.detail,
        "classification": finding.classification,
        "agent_impact": finding.agent_impact,
        "spec_refs": refs,
        "repro_command": finding.repro_command,
        "repro_transcript": finding.repro_transcript,
        "repro_curl": finding.repro_curl,
        "exchange_ids": ids,
        "data": finding.data,
    }


def _skip_row(item: Skip) -> dict[str, JsonValue]:
    return {"probe_id": item.probe_id, "tool": item.tool, "reason": item.reason}


def _tool_row(item: ClassifiedTool) -> dict[str, JsonValue]:
    return {"name": item.tool.name, "effect": item.effect, "source": item.source}
