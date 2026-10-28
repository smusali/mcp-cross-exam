from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic import JsonValue as ModelJson

from mcp_cross_exam.types import (
    ClassifiedTool,
    JsonValue,
    Scope,
    Severity,
    Source,
    ToolView,
    classify_tool,
)
from mcp_cross_exam.types import (
    Hit as Draft,
)
from mcp_cross_exam.types import (
    TransportKind as TransportKind,
)

EffectName = Literal["read", "write", "destructive", "external"]
Origin = Literal["configured", "declared", "observed", "default"]
SeveritySource = Literal["default", "config"]
CoverageStatus = Literal["complete", "partial"]

SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_WEIGHT: dict[Severity, int] = {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}
_EFFECT: dict[EffectName, int] = {
    "read": 1,
    "write": 2,
    "destructive": 3,
    "external": 4,
}
_SCOPE: dict[Scope, int] = {"user": 1, "tenant": 2, "global": 3}
_ORIGIN: dict[Source, Origin] = {
    "config": "configured",
    "annotation": "declared",
    "heuristic": "observed",
    "default": "default",
}
_DISC = (
    "argument",
    "name",
    "path",
    "pattern",
    "rule",
    "kind",
    "constraint",
    "quote",
    "declared_required",
    "observed_required",
)
_SPACE = re.compile(r"\s+")
_PROBE_ERROR = "the probe stopped before it could finish"

IMPACTS: dict[str, str] = {
    "transport.version-negotiation": "the client and server disagree on the protocol revision",
    "transport.capabilities-honesty": "the client calls a feature the server did not declare",
    "transport.required-headers": "a tool call proceeds without the routing headers",
    "transport.unknown-method": "an unknown method is treated as success",
    "session.token-expired-empty-success": "agent silently degrades",
    "session.expired-not-404": "agent silently degrades",
    "session.expired-empty-success": "agent silently degrades",
    "transport.resume-gap": "the client misses events after a dropped stream",
    "transport.reconnect-fails": "a retry does not see the same tool result",
    "transport.stdout-pollution": "a non protocol line on stdout breaks the framing",
    "transport.deprecated-sse": "the client stays on a transport the spec retired",
    "schema.lint.invalid-schema": "the model cannot form a valid call",
    "schema.lint.root-not-object": "the model cannot form a valid call",
    "schema.lint.required-not-declared": "the model omits a required argument and loops",
    "schema.lint.missing-description": "the model guesses what the tool does",
    "schema.lint.name-invalid": "the model cannot address the tool by name",
    "schema.lint.duplicate-name": "the model cannot tell the tools apart",
    "schema.lint.annotation-contradiction": "the model treats a write as a read",
    "schema.lint.unbounded-string": "the model can send an unbounded string",
    "schema.lint.hidden-instructions": "hidden text can steer the model",
    "schema.tool-list-unstable": "the model caches a tool list that changes",
    "schema.tool-set-unstable": "a tool disappears between connections",
    "schema.tool-order-unstable": "tool order changes and the model picks the wrong one",
    "schema.pagination-broken": "the model stops after the first page",
    "schema.list-cache-hints-invalid": "the client caches a list it should refetch",
    "schema.list-changed-not-notified": "the model keeps a stale tool list",
    "schema.undeclared-required-arg": "the model omits a required argument and loops",
    "schema.required-not-enforced": "the model can skip a required argument",
    "schema.extra-args-silently-accepted": "an extra argument is dropped without an error",
    "schema.silent-coercion": "the model receives a value it did not send",
    "schema.constraint-not-enforced": "a value outside the schema is accepted",
    "schema.error-shape.validation-as-protocol-error": (
        "the model treats a bad argument as a broken protocol"
    ),
    "schema.error-shape.unactionable": "the model cannot tell which argument to fix",
    "schema.error-shape.internal-leak": "an error string exposes server internals",
    "schema.output-nonconformant": "the model reads a result the schema does not describe",
    "schema.description-param-mismatch": "the model sends an argument the schema does not define",
    "schema.description-contract-broken": "the result breaks a limit the description stated",
    "schema.example-fails": "the model copies an example the server rejects",
    "schema.annotation-readonly-violated": "a read tool changes server state",
    "schema.error-shape.unknown-tool": "an unknown tool name is not rejected",
    "schema.definition-drift": "the tool contract changed since the snapshot",
}


class Repro(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    command: str
    transcript: str | None = None


class BlastRadius(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    effect: EffectName
    effect_source: Origin
    scope: Scope
    scope_source: Origin
    agent_impact: str


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    probe_id: str
    family: str
    tool: str | None
    severity: Severity
    severity_source: SeveritySource
    title: str
    detail: str | None
    declared: dict[str, ModelJson] | None
    observed: dict[str, ModelJson] | None
    evidence: list[str]
    repro: Repro
    blast_radius: BlastRadius
    spec_refs: list[str]
    fingerprint: str
    raw_penalty: int
    penalty: int


class ToolVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    version: str
    mcp_version: str


class TargetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    transport: TransportKind
    url: str | None
    command: list[str] | None
    protocol_version: str | None
    guard: str
    bearer_env: str | None
    expired_bearer_env: str | None
    header_env: dict[str, str]


class ServerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    revision: str
    server_info: dict[str, ModelJson] | None
    capabilities: dict[str, ModelJson]
    extensions: list[str]


class BudgetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    wall_clock_s: float
    max_calls_per_tool: int
    call_timeout_s: float


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: str
    seed: int
    started_at: str
    finished_at: str
    budget: BudgetRecord


class SkipRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    probe_id: str
    tool: str | None
    reason: str


class Coverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: CoverageStatus
    probes_run: list[str]
    skipped: list[SkipRecord]


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tool: ToolVersion
    target: TargetRecord
    server: ServerRecord
    run: RunRecord
    coverage: Coverage
    score: int
    findings: list[Finding]


def family_of(probe_id: str) -> str:
    return probe_id.split(".", 1)[0]


def fingerprint_for(probe_id: str, tool: str | None, data: Mapping[str, JsonValue] | None) -> str:
    tool_text = "" if tool is None else _norm(tool)
    payload = f"{probe_id}\n{tool_text}\n{_discriminator(data)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def raw_penalty(severity: Severity, effect: EffectName, scope: Scope) -> int:
    return _WEIGHT[severity] * _EFFECT[effect] * _SCOPE[scope]


def promote(
    draft: Draft,
    *,
    classifications: Sequence[ClassifiedTool],
    scopes: Mapping[str, Scope],
    severities: Mapping[str, Severity],
    command: str,
) -> Finding:
    probe_id = _probe_id(draft)
    tool = _tool_name(draft)
    severity, severity_source = _severity(draft, probe_id, severities)
    radius = blast_radius(tool, classifications, scopes, _impact(draft, probe_id))
    declared, observed = _gaps(probe_id, draft.data)
    return Finding(
        probe_id=probe_id,
        family=family_of(probe_id),
        tool=tool,
        severity=severity,
        severity_source=severity_source,
        title=draft.summary,
        detail=draft.detail,
        declared=declared,
        observed=observed,
        evidence=list(draft.exchange_ids),
        repro=Repro(command=command, transcript=draft.repro_transcript),
        blast_radius=radius,
        spec_refs=list(draft.spec_refs),
        fingerprint=fingerprint_for(probe_id, tool, draft.data),
        raw_penalty=raw_penalty(severity, radius.effect, radius.scope),
        penalty=0,
    )


def blast_radius(
    tool: str | None,
    classifications: Sequence[ClassifiedTool],
    scopes: Mapping[str, Scope],
    agent_impact: str,
) -> BlastRadius:
    effect: EffectName = "read"
    effect_source: Origin = "default"
    if tool is not None:
        matched = next((item for item in classifications if item.tool.name == tool), None)
        if matched is None:
            matched = classify_tool(ToolView(tool, None, None, None))
        effect = matched.effect
        effect_source = _ORIGIN[matched.source]
        if matched.source != "config" and _open_world(matched.tool):
            effect = "external"
            effect_source = "declared"
    scope: Scope = "user"
    scope_source: Origin = "default"
    if tool is not None and tool in scopes:
        scope = scopes[tool]
        scope_source = "configured"
    return BlastRadius(
        effect=effect,
        effect_source=effect_source,
        scope=scope,
        scope_source=scope_source,
        agent_impact=agent_impact,
    )


def apply_penalties(findings: Sequence[Finding], tool_count: int) -> tuple[int, list[Finding]]:
    counted = [0] * len(findings)
    groups: dict[tuple[str, str], list[int]] = {}
    for index, finding in enumerate(findings):
        groups.setdefault((finding.tool or "", finding.family), []).append(index)
    for indexes in groups.values():
        ordered = sorted(
            indexes,
            key=lambda index: (-findings[index].raw_penalty, findings[index].fingerprint, index),
        )
        for place, index in enumerate(ordered):
            counted[index] = findings[index].raw_penalty // (2**place)
    by_tool: dict[str, list[int]] = {}
    for index, finding in enumerate(findings):
        by_tool.setdefault(finding.tool or "", []).append(index)
    divisor = tool_count if tool_count > 0 else 1
    cap = min(100, max(25, 300 // divisor))
    for indexes in by_tool.values():
        total = sum(counted[index] for index in indexes)
        if total <= cap:
            continue
        ordered = sorted(indexes, key=lambda index: (findings[index].fingerprint, index))
        scaled = _largest_remainder([counted[index] for index in ordered], cap)
        for index, value in zip(ordered, scaled, strict=True):
            counted[index] = value
    _shave(counted, findings, 100)
    updated = [
        finding.model_copy(update={"penalty": counted[index]})
        for index, finding in enumerate(findings)
    ]
    ranked = sorted(updated, key=lambda item: (-item.penalty, item.fingerprint))
    score = 100 - sum(item.penalty for item in ranked)
    return score, ranked


def _probe_id(draft: Draft) -> str:
    if draft.item_id != "probe.error":
        return draft.item_id
    data = draft.data
    if data is None:
        return draft.item_id
    value = data.get("probe_id")
    if isinstance(value, str) and value:
        return value
    return draft.item_id


def _tool_name(draft: Draft) -> str | None:
    data = draft.data
    if data is None:
        return None
    value = data.get("tool")
    if isinstance(value, str) and value:
        return value
    return None


def _severity(
    draft: Draft,
    probe_id: str,
    severities: Mapping[str, Severity],
) -> tuple[Severity, SeveritySource]:
    if draft.item_id != "probe.error" and probe_id in severities:
        return severities[probe_id], "config"
    return draft.severity, "default"


def _impact(draft: Draft, probe_id: str) -> str:
    if draft.item_id == "probe.error":
        return _PROBE_ERROR
    if draft.agent_impact:
        return draft.agent_impact
    return IMPACTS.get(probe_id, "the server disagreed with its contract")


def _gaps(
    probe_id: str,
    data: Mapping[str, JsonValue] | None,
) -> tuple[dict[str, ModelJson] | None, dict[str, ModelJson] | None]:
    if not probe_id.startswith("schema."):
        return None, None
    declared: dict[str, ModelJson] = {}
    observed: dict[str, ModelJson] = {}
    if data is not None:
        for key, value in data.items():
            copied = to_model_json(value)
            if key == "declared" or key.startswith("declared_"):
                declared[key] = copied
            elif key == "observed" or key.startswith("observed_"):
                observed[key] = copied
            else:
                observed[key] = copied
    return declared, observed


def _open_world(tool: ToolView) -> bool:
    annotations = tool.annotations
    if annotations is None:
        return False
    return annotations.get("openWorldHint") is True


def _discriminator(data: Mapping[str, JsonValue] | None) -> str:
    if not data:
        return ""
    parts: list[str] = []
    for key in _DISC:
        if key not in data:
            continue
        rendered = _disc_value(data[key])
        if rendered is not None:
            parts.append(f"{key}={rendered}")
    return "\n".join(parts)


def _disc_value(value: JsonValue) -> str | None:
    if isinstance(value, str):
        return _norm(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        texts = [_norm(item) for item in value if isinstance(item, str)]
        if not texts:
            return None
        return ",".join(sorted(texts))
    return None


def to_model_json(value: JsonValue) -> ModelJson:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, list):
        return [to_model_json(item) for item in value]
    if isinstance(value, dict):
        return {key: to_model_json(item) for key, item in value.items()}


def _norm(value: str) -> str:
    return _SPACE.sub(" ", value.strip())


def _largest_remainder(values: list[int], cap: int) -> list[int]:
    total = sum(values)
    if total <= 0 or cap <= 0:
        return [0] * len(values)
    floors = [value * cap // total for value in values]
    leftover = cap - sum(floors)
    fractions = sorted(
        range(len(values)),
        key=lambda index: (-(values[index] * cap % total), index),
    )
    for index in fractions:
        if leftover <= 0:
            break
        if values[index] == 0:
            continue
        floors[index] += 1
        leftover -= 1
    return floors


def _shave(counted: list[int], findings: Sequence[Finding], limit: int) -> None:
    while sum(counted) > limit:
        positive = [index for index, value in enumerate(counted) if value > 0]
        if not positive:
            return
        chosen = min(positive, key=lambda index: (counted[index], findings[index].fingerprint))
        counted[chosen] -= 1
