from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar

from mcp_cross_exam.transport import (
    Classification,
    Finding,
    Frame,
    RunContext,
    ServerState,
    Transport,
    TransportFailure,
)
from mcp_cross_exam.transport.base import JsonValue, Severity


@dataclass(frozen=True, slots=True)
class ToolView:
    name: str
    output_schema: dict[str, JsonValue] | None
    read_only: bool | None
    destructive: bool | None


@dataclass(frozen=True, slots=True)
class Call:
    status: int | None
    headers: dict[str, str]
    result: JsonValue | None
    error_code: int | None
    inbound: Frame | None
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class Observation:
    revision: str
    tool: ToolView | None
    frames: tuple[Frame, ...]
    calls: tuple[Call, ...] = ()
    capabilities: dict[str, JsonValue] | None = None
    saw_header_check: bool = False
    seen_ids: tuple[str, ...] = ()
    resumed_ids: tuple[str, ...] = ()


@dataclass(slots=True)
class ProbeContext:
    transport: Transport
    run: RunContext
    http: bool
    endpoint: str | None
    expired_bearer: str | None
    legacy: bool
    cache: dict[str, Observation] = field(default_factory=dict)

    @property
    def server(self) -> ServerState | None:
        return self.run.server

    @property
    def revision(self) -> str:
        if self.run.server is None:
            return ""
        return self.run.server.revision


class Probe(ABC):
    id: ClassVar[str]
    default_severity: ClassVar[Severity]
    revisions: ClassVar[tuple[str, ...]]

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del ctx, tools
        return True

    @abstractmethod
    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation: ...

    @abstractmethod
    def assert_(self, observation: Observation) -> list[Finding]: ...

    async def teardown(self, ctx: ProbeContext) -> None:
        del ctx


def tool_class(tool: ToolView) -> Classification:
    if tool.destructive is True:
        return "destructive"
    if tool.read_only is False:
        return "write"
    return "read"


def is_empty_success(result: JsonValue, tool: ToolView) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("isError") is True:
        return False
    if tool.output_schema is not None and "structuredContent" not in result:
        return True
    if "structuredContent" in result:
        return False
    return _blank(result.get("content"))


def _blank(content: JsonValue | None) -> bool:
    if not isinstance(content, list):
        return False
    if not content:
        return True
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            return False
        text = block.get("text")
        if not isinstance(text, str) or text.strip():
            return False
    return True


def _views(result: JsonValue) -> tuple[ToolView, ...]:
    if not isinstance(result, dict):
        return ()
    raw = result.get("tools")
    if not isinstance(raw, list):
        return ()
    tools: list[ToolView] = []
    for item in raw:
        view = _view(item)
        if view is not None:
            tools.append(view)
    return tuple(tools)


def _view(item: JsonValue) -> ToolView | None:
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    if not isinstance(name, str):
        return None
    schema = item.get("outputSchema")
    output = schema if isinstance(schema, dict) else None
    read_only: bool | None = None
    destructive: bool | None = None
    annotations = item.get("annotations")
    if isinstance(annotations, dict):
        flag = annotations.get("readOnlyHint")
        if isinstance(flag, bool):
            read_only = flag
        flag = annotations.get("destructiveHint")
        if isinstance(flag, bool):
            destructive = flag
    return ToolView(name, output, read_only, destructive)


def _target(tools: tuple[ToolView, ...]) -> ToolView | None:
    for tool in tools:
        if tool.name == "get_ticket":
            return tool
    return None


async def examine(ctx: ProbeContext, probes: Sequence[Probe] | None = None) -> list[Finding]:
    selected = tuple(probes) if probes is not None else _load()
    findings: list[Finding] = []
    if not ctx.revision:
        return findings
    tools = await _listed(ctx)
    tool = _target(tools)
    for probe in selected:
        if ctx.revision not in probe.revisions or not probe.applies(ctx, tools):
            continue
        try:
            try:
                observation = await probe.run(ctx, tool)
                findings.extend(probe.assert_(observation))
            finally:
                await probe.teardown(ctx)
        except Exception as exc:
            findings.append(
                Finding(
                    item_id="probe.error",
                    severity="medium",
                    summary=f"{probe.id} failed: {type(exc).__name__}: {exc}",
                    evidence=None,
                )
            )
    return findings


def _load() -> tuple[Probe, ...]:
    from mcp_cross_exam.probes.transport import PROBES

    return PROBES


async def _listed(ctx: ProbeContext) -> tuple[ToolView, ...]:
    try:
        result = await ctx.transport.request("tools/list", {})
    except TransportFailure:
        return ()
    return _views(result)
