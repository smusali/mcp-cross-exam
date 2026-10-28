from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from random import Random
from typing import TYPE_CHECKING, ClassVar, Literal

from mcp_cross_exam.config import Scope
from mcp_cross_exam.transport import (
    Classification,
    Finding,
    Frame,
    RunContext,
    ServerState,
    Transport,
)
from mcp_cross_exam.transport.base import Direction, JsonValue, ProtocolError, Severity

if TYPE_CHECKING:
    from mcp_cross_exam.evidence import EvidenceLog

Source = Literal["config", "annotation", "heuristic", "default"]
_DESTRUCTIVE = ("delete_", "drop_")
_WRITE = ("create_", "update_", "send_", "transfer_", "set_", "post_")
_READ = ("get_", "list_", "search_", "read_")
_REGISTRY: dict[str, type[Probe]] = {}


@dataclass(frozen=True, slots=True)
class RunBudget:
    wall_clock_s: float = 60
    max_calls_per_tool: int = 50
    call_timeout_s: float = 10


@dataclass(frozen=True, slots=True)
class ToolView:
    name: str
    output_schema: dict[str, JsonValue] | None
    read_only: bool | None
    destructive: bool | None
    description: str = ""
    input_schema: dict[str, JsonValue] | None = None
    annotations: dict[str, JsonValue] | None = None
    definition: dict[str, JsonValue] | None = None


@dataclass(frozen=True, slots=True)
class ClassifiedTool:
    tool: ToolView
    effect: Classification
    source: Source


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
    payload: dict[str, JsonValue] | None = None


@dataclass(slots=True)
class ProbeContext:
    transport: Transport
    run: RunContext
    http: bool
    endpoint: str | None
    expired_bearer: str | None
    legacy: bool
    cache: dict[str, Observation] = field(default_factory=dict)
    rng: Random = field(default_factory=Random)
    budget: RunBudget | None = None
    classifications: tuple[ClassifiedTool, ...] = ()
    effects: dict[str, Classification] = field(default_factory=dict)
    severities: dict[str, Severity] = field(default_factory=dict)
    guard: str = "local"
    seed: int = 0
    read_only: bool = False
    allow_writes: bool = False
    jobs: int = 4
    secrets: tuple[str, ...] = ()
    bearer_env: str | None = None
    expired_bearer_env: str | None = None
    header_envs: dict[str, str] = field(default_factory=dict)
    command: tuple[str, ...] | None = None
    only_tool: str | None = None
    started_at: float | None = None
    clock: Callable[[], float] = time.monotonic
    evidence: EvidenceLog | None = None
    arguments: dict[str, dict[str, JsonValue]] = field(default_factory=dict)
    observers: dict[str, str] = field(default_factory=dict)
    snapshot: str | None = None
    scopes: dict[str, Scope] = field(default_factory=dict)
    ran: list[str] = field(default_factory=list)

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
    family: ClassVar[str] = ""
    title: ClassVar[str] = ""
    mutates: ClassVar[bool] = False

    def applies(self, ctx: ProbeContext, tools: tuple[ToolView, ...]) -> bool:
        del ctx, tools
        return True

    def applies_to(self, tool: ToolView) -> bool:
        del tool
        return False

    async def setup(self, ctx: ProbeContext) -> None:
        del ctx

    @abstractmethod
    async def run(self, ctx: ProbeContext, tool: ToolView | None) -> Observation: ...

    @abstractmethod
    def assert_(self, observation: Observation) -> list[Finding]: ...

    async def teardown(self, ctx: ProbeContext) -> None:
        del ctx


def register(cls: type[Probe]) -> type[Probe]:
    probe_id = cls.id
    if not isinstance(probe_id, str) or not probe_id:
        raise RuntimeError("probe id is missing")
    previous = _REGISTRY.get(probe_id)
    if previous is not None and previous is not cls:
        raise RuntimeError(f"duplicate probe id {probe_id}")
    _REGISTRY[probe_id] = cls
    return cls


def registered_instances() -> tuple[Probe, ...]:
    return tuple(cls() for cls in _REGISTRY.values())


def probe_family(probe: Probe) -> str:
    declared = type(probe).family
    if declared:
        return declared
    return probe.id.split(".", 1)[0]


def classify_tool(tool: ToolView, *, effect: Classification | None = None) -> ClassifiedTool:
    if effect is not None:
        return ClassifiedTool(tool, effect, "config")
    if tool.read_only is True:
        return ClassifiedTool(tool, "read", "annotation")
    if tool.destructive is True:
        return ClassifiedTool(tool, "destructive", "annotation")
    if tool.destructive is False:
        return ClassifiedTool(tool, "write", "annotation")
    for prefix in _DESTRUCTIVE:
        if tool.name.startswith(prefix):
            return ClassifiedTool(tool, "destructive", "heuristic")
    for prefix in _WRITE:
        if tool.name.startswith(prefix):
            return ClassifiedTool(tool, "write", "heuristic")
    for prefix in _READ:
        if tool.name.startswith(prefix):
            return ClassifiedTool(tool, "read", "heuristic")
    return ClassifiedTool(tool, "write", "default")


def tool_class(tool: ToolView, *, effect: Classification | None = None) -> Classification:
    return classify_tool(tool, effect=effect).effect


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


def tool_views(result: JsonValue) -> tuple[ToolView, ...]:
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


def target_tool(tools: Sequence[ToolView]) -> ToolView | None:
    for tool in tools:
        if tool.name == "get_ticket":
            return tool
    return None


def observation_from_json(payload: JsonValue) -> Observation:
    if not isinstance(payload, dict):
        raise ProtocolError("observation is not an object")
    revision = payload.get("revision")
    if not isinstance(revision, str):
        raise ProtocolError("observation revision is missing")
    return Observation(
        revision,
        _view(payload.get("tool")),
        _frames(payload.get("frames")),
        calls=_calls(payload.get("calls")),
        capabilities=_object(payload.get("capabilities")),
        saw_header_check=payload.get("saw_header_check") is True,
        seen_ids=_strings(payload.get("seen_ids")),
        resumed_ids=_strings(payload.get("resumed_ids")),
        payload=_object(payload.get("payload")),
    )


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


def _view(item: JsonValue | None) -> ToolView | None:
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    if not isinstance(name, str):
        return None
    schema = item.get("output_schema")
    if schema is None:
        schema = item.get("outputSchema")
    output = _object(schema)
    read_only = item.get("read_only")
    destructive = item.get("destructive")
    annotations = _object(item.get("annotations"))
    if "read_only" not in item and "destructive" not in item and annotations is not None:
        read_only = _flag(annotations.get("readOnlyHint"))
        destructive = _flag(annotations.get("destructiveHint"))
    description = item.get("description")
    text = description if isinstance(description, str) else ""
    incoming = item.get("input_schema")
    if incoming is None:
        incoming = item.get("inputSchema")
    definition = item if "inputSchema" in item or "definition" not in item else None
    if definition is None:
        definition = _object(item.get("definition"))
    return ToolView(
        name,
        output,
        _flag(read_only),
        _flag(destructive),
        text,
        _object(incoming),
        annotations,
        definition,
    )


def _frames(value: JsonValue | None) -> tuple[Frame, ...]:
    if not isinstance(value, list):
        return ()
    frames: list[Frame] = []
    for item in value:
        frame = _frame(item)
        if frame is not None:
            frames.append(frame)
    return tuple(frames)


def _frame(item: JsonValue | None) -> Frame | None:
    if not isinstance(item, dict):
        return None
    direction = _direction(item.get("direction"))
    if direction is None:
        return None
    body = _text(item.get("body"))
    return Frame(
        direction=direction,
        at=_number(item.get("at")),
        rpc_id=_rpc_id(item.get("rpc_id")),
        method=_text(item.get("method")),
        status=_whole(item.get("status")),
        headers=_string_map(item.get("headers")),
        body=b"" if body is None else body.encode(),
        parsed=item.get("parsed"),
    )


def _calls(value: JsonValue | None) -> tuple[Call, ...]:
    if not isinstance(value, list):
        return ()
    calls: list[Call] = []
    for item in value:
        call = _call(item)
        if call is not None:
            calls.append(call)
    return tuple(calls)


def _call(item: JsonValue) -> Call | None:
    if not isinstance(item, dict):
        return None
    return Call(
        _whole(item.get("status")),
        _string_map(item.get("headers")),
        item.get("result"),
        _whole(item.get("error_code")),
        _frame(item.get("inbound")),
        item.get("timed_out") is True,
    )


def _object(value: JsonValue | None) -> dict[str, JsonValue] | None:
    if isinstance(value, dict):
        return value
    return None


def _strings(value: JsonValue | None) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _string_map(value: JsonValue | None) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    mapped: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(item, str):
            mapped[key] = item
    return mapped


def _direction(value: JsonValue | None) -> Direction | None:
    if value == "inbound":
        return "inbound"
    if value == "outbound":
        return "outbound"
    return None


def _text(value: JsonValue | None) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _flag(value: JsonValue | None) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _whole(value: JsonValue | None) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _number(value: JsonValue | None) -> float:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return 0.0


def _rpc_id(value: JsonValue | None) -> str | int | None:
    if isinstance(value, str):
        return value
    return _whole(value)
