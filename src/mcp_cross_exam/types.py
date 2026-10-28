from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, TypeAlias

JsonValue: TypeAlias = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None
Direction: TypeAlias = Literal["inbound", "outbound"]
Severity: TypeAlias = Literal["info", "low", "medium", "high", "critical"]
Effect: TypeAlias = Literal["read", "write", "destructive"]
TransportKind: TypeAlias = Literal["http", "sse", "stdio"]
Scope: TypeAlias = Literal["user", "tenant", "global"]
Source: TypeAlias = Literal["config", "annotation", "heuristic", "default"]

SUPPORTED_PROTOCOL_REVISIONS: tuple[str, ...] = (
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
MODERN_VERSION = SUPPORTED_PROTOCOL_REVISIONS[0]
HANDSHAKE_LADDER: tuple[str, ...] = SUPPORTED_PROTOCOL_REVISIONS[1:4]
OFFERED_VERSIONS: tuple[str, ...] = (MODERN_VERSION, *HANDSHAKE_LADDER)

_DESTRUCTIVE = ("delete_", "drop_")
_WRITE = ("create_", "update_", "send_", "transfer_", "set_", "post_")
_READ = ("get_", "list_", "search_", "read_")


class SkipReason(StrEnum):
    REVISION = "not applicable to negotiated revision"
    BUDGET = "budget exhausted"
    QUIET = "quiet"
    READ_ONLY = "read-only"
    WRITE_GATE = "write gate"
    NO_TARGET = "no target tool"


class DataError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Frame:
    direction: Direction
    at: float
    rpc_id: str | int | None
    method: str | None
    status: int | None
    headers: dict[str, str]
    body: bytes
    parsed: JsonValue | None


@dataclass(frozen=True, slots=True)
class Hit:
    item_id: str
    severity: Severity
    summary: str
    evidence: Frame | None
    frames: tuple[Frame, ...] = ()
    spec_refs: tuple[str, ...] = ()
    agent_impact: str | None = None
    classification: Effect | None = None
    detail: str | None = None
    repro_command: str | None = None
    repro_transcript: str | None = None
    repro_curl: str | None = None
    exchange_ids: tuple[str, ...] = ()
    data: dict[str, JsonValue] | None = None


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
    effect: Effect
    source: Source


def classify_tool(tool: ToolView, *, effect: Effect | None = None) -> ClassifiedTool:
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


def json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | float):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        mapped: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise DataError("json object key is not a string")
            mapped[key] = json_value(item)
        return mapped
    raise DataError("value is not json")
