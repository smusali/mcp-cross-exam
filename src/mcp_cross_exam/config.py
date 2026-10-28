from __future__ import annotations

import tomllib
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic import JsonValue as ConfigValue

from mcp_cross_exam.types import (
    OFFERED_VERSIONS,
    Effect,
    JsonValue,
    Scope,
    Severity,
    TransportKind,
    json_value,
)

SeverityName = Severity
TransportName = TransportKind


class ConfigError(Exception):
    pass


class TargetSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: TransportName | None = None
    url: str | None = None
    command: list[str] | None = None
    protocol_version: str | None = None
    allow: list[str] = Field(default_factory=list)

    @field_validator("protocol_version")
    @classmethod
    def _version(cls, value: str | None) -> str | None:
        if value is not None and value not in OFFERED_VERSIONS:
            raise ValueError("unsupported protocol version")
        return value

    @field_validator("command")
    @classmethod
    def _command(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and any(not item for item in value):
            raise ValueError("command entry is empty")
        return value


class AuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bearer_env: str | None = None
    expired_bearer_env: str | None = None
    header_env: dict[str, str] = Field(default_factory=dict)


class ProbeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    select: list[str] = Field(default_factory=list)
    skip: list[str] = Field(default_factory=list)
    severity: dict[str, SeverityName] = Field(default_factory=dict)
    target_tool: str | None = None


class BudgetSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wall_clock_s: float = 60
    max_calls_per_tool: int = 50
    call_timeout_s: float = 10

    @field_validator("wall_clock_s", "call_timeout_s")
    @classmethod
    def _positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("budget must be positive")
        return value

    @field_validator("max_calls_per_tool")
    @classmethod
    def _calls(cls, value: int) -> int:
        if value < 1:
            raise ValueError("budget must be positive")
        return value


class ToolHint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    effect: Effect | None = None
    args: dict[str, ConfigValue] | None = None
    observer: str | None = None
    scope: Scope | None = None


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: TargetSettings = Field(default_factory=TargetSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    probes: ProbeSettings = Field(default_factory=ProbeSettings)
    budget: BudgetSettings = Field(default_factory=BudgetSettings)
    tools: dict[str, ToolHint] = Field(default_factory=dict)


def load_settings(path: Path | None = None, *, cwd: Path | None = None) -> Settings:
    if path is not None:
        if not path.is_file():
            raise ConfigError(f"config not found: {path}")
        return _settings(_read_toml(path))
    root = cwd if cwd is not None else Path.cwd()
    dedicated = root / "mcp-cross-exam.toml"
    if dedicated.is_file():
        return _settings(_read_toml(dedicated))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        tool = _read_toml(pyproject).get("tool")
        if isinstance(tool, dict):
            section = tool.get("mcp-cross-exam")
            if isinstance(section, dict):
                return _settings(section)
    return Settings()


def dump_settings(settings: Settings) -> dict[str, JsonValue]:
    dumped = json_value(settings.model_dump(mode="json"))
    if not isinstance(dumped, dict):
        raise ConfigError("config dump is not an object")
    return dumped


def init_document(tools: Sequence[tuple[str, str, str]]) -> str:
    lines = [
        "# Starter config. Effect lines are comments so a hint is not saved as a fact.",
        "",
        "[target]",
        "allow = []",
        "",
        "[auth]",
        "",
        "[probes]",
        "",
        "[budget]",
        "wall_clock_s = 60",
        "max_calls_per_tool = 50",
        "call_timeout_s = 10",
        "",
    ]
    for name, effect, source in tools:
        lines.append(f"[tools.{_key(name)}]")
        lines.append(f"# effect = {_quote(effect)} {source}")
        lines.append("")
    return "\n".join(lines)


def _settings(raw: dict[str, object]) -> Settings:
    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise _invalid(exc) from exc


def _invalid(exc: ValidationError) -> ConfigError:
    pieces: list[str] = []
    for item in exc.errors():
        loc = item.get("loc", ())
        path = ".".join(str(part) for part in loc)
        pieces.append(path or "config")
    return ConfigError(f"invalid config: {', '.join(pieces)}")


def _read_toml(path: Path) -> dict[str, object]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid config: {path.name}") from exc
    return _table(loaded)


def _table(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError("invalid config: config")
    mapped: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConfigError("invalid config: config")
        mapped[key] = item
    return mapped


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _key(name: str) -> str:
    if name and all(char.isalnum() or char in {"_", "-"} for char in name):
        return name
    return _quote(name)
