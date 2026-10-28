from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Literal

import rfc8785
from jsonschema.exceptions import SchemaError
from jsonschema.protocols import Validator
from jsonschema.validators import (
    Draft4Validator,
    Draft6Validator,
    Draft7Validator,
    Draft201909Validator,
    Draft202012Validator,
    validator_for,
)
from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic import JsonValue as ModelJson

from mcp_cross_exam.types import JsonValue

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_TICK = re.compile(r"`([^`]+)`")
_SNAKE = re.compile(r"\b[A-Za-z]+(?:_[A-Za-z0-9]+)+\b")
_CAMEL = re.compile(r"\b[a-z]+[A-Z][A-Za-z0-9]*\b")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_LIMIT = re.compile(r"at most (\d+)", re.IGNORECASE)
_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_JSON_TICK = re.compile(r"`(\{.*?\})`")
_REQUIRED_NAME = re.compile(r"'([^']+)'")
_FILE_FRAME = re.compile(r'File "[^"]+", line \d+')
_JS_FRAME = re.compile(r"\bat [\w$.<>]+\s*\(")
_SQL = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.+\b(?:FROM|INTO|TABLE|WHERE)\b",
    re.IGNORECASE,
)
_DIALECTS = {
    str(Draft202012Validator.META_SCHEMA["$id"]),
    str(Draft201909Validator.META_SCHEMA["$id"]),
    str(Draft7Validator.META_SCHEMA["$id"]),
    str(Draft6Validator.META_SCHEMA["$id"]),
    str(Draft4Validator.META_SCHEMA["id"]),
}
_FORMATS = {
    "date-time": "not-a-date",
    "email": "not-an-email",
    "uri": "not a uri",
}
_ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060})


class _Missing:
    pass


_MISSING = _Missing()


@dataclass(frozen=True, slots=True)
class TextPattern:
    name: str
    expression: str
    false_positives: str


@dataclass(frozen=True, slots=True)
class LintHit:
    rule: str
    summary: str
    data: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class Mutation:
    name: str
    value: JsonValue
    kind: Literal["type", "constraint"]
    canonical: JsonValue
    opposite: JsonValue | None


@dataclass(frozen=True, slots=True)
class ParamMismatch:
    quote: str
    path: str


@dataclass(frozen=True, slots=True)
class ContractClaim:
    kind: Literal["date", "limit"]
    quote: str
    limit: int | None


@dataclass(frozen=True, slots=True)
class Drift:
    name: str
    kind: Literal["added", "removed", "changed"]
    diff: str


HIDDEN_PATTERNS: tuple[TextPattern, ...] = (
    TextPattern(
        "hidden-unicode",
        "",
        "Emoji are ignored. Tag characters, zero-width characters, and bidi overrides are flagged.",
    ),
    TextPattern(
        "ignore-previous",
        r"(?i)ignore previous",
        "Ordinary prose rarely tells a model to ignore previous instructions.",
    ),
    TextPattern(
        "important-tag",
        r"(?i)<\s*important\s*>",
        "Angle-bracket markers are unusual in a tool description.",
    ),
    TextPattern(
        "call-tool",
        r"(?i)\bcall (?:the |another )?(?:tool|tools)\b",
        "A tool that must call another tool can describe that in plain text.",
    ),
    TextPattern(
        "read-file",
        r"(?i)\bread (?:the |a )?file\b",
        "A file-reading tool can describe that behavior in plain text.",
    ),
)
PARAM_PATTERN = TextPattern(
    "parameter",
    r"`[A-Za-z_][A-Za-z0-9_.-]*`|[A-Za-z]+(?:_[A-Za-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]*",
    "Ordinary words are ignored. customer_id and customerId match after normalization.",
)
CONTRACT_PATTERNS: tuple[TextPattern, ...] = (
    TextPattern(
        "date",
        "YYYY-MM-DD",
        "A description can mention this pattern while documenting a different format.",
    ),
    TextPattern(
        "limit",
        r"(?i)at most (\d+)",
        "The number is compared with the longest list in the tool result.",
    ),
)


def lint_hits(tools: Sequence[Mapping[str, JsonValue]]) -> tuple[LintHit, ...]:
    hits: list[LintHit] = []
    counts: dict[str, int] = {}
    for tool in tools:
        name = tool.get("name")
        if isinstance(name, str):
            counts[name] = counts.get(name, 0) + 1
    for name, count in counts.items():
        if count > 1:
            hits.append(
                LintHit(
                    "schema.lint.duplicate-name",
                    f"{name} is declared more than once",
                    {"tool": name, "count": count},
                )
            )
    for tool in tools:
        _lint_tool(tool, hits)
    return tuple(hits)


def schema_issue(schema: JsonValue) -> str | None:
    if not isinstance(schema, dict):
        return "schema is not an object"
    dialect = schema.get("$schema")
    if isinstance(dialect, str) and dialect not in _DIALECTS:
        return "schema dialect is not supported"
    if "$schema" in schema:
        try:
            validator = validator_for(schema)
        except SchemaError as exc:
            return exc.message
    else:
        validator = Draft202012Validator
    try:
        validator.check_schema(schema)
    except SchemaError as exc:
        return exc.message
    return None


def instance_valid(schema: Mapping[str, JsonValue], instance: JsonValue) -> bool:
    if schema_issue(dict(schema)) is not None:
        return False
    validator = _validator(schema)
    try:
        return bool(validator.is_valid(instance))
    except SchemaError:
        return False


def offending_argument(schema: Mapping[str, JsonValue], instance: JsonValue) -> str | None:
    if instance_valid(schema, instance):
        return None
    validator = _validator(schema)
    try:
        error = next(validator.iter_errors(instance))
    except (SchemaError, StopIteration):
        return "arguments"
    if error.path:
        first = error.path[0]
        if isinstance(first, str):
            return first
    match = _REQUIRED_NAME.search(error.message)
    if match is not None:
        return match.group(1)
    return "arguments"


def generated_value(schema: Mapping[str, JsonValue], rng: Random) -> JsonValue | None:
    value = _generate(schema, rng)
    if isinstance(value, _Missing):
        return None
    return value


def minimal_arguments(
    schema: Mapping[str, JsonValue],
    rng: Random,
    hints: Mapping[str, JsonValue] | None,
) -> dict[str, JsonValue] | None:
    if schema.get("type") != "object":
        return None
    required = _strings(schema.get("required"))
    properties = _properties(schema)
    built: dict[str, JsonValue] = {}
    for name in required:
        if hints is not None and name in hints:
            built[name] = hints[name]
            continue
        prop = properties.get(name)
        if prop is None:
            return None
        value = _generate(prop, rng)
        if isinstance(value, _Missing):
            return None
        built[name] = value
    if not instance_valid(schema, built):
        return None
    return {key: built[key] for key in sorted(built)}


def extra_arguments(
    schema: Mapping[str, JsonValue],
    base: Mapping[str, JsonValue],
    seed: int,
) -> dict[str, JsonValue] | None:
    if schema.get("additionalProperties") is not False:
        return None
    candidate = dict(base)
    candidate[f"crossexam_extra_{seed}"] = "x"
    if instance_valid(schema, candidate):
        return None
    return candidate


def without_required(
    schema: Mapping[str, JsonValue],
    base: Mapping[str, JsonValue],
) -> tuple[tuple[str, dict[str, JsonValue]], ...]:
    rows: list[tuple[str, dict[str, JsonValue]]] = []
    for name in _strings(schema.get("required")):
        if name not in base:
            continue
        copied = dict(base)
        del copied[name]
        rows.append((name, copied))
    return tuple(rows)


def mutations(schema: Mapping[str, JsonValue]) -> tuple[Mutation, ...]:
    found: list[Mutation] = []
    seen: set[str] = set()
    for name in sorted(_properties(schema)):
        prop = _properties(schema)[name]
        for item in _property_mutations(name, prop):
            key = name + "\0" + json.dumps(item.value, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return tuple(found)


def undeclared_name(text: str, schema: Mapping[str, JsonValue]) -> str | None:
    required = set(_strings(schema.get("required")))
    for name in sorted(_properties(schema)):
        if name in required:
            continue
        if re.search(rf"\b{re.escape(name)}\b", text):
            return name
    return None


def param_mismatches(
    description: str,
    schema: Mapping[str, JsonValue],
) -> tuple[ParamMismatch, ...]:
    known = {_normalize(name) for name in _property_names(schema)}
    found: list[ParamMismatch] = []
    seen: set[str] = set()
    for quote in _identifiers(description):
        if quote in seen or not _IDENT.fullmatch(quote):
            continue
        seen.add(quote)
        if _normalize(quote) in known:
            continue
        found.append(ParamMismatch(quote, "inputSchema.properties"))
    return tuple(found)


def contract_claims(description: str) -> tuple[ContractClaim, ...]:
    claims: list[ContractClaim] = []
    if "YYYY-MM-DD" in description:
        claims.append(ContractClaim("date", "YYYY-MM-DD", None))
    for match in _LIMIT.finditer(description):
        claims.append(ContractClaim("limit", match.group(0), int(match.group(1))))
    return tuple(claims)


def argument_examples(
    description: str,
    schema: Mapping[str, JsonValue],
) -> tuple[dict[str, JsonValue], ...]:
    found: list[dict[str, JsonValue]] = []
    for pattern in (_FENCE, _JSON_TICK):
        for match in pattern.finditer(description):
            parsed = _json_object(match.group(1))
            if parsed is not None:
                found.append(parsed)
    examples = schema.get("examples")
    if isinstance(examples, list):
        for item in examples:
            if isinstance(item, dict):
                found.append(item)
    return tuple(found)


def string_property(schema: Mapping[str, JsonValue]) -> str | None:
    chosen: str | None = None
    for name, prop in _properties(schema).items():
        if prop.get("type") != "string":
            continue
        if prop.get("format") == "date-time":
            return name
        if chosen is None:
            chosen = name
    return chosen


def wrong_value(schema: Mapping[str, JsonValue]) -> JsonValue:
    if schema.get("type") == "string":
        return 1
    return "nope"


def result_size(result: JsonValue) -> int:
    if not isinstance(result, dict):
        return 0
    return _longest(result.get("structuredContent"))


def result_text(result: JsonValue | None) -> str:
    if not isinstance(result, dict):
        return ""
    parts: list[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
    message = result.get("message")
    if isinstance(message, str):
        parts.append(message)
    return "\n".join(parts)


def leaks_internal(text: str) -> bool:
    if "Traceback (most recent call last)" in text:
        return True
    return bool(_FILE_FRAME.search(text) or _JS_FRAME.search(text) or _SQL.search(text))


def cache_hints_invalid(result: Mapping[str, JsonValue]) -> bool:
    ttl = result.get("ttlMs")
    if isinstance(ttl, bool) or not isinstance(ttl, int | float) or ttl < 0:
        return True
    return result.get("cacheScope") not in {"public", "private"}


def compare_tool_lists(
    samples: Sequence[Sequence[Mapping[str, JsonValue]]],
) -> dict[str, JsonValue]:
    groups = [list(sample) for sample in samples]
    sets = [
        {str(tool.get("name")) for tool in sample if isinstance(tool.get("name"), str)}
        for sample in groups
    ]
    absent: list[JsonValue] = []
    if sets:
        shared = set.intersection(*sets) if sets else set()
        union = set.union(*sets) if sets else set()
        for name in sorted(union - shared):
            absent.append(name)
    else:
        shared = set()
    order = False
    if sets and not absent:
        sequences = [tuple(_names(sample)) for sample in groups]
        order = len(set(sequences)) > 1
    unstable: list[JsonValue] = []
    for name in sorted(shared):
        present = [item for item in (_named(sample, name) for sample in groups) if item is not None]
        if len(present) < 2:
            continue
        first = present[0]
        if all(tool_hash(item) == tool_hash(first) for item in present):
            continue
        other = next(item for item in present if tool_hash(item) != tool_hash(first))
        diff_rows: list[JsonValue] = []
        for row in field_diff(first, other):
            diff_rows.append(row)
        unstable.append({"diff": diff_rows, "name": name})
    return {"absent": absent, "order": order, "unstable": unstable}


def field_diff(
    left: Mapping[str, JsonValue],
    right: Mapping[str, JsonValue],
) -> list[dict[str, JsonValue]]:
    rows: list[dict[str, JsonValue]] = []
    _diff_value(dict(left), dict(right), "", rows)
    return rows


def canonical_bytes(value: JsonValue) -> bytes:
    return rfc8785.dumps(value)


def tool_hash(definition: Mapping[str, JsonValue]) -> str:
    return hashlib.sha256(canonical_bytes(dict(definition))).hexdigest()


class SnapshotTool(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    hash: str
    definition: dict[str, ModelJson]


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hash: str
    tools: list[SnapshotTool]


def snapshot_document(tools: Sequence[Mapping[str, JsonValue]]) -> dict[str, JsonValue]:
    rows: list[dict[str, JsonValue]] = []
    ordered = sorted(tools, key=lambda item: str(item.get("name", "")))
    for tool in ordered:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        definition = dict(tool)
        rows.append({"definition": definition, "hash": tool_hash(definition), "name": name})
    hashes: list[JsonValue] = []
    encoded: list[JsonValue] = []
    for row in rows:
        hashes.append(row["hash"])
        encoded.append(row)
    return {
        "hash": hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
        "tools": encoded,
    }


def snapshot_text(document: Mapping[str, JsonValue]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_snapshot(path: Path, tools: Sequence[Mapping[str, JsonValue]]) -> None:
    path.write_text(snapshot_text(snapshot_document(tools)), encoding="utf-8")


def load_snapshot(path: Path) -> dict[str, JsonValue]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("snapshot is invalid") from exc
    try:
        model = Snapshot.model_validate(loaded)
    except ValidationError as exc:
        raise ValueError("snapshot is invalid") from exc
    dumped = model.model_dump(mode="json")
    mapped: dict[str, JsonValue] = {}
    for key, item in dumped.items():
        mapped[key] = _as_json(item)
    return mapped


def snapshot_drift(
    current: Sequence[Mapping[str, JsonValue]],
    previous: Mapping[str, JsonValue],
) -> tuple[Drift, ...]:
    stored = _stored_tools(previous)
    live = {str(tool["name"]): dict(tool) for tool in current if isinstance(tool.get("name"), str)}
    rows: list[Drift] = []
    for name in sorted(set(stored) | set(live)):
        if name not in stored:
            rows.append(Drift(name, "added", unified_diff({}, live[name], name)))
            continue
        if name not in live:
            rows.append(Drift(name, "removed", unified_diff(stored[name], {}, name)))
            continue
        if tool_hash(live[name]) != tool_hash(stored[name]):
            rows.append(Drift(name, "changed", unified_diff(stored[name], live[name], name)))
    return tuple(rows)


def unified_diff(before: JsonValue, after: JsonValue, name: str) -> str:
    left = json.dumps(before, indent=2, sort_keys=True).splitlines(keepends=True)
    right = json.dumps(after, indent=2, sort_keys=True).splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(left, right, fromfile=f"{name}.before", tofile=f"{name}.after")
    )


def _lint_tool(tool: Mapping[str, JsonValue], hits: list[LintHit]) -> None:
    raw_name = tool.get("name")
    name = raw_name if isinstance(raw_name, str) else ""
    if _NAME.fullmatch(name) is None:
        hits.append(
            LintHit(
                "schema.lint.name-invalid",
                f"{name or 'tool'} breaks the naming guidance",
                {"tool": name},
            )
        )
    description = tool.get("description")
    if not isinstance(description, str) or not description.strip():
        hits.append(
            LintHit(
                "schema.lint.missing-description",
                f"{name or 'tool'} has no description",
                {"tool": name, "path": "description"},
            )
        )
    else:
        _hidden(description, name, "description", hits)
    annotations = tool.get("annotations")
    if (
        isinstance(annotations, dict)
        and annotations.get("readOnlyHint") is True
        and annotations.get("destructiveHint") is True
    ):
        hits.append(
            LintHit(
                "schema.lint.annotation-contradiction",
                f"{name} sets readOnlyHint and destructiveHint",
                {"tool": name},
            )
        )
    incoming = tool.get("inputSchema")
    if not isinstance(incoming, dict):
        hits.append(
            LintHit(
                "schema.lint.invalid-schema",
                f"{name} inputSchema is missing",
                {"tool": name, "path": "inputSchema"},
            )
        )
    else:
        issue = schema_issue(incoming)
        if issue is not None:
            hits.append(
                LintHit(
                    "schema.lint.invalid-schema",
                    f"{name} inputSchema is not a valid schema",
                    {"tool": name, "path": "inputSchema", "observed": issue},
                )
            )
        _lint_input(name, incoming, hits)
    outgoing = tool.get("outputSchema")
    if outgoing is not None:
        issue = schema_issue(outgoing)
        if issue is not None:
            hits.append(
                LintHit(
                    "schema.lint.invalid-schema",
                    f"{name} outputSchema is not a valid schema",
                    {"tool": name, "path": "outputSchema", "observed": issue},
                )
            )


def _lint_input(name: str, schema: Mapping[str, JsonValue], hits: list[LintHit]) -> None:
    if schema.get("type") != "object":
        hits.append(
            LintHit(
                "schema.lint.root-not-object",
                f"{name} inputSchema root type is not object",
                {"tool": name, "path": "inputSchema.type", "observed": schema.get("type")},
            )
        )
    _required_hits(name, schema, "inputSchema", hits)
    for path, prop in _input_properties(schema):
        description = prop.get("description")
        if not isinstance(description, str) or not description.strip():
            hits.append(
                LintHit(
                    "schema.lint.missing-description",
                    f"{name} {path} has no description",
                    {"tool": name, "path": path},
                )
            )
        elif description:
            _hidden(description, name, path, hits)
        declared = prop.get("type")
        stringy = declared == "string" or (isinstance(declared, list) and "string" in declared)
        if stringy and "maxLength" not in prop and "enum" not in prop:
            hits.append(
                LintHit(
                    "schema.lint.unbounded-string",
                    f"{name} {path} has no maxLength",
                    {"tool": name, "path": path},
                )
            )


def _required_hits(
    name: str,
    schema: Mapping[str, JsonValue],
    path: str,
    hits: list[LintHit],
) -> None:
    if isinstance(schema, dict):
        properties = _properties(schema)
        for required in _strings(schema.get("required")):
            if required not in properties:
                hits.append(
                    LintHit(
                        "schema.lint.required-not-declared",
                        f"{name} requires {required}, which is not declared",
                        {"tool": name, "path": path, "observed": required},
                    )
                )
        for key, prop in properties.items():
            _required_hits(name, prop, f"{path}.properties.{key}", hits)
        items = schema.get("items")
        if isinstance(items, dict):
            _required_hits(name, items, f"{path}.items", hits)


def _hidden(text: str, tool: str, path: str, hits: list[LintHit]) -> None:
    if _hidden_unicode(text):
        hits.append(
            LintHit(
                "schema.lint.hidden-instructions",
                f"{tool} {path} contains hidden characters",
                {"tool": tool, "path": path, "pattern": "hidden-unicode"},
            )
        )
    for pattern in HIDDEN_PATTERNS:
        if pattern.expression and re.search(pattern.expression, text):
            hits.append(
                LintHit(
                    "schema.lint.hidden-instructions",
                    f"{tool} {path} matches {pattern.name}",
                    {"tool": tool, "path": path, "pattern": pattern.name},
                )
            )


def _hidden_unicode(text: str) -> bool:
    for char in text:
        code = ord(char)
        if code in _ZERO_WIDTH:
            return True
        if 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            return True
        if 0xE0000 <= code <= 0xE007F:
            return True
    return False


def _input_properties(
    schema: Mapping[str, JsonValue],
) -> tuple[tuple[str, Mapping[str, JsonValue]], ...]:
    found: list[tuple[str, Mapping[str, JsonValue]]] = []

    def visit(node: Mapping[str, JsonValue], path: str) -> None:
        for name, prop in _properties(node).items():
            child = f"{path}.properties.{name}"
            found.append((child, prop))
            visit(prop, child)
        items = node.get("items")
        if isinstance(items, dict):
            visit(items, f"{path}.items")

    visit(schema, "inputSchema")
    return tuple(found)


def _property_mutations(name: str, schema: Mapping[str, JsonValue]) -> tuple[Mutation, ...]:
    declared = _declared(schema)
    canonical, opposite = _pair(schema, declared)
    if isinstance(canonical, _Missing):
        return ()
    rows: list[Mutation] = []
    for value in _candidates(schema, declared):
        if instance_valid(schema, value):
            continue
        kind: Literal["type", "constraint"] = (
            "constraint" if _same_type(declared, value) else "type"
        )
        rows.append(Mutation(name, value, kind, canonical, opposite))
    return tuple(rows)


def _candidates(schema: Mapping[str, JsonValue], declared: str | None) -> tuple[JsonValue, ...]:
    values: list[JsonValue] = []
    if declared == "integer":
        values.extend(["42", 42.5, True, None, 2**63])
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and not isinstance(minimum, bool):
            values.append(minimum - 1)
        if isinstance(maximum, int) and not isinstance(maximum, bool):
            values.append(maximum + 1)
    elif declared == "boolean":
        values.extend(["false", 0, 1, None])
    elif declared == "string":
        enum = schema.get("enum")
        if isinstance(enum, list):
            values.extend(_enum_values(enum))
        formatted = schema.get("format")
        if isinstance(formatted, str) and formatted in _FORMATS:
            values.append(_FORMATS[formatted])
        maximum = schema.get("maxLength")
        if isinstance(maximum, int) and not isinstance(maximum, bool) and 0 <= maximum < 4096:
            values.append("a" * (maximum + 1))
    elif declared == "array":
        values.append(1)
        values.append([])
        maximum = schema.get("maxItems")
        if isinstance(maximum, int) and not isinstance(maximum, bool) and 0 <= maximum < 32:
            values.append(_long_array(schema, maximum + 1))
    return tuple(values)


def _enum_values(enum: Sequence[JsonValue]) -> tuple[JsonValue, ...]:
    values: list[JsonValue] = ["nope", ""]
    for item in enum:
        if isinstance(item, str):
            swapped = item.swapcase()
            if swapped not in enum:
                values.append(swapped)
            break
    return tuple(values)


def _pair(
    schema: Mapping[str, JsonValue],
    declared: str | None,
) -> tuple[JsonValue | _Missing, JsonValue | None]:
    if declared == "boolean":
        if instance_valid(schema, False):
            opposite = True if instance_valid(schema, True) else None
            return False, opposite
        if instance_valid(schema, True):
            return True, None
        return _MISSING, None
    value = _canonical(schema, declared)
    if isinstance(value, _Missing) or not instance_valid(schema, value):
        return _MISSING, None
    return value, None


def _canonical(schema: Mapping[str, JsonValue], declared: str | None) -> JsonValue | _Missing:
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    if declared == "integer":
        return _canonical_integer(schema)
    if declared == "number":
        number = _canonical_integer(schema)
        return number
    if declared == "string":
        return _canonical_string(schema)
    if declared == "array":
        return _canonical_array(schema)
    if declared == "object":
        return {}
    return _MISSING


def _canonical_integer(schema: Mapping[str, JsonValue]) -> int:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if isinstance(minimum, int) and not isinstance(minimum, bool):
        return minimum
    if isinstance(maximum, int) and not isinstance(maximum, bool) and maximum < 0:
        return maximum
    return 0


def _canonical_array(schema: Mapping[str, JsonValue]) -> JsonValue | _Missing:
    minimum = schema.get("minItems")
    size = 0
    if isinstance(minimum, int) and not isinstance(minimum, bool) and minimum > 0:
        size = minimum
    maximum = schema.get("maxItems")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and size > maximum:
        return _MISSING
    if size == 0:
        return []
    return _long_array(schema, size)


def _canonical_string(schema: Mapping[str, JsonValue]) -> str:
    formatted = schema.get("format")
    if formatted == "email":
        return "user@example.com"
    if formatted == "date-time":
        return "2020-01-02T03:04:05Z"
    if formatted == "uri":
        return "https://example.com"
    maximum = schema.get("maxLength")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and maximum < 2:
        return "a"[:maximum]
    return "ok"


def _long_array(schema: Mapping[str, JsonValue], size: int) -> list[JsonValue]:
    items = schema.get("items")
    if isinstance(items, dict):
        filling = _canonical(items, _declared(items))
        if not isinstance(filling, _Missing):
            return [filling for _ in range(size)]
    return [0 for _ in range(size)]


def _generate(schema: Mapping[str, JsonValue], rng: Random) -> JsonValue | _Missing:
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        picked = enum[rng.randrange(len(enum))]
        return picked
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[rng.randrange(len(examples))]
    if "default" in schema:
        return schema["default"]
    declared = _declared(schema)
    if declared == "string":
        return _string(schema, rng)
    if declared == "integer":
        return _integer(schema, rng)
    if declared == "number":
        return _integer(schema, rng)
    if declared == "boolean":
        return rng.choice((False, True))
    if declared == "array":
        return _array(schema, rng)
    if declared == "object":
        built = minimal_arguments(schema, rng, None)
        if built is None:
            return _MISSING
        return built
    if declared == "null":
        return None
    return _MISSING


def _string(schema: Mapping[str, JsonValue], rng: Random) -> str:
    formatted = schema.get("format")
    if formatted == "email":
        return "user@example.com"
    if formatted == "date-time":
        return "2020-01-02T03:04:05Z"
    if formatted == "uri":
        return "https://example.com"
    maximum = schema.get("maxLength")
    minimum = schema.get("minLength")
    length = 4
    if isinstance(minimum, int) and not isinstance(minimum, bool):
        length = max(length, minimum)
    if isinstance(maximum, int) and not isinstance(maximum, bool):
        length = min(length, maximum)
    length = max(length, 1)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _integer(schema: Mapping[str, JsonValue], rng: Random) -> int:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    low = minimum if isinstance(minimum, int) and not isinstance(minimum, bool) else 0
    high = maximum if isinstance(maximum, int) and not isinstance(maximum, bool) else low
    if high < low:
        return low
    if low == high:
        return low
    return rng.randrange(low, high + 1)


def _array(schema: Mapping[str, JsonValue], rng: Random) -> JsonValue | _Missing:
    minimum = schema.get("minItems")
    size = minimum if isinstance(minimum, int) and not isinstance(minimum, bool) else 0
    maximum = schema.get("maxItems")
    if isinstance(maximum, int) and not isinstance(maximum, bool):
        size = min(size, maximum)
    items = schema.get("items")
    built: list[JsonValue] = []
    for _ in range(size):
        if not isinstance(items, dict):
            built.append("item")
            continue
        value = _generate(items, rng)
        if isinstance(value, _Missing):
            return _MISSING
        built.append(value)
    return built


def _validator(schema: Mapping[str, JsonValue]) -> Validator:
    checker = validator_for(schema) if "$schema" in schema else Draft202012Validator
    return checker(schema, format_checker=checker.FORMAT_CHECKER)


def _declared(schema: Mapping[str, JsonValue]) -> str | None:
    raw = schema.get("type")
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        names = [item for item in raw if isinstance(item, str) and item != "null"]
        if len(names) == 1:
            return names[0]
    return None


def _same_type(declared: str | None, value: JsonValue) -> bool:
    if declared is None:
        return False
    if declared == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if declared == "string":
        return isinstance(value, str)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    if declared == "null":
        return value is None
    return False


def _properties(schema: Mapping[str, JsonValue]) -> dict[str, dict[str, JsonValue]]:
    raw = schema.get("properties")
    if not isinstance(raw, dict):
        return {}
    mapped: dict[str, dict[str, JsonValue]] = {}
    for key, item in raw.items():
        if isinstance(item, dict):
            mapped[key] = item
    return mapped


def _property_names(schema: Mapping[str, JsonValue]) -> set[str]:
    names = set(_properties(schema))
    for prop in _properties(schema).values():
        names.update(_property_names(prop))
    items = schema.get("items")
    if isinstance(items, dict):
        names.update(_property_names(items))
    return names


def _identifiers(description: str) -> tuple[str, ...]:
    quotes = [match.group(1) for match in _TICK.finditer(description)]
    quotes.extend(_SNAKE.findall(description))
    quotes.extend(_CAMEL.findall(description))
    return tuple(quotes)


def _normalize(value: str) -> str:
    return re.sub(r"[_\-]", "", value).casefold()


def _strings(value: JsonValue | None) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _json_object(text: str) -> dict[str, JsonValue] | None:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict):
        return loaded
    return None


def _longest(value: JsonValue | None) -> int:
    if isinstance(value, list):
        nested = max((_longest(item) for item in value), default=0)
        return max(len(value), nested)
    if isinstance(value, dict):
        return max((_longest(item) for item in value.values()), default=0)
    return 0


def _names(sample: Sequence[Mapping[str, JsonValue]]) -> list[str]:
    return [str(tool["name"]) for tool in sample if isinstance(tool.get("name"), str)]


def _named(sample: Sequence[Mapping[str, JsonValue]], name: str) -> dict[str, JsonValue] | None:
    for tool in sample:
        if tool.get("name") == name:
            return dict(tool)
    return None


def _diff_value(
    left: JsonValue,
    right: JsonValue,
    path: str,
    rows: list[dict[str, JsonValue]],
) -> None:
    if left == right:
        return
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else key
            if key not in left:
                rows.append({"after": right[key], "before": None, "path": child})
            elif key not in right:
                rows.append({"after": None, "before": left[key], "path": child})
            else:
                _diff_value(left[key], right[key], child, rows)
        return
    rows.append({"after": right, "before": left, "path": path or "$"})


def _stored_tools(previous: Mapping[str, JsonValue]) -> dict[str, dict[str, JsonValue]]:
    raw = previous.get("tools")
    stored: dict[str, dict[str, JsonValue]] = {}
    if not isinstance(raw, list):
        return stored
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        definition = item.get("definition")
        if isinstance(name, str) and isinstance(definition, dict):
            stored[name] = definition
    return stored


def _as_json(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, list):
        return [_as_json(item) for item in value]
    if isinstance(value, dict):
        mapped: dict[str, JsonValue] = {}
        for key, item in value.items():
            if isinstance(key, str):
                mapped[key] = _as_json(item)
        return mapped
    raise ValueError("snapshot is not json")
