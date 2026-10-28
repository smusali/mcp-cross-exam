from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path

from mcp_cross_exam.transport import Frame
from mcp_cross_exam.transport.base import JsonValue, ProtocolError, json_value, parse_json_bytes

BODY_LIMIT = 64 * 1024
EVIDENCE_BUDGET = 20 * 1024 * 1024
_SENSITIVE = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization"})


def placeholder(secret: str) -> str:
    digest = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"«redacted:sha256:{digest}»"


def redact_text(text: str, secrets: Sequence[str]) -> str:
    for secret in _ordered(secrets):
        text = text.replace(secret, placeholder(secret))
    return text


def redact_bytes(payload: bytes, secrets: Sequence[str]) -> bytes:
    updated = payload
    for secret in _ordered(secrets):
        updated = updated.replace(secret.encode(), placeholder(secret).encode())
    return updated


def redact_headers(headers: Mapping[str, str], secrets: Sequence[str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE or any(secret in value for secret in _ordered(secrets)):
            cleaned[key] = placeholder(value)
            continue
        cleaned[key] = redact_text(value, secrets)
    return cleaned


def bound_body(body: bytes) -> tuple[bytes, bool, int, str]:
    size = len(body)
    digest = hashlib.sha256(body).hexdigest()
    if size > BODY_LIMIT:
        return body[:BODY_LIMIT], True, size, digest
    return body, False, size, digest


def sweep_tree(root: Path, secrets: Sequence[str]) -> None:
    if not root.exists():
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        cleaned = redact_bytes(data, secrets)
        if cleaned != data:
            path.write_bytes(cleaned)


class EvidenceLog:
    def __init__(
        self,
        path: Path,
        secrets: Sequence[str],
        *,
        budget: int = EVIDENCE_BUDGET,
    ) -> None:
        self.path = path
        self.secrets = tuple(secrets)
        self.budget = budget
        self.dropped = 0
        self.written = 0
        self._used = 0

    def add(self, record: Mapping[str, JsonValue]) -> str | None:
        line = redact_text(json.dumps(record, sort_keys=True, separators=(",", ":")), self.secrets)
        encoded = (line + "\n").encode()
        if self._used + len(encoded) > self.budget:
            self.dropped += 1
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as handle:
            handle.write(encoded)
        self._used += len(encoded)
        self.written += 1
        exchange_id = record.get("id")
        if isinstance(exchange_id, str):
            return exchange_id
        return None


def build_exchanges(
    frames: Sequence[Frame],
    secrets: Sequence[str],
    *,
    probe_id: str,
    start: int,
) -> list[dict[str, JsonValue]]:
    records: list[dict[str, JsonValue]] = []
    for offset, (request, response) in enumerate(_pairs(frames), start=start):
        started = _started(request, response)
        duration = 0.0
        if request is not None and response is not None:
            duration = max(0.0, (response.at - request.at) * 1000)
        meta_headers = response.headers if response is not None else {}
        if request is not None and not meta_headers:
            meta_headers = request.headers
        record: dict[str, JsonValue] = {
            "id": f"ex-{offset}",
            "probe_id": probe_id,
            "request": _side(request, secrets),
            "response": _side(response, secrets),
            "started_at": started,
            "duration_ms": duration,
            "transport_meta": {
                "status": None if response is None else response.status,
                "headers": _header_json(redact_headers(meta_headers, secrets)),
                "session": _header(meta_headers, "mcp-session-id"),
                "era": _header(meta_headers, "mcp-protocol-version"),
            },
        }
        records.append(record)
    return records


def transcript_for(records: Sequence[Mapping[str, JsonValue]]) -> str:
    lines: list[str] = []
    for record in records:
        for side in ("request", "response"):
            body = record.get(side)
            if not isinstance(body, dict):
                continue
            parsed = body.get("json")
            if not isinstance(parsed, dict):
                continue
            if "method" in parsed or "result" in parsed or "error" in parsed:
                lines.append(json.dumps(parsed, sort_keys=True))
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def curl_for_frames(
    frames: Sequence[Frame],
    *,
    url: str,
    bearer_env: str | None,
    header_envs: Mapping[str, str],
    secrets: Sequence[str],
) -> str:
    commands: list[str] = []
    for frame in frames:
        if frame.direction != "outbound":
            continue
        method = "GET" if not frame.body.strip() else "POST"
        commands.append(
            curl_command(
                url=url,
                method=method,
                headers=frame.headers,
                body=frame.body,
                bearer_env=bearer_env,
                header_envs=header_envs,
                secrets=secrets,
            )
        )
    return "\n".join(commands)


def curl_command(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes,
    bearer_env: str | None,
    header_envs: Mapping[str, str],
    secrets: Sequence[str],
) -> str:
    parts = ["curl", "-sS", "-X", method, url]
    for key, value in headers.items():
        rendered = _curl_value(
            key,
            value,
            bearer_env=bearer_env,
            header_envs=header_envs,
            secrets=secrets,
        )
        parts.extend(["-H", f"{key}: {rendered}"])
    if body.strip():
        parts.extend(["--data", redact_text(body.decode("utf-8", errors="replace"), secrets)])
    return " ".join(shlex.quote(part) for part in parts)


def repro_command(
    *,
    endpoint: str | None,
    probe_id: str,
    tool: str | None,
    seed: int,
    protocol: str | None,
    bearer_env: str | None,
    expired_bearer_env: str | None,
    header_envs: Mapping[str, str],
    legacy: bool,
    command: Sequence[str] | None,
) -> str:
    parts = ["mcp-cross-exam", "run"]
    if legacy and endpoint is not None:
        parts.extend(["--sse", endpoint])
    elif endpoint is not None:
        parts.append(endpoint)
    parts.extend(["--probe", probe_id, "--seed", str(seed)])
    if tool is not None:
        parts.extend(["--tool", tool])
    if protocol:
        parts.extend(["--protocol-version", protocol])
    if bearer_env:
        parts.extend(["--bearer-env", bearer_env])
    if expired_bearer_env:
        parts.extend(["--expired-bearer-env", expired_bearer_env])
    for header, env_name in header_envs.items():
        parts.extend(["--header-env", f"{header}={env_name}"])
    if command:
        parts.append("--")
        parts.extend(command)
    return " ".join(_shown(part) for part in parts)


def transcript_pairs(text: str) -> list[tuple[dict[str, JsonValue], dict[str, JsonValue] | None]]:
    rows: list[dict[str, JsonValue]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        value = json_value(loaded)
        if not isinstance(value, dict):
            raise ValueError("transcript line is not an object")
        rows.append(value)
    pairs: list[tuple[dict[str, JsonValue], dict[str, JsonValue] | None]] = []
    index = 0
    while index < len(rows):
        request = rows[index]
        if "method" not in request:
            raise ValueError("transcript line is not a request")
        expected: dict[str, JsonValue] | None = None
        if index + 1 < len(rows) and "method" not in rows[index + 1]:
            expected = rows[index + 1]
            index += 2
        else:
            index += 1
        pairs.append((request, expected))
    return pairs


def expected_payload(message: Mapping[str, JsonValue]) -> JsonValue:
    if "result" in message:
        return message["result"]
    if "error" in message:
        return message["error"]
    return dict(message.items())


def request_method(message: Mapping[str, JsonValue]) -> str | None:
    method = message.get("method")
    if isinstance(method, str):
        return method
    return None


def request_params(message: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    params = message.get("params")
    if isinstance(params, dict):
        return params
    return {}


def _ordered(secrets: Sequence[str]) -> tuple[str, ...]:
    unique = {secret for secret in secrets if len(secret) >= 8}
    return tuple(sorted(unique, key=len, reverse=True))


def _pairs(frames: Sequence[Frame]) -> list[tuple[Frame | None, Frame | None]]:
    pairs: list[tuple[Frame | None, Frame | None]] = []
    pending: Frame | None = None
    for frame in frames:
        if frame.direction == "outbound":
            if pending is not None:
                pairs.append((pending, None))
            pending = frame
            continue
        if pending is not None:
            pairs.append((pending, frame))
            pending = None
            continue
        pairs.append((None, frame))
    if pending is not None:
        pairs.append((pending, None))
    return pairs


def _side(frame: Frame | None, secrets: Sequence[str]) -> dict[str, JsonValue]:
    if frame is None:
        return {}
    kept, truncated, size, digest = bound_body(frame.body)
    text = redact_text(kept.decode("utf-8", errors="replace"), secrets)
    record: dict[str, JsonValue] = {"text": text}
    parsed = parse_json_bytes(kept)
    if isinstance(parsed, dict):
        redacted = _redact_json(parsed, secrets)
        if isinstance(redacted, dict):
            record["json"] = redacted
    if truncated:
        record["truncated"] = True
        record["original_size"] = size
        record["body_sha256"] = digest
    return record


def _redact_json(value: dict[str, JsonValue], secrets: Sequence[str]) -> JsonValue:
    cleaned = redact_text(json.dumps(value), secrets)
    try:
        loaded = json.loads(cleaned)
    except json.JSONDecodeError:
        return {"raw": cleaned}
    try:
        return json_value(loaded)
    except ProtocolError:
        return {"raw": cleaned}


def _started(request: Frame | None, response: Frame | None) -> float:
    if request is not None:
        return request.at
    if response is not None:
        return response.at
    return 0.0


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name and value:
            return value
    return None


def _header_json(headers: Mapping[str, str]) -> dict[str, JsonValue]:
    return dict(headers.items())


def _curl_value(
    key: str,
    value: str,
    *,
    bearer_env: str | None,
    header_envs: Mapping[str, str],
    secrets: Sequence[str],
) -> str:
    lowered = key.lower()
    if lowered == "authorization" and bearer_env:
        return f"Bearer ${bearer_env}"
    for header, env_name in header_envs.items():
        if header.lower() == lowered:
            return f"${env_name}"
    if lowered in _SENSITIVE:
        return placeholder(value)
    return redact_text(value, secrets)


def _shown(part: str) -> str:
    if part and not any(char.isspace() or char in "\"'\\" for char in part):
        return part
    return shlex.quote(part)
