from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeGuard

from jinja2 import Environment, StrictUndefined
from pydantic import JsonValue
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_cross_exam import version_facts
from mcp_cross_exam.evidence import redact_text, repro_command
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.findings import (
    SEVERITY_RANK,
    BudgetRecord,
    Coverage,
    Finding,
    Report,
    RunRecord,
    ServerRecord,
    SkipRecord,
    TargetRecord,
    ToolVersion,
    TransportKind,
    apply_penalties,
    promote,
    to_model_json,
)
from mcp_cross_exam.probes.base import ProbeContext, RunBudget
from mcp_cross_exam.transport import Finding as Draft
from mcp_cross_exam.transport.base import JsonValue as WireValue
from mcp_cross_exam.transport.base import ServerState, Severity, json_value
from mcp_cross_exam.types import SkipReason

_TEMPLATE = Path(__file__).with_name("report.html.j2").read_text(encoding="utf-8")
_ENV = Environment(autoescape=True, undefined=StrictUndefined)
_PAGE = _ENV.from_string(_TEMPLATE)
_CSI = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
_SEVERITIES = ("critical", "high", "medium", "low", "info")
SCRIPT = """
(function () {
  function current(id) {
    var node = document.getElementById(id);
    if (!node) {
      return "";
    }
    return node.value;
  }
  function apply() {
    var severity = current("filter-severity");
    var family = current("filter-family");
    var tool = current("filter-tool");
    var nodes = document.querySelectorAll("[data-finding]");
    Array.prototype.forEach.call(nodes, function (node) {
      var visible = true;
      if (severity && node.getAttribute("data-severity") !== severity) {
        visible = false;
      }
      if (family && node.getAttribute("data-family") !== family) {
        visible = false;
      }
      if (tool && node.getAttribute("data-tool") !== tool) {
        visible = false;
      }
      node.hidden = !visible;
    });
  }
  ["filter-severity", "filter-family", "filter-tool"].forEach(function (id) {
    var node = document.getElementById(id);
    if (node) {
      node.addEventListener("change", apply);
    }
  });
  var buttons = document.querySelectorAll("[data-command]");
  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener("click", function () {
      var command = button.getAttribute("data-command");
      if (!command || !navigator.clipboard) {
        return;
      }
      navigator.clipboard.writeText(command);
    });
  });
})();
""".strip()


@dataclass(frozen=True, slots=True)
class _Link:
    text: str
    href: str | None


@dataclass(frozen=True, slots=True)
class _ExchangeView:
    request: str
    response: str
    duration: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FindingView:
    severity: str
    probe_id: str
    family: str
    tool: str
    title: str
    detail: str | None
    declared: str | None
    observed: str | None
    exchanges: tuple[_ExchangeView, ...]
    repro_command: str
    effect: str
    effect_source: str
    scope: str
    scope_source: str
    agent_impact: str
    links: tuple[_Link, ...]
    penalty: int
    raw_penalty: int


@dataclass(frozen=True, slots=True)
class _Page:
    csp: str
    script: str
    score: int
    partial: bool
    target: str
    revision: str
    guard: str
    seed: int
    started: str
    finished: str
    budget: str
    skipped: tuple[str, ...]
    severities: tuple[str, ...]
    families: tuple[str, ...]
    tools: tuple[str, ...]
    findings: tuple[_FindingView, ...]


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


def plain(value: str) -> str:
    cleaned = _CSI.sub("", _OSC.sub("", value))
    return "".join(char for char in cleaned if char in "\n\t" or ord(char) >= 32)


def is_partial(reasons: Sequence[str], item_ids: Sequence[str]) -> bool:
    return SkipReason.BUDGET in reasons or "probe.error" in item_ids


def decide_exit(
    findings: Sequence[Finding],
    *,
    fail_on: str,
    partial: bool,
    fail_on_incomplete: bool,
) -> ExitCode:
    chosen = fail_on if _is_severity(fail_on) else "high"
    threshold = SEVERITY_RANK[chosen]
    if any(SEVERITY_RANK[item.severity] >= threshold for item in findings):
        return ExitCode.FINDINGS
    if fail_on_incomplete and partial:
        return ExitCode.FINDINGS
    return ExitCode.SUCCESS


def render_json(report: Report) -> str:
    dumped = json_value(report.model_dump(mode="json"))
    return json.dumps(dumped, indent=2, sort_keys=True) + "\n"


def render_html(report: Report, evidence: Mapping[str, Mapping[str, WireValue]]) -> str:
    return _PAGE.render(page=_page(report, evidence))


def print_summary(console: Console, report: Report, directory: Path, *, quiet: bool) -> None:
    label = f"score {report.score}"
    if report.coverage.status == "partial":
        label = f"{label} partial"
    console.print(Text(label), highlight=False)
    if quiet:
        return
    if report.findings:
        table = Table(width=100, pad_edge=False, show_edge=True)
        table.add_column("severity", no_wrap=True, overflow="ellipsis", max_width=8)
        table.add_column("probe", no_wrap=True, overflow="ellipsis", max_width=40)
        table.add_column("tool", no_wrap=True, overflow="ellipsis", max_width=16)
        table.add_column("impact", no_wrap=True, overflow="ellipsis", max_width=28)
        for finding in report.findings[:10]:
            table.add_row(
                Text(plain(finding.severity)),
                Text(plain(finding.probe_id)),
                Text(plain(finding.tool or "")),
                Text(plain(finding.blast_radius.agent_impact)),
            )
        console.print(table)
    html_path = directory / "report.html"
    json_path = directory / "report.json"
    console.print(Text(f"report.html {html_path}"), highlight=False)
    console.print(Text(f"report.json {json_path}"), highlight=False)


def publish(
    ctx: ProbeContext,
    drafts: Sequence[Draft],
    *,
    directory: Path,
    started_at: str,
    finished_at: str,
    protocol_version: str | None,
    fail_on: str,
    fail_on_incomplete: bool,
    as_json: bool,
    quiet: bool,
    plan: bool,
    console: Console,
) -> ExitCode:
    promoted = [
        promote(
            draft,
            classifications=ctx.classifications,
            scopes=ctx.scopes,
            severities=ctx.severities,
            command=_command(ctx, draft),
        )
        for draft in drafts
    ]
    score, ranked = apply_penalties(promoted, len(ctx.classifications))
    reasons = [item.reason for item in ctx.run.skips]
    partial = is_partial(reasons, [item.item_id for item in drafts])
    report = _report(
        ctx,
        ranked,
        score=score,
        partial=partial,
        started_at=started_at,
        finished_at=finished_at,
        protocol_version=protocol_version,
    )
    body = redact_text(render_json(report), ctx.secrets)
    evidence = _evidence(directory / "evidence.jsonl")
    html = redact_text(render_html(report, evidence), ctx.secrets)
    write_atomic(directory / "report.json", body)
    write_atomic(directory / "report.html", html)
    _transcripts(directory / "transcripts", report, ctx.secrets)
    if plan:
        return ExitCode.SUCCESS
    code = decide_exit(
        ranked,
        fail_on=fail_on,
        partial=partial,
        fail_on_incomplete=fail_on_incomplete,
    )
    if as_json:
        print(body, end="")
        return code
    print_summary(console, report, directory, quiet=quiet)
    return code


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _report(
    ctx: ProbeContext,
    findings: Sequence[Finding],
    *,
    score: int,
    partial: bool,
    started_at: str,
    finished_at: str,
    protocol_version: str | None,
) -> Report:
    facts = version_facts()
    budget = ctx.budget if ctx.budget is not None else RunBudget()
    server = ctx.run.server
    skips = [
        SkipRecord(probe_id=item.probe_id, tool=item.tool, reason=item.reason)
        for item in ctx.run.skips
    ]
    ran: list[str] = []
    seen: set[str] = set()
    for probe_id in ctx.ran:
        if probe_id not in seen:
            seen.add(probe_id)
            ran.append(probe_id)
    return Report(
        tool=ToolVersion(
            name=facts["name"],
            version=facts["version"],
            mcp_version=facts["mcp_version"],
        ),
        target=TargetRecord(
            transport=_transport(ctx),
            url=ctx.endpoint,
            command=None if ctx.command is None else list(ctx.command),
            protocol_version=protocol_version,
            guard=ctx.guard,
            bearer_env=ctx.bearer_env,
            expired_bearer_env=ctx.expired_bearer_env,
            header_env=dict(ctx.header_envs),
        ),
        server=_server_record(server),
        run=RunRecord(
            run_id=ctx.run.run_id,
            seed=ctx.seed,
            started_at=started_at,
            finished_at=finished_at,
            budget=BudgetRecord(
                wall_clock_s=budget.wall_clock_s,
                max_calls_per_tool=budget.max_calls_per_tool,
                call_timeout_s=budget.call_timeout_s,
            ),
        ),
        coverage=Coverage(
            status="partial" if partial else "complete",
            probes_run=ran,
            skipped=skips,
        ),
        score=score,
        findings=list(findings),
    )


def _command(ctx: ProbeContext, draft: Draft) -> str:
    if draft.repro_command:
        return draft.repro_command
    tool = None
    if draft.data is not None:
        value = draft.data.get("tool")
        if isinstance(value, str) and value:
            tool = value
    probe_id = draft.item_id
    if draft.item_id == "probe.error" and draft.data is not None:
        value = draft.data.get("probe_id")
        if isinstance(value, str) and value:
            probe_id = value
    return repro_command(
        endpoint=ctx.endpoint,
        probe_id=probe_id,
        tool=tool,
        seed=ctx.seed,
        protocol=ctx.revision or None,
        bearer_env=ctx.bearer_env,
        expired_bearer_env=ctx.expired_bearer_env,
        header_envs=ctx.header_envs,
        legacy=ctx.legacy,
        command=ctx.command,
    )


def _server_record(server: ServerState | None) -> ServerRecord:
    if server is None:
        return ServerRecord(revision="", server_info=None, capabilities={}, extensions=[])
    info = server.server_info
    return ServerRecord(
        revision=server.revision,
        server_info=None if info is None else _model_object(info),
        capabilities=_model_object(server.capabilities),
        extensions=list(server.extensions),
    )


def _model_object(value: Mapping[str, WireValue]) -> dict[str, JsonValue]:
    return {key: to_model_json(item) for key, item in value.items()}


def _transport(ctx: ProbeContext) -> TransportKind:
    if ctx.command is not None:
        return "stdio"
    if ctx.legacy:
        return "sse"
    return "http"


def _evidence(path: Path) -> dict[str, dict[str, WireValue]]:
    if not path.is_file():
        return {}
    found: dict[str, dict[str, WireValue]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json_value(json.loads(line))
        if not isinstance(loaded, dict):
            continue
        exchange_id = loaded.get("id")
        if isinstance(exchange_id, str):
            found[exchange_id] = loaded
    return found


def _transcripts(directory: Path, report: Report, secrets: Sequence[str]) -> None:
    for finding in report.findings:
        transcript = finding.repro.transcript
        if not transcript:
            continue
        write_atomic(
            directory / f"{finding.fingerprint}.txt",
            redact_text(transcript, secrets),
        )


def _page(report: Report, evidence: Mapping[str, Mapping[str, WireValue]]) -> _Page:
    findings = tuple(_finding_view(item, evidence) for item in report.findings)
    budget = report.run.budget
    present = {item.severity for item in report.findings}
    return _Page(
        csp=_csp(),
        script=SCRIPT,
        score=report.score,
        partial=report.coverage.status == "partial",
        target=_target_label(report),
        revision=report.server.revision or "unknown",
        guard=report.target.guard,
        seed=report.run.seed,
        started=report.run.started_at,
        finished=report.run.finished_at,
        budget=(
            f"{budget.wall_clock_s}s wall, {budget.max_calls_per_tool} calls, "
            f"{budget.call_timeout_s}s timeout"
        ),
        skipped=tuple(
            _skip_label(item.probe_id, item.tool, item.reason) for item in report.coverage.skipped
        ),
        severities=tuple(name for name in _SEVERITIES if name in present),
        families=tuple(sorted({item.family for item in report.findings})),
        tools=tuple(sorted({item.tool for item in report.findings if item.tool})),
        findings=findings,
    )


def _finding_view(
    finding: Finding,
    evidence: Mapping[str, Mapping[str, WireValue]],
) -> _FindingView:
    radius = finding.blast_radius
    return _FindingView(
        severity=finding.severity,
        probe_id=finding.probe_id,
        family=finding.family,
        tool=finding.tool or "",
        title=finding.title,
        detail=finding.detail,
        declared=None if finding.declared is None else _pretty(finding.declared),
        observed=None if finding.observed is None else _pretty(finding.observed),
        exchanges=tuple(_exchange(evidence.get(item)) for item in finding.evidence),
        repro_command=finding.repro.command,
        effect=radius.effect,
        effect_source=radius.effect_source,
        scope=radius.scope,
        scope_source=radius.scope_source,
        agent_impact=radius.agent_impact,
        links=tuple(_link(url) for url in finding.spec_refs),
        penalty=finding.penalty,
        raw_penalty=finding.raw_penalty,
    )


def _exchange(record: Mapping[str, WireValue] | None) -> _ExchangeView:
    if record is None:
        return _ExchangeView("", "", "0", ("evidence dropped",))
    return _ExchangeView(
        _side_text(record.get("request")),
        _side_text(record.get("response")),
        _duration(record.get("duration_ms")),
        _notes(record.get("request")) + _notes(record.get("response")),
    )


def _side_text(side: WireValue | None) -> str:
    if not isinstance(side, dict) or not side:
        return ""
    parsed = side.get("json")
    if isinstance(parsed, dict | list):
        return json.dumps(parsed, indent=2, sort_keys=True)
    text = side.get("text")
    if isinstance(text, str):
        return text
    return ""


def _notes(side: WireValue | None) -> tuple[str, ...]:
    if not isinstance(side, dict) or side.get("truncated") is not True:
        return ()
    size = side.get("original_size")
    count = size if isinstance(size, int) and not isinstance(size, bool) else 0
    lines = [f"truncated ({count} bytes)"]
    digest = side.get("body_sha256")
    if isinstance(digest, str):
        lines.append(digest)
    return tuple(lines)


def _duration(value: WireValue | None) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "0"
    return str(value)


def _pretty(value: Mapping[str, JsonValue]) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _link(url: str) -> _Link:
    if url.startswith("https://") or url.startswith("http://"):
        return _Link(url, url)
    return _Link(url, None)


def _target_label(report: Report) -> str:
    if report.target.command:
        return " ".join(report.target.command)
    if report.target.url:
        return report.target.url
    return report.target.transport


def _skip_label(probe_id: str, tool: str | None, reason: str) -> str:
    if tool:
        return f"{probe_id} {tool}: {reason}"
    return f"{probe_id}: {reason}"


def _csp() -> str:
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    return (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        f"style-src 'unsafe-inline'; script-src 'sha256-{digest}'"
    )


def _is_severity(value: str) -> TypeGuard[Severity]:
    return value in SEVERITY_RANK
