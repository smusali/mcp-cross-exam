from __future__ import annotations

import json
import os
import re
from io import StringIO
from pathlib import Path
from typing import Protocol

import jsonschema
import pytest
from mcp_cross_exam.cli import main
from mcp_cross_exam.exit_codes import ExitCode
from mcp_cross_exam.findings import (
    BlastRadius,
    BudgetRecord,
    Coverage,
    Finding,
    Report,
    Repro,
    RunRecord,
    ServerRecord,
    TargetRecord,
    ToolVersion,
)
from mcp_cross_exam.report import print_summary, render_html
from mcp_cross_exam.transport.base import JsonValue, json_value
from rich.console import Console

from tests.conftest import start_fixture

_SCHEMA = Path(__file__).parents[1] / "mcp_cross_exam" / "report.v1.json"
_GOLDEN = Path(__file__).parent / "corpus" / "report.golden.json"
_PAYLOAD = '"><img src=x onerror="alert(1)"><script>alert(1)</script>'
_URL = re.compile(r"http://127\.0\.0\.1:\d+/mcp")
_VOLATILE = {"started_at", "finished_at", "run_id", "duration_ms"}


def test_reports_match_the_schema_and_golden(tmp_path: Path) -> None:
    with start_fixture(defects="session.expired-empty-success") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        args = ["--seed", "7", "--probe", "session.expired-empty-success", url]
        directory = _run(tmp_path, args)
        again = _run(tmp_path, args)
    report = _load(directory / "report.json")
    _validate(report)
    _validate(_load(again / "report.json"))
    html = (directory / "report.html").read_text(encoding="utf-8")
    assert len(html.encode()) < 2 * 1024 * 1024
    projected = _project(report)
    assert projected == _project(_load(again / "report.json"))
    if os.environ.get("WRITE_GOLDEN") == "1":
        _GOLDEN.write_text(json.dumps(projected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json_value(json.loads(_GOLDEN.read_text(encoding="utf-8")))
    assert projected == expected


def test_fixture_report_opens_as_text(tmp_path: Path) -> None:
    with start_fixture(defects="session.expired-empty-success") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        directory = _run(tmp_path, ["--seed", "7", "--probe", "session.expired-empty-success", url])
    _browse(directory / "report.html", "score ")


def test_hostile_strings_stay_text(tmp_path: Path) -> None:
    html = render_html(_hostile(), {})
    assert len(html.encode()) < 2 * 1024 * 1024
    lowered = html.lower()
    assert lowered.count("<script") == 1
    assert lowered.count("</script") == 1
    assert "<img" not in lowered
    assert 'href="javascript:' not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    path = tmp_path / "report.html"
    path.write_text(html, encoding="utf-8")
    _browse(path, _PAYLOAD)


def test_terminal_summary_fits_one_screen(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    with start_fixture(defects="session.expired-empty-success") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        with pytest.raises(SystemExit) as caught:
            main(["--seed", "1", "--probe", "session.expired-empty-success", url])
        assert caught.value.code == ExitCode.FINDINGS
        noisy = capsys.readouterr().err
        with pytest.raises(SystemExit) as quiet:
            main(["--quiet", "--seed", "1", "--probe", "session.expired-empty-success", url])
        assert quiet.value.code == ExitCode.FINDINGS
        score_only = capsys.readouterr().err
        with pytest.raises(SystemExit) as machine:
            main(["--json", "--seed", "1", "--probe", "session.expired-empty-success", url])
        assert machine.value.code == ExitCode.FINDINGS
        captured = capsys.readouterr()
    assert len(noisy.splitlines()) <= 25
    assert noisy.splitlines()[0].startswith("score ")
    assert "session.expired-empty-success" in noisy
    assert score_only.strip().startswith("score ")
    assert len(score_only.strip().splitlines()) == 1
    assert "report.html" not in score_only
    loaded = json_value(json.loads(captured.out))
    assert isinstance(loaded, dict)
    assert "score " not in captured.err
    _validate(loaded)


def test_truncated_exchange_is_labeled() -> None:
    report = _hostile()
    finding = report.findings[0].model_copy(update={"evidence": ["ex-1", "ex-2"]})
    labeled = report.model_copy(update={"findings": [finding]})
    raw = json_value(
        {
            "duration_ms": 12,
            "request": {
                "json": {"method": "ping"},
                "truncated": True,
                "original_size": 40,
                "body_sha256": "abc",
            },
            "response": {"text": "ok"},
        }
    )
    if not isinstance(raw, dict):
        raise AssertionError("record")
    html = render_html(labeled, {"ex-1": raw})
    assert "truncated (40 bytes)" in html
    assert "abc" in html
    assert "12 ms" in html
    assert "evidence dropped" in html


def test_ansi_tool_name_is_inert(tmp_path: Path) -> None:
    buffer = StringIO()
    console = Console(file=buffer, width=100, no_color=True, highlight=False)
    print_summary(console, _hostile(), tmp_path, quiet=False)
    text = buffer.getvalue()
    assert "\x1b" not in text
    assert "\x01" not in text
    assert "get_ticket" in text
    assert text.splitlines()[0].startswith("score ")


@pytest.mark.parametrize(
    "mode",
    [
        "clean",
        "findings",
        "config",
        "unreachable",
        "exit-zero",
        "incomplete",
        "exit-zero-incomplete",
        "exit-zero-config",
        "exit-zero-unreachable",
    ],
)
def test_exit_contract(mode: str, tmp_path: Path) -> None:
    if mode == "config":
        assert _code(["--fail-on", "nope", "http://127.0.0.1:9/mcp"]) == ExitCode.CONFIG
        return
    if mode == "unreachable":
        assert _code(["http://127.0.0.1:9/mcp"]) == ExitCode.UNREACHABLE
        return
    if mode == "exit-zero-config":
        code = _code(["--exit-zero", "--fail-on", "nope", "http://127.0.0.1:9/mcp"])
        assert code == ExitCode.CONFIG
        return
    if mode == "exit-zero-unreachable":
        assert _code(["--exit-zero", "http://127.0.0.1:9/mcp"]) == ExitCode.UNREACHABLE
        return
    defects = "session.expired-empty-success"
    if mode == "clean" or "incomplete" in mode:
        defects = "none"
    with start_fixture(defects=defects) as port:
        url = f"http://127.0.0.1:{port}/mcp"
        if mode == "clean":
            assert _code(["--probe", "transport.unknown-method", url]) == ExitCode.SUCCESS
            return
        if mode == "findings":
            code = _code(["--probe", "session.expired-empty-success", url])
            assert code == ExitCode.FINDINGS
            return
        if mode == "exit-zero":
            code = _code(["--exit-zero", "--probe", "session.expired-empty-success", url])
            assert code == ExitCode.SUCCESS
            return
        config = tmp_path / "budget.toml"
        config.write_text(
            "[budget]\nwall_clock_s = 60\nmax_calls_per_tool = 1\ncall_timeout_s = 10\n",
            encoding="utf-8",
        )
        probe = ["--config", str(config), "--probe", "transport.reconnect-fails", url]
        if mode == "incomplete":
            directory = _run(tmp_path, probe)
            report = _load(directory / "report.json")
            coverage = report["coverage"]
            assert isinstance(coverage, dict)
            assert coverage["status"] == "partial"
            assert report["score"] == 100
            assert _code(["--fail-on-incomplete", *probe]) == ExitCode.FINDINGS
            return
        code = _code(["--exit-zero", "--fail-on-incomplete", *probe])
        assert code == ExitCode.SUCCESS


def _hostile() -> Report:
    tool = "\x1b[31mget_ticket\x1b[0m\x01"
    finding = Finding(
        probe_id="schema.lint.hidden-instructions",
        family="schema",
        tool=tool,
        severity="low",
        severity_source="default",
        title=_PAYLOAD,
        detail=_PAYLOAD,
        declared={"quote": _PAYLOAD},
        observed={"path": _PAYLOAD},
        evidence=[],
        repro=Repro(command=_PAYLOAD, transcript=None),
        blast_radius=BlastRadius(
            effect="read",
            effect_source="default",
            scope="user",
            scope_source="default",
            agent_impact=_PAYLOAD,
        ),
        spec_refs=["javascript:alert(1)"],
        fingerprint="ab" * 32,
        raw_penalty=1,
        penalty=1,
    )
    return Report(
        tool=ToolVersion(name="mcp-cross-exam", version="0", mcp_version="0"),
        target=TargetRecord(
            transport="http",
            url=f"http://127.0.0.1/{_PAYLOAD}",
            command=None,
            protocol_version=None,
            guard="loopback",
            bearer_env=None,
            expired_bearer_env=None,
            header_env={},
        ),
        server=ServerRecord(
            revision=_PAYLOAD,
            server_info=None,
            capabilities={},
            extensions=[],
        ),
        run=RunRecord(
            run_id="run",
            seed=1,
            started_at="t0",
            finished_at="t1",
            budget=BudgetRecord(wall_clock_s=60, max_calls_per_tool=50, call_timeout_s=10),
        ),
        coverage=Coverage(
            status="complete",
            probes_run=["schema.lint.hidden-instructions"],
            skipped=[],
        ),
        score=99,
        findings=[finding],
    )


class _Dialog(Protocol):
    @property
    def message(self) -> str: ...

    def dismiss(self) -> None: ...


class _Request(Protocol):
    @property
    def url(self) -> str: ...


class _Route(Protocol):
    @property
    def request(self) -> _Request: ...

    def continue_(self) -> None: ...

    def abort(self) -> None: ...


def _browse(path: Path, needle: str) -> None:
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(offline=True)
            page = context.new_page()
            dialogs: list[str] = []

            def _dialog(dialog: _Dialog) -> None:
                dialogs.append(dialog.message)
                dialog.dismiss()

            def _route(route: _Route) -> None:
                if route.request.url.startswith("file:"):
                    route.continue_()
                    return
                route.abort()

            page.on("dialog", _dialog)
            page.route("**/*", _route)
            page.goto(path.resolve().as_uri())
            assert dialogs == []
            assert page.locator("img").count() == 0
            assert needle in page.locator("body").inner_text()
            browser.close()
    except Exception as exc:
        if "Executable doesn't exist" in str(exc):
            pytest.skip(str(exc))
        raise


def _project(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        projected: dict[str, JsonValue] = {}
        for key, item in value.items():
            if key in _VOLATILE:
                continue
            projected[key] = _project(item)
        return projected
    if isinstance(value, list):
        return [_project(item) for item in value]
    if isinstance(value, str):
        return _URL.sub("http://fixture/mcp", value)
    return value


def _run(tmp_path: Path, argv: list[str]) -> Path:
    before = _dirs(tmp_path)
    with pytest.raises(SystemExit):
        main(argv)
    created = _dirs(tmp_path) - before
    assert len(created) == 1
    return created.pop()


def _code(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as caught:
        main(argv)
    code = caught.value.code
    if not isinstance(code, int):
        raise AssertionError("exit")
    return code


def _dirs(tmp_path: Path) -> set[Path]:
    root = tmp_path / "runs"
    if not root.is_dir():
        return set()
    return {path for path in root.iterdir() if path.is_dir()}


def _load(path: Path) -> dict[str, JsonValue]:
    loaded = json_value(json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        raise AssertionError("report")
    return loaded


def _validate(report: dict[str, JsonValue]) -> None:
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)
