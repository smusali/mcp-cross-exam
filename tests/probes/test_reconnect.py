from __future__ import annotations

from pathlib import Path

import pytest

from mcp_cross_exam.transport import Finding
from tests.probes.conftest import audit_http, audit_stdio, finding_ids


@pytest.mark.parametrize("kind", ["stdio", "http", "sse"])
def test_reconnect_loses_connection_scoped_state(tmp_path: Path, kind: str) -> None:
    findings = _audit(tmp_path, kind, "transport.reconnect-fails")
    matched = [item for item in findings if item.item_id == "transport.reconnect-fails"]
    assert len(matched) == 1
    assert matched[0].severity == "high"
    assert len(matched[0].frames) == 2
    assert matched[0].frames[0].body != matched[0].frames[1].body


def test_clean_sse_keeps_reconnect_and_resume(tmp_path: Path) -> None:
    found = finding_ids(audit_http(tmp_path, "2025-11-25", "none", legacy=True))
    assert "transport.reconnect-fails" not in found
    assert "transport.resume-gap" not in found


@pytest.mark.parametrize("legacy", [False, True])
def test_resume_gap(tmp_path: Path, legacy: bool) -> None:
    findings = audit_http(tmp_path, "2025-11-25", "transport.resume-gap", legacy=legacy)
    matched = [item for item in findings if item.item_id == "transport.resume-gap"]
    assert len(matched) == 1
    assert matched[0].severity == "medium"
    assert len(matched[0].frames) == 2


def test_modern_stream_has_no_resume_probe(tmp_path: Path) -> None:
    found = finding_ids(audit_http(tmp_path, "2026-07-28", "transport.resume-gap"))
    assert "transport.resume-gap" not in found
    assert "probe.error" not in found


def _audit(tmp: Path, kind: str, defect: str) -> list[Finding]:
    if kind == "stdio":
        return audit_stdio(tmp, "2025-11-25", defect)
    return audit_http(tmp, "2025-11-25", defect, legacy=kind == "sse")
