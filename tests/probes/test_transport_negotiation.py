from __future__ import annotations

from pathlib import Path

import pytest

from tests.probes.conftest import audit_http, audit_stdio, finding_ids

ERAS = ("2025-11-25", "2026-07-28")
NEGOTIATION = (
    "transport.version-negotiation",
    "transport.capabilities-honesty",
    "transport.unknown-method",
    "none",
)


@pytest.mark.parametrize("era", ERAS)
@pytest.mark.parametrize("defect", NEGOTIATION)
def test_http_negotiation(tmp_path: Path, era: str, defect: str) -> None:
    found = finding_ids(audit_http(tmp_path, era, defect))
    if defect == "none":
        assert not found
        return
    assert found == {defect}


@pytest.mark.parametrize("era", ERAS)
def test_required_headers_follow_the_era(tmp_path: Path, era: str) -> None:
    found = finding_ids(audit_http(tmp_path, era, "transport.required-headers"))
    if era == "2026-07-28":
        assert found == {"transport.required-headers"}
        return
    assert "transport.required-headers" not in found
    assert not found


@pytest.mark.parametrize("era", ERAS)
@pytest.mark.parametrize("defect", NEGOTIATION)
def test_stdio_negotiation(tmp_path: Path, era: str, defect: str) -> None:
    found = finding_ids(audit_stdio(tmp_path, era, defect))
    if defect == "none":
        assert not found
        return
    assert found == {defect}


def test_version_finding_cites_the_negotiated_revision(tmp_path: Path) -> None:
    findings = audit_http(tmp_path, "2026-07-28", "transport.version-negotiation")
    finding = findings[0]
    assert finding.severity == "high"
    assert any("2026-07-28" in ref for ref in finding.spec_refs)
    assert finding.frames
