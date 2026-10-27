from __future__ import annotations

import sys
from pathlib import Path

import anyio
import mcp_types
import pytest
from mcp import Client
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters
from mcp_cross_exam import SUPPORTED_PROTOCOL_REVISIONS

from tests.conftest import start_fixture
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


_HANDSHAKE = tuple(era for era in SUPPORTED_PROTOCOL_REVISIONS if era != "2026-07-28")
_TOOLS = {"get_ticket", "list_tickets", "slow_report", "create_ticket"}
_REDUCED = pytest.mark.skipif(sys.platform != "linux", reason="reduced fixture matrix")


@pytest.mark.parametrize("era", SUPPORTED_PROTOCOL_REVISIONS)
def test_sdk_http_client(era: str) -> None:
    with start_fixture(era=era) as port:
        anyio.run(_http_client, port, era)


@_REDUCED
@pytest.mark.parametrize("era", SUPPORTED_PROTOCOL_REVISIONS)
def test_sdk_stdio_client(era: str) -> None:
    anyio.run(_stdio_client, era)


@_REDUCED
@pytest.mark.parametrize("era", _HANDSHAKE)
def test_sdk_sse_client(era: str) -> None:
    with start_fixture(era=era) as port:
        anyio.run(_sse_client, port, era)


async def _exercise(client: Client) -> None:
    listed = await client.list_tools()
    called = await client.call_tool("get_ticket")
    assert {tool.name for tool in listed.tools} == _TOOLS
    assert any(
        isinstance(block, mcp_types.TextContent) and block.text == "ticket-1"
        for block in called.content
    )


async def _http_client(port: int, era: str) -> None:
    async with Client(f"http://127.0.0.1:{port}/mcp", cache=None) as client:
        await _exercise(client)
        assert client.protocol_version == era


async def _stdio_client(era: str) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_cross_exam", "fixture", "serve", "--stdio", "--era", era, "--clean"],
    )
    async with Client(params, cache=None) as client:
        await _exercise(client)
        assert client.protocol_version == era


async def _sse_client(port: int, era: str) -> None:
    transport = sse_client(f"http://127.0.0.1:{port}/sse")
    async with Client(transport, mode="legacy", cache=None) as client:
        await _exercise(client)
        assert client.protocol_version == era
