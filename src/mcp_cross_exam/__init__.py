from __future__ import annotations

import platform
from importlib.metadata import version
from typing import TypedDict

from mcp_cross_exam.types import SUPPORTED_PROTOCOL_REVISIONS as SUPPORTED_PROTOCOL_REVISIONS

DISTRIBUTION_NAME = "mcp-cross-exam"
__version__ = "0.1.0"


class VersionFacts(TypedDict):
    name: str
    version: str
    mcp_version: str
    python_version: str
    protocol_revisions: list[str]


def version_facts() -> VersionFacts:
    return {
        "name": DISTRIBUTION_NAME,
        "version": __version__,
        "mcp_version": version("mcp"),
        "python_version": platform.python_version(),
        "protocol_revisions": list(SUPPORTED_PROTOCOL_REVISIONS),
    }
