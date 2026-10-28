from __future__ import annotations

import typer
from typer.testing import CliRunner

from mcp_cross_exam.cli import app, bind_stdio, release_stdio

RUNNER = CliRunner()


def invoke(argv: list[str]) -> typer.testing.Result:
    left, token = bind_stdio(argv)
    try:
        return RUNNER.invoke(app, left)
    finally:
        release_stdio(token)
