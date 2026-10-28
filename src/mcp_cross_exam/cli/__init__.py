from __future__ import annotations

import os
import sys
import traceback

import typer

from mcp_cross_exam.cli.app import app, bind_stdio, dispatch, release_stdio
from mcp_cross_exam.exit_codes import ExitCode, exit_with

__all__ = [
    "app",
    "bind_stdio",
    "dispatch",
    "exit_code_for",
    "main",
    "release_stdio",
]


def exit_code_for(exc: BaseException) -> ExitCode:
    if isinstance(exc, KeyboardInterrupt):
        return ExitCode.INTERRUPTED
    if isinstance(exc, typer.Exit):
        if exc.exit_code == 0:
            return ExitCode.SUCCESS
        return ExitCode.CONFIG
    if isinstance(exc, typer.TyperException):
        return ExitCode.CONFIG
    return ExitCode.INTERNAL


def _report_internal(exc: BaseException) -> None:
    print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
    print("Set MCP_CROSS_EXAM_DEBUG=1 to print the traceback.", file=sys.stderr)
    if os.environ.get("MCP_CROSS_EXAM_DEBUG") == "1":
        traceback.print_exc()


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        dispatch(args)
    except KeyboardInterrupt:
        exit_with(ExitCode.INTERRUPTED)
    except typer.Exit as exc:
        exit_with(exit_code_for(exc))
    except typer.TyperException:
        exit_with(ExitCode.CONFIG)
    except Exception as exc:
        _report_internal(exc)
        exit_with(ExitCode.INTERNAL)
