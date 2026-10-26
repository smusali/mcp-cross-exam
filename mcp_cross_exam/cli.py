from __future__ import annotations

import json
import os
import sys
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Annotated, NoReturn
from urllib.parse import urlsplit

import typer
from rich.console import Console

from mcp_cross_exam import version_facts
from mcp_cross_exam.exit_codes import ExitCode, exit_with, set_exit_zero

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
    pretty_exceptions_enable=False,
    help=("Audit an MCP server.\n\nPass an http or https URL, an --sse URL, or a stdio command."),
)


class UsageFailure(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Flags:
    version: bool = False
    as_json: bool = False
    quiet: bool = False
    no_color: bool = False
    exit_zero: bool = False
    sse: str | None = None


_stdio_command: ContextVar[tuple[str, ...] | None] = ContextVar("stdio_command", default=None)


_VALUE_OPTIONS = {"--sse"}


def split_stdio(argv: list[str]) -> tuple[list[str], tuple[str, ...] | None]:
    if "--" not in argv:
        return argv, None
    index = argv.index("--")
    return argv[:index], tuple(argv[index + 1 :])


def route(argv: list[str]) -> list[str]:
    if not argv or "run" in argv or argv in (["-h"], ["--help"]):
        return argv
    routed: list[str] = []
    index = 0
    inserted = False
    while index < len(argv):
        token = argv[index]
        if token in _VALUE_OPTIONS:
            routed.append(token)
            if index + 1 < len(argv):
                routed.append(argv[index + 1])
                index += 2
            else:
                index += 1
            continue
        if token.startswith("-"):
            routed.append(token)
            index += 1
            continue
        if not inserted:
            routed.append("run")
            inserted = True
        routed.append(token)
        index += 1
    return routed


def prepare(argv: list[str]) -> tuple[list[str], tuple[str, ...] | None]:
    left, command = split_stdio(argv)
    return route(left), command


def parse_target(
    endpoint: str | None,
    sse: str | None,
    command: tuple[str, ...] | None,
) -> None:
    if command is not None:
        if endpoint is not None or sse is not None:
            raise UsageFailure("conflicting transport flags")
        if not command:
            raise UsageFailure("missing stdio command")
        return
    if endpoint is not None and sse is not None:
        raise UsageFailure("conflicting transport flags")
    if sse is not None:
        _http_url(sse)
        return
    if endpoint is not None:
        _http_url(endpoint)
        return
    raise UsageFailure("missing endpoint")


def _http_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise UsageFailure("expected an http or https URL")
    return value


def _positional(args: list[str]) -> str | None:
    if not args:
        return None
    if len(args) > 1:
        raise UsageFailure("conflicting transport flags")
    token = args[0]
    if token.startswith("-"):
        raise UsageFailure(f"unrecognized option {token}")
    return token


def _extra_args(ctx: typer.Context) -> list[str]:
    args = ctx.args
    if not isinstance(args, list):
        return []
    return [item for item in args if isinstance(item, str)]


def _combine(parent: Flags | None, local: Flags) -> Flags:
    if parent is None:
        return local
    if parent.sse is not None and local.sse is not None and parent.sse != local.sse:
        raise UsageFailure("conflicting transport flags")
    sse = local.sse if local.sse is not None else parent.sse
    return Flags(
        version=parent.version or local.version,
        as_json=parent.as_json or local.as_json,
        quiet=parent.quiet or local.quiet,
        no_color=parent.no_color or local.no_color,
        exit_zero=parent.exit_zero or local.exit_zero,
        sse=sse,
    )


def _is_empty(flags: Flags, endpoint: str | None, command: tuple[str, ...] | None) -> bool:
    return (
        endpoint is None
        and command is None
        and flags.sse is None
        and not flags.version
        and not flags.as_json
        and not flags.quiet
        and not flags.no_color
        and not flags.exit_zero
    )


def console_for(*, no_color: bool) -> Console:
    forced = no_color or os.environ.get("NO_COLOR") is not None
    return Console(stderr=True, no_color=forced)


def emit_version(*, as_json: bool) -> None:
    facts = version_facts()
    if as_json:
        print(json.dumps(facts))
        return
    print(f"{facts['name']} {facts['version']}")
    print(f"mcp {facts['mcp_version']}")
    print(f"Python {facts['python_version']}")
    print(", ".join(facts["protocol_revisions"]))


def execute(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
) -> None:
    set_exit_zero(flags.exit_zero)
    if flags.version:
        emit_version(as_json=flags.as_json)
        exit_with(ExitCode.SUCCESS)
    try:
        parse_target(endpoint, flags.sse, command)
    except UsageFailure as exc:
        console_for(no_color=flags.no_color).print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    exit_with(ExitCode.SUCCESS)


def _flags_from(
    *,
    version: bool,
    as_json: bool,
    quiet: bool,
    no_color: bool,
    exit_zero: bool,
    sse: str | None,
) -> Flags:
    return Flags(
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
        sse=sse,
    )


def _fail(flags: Flags, exc: UsageFailure) -> NoReturn:
    set_exit_zero(flags.exit_zero)
    console_for(no_color=flags.no_color).print(str(exc), highlight=False)
    exit_with(ExitCode.CONFIG)


@app.callback(
    invoke_without_command=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def root(
    ctx: typer.Context,
    sse: Annotated[str | None, typer.Option("--sse", help="Legacy HTTP+SSE endpoint.")] = None,
    version: Annotated[bool, typer.Option("--version", help="Print version facts.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print machine-readable output.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress non-error output.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable color.")] = False,
    exit_zero: Annotated[
        bool,
        typer.Option("--exit-zero", help="Exit 0 when the result is findings."),
    ] = False,
) -> None:
    flags = _flags_from(
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
        sse=sse,
    )
    if ctx.invoked_subcommand is not None:
        ctx.obj = flags
        return
    try:
        endpoint = _positional(_extra_args(ctx))
    except UsageFailure as exc:
        _fail(flags, exc)
    command = _stdio_command.get()
    if _is_empty(flags, endpoint, command):
        print(ctx.get_help())
        exit_with(ExitCode.SUCCESS)
    execute(flags, endpoint, command)


@app.command(help="Audit one MCP endpoint.")
def run(
    ctx: typer.Context,
    endpoint: Annotated[str | None, typer.Argument(help="Streamable HTTP endpoint.")] = None,
    sse: Annotated[str | None, typer.Option("--sse", help="Legacy HTTP+SSE endpoint.")] = None,
    version: Annotated[bool, typer.Option("--version", help="Print version facts.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print machine-readable output.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress non-error output.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable color.")] = False,
    exit_zero: Annotated[
        bool,
        typer.Option("--exit-zero", help="Exit 0 when the result is findings."),
    ] = False,
) -> None:
    local = _flags_from(
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
        sse=sse,
    )
    parent = ctx.obj if isinstance(ctx.obj, Flags) else None
    try:
        flags = _combine(parent, local)
    except UsageFailure as exc:
        _fail(local, exc)
    execute(flags, endpoint, _stdio_command.get())


def dispatch(argv: list[str]) -> None:
    left, command = prepare(argv)
    token = _stdio_command.set(command)
    try:
        app(args=left, standalone_mode=False, prog_name="mcp-cross-exam")
    finally:
        _stdio_command.reset(token)


def bind_stdio(argv: list[str]) -> tuple[list[str], Token[tuple[str, ...] | None]]:
    left, command = prepare(argv)
    return left, _stdio_command.set(command)


def release_stdio(token: Token[tuple[str, ...] | None]) -> None:
    _stdio_command.reset(token)


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        dispatch(args)
    except KeyboardInterrupt:
        exit_with(ExitCode.INTERRUPTED)
    except typer.Exit as exc:
        if exc.exit_code == 0:
            exit_with(ExitCode.SUCCESS)
        exit_with(ExitCode.CONFIG)
    except typer.TyperException:
        exit_with(ExitCode.CONFIG)
    except Exception:
        exit_with(ExitCode.INTERNAL)
