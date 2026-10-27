from __future__ import annotations

import json
import os
import sys
import tempfile
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn
from urllib.parse import urlsplit

import anyio
import typer
from rich.console import Console

from mcp_cross_exam import version_facts
from mcp_cross_exam.exit_codes import ExitCode, exit_with, set_exit_zero
from mcp_cross_exam.transport import OFFERED_VERSIONS, Transport, TransportFailure
from mcp_cross_exam.transport.http import open_http
from mcp_cross_exam.transport.stdio import open_stdio

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
    cwd: str | None = None
    env: tuple[str, ...] = ()
    env_from: tuple[str, ...] = ()
    bearer_env: str | None = None
    header_env: tuple[str, ...] = ()
    ca_bundle: str | None = None
    protocol_version: str | None = None


_stdio_command: ContextVar[tuple[str, ...] | None] = ContextVar("stdio_command", default=None)


_VALUE_OPTIONS = {
    "--sse",
    "--cwd",
    "--env",
    "--env-from",
    "--bearer-env",
    "--header-env",
    "--ca-bundle",
    "--protocol-version",
}


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


def _merge(left: str | None, right: str | None) -> str | None:
    if left is not None and right is not None and left != right:
        raise UsageFailure("conflicting transport flags")
    return right if right is not None else left


def _combine(parent: Flags | None, local: Flags) -> Flags:
    if parent is None:
        return local
    return Flags(
        version=parent.version or local.version,
        as_json=parent.as_json or local.as_json,
        quiet=parent.quiet or local.quiet,
        no_color=parent.no_color or local.no_color,
        exit_zero=parent.exit_zero or local.exit_zero,
        sse=_merge(parent.sse, local.sse),
        cwd=_merge(parent.cwd, local.cwd),
        env=parent.env + local.env,
        env_from=parent.env_from + local.env_from,
        bearer_env=_merge(parent.bearer_env, local.bearer_env),
        header_env=parent.header_env + local.header_env,
        ca_bundle=_merge(parent.ca_bundle, local.ca_bundle),
        protocol_version=_merge(parent.protocol_version, local.protocol_version),
    )


def _is_empty(flags: Flags, endpoint: str | None, command: tuple[str, ...] | None) -> bool:
    return (
        endpoint is None
        and command is None
        and flags.sse is None
        and flags.cwd is None
        and not flags.env
        and not flags.env_from
        and flags.bearer_env is None
        and not flags.header_env
        and flags.ca_bundle is None
        and flags.protocol_version is None
        and not flags.version
        and not flags.as_json
        and not flags.quiet
        and not flags.no_color
        and not flags.exit_zero
    )


def _validate(flags: Flags, endpoint: str | None, command: tuple[str, ...] | None) -> None:
    parse_target(endpoint, flags.sse, command)
    stdio_only = flags.cwd is not None or bool(flags.env) or bool(flags.env_from)
    http_only = (
        flags.bearer_env is not None or bool(flags.header_env) or flags.ca_bundle is not None
    )
    if command is not None and http_only:
        raise UsageFailure("http options require an http endpoint")
    if command is None and stdio_only:
        raise UsageFailure("stdio options require a stdio command")
    if flags.protocol_version is not None and flags.protocol_version not in OFFERED_VERSIONS:
        raise UsageFailure("unsupported protocol version")
    for item in flags.env:
        if "=" not in item or item.startswith("="):
            raise UsageFailure("expected KEY=VALUE")
    for name in flags.env_from:
        if name not in os.environ:
            raise UsageFailure(f"environment variable {name} is not set")
    if flags.bearer_env is not None:
        _env_value(flags.bearer_env)
    for item in flags.header_env:
        if "=" not in item or item.startswith("="):
            raise UsageFailure("expected Header=ENV")
        header, env_name = item.split("=", 1)
        if not header or any(char in header for char in "\r\n"):
            raise UsageFailure("expected Header=ENV")
        _env_value(env_name)
    if flags.ca_bundle is not None and not Path(flags.ca_bundle).is_file():
        raise UsageFailure("ca bundle not found")
    if flags.cwd is not None and not Path(flags.cwd).is_dir():
        raise UsageFailure("cwd not found")


def _env_value(name: str) -> str:
    if name not in os.environ:
        raise UsageFailure(f"environment variable {name} is not set")
    value = os.environ[name]
    if "\n" in value or "\r" in value:
        raise UsageFailure("header value is invalid")
    return value


def _child_env(flags: Flags) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in flags.env:
        key, value = item.split("=", 1)
        values[key] = value
    for name in flags.env_from:
        values[name] = os.environ[name]
    return values


def _header_values(flags: Flags) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in flags.header_env:
        header, env_name = item.split("=", 1)
        headers[header] = os.environ[env_name]
    return headers


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


def _open_transport(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
    run_dir: Path,
) -> Transport:
    if command is not None:
        return open_stdio(
            command,
            cwd=flags.cwd,
            env=_child_env(flags),
            protocol_version=flags.protocol_version,
            run_dir=run_dir,
        )
    url = flags.sse if flags.sse is not None else endpoint
    if url is None:
        raise UsageFailure("missing endpoint")
    verify: bool | str = flags.ca_bundle if flags.ca_bundle is not None else True
    bearer = _env_value(flags.bearer_env) if flags.bearer_env is not None else None
    return open_http(
        url,
        legacy=flags.sse is not None,
        bearer=bearer,
        headers=_header_values(flags),
        verify=verify,
        protocol_version=flags.protocol_version,
        run_dir=run_dir,
    )


async def _audit(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
) -> ExitCode:
    run_dir = Path(tempfile.mkdtemp(prefix="mcp-cross-exam-"))
    transport = _open_transport(flags, endpoint, command, run_dir)
    try:
        context = await transport.connect()
        if not flags.quiet:
            console = console_for(no_color=flags.no_color)
            for finding in context.findings:
                console.print(
                    f"{finding.severity} {finding.item_id}: {finding.summary}",
                    highlight=False,
                )
        if any(item.severity == "medium" for item in context.findings):
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS
    finally:
        await transport.close()


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
        _validate(flags, endpoint, command)
    except UsageFailure as exc:
        console_for(no_color=flags.no_color).print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    try:
        code = anyio.run(_audit, flags, endpoint, command)
    except TransportFailure as exc:
        console_for(no_color=flags.no_color).print(str(exc), highlight=False)
        exit_with(ExitCode.UNREACHABLE)
    exit_with(code)


def _tuple(values: list[str] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(values)


def _flags_from(
    *,
    version: bool,
    as_json: bool,
    quiet: bool,
    no_color: bool,
    exit_zero: bool,
    sse: str | None,
    cwd: str | None,
    env: list[str] | None,
    env_from: list[str] | None,
    bearer_env: str | None,
    header_env: list[str] | None,
    ca_bundle: str | None,
    protocol_version: str | None,
) -> Flags:
    return Flags(
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
        sse=sse,
        cwd=cwd,
        env=_tuple(env),
        env_from=_tuple(env_from),
        bearer_env=bearer_env,
        header_env=_tuple(header_env),
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
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
    cwd: Annotated[
        str | None, typer.Option("--cwd", help="Working directory for a stdio command.")
    ] = None,
    env: Annotated[
        list[str] | None, typer.Option("--env", help="Set KEY=VALUE for a stdio command.")
    ] = None,
    env_from: Annotated[
        list[str] | None,
        typer.Option("--env-from", help="Copy an environment variable into a stdio command."),
    ] = None,
    bearer_env: Annotated[
        str | None,
        typer.Option("--bearer-env", help="Environment variable holding a bearer token."),
    ] = None,
    header_env: Annotated[
        list[str] | None,
        typer.Option("--header-env", help="Send Header from an environment variable (Header=ENV)."),
    ] = None,
    ca_bundle: Annotated[str | None, typer.Option("--ca-bundle", help="CA bundle for TLS.")] = None,
    protocol_version: Annotated[
        str | None,
        typer.Option("--protocol-version", help="Offer only this protocol revision."),
    ] = None,
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
        sse=sse,
        cwd=cwd,
        env=env,
        env_from=env_from,
        bearer_env=bearer_env,
        header_env=header_env,
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
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
    cwd: Annotated[
        str | None, typer.Option("--cwd", help="Working directory for a stdio command.")
    ] = None,
    env: Annotated[
        list[str] | None, typer.Option("--env", help="Set KEY=VALUE for a stdio command.")
    ] = None,
    env_from: Annotated[
        list[str] | None,
        typer.Option("--env-from", help="Copy an environment variable into a stdio command."),
    ] = None,
    bearer_env: Annotated[
        str | None,
        typer.Option("--bearer-env", help="Environment variable holding a bearer token."),
    ] = None,
    header_env: Annotated[
        list[str] | None,
        typer.Option("--header-env", help="Send Header from an environment variable (Header=ENV)."),
    ] = None,
    ca_bundle: Annotated[str | None, typer.Option("--ca-bundle", help="CA bundle for TLS.")] = None,
    protocol_version: Annotated[
        str | None,
        typer.Option("--protocol-version", help="Offer only this protocol revision."),
    ] = None,
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
        sse=sse,
        cwd=cwd,
        env=env,
        env_from=env_from,
        bearer_env=bearer_env,
        header_env=header_env,
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
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
