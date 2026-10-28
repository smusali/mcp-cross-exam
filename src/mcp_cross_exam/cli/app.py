from __future__ import annotations

import hashlib
import json
import os
import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated, NoReturn
from urllib.parse import urlsplit

import anyio
import typer
from rich.console import Console

from mcp_cross_exam import version_facts
from mcp_cross_exam.cli.session import open_session
from mcp_cross_exam.config import (
    ConfigError,
    Settings,
    dump_settings,
    init_document,
    load_settings,
)
from mcp_cross_exam.evidence import (
    expected_payload,
    request_method,
    request_params,
    sweep_tree,
    transcript_pairs,
)
from mcp_cross_exam.exit_codes import ExitCode, exit_with, set_exit_zero
from mcp_cross_exam.findings import SEVERITY_RANK
from mcp_cross_exam.guard import TargetDecision, decide
from mcp_cross_exam.probes.base import Probe, ProbeContext, RunBudget
from mcp_cross_exam.probes.schema import collect_definitions
from mcp_cross_exam.report import publish, timestamp
from mcp_cross_exam.runner import (
    SelectionError,
    UnknownTool,
    classify_listed,
    examine,
    list_payload,
    list_text,
    load_probes,
    plan_lines,
    select_probes,
)
from mcp_cross_exam.schema_audit import write_snapshot
from mcp_cross_exam.transport import OFFERED_VERSIONS, RunContext, Transport, TransportFailure
from mcp_cross_exam.transport.base import JsonValue, json_value


class _DefaultRun(typer.core.TyperGroup):
    def resolve_command(
        self, ctx: typer._click.core.Context, args: list[str]
    ) -> tuple[str | None, typer._click.core.Command | None, list[str]]:
        return super().resolve_command(ctx, _insert_run(self, ctx, list(args)))


def _insert_run(
    group: typer.core.TyperGroup, ctx: typer._click.core.Context, argv: list[str]
) -> list[str]:
    if not argv or argv in (["-h"], ["--help"]):
        return argv
    if any(token in group.commands for token in argv):
        return argv
    valued = _valued_options(group, ctx)
    routed: list[str] = []
    index = 0
    inserted = False
    while index < len(argv):
        token = argv[index]
        if token in valued:
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


def _valued_options(group: typer.core.TyperGroup, ctx: typer._click.core.Context) -> set[str]:
    command = group.get_command(ctx, "run")
    if command is None:
        return set()
    found: set[str] = set()
    for param in command.params:
        opts = getattr(param, "opts", None)
        if not opts or getattr(param, "is_flag", False):
            continue
        found.update(opt for opt in opts if isinstance(opt, str))
    return found


app = typer.Typer(
    cls=_DefaultRun,
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
    expired_bearer_env: str | None = None
    header_env: tuple[str, ...] = ()
    ca_bundle: str | None = None
    protocol_version: str | None = None
    probe: tuple[str, ...] = ()
    family: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()
    seed: int | None = None
    tool: str | None = None
    jobs: int = 4
    config: str | None = None
    read_only: bool = False
    allow_writes: bool = False
    target_is_not_production: bool = False
    fail_on_incomplete: bool = False
    fail_on: str = "high"
    out_dir: str | None = None
    snapshot: str | None = None


_stdio_command: ContextVar[tuple[str, ...] | None] = ContextVar("stdio_command", default=None)


def split_stdio(argv: list[str]) -> tuple[list[str], tuple[str, ...] | None]:
    if "--" not in argv:
        return argv, None
    index = argv.index("--")
    return argv[:index], tuple(argv[index + 1 :])


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
    return list(ctx.args)


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
        expired_bearer_env=_merge(parent.expired_bearer_env, local.expired_bearer_env),
        header_env=parent.header_env + local.header_env,
        ca_bundle=_merge(parent.ca_bundle, local.ca_bundle),
        protocol_version=_merge(parent.protocol_version, local.protocol_version),
        probe=parent.probe + local.probe,
        family=parent.family + local.family,
        skip=parent.skip + local.skip,
        seed=_merge_seed(parent.seed, local.seed),
        tool=_merge(parent.tool, local.tool),
        jobs=_merge_jobs(parent.jobs, local.jobs),
        config=_merge(parent.config, local.config),
        read_only=parent.read_only or local.read_only,
        allow_writes=parent.allow_writes or local.allow_writes,
        target_is_not_production=parent.target_is_not_production or local.target_is_not_production,
        fail_on_incomplete=parent.fail_on_incomplete or local.fail_on_incomplete,
        fail_on=_merge_fail_on(parent.fail_on, local.fail_on),
        out_dir=_merge(parent.out_dir, local.out_dir),
        snapshot=_merge(parent.snapshot, local.snapshot),
    )


def _merge_seed(left: int | None, right: int | None) -> int | None:
    if left is not None and right is not None and left != right:
        raise UsageFailure("conflicting flags")
    return right if right is not None else left


def _merge_fail_on(left: str, right: str) -> str:
    if left != right and left != "high" and right != "high":
        raise UsageFailure("conflicting flags")
    if right != "high":
        return right
    return left


def _merge_jobs(left: int, right: int) -> int:
    if left != right and left != 4 and right != 4:
        raise UsageFailure("conflicting flags")
    if right != 4:
        return right
    return left


def _is_empty(flags: Flags, endpoint: str | None, command: tuple[str, ...] | None) -> bool:
    return (
        endpoint is None
        and command is None
        and flags.sse is None
        and flags.cwd is None
        and not flags.env
        and not flags.env_from
        and flags.bearer_env is None
        and flags.expired_bearer_env is None
        and not flags.header_env
        and flags.ca_bundle is None
        and flags.protocol_version is None
        and not flags.probe
        and not flags.family
        and not flags.skip
        and flags.seed is None
        and flags.tool is None
        and flags.jobs == 4
        and flags.config is None
        and not flags.read_only
        and not flags.allow_writes
        and not flags.target_is_not_production
        and not flags.fail_on_incomplete
        and flags.snapshot is None
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
        flags.bearer_env is not None
        or flags.expired_bearer_env is not None
        or bool(flags.header_env)
        or flags.ca_bundle is not None
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
    if flags.expired_bearer_env is not None:
        _env_value(flags.expired_bearer_env)
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
    if flags.jobs < 1:
        raise UsageFailure("jobs must be at least 1")
    if flags.snapshot is not None and not Path(flags.snapshot).is_file():
        raise UsageFailure("snapshot not found")
    if flags.fail_on not in SEVERITY_RANK:
        raise UsageFailure("unsupported fail-on severity")
    if flags.out_dir is not None and not flags.out_dir.strip():
        raise UsageFailure("out dir is empty")


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


def console_for(*, no_color: bool, width: int | None = None) -> Console:
    forced = no_color or os.environ.get("NO_COLOR") is not None
    if width is None:
        return Console(stderr=True, no_color=forced)
    return Console(stderr=True, no_color=forced, width=width, highlight=False)


def emit_version(*, as_json: bool) -> None:
    facts = version_facts()
    if as_json:
        print(json.dumps(facts))
        return
    print(f"{facts['name']} {facts['version']}")
    print(f"mcp {facts['mcp_version']}")
    print(f"Python {facts['python_version']}")
    print(", ".join(facts["protocol_revisions"]))


async def _audit(chosen: Chosen) -> ExitCode:
    flags = chosen.flags
    run_id = uuid.uuid4().hex
    seed = flags.seed if flags.seed is not None else _derive_seed(run_id)
    run_dir = Path(flags.out_dir) if flags.out_dir else runs_root() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    secrets = _secrets(flags)
    started = timestamp()
    try:
        async with open_session(flags, chosen.endpoint, chosen.command, run_dir) as (
            transport,
            context,
        ):
            context.guard = chosen.decision.guard
            context.seed = seed
            context.run_id = run_id
            probe_ctx = _probe_context(chosen, transport, context, seed, secrets)
            console = console_for(no_color=flags.no_color, width=100)
            if chosen.plan:
                await classify_listed(probe_ctx)
                for line in plan_lines(probe_ctx, chosen.probes):
                    print(line)
                publish(
                    probe_ctx,
                    context.findings,
                    directory=run_dir,
                    started_at=started,
                    finished_at=timestamp(),
                    protocol_version=flags.protocol_version,
                    fail_on=flags.fail_on,
                    fail_on_incomplete=flags.fail_on_incomplete,
                    as_json=False,
                    quiet=True,
                    plan=True,
                    console=console,
                )
                return ExitCode.SUCCESS
            context.findings.extend(await examine(probe_ctx, chosen.probes))
            return publish(
                probe_ctx,
                context.findings,
                directory=run_dir,
                started_at=started,
                finished_at=timestamp(),
                protocol_version=flags.protocol_version,
                fail_on=flags.fail_on,
                fail_on_incomplete=flags.fail_on_incomplete,
                as_json=flags.as_json,
                quiet=flags.quiet,
                plan=False,
                console=console,
            )
    finally:
        sweep_tree(run_dir, secrets)


def execute(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
    *,
    plan: bool = False,
) -> None:
    set_exit_zero(flags.exit_zero)
    if flags.version:
        emit_version(as_json=flags.as_json)
        exit_with(ExitCode.SUCCESS)
    console = console_for(no_color=flags.no_color)
    try:
        chosen = _prepare(flags, endpoint, command, plan=plan)
    except (UsageFailure, ConfigError, SelectionError) as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    if not chosen.decision.allowed:
        console.print(chosen.decision.reason, highlight=False)
        exit_with(ExitCode.CONFIG)
    if chosen.decision.guard == "overridden":
        console.print('warning: target.guard = "overridden"', highlight=False)
    try:
        code = anyio.run(_audit, chosen)
    except TransportFailure as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.UNREACHABLE)
    except UnknownTool as exc:
        console.print(f"unknown tool {exc.name}", highlight=False)
        exit_with(ExitCode.CONFIG)
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
    expired_bearer_env: str | None,
    header_env: list[str] | None,
    ca_bundle: str | None,
    protocol_version: str | None,
    probe: list[str] | None = None,
    family: list[str] | None = None,
    skip: list[str] | None = None,
    seed: int | None = None,
    tool: str | None = None,
    jobs: int = 4,
    config: str | None = None,
    read_only: bool = False,
    allow_writes: bool = False,
    target_is_not_production: bool = False,
    fail_on_incomplete: bool = False,
    fail_on: str = "high",
    out_dir: str | None = None,
    snapshot: str | None = None,
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
        expired_bearer_env=expired_bearer_env,
        header_env=_tuple(header_env),
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
        probe=_tuple(probe),
        family=_tuple(family),
        skip=_tuple(skip),
        seed=seed,
        tool=tool,
        jobs=jobs,
        config=config,
        read_only=read_only,
        allow_writes=allow_writes,
        target_is_not_production=target_is_not_production,
        fail_on_incomplete=fail_on_incomplete,
        fail_on=fail_on,
        out_dir=out_dir,
        snapshot=snapshot,
    )


def runs_root() -> Path:
    override = os.environ.get("MCP_CROSS_EXAM_RUNS")
    if override:
        return Path(override)
    return Path.cwd() / ".mcp-cross-exam" / "runs"


def _derive_seed(run_id: str) -> int:
    return int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:4], "big")


@dataclass(frozen=True, slots=True)
class Chosen:
    flags: Flags
    settings: Settings
    endpoint: str | None
    command: tuple[str, ...] | None
    probes: tuple[Probe, ...]
    decision: TargetDecision
    plan: bool = False


def _prepare(
    flags: Flags,
    endpoint: str | None,
    command: tuple[str, ...] | None,
    *,
    plan: bool,
    select: bool = True,
) -> Chosen:
    settings = load_settings(Path(flags.config) if flags.config is not None else None)
    flags, endpoint, command = _targets(flags, settings, endpoint, command)
    flags = _apply_file(flags, settings)
    _validate(flags, endpoint, command)
    probes: tuple[Probe, ...] = ()
    if select:
        include = flags.probe if flags.probe else tuple(settings.probes.select)
        skip = flags.skip if flags.skip else tuple(settings.probes.skip)
        probes = select_probes(load_probes(), include=include, families=flags.family, skip=skip)
    decision = _decision(flags, settings, endpoint, command)
    return Chosen(flags, settings, endpoint, command, probes, decision, plan)


def _targets(
    flags: Flags,
    settings: Settings,
    endpoint: str | None,
    command: tuple[str, ...] | None,
) -> tuple[Flags, str | None, tuple[str, ...] | None]:
    if endpoint is not None or flags.sse is not None or command is not None:
        return flags, endpoint, command
    target = settings.target
    if target.url and target.command:
        raise ConfigError("target sets both url and command")
    if target.transport == "stdio" or (target.transport is None and target.command):
        if not target.command:
            raise ConfigError("target command is missing")
        return flags, None, tuple(target.command)
    if target.transport == "sse":
        if not target.url:
            raise ConfigError("target url is missing")
        return replace(flags, sse=target.url), None, None
    if target.url:
        return flags, target.url, None
    return flags, None, None


def _apply_file(flags: Flags, settings: Settings) -> Flags:
    headers = flags.header_env
    if not headers and settings.auth.header_env:
        headers = tuple(f"{key}={value}" for key, value in settings.auth.header_env.items())
    return replace(
        flags,
        bearer_env=flags.bearer_env or settings.auth.bearer_env,
        expired_bearer_env=flags.expired_bearer_env or settings.auth.expired_bearer_env,
        header_env=headers,
        protocol_version=flags.protocol_version or settings.target.protocol_version,
    )


def _decision(
    flags: Flags,
    settings: Settings,
    endpoint: str | None,
    command: tuple[str, ...] | None,
) -> TargetDecision:
    if command is not None:
        return decide(
            stdio=True,
            host=None,
            allow=settings.target.allow,
            override=flags.target_is_not_production,
        )
    url = flags.sse if flags.sse is not None else endpoint
    host = None if url is None else urlsplit(url).hostname
    return decide(
        stdio=False,
        host=host,
        allow=settings.target.allow,
        override=flags.target_is_not_production,
    )


def _probe_context(
    chosen: Chosen,
    transport: Transport,
    context: RunContext,
    seed: int,
    secrets: tuple[str, ...],
) -> ProbeContext:
    flags = chosen.flags
    expired = _env_value(flags.expired_bearer_env) if flags.expired_bearer_env is not None else None
    url = flags.sse if flags.sse is not None else chosen.endpoint
    effects = {
        name: hint.effect for name, hint in chosen.settings.tools.items() if hint.effect is not None
    }
    budget = chosen.settings.budget
    return ProbeContext(
        transport=transport,
        run=context,
        http=chosen.command is None,
        endpoint=url,
        expired_bearer=expired,
        legacy=flags.sse is not None,
        target_name=chosen.settings.probes.target_tool,
        budget=RunBudget(
            wall_clock_s=budget.wall_clock_s,
            max_calls_per_tool=budget.max_calls_per_tool,
            call_timeout_s=budget.call_timeout_s,
        ),
        effects=effects,
        scopes={
            name: hint.scope
            for name, hint in chosen.settings.tools.items()
            if hint.scope is not None
        },
        severities=dict(chosen.settings.probes.severity),
        guard=chosen.decision.guard,
        seed=seed,
        read_only=flags.read_only,
        allow_writes=flags.allow_writes,
        jobs=flags.jobs,
        secrets=secrets,
        bearer_env=flags.bearer_env,
        expired_bearer_env=flags.expired_bearer_env,
        header_envs=_header_envs(flags),
        command=chosen.command,
        only_tool=flags.tool,
        arguments=_arguments(chosen.settings),
        observers=_observers(chosen.settings),
        snapshot=flags.snapshot,
    )


def _arguments(settings: Settings) -> dict[str, dict[str, JsonValue]]:
    arguments: dict[str, dict[str, JsonValue]] = {}
    for name, hint in settings.tools.items():
        if hint.args is None:
            continue
        arguments[name] = {key: json_value(item) for key, item in hint.args.items()}
    return arguments


def _observers(settings: Settings) -> dict[str, str]:
    return {
        name: hint.observer for name, hint in settings.tools.items() if hint.observer is not None
    }


def _secrets(flags: Flags) -> tuple[str, ...]:
    values: list[str] = []
    if flags.bearer_env is not None:
        values.append(_env_value(flags.bearer_env))
    if flags.expired_bearer_env is not None:
        values.append(_env_value(flags.expired_bearer_env))
    values.extend(_header_values(flags).values())
    values.extend(_child_env(flags).values())
    return tuple(item for item in values if len(item) >= 8)


def _header_envs(flags: Flags) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in flags.header_env:
        header, env_name = item.split("=", 1)
        headers[header] = env_name
    return headers


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
    expired_bearer_env: Annotated[
        str | None,
        typer.Option(
            "--expired-bearer-env",
            help="Environment variable holding an expired bearer token.",
        ),
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
    probe: Annotated[
        list[str] | None,
        typer.Option("--probe", help="Run probes whose ids match this glob."),
    ] = None,
    family: Annotated[
        list[str] | None, typer.Option("--family", help="Run probes in this family.")
    ] = None,
    skip: Annotated[list[str] | None, typer.Option("--skip", help="Skip this probe id.")] = None,
    seed: Annotated[int | None, typer.Option("--seed", help="Seed the run.")] = None,
    tool: Annotated[str | None, typer.Option("--tool", help="Limit the audit to one tool.")] = None,
    jobs: Annotated[int, typer.Option("--jobs", help="How many tools to examine at once.")] = 4,
    config: Annotated[str | None, typer.Option("--config", help="Config file.")] = None,
    read_only: Annotated[
        bool, typer.Option("--read-only", help="Skip write and destructive calls.")
    ] = False,
    allow_writes: Annotated[
        bool,
        typer.Option("--allow-writes", help="Allow writes when the guard is overridden."),
    ] = False,
    target_is_not_production: Annotated[
        bool,
        typer.Option(
            "--target-is-not-production",
            help="Audit an allow-listed host that is not production.",
        ),
    ] = False,
    fail_on_incomplete: Annotated[
        bool,
        typer.Option("--fail-on-incomplete", help="Exit 3 when the run is partial."),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Fail when a finding is at or above this severity."),
    ] = "high",
    out_dir: Annotated[
        str | None,
        typer.Option("--out-dir", help="Directory for the report, evidence, and transcripts."),
    ] = None,
    snapshot: Annotated[
        str | None,
        typer.Option("--snapshot", help="Compare tool definitions with this snapshot."),
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
        expired_bearer_env=expired_bearer_env,
        header_env=header_env,
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
        probe=probe,
        family=family,
        skip=skip,
        seed=seed,
        tool=tool,
        jobs=jobs,
        config=config,
        read_only=read_only,
        allow_writes=allow_writes,
        target_is_not_production=target_is_not_production,
        fail_on_incomplete=fail_on_incomplete,
        fail_on=fail_on,
        out_dir=out_dir,
        snapshot=snapshot,
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


def _parent(ctx: typer.Context) -> Flags | None:
    if isinstance(ctx.obj, Flags):
        return ctx.obj
    return None


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
    expired_bearer_env: Annotated[
        str | None,
        typer.Option(
            "--expired-bearer-env",
            help="Environment variable holding an expired bearer token.",
        ),
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
    probe: Annotated[
        list[str] | None,
        typer.Option("--probe", help="Run probes whose ids match this glob."),
    ] = None,
    family: Annotated[
        list[str] | None, typer.Option("--family", help="Run probes in this family.")
    ] = None,
    skip: Annotated[list[str] | None, typer.Option("--skip", help="Skip this probe id.")] = None,
    seed: Annotated[int | None, typer.Option("--seed", help="Seed the run.")] = None,
    tool: Annotated[str | None, typer.Option("--tool", help="Limit the audit to one tool.")] = None,
    jobs: Annotated[int, typer.Option("--jobs", help="How many tools to examine at once.")] = 4,
    config: Annotated[str | None, typer.Option("--config", help="Config file.")] = None,
    read_only: Annotated[
        bool, typer.Option("--read-only", help="Skip write and destructive calls.")
    ] = False,
    allow_writes: Annotated[
        bool,
        typer.Option("--allow-writes", help="Allow writes when the guard is overridden."),
    ] = False,
    target_is_not_production: Annotated[
        bool,
        typer.Option(
            "--target-is-not-production",
            help="Audit an allow-listed host that is not production.",
        ),
    ] = False,
    fail_on_incomplete: Annotated[
        bool,
        typer.Option("--fail-on-incomplete", help="Exit 3 when the run is partial."),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Fail when a finding is at or above this severity."),
    ] = "high",
    out_dir: Annotated[
        str | None,
        typer.Option("--out-dir", help="Directory for the report, evidence, and transcripts."),
    ] = None,
    snapshot: Annotated[
        str | None,
        typer.Option("--snapshot", help="Compare tool definitions with this snapshot."),
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
        expired_bearer_env=expired_bearer_env,
        header_env=header_env,
        ca_bundle=ca_bundle,
        protocol_version=protocol_version,
        probe=probe,
        family=family,
        skip=skip,
        seed=seed,
        tool=tool,
        jobs=jobs,
        config=config,
        read_only=read_only,
        allow_writes=allow_writes,
        target_is_not_production=target_is_not_production,
        fail_on_incomplete=fail_on_incomplete,
        fail_on=fail_on,
        out_dir=out_dir,
        snapshot=snapshot,
        version=version,
        as_json=as_json,
        quiet=quiet,
        no_color=no_color,
        exit_zero=exit_zero,
    )
    parent = _parent(ctx)
    try:
        flags = _combine(parent, local)
    except UsageFailure as exc:
        _fail(local, exc)
    execute(flags, endpoint, _stdio_command.get())


fixture_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="Run the bundled fixture server.",
)
app.add_typer(fixture_app, name="fixture")


@fixture_app.command(help="Serve the fixture over stdio, streamable HTTP, or legacy SSE.")
def serve(
    stdio: Annotated[bool, typer.Option("--stdio", help="Speak MCP on standard input.")] = False,
    http: Annotated[
        str | None,
        typer.Option("--http", help="Listen on HOST:PORT for streamable HTTP."),
    ] = None,
    sse: Annotated[
        str | None,
        typer.Option("--sse", help="Listen on HOST:PORT for legacy HTTP+SSE."),
    ] = None,
    era: Annotated[str, typer.Option("--era", help="Protocol revision to speak.")] = "2025-11-25",
    defects: Annotated[
        str,
        typer.Option("--defects", help="Comma-separated probe ids, all, or none."),
    ] = "session.expired-empty-success,schema.undeclared-required-arg",
    clean: Annotated[bool, typer.Option("--clean", help="Enable no defects.")] = False,
    token_ttl_s: Annotated[
        float | None,
        typer.Option("--token-ttl-s", help="Seconds before the valid bearer expires."),
    ] = None,
) -> None:
    from mcp_cross_exam.fixture import (
        FixtureError,
        parse_bind,
        parse_defects,
        parse_era,
        parse_ttl,
        serve_http,
        serve_stdio,
    )

    try:
        chosen = parse_era(era)
        selected = parse_defects(defects, clean=clean)
        ttl = parse_ttl(token_ttl_s)
        modes = (stdio, http is not None, sse is not None)
        if sum(modes) != 1:
            raise FixtureError("choose one of --stdio, --http, or --sse")
    except FixtureError as exc:
        _fixture_fail(str(exc))
    if stdio:
        serve_stdio(chosen, selected, token_ttl_s=ttl)
        return
    address = http if http is not None else sse
    if address is None:
        _fixture_fail("choose one of --stdio, --http, or --sse")
    try:
        host, port = parse_bind(address)
    except FixtureError as exc:
        _fixture_fail(str(exc))
    serve_http(host, port, era=chosen, defects=selected, token_ttl_s=ttl)


@fixture_app.command("mint-token", help="Print a bearer token the fixture accepts.")
def mint_token(
    expired: Annotated[bool, typer.Option("--expired", help="Print the expired token.")] = False,
) -> None:
    from mcp_cross_exam.fixture import EXPIRED_TOKEN, VALID_TOKEN

    print(EXPIRED_TOKEN if expired else VALID_TOKEN)
    exit_with(ExitCode.SUCCESS)


snapshot_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="Write a canonical tool snapshot.",
)
app.add_typer(snapshot_app, name="snapshot")


@snapshot_app.command("write", help="List tools and write a snapshot file.")
def snapshot_write(
    ctx: typer.Context,
    endpoint: Annotated[str | None, typer.Argument(help="Streamable HTTP endpoint.")] = None,
    out: Annotated[
        str,
        typer.Option("--out", help="Snapshot path."),
    ] = "mcp-cross-exam.tools.json",
) -> None:
    flags = _parent(ctx) or Flags()
    console = console_for(no_color=flags.no_color)
    try:
        chosen = _prepare(flags, endpoint, _stdio_command.get(), plan=False, select=False)
    except (UsageFailure, ConfigError, SelectionError) as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    if not chosen.decision.allowed:
        console.print(chosen.decision.reason, highlight=False)
        exit_with(ExitCode.CONFIG)
    try:
        anyio.run(_write_tools, chosen, Path(out))
    except TransportFailure as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.UNREACHABLE)
    except OSError as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    exit_with(ExitCode.SUCCESS)


async def _write_tools(chosen: Chosen, destination: Path) -> None:
    flags = chosen.flags
    run_id = uuid.uuid4().hex
    run_dir = runs_root() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    secrets = _secrets(flags)
    try:
        async with open_session(flags, chosen.endpoint, chosen.command, run_dir) as (
            transport,
            _context,
        ):
            write_snapshot(destination, await collect_definitions(transport))
    finally:
        sweep_tree(run_dir, secrets)


probes_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="List and plan probes.",
)
app.add_typer(probes_app, name="probes")

config_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="Show and write config.",
)
app.add_typer(config_app, name="config")


@probes_app.command("list", help="Print the registered probes.")
def probes_list(
    ctx: typer.Context,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    parent = _parent(ctx)
    rows = load_probes()
    from mcp_cross_exam.fixture import DEFECT_IDS

    missing = [item for item in DEFECT_IDS if item not in {probe.id for probe in rows}]
    if missing:
        raise RuntimeError("defect ids missing from the probe registry")
    if as_json or (parent is not None and parent.as_json):
        print(json.dumps(list_payload(rows)))
    else:
        print(list_text(rows), end="")
    exit_with(ExitCode.SUCCESS)


@probes_app.command("plan", help="Show which probes would run. Does not call tools.")
def probes_plan(
    ctx: typer.Context,
    endpoint: Annotated[str | None, typer.Argument(help="Streamable HTTP endpoint.")] = None,
) -> None:
    execute(_parent(ctx) or Flags(), endpoint, _stdio_command.get(), plan=True)


@config_app.command("show", help="Print the effective config. Secrets stay as env names.")
def config_show(
    ctx: typer.Context,
    config: Annotated[str | None, typer.Option("--config", help="Config file.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    parent = _parent(ctx)
    chosen = config
    if chosen is None and parent is not None:
        chosen = parent.config
    use_json = as_json or (parent is not None and parent.as_json)
    console = console_for(no_color=False if parent is None else parent.no_color)
    try:
        settings = load_settings(Path(chosen) if chosen is not None else None)
    except ConfigError as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    payload = dump_settings(settings)
    print(json.dumps(payload, indent=None if use_json else 2, sort_keys=True))
    exit_with(ExitCode.SUCCESS)


@config_app.command("init", help="Write a commented config from tools/list.")
def config_init(
    ctx: typer.Context,
    endpoint: Annotated[str | None, typer.Argument(help="Streamable HTTP endpoint.")] = None,
) -> None:
    flags = _parent(ctx) or Flags()
    destination = Path.cwd() / "mcp-cross-exam.toml"
    console = console_for(no_color=flags.no_color)
    if destination.exists():
        console.print("config already exists", highlight=False)
        exit_with(ExitCode.CONFIG)
    try:
        chosen = _prepare(flags, endpoint, _stdio_command.get(), plan=False, select=False)
    except (UsageFailure, ConfigError, SelectionError) as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    if not chosen.decision.allowed:
        console.print(chosen.decision.reason, highlight=False)
        exit_with(ExitCode.CONFIG)
    try:
        anyio.run(_write_config, chosen, destination)
    except TransportFailure as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.UNREACHABLE)
    except UnknownTool as exc:
        console.print(f"unknown tool {exc.name}", highlight=False)
        exit_with(ExitCode.CONFIG)
    exit_with(ExitCode.SUCCESS)


@app.command("replay", help="Send a transcript and diff the result bodies.")
def replay_cmd(
    ctx: typer.Context,
    transcript: Annotated[str, typer.Argument(help="JSON-RPC JSONL transcript.")],
    endpoint: Annotated[str, typer.Argument(help="Streamable HTTP endpoint.")],
) -> None:
    flags = _parent(ctx) or Flags()
    console = console_for(no_color=flags.no_color)
    path = Path(transcript)
    try:
        pairs = transcript_pairs(path.read_text(encoding="utf-8"))
        chosen = _prepare(flags, endpoint, None, plan=False, select=False)
    except (OSError, ValueError, UsageFailure, ConfigError, SelectionError) as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.CONFIG)
    if not chosen.decision.allowed:
        console.print(chosen.decision.reason, highlight=False)
        exit_with(ExitCode.CONFIG)
    try:
        code = anyio.run(_replay, chosen, pairs)
    except TransportFailure as exc:
        console.print(str(exc), highlight=False)
        exit_with(ExitCode.UNREACHABLE)
    exit_with(code)


async def _write_config(chosen: Chosen, destination: Path) -> None:
    flags = chosen.flags
    run_id = uuid.uuid4().hex
    run_dir = runs_root() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    secrets = _secrets(flags)
    try:
        async with open_session(flags, chosen.endpoint, chosen.command, run_dir) as (
            transport,
            context,
        ):
            context.guard = chosen.decision.guard
            probe_ctx = _probe_context(chosen, transport, context, flags.seed or 0, secrets)
            await classify_listed(probe_ctx)
            tools = [
                (item.tool.name, item.effect, item.source) for item in probe_ctx.classifications
            ]
            destination.write_text(init_document(tools), encoding="utf-8")
    finally:
        sweep_tree(run_dir, secrets)


async def _replay(
    chosen: Chosen,
    pairs: list[tuple[dict[str, JsonValue], dict[str, JsonValue] | None]],
) -> ExitCode:
    flags = chosen.flags
    endpoint = chosen.endpoint
    if endpoint is None:
        return ExitCode.CONFIG
    run_id = uuid.uuid4().hex
    run_dir = runs_root() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    secrets = _secrets(flags)
    console = console_for(no_color=flags.no_color)
    try:
        async with open_session(flags, endpoint, None, run_dir) as (transport, _context):
            for request, expected in pairs:
                method = request_method(request)
                if method is None:
                    console.print("transcript line is not a request", highlight=False)
                    return ExitCode.FINDINGS
                actual = await transport.request(method, request_params(request))
                if expected is None:
                    continue
                if actual != expected_payload(expected):
                    console.print(f"{method} differed", highlight=False)
                    return ExitCode.FINDINGS
            return ExitCode.SUCCESS
    finally:
        sweep_tree(run_dir, secrets)


def _fixture_fail(message: str) -> NoReturn:
    console_for(no_color=False).print(message, highlight=False)
    exit_with(ExitCode.CONFIG)


def dispatch(argv: list[str]) -> None:
    left, command = split_stdio(argv)
    token = _stdio_command.set(command)
    try:
        app(args=left, standalone_mode=False, prog_name="mcp-cross-exam")
    finally:
        _stdio_command.reset(token)


def bind_stdio(argv: list[str]) -> tuple[list[str], Token[tuple[str, ...] | None]]:
    left, command = split_stdio(argv)
    return left, _stdio_command.set(command)


def release_stdio(token: Token[tuple[str, ...] | None]) -> None:
    _stdio_command.reset(token)
