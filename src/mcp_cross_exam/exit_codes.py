from __future__ import annotations

from contextvars import ContextVar
from enum import IntEnum
from typing import NoReturn


class ExitCode(IntEnum):
    SUCCESS = 0
    INTERNAL = 1
    CONFIG = 2
    FINDINGS = 3
    UNREACHABLE = 4
    INTERRUPTED = 130


EXIT_MEANINGS: dict[ExitCode, str] = {
    ExitCode.SUCCESS: "No findings at or above the fail-on severity",
    ExitCode.INTERNAL: "Internal error",
    ExitCode.CONFIG: "Usage or config error, including the production guard",
    ExitCode.FINDINGS: "Findings at or above the fail-on severity",
    ExitCode.UNREACHABLE: (
        "Target unreachable, or the connection or handshake failed before any probe ran"
    ),
    ExitCode.INTERRUPTED: "Interrupted",
}


_exit_zero: ContextVar[bool] = ContextVar("exit_zero", default=False)


def set_exit_zero(enabled: bool) -> None:
    _exit_zero.set(enabled)


def exit_with(code: ExitCode) -> NoReturn:
    if code is ExitCode.FINDINGS and _exit_zero.get():
        raise SystemExit(ExitCode.SUCCESS)
    raise SystemExit(code)
