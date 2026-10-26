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


_exit_zero: ContextVar[bool] = ContextVar("exit_zero", default=False)


def set_exit_zero(enabled: bool) -> None:
    _exit_zero.set(enabled)


def exit_with(code: ExitCode) -> NoReturn:
    if code is ExitCode.FINDINGS and _exit_zero.get():
        raise SystemExit(ExitCode.SUCCESS)
    raise SystemExit(code)
