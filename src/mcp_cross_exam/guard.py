from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True, slots=True)
class TargetDecision:
    allowed: bool
    guard: str
    reason: str


Resolver = Callable[[str], tuple[str, ...] | None]


def decide(
    *,
    stdio: bool,
    host: str | None,
    allow: Sequence[str] = (),
    override: bool = False,
    resolve: Resolver | None = None,
) -> TargetDecision:
    if stdio:
        return TargetDecision(True, "local", "")
    if host is None or not host:
        return TargetDecision(False, "", "refused: missing host")
    addresses = _addresses(host, resolve if resolve is not None else resolve_host)
    if addresses is None:
        return TargetDecision(False, "", "refused: host did not resolve")
    listed = _listed(host, allow)
    if listed and override:
        return TargetDecision(True, "overridden", "")
    if addresses and all(_loopback(item) for item in addresses):
        return TargetDecision(True, "local", "")
    if listed:
        return TargetDecision(True, "allow", "")
    if override:
        return TargetDecision(
            False,
            "",
            "refused: --target-is-not-production requires a matching allow entry",
        )
    return TargetDecision(False, "", "refused: host is not loopback and is not in the allow list")


def resolve_host(host: str) -> tuple[str, ...] | None:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        address = sockaddr[0]
        if isinstance(address, str):
            bare = address.split("%", 1)[0]
            if bare not in found:
                found.append(bare)
    if not found:
        return None
    return tuple(found)


def _addresses(host: str, resolve: Resolver) -> tuple[str, ...] | None:
    literal = _literal(host)
    if literal is not None:
        return (literal,)
    return resolve(host)


def _literal(host: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(parsed)


def _loopback(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    if mapped is not None:
        parsed = mapped
    return bool(parsed.is_loopback)


def _listed(host: str, allow: Sequence[str]) -> bool:
    folded = host.casefold()
    return any(bool(pattern) and fnmatchcase(folded, pattern.casefold()) for pattern in allow)
