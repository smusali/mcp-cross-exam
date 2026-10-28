# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-28

### Added

- `mcp-cross-exam <endpoint>` audits one MCP server over stdio, streamable HTTP, or legacy HTTP+SSE.
- Transport and session probes check negotiation, capabilities, reconnects, stream resume, and expired sessions.
- Schema probes compare tool definitions, arguments, errors, and descriptions with what the server does.
- A production guard refuses any host that is not loopback and not in `[target] allow`.
- Each run writes a scored `report.json`, a static `report.html`, and redacted evidence.
- `--fail-on` and documented exit codes let a CI job fail on findings.
- `probes`, `config`, `snapshot`, and `replay` subcommands plan, configure, pin, and repeat an audit.
- `fixture serve` defaults to the two demo findings, and `--clean` serves none.
- PyPI releases carry provenance attestations.
