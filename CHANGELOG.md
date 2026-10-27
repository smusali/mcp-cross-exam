# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Package metadata, the `mcp-cross-exam` command, and version facts for the tool, the MCP SDK, and the supported protocol revisions.
- A command-line skeleton with shared exit codes for CI.
- Offline tests, lint, type checks, and a release workflow that publishes to PyPI with attestations.
- A transport that connects over stdio, streamable HTTP, and legacy HTTP+SSE, records each frame, and negotiates the protocol revision.
- Transport and session probes for protocol negotiation, reconnect, SSE resume, and session or bearer expiry, plus a fixture server that can reproduce each one.
