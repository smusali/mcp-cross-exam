# mcp-cross-exam

Audit MCP servers by cross-examining them.

Built because it was needed while running MCP connectors in production. `0.1.0` is the probe set that makes that demo work, not a product.

## Why this exists

Five failures showed up on the wire, across time, where unit tests stay green:

1. Session auth expires mid-conversation. The tool returns 200 with an empty payload and the agent silently degrades. `0.1.0` probes this.
2. A timeout triggers a retry and the write lands twice.
3. The tool description drifts from behavior, so the model calls the right tool with the wrong arguments and gets a plausible wrong answer. `0.1.0` probes this.
4. PII flows into logs, traces and error strings.
5. A tool blocks for 90 seconds with no timeout contract, and the agent has no way to cancel.

## What it does

`mcp-cross-exam <endpoint>` connects and cross-examines one server. Three transports are accepted:

- an `http://` or `https://` URL for streamable HTTP
- `--sse URL` for the deprecated HTTP+SSE transport
- `-- <command> [args...]` for stdio

`0.1.0` has two probe families:

- Transport and session: <https://github.com/smusali/mcp-cross-exam/issues/18>
- Schema integrity: <https://github.com/smusali/mcp-cross-exam/issues/4>

`mcp-cross-exam run <endpoint>` is the same audit. `mcp-cross-exam --version` prints the tool version, the MCP SDK version, the Python version, and the protocol revisions this tool can speak.

## Quick start

The bundled fixture server is not in this revision. When it lands, the demo is:

```sh
mcp-cross-exam fixture serve --http 127.0.0.1:8765
mcp-cross-exam http://127.0.0.1:8765/mcp
```

Until then, install the package and read the command help:

```sh
uv sync --extra dev
uv run mcp-cross-exam --help
```

## Non-goals

Not a pentest. Not a load tester. Not a proxy or gateway. No hosted SaaS in v1.

## Safety

The runner refuses production targets by default. Writes happen only against allowlisted targets. Credentials are read from the environment and redacted from every artifact.

That runner is not in this revision, so the guard is not enforced yet. A valid endpoint is parsed and the process exits without opening a connection.

## Status

This revision is the package, the command, and CI. Neither probe family is implemented yet.
