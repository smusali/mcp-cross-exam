# mcp-cross-exam

Audit one MCP server and write a scored report.

## Install

```sh
pipx install mcp-cross-exam
uvx mcp-cross-exam --help
```

## Try it

Start the local server, then audit it. The server defaults to `session.expired-empty-success` and `schema.undeclared-required-arg`:

```sh
mcp-cross-exam fixture serve --http 127.0.0.1:8765
mcp-cross-exam http://127.0.0.1:8765/mcp
```

`--clean` serves no defects, and that audit exits 0. A server with findings exits 3 unless `--fail-on` says otherwise.

## Probes

| Family | What a finding means |
| --- | --- |
| Transport and session | Negotiation, headers, reconnects, stream resume, or an expired session is wrong. |
| Schema | A tool definition, argument, error, or description does not match what the server does. |

The catalog is in [Methodology](docs/METHODOLOGY.md).

## Safety

Stdio and a loopback host are local. Any other host must match `[target] allow`, and `--target-is-not-production` still needs that match. Credentials come from the environment and are redacted from the run directory.

Not a pentest, not a load tester, not a proxy or gateway, and not a hosted service.

## More

- [Usage](docs/USAGE.md)
- [Methodology](docs/METHODOLOGY.md)
- [Changelog](docs/CHANGELOG.md)
- [Limitations](docs/limitations.md)
