# Usage

`mcp-cross-exam <endpoint>` audits one server. `--help` prints the options for the current command.

## run

| Option | Meaning |
| --- | --- |
| `endpoint` | Streamable HTTP URL. A bare URL is the same as `run`. |
| `--sse` | Legacy HTTP+SSE endpoint. |
| `--` | Stdio command after this separator. |
| `--cwd` | Working directory for a stdio command. |
| `--env` | Set `KEY=VALUE` for a stdio command. |
| `--env-from` | Copy an environment variable into a stdio command. |
| `--bearer-env` | Environment variable holding a bearer token. |
| `--expired-bearer-env` | Environment variable holding an expired bearer token. |
| `--header-env` | Send a header from an environment variable (`Header=ENV`). |
| `--ca-bundle` | CA bundle for TLS. |
| `--protocol-version` | Offer only this protocol revision. |
| `--probe` | Run probes whose ids match this glob. Repeat to combine. |
| `--family` | Run probes in this family. |
| `--skip` | Skip this probe id. |
| `--seed` | Seed the run. |
| `--tool` | Limit the audit to one tool. |
| `--jobs` | How many tools to examine at once. Default 4. |
| `--config` | Config file. |
| `--read-only` | Skip write and destructive calls. |
| `--allow-writes` | Allow writes when the guard is overridden. |
| `--target-is-not-production` | Audit an allow-listed host that is not production. |
| `--fail-on-incomplete` | Exit 3 when the run is partial. |
| `--fail-on` | Fail when a finding is at or above this severity. Default `high`. |
| `--out-dir` | Directory for the report, evidence, and transcripts. |
| `--snapshot` | Compare tool definitions with this snapshot. |
| `--version` | Print version facts. |
| `--json` | Print machine-readable output. |
| `--quiet` | Suppress non-error output. |
| `--no-color` | Disable color. |
| `--exit-zero` | Exit 0 when the result is findings. |

## probes

| Command | Meaning |
| --- | --- |
| `probes list` | Print the registered probes. `--json` prints JSON. |
| `probes plan` | Show which probes would run. Does not call tools. |

## config

| Command | Meaning |
| --- | --- |
| `config show` | Print the effective config. `--config` selects a file. `--json` prints JSON. |
| `config init` | Write a commented config from `tools/list`. |

## snapshot

| Command | Meaning |
| --- | --- |
| `snapshot write` | List tools and write a snapshot. `--out` sets the path. |

## replay

| Argument | Meaning |
| --- | --- |
| `transcript` | JSON-RPC JSONL transcript. |
| `endpoint` | Streamable HTTP endpoint. |

## fixture

| Option | Meaning |
| --- | --- |
| `fixture serve --stdio` | Speak MCP on standard input. |
| `--http` | Listen on `HOST:PORT` for streamable HTTP. |
| `--sse` | Listen on `HOST:PORT` for legacy HTTP+SSE. |
| `--era` | Protocol revision to speak. |
| `--defects` | Comma-separated probe ids, `all`, or `none`. The default is `session.expired-empty-success,schema.undeclared-required-arg`. |
| `--clean` | Serve no defects. |
| `--token-ttl-s` | Seconds before the valid bearer expires. |
| `fixture mint-token --expired` | Print the expired token. |

## Config keys

| Key | Meaning |
| --- | --- |
| `target.url` | Endpoint used when the command line omits one. |
| `target.allow` | Hosts the guard accepts besides loopback. |
| `auth.bearer_env` | Environment variable for the bearer token. |
| `auth.expired_bearer_env` | Environment variable for an expired bearer token. |
| `auth.header_env` | Map of header name to environment variable. |
| `probes.select` | Probe id globs to run. |
| `probes.skip` | Probe ids to skip. |
| `probes.severity` | Override a probe severity. |
| `probes.target_tool` | Tool the transport and session probes call. |
| `budget.wall_clock_s` | Stop the run after this many seconds. |
| `budget.max_calls_per_tool` | Cap calls to one tool. |
| `budget.call_timeout_s` | Timeout for one call. |
| `tools.<name>.effect` | `read`, `write`, `destructive`, or `external`. |
| `tools.<name>.scope` | `user`, `tenant`, or `global`. |

## Run directory

The default directory is `.mcp-cross-exam/runs/<run-id>/`. Set `MCP_CROSS_EXAM_RUNS` to move it. Each run writes `report.json`, `report.html`, `evidence.jsonl`, and `transcripts/`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above the fail-on severity |
| 1 | Internal error |
| 2 | Usage or config error, including the production guard |
| 3 | Findings at or above the fail-on severity |
| 4 | Target unreachable, or the connection or handshake failed before any probe ran |
| 130 | Interrupted |
