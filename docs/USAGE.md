# Usage

`mcp-cross-exam <endpoint>` audits one server. Add `--probe`, `--family`, and `--skip` to choose probes. Repeat them to combine globs. `--seed` fixes the random stream used by probes. `--read-only` skips write and destructive calls.

## Staging

Put the staging host in the allow list. The match is case-insensitive and supports globs:

```toml
[target]
url = "https://staging.example.com/mcp"
allow = ["*.fixtures.local", "staging.example.com"]
```

A matching host is audited with `target.guard = "allow"`. Writes run there without an extra flag.

## Override

`--target-is-not-production` does not widen the allow list. It only applies when the host already matches `allow`. The run prints a warning and records `target.guard = "overridden"`. Writes stay off unless you also pass `--allow-writes`.

```sh
mcp-cross-exam --config mcp-cross-exam.toml --target-is-not-production --allow-writes https://staging.example.com/mcp
```

A public host that is not in `allow` is refused before a socket is opened, including when the override flag is set.

## Read only

`--read-only` skips every probe that mutates or whose tool is classified `write` or `destructive`. The skip is recorded on the run and is not a finding.

```sh
mcp-cross-exam --read-only http://127.0.0.1:8765/mcp
```

## Config

`--config PATH` wins over `mcp-cross-exam.toml` and `[tool.mcp-cross-exam]` in `pyproject.toml`. Command-line flags win over the file. `config show` prints the effective file with environment variable names, never secret values. `config init <endpoint>` writes a commented starter from `tools/list` and refuses to overwrite an existing file.

## Report

The audit writes `report.json`, `report.html`, `evidence.jsonl`, and `transcripts/` under `--out-dir`. The default directory is `.mcp-cross-exam/runs/<run-id>/`.

`--json` prints the report JSON on stdout and leaves warnings on stderr. `--quiet` prints the score line only. Passing both prints the JSON and skips the score line.

`--fail-on` sets the lowest severity that fails the run. The default is `high`. Severities are `info`, `low`, `medium`, `high`, and `critical`.

`--fail-on-incomplete` exits 3 when the run is partial. A partial run skipped probes because the budget ran out, or a probe errored. `--exit-zero` turns exit 3 into 0, including that partial case. Exits 1, 2, and 4 still fail.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above the fail-on severity |
| 1 | Internal error |
| 2 | Usage or config error, including the production guard |
| 3 | Findings at or above the fail-on severity |
| 4 | Target unreachable, or the connection or handshake failed before any probe ran |
| 130 | Interrupted |
