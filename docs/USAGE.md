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
