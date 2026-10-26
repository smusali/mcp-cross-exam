# Contributing

## Tests

Install the lockfile and run the suite offline:

```sh
uv sync --extra dev
uv run pytest
```

Tests may open sockets only to `127.0.0.1` and `::1`. Anything else fails closed.

Lint and types:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict mcp_cross_exam tests tools
```

## Fixture

The fixture server is not in this revision. When it is, start it with:

```sh
mcp-cross-exam fixture serve --http 127.0.0.1:8765
```

Point the audit at `http://127.0.0.1:8765/mcp`. A clean mode of the same server must stay quiet.

## Adding a built-in probe

Add the probe beside the other built-in probes and register it. Add one fixture defect that makes that probe fire, and keep the fixture's clean mode free of that defect. A probe that cannot be triggered, or that fires on the clean server, is not done.

## Item ids

Tracker items keep stable ids such as `A1` and `B8`. Commits, changelog entries, and other items refer to those ids. Do not renumber an item once it has been used.
