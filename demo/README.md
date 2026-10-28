# Demo

Walk the broken fixture, the audit, the terminal summary, and the HTML report. A good run exits 3.

## Presenter

```sh
DEMO_PAUSE=1 bash demo/run.sh
```

`DEMO_PORT=8765` pins the listen port. Headless, with no pauses and no browser:

```sh
bash demo/run.sh
```

## 0:00 Fixture

The script listens on `127.0.0.1` and prints `fixture http://127.0.0.1:<port>/mcp`. Two defects are on:

- `get_ticket` returns an empty success after the session expires (`session.expired-empty-success`).
- `create_ticket` requires `title` without declaring it (`schema.undeclared-required-arg`).

Pause 5 seconds.

## 0:05 Audit

The script audits that URL with seed 7. The audit prints the terminal summary when it finishes.

## Summary

Pause 15 seconds. The summary shows the score, both high findings, and the paths to `report.html` and `report.json`.

- `schema.undeclared-required-arg` is on `create_ticket`.
- `session.expired-empty-success` is the empty `get_ticket` result. The reproduction command names `get_ticket`.

The process exits 3.

## Report

The script opens `report.html`. Pause 25 seconds. Walk the evidence for `session.expired-empty-success`, then `schema.undeclared-required-arg` on `create_ticket`.
