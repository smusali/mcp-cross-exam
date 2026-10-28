# Limitations

The auditor is black box. It sees JSON-RPC on the wire. For a stdio server it also reads stderr. It does not read server source, files, or process memory.

Hints are hints. `readOnlyHint`, `destructiveHint`, and `openWorldHint` are labels from the server, not proof. The report marks each blast radius value as configured, declared, observed, or default so a hint is not shown as a fact. A behavior check, such as a read tool that changes state, is a separate finding from the hint itself.

Description checks are deterministic. They compare text patterns with the schema and with tool results. They do not decide whether the prose is true beyond those patterns. A description can mention a date format or a limit while documenting something else, and those cases are called out as false positive modes in the methodology.

This is not a pentest. It does not guess credentials, bypass authentication, or try to exploit the host. This is not a load tester. It does not flood the server or measure capacity. The budget exists to stop the audit, not to stress the target.

These probe families are not covered: idempotency, latency, data handling, auth and scope, and concurrency. The score is one server's own run. It is not a comparison across servers.
