# Methodology

A run connects, lists tools, selects probes, and records each call. A probe returns a draft when the server disagrees with its contract. The report turns that draft into a finding with a severity, a blast radius, and a penalty. The score starts at 100 and subtracts penalties.

## Catalog

| Probe | Severity | Impact |
| --- | --- | --- |
| `transport.version-negotiation` | high | the client and server disagree on the protocol revision |
| `transport.capabilities-honesty` | high | the client calls a feature the server did not declare |
| `transport.required-headers` | high | a tool call proceeds without the routing headers |
| `transport.unknown-method` | high | an unknown method is treated as success |
| `session.token-expired-empty-success` | high | agent silently degrades |
| `session.expired-not-404` | high | agent silently degrades |
| `session.expired-empty-success` | high | agent silently degrades |
| `transport.resume-gap` | medium | the client misses events after a dropped stream |
| `transport.reconnect-fails` | high | a retry does not see the same tool result |
| `schema.lint.invalid-schema` | high | the model cannot form a valid call |
| `schema.lint.root-not-object` | medium | the model cannot form a valid call |
| `schema.lint.required-not-declared` | high | the model omits a required argument and loops |
| `schema.lint.missing-description` | low | the model guesses what the tool does |
| `schema.lint.name-invalid` | low | the model cannot address the tool by name |
| `schema.lint.duplicate-name` | high | the model cannot tell the tools apart |
| `schema.lint.annotation-contradiction` | medium | the model treats a write as a read |
| `schema.lint.unbounded-string` | info | the model can send an unbounded string |
| `schema.lint.hidden-instructions` | info | hidden text can steer the model |
| `schema.error-shape.unknown-tool` | low | an unknown tool name is not rejected |
| `schema.tool-list-unstable` | high | the model caches a tool list that changes |
| `schema.tool-set-unstable` | high | a tool disappears between connections |
| `schema.tool-order-unstable` | low | tool order changes and the model picks the wrong one |
| `schema.pagination-broken` | medium | the model stops after the first page |
| `schema.list-cache-hints-invalid` | low | the client caches a list it should refetch |
| `schema.list-changed-not-notified` | medium | the model keeps a stale tool list |
| `schema.definition-drift` | medium | the tool contract changed since the snapshot |
| `schema.undeclared-required-arg` | high | the model omits a required argument and loops |
| `schema.required-not-enforced` | medium | the model can skip a required argument |
| `schema.extra-args-silently-accepted` | medium | an extra argument is dropped without an error |
| `schema.silent-coercion` | high | the model receives a value it did not send |
| `schema.constraint-not-enforced` | medium | a value outside the schema is accepted |
| `schema.error-shape.validation-as-protocol-error` | medium | the model treats a bad argument as a broken protocol |
| `schema.error-shape.unactionable` | medium | the model cannot tell which argument to fix |
| `schema.error-shape.internal-leak` | medium | an error string exposes server internals |
| `schema.output-nonconformant` | high | the model reads a result the schema does not describe |
| `schema.description-param-mismatch` | medium | the model sends an argument the schema does not define |
| `schema.description-contract-broken` | medium | the result breaks a limit the description stated |
| `schema.example-fails` | medium | the model copies an example the server rejects |
| `schema.annotation-readonly-violated` | high | a read tool changes server state |

`transport.stdout-pollution` and `transport.deprecated-sse` are transport findings, not probes.

## Severity and score

Severity weights are info 0, low 1, medium 4, high 10, and critical 25. Effect multipliers are read 1, write 2, destructive 3, and external 4. Scope multipliers are user 1, tenant 2, and global 3. The raw penalty is the product of those three.

Findings that share a tool and a family are ordered by raw penalty. The first keeps its penalty, and each later finding keeps half of its raw penalty, rounded down. A tool's penalties are then capped at `min(100, max(25, 300 / tool count))`. The score is 100 minus the sum of the penalties.

A high finding on a write tool scoped to one user is `10 * 2 * 1 = 20`. One such finding scores 80.

## False positives

Hidden-instruction lint matches steering text in a description, so a warning that names the pattern can look like the defect. A description contract is only a finding when the result breaks a limit the description stated. Extra arguments are a finding only when `additionalProperties` is not true and the server accepts the extra key. Silent coercion is a finding when the server returns a value the client did not send. The read-only observer calls a read tool twice and reports a finding only when the second result shows a write.

## References

- [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching)
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
