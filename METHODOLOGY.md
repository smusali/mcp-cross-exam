# Methodology

Each finding has a severity, the evidence pair, a reproduction command, and a blast radius. The report rolls those findings up to one score. `score_version` is 1, so a formula change is visible separately from a server change.

## transport.version-negotiation

Sends a bogus protocol version. On HTTP it also sends a request whose protocol header does not match the body.

A finding means the server accepted the mismatch instead of rejecting it for the negotiated revision.

Severity is high because a client can stay on the wrong protocol.

False positives: a server that rejects the bogus version with the documented error is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>

## transport.capabilities-honesty

Sends `tools/list`, `resources/list`, and `prompts/list`.

A finding means the server answered a feature it did not declare in its capabilities.

Severity is high because the client will call a feature the server said it does not have.

False positives: a method-not-found error for an undeclared feature is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>

## transport.required-headers

Sends `tools/call` on streamable HTTP without the required routing headers. It runs only on the modern HTTP transport.

A finding means the server accepted the call.

Severity is high because a client can skip the routing the transport requires.

False positives: HTTP 400 is clean. Older revisions and stdio do not run this probe.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## transport.unknown-method

Sends the method `x/not-a-method`.

A finding means the server did not reject it as an unknown method.

Severity is high because the client cannot tell a real method from a typo.

False positives: a JSON-RPC method-not-found error is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>

## session.token-expired-empty-success

Sends `tools/call` with the bearer from `--expired-bearer-env`. It runs only when that variable is set.

A finding means the expired bearer returned an empty tool success.

Severity is high because the agent silently degrades.

False positives: an auth error, or a non-empty result, is clean. The probe does not run without an expired token.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

## session.expired-not-404

Drops the session and sends another call on the handshake revisions.

A finding means the expired session was not rejected with not found.

Severity is high because the agent keeps using a dead session.

False positives: HTTP 404 is clean. The modern revision and legacy SSE do not run this probe.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## session.expired-empty-success

Drops the session and sends another call on the handshake revisions.

A finding means the expired session returned an empty tool success.

Severity is high because the agent silently degrades.

False positives: a non-empty result or a not-found error is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## transport.resume-gap

Drops the SSE stream and resumes from the last event id.

A finding means the replay had a gap or a repeated event id.

Severity is medium because the client misses events but the call itself may still succeed.

False positives: an empty resume, or a contiguous id sequence, is clean. Stdio does not run this probe.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## transport.reconnect-fails

Calls a tool, drops the stream, reconnects, and calls the tool again.

A finding means the second result timed out, errored, or differed from the first.

Severity is high because a retry does not see the same tool result.

False positives: an identical success after reconnect is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## transport.stdout-pollution

This is not a scheduled probe. Any stdout line that is not JSON-RPC is recorded while a stdio server is connected.

A finding means the server wrote a non protocol line on stdout.

Severity is medium because one bad line can desynchronize the framing without failing the handshake.

False positives: stderr is not this finding. HTTP transports do not produce it.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## transport.deprecated-sse

Recorded when the audit connects with `--sse`.

A finding means the client is using the deprecated HTTP+SSE transport.

Severity is info because the transport still works. The point is to show the migration.

False positives: streamable HTTP and stdio do not produce it.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## schema.lint.invalid-schema

Reads `tools/list` and checks each input and output schema against JSON Schema.

A finding means a schema is not a valid JSON Schema document.

Severity is high because the model cannot form a valid call.

False positives: a schema the validator accepts is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.root-not-object

Reads `tools/list` and checks the root type of each tool schema.

A finding means the schema root is not an object.

Severity is medium because tool arguments are objects, and another root type cannot be called as one.

False positives: `"type": "object"` at the root is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.required-not-declared

Reads `tools/list` and compares `required` with `properties`.

A finding means a required name is not declared.

Severity is high because the model omits a required argument and loops.

False positives: every required name present under `properties` is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.missing-description

Reads `tools/list` and checks tool and property descriptions.

A finding means a description is missing or blank.

Severity is low because the model can still call the tool, but it has to guess.

False positives: a non-blank description is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.name-invalid

Reads `tools/list` and checks tool names.

A finding means a name is empty or contains a character the client cannot use as an identifier.

Severity is low because the model cannot address that tool reliably.

False positives: a single token of letters, digits, and simple separators is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.duplicate-name

Reads `tools/list` and counts tool names.

A finding means the same name appears more than once.

Severity is high because the model cannot tell the tools apart.

False positives: unique names are clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.annotation-contradiction

Reads `tools/list` and compares `readOnlyHint` with `destructiveHint`.

A finding means both hints are true.

Severity is medium because the model may treat a write as a read. The hints are still hints.

False positives: either hint alone, or both false, is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.unbounded-string

Reads `tools/list` and looks for string properties with no length limit.

A finding means a string property has no `maxLength`.

Severity is info because the call can succeed. The note is that the model can send an unbounded string.

False positives: a `maxLength` on the string is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.lint.hidden-instructions

Reads `tools/list` and scans descriptions for hidden characters and instruction patterns.

A finding means the text contains tag characters, zero-width characters, bidi overrides, `ignore previous`, an `<important>` marker, `call tool`, or `read file`.

Severity is info because the text may be accidental. Emoji are ignored. A tool that must call another tool, or read a file, can describe that in plain text and still match.

False positives: ordinary prose, emoji, and a description that documents another tool or a file on purpose.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.tool-list-unstable

Lists tools more than once and compares the descriptions.

A finding means a tool definition changed across connections.

Severity is high on the modern revision and low on older revisions, because a cached list becomes wrong.

False positives: identical lists are clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.tool-set-unstable

Lists tools more than once and compares the set of names.

A finding means a tool appeared or disappeared across connections.

Severity is high because the model calls a tool that is no longer there.

False positives: the same set of names is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.tool-order-unstable

Lists tools more than once and compares order.

A finding means the order changed while the set stayed the same.

Severity is medium on the modern revision and low on older revisions. Order is not an identity, but a client that picks by position will call the wrong tool.

False positives: a stable order is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.pagination-broken

Reads `tools/list` and follows `nextCursor` for a bounded number of pages.

A finding means the cursor never advances or the pages repeat.

Severity is medium because the model stops after the first page or loops.

False positives: a complete list, or a cursor that reaches the end, is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.list-cache-hints-invalid

Reads `tools/list` on the modern revision and checks `cacheScope` and `ttlMs`.

A finding means the cache hints are missing or not in the allowed set.

Severity is low because the client may cache a list it should refetch. The hints are still hints.

False positives: `public` or `private` with a numeric ttl is clean. Older revisions do not run this check.

Spec: <https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching>

## schema.list-changed-not-notified

Lists tools twice and watches for `notifications/tools/list_changed`.

A finding means the list changed and no notification was seen.

Severity is medium because the model keeps a stale tool list.

False positives: an unchanged list, or a notification after the change, is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.undeclared-required-arg

Calls a tool with a minimal argument object, then records a required name the schema does not declare.

A finding means the server requires an argument it does not list in `required` and `properties`.

Severity is high because the model omits a required argument and loops.

False positives: a schema that declares every required argument is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.required-not-enforced

Calls a tool while omitting a name listed in `required`.

A finding means the server accepted the call.

Severity is medium because the model can skip a required argument and still get a success.

False positives: a validation error is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.extra-args-silently-accepted

Calls a tool with an argument name that is not in `properties`.

A finding means the server accepted the extra argument.

Severity is medium because an extra argument is dropped without an error.

False positives: a validation error is clean. `additionalProperties: true` is still reported, because the schema did not name the argument.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.silent-coercion

Calls a tool with a value of the wrong JSON type, then calls it again with the canonical value and, when possible, the opposite value.

A finding means the server accepted the wrong type. Severity rises to high when the opposite value returns the same result as the wrong type and that result differs from the canonical call. Otherwise the severity is low.

False positives: a rejection of the wrong type is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.constraint-not-enforced

Calls a tool with a value outside a numeric, length, or enum constraint.

A finding means the server accepted the value.

Severity is medium because a value outside the schema is treated as valid.

False positives: a validation error is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.error-shape.validation-as-protocol-error

Calls a tool with one invalid argument.

A finding means the server reported a protocol error instead of a tool error.

Severity is medium because the model treats a bad argument as a broken protocol and may retry the connection.

False positives: a tool error, or `isError: true`, is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.error-shape.unactionable

Calls a tool with one invalid argument and reads the error text.

A finding means the error does not name the argument the caller sent.

Severity is medium because the model cannot tell which argument to fix.

False positives: an error that names the offending argument is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.error-shape.internal-leak

Calls a tool with one invalid argument and scans the error text.

A finding means the error contains a stack trace, a file path, or another internal marker.

Severity is medium because an error string exposes server internals.

False positives: a short validation message is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.output-nonconformant

Calls a tool with valid arguments and checks `structuredContent` against `outputSchema`.

A finding means the structured result does not match the output schema.

Severity is high because the model reads a result the schema does not describe.

False positives: a result that validates, or a tool with no output schema, is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.description-param-mismatch

Reads the description and compares backticked or identifier-shaped words with the input schema.

A finding means the description names a parameter the schema does not define.

Severity is medium because the model sends an argument the schema does not define.

False positives: ordinary words are ignored. `customer_id` and `customerId` match after normalization, so a real parameter written in either form is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.description-contract-broken

Reads date and limit claims in the description and compares them with the tool result.

A finding means the result breaks a limit the description stated, or a date claim has no matching string result.

Severity is medium because the model trusts the sentence.

False positives: a description can mention `YYYY-MM-DD` while documenting a different format. The limit number is compared only with the longest list in the result.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.example-fails

Reads an example object from the description and calls the tool with it.

A finding means the example was rejected.

Severity is medium because the model copies an example the server rejects.

False positives: an example the server accepts is clean. A description with no example object does not run the call.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.annotation-readonly-violated

Calls a tool marked `readOnlyHint` and then reads an observer tool.

A finding means the observer result changed.

Severity is high because a read tool changed server state. The hint is still a hint. This probe is the behavior check.

False positives: an unchanged observer is clean. The probe does not run unless the config names an observer.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.error-shape.unknown-tool

Sends `tools/call` for `crossexam_unknown_tool`.

A finding means the server did not reject it with JSON-RPC `-32602`.

Severity is low because the name is unknown, but the client still needs a stable error.

False positives: error code `-32602` is clean.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## schema.definition-drift

Reads `tools/list` and compares it with the snapshot passed in `--snapshot`.

A finding means a tool was added, removed, or its definition changed.

Severity is medium because the tool contract changed since the snapshot.

False positives: a byte-for-byte match is clean. The probe does not run without a snapshot.

Spec: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

## Blast radius

Effect comes from the tool classification. `openWorldHint: true` sets the effect to external unless config already set the effect. Scope comes from `[tools.<name>] scope`. A missing scope is `user` and is marked default.

A finding with no tool uses effect `read` and scope `user`, both default.

Sources: config is `configured`, an annotation is `declared`, a name heuristic is `observed`, and a fallback is `default`.

Effect multipliers: read 1, write 2, destructive 3, external 4.

Scope multipliers: user 1, tenant 2, global 3.

## Score

`score_version` is 1. The score runs from 0 to 100. Higher is better.

Weights: critical 25, high 10, medium 4, low 1, info 0.

The raw penalty is the weight times the effect multiplier times the scope multiplier.

Findings that share a tool and a family are ordered by raw penalty, then fingerprint. The nth finding, starting at zero, counts the raw penalty divided by 2 to the n, using integer division.

Each tool's counted penalties are then capped at `min(100, max(25, 300 // tool_count))`. The largest remainder method keeps that tool's counted sum equal to the cap. One tool on a 40 tool server therefore counts at most 25.

If the total is still above 100, the smallest counted penalties are reduced until the total is 100. The score is 100 minus that total. The listed `penalty` is the counted value. `raw_penalty` stays the full product. Their sum equals `100 - score`.

A run is partial when the budget skips a probe or a probe errors. Revision skips, read-only skips, and write-gate skips are listed and do not mark the run partial.

Worked example. One high read user finding has raw penalty 10 and counts 10, so the score is 90. A second medium finding on the same tool and family counts `4 // 2 = 2`, so the two findings count 12 and the score is 88. One critical external global finding on a 40 tool server has raw penalty 300 and counts 25, so the score is 75.
