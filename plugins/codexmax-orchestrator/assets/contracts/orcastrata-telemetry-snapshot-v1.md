# OrcastrataTelemetrySnapshotV1

Orcastrata exposes one local, read-only snapshot command that prints a closed
JSON object to stdout. The command reads one explicit project marker, verifies
the existing `.orcastrata/usage/dispatch.jsonl` hash chain, and returns its
exact `{event_count, head_hash}` cursor.

The snapshot projects row details only for verified rows owned by
`orcastrata_managed`. Its accounting coverage also counts accepted bounded
`host_native` imports. Coverage is limited to
`orcastrata_admitted_executions`; it does not claim host-wide completeness.
Native Parent and collaboration usage remains unaccounted and `unknown` unless
the host produces a supported bounded import.

Explicit `LoopRunReceipt v1` and adjacent `LoopRunTraceV1` pairs appear in the
separate `loop_runs` array. They do not become ledger rows and do not change
accounting coverage. The command does not append, repair, truncate, upload,
start a server, call a provider, tokenize content, or create a second ledger.

The output is metadata-only. Missing host counters remain `unknown`. The
snapshot is an operator-owned observation that does not grant authority,
select a route, rank a model, mutate a board, retain learning data, or prove
publication. Each loop row identifies the current loop and definition version,
plus its source event and parent ancestry. Use an explicit receipt path for each
loop run; the command does
not crawl sibling directories or infer projects from names.

`accounted` identifies an accepted accounting record. It does not mean that a
provider reported every token field. Missing counters stay `unknown`, and no
token value is inferred from worker count.

The classifier fails closed on provenance. Managed rows need a valid manifest
digest and explicit external-call evidence. Bounded native rows need accepted
import status, completed-only lifecycle, a valid source digest, and matching
valid task and action identifiers. Self-labelled owner and accounting-method
fields are insufficient.

The approved tool name and bounded reasoning and billing categories remain
readable. Route, provider, model, and runtime identities are field-specific
stable SHA-256 references. Use the original verified dispatch receipt when an
operator must inspect an exact model name. This prevents prompt-like or
path-like values in a route field from entering the snapshot.

Only receipts with a matching `loop-run-trace` binding artifact are eligible
for `loop_runs`. Legacy receipts remain valid for their original validator but
are excluded from this snapshot.
