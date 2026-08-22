# LoopRunTraceV1

`LoopRunTraceV1` is an optional, local, metadata-only companion to one
`LoopRunReceipt v1`. Orcastrata writes it beside the receipt with the same
stem and the `.trace.json` suffix.

The trace contains the receipt ID. It records the current loop ID and
definition version, event
identity, execution status, bounded output descriptor, and root or nested loop
ancestry. It never contains output text,
prompts, responses, commands, environment values, credentials, or provider
payloads.

The trace also contains `binding_sha256`. This semantic digest binds the receipt
ID, current loop identity, event identity and digest, source, and origin. The
receipt contains one `loop-run-trace` artifact row whose SHA-256 is the digest
of the exact trace file bytes. The trace does not contain the receipt digest,
so the link is non-circular. The snapshot computes the receipt digest after it
validates the pair. A legacy receipt without that artifact remains valid as a
receipt but is not eligible for a telemetry snapshot pair.

The pair is valid only when the trace is adjacent, its exact byte digest matches
the receipt artifact row, the semantic binding matches, and both artifacts pass
their source validators.
An absent or invalid trace never upgrades a receipt's proof boundary. It is
additional observability evidence, not execution authority, acceptance, a
second ledger, retention policy, or learning input.
