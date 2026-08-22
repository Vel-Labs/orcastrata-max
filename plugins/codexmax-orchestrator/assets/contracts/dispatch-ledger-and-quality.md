# Dispatch Ledger and Artifact Quality

`DispatchLedger v1` is standalone Codexmax runtime truth for queueing,
admission, attempts, accounting, and deterministic quality outcomes. It is not
GoalBuddy board truth and it grants no task, provider, billing, or acceptance
authority.

Each JSONL row is append-only, strictly shaped, monotonically sequenced, and
SHA-256 chained to its predecessor. A locked compare-and-append operation binds
the event to goal, checkpoint, task, assignment, task envelope, configuration,
board, exact route, lease/fencing data, typed accounting, and evidence. Missing
usage remains the string `unknown`; it is never inferred as zero. A malformed,
duplicate, truncated, or chain-divergent ledger stops scheduling.

Work status and accounting status are separate facts. `accounted` means one of
two operations succeeded: the managed dispatch gateway appended its final row,
or the bounded native importer accepted and appended or idempotently matched a
`turn.completed` row. A completed task with a missing or failed managed append
is `unaccounted`. Native Parent and collaboration work remains `unknown` and
unaccounted unless a supported bounded import is accepted. Worker count is not
a token measurement and must never produce token values.

A managed row counts as `accounted` only when its evidence has
`external_call_performed: true` and a valid `manifest_sha256`. A bounded native
row also requires `import_acceptance: accepted_bounded`,
`lifecycle: completed_only`, a valid `source_sha256`, and valid task and action
identifiers. The evidence task identifier must match the ledger task. Owner and
method labels alone do not establish accounting provenance.

Accounting coverage uses only the scope
`orcastrata_admitted_executions`. It is not host-wide coverage. Loop run
receipts and their adjacent traces remain separate evidence. They are never
converted to dispatch-ledger rows by the telemetry snapshot.

Stable event types cover enqueue and classification, broker outcomes, candidate
rejections, lease and budget lifecycle, dispatch lifecycle, uncertain
execution, quality decisions, retries, and schedule closeout. An interrupted
attempt that might have reached a provider is `execution_unknown` and is not
automatically retried.

`ArtifactQualityReceipt v1` separates transport completion from usable work.
The only policy identifiers are:

- `provider_neutral_result_v1` for governed result headings, identity, input
  receipt, validation, status, artifacts, and optional source binding;
- `markdown_sections_v1` for an explicit ordered-heading contract;
- `json_object_v1` for a JSON-object schema/field contract; and
- `opaque_nonempty_v1` for explicitly low-consequence opaque output.

Validation checks regular-file identity, byte ceiling, UTF-8, descriptor digest
and size, and the selected deterministic content contract. It executes no
arbitrary command and uses no model judgment. A nonempty artifact may still be
rejected; rejected output cannot be applied to Supervisor state.
