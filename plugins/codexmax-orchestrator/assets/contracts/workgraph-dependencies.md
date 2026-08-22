# WorkGraph Dependency And Lease Runtime v1 Contract

## Purpose And Authority

T004 derives local readiness and lease state from a validated T002 WorkGraph
plus an explicit canonical-satisfaction snapshot. It never treats a candidate
WorkGraph status as Parent acceptance, never mutates GoalBuddy `state.yaml`,
and never grants scope, tools, provider access, billing, or acceptance.

## Canonical Satisfaction And Readiness

A satisfaction snapshot has exactly integer `schema_version: 1`, a canonical
`board_sha256`, and unique known `satisfied_work_item_ids`. Callers may bind an
expected board hash. Wrong shape/version, boolean or float version, invalid or
stale hash, duplicate ID, and unknown ID fail closed. Satisfied items are not
rescheduled.

Before scheduling, T004 runs the accepted T002 validator and its stricter
artifact/path checks. Missing references, dependency or containment cycles,
multiple parents, invalid relationships, missing or ambiguous artifact
producers, and unsafe paths fail as errors, not empty readiness.

An item is ready only when:

- its status is one of `queued`, `blocked`, `needs_revision`,
  `needs_reassignment`, or `needs_parent_repair`;
- it is not already satisfied or actively claimed;
- every `blocked_by` target is explicitly satisfied; and
- every `consumes` evidence row is `validated` with a concrete digest.

`related_to` never blocks. `parent_of` is containment only. Blocked receipts
contain deterministic sorted reason objects with a code, reference, and next
action. Rejected and unvalidated artifacts remain distinct.

## Containment, Artifact Flow, And Parallel Groups

Containment supports roots, ancestors, and descendants with deterministic
depth ordering. Artifact flow reports each evidence producer and consumer.
Every consumed `artifact` or `command_result` has exactly one producer;
missing or multiple producers fail closed. External `source_reference` and
`receipt` inputs may be consumed without an in-graph producer. Neither surface
changes dependency satisfaction.

Scope paths are canonical nonempty repository-relative POSIX paths. Absolute,
dot, traversal, repeated-separator, trailing-slash, and backslash aliases fail.
ASCII control characters, including NUL and DEL, also fail. Ancestor and
descendant paths overlap. Parallel grouping is input-order independent:
read/read overlap is safe, while write/write and write/read overlap conflict.
Only ready unclaimed items appear, once each.

## Fenced Lease Registry

The registry is derived runtime state with exactly schema version, next fencing
token, and preserved claims. Each claim records unique claim/request IDs, Work
Item, known provenance-backed holder ID and descriptive role, attempt,
normalized read/write scope, board hash, acquired/expiry UTC timestamps,
monotonic fencing token, state, prior claim, and append-only outcome history.
Unknown holder identity cannot own a lease; role or provider labels do not
grant authority.

Registry mutation locks a stable sibling lock file, verifies the complete
current registry, applies one operation, verifies again, writes and fsyncs a
temporary file, atomically replaces the registry, and fsyncs its directory.
Concurrent conflicting claims serialize so exactly one succeeds. Read/read
claims may coexist when their complete scopes do not otherwise conflict.

The same request with identical immutable inputs returns the original claim;
reuse for another item, holder, or board fails. Renew and release require the
current holder, board hash, and fencing token and reject expiry or clock
reversal. Retry preserves the failed attempt, increases attempt and fencing
token, and obeys the Work Item retry maximum. Recovery requires an actually
expired active claim, preserves it as recovered, links the replacement, and
uses a strictly higher token. Old holders cannot operate recovered claims.

Malformed, missing, empty, or invalid JSON registries; duplicate IDs/tokens;
token regression; bad timestamps/scopes/history; stale board hashes; invalid
durations; conflicts; exhausted retries; and stale operations have stable
errors. Tests inject time rather than sleep.

## Library, CLI, And Proof Boundary

The standard-library module exposes graph/satisfaction validation, `ready`,
`explain_blocked`, `containment`, `artifact_flow`, `parallel_groups`, path and
scope conflict checks, registry verification/read, `claim`, `renew`, `release`,
`retry`, and `recover`. The local CLI exposes readiness, blocked explanation,
containment, artifact flow, parallel groups, registry verification, and claim.
It prints one canonical JSON receipt, exits 0 on success and 2 on a stable
protocol/storage error. The unified operator/tool facade remains T007.

T004 proves local deterministic dependency and lease mechanics only. Canonical
state application, GoalBuddy integration, notes, frontend behavior, migration,
cross-host locking, installation, and Parent acceptance belong elsewhere.
