# WorkGraph GoalBuddy Adapter v1 Contract

Queued-task insertion uses the existing lock, CAS, write-ahead journal,
applied ledger row, and recovery flow. A narrow task mapping, safe values,
unique ID, existing non-self dependencies, and unchanged `active_task` are
validated before mutation; no generic YAML serializer is used.

Creation serializes empty canonical list fields as the explicit YAML sequence
`[]`. Nonempty lists retain their declared order and block-sequence form. A
blank YAML mapping key is never used to represent an empty list.

## Purpose And Authority

The adapter binds accepted WorkGraph updates-v1 history to canonical GoalBuddy
`state.yaml`. GoalBuddy remains the only board authority. The adapter never
reconstructs state from activity, chat, projections, or an unreviewed update.
Only a complete update lineage whose latest review is an approval by a
provably distinct Parent identity under `parent_issued` authority may reach the
mutation path. Adapter receipts describe local execution; they do not accept a
task, checkpoint, or goal.

## Snapshot And Version Capabilities

`snapshot` reads the exact board bytes and returns their SHA-256, schema
version, active task, task statuses, canonical owner, and explicit read,
apply, recovery, and migration capabilities. GoalBuddy schema version `2` is
the pinned current read/write version. Version `3` is the deterministic next
fixture and is readable only to report that migration is required and not yet
available. Other versions fail clear. Application version names never imply a
schema version.

Snapshot parsing requires one unambiguous top-level `version`, `active_task`,
one nested `goal.status`, and one `tasks` sequence, plus unique task IDs, one
status per task, task type and status-sensitive Worker lists, receipt keys,
receipt lists, receipt scalars, and command-status metadata. Duplicate, missing,
malformed, non-integer, and boolean versions fail closed. Goal status is
limited to `active`, `blocked`, and `done`; task status is limited to `queued`,
`active`, `blocked`, and `done`. Active goals require exactly one active task
and an aligned pointer. Blocked goals allow at most one active task and require
alignment when one exists. Done goals require no active task and a null
pointer. Non-null pointers name an existing task. Blocked tasks require a
receipt; done tasks require a receipt with `result: done`.

The local status-sensitive parity matrix also enforces every official
GoalBuddy v2 error rule whose result can change solely because a task status
changes:

- an active Worker has nonempty block-form `allowed_files`, `verify`, and
  `stop_if` lists;
- a done Worker receipt contains `summary`, a nonempty `changed_files` list
  whose entries match `allowed_files` under GoalBuddy path normalization and
  glob semantics, and `commands` with at least one `status` and only `pass`
  statuses;
- a done Scout receipt contains `summary` and either `evidence` or `note`;
- a done Judge receipt contains `decision`;
- a done goal has no active task, a null pointer, no queued or active Workers,
  and at least one final done Judge or PM receipt whose decision is `complete`
  or `done`; a goal with `continuous_until_full_outcome: true` additionally
  requires that final receipt to contain `full_outcome_complete: true`; and
- a blocked goal under both continuous execution rules remains invalid unless
  its task statuses and receipts prove the official terminal user-approval
  wait exception.

These invariants are checked on the snapshot source and intended result before
journal creation. List and receipt parsing deliberately recognizes only the
official checker's indentation-sensitive v2 forms and never fills in or
infers omitted fields. The adapter preserves the original YAML document rather
than serializing it through a second board model.

This local matrix is not a replacement for the official checker. Schema-wide
task shape, agent installation states, goal proof strength, goal-root entries,
`goal.md`, `notes/`, subgoal paths and child files, and other filesystem-aware
rules remain official-checker responsibilities. Every accepted checkpoint
must run that checker against the real board and artifact-style temporary goal
roots in addition to the adapter tests.

## Parent-Reviewed Application

Application accepts one updates-v1 `update_id`. The complete ledger must pass
the accepted T003 verifier. The latest row for that lineage must be `reviewed`
with `review_status: approved`, `parent_decision: approve`, a known Parent
reviewer ID distinct from the known proposer ID, and a `parent_issued`
authority reference. Worker, role-label-only, unknown, self-reviewed,
rejected, pending, superseded, fabricated-applied, or divergent lineages grant
no mutation authority.

The adapter supports exactly `replace /tasks/<task-id>/status`. The middle
segment is a logical task ID, never a list index. The path task must equal the
update target and resolve exactly once. Allowed values are `queued`, `active`,
`blocked`, and `done`; transitions follow the explicit lifecycle in the
executable. Add, remove, duplicate, no-op, missing, ambiguous, foreign-task,
receipt, dependency, scope, acceptance, rule, and other field patches fail
before mutation. This deliberately narrow surface prevents an approved status
proposal from broadening its own acceptance or authority scope.

A status-only patch that would require simultaneously changing `active_task`
or adding a receipt fails with a stable canonical-invariant error. Activation
of a second task and completion or blocking of the sole active task are
explicit unsupported atomic handoffs; the adapter never infers pointer,
receipt, scope, verification, stop condition, command result, final-audit
decision, acceptance, or authority changes. Any unsupported transition fails
before the write-ahead journal exists, leaving the board and accepted updates
ledger byte-identical.

## Compare And Swap And Durability

The expected board SHA-256 is rechecked while holding one stable sibling lock
derived from the resolved board path. Concurrent applications over the same
base serialize; at most one divergent write succeeds. An exact completed
lineage may return an idempotent receipt, while another stale proposal fails
with a stable stale error.

Before that lock can be created, all mutation paths are normalized and bound
to the resolved regular non-symlink board. The sidecar must be the regular
non-symlink `<board-parent>/.goalbuddy-board` directory. Updates must be the
regular non-symlink `<sidecar>/updates.jsonl`. The journal is a distinct
non-symlink `.json` file directly beneath the same sidecar; it may be absent
only before first apply. Traversal, outside paths, aliases, symlinks,
directories, duplicates, and unsupported journal names fail without writes.

Before board mutation the adapter writes and fsyncs a strict write-ahead
journal. It then writes the patched GoalBuddy-compatible YAML to a sibling
temporary file, fsyncs it, atomically replaces the board, and fsyncs the board
directory. Only the intended status scalar line changes; every other byte and
all unknown mapping, list, and scalar content remain unchanged. The adapter
then appends an accepted updates-v1 `applied` row and records the terminal
journal phase.

After the prepared journal is durable and while the stable lock remains held,
the adapter rereads the exact board bytes immediately before replacement. A
GoalBuddy-owner change at that boundary is preserved, no ledger row is
appended, and apply returns a stable stale-after-prepare error. The lock is a
shared local coordination path, not proof that an unrelated writer honors it.

## Recovery And Reconciliation

Recovery verifies the strict journal, current board hash, complete update
ledger, approved review hash, patch digest, and expected/result hashes while
holding the same lock. It distinguishes:

- `pre_write`: the prepared journal exists and the board remains at the base;
- `board_written`: the result board exists without an applied row;
- `ledger_written`: the result board and applied row exist;
- `already_recovered`: a terminal or reconciled recovery is replayed;
- stale journal: the phase contradicts the observed base board;
- corrupt journal: shape, version, hash, or lineage binding is invalid;
- divergent board: the board matches neither expected nor result state.

When recovery observes the result board, it appends any missing `applied` row
and an immutable updates-v1 `reconciled` row with the observed result hash and
`recovered` outcome. It never reapplies the patch, changes the applied-state
hash, rewrites history, or treats divergence as success. Repeated recovery is
idempotent.

## Library, CLI, And Proof Boundary

The standard-library module exposes `snapshot`, `apply_update`, and
`recover`. The CLI exposes:

```sh
python3 workgraph_goalbuddy_adapter.py snapshot <state.yaml>
python3 workgraph_goalbuddy_adapter.py apply <state.yaml> <updates.jsonl> <journal.json> <update-id> --timestamp <RFC3339-UTC>
python3 workgraph_goalbuddy_adapter.py recover <state.yaml> <updates.jsonl> <journal.json> --timestamp <RFC3339-UTC>
```

Stdout is one canonical JSON receipt. Success exits `0`; protocol, authority,
identity, schema, stale, patch, storage, corruption, and recovery errors exit
`2` with one stable error code. Library and CLI never report a failure as an
empty success.

T005 proves local single-host GoalBuddy v2 snapshot, Parent-only CAS apply,
status-sensitive local parity, updates lineage, YAML preservation, and
interrupted recovery. Full v3
migration, distributed locking, external GoalBuddy frontend behavior,
installation, and Parent acceptance belong to later checkpoints.
