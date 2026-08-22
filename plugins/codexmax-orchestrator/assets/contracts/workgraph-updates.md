# Codexmax WorkGraph Updates v1 Contract

`task_creation` is a proposal containing exactly one `add /tasks/<new-id>`
patch. Its value ID matches the target and begins queued. Non-accepting
authority names only that exact path; a distinct Parent review is required.

## Purpose And Authority

`.goalbuddy-board/updates.jsonl` is an append-only proposal, review, decision,
application-receipt, and reconciliation history. T003 never edits GoalBuddy
`state.yaml`. Only the GoalBuddy owner may later apply canonical state after a
Parent review and compare-and-swap gate. A row, note, identity claim, or
authority reference cannot self-grant that permission or acceptance.

## Row Shape

Every line is a strict v1 object with a globally unique `row_id`, lineage
`update_id`, positive monotonic `sequence`, strict RFC3339 UTC date-time
`timestamp` in `YYYY-MM-DDTHH:MM:SS[.fraction]Z` form, target
task, update kind, transition, proposed patch, proposer identity, expected
board hash, authority reference, review fields, applied-state receipt fields,
per-update lineage hash, global previous-row hash, and row hash.

Update kinds are `task_transition`, `dependency_change`, `metadata_change`,
and `scope_change`. Transitions are `proposed`, `reviewed`, `rejected`,
`superseded`, `applied`, and `reconciled`. Each transition repeats the exact
patch, proposer, expected board hash, and authority reference so replay is
self-contained. Identity facts follow the activity v1 unknown/provenance rule.

Patches are nonempty strict JSON Patch subsets using `add`, `replace`, and
`remove`. Every JSON Pointer must resolve beneath `/tasks/<target_task>` and
beneath one structurally decoded `allowed_patch_paths` authority prefix.
Malformed pointer escapes, duplicate paths, another task, or a merely textual
prefix match fail closed as scope broadening.

Authority references contain a nonempty Parent- or operator-prefixed source,
receipt ID, matching issued provenance, nonempty allowed patch paths, and
literal false values for both `may_accept` and
`may_mutate_canonical_state`. They describe proposal scope only.

## Transition State Machine

- `proposed` starts one update lineage with pending review and no reviewer,
  decision, applied hash, supersession, or reconciliation.
- `reviewed` follows only a proposal. A distinct Parent reviewer records
  `approve` or `reject`. Both proposer and reviewer must carry known,
  provenance-valid agent IDs, and those IDs must differ. An unknown ID cannot
  prove independence, so either unknown ID fails closed with
  `update_reviewer_independence_unproved`; equal known IDs fail as self-review.
- `rejected` follows a Parent rejection and keeps it durable.
- `applied` follows only Parent approval and records a resulting state hash.
  It is a receipt of an application owned elsewhere, not an application API.
- `superseded` follows a nonterminal proposal or review, names an already
  proposed replacement update, and requires a Parent supersede decision.
- `reconciled` follows an applied row and must repeat its exact
  `applied_state_sha256`; that receipt is immutable. It separately records the
  observed state hash. `matched` and `recovered` require the observation to
  equal the applied receipt, while `diverged` requires a different observation.

Every non-proposal row binds the preceding row in the same update lineage.
Terminal transitions cannot be extended except applied to reconciled. Missing
proposal, duplicate proposal, invalid decision, self-review, missing Parent
authority, unproved reviewer independence, absent applied receipt, missing
replacement, or supersession cycle fails clear. Parent authority is checked
before reviewer independence and immutable-lineage comparisons so an
operator-issued decision returns the stable `update_parent_authority_required`
error. No transition produces an `accepted` state.

## Hashing, Board Binding, And Atomic Append

Canonical JSON is UTF-8, key sorted, compact separators, and unescaped Unicode.
`row_hash` is SHA-256 of the canonical row excluding only `row_hash`.
`previous_row_hash` binds the global stream and `previous_update_hash` binds
the update lineage; both use 64 zeroes at genesis.

Every append requires the caller's current pre-application board SHA-256 and
requires it to equal `expected_board_sha256`. This is a stale-proposal gate,
not state mutation. The adapter checkpoint owns later compare-and-swap apply.
Append takes an exclusive advisory file lock, verifies current history, derives
sequence and hashes, writes one newline-terminated record, flushes, and fsyncs.
Concurrent writers serialize or return a stable failure without accepting a
partial line.

## Replay, Consume, Library, And CLI

Replay filters by target task or update lineage. Consumer cursors are derived,
hash-bound, non-authorizing v1 objects identical in shape to activity cursors;
their schema version must be an integer, not a boolean or equal-valued float.
Library operations are `append_update`, `read_rows`, `verify_rows`, `replay`,
and `consume`. CLI operations are:

```sh
python3 workgraph_updates.py append <updates.jsonl> <draft.json> --board-hash sha256:<hex>
python3 workgraph_updates.py verify <updates.jsonl>
python3 workgraph_updates.py replay <updates.jsonl> [--task-id ID] [--update-id ID]
python3 workgraph_updates.py consume <updates.jsonl> <cursor.json> [--limit N]
```

CLI stdout is one canonical JSON receipt. Success exits 0. Stable protocol,
authority, lineage, stale-hash, scope, cursor, corruption, and storage errors
exit 2. Empty, missing, blank, truncated, invalid JSON, duplicate key/row ID,
unsupported version, broken hash, and invalid concurrency history are distinct.

## Template And Proof Boundary

`assets/templates/workgraph-update.json` is a deterministic proposal draft. It
does not review, apply, reconcile, mutate, or accept canonical state. T003
proves local history mechanics only; GoalBuddy adapter apply belongs to T005.
