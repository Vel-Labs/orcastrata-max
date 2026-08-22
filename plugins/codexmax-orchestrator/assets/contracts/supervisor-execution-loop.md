# GoalBuddy Supervisor Execution Loop Contract

## Boundary

The local Supervisor execution loop consumes a locked goal plus the current
GoalBuddy `state.yaml` as read-only board truth. It does not create a GoalBuddy
goal, mutate the board, call a provider, create a Desktop chat, reconstruct
authority from transcript, or accept a checkpoint. It provides deterministic
repository-local lifecycle and receipt proof only; it is never native `/side`
Supervisor proof.

The runtime surface is
`scripts/run_goalbuddy_supervisor.py`. Its supported operations are `inspect`,
`initialize`, `apply`, and `snapshot`.

Provider execution uses the separate T179
`provider-supervisor-harness-v1.md` seam. That seam validates normalized
provider observations and calls the accepted T170 controller once. This older
GoalBuddy lifecycle loop does not translate its assignment-event vocabulary
into provider execution events and does not gain provider authority.

Long-horizon continuation decisions are governed by
`execution-continuity.md` and may be classified with
`scripts/assess_execution_continuity.py`. That classifier is deterministic,
does not mutate this runtime or GoalBuddy, and does not claim acceptance.
Continuity actions must be persisted through an authorized runtime event or
rollover artifact before execution proceeds.

## Locked Plan And Board Truth

Before initialization and every event application, the runtime reads the goal
and board files directly and records SHA-256 digests. It requires:

- GoalBuddy schema version 2 and an active goal;
- `pm_owns_state`, `one_active_task`, and
  `parent_codex_final_acceptance` to be true;
- `max_write_workers` to be a positive integer; the runtime enforces the lower
  of that value and the absolute local ceiling of two write Workers;
- exactly one task with status `active`, identical to `active_task`;
- every active-task dependency to exist, be `done`, and carry the GoalBuddy
  Parent decision vocabulary `decision: accept` or `decision: accepted` plus
  `accepted_by: Parent Codex`;
- nonempty active-task objective, allowed files, verification commands, and
  stop conditions.

The disposition is `reuse_existing_locked_board`. A missing board, mismatched
goal, incomplete dependency, non-Parent dependency acceptance, changed plan
hash, changed board hash, or changed active task fails closed. The runtime does
not infer a replacement board from chat or its own event log. GoalBuddy remains
the only owner that can materialize or update board truth.

## Runtime State And Append-Only Deltas

Execution state is a resumable schema-v2 JSON projection. A schema-v1
projection is upgraded deterministically on read by adding lane-local phase and
repair counters plus aggregate phase/status; the append-only log is not
rewritten. The legacy `phase`, `active_lane_id`, and total `repair_cycles`
fields remain readable compatibility projections of the most recently touched
lane. Evidence is a separate schema-v1 JSONL event log, so existing event
bundles remain readable unchanged. Each event has a monotonically increasing sequence, stable event ID,
deterministic UTC timestamp, prior-event hash, board hash, payload, and SHA-256
over its canonical JSON. New events append exactly one line. Existing events
are never rewritten. Resume and snapshot verify every sequence and hash link,
reject duplicate event IDs, and require the mutable projection cursor to equal
the append-only log cursor.

Every ordinary runtime writer takes the state-owned shared runtime-pair lock
before reading or mutating the projection and log. Scheduler application holds
that same lock across its two-event Worker bundle, under the scheduler lock, and
uses its own manifest-bound recovery controller to repair only an exact
application-owned log prefix after interruption. The general Supervisor does
not infer or repair an unmatched cursor from transcript, role output, or a
foreign recovery record.

When T006 is active, `apply` is also recovery-gated. It reconciles any pending
write-ahead transition, verifies the complete T006 recovery and T005 sync
bindings, and requires the exact Supervisor ID/epoch plus a unique recovery
transition ID before computing or writing the next loop record. It records a
recovery prepare before the T012 append and a recovery commit afterward. A
missing, paused, stopped, revision-required, stale, or authority-blocked
recovery control fails before the T012 log changes; interrupted commits are
reconciled exactly once on restart.

When the event creates or reports a repair, recovery also owns the exact Parent
authorization check. T012 computes its normal deterministic transition, but
recovery will not prepare it unless predecessor and repair IDs, expected/result
artifact, read/write scope, route profile, task, lane, repair role, write mode,
authorization action, board binding, and recovery epoch all match. The same
authorization is rechecked against replayed T012 state before commit and is
single-use across restart and replay.

This event log contains structured assignments, route receipts, artifacts,
command rows, and deltas. It is not a raw transcript. Event packets containing
`transcript`, `raw_transcript`, `chat_history`, or `conversation_history` fail
with `transcript_reconstruction_forbidden`.

The state and every event explicitly retain:

- `board_mutated: false`;
- `transcript_used: false`;
- `native_side_proof: false`;
- `acceptance_claimed: false`;
- `parent_acceptance_authority: Parent Codex` in state;
- `external_call_performed: false` in each local event.

## Assignment And Ownership Gate

An internal assignment names objective, active task, role, lane mode,
dependencies, exact read/write scope, forbidden actions, registry profile,
expected artifact, self-test, independent-test requirement, and retry cap.
Writes must match the active board's `allowed_files`. Glob-bearing requested
scopes must be exactly board-authorized; a concrete path may be a subset of an
authorized board glob. A read-only lane has no write scope. `artifact_only`
lanes may coexist without consuming repository-writer capacity because their
provider output is captured and applied by the trusted local runtime rather
than mutating source directly.

Every assignment forbids checkpoint acceptance, goal acceptance, GoalBuddy
mutation, and Desktop-chat creation. Up to the board limit, capped at two,
nonterminal write Workers are allowed only when their declared write scopes do
not overlap. Read-only and artifact-only lanes may coexist with them. Internal
assignment dependencies must already be independently audited/candidate-ready
or `candidate_complete`. A
repair uses an assignment ID never consumed anywhere in the checkpoint and an
expected artifact path absent from the complete active and predecessor
history. Assignment IDs and expected/result, test, documentation, audit, and
closeout artifact paths remain reserved for the goal/checkpoint lifetime. The
prior assignment, route receipts, artifacts, and failures remain preserved.

## Route Integration

`route_resolved`, `independent_test`, and `audit_result` carry deterministic
T011 route packets. The loop calls the accepted route resolver and stores its
complete receipt. It does not trust a caller-supplied selected route. Task ID,
registry profile, read scope, and write scope must match the assignment.
Resolution must return `selected` and `external_call_performed: false`.

Builder work uses its assignment profile. Independent testing uses
`independent_test`, requires independence, and excludes the selected builder's
independence group. Audit uses `embedded_audit`. The trusted lifecycle adapter
may supply the scheduler aliases `semantic_independent_artifact` and
`semantic_embedded_audit` only when the packet's read scope is a subset of the
Worker lane and its write scope is exactly the separately captured role
artifact. The Tester alias is command-free at the provider boundary, so a pass
also requires separate trusted command rows. These aliases do not widen any
profile floor. Billing, consequence, tools, scope, attempts, failures, and
actual accounting remain governed by the accepted T011 runtime.

## Per-Lane Lifecycle And Aggregate Closeout

Each lane owns its phase and repair counter. Events are checked against the
named lane rather than a global active lane, so independent eligible lanes may
interleave their lifecycle events. `active_lane_id` identifies only the last
touched lane and grants no authority. The normal per-lane event order is:

1. `assignment_created`;
2. `route_resolved`;
3. `worker_result`;
4. `worker_self_test`;
5. `independent_test`;
6. `documentation_result`;
7. `audit_result`;
8. `candidate_closeout`.

A failed self-test, independent test, or audit moves only that lane to
`repair_required`.
Repair follows a fresh `assignment_created`, `route_resolved`,
`repair_result`, and the verification ladder again. Repair count never exceeds
the original assignment retry cap or the repository ceiling of three.
Original failed evidence remains append-only and repair budgets are per lane.

Result artifacts must be regular, non-symlinked, single-link files inside the
repository. Repair changed-file declarations cannot name any artifact or
expected-output path reserved by an ancestor. Before every repair event and
every snapshot/restart, all preserved artifacts are resolved and rehashed;
replacement, disappearance, symlinking, link-count change, size change, or
content-hash change fails closed. Changed files remain inside assignment write
scope. A passing self-test command is `completed` plus `pass`; `not_run` is
never promoted. Documentation names only previously recorded artifacts and
declares no semantic change. Aggregate phase becomes `ready_for_closeout` only
when every required current lane has a passing audit. A `candidate_closeout`
event before that point fails with `aggregate_closeout_not_ready`; no
individual lane can close the schedule early. Aggregate closeout marks all
required lanes and the aggregate projection `candidate_complete` without
claiming Parent acceptance.

`compile_role_lifecycle.py` may dry-run and bind the post-Worker events above,
and `apply_role_lifecycle.py` may apply them under the shared lock through a
hash-bound recovery WAL. Those tools cannot create an assignment, run a
provider, run a command, mutate GoalBuddy, or claim acceptance. See
`role-lifecycle.md` for their exact evidence and replay contract.

## Parent-Only Acceptance

The loop may emit `candidate_complete` and a proposed GoalBuddy delta with
`applied_to_goalbuddy: false`. It may request `accept`, `repair_directly`, or
`issue_revision_packet` from Parent Codex. Events named `parent_acceptance`,
`checkpoint_accepted`, or `goal_accepted`, or payloads that claim auxiliary
acceptance, fail with `parent_acceptance_only`.

Only Parent review followed by GoalBuddy-owner mutation can accept the
checkpoint or advance the active task. Local fixtures, state projections,
event logs, reports, and passing tests do not satisfy the native Desktop
functional oracle.

A soft forecast crossing is not Parent-only acceptance work and is not an
authority failure. The Supervisor assesses progress, optimizes the packet,
reforecasts, and continues or rolls over under existing authority. An explicit
operator token cap, cost-authority expansion, scope expansion, or other
consequential gate remains fail-closed.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/run_goalbuddy_supervisor.py \
  inspect --goal <goal.md> --board <state.yaml>

python3 plugins/codexmax-orchestrator/scripts/run_goalbuddy_supervisor.py \
  initialize --goal <goal.md> --board <state.yaml> \
  --state <runtime-state.json> --events <events.jsonl> \
  --event-id <stable-id> --timestamp <UTC-seconds>

python3 plugins/codexmax-orchestrator/scripts/run_goalbuddy_supervisor.py \
  apply --goal <goal.md> --board <state.yaml> \
  --state <runtime-state.json> --events <events.jsonl> \
  --event <event.json> --repository-root <repository> \
  --recovery-state <recovery-state.json> \
  --recovery-events <recovery-events.jsonl> \
  --recovery-cursor <recovery-cursor.jsonl> \
  --sync-state <sync-state.json> --sync-events <sync-events.jsonl> \
  --sync-cursor <sync-cursor.jsonl> \
  --recovery-transition-id <unique-id> \
  --supervisor-id <exact-id> --supervisor-epoch <exact-epoch>

python3 plugins/codexmax-orchestrator/scripts/run_goalbuddy_supervisor.py \
  snapshot --goal <goal.md> --board <state.yaml> \
  --state <runtime-state.json> --events <events.jsonl> \
  --repository-root <repository>
```

Exit 0 means the local deterministic operation succeeded. Exit 2 returns a
stable fail-closed code and detail. Neither exit status proves a provider call,
Desktop topology, installation, or Parent acceptance.
