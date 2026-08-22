# Supervisor Restart And Recovery Contract

## Boundary

T006 is a deterministic repository-local recovery layer over the accepted T012
Supervisor loop and T005 Parent/Supervisor synchronization histories. GoalBuddy
remains board truth and Parent Codex remains the only authority that may accept
a checkpoint, change scope, or complete a goal.

The runtime does not read a transcript, reconstruct board truth or authority,
call a provider, invoke a Desktop adapter, create or replace a chat, prove a
native `/side` identity, install anything, or mutate GoalBuddy. Every output
retains `board_mutated: false`, `transcript_used: false`,
`native_side_proof: false`, and `acceptance_claimed: false`.

T179 provider attempt ambiguity remains in its own normalized event and T170
attempt receipts. This recovery layer cannot convert `execution_unknown` to a
retryable state. It cannot issue a fallback, hedge, replacement route, or new
grant. Parent must reconcile the immutable T170 evidence before any new task.

## Recovery Inputs

Initialization requires all of the following:

- the current goal and GoalBuddy board with T006 as the one active task and
  Parent-accepted T005 as its dependency;
- a current T012 loop state and complete append-only event history bound to the
  current goal, board, and T006;
- the accepted T005 synchronization predecessor state, complete append-only
  history, and complete Parent cursor history;
- a bounded Supervisor inventory that explicitly says it was not reconstructed
  from transcript.

The T012 and T005 bindings are hashed into the recovery initialization event and
reverified before every apply and snapshot/restart. A changed, corrupt,
truncated, or mismatched substrate fails closed.

## Supervisor Reconciliation

The accepted T005 Supervisor identity is reused. T006 increments its local
recovery epoch; changing the Supervisor ID is not a model failover. Any active
observation at an old task, wrong goal, old epoch, or duplicate active identity
must be explicitly disclosed. Undisclosed stale or duplicate activity returns
`stale_supervisor_undisclosed` or `duplicate_supervisor_undisclosed`.

Execution begins in `reconciliation_required`. Only a Parent-sourced
`goalbuddy_reconciled` event containing exactly one active expected Supervisor
may enable work. Every disclosed stale or duplicate observation must be
terminal in that clean inventory. A stale or duplicate actor cannot continue
under the expected Supervisor identity.

## Controls

Parent-sourced controls provide:

- `pause` and a separate `resume`;
- `revise` with exact scope;
- `repair_assignment_authorized`, which names the terminal failed assignment
  and a distinct repair assignment ID before T012 may create that assignment.
  The event also binds the revision/action ID, recovery epoch, expected and
  result artifact path, read/write scope, route profile, task, lane, repair
  role, and write mode;
- `stop`, which is terminal for execution;
- `goalbuddy_reconciled` and `cursor_recovered`.

Supervisor-sourced evidence provides:

- `restart_verified` after all bindings pass;
- `repair_assignment_acknowledged` only when the pinned T012 history proves a
  fresh assignment, terminal predecessor, and preserved failure evidence.

Unresolved authority stops initialization or resume. Transcript, chat history,
board-from-transcript, authority-from-transcript, acceptance, and self-granted
authority keys fail closed.

T012 remains the execution owner. While GoalBuddy's active task is T006, every
T012 `apply` must include the verified recovery state/event/cursor paths, the
accepted T005 sync state/event/cursor paths, the exact Supervisor ID and epoch,
and a goal-lifetime-unique transition ID. A direct apply without that complete
control packet, or an apply while recovery is paused, stopped,
`revision_required`, stale, or authority-blocked, fails before a T012 event is
written. `stop` is terminal.

## Append-Only Recovery And Cursor Histories

Recovery events have unique event and action IDs, deterministic timestamps,
source and actor identity, prior-event hash, and pre/post durable-state
projection hashes. `last_event_id` participates in the projection. Event
sequence and event hash are compared directly with replay. Duplicate events or
actions never reapply work.

Each permitted T012 event uses an append-only write-ahead handshake. Recovery
first records `loop_transition_prepared` with the old T012 head and exact
expected new head. T012 then appends its event and state, after which recovery
records `loop_transition_committed` and advances the pinned loop binding. On
restart, an unwritten prepare remains safely pending, while a T012 write whose
commit was interrupted is deterministically reconciled and committed exactly
once. Any third head, reused transition ID, changed event receipt, or partial
history mismatch fails closed.

For a repair assignment, `loop_transition_prepared` additionally binds the
complete immutable Parent authorization. Recovery independently compares the
submitted assignment with that authorization and the replayed open failure
before prepare, then compares the committed T012 repair lane with it again
before commit. The authorization moves through `authorized`,
`assignment_prepared`, and `assignment_committed` exactly once. The mediated
`repair_result` must carry the authorized result path and write only within the
authorized scope; its prepare/commit moves through `result_prepared` and
`result_committed` exactly once.

The authorization is single-use. Missing or extra authorization fields, wrong
predecessor or repair ID, reused
assignment or artifact paths, artifact substitution, scope broadening, wrong
route profile, task, lane, role, mode, action, or epoch fail before either log
grows. An authorization cannot be reused for a later repair. `stop` marks it
`invalidated`; a changed board fails the pinned board binding, and an epoch
change expires it.

The Parent recovery cursor is a separate append-only hash chain. Each record
binds a complete recovery event-head tuple. Cursor sequence, cursor hash, and
consumed sequence/ID/hash are included in recovery state and therefore in the
event projection chain. A valid stale cursor may catch up through
`cursor_recovered`; corrupt, truncated, decreasing, out-of-range, or state-
mismatched cursor history fails closed.

## Failure And Repair

T012 remains the assignment lifecycle owner. Recovery never fabricates a
repair assignment. After `revise`, Parent must issue
`repair_assignment_authorized` against a pinned open failure before T012 may
create the named repair assignment. The authorization's expected and result
artifacts must be identical because T012 requires the result artifact to equal
the assignment's fresh expected artifact. Its scopes must be bounded by the
Parent revision, the failed lane, and GoalBuddy. A Supervisor acknowledgement
must match a pinned T012
`preserved_predecessors` row whose original assignment is terminal, whose
failure evidence remains nonempty and hash-preserved, and whose current repair
assignment uses a distinct ID. Reuse, missing evidence, or changed artifacts
fails closed.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/recover_supervisor_runtime.py \
  initialize --goal <goal.md> --board <state.yaml> \
  --loop-state <loop-state.json> --loop-events <loop-events.jsonl> \
  --sync-state <sync-state.json> --sync-events <sync-events.jsonl> \
  --sync-cursor <sync-cursor.jsonl> --inventory <inventory.json> \
  --state <recovery-state.json> --events <recovery-events.jsonl> \
  --cursor <recovery-cursor.jsonl> --timestamp <UTC-seconds>

python3 plugins/codexmax-orchestrator/scripts/recover_supervisor_runtime.py \
  apply <same bindings and paths> --event <recovery-event.json>

python3 plugins/codexmax-orchestrator/scripts/recover_supervisor_runtime.py \
  snapshot <same bindings and paths>

python3 plugins/codexmax-orchestrator/scripts/run_goalbuddy_supervisor.py \
  apply --goal <goal.md> --board <state.yaml> \
  --state <loop-state.json> --events <loop-events.jsonl> \
  --event <loop-event.json> --repository-root <repository> \
  --recovery-state <recovery-state.json> \
  --recovery-events <recovery-events.jsonl> \
  --recovery-cursor <recovery-cursor.jsonl> \
  --sync-state <sync-state.json> --sync-events <sync-events.jsonl> \
  --sync-cursor <sync-cursor.jsonl> \
  --recovery-transition-id <unique-id> \
  --supervisor-id <exact-id> --supervisor-epoch <exact-epoch>
```

All commands are local-not-native evidence. They do not satisfy T013 or the
final visible Desktop oracle.
