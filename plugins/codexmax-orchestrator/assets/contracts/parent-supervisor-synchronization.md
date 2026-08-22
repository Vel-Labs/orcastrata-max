# Parent And Supervisor Synchronization Contract

## Boundary

This contract defines deterministic repository-local synchronization for T005.
It does not read a full transcript, call a provider, invoke a Desktop adapter,
prove a native `/side` identity, mutate GoalBuddy, grant scope or authority, or
accept a checkpoint or goal. GoalBuddy `state.yaml` remains read-only board
truth and Parent Codex remains the only acceptance authority.

T179 normalized provider events can be summarized as bounded Supervisor
deltas only after their event and T170 aggregate digests validate. The
synchronization layer does not reinterpret capability, qualification, task
authority, mutation state, or `execution_unknown`. It does not fold provider
artifacts or accept them.

The runtime is `scripts/synchronize_parent_supervisor.py`. It locks its state to
the current goal and board SHA-256 values and requires T005 to be the one active
task with Parent-accepted dependencies through the accepted T012 inspector.

## Typed Append-Only Protocol

Every synchronization event has schema version, stable event ID, deterministic
UTC timestamp, source role, actor ID, event type, typed payload, sequence,
previous-event hash, board hash, audience, proof boundary, and canonical event
hash. The JSONL log is append-only. Sequence gaps, duplicate IDs, broken prior
hashes, payload replacement, or projection/log cursor mismatch fail closed.

The first event is `sync_initialized`. It binds the goal, checkpoint, Parent
ID, Supervisor ID, fixed control routes, state epoch, and initial durable-state
projection hash. Every later event records both the complete pre-transition and
post-transition projection hashes; those hashes form a second chain inside the
event hash chain. The mutable JSON projection includes `last_event_id`. It
excludes only event sequence and event hash, whose values depend on the record
being created and are instead checked directly against replay.

Before append, relay, consume, snapshot, or restart, the runtime requires the
complete mutable event-head tuple (`event_sequence`, `last_event_id`, and
`last_event_hash`) to match the replayed event log, its complete projection hash to
match the final transition receipt, and its Parent, Supervisor, control-route,
checkpoint, and epoch identity to match `sync_initialized`. Editing only state
to clear `paused`, remove a pending authority request, change status, replace a
Supervisor ID, change epoch, erase closeout state, or alter any other durable
field therefore fails closed. Recovery never trusts the mutable projection by
itself.

Parent controls are:

- `parent_pause` and `parent_resume`;
- `parent_message`;
- `parent_open`;
- `parent_request_candidate_closeout`;
- `parent_authority_response`.

Supervisor-to-Parent deltas are:

- `milestone`, `decision_needed`, `failure`, and `validation`;
- `candidate_closeout`;
- `side_user_comment`;
- `side_authority_change_request`.

There is no Worker source role. Actor IDs are locked at initialization. Local
actor binding is not native identity proof; `native_identity_verified` remains
false until the later T013 native oracle.

## T012 Relay

Lifecycle deltas may be relayed only from a selected record in a complete T012
JSONL event log that passes the accepted T012 sequence and hash-chain verifier.
The synchronization event retains only the source sequence, event ID, type,
and hash plus a bounded summary. It never copies a transcript or reconstructs
GoalBuddy authority. A source event hash may be relayed once.

Assignment, route, result, and documentation records become milestones.
Self-test, independent-test, and audit records become validation or failure
deltas. Candidate closeout can be emitted only through this verified relay and
retains `applied_to_goalbuddy: false`.

## Durable Parent Cursor

The Parent reads new structured deltas through a separate append-only cursor
JSONL. Each cursor record has its own monotonic sequence and hash chain and
binds the last consumed synchronization sequence to that event's hash.
Consumption scans a contiguous bounded batch, returns only Parent-audience
deltas, and advances past the complete scanned batch. A stale, decreasing,
out-of-range, identity-mismatched, or event-hash-mismatched cursor fails closed.

Repeated full transcript ingestion is neither required nor accepted. Payload
keys for transcripts, chat/conversation history, acceptance, completion,
authority grants, or scope grants fail closed.

## Comments, Authority, And Pause

A side user comment requiring a Parent response pauses local progression. A
side authority-change request must name an exact scope, remain `pending`, and
set `applied_to_execution: false`; it pauses immediately. A Parent authority
response records `approve` or `deny`, an external durable authority reference,
and `applied_to_execution: false`. A separate Parent resume control is required
after the response. The synchronization layer never materializes the grant.

While paused, Supervisor milestone, validation, and closeout progression is
rejected. Failure, decision-needed, and further user-comment evidence may still
be surfaced. Open and message controls record local requests with
`external_action_performed: false`; they do not claim the Desktop host acted.

## Candidate Closeout And Acceptance

Parent may request a candidate closeout. The Supervisor may relay a verified
T012 candidate closeout. Neither operation accepts anything. All state and log
records retain:

- `board_mutated: false`;
- `transcript_ingested: false`;
- `native_side_proof: false`;
- `acceptance_claimed: false`;
- `external_action_performed: false`.

Only Parent review followed by the GoalBuddy owner may advance board truth.
Local tests and receipts are not native Desktop proof.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/synchronize_parent_supervisor.py \
  initialize --goal <goal.md> --board <state.yaml> --state <sync-state.json> \
  --events <sync-events.jsonl> --cursor <parent-cursor.jsonl> \
  --parent-id <id> --supervisor-id <id> --timestamp <UTC-seconds>

python3 plugins/codexmax-orchestrator/scripts/synchronize_parent_supervisor.py \
  apply --goal <goal.md> --board <state.yaml> --state <sync-state.json> \
  --events <sync-events.jsonl> --cursor <parent-cursor.jsonl> --event <event.json>

python3 plugins/codexmax-orchestrator/scripts/synchronize_parent_supervisor.py \
  relay-loop --goal <goal.md> --board <state.yaml> --state <sync-state.json> \
  --events <sync-events.jsonl> --cursor <parent-cursor.jsonl> \
  --loop-events <supervisor-events.jsonl> --loop-sequence <n> \
  --event-id <id> --timestamp <UTC-seconds>

python3 plugins/codexmax-orchestrator/scripts/synchronize_parent_supervisor.py \
  consume --goal <goal.md> --board <state.yaml> --state <sync-state.json> \
  --events <sync-events.jsonl> --cursor <parent-cursor.jsonl> \
  --timestamp <UTC-seconds> --scan-limit 50
```

Exit 0 proves only the local deterministic operation. Exit 2 reports a stable
fail-closed code.
