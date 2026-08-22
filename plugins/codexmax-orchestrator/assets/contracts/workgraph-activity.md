# Codexmax WorkGraph Activity v1 Contract

## Purpose And Authority

`.goalbuddy-board/activity.jsonl` is the append-only WorkGraph activity stream.
It records task-scoped notes and evidence; it is not canonical board state and
cannot grant scope, authority, acceptance, or permission to edit `state.yaml`.
GoalBuddy `state.yaml` remains canonical and Parent Codex remains the only
checkpoint and goal acceptance authority.

## Row Shape

Every JSON line is a strict object with exactly these fields:

- integer `schema_version: 1`, unique `event_id`, `task_id`, positive monotonic
  `sequence`, and a strict RFC3339 UTC date-time `timestamp` in
  `YYYY-MM-DDTHH:MM:SS[.fraction]Z` form. Date-only, missing-seconds, space
  separator, offset, and invalid calendar/time values fail closed;
- `event_kind`: `progress`, `observation`, `question`, `concern`, `blocker`,
  `test_result`, `decision_request`, `handoff`, or `correction`;
- `author_role`: `Worker`, `Tester`, `Auditor`, `Parent`, `user`, or `system`;
- strict `identity` facts for agent name and ID, provider, model, route, and
  runtime. Each fact is `{value, provenance}`. Unknown is represented only by
  `{value: unknown, provenance: unknown}`. A known runtime requires observed or
  receipt-backed provenance. Identity never implies tools or authority;
- nonempty `body`, strict structured `evidence` references, optional `reply_to`
  and `correction_of` event IDs, and the canonical `board_sha256` observed by
  the author;
- `previous_event_hash` and `event_hash` as lowercase SHA-256 hex.

Evidence references contain exactly `evidence_id`, `locator`, and `digest`.
Digest is `unknown` or `sha256:` plus lowercase hex. Evidence IDs are unique in
one event and have no authority effect.

## Hashing And Append

Canonical JSON is UTF-8, key sorted, compact separators, and unescaped Unicode.
The event hash is SHA-256 of the canonical complete row excluding only its own
`event_hash` field. The first previous hash is 64 zeroes. Every later row binds
the preceding event hash.

`append_event` takes a strict draft without sequence or hash fields. It locks
the ledger with an exclusive advisory file lock, reads and verifies the entire
current stream, derives the next sequence and both hashes, appends one compact
newline-terminated record, flushes, and fsyncs before success. Concurrent
writers serialize under that lock. A partial or non-newline-terminated record
fails verification and is never treated as an event.

## Replies, Corrections, Replay, And Cursors

Replies and corrections must target an earlier event on the same task. Only a
`correction` event may carry `correction_of`, and every correction must carry
one. History is never replaced. Missing targets and correction cycles fail
closed.

Replay preserves ledger order and can filter by task and event kind. A v1
consumer cursor contains exactly schema version, consumer ID, next sequence,
and the hash immediately before that sequence. The cursor schema version must
be an integer and cannot be a boolean or numerically equal float. `consume`
checks both position
and hash, returns bounded rows and a new derived cursor, and never writes or
authorizes the ledger. A cursor beyond the head or bound to another history
fails clear.

## Library And CLI

Library operations are `append_event`, `read_rows`, `verify_rows`, `replay`,
and `consume`. CLI operations are:

```sh
python3 workgraph_activity.py append <activity.jsonl> <draft.json>
python3 workgraph_activity.py verify <activity.jsonl>
python3 workgraph_activity.py replay <activity.jsonl> [--task-id ID] [--event-kind KIND]
python3 workgraph_activity.py consume <activity.jsonl> <cursor.json> [--limit N]
```

CLI stdout is one canonical JSON receipt. Success exits 0. Protocol, input, or
storage failure exits 2 with a stable `error` value. Missing, empty, blank,
truncated, invalid JSON, duplicate-key, wrong-version, duplicate-ID,
non-monotonic, broken-chain, board-hash, reply/correction, evidence, cursor,
and append failures have distinct machine-readable errors.

## Template And Proof Boundary

`assets/templates/workgraph-activity.json` is a deterministic valid append
draft, not a recorded event and not evidence of execution. T003 proves the
local ledger protocol only; GoalBuddy projection, accepted-state application,
frontend behavior, migrations, and final acceptance belong to later tasks.
