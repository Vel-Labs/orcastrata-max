# Codexmax WorkGraph Notes v1 Contract

## Purpose And Authority

WorkGraph Notes is a task-scoped facade over the accepted activity-v1 ledger.
It creates, presents, filters, and tracks unread activity without writing
GoalBuddy `state.yaml` or `.goalbuddy-board/updates.jsonl`. Notes never grant
scope, permission, authority, canonical mutation, checkpoint acceptance, or
goal acceptance. Parent Codex remains the sole acceptance authority.

## Create And Identity

`create` accepts exactly an activity-v1 draft and the current canonical board
SHA-256. The hashes must match before append. Event and task IDs are bounded
safe identifiers. All activity validation, hashing, timestamp, evidence,
identity, reply, correction, and append locking is delegated to the accepted
activity-v1 implementation. Known identity remains at its supplied provenance;
unknown provider, model, route, runtime, agent name, or agent ID remains the
literal unknown fact and is never promoted from a role or body.

Only the exact canonical absolute regular `.goalbuddy-board/activity.jsonl`
path is accepted. Every symlinked ancestor, direct symlink, hardlink,
traversal, `state.yaml`, and `updates.jsonl` fails before use. Opened activity,
cursor, temporary, and lock files use no-follow opening where the host provides
it, regular-file identity agreement, and exactly one filesystem link.

Every note operation retains that validated activity descriptor through its
sensitive work and verifies that the canonical directory entry names the same
unique regular device/inode before and after. Create locks, parses, delegates
row construction and hashing to accepted activity-v1 primitives, appends,
flushes, and fsyncs through that descriptor. Presentation, unread, and
mark-read parse and fence the already locked descriptor without reopening its
pathname. Ledger identity derives from the captured descriptor and canonical
path. Name substitution fails clear without writing the replacement target.

## Presentation And Relationships

Presentation preserves every ledger event. Correction metadata names the
original event, latest event, current/superseded state, and a visible corrected
marker; it never replaces a historical row. Filters deterministically combine
task IDs, event IDs, note kinds, roles, exact identity fact/provenance,
evidence presence, correction state, and one relationship selection.

Relationship modes are roots, direct replies, transitive descendants,
correction targets, and the complete corrected-history component. Replies and
corrections retain the accepted same-task, prior-event, and acyclic gates.

## Decision Requests

An activity `decision_request` is projected as `pending` with
`authority_effect: none` and `acceptance_effect: none`. Prose in any other note
kind, including a Parent role label or forged approval phrase, is ordinary
text and cannot become a decision or grant. A pending request must travel
through the accepted Parent-reviewed updates and GoalBuddy adapter path before
canonical state can change.

## Durable Unread Cursors

Unread cursors are consumer-specific, optional-task-specific v1 JSON. They bind
the resolved activity path, filesystem ledger identity, next global sequence,
and exact prior event hash. The derived path is distinct per scope:
`.goalbuddy-board/cursors/notes/<consumer>--global.json` for global activity
and `<consumer>--task-<sha256(task-id)>.json` for each task. Callers cannot
select another registry. Corrupt, stale, ahead, aliased, replaced-ledger, and
other-ledger cursors fail clear. Reading unread notes performs no write.

`mark-read` holds the accepted activity file lock against append, holds a
stable scope-specific consumer lock, validates any existing sequence and prior
hash, derives the current head, writes a sibling temporary file, fsyncs,
atomically replaces the cursor, and fsyncs the cursor directory. Restart replay
therefore observes either the prior valid cursor or the new valid cursor.

## Library CLI And Proof Boundary

Library operations are `create_note`, `present_notes`, `unread_notes`, and
`mark_read`. CLI operations are:

```sh
python3 workgraph_notes.py create <activity.jsonl> <draft.json> --board-hash sha256:<hex>
python3 workgraph_notes.py present <activity.jsonl> [--filters filters.json] [--board-hash sha256:<hex>]
python3 workgraph_notes.py unread <activity.jsonl> <consumer-id> [--task-id ID]
python3 workgraph_notes.py mark-read <activity.jsonl> <consumer-id> [--task-id ID]
```

All CLI JSON inputs reject duplicate keys. Stdout is one canonical JSON
receipt. Success exits zero; input, path,
activity, filter, identity, board, cursor, corruption, and storage failures
exit two with one stable error code. T006 proves only the local note facade;
the tool facade, GoalBuddy frontend, migrations, browser workflow,
installation, provider behavior, and final acceptance remain later work.
