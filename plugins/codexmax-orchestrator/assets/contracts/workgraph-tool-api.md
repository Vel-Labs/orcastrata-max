# WorkGraph Tool API v1 Contract

Readiness includes deterministic `next_ready` rows with ID, objective, clarity
tier, non-claiming basis, and next action. Blocked explanations retain stable
codes/references and add readable text. Native creation uses `propose`; no new
route or runtime is introduced.

## Purpose And Authority

`workgraph_cli.py` is the local machine-readable facade over the Parent-accepted
WorkGraph v1 runtimes. GoalBuddy `state.yaml` remains canonical board truth.
The facade delegates accepted validation, dependency, activity, update, note,
snapshot, compare-and-swap apply, and recovery behavior; it does not create a
second board, cursor, review authority, migration engine, or acceptance path.

The tool is local and standard-library only. It never reads chat or transcript
history, executes validation instructions embedded in a WorkGraph, shells
through request text, invokes a network/provider route, infers billing, or
grants scope. A success receipt records execution, not checkpoint acceptance.

## Request And Receipt Envelope

The CLI accepts exactly one absolute canonical path to one JSON request. The
request has exactly:

```json
{"arguments":{},"operation":"inspect","schema_version":1}
```

Unknown or duplicate keys, non-integer or unsupported versions, unsupported
operations, malformed JSON, aliases, symlinks, hardlinks, traversal, missing
inputs, and operation-inappropriate arguments fail closed. Each operation has
an exact argument shape; optional values are explicit `null`, never omitted.
Every referenced path is absolute, lexically canonical, and resolves without a
symlink alias. Existing inputs are unique regular files. A missing output may
be created only beneath its already existing canonical parent and remains
subject to the delegated runtime's stricter sidecar rules. Every JSON input is
opened without following the final path component, read from that validated
unique-regular-file descriptor, and checked against its canonical name both
before and after the read. A concurrent name or identity substitution fails as
`tool_path_identity_changed`; content from a substituted name is never used.

Success exits zero and returns one canonical key-sorted JSON object containing
`protocol: workgraph_tool_api`, `schema_version: 1`, the operation, `status:
ok`, a nonempty delegated result mapping, and capability discovery. Failure
exits two and returns the same protocol/version/operation identity with
`status: error` and one stable error. Delegated stable errors remain visible.
An empty or non-mapping result fails as `tool_dependency_malformed_receipt`.
Unexpected or malformed dependency behavior is an explicit nonzero tool error,
never an empty success.

## Operations

- `inspect`: `graph_path`; strictly parses and validates a WorkGraph without
  opening evidence locators or executing its instructions. Returns the exact
  input digest and T002 validation receipt.
- `ready`: `graph_path`, `satisfaction_path`, `expected_board_sha256`, and
  nullable `registry_path`; delegates T004 readiness with exact satisfaction,
  board-hash, and active-claim inputs.
- `explain-blocked`: the `ready` arguments plus `work_item_id`; returns exact
  accepted reasons. `related_to`, containment, `produces`, and `consumes` retain
  their separate meanings.
- `note`: action-specific strict arguments expose only T006 `create`, `present`,
  `unread`, and `mark-read`. The facade creates no alternate ledger, filter,
  cursor, identity, or decision logic.
- `consume`: `ledger_protocol` (`activity-v1` or `updates-v1`), `ledger_path`,
  `cursor_path`, and nullable positive `limit`; wrong-protocol cursors fail in
  the delegated accepted consumer.
- `propose`: `updates_path`, `draft_path`, and `current_board_sha256`; accepts
  only a `proposed` updates-v1 draft and retains one validated output descriptor
  through its append while reusing the accepted updates-v1 parse, verification,
  lineage, row-build, hash, and canonical-serialization primitives.
- `review`: the same arguments, accepts only a `reviewed` updates-v1 draft with
  a Parent reviewer, and uses the same stable-descriptor accepted-primitives
  append. The descriptor remains locked through flush and `fsync`, and its
  canonical name is checked again before success. Role labels and prose do not
  grant review authority.
- `apply`: `board_path`, `updates_path`, `journal_path`, `update_id`, and
  `timestamp`; delegates only the accepted T005 CAS/WAL adapter. Unsupported
  status-only active-task handoffs remain explicit failures.
- `snapshot`: `board_path`; delegates accepted GoalBuddy snapshot and version
  capability negotiation.
- `recover`: `board_path`, `updates_path`, `journal_path`, and `timestamp`;
  delegates only accepted recovery and preserves its explicit outcomes.

## Note Argument Shapes

- `create`: `action`, `activity_path`, `draft_path`, `current_board_sha256`.
- `present`: `action`, `activity_path`, nullable `filters_path`, nullable
  `expected_board_sha256`.
- `unread` and `mark-read`: `action`, `activity_path`, `consumer_id`, nullable
  `task_id`.

The accepted notes runtime owns activity path binding, identity/evidence
presentation, correction history, unread cursor derivation, and pending
decision projection. The tool facade does not weaken any of those checks.

## Capability Discovery

Every success reports exact operation names, protocol version 1 for the tool
and composed accepted runtimes, GoalBuddy as canonical owner, and booleans for
read, activity write, updates write, GoalBuddy-v2 apply/recovery, migration,
network, transcript, provider/billing, and acceptance capability. `migration`,
`network`, `transcript`, provider/billing access, and acceptance authority are
false. Capabilities do not imply installation, source access outside named
paths, provider access, token/cost knowledge, or Parent acceptance.

## Proof Boundary

T007 proves a local headless facade over accepted T002-T006 behavior. It does
not prove installation, external GoalBuddy frontend integration, migrations,
browser behavior, provider behavior, distributed locking, or final acceptance.
