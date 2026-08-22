# Role lifecycle bridge contract

`compile_role_lifecycle.py` and `apply_role_lifecycle.py` form the trusted,
local successor bridge from a scheduled Worker result to a complete Supervisor
candidate lifecycle. They do not call a provider, run a command, mutate
GoalBuddy, accept a checkpoint, or install Codexmax.

The supported order for one existing Worker lane is:

1. `worker_self_test` from a controller-supplied `TrustedCommandReceipt v1`;
2. scheduled Tester output adapted to `independent_test`;
3. scheduled Documenter output adapted to `documentation_result`;
4. scheduled Auditor output adapted to `audit_result`; and
5. controller-owned `candidate_closeout`.

The legacy `apply_scheduled_dispatch.py` remains the Worker-result gate. It
continues to reject non-Worker reference bundles. The lifecycle bridge consumes
those typed, empty non-Worker bundles separately and targets the already
existing Worker lane; it never treats a Tester, Documenter, or Auditor dispatch
assignment as a new Supervisor Worker lane.

## Trusted command evidence

A `TrustedCommandReceipt v1` is evidence supplied by the trusted local
controller after commands have run. Provider output cannot substitute for it.
The receipt binds its purpose, Worker lane and assignment, normalized command
rows, aggregate result, and a canonical self-digest. It declares
`authority: trusted_local_runtime` and `provider_generated: false`.

For Worker self-test, command strings must exactly equal the self-test list
frozen in the Supervisor assignment. For Tester promotion, every trusted
command must be `completed` and `pass` before the provider artifact may report
`lifecycle_result: pass`. A missing receipt, `not_run`, result disagreement,
different lane or assignment, changed digest, or model-only success claim fails
closed. The lifecycle compiler validates receipts; command execution and its
containment remain the responsibility of the trusted controller that creates
the receipt.

## Provider role artifacts

Each role still runs through the one-attempt scheduler seam and deterministic
artifact-quality gate. The provider receives only its declared artifact
authority. The provider artifact remains the exact raw byte sequence returned
by transport: it is never rewritten, normalized, extracted, or reserialized.

For lifecycle compilation, the assignment must bind a closed strict response
schema whose only required top-level fields are the exact `route_identity`
object and a nonempty string `content`. The compiler reuses the dispatcher's
strict one-object parser and schema validator. Before it reads `content`, it
reverifies the artifact descriptor, schedule manifest, reference bundle,
assignment and route-packet bindings, exactly one selected successful attempt,
the dispatcher's positive response-identity validation, absence of fallback,
retry, and failover, and equality between the artifact `route_identity` and the
expected identity recomputed from the selected route. Missing, null, stale,
duplicate-key, extra-field, schema-drifted, or mismatched evidence fails closed.

Only after those gates pass does the lifecycle-only semantic view expose the
top-level `content` string. The adapter runs its marker expression only against
that string, never against serialized JSON, sibling/nested fields, or a
recursive traversal. `content` must contain exactly one control marker:

- Tester: `lifecycle_result: pass` or `lifecycle_result: fail`;
- Documenter: `semantic_changes: none`;
- Auditor: `lifecycle_result: pass` or `lifecycle_result: fail`.

These markers are advisory inputs, not acceptance. A marker in `route_identity`
or any other wrong field is ignored and rejected by the closed schema; fenced
or prose-wrapped JSON is not recovered. Tester pass is also bound to
passing trusted command rows. Tester and Auditor route packets must require
independence and exclude the Worker builder's exact independence group.
Documenter derives only from the preserved Worker and independent-test
artifacts already recorded by Supervisor.

The compiler reconstructs the assignment's effective configuration and exact
prepared route packet, then verifies the schedule manifest, task envelope,
return manifest, deterministic quality receipt, selected route, semantic role,
profile, artifact descriptor, current lane phase, GoalBuddy hashes, and
Supervisor cursor. Scheduler semantic profiles are accepted only through the
explicit role mapping:

- Tester: `semantic_independent_artifact`;
- Documenter: `semantic_document_artifact`;
- Auditor: `semantic_embedded_audit`.

The Supervisor retains its legacy semantic floors and validates the mapped
event again. No profile alias widens read, write, command, consequence,
independence, or artifact scope.

## RoleLifecyclePacket v1

The compiler emits one immutable `RoleLifecyclePacket v1`. It binds:

- stage, target Worker lane, Worker assignment and active task;
- GoalBuddy goal/board hashes and exact Supervisor state/log cursor;
- schedule manifest, task envelope, headless assignment, trusted command
  receipt, or closeout artifact descriptors as applicable;
- every provider or predecessor source-artifact descriptor;
- exact scheduled dispatch identity for scheduled roles;
- one proposed Supervisor event; and
- `applied_to_supervisor: false`, `applied_to_goalbuddy: false`,
  `accepted: false`, with Parent Codex as acceptance authority.

Compilation dry-runs the proposed event against a copy of current Supervisor
state. Any stale phase, cursor, source, artifact, route, independence, or
authority binding is rejected before application.

## Application and recovery

Application revalidates the packet and every descriptor and, on first apply,
recompiles the exact packet against current state. Scheduled roles also
reverify the active fenced lease, return manifest, quality receipt, and typed
role-reference bundle. The fixed lock order is scheduler lock followed by the
shared Supervisor lock. Self-test and closeout use only the Supervisor lock and
must not receive a ledger argument.

Before mutation the application creates the same hash-bound recovery WAL used
by scheduled Worker application. Recovery supports any nonempty event count,
records every expected event and state snapshot, accepts only its exact applied
prefix, and preserves the first application timestamp. The current lifecycle
packet contains one event. After that event is durable, scheduled roles append
or exactly reuse the deterministic dispatch-completion ledger stages and
release their lease. Retry is idempotent; unrelated state, board, artifact,
event-log, receipt, or ledger drift fails closed.

The final `RoleLifecycleApplicationReceipt v1` is immutable and explicitly
records `supervisor_applied: true`, `goalbuddy_applied: false`, and
`accepted: false`. `candidate_closeout` may mark the local runtime
`candidate_complete` and request a Parent decision, but only Parent review plus
GoalBuddy-owner mutation can accept or advance the board.

## Proof boundary

Deterministic fake-process tests prove the local packet, application, recovery,
independence, and non-acceptance semantics. They do not prove live provider CLI
syntax, authentication, entitlement, quota, billing, containment, installation,
AOL integration, or real provider diversity. Those remain separately qualified
operations.
