# Provider Fan-Out V1

## Purpose

`provider_fanout.py` compiles several independent provider-dispatch lanes into
one Parent-owned plan. `run_provider_fanout.py` executes that plan by composing
the existing scheduler admission, execution binder, one-attempt dispatcher,
and visible-result finalizer. Neither module applies a Supervisor event,
mutates GoalBuddy, folds a result, or accepts work.

The existing `DispatchReturnManifest v1` stays single-route and one-attempt.
Fan-out composes that boundary. It does not weaken it.

## Execution Controller

The Parent supplies one immutable runtime-input row for each allowed lane
attempt. Each row contains exactly one route candidate. The controller does not
manufacture or select a route, capability, grant, preflight, lease, fencing
token, assignment, or task envelope. The composed executor calls
`schedule_headless_dispatch.admit`, `bind_scheduled_dispatch`,
`run_headless_provider_dispatch.run_dispatch` in scheduler-bound one-attempt
mode, and `finalize_visible_provider_dispatch` in that order.

Source validation injects the complete lane executor. It cannot enter the
composed executor or call a provider. Its sibling finalization result is
`ProviderFanoutSourceLocalFinalization` with status
`source_validated_non_promotable`. Source-local results require both external
call and provider network markers to be false. They can never become
`candidate_ready`. The CLI fails closed because it has no authority-input
surface.

The source-local and live entry paths are distinct. An arbitrary
`LaneExecutor` can enter only `source_local_controller`. The live entry requires
the exact `ComposedLaneExecutor` type. It rejects fixture worktree probes. A
source-local executor cannot produce a live candidate even when it forges a
live-looking finalization document.

The first runtime uses a hard read-lane semaphore equal to the smallest of the
plan limit, task cap, fleet cap, and two. Read-only and artifact-only lanes can
overlap. Scoped-write lanes start only after all read lanes finish. Scoped-write
lanes always run one at a time.

Each attempt gets an absent-only evidence directory and one immutable
`ProviderFanoutExecutionAttemptRecord`. The record binds the exact route,
capability, preflight, lease, fence, execution binding, grant, worktree,
timestamps, dispatch observations, finalization outputs, and terminal status.
Every attempt keeps the exact lane capability card and task grant. A retry must
use a different preflight, lease, fence, execution binding, and evidence
directory. The aggregate consumes these
validated record bytes. It does not consume caller summaries.

Evidence-directory creation uses descriptor-relative, no-follow directory
operations. It verifies each existing parent as a real directory before it
creates the next component. An intermediate symlink cannot create a directory
outside the artifact root.

The live path calls the composed executor's mandatory Git worktree verifier
before admission. The verifier checks the exact top-level path, HEAD identity,
and an empty porcelain status. It emits a digest-bound
`VerifiedFanoutWorktreeReceipt`. The controller validates and persists this
receipt. The source-local path can use a fixture probe, but its record marks the
probe as `fixture_source_local` and remains non-promotable.

After the exact-type check, the live controller calls each
`ComposedLaneExecutor` class method directly. Instance attributes cannot
replace worktree verification, admission, binding, pre-spawn validation,
run-one, finalization, semantic finalization validation, or lease release.

## Lane Boundary

The Parent supplies every lane. The plan binds immutable descriptors for the
candidate, board, effective configuration, and Parent authority. Each descriptor
must match its declared plan digest. Each lane binds one task, route, provider,
model, harness, independence group, capability card, preflight, lease, fencing
token, execution binding, mutation mode, worktree path and identity, base tree,
evidence directory and identity, task grant, and explicit read and write scope.
Lane IDs, task IDs, routes, independence groups, worktrees, evidence roots,
leases, fences, and execution bindings must be unique. Write scopes cannot
overlap.

The capability card, task grant, `VisibleProviderTaskState`, and
`DispatchExecutionAttemptIdentity` are immutable file descriptors under the
supplied artifact root. Compilation verifies each file digest. It calls
`provider_work_authority.effective_authority` for the capability card and task
grant. It also calls the existing task-state validator. It verifies the exact
single-attempt execution-binding shape and binds its task, route, lease, fence,
preflight, and evidence directory. The effective route, task, access mode,
scopes, base tree, and authority digests must equal the lane fields. A
caller-supplied digest alone is not authority.

Read-only and artifact-only lanes can share a concurrent execution wave up to
the explicit plan limit. Scoped-write lanes run in separate serialized waves.
This contract does not qualify concurrent writes.

## Retry Boundary

The scheduler can replace a lane attempt at most twice. A replacement is valid
only when the prior attempt failed before provider process spawn and before an
external call. The accepted classes are:

- `lease_expired_before_spawn`;
- `preflight_expired_before_spawn`;
- `protected_capability_expired_before_spawn`;
- `evidence_collision_before_claim`.

The prior receipt is an immutable `FanoutPreProviderFailureReceipt` file. The
controller verifies its file digest, canonical receipt digest, attempt identity,
route identity, authority bindings, and terminal markers. The next attempt must
be fully bound when the retry decision is made. It gets a new attempt ID,
preflight, lease, fence, execution binding, evidence directory, and evidence
root identity. Reuse fails closed. The route, provider, model, harness, grant,
worktree, capability, and scope stay exact.

A provider process remains one-attempt. A retry also requires a finalized,
certain pre-spawn failure receipt and terminal release of any admitted lease.
Process spawn, external call, mutation,
possible mutation, timeout, disconnect, partial capture, malformed terminal
output, receipt failure, or `execution_unknown` forbids retry. Automatic route
fallback and hedging are forbidden.

The controller does not make a retry decision from exception flags. It first
persists an immutable `FanoutPreProviderFailureReceipt`. It reloads the file and
validates its digest, attempt, lane, route, authority, stage, and all negative
effect markers. It then admits and binds the successor. Only after it proves
the exact lane capability and grant plus a fresh preflight, lease, fence,
execution binding, and evidence directory does it persist
`ProviderFanoutRetryDecision` and permit the
successor to reach run-one. A failure before a complete binding fails closed.

An `evidence_collision_before_claim` occurs before admission and binding. The
controller writes its immutable receipt and attempt record to a separate
absent-only claim-failure directory. It never reads or writes the occupied
attempt directory. It then claims `attempt-002` and applies the normal fresh
preflight, lease, fence, and execution-binding checks. The lane capability card
and grant remain exact.

## Aggregate Receipt

One aggregate receipt references one receipt for every lane. It preserves the
complete ordered attempt history. Earlier attempts can exist only as certain
pre-provider failures and must bind their failure and retry-decision digests.
A `candidate_ready` scoped-write lane requires an exact diff digest. The term
`accepted` is reserved for Parent action and is not a child status.

The aggregate validates the exact plan fan-out ID, lane ID, attempt ID,
contiguous attempt index, route, authority shape, worktree boundary, and lane
evidence path. Attempt IDs and evidence paths are unique across all lanes. A
self-consistent digest cannot change a record status unless all closed status
semantics still match. Only a live-composed record with the semantic-finalizer
marker can become `candidate_ready`.

Each lane receipt carries verified single-link descriptors for its
`VisibleProviderTaskState`, schedule manifest, dispatch return, quality receipt,
and reconciliation receipt. The controller calls
`reconcile_visible_provider_result` with the first four documents. The stored
reconciliation must equal the recomputed document. The reconciliation status,
not caller booleans, determines `candidate_ready`, `rejected`, or
`execution_unknown`. Candidate artifact identity must equal the validated
dispatch-return artifact identity.

R2 does not promote a scoped-write lane to `candidate_ready`. That status needs
semantic validation of the canonical provider change receipt and changed-path
scope. Read-only and artifact-only results can become fold candidates. Parent
acceptance remains separate.

Telemetry records attempts, turns, latency, process count, tokens, quota, and
cost. Values must be finite and non-negative. An unobserved value is the
literal string `unknown`. It is never zero.

The aggregate can list fold candidates after a child audit passes. It always
sets these values to false:

- `accepted_by_parent`;
- `board_mutation_performed`;
- `fold_performed`.

Parent Codex reviews the referenced files, diffs, tests, audit receipt, and
route identity before a separate application or board decision.

Before a live lane can become a candidate, the exact composed executor reloads
the task state, quality receipt, schedule manifest, and reconciliation. It
verifies each descriptor and digest. It recomputes reconciliation with
`reconcile_visible_provider_result` and requires exact semantic equality plus
`candidate_ready_for_sol_review`. Injected finalizer output is never sufficient.

## Proof Boundary

Compilation, injected-executor concurrency tests, retry classification,
aggregation, and schemas are source-local proof only. They prove controller
ordering and fail-closed behavior. They do not prove provider availability,
live concurrent process execution, tool access, protected authority,
installation, or product acceptance. A live run needs fresh Parent-owned
runtime inputs and separate action-specific provider authority.
