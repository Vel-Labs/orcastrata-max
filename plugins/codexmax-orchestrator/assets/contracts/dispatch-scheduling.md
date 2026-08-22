# Dispatch scheduling contract

`DispatchScheduler v1` is a local admission and accounting boundary. It never
starts a provider process. The scheduler selects exactly one eligible route for
each attempt; retry and failover return to the scheduler rather than occurring
inside the one-attempt dispatcher seam.

## Bound inputs

An admission consumes a compiled `DispatchTaskEnvelope v1`, the exact
configuration/board/authority/WorkGraph/Supervisor digest set repeated by the
caller, an ordered route list, an expanded `SchedulerPolicy v1` compiled from
the configuration scheduler receipt plus explicit allowance/token capacities,
the current ledger, WorkGraph
claim and fencing tokens, board/config writer limits, and an injected UTC time.
Every digest must match. `hedge_requested`, repository mutation, stale context,
expired deadlines, excess queue age, widened scopes, and unbound preflight
evidence fail closed.

An optional `RouteFabricSchedulerAdvisory v1` is a constraint receipt, not a
selection or admission input. `plan()` validates its exact wrapper, decision
digest, assignment/envelope bindings, current route identity, and prior ledger
head before eligibility. `continue` preserves the ordered candidate list;
`switch` removes only the bound current route and leaves target selection to
`eligible_routes()` and `select_route()`. Handoff, unavailable, and human-gate
actions return typed non-admission failures. `admit()` revalidates the same
receipt under the scheduler lock before appending `lease_granted`; no advisory
path may write the ledger before that point.

Current route identity comparison covers every Route Fabric identity field,
including evidence-owned `adapter_id` and `adapter_sha256`. Adapter mismatch is
a typed identity mismatch before route selection. Locked admission repeats the
same comparison before any ledger mutation.

The expanded policy preserves the configuration names `global_active_limit`,
`lease_ttl_seconds`, provider/runtime-host defaults,
`diversity_min_quality_observations`, and per-role rank displacement. It also
names any more restrictive provider/runtime-host overrides and runtime
allowance/token capacities; absent overrides use the configured defaults.

Each candidate has the strict fields implemented by
`schedule_headless_dispatch.py:ROUTE_KEYS`. Its broker observation key must bind
provider, exact model, route id, runtime, reasoning, and proof mode
`scheduler_artifact_only`; the observation must still be available, healthy,
callable, and unexpired.

Each candidate also carries compiler-derived `adapter_id` and
`adapter_sha256`. The resolver independently derives both from the same
product-owned dispatcher bytes, and its `next_attempt.identity` must return
both exactly. The digest-bound resolver packet remains assignment-compatible;
caller-supplied adapter evidence is rejected. Neither configuration nor Worker
output is adapter provenance.

Broker evidence is never sufficient for admission. Every candidate also embeds
a digest-bound, task-specific `resolve_worker_route` pre-dispatch packet. Its
selected task profile has exactly one route, the candidate; no attempt outcome
is supplied. The scheduler re-runs the canonical resolver and requires
`dispatch_required` with `next_attempt.route_name` and identity equal to that
candidate. Task id, resolution time, source/input mode, token boundary,
read/write/authority scopes, consequence, independence, command requirements,
authentication, quota, billing, identity, and capability are thereby rebound
for each attempt. None of these facts may come from the broker cache.

## Atomic admission

All scheduler admissions for one ledger serialize through its
`.scheduler.lock`; the hash-chained `DispatchLedger v1` remains the durable
record. Admission atomically checks and reserves:

- global, exact-route, provider, and runtime-host capacity;
- exact evidence-path and envelope-idempotency uniqueness;
- required independence groups;
- named allowance and optional token capacity;
- unique evidence path and envelope idempotency key.

The admission's selected candidate, plan digest, and locked advisory receipt
bind all eleven Route Fabric identity fields, including adapter provenance. The
legacy `lease_granted.route` shape remains unchanged for existing binder
compatibility; it is not treated as the adapter-provenance source.

Unknown token use and cost remain the string `unknown`. Unknown token
reservation is ineligible under a finite token capacity. Any route requiring a
cash reservation is ineligible unless the task has both known cost and explicit
cash authority; envelope v1 currently denies external cash, so such a route
fails closed.

Artifact-only lanes do not consume repository-writer capacity. Providers never
receive direct repository-write authority; the trusted dispatcher captures one
exact, unique artifact path and the application gate verifies it before
Supervisor ingestion. Board/config writer limits remain bound compatibility
inputs for a future separately qualified direct-write mode, which is disabled.

Leases bind the WorkGraph claim and fencing token. A release must present the
current scheduler fencing token. Recovery is allowed only after expiry, records
the old lease as recovered, and issues a strictly higher next fencing token for
the next admission; stale release or recovery is rejected.

## Selection and diversity

Ordered routes are failover order. Eligibility, authority, independence,
capacity, and budget are evaluated first. Soft diversity may move only one
place within the eligible list, only for Worker, Tester, Documenter, or Auditor,
and only after at least five `quality_accepted` ledger events. Planner and
Architect displacement is zero. Diversity never creates eligibility.

## Result boundary

`DispatchScheduleManifest v1` binds envelope and task identity, all five source
digests, selected route, lease, ledger sequence range and heads, and
reserved/observed usage. Legacy `DispatchReturnManifest v1`,
`ArtifactQualityReceipt v1`, and Supervisor event bundle are regular-file,
in-repository descriptors whose size and digest are reverified; their inline
contents are not copied. A newly rendered manifest sets transport,
quality, Supervisor application, GoalBuddy application, and overall acceptance
to false. Later stages may create new evidence; they must not mutate history.

The admitted scheduler identity remains the legacy four-field
`goal_id`/`checkpoint_id`/`task_id`/`assignment_id` shape required by the
existing binder. When the immutable post-dispatch manifest is rendered, its
finalizer-rendered, digest-bound `visible_identity` additionally binds the
verified return manifest's `dispatch_id` and `semantic_role`. Keeping the sections separate
preserves exact legacy admission consumers while the visible-provider
reconciler requires both. Ordinary scheduler manifests omit that additive
section, so existing application and role-lifecycle consumers remain exact;
this does not change scheduler admission or execution.

`finalize_visible_provider_dispatch.py` is the idempotent post-dispatch seam.
It consumes the immutable visible task state, admission, envelope, assignment,
execution binding, ledger, return manifest, Supervisor event bundle, and raw
provider artifact. It reverifies their identities, hashes, descriptors,
one-attempt/no-fallback facts, invokes the existing deterministic artifact
validator, and writes new quality, schedule, and visible-reconciliation
receipts. It does not import or invoke the provider runner, retry, fall back,
apply Supervisor or GoalBuddy state, or make an acceptance decision.

`bind_scheduled_dispatch.py` is the non-executing bridge from an exact
admission to the strict one-attempt dispatcher lease binding.
`apply_scheduled_dispatch.py` is the sole Worker-result application gate. It
requires accepted deterministic quality, prepares a manifest-bound recovery
controller, applies the bound event pair under the shared Supervisor lock, then
appends or exactly resumes deterministic completion rows, releases the lease,
and creates or verifies one immutable application receipt. No
`quality_accepted` row precedes the complete Supervisor pair. Concurrent calls
serialize and changed retry clocks cannot create new stage identities.
The additive bridge documented in `role-lifecycle.md` qualifies local
application of the typed non-Worker references after their own deterministic
quality gate. It rebinds each scheduled role to the current Worker lane, maps
only the frozen semantic profile for that role, and applies one lifecycle event
through the same recovery and ledger machinery. This does not alter
scheduling, selection, provider execution, or the legacy Worker gate, and it
is not live provider qualification.

A possibly started attempt is recorded explicitly as `execution_unknown` with
`automatic_retry_allowed: false`. It retains its lease reservation until an
explicit fenced release or recovery; the scheduler never retries it
automatically.
