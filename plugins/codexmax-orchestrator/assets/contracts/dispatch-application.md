# Scheduled dispatch application contract

`apply_scheduled_dispatch.py` is the only scheduler-v1 path into Supervisor
runtime. It is a trusted local evidence gate, not a provider runner and not an
acceptance surface.

The gate consumes an immutable `DispatchScheduleManifest v1`, its exact task
envelope, the hash-chained DispatchLedger, and the current GoalBuddy-bound
Supervisor runtime. It re-verifies the manifest self-digest, descriptors and
content kinds; exact admission ledger interval; active fenced lease; task,
assignment, route, lane, artifact, policy, and quality bindings; and the
complete direct Worker event bundle. It dry-runs every Supervisor transition
against a copy of current state before any result event is appended.

Application is one serialized, resumable single-host transaction. Its fixed
lock order is scheduler lock, then the shared Supervisor runtime-pair lock;
individual append-only ledger writes take the ledger lock underneath those two.
No application path may acquire the scheduler lock while already holding the
Supervisor lock. Ordinary Supervisor writers use the same runtime-pair lock.

Before the first mutation, the gate atomically creates a private
`DispatchApplicationRecovery v1` control file beside the requested final
receipt. It binds the manifest, envelope, exact fenced lease, board and initial
Supervisor state, output paths, original application timestamp, both expected
Supervisor records, and the state snapshot after each record. It is a recovery
WAL, not acceptance evidence. Retry must present the same immutable bindings;
a missing, forged, widened, or conflicting controller fails closed.

Only a selected one-attempt Worker return with a passing deterministic
`ArtifactQualityReceipt v1` may cross this gate. Rejected quality leaves
Supervisor untouched. `execution_unknown` keeps its reservation and requires a
Parent decision. Tester, Documenter, and Auditor returns remain typed,
immutable references and this legacy gate still stops with
`manual_role_adapter_required`. The separately qualified additive successor in
`role-lifecycle.md` consumes those references without weakening this Worker
boundary.

The Worker event pair is applied before any quality-accepted ledger fact. If a
process stops after a Supervisor log append but before the paired state write,
retry accepts only the exact WAL-owned prefix and restores the exact saved
state. Changed board, goal, artifact, event suffix, or runtime cursor fails
closed with the lease retained. After both events are durable, the gate appends
or exactly reuses deterministic `dispatch_finished`, `quality_accepted`,
`schedule_closed`, and `lease_released` rows. Stage IDs and timestamps come
from the first prepared transaction, never the retry clock.

The final `DispatchApplicationReceipt v1` is create-or-verify-identical. A
concurrent or repeated invocation returns the same receipt and cannot duplicate
Supervisor or ledger rows; conflicting evidence stops. The gate never rewrites
the schedule manifest. The receipt records `supervisor_applied: true` while
keeping `goalbuddy_applied: false`, `accepted: false`, and Parent Codex as
acceptance authority. GoalBuddy is never mutated.

This v1 implementation is repository-local and single-host. Deterministic
same-host replay is qualified only for exact application-owned Supervisor and
ledger prefixes; distributed leases and recovery from unrelated or legacy
partial writes remain unqualified. Live provider syntax, provider identity,
credentials, entitlement, quota, billing, installation, and AOL integration
require separate qualification.
