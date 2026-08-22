# Dispatch execution binding contract

`DispatchExecutionBinding v1` is the non-executing bridge between one admitted
`DispatchSchedulePlan v1` lease and
`run_headless_provider_dispatch.py run-one`. It emits the dispatcher's existing
strict single-attempt lease object. It does not start or probe a provider,
inspect authentication, use the network, install anything, write evidence, or
append to the dispatch ledger.

## Inputs

`bind_scheduled_dispatch.py` consumes:

- the exact scheduler `admit` result;
- the exact compiled `DispatchTaskEnvelope v1`;
- the strict headless dispatch assignment that `run-one` will consume;
- a canonical repository root and its append-only dispatch ledger;
- an injected current UTC time; and
- the same optional workspace configuration path that will be passed to
  `run-one`.

All JSON inputs and the ledger must be canonical, in-repository, regular,
single-link files. The scheduler and ledger lock files must already exist from
admission. The bridge opens them read-only and holds shared locks while it
checks the ledger, bound sources, effective configuration, and route packet.
It never creates a missing lock.

## Fail-closed checks

The bridge requires all of the following before emitting a binding:

1. The admission is an exact v1 `admitted` result with
   `provider_call_started: false`. Its strict plan subset must reproduce
   `plan_sha256`, and its selected route must occur exactly once in the eligible
   list.
2. The envelope's canonical digest, goal/checkpoint/task/assignment identity,
   five authority bindings, role, exact selected provider/model/reasoning,
   artifact-only mode, and normalized artifact scopes must equal the admission.
3. Every board/config/authority/WorkGraph/Supervisor source descriptor is
   reopened and rehashed. When an active config file is present, it must be the
   file named by the admission's config descriptor. Multiple active config
   files cannot be represented by one source digest and fail closed.
4. The admission's ledger range is exactly one row. Its before and after heads
   must identify the canonical `lease_granted` row reconstructed from the
   envelope, selected route, reservation, evidence path, lease, and plan hash.
   Later unrelated ledger rows are allowed; any later row for this lease, a
   later grant for this task, a higher fence, or an `execution_unknown` state
   rejects the binding.
5. The lease must still be active, unexpired at the injected time, and carry
   equal positive scheduler and WorkGraph fencing tokens. Released, expired,
   recovered, superseded, already-started, execution-unknown, missing, or
   otherwise ambiguous leases are rejected. Artifact-only output is dispatcher
   evidence: `writer` stays false, `write_scopes` stays empty, and the lease's
   `artifact_scopes` exactly match normalized requested writes.
6. The assignment must pass the dispatcher's strict schema and path checks.
   Its Supervisor assignment, semantic role, task, expected artifact, and
   artifact scope must equal the envelope and admitted evidence route.
   The expected artifact normally keeps its legacy pre-existing parent. The
   only permitted absent parent is the assignment's exact repository-relative,
   single-use `evidence_directory`, when that directory is also absent and the
   expected artifact is the exact scheduler-selected evidence path. Traversal,
   symlinks, non-directory ancestors, unrelated missing parents, and existing
   evidence directories fail before binding. The binder validates this
   reservation but creates neither directory nor artifact.
7. The current effective Codexmax configuration is resolved using the same
   function as `run-one`. The dispatcher scheduler-mode packet is recomputed
   for exactly the admitted route. Its canonical bytes and SHA-256 must equal
   the admitted selected route's task-bound resolver packet. Registry/profile,
   task, role, source, command, scope, consequence, independence, and attempt
   drift therefore fail closed.
8. The packet must contain one current resolver preflight, no attempt result,
   and a one-route profile. The candidate's digest-bound broker state entry is
   reopened at bind time; a copied observation is never authoritative. Both
   the resolver preflight and re-read broker observation must be observed by
   and unexpired at the injected time. Canonical resolver replay must return
   `dispatch_required` for the same exact route identity.

No partial or degraded binding is emitted. A rejection is JSON on stderr with
`provider_call_started: false` and `writes_performed: false`.

## Output

Success is exactly the strict object already accepted by the dispatcher:

```json
{
  "schema_version": 1,
  "lease_id": "lease-example",
  "fencing_token": 1,
  "attempt_id": "attempt-<64 lowercase hex characters>",
  "task_id": "T020",
  "assignment_id": "assignment-T020-worker-001",
  "route_name": "worker_minimax_m3",
  "envelope_sha256": "sha256:<hex>",
  "preflight_sha256": "sha256:<hex>",
  "authority_sha256": "sha256:<hex>",
  "effective_config_sha256": "sha256:<hex>",
  "evidence_directory": "reports/example/dispatch-001",
  "expires_at": "2026-07-27T12:15:00Z",
  "execution_mode": "single_resolved_attempt"
}
```

`attempt_id` is deterministic. It hashes the other binding fields together
with the admitted plan SHA-256 and exact admission ledger sequence/head. Calling
the bridge again with unchanged inputs yields the same ID; it does not mint a
second attempt.

The emitted `preflight_sha256`, `authority_sha256`, and
`effective_config_sha256` use the dispatcher's canonical JSON digest function,
so `run-one` can consume the object without translation.

## Invocation

```sh
python3 plugins/codexmax-orchestrator/scripts/bind_scheduled_dispatch.py \
  --admission <admission.json> \
  --task-envelope <dispatch-task-envelope.json> \
  --assignment <headless-dispatch-assignment.json> \
  --repo-root <absolute-repository-root> \
  --ledger <absolute-dispatch-ledger.jsonl> \
  --now <injected-utc-time> \
  [--workspace-config <absolute-config-path>]
```

The caller must pass the emitted object, the same envelope, assignment,
repository root, and optional workspace config to `run-one`. Binding is a
pre-execution proof, not a lease-state transaction: a coordinator must not
release, recover, supersede, or otherwise mutate the lease between this check
and the dispatcher start. The runner's existing evidence-directory
single-use rule remains the final duplicate-start guard.
When the expected artifact is a child of the reserved evidence directory,
`run-one` revalidates the same exact relationship and atomically creates the
directory before any process starts. A changed assignment or pre-created
directory cannot reuse the binding.

## Qualification boundary

Qualification is deterministic and local only. It proves no provider syntax,
authentication, entitlement, quota, billing, network, live process, or result
quality behavior. Parent Codex remains acceptance authority; the scheduler
retains retry/failover authority after one bound attempt.
