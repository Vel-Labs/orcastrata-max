# Single Effect Kernel V1

## Ownership

Every effectful run, cancel, recover, reconnect, shutdown, native-host action,
provider call, or registered tool call crosses one canonical runtime/scheduler
effect writer. Operator, Responses, preset, adapter, and native clients submit
closed requests; none invokes a transport directly. GoalBuddy remains board
truth and Parent alone accepts work.

The existing standalone `inspect`, `reconnect`, and `shutdown` client is a
side-effect-free preview surface. T050 must add explicit effect operations; it
must not silently change those accepted methods into effectors.

## Request and receipt

`effect_kernel_request_v1` contains exactly:

`schema_version`, `artifact_type`, `request_id`, `idempotency_key`, `operation`,
`workspace_id`, `goal_id`, `task_id`, `actor`, `authority_receipt`,
`source_bundle`, `thread_snapshot`, `preset_snapshot`, `route_snapshot`,
`adapter_snapshot`, `policy_snapshot`, `lease`, `run`, `cas`, `input`,
`request_sha256`, `created_at`.

Actor is descriptive. Authority is separately validated and cannot originate
from a model, UI, route, adapter, or transcript. Mutation requires
`cas.expected_state_version` and `cas.expected_thread_generation`. Preset,
thread, route, adapter, policy, lease, and source snapshots are immutable for a
run. Requested and observed route/model/host identity are separate; unknown
observed values remain unknown.

Requests reject caller URLs, argv, executables, modules, environment data,
credential values, arbitrary provider aliases, unregistered tools, direct
transport handles, unknown fields, non-finite JSON, and stale snapshots.

`effect_kernel_receipt_v1` contains exactly:

`schema_version`, `artifact_type`, `request_id`, `request_sha256`, `operation`,
`disposition`, `run_id`, `pre_state`, `post_state`, `state_version_before`,
`state_version_after`, `action_receipt`, `route_requested`, `route_observed`,
`preset_snapshot`, `lease`, `event_ids`, `proof_boundary`, `unknowns`,
`receipt_sha256`.

Every object is closed. Nested request shapes are:

- `authority_receipt`: `schema_version`, `artifact_type`, `authority_id`,
  `issuer_id`, `actor`, `workspace_id`, `goal_id`, `task_id`, `source_sha256`,
  `candidate_sha256`, `thread_id`, `thread_generation`, `operation`,
  `request_intent_sha256`, `issued_at`, `expires_at`, `receipt_sha256`; type
  `effect_kernel_authority_receipt_v1`, exact request scope and identity,
  current time, and exactly one requested operation are mandatory.
- `source_bundle`: `source_id`, `source_sha256`, `candidate_sha256`,
  `snapshot_sha256`.
- `thread_snapshot`: `thread_id`, `generation`, `captured_at`, `expires_at`,
  `snapshot_sha256`.
- `preset_snapshot`: `preset_id`, `captured_at`, `expires_at`,
  `snapshot_sha256`.
- `route_snapshot`: `route_id`, `requested_model`, `requested_host`,
  `captured_at`, `expires_at`, `snapshot_sha256`.
- `adapter_snapshot`: `adapter_id`, `action_id`, `tool_id`, `transport`,
  `qualification_status`, `captured_at`, `expires_at`, `snapshot_sha256`;
  qualification must be `qualified` and action/tool/transport must match one
  immutable kernel registration.
- `policy_snapshot`: `policy_id`, `active`, `captured_at`, `expires_at`,
  `snapshot_sha256`; `active` must be true.
- `lease`: `lease_id`, `fencing_token`, `issued_at`, `expires_at`,
  `lease_sha256`.
- `run`: `run_id`, `predecessor_run_id`; only recovery has a predecessor.
- `cas`: `expected_state_version`, `expected_thread_generation`.
- `input`: `tool_id`, `parameters`; registration closes the parameter field
  set. Parameter keys recursively reject URL/URI, argv, executable, module,
  environment, credential, token, secret, transport, and provider injection.

`request_intent_sha256` is non-circular: it canonically digests every request
semantic except `authority_receipt` and `request_sha256`. Issuance binds that
intent plus exact workspace, source, candidate, thread identity/generation,
operation, and expiry. After issuance, `request_sha256` seals the complete
request including the authority receipt. Every snapshot digest covers the same
object without its digest field. Timestamps are whole-second UTC `Z` values.
Authority, snapshots, and leases must be current at execution.

A structurally valid or self-digested authority receipt is not authority.
Before any action lookup or persistence lock, the gateway requires a trusted
package/Parent verifier owned by immutable package state outside the request.
The verifier receives a
deep copy of the receipt and its exact binding context; absence returns
`authority_missing`, and rejection or verifier failure returns
`actor_not_authorized`. No request, UI, model, preset, route, adapter, client,
CLI, public gateway call, authority-preflight call, or service helper can
supply a verifier, registry, or trust anchor.

`action_receipt` is null only for `execution_unknown`; otherwise it is a closed
`effect_kernel_action_receipt_v1` containing exactly `schema_version`,
`artifact_type`, `action_receipt_id`, `action_id`, `effect_id`, `operation`,
`outcome`, `requested_at`, `observed_at`, `host_receipt_id`,
`observed_identity`, `request_sha256`, `output_sha256`,
`reconciled_outcome`, `successor_run_id`, and `receipt_sha256`.
`observed_identity` contains exactly `route_id`, `model`, and `host`; an
unobserved value is the literal `unknown`, never a requested value.

The service persists one workspace-direct `effect_kernel_state_v1` under an
exclusive local lock. Exact idempotent replay returns the original immutable
receipt; request, run, lease, action-receipt, or receipt collisions fail
closed. Production action registrations and the production authority verifier
are immutable package-owned capabilities and intentionally empty/absent in
T050. All non-test gateway and service execution entries acquire only those
capabilities internally; the public service/client/CLI path exposes neither
injection seam. Only unmistakably private, test-only entries accept an explicit
test registry and verifier. Every injected registration must declare
`test_only:true`; any `test_only:false` registration is rejected before handler
invocation or any manifest/workspace/lock/state access. There is no generic execution core or generic
registry-validation callable that accepts raw caller capabilities; deterministic
shared validation accepts request/state data only.

Every effectful success requires an observed action receipt with action/effect
IDs and digests, requested/observed timestamps, host/provider receipt ID,
observed identity, and its own digest. Accepted input or a preview is never
effect success.

## Recovery authority and effect state V2

New executions persist only closed `effect_kernel_state_v2`. Historical
`effect_kernel_state_v1` is read-only and yields
`recovery_authority_unavailable`; it is never upgraded or rehashed. Every V2
run stores the complete validated V1 `lease` object rather than a lossy lease
ID/fence pair. A recovered successor additionally stores closed
`recovery_provenance` containing exactly `grant_id`, `grant_sha256`,
`issuer_id`, `predecessor_run_id`, `predecessor_effect_request_sha256`,
`predecessor_effect_receipt_sha256`, `reconciliation_receipt_sha256`,
`expected_cas`, and `reserved_authority_id`. Non-recovered runs have null
provenance.

Each V2 idempotency row is closed and stores `request_sha256`,
`receipt_sha256`, `recovery_grant_id`, `recovery_grant_sha256`, the complete
closed `recovery_provenance`, and `recovery_provenance_sha256`; all four
recovery fields are null for non-Recover operations. The commitment digest
covers the full canonical provenance object. State validation and replay
require exact equality between the commitment, its digest, the grant identity,
and successor provenance.

Recover requires a separately package-host-authenticated
`effect_kernel_recovery_lease_grant_v1` with exactly `schema_version`,
`artifact_type`, `grant_id`, `issuer_id`, `workspace_id`, `source_sha256`,
`candidate_sha256`, `service_instance_id`, `admission_id`,
`binding_state_version`, `binding_state_sha256`, `selection_sha256`,
`predecessor_run_id`, `predecessor_effect_request_sha256`,
`predecessor_effect_receipt_sha256`, `reconciliation_receipt_sha256`,
`no_successor`, `fresh_lease`, `expected_cas`, `reserved_authority_id`,
`issued_at`, `expires_at`, `grant_sha256`, and `seal`. `grant_sha256` covers
every field except itself and `seal`; the TLS package host verifies `seal`.
`fresh_lease` is the unchanged closed V1 lease and `expected_cas` is the closed
V1 CAS object.

The grant is private package context, never request/browser/CLI/workspace input.
At execution under the effect lock, the service re-reads it and binds exact
grant ID/digest, predecessor request/receipt/reconciliation, fresh lease, CAS,
and the ordinary authority receipt ID reserved by the grant. Exact replay is
allowed only for the identical request and grant digest. Cancel of a recovered
successor validates the successor's persisted full lease and expiry.

## Lifecycle

```text
draft -> admitted -> leased -> starting -> running -> completed
                              |          |-> cancel_requested -> cancelled
                              |          |-> execution_unknown
                              |-> execution_unknown
execution_unknown -> reconciling -> failed | cancelled | unreconciled
failed | cancelled | unreconciled -> recovering -> starting(successor)
```

`execution_unknown` blocks success, retry, replacement, fallback, and new
admission for the same effect. Recovery requires current reconciliation, a new
successor run, fresh lease, and strictly higher fencing token. Cancellation is
not terminal until current observed evidence exists. A missing or malformed
run/cancel/recover observation seals `execution_unknown`. Recovery is one
registered observed action that reconciles the predecessor to `failed` or
`cancelled` and starts a named successor with a new lease and higher fence.

## Stable failures

`request_shape_invalid`, `unknown_field`, `idempotency_collision`,
`source_bundle_stale`, `authority_missing`, `actor_not_authorized`,
`route_snapshot_stale`, `route_identity_unknown`, `adapter_snapshot_stale`,
`policy_snapshot_stale`, `lease_expired`, `fence_mismatch`, `cas_mismatch`,
`run_not_found`, `invalid_transition`, `in_flight_switch_denied`,
`effect_observation_missing`, `execution_unknown`,
`execution_unknown_cannot_succeed`, `receipt_replay_collision`,
`direct_effect_bypass`, `recovery_requires_new_fence`, and
`acceptance_not_parent`.

The legacy transition API follows the same cancel boundary: `cancel_run`
records only `cancel_requested`; a distinct digest-bound `cancel_observed`
event is required before terminal `cancelled`.

## Proof boundary

Schemas, fixtures, fake processes, and source tests prove closed behavior only.
Each live claim requires current route, authority, host/provider observation,
action receipt, and lifecycle evidence bound to the exact candidate.
