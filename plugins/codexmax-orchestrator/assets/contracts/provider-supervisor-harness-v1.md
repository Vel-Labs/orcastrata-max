# Provider Supervisor Harness v1

## Purpose

`scripts/provider_supervisor_harness.py` is the provider-neutral validation and
coordination seam for T179. It composes accepted T178 capability evidence,
accepted task-grant authority, the T158 plan validator, and the accepted T170
execution controller.

The harness does not implement a second scheduler. It calls one supplied T170
`FanoutController` exactly once.

## Ownership

- T178 owns adapter capability, exact model compatibility, current
  qualification, lane profiles, and lower configuration caps.
- `provider_work_authority.py` owns task-grant validation and scope.
- T158 validates the compiled plan and its immutable descriptors.
- T170 owns admission, leases, dispatch, concurrency, certain pre-spawn retry,
  attempt evidence, write serialization, and aggregate receipts.
- The harness validates the intersection and normalizes observations.
- Parent Codex owns selection, acceptance, fold, GoalBuddy mutation, and board
  transition.

Model identity, configuration, route order, cost, reasoning, and conformance
output grant no authority.

## Admission

The request supplies one compiled T170 plan, one T178 universal registry, one
lane requirement for every plan lane, and bounded provider transport events.
The harness revalidates the plan descriptors from the artifact root. It
requires:

- an exact route, provider, model, transport, adapter ID, and adapter version;
- a current capability card, qualification, task grant, and execution binding;
- a version-2 task grant with `no_retry: true` and
  `execution_unknown_policy: preserve_and_stop`;
- an exact adapter harness digest;
- a capability-card qualification digest equal to the selected universal
  qualification digest;
- a selected qualification that binds the exact adapter ID, adapter version,
  provider transport, and adapter harness evidence digest;
- matching lease and fencing authority;
- lane mutation mode consistent with the grant;
- all required primitives present in the four-way intersection;
- exact tool names present in both qualification and task grant;
- effective expiry equal to the earliest accepted expiry.

Configuration cannot provide qualification evidence. Unknown, stale, expired,
recalled, Terra, Qwopus, exact-model substitution, adapter substitution, and
grant substitution fail before T170 execution.

## Execution And Recovery

All read, artifact, tool, and scoped-write lanes pass through the supplied T170
controller. T170 caps concurrent reads at two. T170 starts writers after reads
and serializes all writers. Scoped writes retain isolated worktrees, exact
write scopes, leases, evidence roots, and immutable attempt receipts.

The Supervisor does not request retry, fallback, or hedging. T170 alone may use
its accepted certain pre-spawn retry path. No retry is valid after `run_one`
starts, a provider might have spawned, a mutation is possible, or execution is
unknown.

If the T170 call crashes or receipt completion is ambiguous, the harness emits
`execution_unknown`. It does not invoke T170 again. A successful call still
requires each normalized terminal event to match the T170 aggregate.

`validate_supervisor_receipt` is the public semantic consumption boundary. It
requires `expected_receipt_sha256` from a separately retained Parent or T179
checkpoint. A missing, wrong, or stale anchor fails before semantic use. The
validator recomputes the receipt digest. It validates each normalized event sequence and
exact stored binding. It recomputes terminal status and aggregate
reconciliation. It also checks T170 controller ownership and every false
authority flag. `execute` calls this validator before it returns any receipt.
A rehashed receipt with contradictory terminal or aggregate facts fails.

## Proof Boundary

The receipt keeps these fields false:

- `retry_requested_by_supervisor`
- `fallback_requested`
- `hedging_requested`
- `accepted_by_parent`
- `board_mutation_performed`
- `fold_performed`
- `application_performed`

The source-local harness does not call a provider, use credentials, use the
network, install, start a service, publish, or mutate GoalBuddy. Its schema is
`assets/templates/provider-supervisor-harness-v1-schema.json`.

The receipt digest and internal event digests prove self-consistency. They do
not prove provenance against an actor that can replace and rehash the complete
receipt. A trusted consumer must retain the accepted receipt digest outside
the receipt and supply it as `expected_receipt_sha256`. `execute` can use its
freshly produced digest only for internal structural proof. That internal call
does not replace the external consumer checkpoint.
