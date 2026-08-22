# Universal Adapter Capability V1

## Purpose

This contract defines one provider-neutral capability layer. It does not run
an adapter. It does not call a provider. It does not grant task authority.

The ownership rule is strict:

- The adapter owns capability potential.
- Exact model qualification owns compatibility evidence and current limits.
- The task grant owns execution authority and scope.
- Configuration owns candidate order, candidate subsets, and lower user caps.
- Parent Codex owns route choice and acceptance.

## Capability primitives

The closed primitive catalog is:

- `local_read`
- `artifact_output`
- `tool_loop`
- `command_execution`
- `scoped_write`
- `browser_control`
- `web_search`
- `connector_access`

Model identity, reasoning, verbosity, token limits, cost, route order, and
conformance output are not primitives. They cannot grant a primitive.

## Lane profiles

Lane profiles compose only declared primitives:

| Lane | Required primitives | Mutation mode |
| --- | --- | --- |
| `read` | `local_read` | `read_only` |
| `artifact` | `artifact_output` | `artifact_only` |
| `scoped_write` | `local_read`, `scoped_write` | `scoped_write` |
| `implementation` | `local_read`, `artifact_output`, `tool_loop`, `command_execution`, `scoped_write` | `scoped_write` |
| `tool_loop` | `tool_loop` plus an exact tool allowlist | `artifact_only` |
| `audit` | `local_read`, `artifact_output`, `command_execution` | `read_only` |

A lane profile has no authority, eligibility, acceptance, provider-call, or
execution field. An exact tool allowlist is mandatory for `tool_loop` and is
not valid for another lane.

## Exact compatibility and qualification

The compatibility key contains all five fields:

`provider + provider_transport + exact_model + adapter_id + adapter_version`

Substitution of any field changes the key and invalidates the qualification.
The record binds the proved primitive subset, exact tool allowlist, adapter
concurrency cap, evidence digests, source-local proof boundary, issue time,
expiry time, recall state, and its own digest.

The proved primitives must be a subset of the adapter card. A current
qualification does not grant task eligibility. It only lets a later admission
step compare the lane requirement, qualification, and task grant.

Before `issued_at`, the derived state is `not_yet_valid`. It is ineligible.
`unknown`, `expired`, `stale`, `recalled`, `revoked`,
`qualification_failed`, and `execution_unknown` are not current. They fail
closed. Both retry and fallback remain false. Terra is policy-denied. Qwopus
remains on hold. A source-local record cannot enable either route.

## User preference and concurrency

`capability_preferences.lanes` lets the user reorder or subset only the
package-owned compatible candidates for a lane. The user can lower
`user_concurrency_limit`. The user cannot add a profile-external route, a
control route, Terra, Qwopus, a qualification, evidence, a primitive, or task
authority.

Effective concurrency is the minimum of these six positive caps:

1. user;
2. adapter qualification;
3. task;
4. fleet;
5. provider;
6. runtime host.

A scoped-write task must have a task cap of one. This keeps scoped writes
serialized without changing T170 scheduling or fan-out semantics.

## Source-local conformance

The shared harness validates the universal registry, exact qualification,
lane primitive subset, tool allowlist, and six concurrency caps. It returns a
digest-bound receipt with:

- `proof_boundary: source_local`;
- `provider_called: false`;
- `execution_started: false`;
- `eligibility_granted: false`;
- `authority_granted: false`;
- `acceptance_granted: false`;
- `no_retry: true`;
- `execution_unknown_policy: preserve_and_stop`.

This receipt proves deterministic source behavior only. It is not installed,
provider, live, protected-host, production, or acceptance proof.

## Schemas and implementation

- `assets/templates/universal-adapter-capability-v1-schema.json`
- `assets/templates/provider-flexible-execution-schema.json`
- `scripts/adapter_registry.py`
- `scripts/provider_execution_policy.py`
- `scripts/resolve_codexmax_config.py`
- `scripts/resolve_worker_route.py`

T170 retains scheduler and fan-out ownership. T172 retains transaction
ownership. T173 Release Candidate 1 bytes remain unchanged.
