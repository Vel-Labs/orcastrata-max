# Supported-Host Registered-Action V1

## Status

This contract defines a source-local structural mechanism. It does not define a
real executor. It does not grant positive canonical fact authority.

## Source ownership

- Operation: `invoke_registered_action`
- Canonical source ID: `registered-action-observation-store`
- Unavailable reason: `canonical_action_executor_not_implemented`
- Positive integration owner: T073

`RegisteredActionFactSource` and `UnavailableRegisteredActionExecutor` return
the shared T063 `UnavailableFact`. They never return `AvailableFact`.

## Ledger

The ledger is a closed value with these fields:

`schema_version`, `artifact_type`, `ledger_id`, `events`, `head_sha256`, and
`state_sha256`.

Each event has these fields:

`schema_version`, `artifact_type`, `ledger_id`, `sequence`,
`previous_event_sha256`, `expected_head_sha256`, `event_type`, `occurred_at`,
`action_id`, `effect_request_sha256`, `registration`, `observation`, `reason`,
and `event_sha256`.

The event types are `registration`, `execution_admission`, `observation`, and
`revoke`. Each append requires exact head compare-and-swap. The ledger seals
every event and the full state. A failed check returns no candidate state.

`recover_ledger` validates the full chain. It also requires an external minimum
sequence and exact head digest. A ledger self-digest is not an external anchor.

## Effects bindings

The mechanism consumes the frozen `codexmax_package_host.effects_v1` validators.
It requires the exact effect request, action registration, and action receipt
schemas. It preserves exact bindings for the action, tool, transport, parameter
fields, operation, request digest, authority, workspace, source, candidate,
thread generation, lease fence, policy, and CAS values.

An execution admission stores the complete effect request. The admission expiry
is the earliest expiry across the authority, thread, preset, route, adapter,
policy, and lease facts. The mechanism does not invoke the action.

An observation requires a prior admission. It requires a current receipt with a
known route, model, and host. It accepts only the outcome allowed by
`effects_v1`. It does not infer success from a request, handler, fixture,
transport state, timeout, or missing provider result.

An observation expires no more than five minutes after its observed event.
Mutation and full-chain recovery enforce the same limit. A revoked request
cannot replay its earlier observation. A repeated revoke is idempotent only
when its reason is exact. A different reason is a collision.

Exact repeated registration, admission, observation, and revoke calls are
idempotent and return an unchanged copy. Conflicting action IDs, request IDs,
idempotency keys, receipt IDs, request digests, or receipt digests fail closed.

## Positive-value boundary

`validate_positive_value` can check the future closed shape:

`variant`, `registration`, `observation_key`, and `observation`.

The validator also requires the exact effect request. It applies the frozen
`effects_v1` request, registration, and receipt validators. It rejects extra or
unknown observed identity fields, invalid outcomes, time drift, request drift,
action drift, and digest drift. It does not return a canonical fact. The source
adapter remains unavailable. T073 can promote a positive value only after it
supplies a named authenticated executor and a durable non-caller observation
anchor.

## Prohibitions

This module has no file, environment, process, socket, service, credential,
provider, receiver-write, callback, handler, or persistence interface. Tests do
not become production authority.
