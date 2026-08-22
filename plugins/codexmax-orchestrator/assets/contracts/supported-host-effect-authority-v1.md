# Supported-host effect authority v1

## Scope

This contract defines a pure authority-ledger mechanism. It also defines two
canonical fact sources for T064.

The mechanism performs no input or output operation. The caller owns durable
storage. The caller must validate the complete returned state before it writes
that state.

T064 does not create a positive production authority. A caller-authored value,
a literal source ID, a private in-process sentinel, a self-digest, a callback,
or a caller flag is not trust. T066 must define and prove a separate trust root
before any source can emit a positive authority fact.

T064 has no registered-action executor or action-observation store. The action
source always returns `unavailable`.

## Ledger state

`supported_host_effect_authority_ledger_v1` has these exact fields:

- `schema_version`
- `artifact_type`
- `ledger_id`
- `events`
- `head_sha256`
- `state_sha256`

The state seal is the SHA-256 digest of canonical JSON without
`state_sha256`. The empty head is a canonical digest that binds `ledger_id`.
The validator checks the complete event sequence before it returns the state.

## Events

Each `supported_host_effect_authority_event_v1` has these exact fields:

- `schema_version`
- `artifact_type`
- `ledger_id`
- `sequence`
- `previous_event_sha256`
- `expected_head_sha256`
- `event_type`
- `occurred_at`
- `authority_id`
- `authority_receipt_sha256`
- `authority`
- `request_sha256`
- `reason`
- `issuer_decision_sha256`
- `event_sha256`

The sequence starts at one. It increases by one. Both head fields must equal
the prior event digest. The event digest seals the canonical event without
`event_sha256`.

An `issue` event contains one structurally valid package-host authority
receipt. It binds the exact request digest and decision digest. It rejects a
duplicate authority, receipt replay, decision replay, or authority ID
collision.

An issue event is ledger data only. It is not proof that T066 created or
accepted the decision. It cannot authorize an operation or produce an
available canonical fact.

A `revoke` event contains no authority or issuer decision. It references one
prior authority receipt. The reason must be one of:

- `operator_revoked`
- `request_withdrawn`
- `binding_invalidated`

## Issuer decision

`supported_host_effect_authority_issue_decision_v1` has these exact fields:

- `schema_version`
- `artifact_type`
- `decision_id`
- `decision_source_id`
- `decision`
- `ledger_id`
- `authority`
- `request_sha256`
- `decided_at`
- `expires_at`
- `decision_sha256`

`decision_source_id` must be `responses-context-issuer`. `decision` must be
`issue`. The receipt, request, ledger, issue time, expiry time, context, and
decision seal must agree exactly.

`validate_issuer_decision` proves structure and binding only. Its return value
is not a trusted capability. The issue transition remains non-authoritative.
A caller can calculate a valid digest. Therefore neither function can promote
that value to a canonical fact.

The issue transition validates the nested authority as a closed mapping before
it reads any nested field. A missing, null, list, partial, extra-field, or
malformed authority returns a stable typed error. It does not expose a Python
mapping or indexing exception.

## Recovery and current authority

`recover_ledger` requires `trusted_minimum_sequence` and
`trusted_head_sha256`. It validates the full state. It rejects a state below
the minimum sequence. It also rejects a state whose head differs from the
expected head. This detects a properly sealed prefix rollback when the caller
holds the later anchor.

The anchor arguments enforce rollback comparison. They do not prove their own
authority. T064 has no accepted non-caller trust root. Therefore
`current_authority` validates the structural anchor and then fails closed with
`authority_trust_anchor_unavailable`. It never exposes a current positive
authority.

## Canonical source results

`EffectAuthorityFactSource` always returns typed `unavailable` with reason
`canonical_authority_trust_anchor_not_implemented`. A self-authored and
self-rehashed decision, ledger, receipt, or anchor cannot change this result.

`RegisteredActionObservationSource` returns typed `unavailable` with reason
`canonical_action_executor_not_implemented`. A certificate, fixture,
registration row, adapter, route, model, or caller assertion cannot change
that result.

## Proof boundary

The proof is repository-local and in memory. It proves the non-authoritative
ledger mechanism, closed schemas, exact integer types, deterministic seals,
compare-and-swap, chain validation, expiry, revocation, rollback-aware
recovery, and typed unavailable boundaries.

It does not prove a T066 issuer decision, persistent ledger, executor, action
observation, service, socket, certificate principal, credential, or external
execution.
