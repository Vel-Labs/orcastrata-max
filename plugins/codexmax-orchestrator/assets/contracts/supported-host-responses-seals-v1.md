# Supported-host Responses and seals mechanism v1

## Status

This contract defines a repository-local structural mechanism. It does not
define a positive fact source. It does not grant authority.

## Operations

The mechanism supports these exact operations:

- `issue_responses_context`
- `verify_responses_bridge`
- `commit_or_verify_record`
- `seal_or_verify_projection`

Each structural decision binds the exact operation to SHA-256 digests for the
identity, request, dependency receipts, selection, supervision, runtime,
action, route, output, record, and projection. The decision has one fixed
source identifier and one fixed structural result for its operation.

## Ledger

The ledger is one closed JSON-like value. It contains a closed event list.
Every event binds its sequence, previous event digest, expected head digest,
operation, decision identity, decision digest, and occurrence time. The event
digest is the SHA-256 digest of canonical JSON without `event_sha256`. The
state digest is the SHA-256 digest of canonical JSON without `state_sha256`.

All schema versions and event sequences use exact integers. Boolean and
floating-point values are invalid.

Issue and revoke transitions use expected-head compare-and-swap. The validator
checks the full chain. It rejects duplicate decisions, digest replay, identity
collision, duplicate revocation, time regression, and digest drift.

Recovery requires both an exact externally retained sequence and an exact
externally retained head digest. The recovered ledger must equal both values.
A resealed proper prefix is invalid.

## Freshness and revocation

A structural decision has exact second-resolution UTC timestamps. The observed
time cannot be in the future. The expiry must be later than the observed time
and later than the validation time. The validity interval cannot exceed five
minutes. A revoked decision is not current.

## Authority boundary

Structural validation is not evidence authority. A caller-authored decision,
a fixture, a test projector, provider inference, or a self-rehashed value
cannot become a positive producer fact.

The four source adapters always return this closed result shape:

- `schema_version`
- `artifact_type`
- `operation`
- `state`
- `reason`
- `canonical_source_id`

The state is always `unavailable`. This module has no positive fact class or
positive fact return path.

## Safety boundary

The mechanism performs no file, environment, endpoint, socket, process,
service, credential, provider, or network I/O. It rejects private-key,
credential, path, environment, endpoint, fixture, test-projector, provider
result, and live-status fields.

The mechanism does not prove a canonical source, durable external anchor,
authenticated producer, public certificate, private identity, service, or
external execution.
