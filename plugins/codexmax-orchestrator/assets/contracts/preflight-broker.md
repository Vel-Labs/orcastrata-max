# Preflight Broker Contract

## Purpose

`PreflightBroker v1` deduplicates a short-lived, local preflight probe for one
exact provider route. It does not perform the probe and it is never an
authorization, capability, accounting, or scheduling authority.

## Exact cache key

Every request supplies exactly these case-sensitive strings:

- `provider`
- `exact_model`
- `route_id`
- `runtime`
- `reasoning`
- `proof_mode`

Whitespace aliases, empty values, extra fields, and omitted fields fail closed.
The canonical key digest is SHA-256 over canonical JSON for those six fields.

## Cacheable observation

The broker may retain only:

- the exact cache key;
- `availability`, `health`, and `callability` statuses;
- a non-secret receipt descriptor and its `sha256:` digest;
- deterministic `observed_at` and `expires_at` timestamps.

An observation cannot contain credentials, authentication or task authority,
read/write scope, source compatibility, quota, billing permission, capability
claims, or independence claims. Unknown status remains `unknown`; it never
becomes available or callable by default.

The default observation TTL is 60 seconds. Both observation TTLs and probe
leases are positive integer seconds capped at 300 seconds.

## Singleflight protocol

`request` atomically returns one of:

- `cache_hit`: an unexpired exact-key observation is returned;
- `probe_required`: the supplied owner token owns the exact-key probe lease;
- `probe_in_flight`: another owner holds an unexpired exact-key probe lease.

Only the matching, unexpired owner may `record` an observation. A request after
lease expiry may recover the abandoned lease and reports that recovery. An
expired observation is never returned as a cache hit.

## Persistence and integrity

The state file is protected by a sibling filesystem lock and replaced
atomically. It contains a hash-chained event history and a digest over the
complete state payload. Corruption, digest mismatch, malformed timestamps,
unknown fields, or an invalid history chain fail closed. Callers inject all
timestamps; the broker never needs a network or provider call.

## Non-authority boundary

A cache hit proves only that an exact route had the recorded callability state
within the bounded TTL. Dispatch must independently revalidate current task,
scope, source, configuration, allowance, WorkGraph claim, and Supervisor
authority before admission.

The explicit tool/model session probe is separate from broker persistence. It
verifies an existing configured tool session and exact model through two fixed,
bounded status and model-list commands. Its non-secret output digest can be bound into an
`ExplicitToolModelSelection v1`. It does not add credentials, authentication,
task authority, or a reusable provider session to broker state.
