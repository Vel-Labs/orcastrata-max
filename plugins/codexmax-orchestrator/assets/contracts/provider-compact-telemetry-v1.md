# Provider Compact Telemetry V1

## Purpose

`ProviderCompactTelemetryV1` is a small, inert projection of one current
`DispatchReturnManifest`. It binds the manifest, retained stdout, retained
stderr, and returned artifact by canonical path, byte count, and SHA-256.

It does not copy raw provider output. It does not call a provider, select a
route, retry, fall back, rank a model, grant authority, accept work, or mutate
GoalBuddy.

The `compiler_started_provider_call` field describes this compiler only. The
terminal section separately preserves whether the source dispatch observed an
external call.

## Truth Boundary

The projection separates requested identity from observed runtime identity.
The current headless dispatcher binds requested route, provider, model,
runtime, and billing facts. It does not emit an independently observed runtime
route or runtime identity. Therefore all observed identity fields remain
`unknown/not_emitted`.

Usage and cost are observed only when the dispatch attempt contains a
nonnegative runtime value. Missing, malformed, or unreported values stay
unknown. Unknown values never become zero.

## Evidence Window

Every projection binds one task family, recording time, expiry time, requested
model, requested runtime, and requested route. The evidence window must be
positive and no longer than 14 days. A later model, runtime, adapter, route, or
task family is a different observation.

This prevents a historical result from becoming a permanent provider ranking.

## Terminal Semantics

The projection records timeout, output-limit stream, process start, external
call observation, network observation, and the dispatch outcome. It rejects
more than one attempt. Retry count is zero. Fallback, hedging, and model
substitution are always false.

An external call with `provider_network_performed: false` is contradictory and
is rejected. A proved provider-network action without a proved external call is
also rejected. A started live process without an authenticated network event
must retain `provider_network_performed: unknown`.

A timeout, truncation, malformed output, identity mismatch, or unknown
execution remains terminal evidence. Compilation cannot start another process.

The JSON Schema describes the storage shape. The Python validator is the
semantic authority. It also verifies retained file identities and digests.

## Filesystem Safety

The compiler accepts only canonical, regular, single-link evidence files below
the exact repository root. It rejects absolute descriptor paths, parent
traversal, symlinks, hardlinks, size drift, digest drift, duplicate JSON keys,
and evidence files larger than 16 MiB.

The output is created once with mode `0600`. Existing output is never replaced.

## Proof Boundary

Source tests prove local compilation and validation only. T165 must still prove
installed task-scoped provider usability for the exact installed candidate.
T167 must still prove Parent-reviewed dogfood on real GoalBuddy work.
