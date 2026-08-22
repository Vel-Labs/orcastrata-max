# Supported-host runtime integration v1

## Scope

This contract integrates the accepted T063, T064, T066, T067, T068, T069,
and T072 source classes. It does not add a positive source.

The registry covers exactly the twelve external operations in the accepted v8
producer policy. The two service-owned operations remain separate. The registry
uses `external_source_mtls_v2` for every external operation.

## Fixed source dispatch

`source_for(operation)` selects one private fixed adapter. A caller cannot
provide a source, transport, certificate, profile, function, lookup service,
fact, file location, environment value, or external result.

`read_fact(operation, exact_identity, dependency_receipts, now)` delegates to
the accepted family adapter. It returns the shared `UnavailableFact` type. It
normalizes the T066 legacy mapping only when it has the exact six-field closure
and the exact `supported_host_responses_seals_source_result_v1` artifact type.
One canonical validator then requires exact field types and values. Schema
version uses `type is int` and value `1`. Operation must be an exact T066
operation and must match the requested operation before any source-table lookup.
State, reason, and source identifier must be exact accepted strings. It rejects
a missing, extra, forged, relabeled, or wrong-type value and every other result
shape. The runtime integration has no local positive branch.

`boundary_inventory()` returns the immutable field, type, membership, table,
dispatch, input, matrix, and gate boundary inventory. Each row gives one rule,
stable error code, and stable location. The inventory documents that dispatch
and source-table lookups occur only after operation membership validation.
This rule also applies inside `_read_from_family`; direct helper calls validate
the operation before the private source-factory lookup and cannot expose a raw
lookup exception.

## Source-of-truth matrix

`integration_matrix()` returns twelve immutable and unique rows. Each row binds
one operation to its accepted source identifier, family source class, canonical
owner role, required persistence, durable non-caller anchor kind, authentication
scheme, and freshness limit. The freshness limit is 300 seconds. A family can
apply a smaller limit. It cannot apply a larger limit.

All rows have state `external_gate_required`. A fixture, structural decision,
self-digest, generated certificate, caller assertion, or relabeled source cannot
change this state.

## External gate

`external_gate()` returns one immutable report. It is not an eligibility value.
It names only public missing categories:

- authenticated producer identity;
- current public certificate chain;
- durable non-caller anchor;
- current canonical source receipt;
- current freshness evidence;
- supported-host profile and principal operation map.

Private keys, credentials, and their locations are outside this contract and
outside the workspace. External setup and execution remain human-owned.

## Proof boundary

The registry performs no file, process, socket, network, provider, environment,
or service operation. Source-local tests prove exact routing and unavailable
closure only. They do not prove a supported host, a live producer, a durable
external anchor, mutual TLS, or current operation evidence.
