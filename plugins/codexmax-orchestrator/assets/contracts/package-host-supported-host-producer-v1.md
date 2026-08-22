# Package-host supported-host producer v1

Status: source-local shared plane

## Purpose

This plane constructs the accepted v8
`package_host_producer_binding_request_v1` frame. It validates the returned
`package_host_authenticated_producer_evidence_v1` receipt.

## Inputs

`ProducerClient` accepts these inputs:

- one validated, closed public configuration;
- the exact `FirstPartySupportedHostRuntimeV1` in production, or an explicit test-only source;
- one validated `BoundServiceIdentity`;
- one sealed dependency digest set derived from closed, positive,
  receiver-owned 27-field receipts;
- one UTC clock;
- one OS-bound opaque TLS-agent transport in production, or an explicit in-memory test transport.

The public configuration contains only the producer policy, qualified public
host-profile identity, expected server certificate digest, and binding lifetime.
It does not contain an endpoint, certificate path, private-key path, credential,
environment name, process command, or transport constructor.

## Fact authority

The production source interface is:

```text
read_fact(operation, exact_identity, dependency_receipts, now, operation_body)
  -> unavailable(reason, canonical_source_id)
   | available(key, value, observed_at, expires_at,
               canonical_source_id, source_digest)
```

The client owns request construction and response validation. The receiver owns
`producer_id`, `evidence_issuer_id`, `evidence_source_id`,
`transport_submitter_leaf_sha256`, and `receipt_sha256`. A source can own only
the canonical fact and its provenance.
Nested source data cannot set peer, transport, identity, candidate, service,
status, receipt, live, private, or digest-authority fields. `source_digest` is
the only source provenance digest field.

T063 implements twelve unavailable adapters. T081 adds one closed positive
validator for each operation. A validator accepts only the operation-specific
shape. It binds the exact identity, body, source, dependencies, time, digest,
revocation state, and operation key.

`accepted_positive_source_digest_v1` is the single positive-source digest
implementation. Both the source-owner service and the producer client call it.
Dependency names are sorted before their receipt digests enter this preimage.
The two-dependency `verify_responses_bridge` operation uses the same order at
acquisition and at producer binding.

The production source is the exact `FirstPartySupportedHostRuntimeV1`.
Production rejects a directly constructed `AvailableFact`, a mapping, a
subclass, and a store result with test-only classification before receiver
publication. Production accepts only `ValidatedProtectedFact` returned through
the exact runtime after an OS-bound protected writer and independent anchor
exchange. The type is data, not authority. The live kernel-authenticated
exchanges and exact T082 receipts are authority.

`ProducerClient.test_only` is the explicit validator-fixture mode. It converts
the supplied in-memory receiver harness to
`TestOnlyInMemoryReceiverTransport`. It cannot use the production transport
class. This mode can validate synthetic positive shapes and test-only
store-derived results. Its receipts do not become production authority.

A certificate authenticates the named principal only. It is not fact
authority.

## Binding rules

The client binds the operation to all of these values:

- source, candidate, and manifest digests;
- generation and service-start identity;
- request and response digests;
- policy digest and payload schema digest;
- exact ordered dependency receipt digests;
- previous binding-state digest;
- observed and expiry times;
- the policy-selected supported-host principal.

The client rejects an unknown or service-owned operation. It rejects a wrong,
unverified, or reused transport. It rejects stale, future, expired, or overlong
source facts and receipts. It rejects response drift, receipt replay context
drift, authority drift, and digest drift.

The client constructs exact closed request and response digest preimages. It
does not accept caller-selected preimages or caller-asserted request or response
digests. Both preimages bind the operation, exact service identity, local source
result, ordered dependencies, observed and expiry times, evidence ID, previous
binding-state digest, policy digest, host-profile identity, and correlation ID.
The response preimage also binds the request digest and the exact intended local
unavailable outcome. The dependency validator rejects unavailable and
authenticated-absence receipts before it derives their digests.

## Local outcome

The client returns one closed `package_host_supported_host_client_outcome_v1`.
It retains the local unavailable `reason` and `canonical_source_id`. It also
contains both generated digest preimages and the validated receiver-owned
27-field receipt. The client does not add the local reason or canonical source
ID to the v8 request or receiver receipt.

## I/O boundary

This module does not open a socket, start a process, read the environment, load
a key, or read a path. Production accepts only `OsBoundOpaqueTlsTransport`.
That transport uses a preconnected AF_UNIX channel whose distinct TLS-agent
peer identity is kernel-verified. The package-host v8 receiver protocol stays
unchanged and independently authenticates the client principal.

## Positive family closure

The client has closed validators for all twelve external operations. Catalog,
selection, supervision, effect authority, action observation, Responses
context, bridge observation, record lineage, projection seal, and recovery
reservation each use a separate validator. A generic mapping cannot create a
positive request. The selection commit source authorizes the exact command
body only. The package-host receiver owns the commit result.

## Proof boundary

The source-local proof uses explicit test facts to exercise each validator and
the actual producer-client and receiver seam. Those facts do not become live
authority. The proof does not establish an external host, live protected
writer, independent anchor, certificate handshake, private key, socket,
service, network journey, installation, or public release.
