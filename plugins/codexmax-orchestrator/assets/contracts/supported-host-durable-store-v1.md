# Supported-host protected durable writer v1

## Architecture truth

Local pathname checks cannot prove integrity against a hostile same-UID writer.
The accepted product boundary must use a separate protected writer. That writer
owns atomic append, durable anchor publication, and one-use receipt issuance.

This module defines the accepted request and receipt protocol. The separate
`supported_host_protected_fact_store_v1.py` module implements the concrete
producer-side writer/store and consumes injected protected persistence and
anchor sessions. This module includes one temp-root backend named
`TestOnlyUntrustedLocalBackend`. That backend is not production-independent. It
cannot return production-ready evidence.

## Fixed scope

The protocol supports exactly seven store namespaces and the twelve accepted
external operations. A request binds:

- store and namespace;
- canonical source and producer principal;
- operation;
- exact candidate and public profile digests;
- expected sequence, head, and generation;
- fact, revocation, or consumption event kind;
- record ID and one-use nonce;
- canonical payload and payload digest;
- target event and consumer digest when applicable;
- canonical request digest.

Integer fields require the exact JSON integer type. JSON is canonical UTF-8.
Floating-point values are not permitted.

## Protected writer receipt

A protected writer returns one closed receipt. The receipt binds:

- the exact request digest and all authority identities;
- prior and successor sequence, head, and generation;
- event and anchor digests;
- the previous receipt digest;
- writer ID and writer-build digest;
- protected session ID and binding digest;
- witness and expiry times;
- canonical receipt digest.

The writer receipt also binds the exact anchor-authority ID, authority-build
digest, and anchor-receipt digest. The anchor authority returns a separate
closed `protected_anchor_receipt_v1`. It binds:

- anchor authority ID, build, and receipt ID;
- exact append request digest and nonce;
- prior and successor sequence, head, and generation;
- event digest and stable writer-statement digest;
- anchor digest and previous anchor-receipt digest;
- retention and expiry times;
- canonical anchor-receipt digest.

The stable writer-statement digest blanks the later anchor-receipt reference and
final envelope digest. This two-stage construction avoids a digest cycle. The
anchor receipt binds the writer statement first. The final writer envelope then
binds the anchor receipt and authority. Validation cross-checks both directions.

The successor sequence and generation must be exactly one greater than the
prior values. The event digest is deterministic from the request and successor
CAS values. The anchor digest binds the event and previous receipt. Receipt
validation rejects rollback, fork, truncation, replay, collision, binding drift,
and anchor drift.

## Session and trust boundary

The runtime receives protected session provenance from a separate boundary. A
receipt must match that provenance exactly. Python objects and sentinels are
caller-constructible. Structural source-local validation cannot prove that the
separate boundary is protected.

For this reason, `evaluate_protected_receipt` always returns
`protected_writer_pending`. A receipt labeled `protected_writer_receipt` still
remains pending in source-local validation. A real later runtime can promote a
fact only after it verifies protected session provenance at the separate
boundary and preserves exact receipt and anchor parity.

A certificate can authenticate a writer principal. It is not fact authority.
A caller, fixture, certificate, self-digest, or Python sentinel cannot create a
positive fact.

## Test-only local backend

`TestOnlyUntrustedLocalBackend` uses an explicitly injected absolute temp root.
It has no production default. It stores closed request and receipt pairs in an
append-only sequence. It validates expected-head CAS, nonce replay, record
replay and collision, restart chains, revocation, recovery-grant consumption,
and local anchor parity.

Its receipts use state `test_only_untrusted_local_backend`. They always evaluate
to `protected_writer_pending` with `production_ready: false`.

The local backend can test crash and mutation behavior. Same-UID root,
namespace, event-name, and head replacement can corrupt or redirect local
files. Such a race proves only local mutation and pending status. It does not
prove protected-anchor integrity. This backend has no protected anchor and can
never return production success.

## Credential and execution boundary

The module does not read environment variables, credentials, private keys,
credential paths, keychains, or browser state. It does not use a socket,
network, process, service, provider, or production installation. Tests use only
temporary roots.

## Promotion condition

`validate_protected_record` validates and detaches the exact T082 append
request, writer receipt, and anchor receipt. It does not promote the triple to
live authority. T085 separately proves the writer and anchor kernel peer
identities before it uses this validated triple.

The durable-store lane can become production-ready only when an authorized
external runtime provides a real protected writer and independently retained
anchor service, and the runtime verifies exact session provenance and receipt
parity. Until then, the exact state is `protected_writer_pending`.
