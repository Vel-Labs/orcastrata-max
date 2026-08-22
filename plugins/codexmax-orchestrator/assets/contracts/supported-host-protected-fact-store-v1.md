# Supported-host protected fact store v1

Status: test-only algorithm retained; production authority moved to the OS-bound service protocol

## Authority boundary

`FirstPartyProtectedWriterServiceV1` is now an explicit test-only chain harness.
It cannot create production authority. The former callback-backed production
devices reject construction with `protected_os_service_channel_required`.
Python callbacks, sentinels, classes, module names, mappings, booleans, and
classification strings are not production authority.

The persistence device must implement atomic compare-and-publish. The anchor
device must implement a separate atomic compare-and-publish. An interruption
between the two publications causes anchor parity failure on recovery. It does
not create a readable fact.

## Closed record

Each `supported_host_protected_fact_record_v1` binds the operation, canonical
source, producer principal, namespace, exact eight-field runtime identity,
profile digest, service start, body digest, dependency-receipt-set digest, v8
fact key, value, fact digest, source digest, issue, observation and expiry
times, initial revocation and consumption state, append request, writer
receipt, anchor receipt, sequence, generation, prior head, successor head, and
record digest.

Revocation and consumption are append-only transitions. Consumption is valid
only for the recovery namespace. The store rejects a second transition.

## Recovery and read

Every operation reconstructs the event chain from the persistence device and
compares it with the independent anchor. Recovery rejects fork, rollback,
truncation, malformed records, digest drift, record collision, transition
replay, and anchor drift. Append uses expected sequence, generation, and head
compare-and-swap. Validation finishes before publication.

A read matches exactly one current record against the operation, source,
principal, namespace, identity, profile, service start, body, dependency set,
and current UTC time. A missing, ambiguous, future, expired, revoked, consumed,
or anchor-invalid record is unavailable.

## Producer result

`ProtectedFactStoreClientV1` can mint `StoreDerivedAvailableFact` only for
test-only validator work. It exposes no production-authority property.
Production uses `supported_host_protected_service_v1.py` and exact T082 triples.

## Proof boundary

Source-local tests use in-memory devices and an authenticated in-memory
receiver harness. They prove algorithms and fail-closed routing only. They do
not prove a live protected service, independent hardware or service anchor,
TLS principal, external persistence, production receipt, installation, or
release.
