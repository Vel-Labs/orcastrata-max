# Supported-host recovery v1

## Proof boundary

This contract defines structural recovery candidates only. It does not observe a native host. It does not reconcile an effect. It does not grant a lease. It does not make a producer fact available.

The canonical source adapter always returns the shared T063 `UnavailableFact`. A later source must supply authoritative evidence before the package host can become ready.

## Operation

The only operation is `read_operator_recovery_lease_grant`.

The source identifier is `recovery-lease-authority`.

## Structural decisions

Each decision uses the closed `supported_host_recovery_structural_decision_v1` shape. It binds:

- the ledger and operation;
- the workspace and service-start identity;
- the source, candidate, manifest, generation, and dependency receipt digests;
- effect, run, thread, and lease identifiers;
- predecessor effect-state and effect-receipt digests;
- the reconciliation decision digest;
- the T064 and T066 structural dependency identity digests;
- the observed and expiry times;
- a canonical SHA-256 decision seal.

`recovery_reservation_candidate` records a structural reservation intent and its fencing token and version.

`recovery_lease_grant_candidate` must refer to an earlier reservation decision in the same ledger. It must preserve all predecessor and dependency bindings. Its fencing token and version must each increment by one.

The earlier reservation must be unrevoked and unconsumed. The grant observation time must be strictly earlier than the reservation expiry time. A successful grant consumes the reservation permanently. Revoking the grant does not make the reservation reusable.

The recovery resource scope contains exactly the workspace, effect, run, thread, and lease identities. Evidence digests are lineage inputs. They never create a new namespace.

The permanent fence key contains the resource scope, fencing token, and fencing version. The ledger rejects a second active reservation for the same resource scope, including one that changes evidence or claims a different fence. Cancelling or consuming the active reservation permits a replacement only when both the token and version are the exact successors. Cancelling a reservation never permits a same-fence or arbitrary-fence replacement.

A grant must match every binding field stored with its reservation. The ledger checks all bindings, evidence lineage, expiry, revocation, consumption, and fencing before it marks the reservation consumed. A failed check does not change ledger state.

These variants do not assert that the dependencies are authoritative. A digest proves only the exact structural input identity.

## Ledger

The ledger is pure and has no I/O. It uses a closed append-only event chain.

Each append requires the exact expected head. The validator rechecks every stored decision, event, seal, binding, time window, sequence, predecessor, semantic identifier, and reservation-to-grant link.

The ledger rejects duplicate decisions, replayed decision digests, identifier collisions, stale heads, invalid revocations, time regression, and malformed nested values.

Recovery requires an exact externally retained event count and head digest. A valid but shorter prefix cannot satisfy the anchor.

## Exclusions

The contract rejects fixture, synthetic, test, caller-selected, missing, unverified, unknown, and default identities. It rejects private, credential, environment, path, endpoint, provider, and live-status fields.

The module does not access files, processes, sockets, services, providers, networks, credentials, or private keys. It has no `AvailableFact` path.
