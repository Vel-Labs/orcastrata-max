# Supported Host Cross-Owner Artifacts V1

## Purpose

This contract transfers complete accepted dependency bytes between the six
first-party source-owner roles. It does not transfer fact authority through the
protected writer. It does not let a caller select an edge, role, mechanism,
ledger, source, family head, or promotion state.

## Fixed graph

The source contains exactly these edges:

| Edge | Producer | Consumer | Accepted mechanism |
| --- | --- | --- | --- |
| `catalog_selection_to_responses_selection_v1` | `catalog-selection` | `responses-seals` | T067 |
| `native_supervision_to_responses_context_v1` | `native-supervision` | `responses-seals` | T068 |
| `responses_context_to_effect_authority_v1` | `responses-seals` | `effect-authority` | T066 |
| `effect_authority_to_registered_action_v1` | `effect-authority` | `registered-action` | T064 |
| `registered_action_to_responses_bridge_v1` | `registered-action` | `responses-seals` | T072 |
| `responses_projection_to_recovery_v1` | `responses-seals` | `recovery` | T066 |
| `native_supervision_to_recovery_v1` | `native-supervision` | `recovery` | T068 |
| `effect_authority_to_recovery_v1` | `effect-authority` | `recovery` | T064 |

Catalog-to-supervision stays an exact public v8/T082 dependency. It is not a
complete-ledger edge.

## Artifact

`supported_host_cross_owner_artifact_v1` is exact closed. It binds the fixed
edge and protocol. It binds the joint authority digest. It binds both complete
service identities. Each identity includes the role, service, build, root,
start, session, session expiry, expected peer UID, expected primary GID, and
exact supplemental groups. Primary GID and supplemental groups are distinct
closed fields. A resealed swap between them rejects even if their combined set
is unchanged.

The artifact contains its export sequence and predecessor export head. It
contains the accepted mechanism, operation, semantic subject, event kind, and
optional revoke target. It contains the complete canonical predecessor and
successor ledger bytes. T068 uses the complete predecessor and successor
candidate chains. The artifact also contains the exact transition or current
T068 candidate bytes. Each byte field uses canonical base64 and a byte digest.

The artifact contains one exact family-anchor wrapper. The wrapper binds the
accepted mechanism, producer role, successor sequence, successor head,
successor ledger bytes, transition bytes, dependency-import heads, and the
retained family anchor. The retained anchor must pass its family-specific
validator. Its sequence, head, ledger bytes, and transition must equal the
exported successor. The dependency-import heads must equal the exact heads in
the accepted transition, including a T066 transition. A transition type that has no dependency-head
field requires an empty map. The artifact contains the observation time and
the effective expiry. Its final digest seals all fields.

Validation decodes all bytes. It checks canonical JSON. It runs the exact
closed T064, T066, T067, T068, or T072 transition validator. Unknown and
missing transition fields reject. It reproduces the operation, event,
sequence, predecessor, successor, head, dependency-import heads, and family
anchor. A digest or summary cannot replace the complete bytes.

## Durable stores

Each role root contains edge-local export and import artifact journals. Each
journal contains immutable artifacts, immutable events, and a sealed cursor.
The role has one shared lock, one sealed cross-owner anchor, and one transaction
pending file.

Publication creates the pending file first. It publishes the artifact and
event with absent-only creation. It fsyncs each file and directory. It replaces
the sealed cursor atomically. It removes the pending file only after the cursor
is durable. Recovery rolls back a pending transaction with no published bytes.
It completes a transaction with an already published artifact. Changed pending
or retained bytes reject.

Exact retry is idempotent. Changed bytes at one sequence collide. A gap, fork,
rollback, truncation, non-canonical byte stream, unknown edge residue, stale
expected head, or unexplained pending state rejects.

## Fixed transport

Each edge uses one inherited AF_UNIX descriptor. The consumer sends only its
durable cursor and a fresh challenge. The response binds the challenge and the
request digest. It contains the next producer-retained artifact or an exact
empty result.

Both endpoints capture the descriptor fingerprint and kernel peer identity
before the exchange. They compare the peer UID and groups with the complete
target identity. They repeat the witness after the exchange. Unsupported peer
credentials, changed descriptors, changed witnesses, or identity mismatches
reject.

Every public import, current-read, export, and serve method names one fixed
edge. Public methods do not accept an edge, producer role, consumer role,
artifact bytes, ledger, family head, source, or promotion state.

The consumer import receives the complete producer and consumer identities
from the sealed joint authority. It requires exact service, build, root,
start, session, expiry, UID, GID, and supplemental-group equality before it
persists an artifact. A correctly resealed artifact with one changed identity
field rejects.

## Restart and authority state

Producer restart keeps its export sequence. A current family transition can be
refreshed for a new producer or consumer session. Consumer restart keeps the
import cursor. A new consumer session needs an artifact targeted to that
session.

The effective expiry is no later than the mechanism, producer session,
consumer session, or five-minute artifact limit. Revoke and consume are new
complete transitions. They cannot reactivate an old subject.

All source-local projections have `authority_state=quarantine` and
`proof_boundary=source_local_quarantine_non_production`. The `event_kind`
separates issue, revoke, consume, admission, and observation. The module has no
positive promotion route. A promotion call fails with
`artifact_promotion_forbidden`. T082 never imports this module.

## Proof boundary

This contract proves source-local construction, validation, persistence,
restart, and transport. It does not prove live identities, credentials,
installation, a service start, external observation, or a live journey.
