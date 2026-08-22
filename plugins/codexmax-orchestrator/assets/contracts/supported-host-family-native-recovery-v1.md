# Supported-host family native-recovery v1

## Status

This module contains two fixed first-party owners. `NativeSupervisionFamilyStore`
owns only the complete accepted T068 candidate chain. `RecoveryFamilyStore`
owns only the T069 recovery ledger, revocation, and consumption. The combined
`NativeRecoveryFamilyStore` remains a historical migration helper. It is not a
supported runtime store. It cannot open or share either supported role root.

The supported stores do not replace an accepted validator. Source-local output
has the fixed `source_local_quarantine_non_production` scope. It cannot promote
to T082.

The public native split-transition validator requires the exact closed T068
schema. It binds sequence, predecessor and successor chain bytes, candidate,
and dependency-import heads. The public native split-anchor validator requires
exact parity with that successor and transition. Unknown or missing fields
reject.

## Fixed operations

`NativeSupervisionFamilyStore.observe_supervision` implements
`read_operator_supervision`. It accepts raw native-host topology and one owner
cursor observation. The owner constructs the complete T068 candidate. It
validates cursor, topology, time, identity, and predecessor continuity. It also
derives the inventory artifact.

`RecoveryFamilyStore.reconcile_and_issue_grant` implements
`read_operator_recovery_lease_grant`. It accepts the stable recovery scope, the
observed predecessor fence, and owner time. It reads three typed imports from
its configured `RecoveryCrossOwnerStore`: the complete T066 projection
transition, the complete T068 chain, and the complete T064 ledger.

The operation method does not accept artifact bytes, import heads, source
identifiers, or mechanism output. The owner derives reconciliation identities
from the three imports. It derives the stable T078 resource scope from
workspace, effect, run, thread, and lease identity. It derives the exact
successor reservation fence and grant fence. It constructs the T069 reservation
before the grant. It validates the complete resulting ledger.

The public operation methods do not accept a candidate, inventory, reservation,
grant, ledger, family head, source, principal, callback, fixture, certificate,
complete result, import artifact, or promotion state.

## Durable retention

Each role root retains an independent manifest, append-only snapshot chain,
sealed anchor, and role lock. The native-supervision root cannot open a recovery
ledger. The recovery root cannot open a native-supervision chain. The recovery
transition records the exact current import heads for all three fixed edges. It
rejects a retry if a head or derived request changes.

Every snapshot is create-only. Each role lock protects recovery, retry,
collision, compare-and-swap, publication, revocation, or consumption for only
that role.

Recovery validates canonical bytes and every accepted T068 or T069 record. It
requires gap-free sequences and exact predecessor continuity. Each sealed
anchor binds only its role-local state bytes. Recovery rejects rollback, fork,
truncation, gaps, malformed records, hard links, symbolic links, and anchor
drift.

An exact acquisition retry returns the original retained bytes. Changed input
or changed import heads under the same acquisition identifier cause a
collision. T069 revocation is a complete accepted ledger event. Grant
consumption uses a sealed role-local journal because T069 does not define a
consumption event. Consumption does not change or summarize T069 bytes.

## Fixed import boundary

Parent integration must configure one `NativeSupervisionCrossOwnerStore` and
one `RecoveryCrossOwnerStore` with their exact service identities and joint
authority. It must use separate service roots. The artifact store owns the
fixed edge, producer, consumer, protocol, and complete artifact bytes.

`RecoveryFamilyStore` calls only these fixed current-read methods:

- `current_responses_projection_from_responses_seals`
- `current_native_supervision_from_native_supervision`
- `current_effect_authority_from_effect_authority`

It revalidates the complete T066 transition, T068 chain, and T064 ledger. It
binds the three imported heads into each dependent T069 transition.

## Proof boundary

The module performs no network, service, credential, certificate, provider,
browser, keychain, installation, publication, AOL, or production action.
Temp-root tests are source-local only. Parent integration must preserve the
complete predecessor and successor bytes supplied by the result artifacts.
