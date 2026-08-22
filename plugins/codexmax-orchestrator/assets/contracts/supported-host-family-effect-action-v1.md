# Supported-host effect-action family v1

Status: T092 split source-local candidate

## Owner and boundary

The supported runtime has two owners. `effect-authority` owns T064.
`registered-action` owns T072. Each owner has a separate root, lock, manifest,
snapshot chain, and CAS anchor. A supported store cannot open the other
owner's root.

The combined T091 `EffectActionFamilyStore` remains a historical and migration
helper. It is not a supported runtime store.

Each split store retains one complete accepted ledger. It stores canonical
ledger bytes in every predecessor and successor transition. It revalidates
every byte during recovery.

The public split-transition validator requires the exact closed T064 or T072
schema. It binds the predecessor and successor sequences, heads, canonical
ledger bytes, mechanism event, and dependency-import heads. The public split-
anchor validator requires exact parity with that validated successor and
transition. Unknown or missing fields reject.

The proof boundary is `source_local_quarantine_non_production`. The module does
not prove a live executor, provider, service, socket, credential, or external
effect.

## Fixed operation paths

`EffectAuthorityFamilyStore` reads the current accepted
`responses_context_to_effect_authority_v1` import from its fixed artifact
store. The source-local authority state is exactly `quarantine`. It validates
the complete T066 transition. T066 retains only the
verification-context digest. The store resolves the complete context from an
owner-controlled pending-operation store by this digest. It validates the
T064 context shape and exact digest before it derives the T064 authority. The
public operation method accepts only `owner_now`.

`RegisteredActionFamilyStore` reads the current accepted
`effect_authority_to_registered_action_v1` import from its fixed artifact
store. It validates the complete T064 successor ledger. It rejects expired,
revoked, or nonquarantine authority. The public operation method cannot accept an
artifact, edge, ledger, head, source, principal, callback, or promotion state.

`invoke_registered_action` accepts one exact executor receipt only after these
records exist in order:

1. A repository-transport registry entry.
2. A T072 execution admission that contains the exact retained T064 authority.
3. An executor observation with a known route, model, and host.

Transport loss, a missing receipt, an unknown executor identity, or an invalid
receipt does not append an observation.

## Durable store

Each split store uses an owner lock and canonical immutable snapshots. Each snapshot
binds its predecessor snapshot digest. The current anchor binds the family
sequence, the accepted ledger sequence, the ledger head, and the canonical
ledger-byte digest.

Publication uses a new-file link for immutable snapshots and an atomic replace
for the current anchor. Recovery validates the full snapshot chain. Recovery
also validates every T064 and T072 event, every cross-family context binding,
and every predecessor and successor ledger transition. Each dependent
transition also binds its exact current import head. A complete valid
snapshot that precedes an interrupted anchor update advances the anchor. A
rollback, fork, gap, collision, truncation, malformed ledger, or noncanonical
file fails closed.

## Revocation and retry

Authority and observation revocations use the accepted T064 and T072 event
types. Revocation survives restart. An exact registration, admission,
observation, or authority retry returns the retained transition. A changed
request with a retained identity fails as a collision.

An effect-authority revoke stays in the effect-authority ledger. A
registered-action revoke stays in the registered-action ledger. The cross-owner
artifact store transfers each complete accepted transition on the fixed edge.

## Forbidden authority inputs

The public operation surface does not accept a family ledger, family head,
source identity, principal, callback, fixture, promotion state, generic
mechanism, or complete positive operation value. A certificate can authenticate
the principal at the later service boundary. It is not fact authority.
