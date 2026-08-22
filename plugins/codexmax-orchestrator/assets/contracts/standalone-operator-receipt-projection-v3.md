# Standalone operator receipt projection V3

The current browser/operator projection is standalone_operator_local_projection_v3.
The V2 projection remains a historical ABI and is fail-closed for a current
operator surface.

## Recovered-successor Cancel

A successor created by an accepted Recover may expose a positive Cancel grant
only when the canonical runtime effect-state verifier has persisted and
cross-bound the complete state-v2 recovery commitment. The Cancel grant uses
effect_operation "recover"; an ordinary running Cancel uses "run".

The recovered Cancel recovery object is closed and contains exactly the nine
persisted recovery_provenance fields plus predecessor_lease:

    grant_id, grant_sha256, issuer_id, predecessor_run_id,
    predecessor_effect_request_sha256, predecessor_effect_receipt_sha256,
    reconciliation_receipt_sha256, expected_cas, reserved_authority_id,
    predecessor_lease, predecessor_effect_receipt

`predecessor_effect_receipt` is the complete closed
`effect_kernel_receipt_v1` object copied from the verified state receipt index;
it is not a caller-provided summary. Its receipt digest, request digest, run
ID, lease, and post-state version must match the surrounding provenance. It
must represent the accepted `execution_unknown` predecessor (with no action
receipt and unknown observed route). Its 20 canonical fields are closed, and
any nested action receipt, if present in the canonical ABI, is itself closed
and digest-checked.

The current V3 schema is closed at every nested boundary. The root contains
exactly the fields in the companion schema, including the closed selection,
artifact references, controls, claims, supervision receipt, active selection
head, artifact-selection relation, preset catalog, and control authority.
Each non-null control grant contains exactly these 26 fields:

    grant_id, operation, provenance, run_id, predecessor_run_id,
    successor_run_id, effect_operation, lease_id, fencing_token,
    lease_expires_at, cas_expected_state_version,
    cas_expected_thread_generation, authority_receipt_sha256,
    effect_request_sha256, effect_receipt_sha256, action_receipt_sha256,
    bridge_receipt_sha256, cancel_observed, recovery,
    catalog_receipt_sha256, bundle_sha256, bundle_generation,
    selection_head_receipt_sha256, issued_at, expires_at, grant_sha256

The `recover` grant's `recovery` value is the complete closed
`effect_kernel_recovery_lease_grant_v1` record. A recovered-successor Cancel's
`recovery` value is the exact closed ten-field object above; ordinary Run,
Cancel, and Select grants carry null recovery. Authority, selection head,
supervision, catalog, lease, CAS, and receipt objects are all closed and must
not accept caller-added fields.

The nine fields are historical commitments. Their predecessor request/receipt
digests must not be replaced with the current successor request/receipt. The
top-level Cancel grant binds the current successor request/receipt, run ID,
lease ID, fence, expiry, authority, admission, selection, and effect-state
facts. The recovered CAS is pre-Recover: expected_state_version + 1 equals
the current authority effect-state version and the expected thread generation
equals the current selection generation. The successor lease ID is distinct
from the predecessor lease ID and its fence is strictly higher.

No current host recovery-grant read or seal is required for this display; the
verified persisted commitment is the authority evidence. Missing, stale,
duplicated, drifted, malformed, or merely self-rehashed lineage yields a null
Cancel grant and disabled control. Service submission re-derives the same
predicate under the effect lock.

## Proof boundary

V3 is source-local authenticated projection logic with fixture-only transport
mechanics. It does not prove installed distribution, native Desktop topology,
provider execution, human browser use, public publication, AOL admission, or
Parent acceptance.
