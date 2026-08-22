# Standalone operator local projection V2

The dynamic same-origin `/operator/v1/status` response is exactly
`standalone_operator_local_projection_v2`: every V1 local-binding field plus a
required closed `supervision` wrapper `{state,reason,receipt}`, active selection
head, artifact-selection relation, bounded public preset catalog, and required
`control_authority`. `verified`
requires an externally TLS-authenticated
`standalone_operator_supervision_receipt_v1`; `unavailable` requires a stable
reason and null receipt.

The catalog exposes only preset ID, family ID, and role plus its receipt/bundle
digests and generation; route, model, adapter, action, transport, qualification,
secret, and credential data remain host-private. Singleton or unavailable
catalogs disable Select, and unavailable catalogs disable Run. The active head
is catalog-bound while historical effect artifacts retain their own immutable
selection and are labelled rather than rewritten.

The V2 projection digest and package projection seal cover supervision,
catalog, head, and control authority. Any snapshot change rotates projection identity and view
nonce. Supervision is
veto-only: unavailable disables Run, Cancel, Recover, and Select; verified
supervision cannot enable a control denied by R4 lifecycle, capability,
lease/fence, CAS/generation, cancellation, or recovery rules. Retry, fallback,
and replacement remain false.

`control_authority` is null unless the service has revalidated every canonical
fact needed for at least one control. A non-null value is the closed
`standalone_operator_control_authority_v1` defined by the companion schema. It
binds the admission, candidate, binding and effect-state digests, active
selection, and four exact operation slots. Its `sealed_by` value is fixed to
`projection_receipt_v1`; its digest covers every other field, and the external
projection receipt then seals the complete V2 projection. Each non-null slot is
a closed `standalone_operator_control_grant_v1` whose digest covers all other
grant fields. Run, Cancel, Recover, and Select are enabled if and only if their
matching exact grant exists and is current. A shape-valid hash, lifecycle
reason, or browser copy is never authority.

The `run` object is closed. When `run.lifecycle` is `absent`, a non-null
`run.fencing_token` is permitted only when `control_authority.grants.run` is
non-null, enabled, current, and carries the exact same positive fence. An
absent run with a positive fence and no exact Run grant is invalid, even when
all outer digests are recomputed.

A Cancel grant for a successor run has a closed nine-field `recovery` object:
`grant_id`, `grant_sha256`, `issuer_id`, `predecessor_run_id`,
`predecessor_effect_request_sha256`, `predecessor_effect_receipt_sha256`,
`reconciliation_receipt_sha256`, `expected_cas`, and `reserved_authority_id`.
Its predecessor IDs and request/receipt digests must equal the projection run
and exact artifact references; its reconciliation digest must equal the
accepted supervision recovery receipt; and its closed CAS must equal the
authority effect-state version and active-selection thread generation. The
successor Cancel also requires the exact current successor lease/fence and
CAS bindings. Because V2 does not independently project the predecessor
lease/fence required to prove a strictly higher successor fence, recovered
successor Cancel is fail-closed and disabled until that trusted fact is
projected. Arbitrary, shape-only, or self-rehashed recovery never enables
Cancel.

The browser accepts neither V1 nor the rejected static receipt projection. It
loads only `./status`, submits only `./submit`, treats transport receipts as
outcome-unknown, and refreshes status before rendering any state change.
