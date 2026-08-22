# Standalone operator local binding V1

This package defines a dormant, fixed-origin binding between the standalone
operator and the existing runtime effect authority. It does not add a second
executor. The only routes are `GET /operator/v1/`, `GET /operator/v1/app.js`,
`GET /operator/v1/styles.css`, `GET /operator/v1/status`, and
`POST /operator/v1/submit`; the handler accepts no origin, URL, transport,
credential, provider, model, host, registry, handler, verifier, or trust root.
The listener-start entry is present but fails closed until immutable package
slots contain independently verified capabilities. T050 never starts it.

## Capability admission

`standalone_operator_capability_admission_v1` is closed and binds issuer,
workspace, exact source/candidate, service instance, the complete set of named
shipped capability IDs, issuance/expiry, revocation, and an opaque externally
verified seal. Admission can activate shipped mappings only; it carries no
code or endpoint. Missing, malformed, expired, revoked, or identity-mismatched
admission yields disabled status and makes submission fail with
`production_capability_unavailable` before workspace, lock, state, or effect
access. Public methods expose no capability or verifier parameters.

The immutable resolution path is the shared package host capability adapter.
It requires TLS 1.3 over `AF_UNIX` `SOCK_STREAM`, the release-pinned CA digest,
certificate verification, and exact DNS SAN before sending a closed semantic
request. Same-uid socket possession is not authority. No environment variable,
caller path, URL, origin, transport, verifier, or trust root can redirect it.
Source package data is explicitly unconfigured and fails closed; a later
candidate may replace only pinned trust/allowlist data. Listener start receives
only validated package identity and the fixed route table and returns a closed
local-only receipt.

## Canonical artifacts and persistence

`standalone_operator_binding_record_v1` retains the full, exact
`standalone_responses_request_v1`, `effect_kernel_request_v1`,
`effect_kernel_receipt_v1`, nested `effect_kernel_action_receipt_v1`, and
`standalone_responses_bridge_receipt_v1`. The package invokes the canonical
gateway and Responses validators plus their external receipt authorities
before creating and whenever reading a record. Proxy artifact names and
self-digests are rejected. A host seal binds the complete artifact set to the
admitted seal but never substitutes for local canonical revalidation. The
public record validator has no caller verifier parameter.

Records are written beneath the existing exclusive effect lock with CAS and
view/submission replay state. A reserved submission becomes
`pending_submission`; status disables every mutable control until canonical
post-dispatch artifacts reconcile it. Each completed submission persists an
ordered closed replay row containing the submission ID, canonical submission
digest, and exact immutable transport receipt. The binding never writes effect
state.

## Projection and controls

`standalone_operator_local_projection_v1` contains exactly the fields listed
in the companion schema. Its artifact references are digests of stored
originals, not smaller proxy receipts. Positive projections are bound by an
external package projection receipt. Unadmitted projections are explicitly
unavailable, unsealed, and have every control disabled.

No-record Run is enabled only by an authenticated baseline grant binding exact
candidate/workspace/source, selection digest, effect-state version, thread
generation, positive current lease/fence, CAS, expiry, and shipped action,
context, and bridge capabilities. Run, Cancel, Recover, and Select are server-derived from admitted named
capabilities, authentic lineage, current positive lease/fence, exact CAS and
thread generation, canonical lifecycle, observed cancellation/reconciliation,
and predecessor/successor constraints. Zero/stale/unknown/request-only facts
never enable a control. Retry, fallback, and replacement are always false.
Dynamic status returns current standalone_operator_local_projection_v3.
V2 remains a historical fail-closed ABI. V3 is V1 plus closed supervision,
active-selection, artifact-selection, bounded public catalog facts, and a
required nullable sealed `control_authority`. Its recovered-successor Cancel
uses the closed nine-field persisted recovery commitment plus predecessor
lease described in the V3 projection contract. The positive supervision receipt is externally read
through the pinned TLS channel and binds binding, thread, selection, native
identity, topology, continuity, recovery, and snapshot chain. It is veto-only:
unavailable disables every effect control, while verified supervision cannot
enable any control whose R4 predicate is false. Its snapshot digest participates
in projection ID and view-nonce derivation.
Catalog and head receipt digests also rotate projection identity. Missing or
singleton catalogs disable Select; missing catalogs also disable Run. Artifact
selection remains labelled current, historical, or unavailable and never
authorizes a new Run.

The service alone derives `standalone_operator_control_authority_v1` after
canonical admission, baseline-or-record, binding, selection/head/catalog,
supervision, lease/fence/CAS, and artifact validation. Its exact four-slot
grant map contains only closed `standalone_operator_control_grant_v1` values or
null. Run requires zero-state CAS and a current positive lease; Cancel requires
canonical running lineage and the original Run receipts; Recover requires
execution-unknown, observed reconciliation, and the host-sealed distinct
successor lease/provenance commitment; Select requires the current head and an
alternative qualified preset with no in-flight lineage. Legacy state v1,
missing facts, stale or expired facts, and operation-specific nullability drift
produce no grant. Controls are enabled if and only if the corresponding exact
grant is present. Submit re-reads and re-derives this authority beneath the
existing effect lock; browser authority is evidence only and cannot authorize
execution.

Projection nonce and authority remain stable until advertised expiry. Failed
submission does not consume it, idempotent replay returns the same transport
receipt, and successful mutation invalidates the prior state/version/nonce.

## Submission

`standalone_operator_control_submission_v1` binds one projection digest and
view nonce. Payloads are closed:

- Run: `{message}`
- Cancel: `{run_id,effect_receipt_sha256,fencing_token}`
- Recover: `{predecessor_run_id,predecessor_receipt_sha256,predecessor_fencing_token}`
- Select: `{preset_id,expected_generation}`, where generation is the catalog
  generation and is independent from the host-owned thread generation

The service closes and validates the complete submission before capability or
replay work. Select first performs a side-effect-free host lookup. Exact lookup
fully revalidates the original mutation and returns its transport receipt after
head advance; changed semantics collide. Only absent lookup acquires the shared
effect lock, reconstructs current catalog/head/supervision/lifecycle state, and
permits one host CAS. No stale or unavailable validation is bypassed. Select
writes neither effect state nor the historical binding record. Malformed or
extra fields fail before host dispatch or filesystem mutation. The service and
its package-owned dispatcher mint all request, idempotency,
authority, context, and lease material. A transport receipt never claims an
effect outcome and requires a fresh status read before presentation changes.

Proof is source-local only. It is not installed listener, browser, provider,
native-host, credential, AOL, release, or T075 evidence.
