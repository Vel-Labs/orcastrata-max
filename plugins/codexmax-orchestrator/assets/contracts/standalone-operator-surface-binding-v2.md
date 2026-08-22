# Standalone Operator Surface Binding v2

## Purpose and compatibility

Version 2 preserves every closed request, deterministic recomputation,
cross-binding, presentation-derivation, escaping, and all-false effect rule from
`standalone-operator-surface-binding.md`. It adds one prerequisite: every
displayed source identity must belong to one independently accepted bundle in
the fixed package-owned source manifest.

There is no implicit migration. A v1 binding, legacy snapshot, missing anchor
field, or alternate artifact type fails with
`surface_provenance_anchor_required` before any display is derived.

## Closed binding shape

The root contains exactly:

`schema_version`, `artifact_type`, `source_manifest_sha256`,
`source_bundle_id`, `accepted_cli_sha256`, `role_ids`, `status`,
`routes_by_role`, `plan`, `run`, `delegate`, `lineage`, `journal`,
`policy_proposal`, `effect_guarantees`, and `binding_sha256`.

`schema_version` is `2` and `artifact_type` is
`standalone_operator_surface_binding_v2`. `source_manifest_sha256` is the exact
fixed raw identity from the source-manifest contract. `source_bundle_id` names
one already-present bundle. Neither field is a path, URI, module, configuration
locator, update instruction, signature, or caller-controlled acceptance root.

The packaged schema reuses only the closed slot definitions from its fixed
sibling v1 schema; it does not loosen any request shape. Runtime validation
still performs the complete semantic checks and never resolves caller-provided
schema or manifest locations.

## Validation order

Validation is immutable and fail-closed in this order:

1. Require strict JSON and the exact v2 root shape.
2. Resolve the manifest only from the renderer's source-relative constant.
3. Reject a missing, non-regular, or symlinked asset.
4. Hash the manifest's raw bytes and require equality with both the renderer
   constant and `source_manifest_sha256`.
5. Parse and strictly validate the manifest, then select exactly one existing
   `source_bundle_id`.
6. Match scope, proof boundary, workspace, versions, roles, complete request
   and receipt digests, runtime/source identities, every complete route
   identity, available evidence identities, evaluation window, and recall
   state against that one bundle.
7. Only after source membership succeeds, hash-verify and import the fixed
   source-local CLI, re-execute every complete request, and apply all retained
   v1 cross-binding and no-effect checks.
8. Recompute `binding_sha256` over the complete canonical binding excluding
   only `binding_sha256`; then derive presentation solely from accepted
   recomputed receipts.

The CLI hash inside the binding cannot accept itself: it must equal the
selected manifest membership and the independently fixed CLI raw-byte pin.
Recomputing caller-controlled requests, receipts, adapter identities, and the
binding digest cannot create manifest membership.

## Bundle membership

All slots must be members of the same selected bundle. The status runtime and
workspace, planner roles/task/source scope, complete adapter identities,
gateway/evidence source and policy bindings, proposal base, evaluation facts,
and recall state remain subject to their original contracts as well as the
manifest match. A digest found only in another bundle is not accepted.

Route membership covers the complete displayed identity: route, adapter,
adapter bytes, provider, exact model, runtime, host, transport, service class,
billing basis and provenance, independence group, and input-delivery profile.
Its `adapter_identity_sha256` is recomputed only through
`runtime_adapter.adapter_identity_digest`, which hashes the validated complete
identity inside the primitive's fixed domain wrapper; a direct identity-object
digest is incompatible and rejected.
Capability, health, billing, usage, conformance, eligibility, rank, and gate
values remain recomputed receipt facts; manifest membership cannot promote a
negative or unknown value.

The selected bundle's membership sets must exactly equal all consumed
capability, health, billing, usage, conformance, evaluation-manifest,
task-profile, and source evidence. Subset acceptance, omitted usage evidence,
extra evidence, or evidence assembled across bundles fails closed.

The manifest window is applied to the source evaluation timestamps consumed by
the binding. The bounds are inclusive and ordered. Source-level expiry and
freshness checks remain independently mandatory. Recall state is exact:
omission, deletion, substitution, resurrection, or cross-bundle recall mixing
fails closed.

## Stable failures

| Code | Meaning |
| --- | --- |
| `surface_provenance_anchor_required` | Input is not the exact v2 anchored binding. |
| `surface_anchor_unavailable` | The fixed asset is absent, non-regular, unreadable, or a symlink. |
| `surface_anchor_identity_mismatch` | Binding, renderer, and raw manifest identities do not agree. |
| `surface_anchor_shape_invalid` | The fixed manifest is malformed, open, duplicated, or not strict JSON. |
| `surface_anchor_digest_mismatch` | A canonical manifest-owned object digest does not recompute. |
| `surface_anchor_bundle_unknown` | `source_bundle_id` does not name exactly one accepted bundle. |
| `surface_anchor_scope_mismatch` | Workspace, proof boundary, role scope, or bundle scope differs. |
| `surface_anchor_version_mismatch` | Any consumed artifact version is unsupported by the bundle. |
| `surface_anchor_window_invalid` | The manifest window is malformed, reversed, or a source evaluation predates it. |
| `surface_anchor_expired` | A consumed source evaluation or required source expiry is later than the accepted bound. |
| `surface_anchor_recall_mismatch` | Recall state, evidence, or recalled artifact membership differs. |
| `surface_source_not_accepted` | CLI, runtime, candidate, workspace-root, evidence-source, policy, request, or receipt membership is absent. |
| `surface_source_membership_mismatch` | Source identities are accepted only separately or from different bundles. |
| `surface_route_membership_mismatch` | A route or complete adapter identity is absent or differs. |

After anchor acceptance, the stable v1 request, receipt, cross-binding, and
effect failures remain applicable. More precise internal paths may be retained
for diagnostics but cannot repair rejection or become display truth.

## Non-authority and no-effect boundary

The anchor is a package-local hash pin, not a signature or authenticity claim.
It proves membership against reviewed package bytes for the bounded T066
attacker model; it does not prove installed-package integrity or protect
against package-root modification.

Validation and rendering do not start or bind a service, use a network, call a
provider, authenticate, allocate capacity, create a lease, dispatch, mutate or
recover a run, write a journal, persist or activate policy, grant capability or
authority, accept work, install, publish, release, or mutate AOL/GoalBuddy.
Success means only that a deterministic synthetic/no-effect operator view was
derived from one accepted source-local bundle. It is not live, provider,
quality, Parent, installation, release, native-route, publication, or AOL
acceptance.
