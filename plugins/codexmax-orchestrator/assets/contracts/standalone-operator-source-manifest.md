# Standalone Operator Source Manifest v1

## Purpose

The standalone operator source manifest is the package-owned acceptance root
for deterministic source-local operator rendering. It is a closed,
multi-bundle allowlist. A successful match proves only that all displayed
source identities belong to one reviewed synthetic/no-effect bundle.

The fixed v1 asset is
`assets/manifests/standalone-operator-source-manifest-v1.json`. The renderer
discovers that asset from one source-relative constant, requires a regular
non-symlink file, hashes its exact raw bytes, and compares the result with its
separately reviewed constant before parsing it. No flag, environment variable,
binding value, configuration value, import path, or caller filesystem path may
select or replace the manifest.

The initial accepted raw identity is
`sha256:8532761f9ee497202b0a8a670fbed41fbaa56bd435c7ba9e215e533372c4884c`.
Changing either the manifest bytes or this consumer pin is a separate
package/workspace source-acceptance change; neither can accept the other.

## Closed shape

The root contains exactly `schema_version`, `artifact_type`, `scope`,
`canonicalization`, and `bundles`. `bundles` is nonempty, has unique bundle
objects, and is strictly ordered by `bundle_id` using ASCII ordering. Unknown,
missing, duplicate, noncanonical, non-JSON, symlinked, or non-regular input
fails closed.

Each bundle contains exactly:

- `bundle_id`, `workspace_id`, `proof_boundary`, and canonically ordered
  `role_ids`;
- closed `supported_versions` for the CLI, binding, runtime manifest, planner,
  adapter snapshot, Runtime Evidence, and policy proposal;
- an inclusive source-evaluation `validity` window and explicit `recall` state;
- `source_memberships` for the accepted CLI, runtime, candidate, workspace
  root, evidence source, and current policy identities;
- every complete binding slot's `request_sha256` and recomputed
  `receipt_sha256` in `request_memberships`;
- every displayed route's complete identity and recomputed
  `adapter_identity_sha256` in `route_memberships`, computed only by
  `runtime_adapter.adapter_identity_digest` over its fixed domain-wrapped
  complete identity;
- all available registry, capability-card, conformance-certificate,
  evaluation-manifest, task-profile, and evidence digests in
  `identity_memberships`; and
- the exact all-false `effect_guarantees` map.

Empty registry/card/certificate arrays mean that the accepted fixture contains
no such independently identified artifacts. They do not mean that an
unidentified artifact is accepted. `none` is permitted only for an explicit
recall-evidence value; it is never a digest wildcard.

## Digest and membership semantics

Raw file identity is SHA-256 over the manifest bytes as stored. It is not a
field inside the manifest. The manifest therefore cannot self-hash or
self-accept.

All JSON-object digests use the accepted
`standalone_runtime_cli.canonical_json` operation: UTF-8 JSON with keys sorted,
no insignificant whitespace, and the CLI's established scalar encoding.
`request_sha256` hashes the complete closed request. `receipt_sha256` equals
the accepted CLI receipt's own recomputed digest. `adapter_identity_sha256` is
exactly `runtime_adapter.adapter_identity_digest(identity)`: the existing
runtime primitive validates the complete identity and hashes
`{"domain": runtime_adapter.IDENTITY_DOMAIN, "identity": validated_identity}`.
It is not the direct canonical digest of the identity object. Raw-file and
canonical-object digests are not interchangeable.

Validation selects exactly one existing `bundle_id`; the binding cannot add or
modify a bundle. It then requires:

1. schema, scope, proof boundary, workspace, role set, and all supported
   versions to match exactly;
2. the accepted CLI raw identity and all runtime/source/candidate/policy
   memberships to match the recomputed sources;
3. one manifest request membership for every binding slot and no additional
   slot, with exact command, role, request, and receipt digests;
4. identical route sets across roles and an exact manifest route membership
   for every displayed route identity, with every adapter digest recomputed by
   `runtime_adapter.adapter_identity_digest`;
5. every source evaluation timestamp to fall inside the inclusive manifest
   window, with `evaluated_not_before` not later than `evaluated_not_after`;
6. exact set equality between manifest identity memberships and all consumed
   capability, health, billing, usage, conformance, evaluation-manifest,
   task-profile, and source evidence; an empty category accepts no unidentified
   member and a digest in another category or bundle cannot repair an omission;
7. the source's recall state, recall evidence, and recalled artifact IDs to
   equal the manifest exactly; a deleted recall cannot resurrect evidence and
   an added recall cannot preserve acceptance; and
8. all root, manifest, and recomputed receipt effects to remain the exact
   all-false maps required by their contracts.

The fixed anchor is verified before importing or executing the CLI and before
deriving any display value. Cross-bundle mixing is forbidden even when an
individual digest appears in more than one bundle. Unknown bundle, source,
request, route, adapter, evidence, version, window, or recall membership fails
closed.

## Initial source-local bundle

`source-local-fixture-20260806` anchors the exact accepted v1 fixture source
family used to construct the v2 binding: workspace `workspace-a`, roles
`auditor` and `worker`, routes `fake-route-a` and `fake-route-b`, all nine
complete command slots, their recomputed receipts, both complete adapter
identities, the runtime/candidate/workspace/evidence/policy identities, and the
available evaluation/task/evidence memberships. Its timestamps and recall
state are fixture facts, not current provider or deployment observations.

## Stable rejection boundary

The consumer maps failures to the stable surface families defined by the v2
binding contract, including unavailable, identity, shape, digest, bundle,
scope, version, window, expiry, recall, source-membership, and route-membership
failures. A more precise internal path may be retained for diagnostics but may
not turn a rejection into display truth.

## Non-authority boundary

Manifest membership is not a signature or an authenticity claim. The pin
protects against a caller who controls bindings and recomputed input sources;
it does not protect against modification of the package root. Mutable or
external anchors require a separately approved key, revocation, and installed
integrity design.

Acceptance grants no capability, route eligibility, planning authority, lease,
dispatch, provider call, runtime mutation, policy persistence or activation,
Parent acceptance, installation, release, publication, native-route status, or
AOL admission. It is not live/provider proof. All accepted content remains
source-local, deterministic, synthetic, read-only, and no-effect.
