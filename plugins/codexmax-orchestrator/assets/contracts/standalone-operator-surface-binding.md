# Standalone Operator Surface Binding v1

## Purpose

`standalone_operator_surface_binding_v1` is the only accepted input to the
standalone operator surface. It binds every displayed runtime fact to complete
requests re-executed by the accepted source-local standalone CLI. It is not a
snapshot, cache, receipt substitute, signature, authority grant, or acceptance
record.

Legacy `standalone_operator_snapshot_v1` input and any other unbound display
object fail with `surface_binding_required`. There is no implicit conversion:
caller-authored titles, provenance labels, timestamps, provider claims,
lifecycle/outcome claims, events, receipts, eligibility, authority, or
acceptance facts are not evidence.

The companion JSON Schema is
`assets/templates/standalone-operator-surface-binding-schema.json`.

## Closed v1 envelope

The binding contains exactly:

```text
schema_version       = 1
artifact_type        = standalone_operator_surface_binding_v1
accepted_cli_sha256  = SHA-256 of raw standalone_runtime_cli.py bytes
role_ids             = canonical role-ID list
status               = status source slot
routes_by_role       = one routes source slot per role
plan                 = plan source slot
run                  = run source slot
delegate             = delegate source slot
lineage              = lineage source slot
journal              = journal source slot
policy_proposal      = policy-propose source slot
effect_guarantees    = the exact all-false CLI effect map
binding_sha256       = canonical digest of this object excluding binding_sha256
```

The accepted v1 CLI byte identity is:

```text
sha256:d280030dec49dee42c11f01bc244f96e2f63e40750a21b35e4eb5a8caf3cc8cf
```

Changing those CLI bytes requires a separately reviewed binding version or an
explicit v1 identity update with full parity proof. A caller cannot select a
different CLI module or path.

Every ordinary source slot contains exactly `request`, `request_sha256`, and
`receipt_sha256`. Each `routes_by_role` item additionally contains `role_id`.
No caller-supplied receipt body is accepted. The validator recomputes it.

## Canonical JSON and digests

All binding JSON is strict UTF-8 JSON. Duplicate object keys, invalid UTF-8,
non-finite numbers, unsupported types, missing fields, and extra fields fail
closed.

Canonical JSON is exactly the accepted CLI `canonical_json` profile:

1. recursively reject non-finite numbers;
2. serialize with keys sorted lexicographically;
3. use compact separators `,` and `:`;
4. use `ensure_ascii=False` and `allow_nan=False`;
5. encode the result as UTF-8 bytes.

`digest(value)` is lowercase SHA-256 of those bytes prefixed with `sha256:`.
The digest rules are:

- `accepted_cli_sha256`: SHA-256 of the raw bytes of the exact source-local
  `scripts/standalone_runtime_cli.py`, prefixed with `sha256:`;
- `request_sha256`: `digest(slot.request)`;
- `receipt_sha256`: the `receipt_sha256` returned by
  `standalone_runtime_cli.execute(slot.request)`. The CLI computes that value
  as `digest(receipt_without_receipt_sha256)`;
- `binding_sha256`: `digest(binding_without_binding_sha256)`.

Digests prove deterministic byte/content continuity, not signer authenticity.

## Verification order

A conforming renderer validates in this order and stops on the first failure:

1. Strictly decode the binding and require the closed v1 schema. A legacy raw
   snapshot fails `surface_binding_required`.
2. Read the fixed source-local CLI file as bytes. Require its raw digest to
   equal both the v1 accepted identity above and `accepted_cli_sha256` before
   importing or executing it.
3. Recompute and compare `binding_sha256` with that field excluded.
4. Require `role_ids` to be nonempty, unique, and strictly increasing by the
   accepted ASCII identifier order. Require `routes_by_role` to have the same
   length and the same role IDs in the same order.
5. For every slot, require the exact command named below, recompute
   `request_sha256`, execute the complete request with the accepted CLI, and
   compare the recomputed receipt's own `receipt_sha256` to the slot value.
   Any CLI rejection becomes `surface_cli_request_rejected` with the original
   CLI code/path retained only as diagnostic detail.
6. Require every recomputed receipt to be
   `standalone_runtime_cli_receipt_v1`, `proof_boundary: synthetic_local`,
   `structured_output: true`, `side_effect_free: true`, and to contain the
   exact all-false effect map. The root effect map must be identical.
7. Apply every cross-binding rule below to the recomputed receipts and complete
   requests.
8. Derive presentation only from those recomputed receipts. Do not render a
   parallel caller-authored truth object.

Schema validation is necessary but never substitutes for CLI byte checking,
request/receipt recomputation, or semantic cross-binding.

## Exact command slots

| Slot | Required request command | Accepted source and displayed truth |
| --- | --- | --- |
| `status` | `status` | Closed runtime manifest; runtime identity, workspace, lifecycle, health, endpoint, and source provenance from the recomputed receipt only. |
| `routes_by_role[*]` | `routes` | One complete planner source per canonical role; all routes, identities, gates, exact blockers, ranks, and separate planes. |
| `plan` | `plan` | The selected role/task/route and child preview from the recomputed planner receipt; no execution or lease claim. |
| `run` | `run` | One immutable verified gateway run; lifecycle, terminal outcome, events, receipt references, bindings, and operation preview. |
| `delegate` | `delegate` | Delegation proposal/admission result from one verified Runtime Evidence source; no child launch. |
| `lineage` | `lineage` | Lineage, checkpoint, and recovery from that same evidence source. |
| `journal` | `journal` | Scoped untrusted journal, recalls, disclosure, TTL, and provenance from that same evidence source; no executable message. |
| `policy_proposal` | `policy-propose` | Deterministic unapplied policy proposal receipt, validation, diff, and forward rollback metadata. |

The request envelope is always the complete closed
`standalone_runtime_cli_request_v1` with exactly `cli_version`,
`artifact_type`, `command`, and `input`. The JSON Schema discriminates command
slots and recursively constrains JSON values; the accepted CLI remains the
authority for each complete upstream input's closed shape and semantics.

## Cross-bindings

### Roles, routes, and plan

- `role_ids` and `routes_by_role[*].role_id` are identical, nonempty, unique,
  and canonically ordered. Every recomputed routes receipt `role_id` equals its
  enclosing role ID.
- Each routes receipt contains a unique route ID set. All role receipts contain
  the same route ID set. For a given route ID, `adapter_identity_sha256` and the
  complete `identity` object are identical across roles. Eligibility, gates,
  reasons, weight, and rank may differ only as recomputed by each role request.
- The plan receipt `role_id` is one of `role_ids`. Its request `input` is
  byte-semantic JSON equal to the matching role's routes request `input`; only
  the command differs. Its `task_id`, complete `routes`, `selected`, and
  `child_preview` are therefore the exact recomputed plan truth.
- A complete binding represents one coherent planned run, so `plan.selected`
  is non-null. Its route exists in the matching routes receipt, is eligible,
  and has the identical adapter identity. No preference or display value may
  repair a failed hard gate.

### Workspace, task, run, and evidence lineage

- The status receipt runtime `workspace_id`, the CLI-validated planner source
  `workspace_id` (direct request, or the nested request in an accepted
  `runtime_plan_binding_v1`), and Runtime Evidence receipt
  `bindings.workspace_id` are identical.
- The plan `task_id` equals Runtime Evidence `bindings.task_id`.
- `delegate`, `lineage`, and `journal` requests have byte-semantic identical
  `input` values. Their recomputed receipt `source_sha256` values are identical;
  their command-specific receipt hashes remain distinct.
- The run receipt `run.run_id` equals Runtime Evidence `bindings.run_id`,
  `lineage.current_run_id`, and `journal.current_run_id`.
- The evidence `lineage.root_run_id` equals `bindings.root_run_id` and
  `journal.root_run_id`. Its parent, depth, and ancestors are displayed only
  from the recomputed lineage receipt.
- For the overlapping gateway/evidence binding fields, the run's
  `authority_sha256`, `route_sha256`, `policy_sha256`, and `source_sha256` equal
  the Runtime Evidence bindings. Missing overlap fails closed; identifiers or
  unrelated hashes are never coerced into a match.
- The selected plan route ID equals Runtime Evidence `bindings.route_id`, and
  its route identity `adapter_sha256` equals Runtime Evidence
  `bindings.adapter_sha256`.
- Journal workspace, task, root/current run, adapter, subtree, disclosure,
  message, recall, trust, TTL, and provenance facts come only from the
  recomputed journal receipt. A recalled or undisclosed fact cannot be restored
  through another slot.

### Policy proposal

- The policy receipt is recomputed from the complete `policy-propose` request;
  the displayed proposal is exactly `receipt.proposal`.
- The proposal `base_policy_sha256` equals Runtime Evidence
  `bindings.policy_sha256`, binding the preview to the current accepted policy.
- The proposal's `proposal_sha256`, validation codes, ordered changes, inverse
  changes, append-only/dry-run flags, and false persistence/activation/
  authority/acceptance claims remain exactly as emitted by the CLI.
- `proposed_policy_sha256` is never treated as the run's active policy. A
  proposal remains proposed and unapplied.

## Presentation derivation

Static headings and accessibility labels may be fixed UI chrome. Every factual
value is derived from the recomputed receipts:

- runtime/status identity and health from `status`;
- complete matrix, provider/model/runtime/adapter/billing identity, eligibility,
  hard gates, blockers, rank, and capacity plane from `routes_by_role`;
- plan role/task/selection from `plan`;
- lifecycle, terminal outcome, events, and receipt references from `run`;
- delegation state from `delegate`;
- lineage/checkpoint/recovery from `lineage`;
- journal messages, scope, trust, TTL, disclosure, recall, and provenance from
  `journal`;
- proposal/diff/rollback state from `policy_proposal`;
- source provenance from the accepted CLI hash plus request and recomputed
  receipt hashes.

The binding has no title, generated timestamp, free-form provenance, provider,
lifecycle, terminal outcome, event, receipt, authority, or acceptance field.
Such fields at the binding layer are unknown fields and fail closed. A UI may
show an evaluation time only when that exact value exists in a recomputed
source receipt; it may not create `generated_at`.

## Stable surface-binding failures

| Code | Meaning |
| --- | --- |
| `surface_binding_required` | Input is a legacy snapshot or is not the v1 binding artifact. |
| `surface_binding_version_invalid` | Schema or artifact version is unsupported. |
| `surface_binding_shape_invalid` | A binding-owned object is malformed, missing, extra, duplicated, or not strict JSON. |
| `surface_cli_identity_mismatch` | The fixed source-local CLI bytes do not equal the accepted and supplied identity. |
| `surface_binding_digest_mismatch` | `binding_sha256` does not match the canonical binding excluding itself. |
| `surface_command_slot_mismatch` | A slot contains the wrong CLI command. |
| `surface_request_digest_mismatch` | A request digest is not the canonical digest of the complete request. |
| `surface_cli_request_rejected` | Re-executing a complete request failed in the accepted CLI. |
| `surface_receipt_digest_mismatch` | A slot digest does not equal the recomputed CLI receipt's own digest. |
| `surface_receipt_shape_invalid` | A recomputed result is not an accepted no-effect CLI receipt. |
| `surface_effect_claimed` | Root or recomputed receipt effects are not the exact all-false map. |
| `surface_role_order_invalid` | Role IDs are empty, duplicated, noncanonical, or disagree with route slots. |
| `surface_role_binding_mismatch` | A route receipt's role differs from its slot. |
| `surface_route_set_mismatch` | Per-role route ID sets differ or contain duplicates. |
| `surface_route_identity_mismatch` | A shared route has inconsistent adapter/identity facts. |
| `surface_plan_binding_mismatch` | Plan role/source/routes/selection are not exactly bound to the matching route source. |
| `surface_evidence_source_mismatch` | Delegate, lineage, and journal do not share one exact evidence source. |
| `surface_workspace_mismatch` | Status, plan, and evidence workspace identities differ. |
| `surface_task_mismatch` | Plan and evidence task identities differ. |
| `surface_run_lineage_mismatch` | Gateway run and evidence run/lineage/journal identities or shared digests differ. |
| `surface_policy_binding_mismatch` | Proposal receipt/base policy does not bind the current evidence policy or claims application. |

The implementation may retain a more precise CLI cause/path as diagnostic
metadata, but it must not turn a rejection into display truth.

## No-effect and security boundary

Validation and rendering are deterministic, source-local, read-only operations.
They do not start or bind a service, use a network, call a provider, authenticate,
allocate capacity, create a lease, dispatch, mutate/cancel/recover a run, write a
journal, persist or activate policy, grant authority, accept work, install,
publish, release, or mutate AOL/GoalBuddy. The renderer imports only the
hash-verified source-local CLI and must not accept a caller-controlled module
path.

Journal content remains escaped, untrusted, non-executable evidence. Embedded
JSON must be safe for its HTML context. Unknown, recalled, stale, contradictory,
expired, undisclosed, or unbound facts fail closed. Validation success means
only that a deterministic no-effect operator view can be derived from accepted
source bytes; it is not runtime, provider, quality, Parent, installation,
release, native-route, or AOL acceptance.
