# StandaloneRuntimeContract v1

## Status and proof boundary

This contract is the additive semantic spine for a standalone Codexmax runtime.
It binds current legacy v1 contracts through explicit adapters; it does not
change their schemas or consumers. The accompanying validator is deterministic,
side-effect-free, and non-authoritative. It parses one local JSON document and
returns pass or a typed failure. It never selects a route, allocates capacity,
schedules or dispatches a run, calls a provider, writes a ledger, activates
policy, mutates GoalBuddy, starts a service, installs, publishes, or accepts
work.

Validation proves only source-local contract conformance over synthetic data.
It is not release, installed-runtime, provider, native-route, AOL, or product
acceptance proof.

## Aggregate and component versioning

The envelope is exactly `StandaloneRuntimeContract` version `1`. Every semantic
component declares its own version: runtime manifest, route identity,
capability evidence, qualification, role policy, assignment authority,
preflight, plan, capacity authority, run, event, receipt, continuation,
delegation, task journal, compatibility, and downstream fork.

The aggregate version does not imply component compatibility. Unknown,
missing, extra, or mismatched versions fail closed. Existing
`DispatchScheduler v1`, `DispatchLedger v1`, `PreflightBroker v1`, Route Fabric
v1, WorkGraph v1, Execution Continuity v1, and Trajectory Memory v1 remain
unchanged behind explicit adapters.

## Identity and evidence

`RuntimeManifest` binds runtime/API version, source and candidate digests,
workspace isolation, foreground process mode, local endpoint type, supported
transports, health, degradation reasons, and recovery instructions.
Supported transports are a nonempty subset of `local_cli`, `in_process`,
`unix_socket`, and `loopback_http`; the selected local endpoint transport must
be present and the other endpoint kind absent.

`RouteIdentity` binds route, provider, exact model, runtime/version,
adapter/version/digest, transport, non-secret service-reference class, billing
basis and provenance, independence group, and input-delivery profile. The same
model through another service, runtime, host, transport, or adapter is another
route and inherits no capability, health, billing, qualification, or acceptance
evidence.

`CapabilityEvidence` is typed, positive/negative/unknown, declared or observed,
and bound to exact route/provider/model/runtime/host/adapter, task profile,
evaluation manifest, collection time, expiry, invalidation, contradiction, and
artifact digest. Provider/model identity, role, preference, parent route,
checkpoint state, journal content, and model output create neither capability
nor authority. Unknown, stale, contradictory, expired, recalled, or unavailable
evidence never becomes eligible.

Qualification uses the precedence `recalled > expired > stale > active`.
Active qualification is only capability evidence; it is not task authority,
capacity, execution success, quality, acceptance, or signer authenticity.
The envelope carries one deterministic `evaluated_at`; validators derive
expiry and freshness from it, then apply append-only invalidation,
contradiction, and recall evidence. Caller-supplied effective status never
overrides that derivation. Qualification task-profile and evaluation-manifest
digests must equal every capability-evidence binding used by preflight.

## Role, task, authority, preflight, and plan

`RolePolicy` describes requirements, maximum effects, route filters,
independence/consequence/billing/fallback ceilings, incompatibility reasons,
and soft affinity weights. A role cannot create provider identity, capability,
billing permission, or task authority.
Every assignment effect and tool is cross-checked against the role maximum and
positive observed capability evidence for the exact qualified route.

`AssignmentAuthority` is exact, task-scoped, source-digest-bound, expiring, and
revocable. Active authority is derived at the envelope `evaluated_at`: expiry
or any `revocation_ref` denies it, and `issued_at` must not be later than that
evaluation. Every scope path is a normalized portable relative path beneath the
runtime `workspace_root_sha256` identity; absolute paths, platform drive paths,
backslashes, percent-encoded forms, empty segments, dot segments, and traversal
segments fail closed.
It binds scope paths, tools, effects, mutation mode, route policy,
fallback, billing, finite limits, approver, expected artifacts, and validation
and return-schema policies. `source_scope_sha256` is recomputed over the
`standalone-runtime-source-scope-v1` domain containing workspace-root identity,
source-tree identity, manifest identity, and ordered scope paths.
`authority_sha256` is recomputed over the
`standalone-runtime-assignment-authority-v1` domain containing every authority
field except that digest, including embedded source scope, approver, policies,
and containment evidence. Authority is rechecked before every effect phase and
child admission.

Every authority contains explicit digest-bound
`realpath_symlink_containment_v1` evidence for the exact workspace and ordered
scope paths. That closed evidence object carries the workspace-root identity,
source-scope identity, ordered `declared_scope_paths`, ordered
`resolved_path_identities`, the digest of those resolved identities, check time,
contained result, and an exact fail-closed effect-gate policy. Its evidence
digest is recomputed over every closed `scope_containment` field except
`resolution_evidence_sha256` itself, including `source_scope_sha256` and
`resolved_scope_paths_sha256`, so a changed scope cannot reuse an opaque
containment assertion. The effect boundary must resolve
realpaths and symlinks again immediately before each effect and fail closed on
missing, stale, identity-mismatched, outside-workspace, or ambiguous evidence.
This source-local validator verifies the evidence envelope and mandatory gate
only; it performs no filesystem resolution and claims no filesystem proof.

Eligible preflight and effect-ready plan bind an effect-recheck requirements
commitment derived from requested effects, target identities, containment
evidence, and the closed gate policy; neither binds a future receipt. At run
time, every requested true effect has exactly one ordered, single-use receipt.
Each receipt binds run identity, effect kind and sequence, target identity,
authority, source scope, qualification, containment evidence, gate policy,
check time, and effect-boundary identity. A receipt preceding run creation,
more than one second before its boundary, outside the run, duplicated, reused,
out of order, or missing for a requested effect fails closed. Completed
execution binds the ordered receipt-digest list. Rotating authority, scope,
qualification, containment, target, or boundary identity requires fresh
downstream bindings; assignment-local identifiers alone are insufficient.

Preflight returns every visible route's configured preference, effective
eligibility, all passed/failed hard gates, evidence state, health, quota,
capacity, billing, fallback, and a probe-serialization lease reference. Gate
order is fixed:

1. identity and schema;
2. task and source compatibility;
3. capability and freshness;
4. assignment authority;
5. privacy, consequence, and independence;
6. billing and fallback;
7. health, quota, and capacity;
8. only then affinity, fairness, and deterministic tie-breaking.

Preflight and plan are side-effect-free. A successful plan binds the exact
eligible preflight identifier and a route allowed by every role-policy filter
and consequence, billing, and fallback ceiling. A plan may report one eligible route,
but it creates no capacity lease, run admission, provider/filesystem effect, or
ledger row. Preference and weight never bypass a hard gate. The preflight
bounds only the effect-recheck policy/requirements commitment, never a future
effect receipt. The preflight
billing basis and provenance exactly mirror the selected route; the billing
basis remains within both assignment and role ceilings. Preflight also binds
the exact `qualification_id`. Its `fallback_allowed`
value is derived from both fallback ceilings. Eligibility also requires a
healthy, non-degraded runtime and active route evidence. An unknown billing
basis, billing provenance, or billing gate can remain visible, but it cannot be
eligible, feed a plan, or complete successfully.
Any metered route is ineligible under the frozen zero external-cost budget,
including when usage is unknown or claimed as zero.

## Exclusive capacity authority and distinct leases

Exactly one qualified, non-compatibility adapter is selected, preserving one `CapacityAuthorityAdapter` per `authority_domain`.
In the workspace-shared
domain, `fleet.sqlite3` is the sole shared count, reservation, capacity-lease,
and capacity-fencing authority. `DispatchScheduler` adjudicates product runs;
`DispatchLedger` records run/accounting/effect history and the external
capacity-lease reference. Neither allocates shared fleet slots.

A `run_execution_fence` protects run ownership, not fleet capacity.
`PreflightBroker` probe leases serialize probes only. Capacity leases, run
fences, and probe leases are different identifiers and authority domains.

Standalone isolated operation may select one qualified
`LocalCapacityAdapter`. Legacy JSONL capacity is compatibility-only and cannot
coexist with SQLite capacity authority in the same domain.
Every adapter identity is unique, including unqualified and compatibility-only
entries. `workspace-shared` admits only `shared_sqlite_fleet`, while
`isolated-local` admits only `isolated_local`.

## Run lifecycle, events, and receipts

The ordered lifecycle is:

```text
created -> preflighted -> planned -> admitted -> launching -> running
        -> reconciling -> quality_checked -> review_pending -> terminal
```

Terminal outcomes are `completed`, `denied`, `cancelled`, `failed`,
`timed_out`, `unavailable`, `unreconciled`, `superseded`, and
`recovered_to_successor`. Recovery appends a digest-bound successor; it never
rewrites a predecessor. Runtime completion never claims Parent acceptance.

Events are append-only, sequence-bound, predecessor-linked, timestamped, and
bound to the run. Receipts separately bind execution, quality, usage,
artifacts, lineage, and recovery. Quality never implies execution success.
Usage is observed, estimated, or the literal `unknown`, with an
anti-double-counting identity. Unknown never becomes zero or false.
Event identifiers are unique, timestamps strictly increase, and event types
come from the portable lifecycle mapping. A successful accepted terminal may
not exceed assignment token or cost limits; a measured overrun must close as a
failed, rejected disposition. Root lineage has no predecessor, and recovery
successors differ from current and predecessor identities. Every run event,
including the terminal event, occurs no earlier than authority issuance and
evaluation and strictly before both assignment-authority and qualification
expiry. The terminal event is also strictly before the earliest active
capability-evidence expiry. Terminal event legality remains bound to the run
lifecycle and outcome.

## Continuation and governed delegation

Continuation binds an immutable predecessor, checkpoint, context-rollover and
handoff identity, remaining finite limits, an existing authorized journal
message cursor, and mandatory fresh
authority/capability checks. A longer run, client exit, checkpoint, or rollover
never expands authority.

A model may propose a typed delegation request. It cannot spawn, admit, or call
a child directly. Admission is independent and the child's scope, paths,
tools, effects, disclosure, egress, network, providers, billing, fallback,
route set, retention, and every recursion/budget ceiling remain a strict subset
of current parent authority and remaining limits.

V1 structural maxima are root depth `0`, child depth `1`, one total child per
parent, one active child per parent, one active descendant per root, and zero
child-to-child message edges. Every child has finite positive attempt, runtime,
uninterrupted-action, token, disclosure-byte, journal-count, message-byte, and
TTL ceilings plus a finite nonnegative external-cost ceiling. T015 owns later
operational maxima; missing or unknown ceilings deny admission.

The frozen synthetic/local root maxima are 2 attempts, 600 runtime seconds,
120 uninterrupted-action seconds, 20,000 tokens, 65,536 disclosure bytes, 20
journal messages, 4,096 bytes per message, 3,600 TTL seconds, and zero external
cost microunits. Child/remaining maxima are respectively 1, 300, 60, 10,000,
32,768, 10, 2,048, 1,800, and zero. A child is bound to the current parent run,
the exact lineage, a passing cycle check, and values no greater than the
continuation's remaining budget.
The child identity differs from parent, current, and root identities; this is
derived structurally rather than trusted from `cycle_check` alone. A denied
parent cannot carry an admitted child or a running/completed materialization.
Child validation-policy and return-schema digests exactly equal the explicit
parent assignment-authority fields; a child cannot supply either policy.

No mandatory model hop exists. Same-route recursion is permissible only
through ordinary governed admission and receives no authority from model
identity.

## Standalone TaskJournal and recall

The standalone `TaskJournal` is canonical append-only storage for scoped
coordination records. WorkGraph may provide lineage/scope references and
GoalBuddy notes may be adapted, but neither is required standalone storage.
Messages are typed, provenance-bound, TTL/size limited, redacted, scoped to an
authorized subtree, and treated as append-only untrusted evidence. They are
never executable instructions or authority and cannot select routes, grant
capability, activate policy, mutate GoalBuddy, dispatch, or cause tool/provider
effects. Global/anonymous discovery, mutable edits, hidden namespaces, and
direct child-to-child messaging are forbidden.

Recall and invalidation append authority-bound events whose typed subject must
exist and match the named qualification, journal, or run. Recall blocks new
admission and fences cancellation/reconciliation while preserving history. A
recalled channel cannot be reconstructed through another shared resource.
Recall identifiers are unique, and every recall event occurs during the same
active evaluated assignment and qualification time window as run events; no
recall event may precede `evaluated_at`.
Journal validation binds sender lineage, assignment authority, authorized
WorkGraph subtree, predecessor/reply chain, redaction class, recomputed content
bytes and digests, TTL, message count, artifact references, recall event, and
channel-open state. Historical messages remain immutable after recall while
the channel is closed.
Only a materially admitted lineage child may send. TTL, message bytes, and
journal count are derived per sender lineage, so child ceilings apply to child
messages. Journal record and expiry times stay inside authority and evaluation
validity. Credential-like unredacted content fails machine validation across
every operational or exportable string surface. Detection includes
`sk-proj-*`, bearer values, URL credentials, common provider-token prefixes,
and token, secret, or key assignments.
Credential-like reference content also fails machine validation in route
service references, assignment expected artifacts, artifact receipts,
delegation disclosure references, journal artifact references, and downstream
distribution or fork identifiers. A `sanitized: true` declaration never
overrides content inspection.

Required adversarial coverage treats filenames, paths, metadata, artifact
names, caches, logs, error text, timing, package registries, shared services,
and indirect egress as covert channels. Controls must also detect attempts to
reconstruct disabled channels, forge/replay messages, smuggle instructions,
widen child authority, delete history, or leak across workspaces/runs.

## Integrity and authenticity

Canonical SHA-256 object digests and predecessor chains prove integrity, not authenticity.
Signature state is only `not_configured` or `unknown` in v1.
There is no cryptographic authenticity claim until an algorithm, trust root,
key lifecycle, revocation model, and verification policy receive separate
approval.
The canonical domain is sorted ASCII JSON with every floating-point number,
including finite and non-finite values, forbidden.
Event and journal-message digests exclude only their own digest field and bind
the predecessor digest. The envelope digest covers the entire document except
`integrity.object_digest`; validators recompute each domain dependency-free.

## Compatibility and downstream fork metadata

Legacy v1 inputs stay exact and unchanged behind adapters. Compatibility is
explicit per component and fails closed; the aggregate version never silently
coerces a legacy or future component.

Downstream metadata binds upstream version/commit/tree digest, downstream
distribution/fork identity, divergence-ledger digest, allowed overlay classes,
forbidden duplicate authorities, conformance versions, and sanitization. Raw
prompts, credentials, auth material, unrelated transcripts, and private
environment data are excluded. The envelope may describe an AOL candidate but
cannot claim AOL admission, joined execution, Assurance, economics, Home/Now
truth, release promotion, or product acceptance.
The duplicate-authority set is exactly capacity, assignment authority, and
acceptance. Downstream conformance versions are exact for runtime, event,
receipt, adapter, route identity, assignment authority, delegation, task
journal, and capacity authority.
The V1 overlay allowlist is exactly `client_adapter` and
`read_model_projection`; capacity, assignment-authority, and acceptance
semantics cannot enter through an overlay alias. The direct validator enforces
`foreground` process mode and only `unix_socket` or `loopback_http` endpoints,
independently of JSON Schema enforcement.
The upstream version, commit, and tree digest exactly match `source_identity`.

## Stable T021 semantic failure codes

The 22 independently recomputed valid-digest repairs fail with these stable
typed codes:

| Invariant | Failure code |
| --- | --- |
| authority issued by evaluation | `authority_issued_after_evaluation` |
| fallback bound to assignment and role | `preflight_fallback_ceiling_mismatch` |
| billing basis and provenance bound | `preflight_billing_identity_mismatch` |
| eligible preflight requires healthy runtime | `preflight_runtime_health_mismatch` |
| capacity domain selects its required adapter kind | `capacity_domain_kind_mismatch` |
| adapter identities are globally unique in the envelope | `capacity_adapter_id_duplicate` |
| child identity is structurally acyclic | `delegation_identity_cycle` |
| child journal author is materially admitted | `journal_child_not_materially_admitted` |
| child TTL ceiling | `journal_child_ttl_exceeded` |
| child message-byte ceiling | `journal_child_message_size_exceeded` |
| child per-lineage journal-count ceiling | `journal_child_count_exceeded` |
| credential-like content is redacted | `journal_credential_redaction_required` |
| journal time is authority/evaluation valid | `journal_time_outside_authority` |
| denied parent has no admitted/full lifecycle materialization | `denied_run_materialization_mismatch` |
| recovery identities are acyclic | `recovery_identity_cycle` |
| root predecessor semantics | `lineage_predecessor_mismatch` |
| unique event identities | `event_id_duplicate` |
| monotonic event time | `event_timestamp_regression` |
| closed portable lifecycle event type | `event_type_unsupported` |
| successful usage stays within authority | `usage_authority_limit_exceeded` |
| downstream upstream identity matches source | `downstream_source_identity_mismatch` |
| effective run recall governs later lifecycle | `run_recall_lifecycle_violation` |

## Stable T024 boundary-repair failure codes

The 25 T023 repair fixtures retain the prior 97 cases and fail with these
stable typed mappings:

| Invariant | Failure code |
| --- | --- |
| assignment scope is relative to runtime workspace identity | `authority_scope_path_outside_workspace` |
| unknown billing basis, provenance, or gate denies success | `billing_identity_unknown` |
| run events remain inside evaluated authority time | `event_time_outside_authority` |
| terminal event occurs exactly once at the legal lifecycle boundary | `event_terminal_legality_invalid` |
| route service reference contains no credential | `route_service_reference_credential` |
| authority expected artifact contains no credential | `authority_expected_artifact_credential` |
| artifact receipt export contains no credential | `artifact_receipt_reference_credential` |
| delegation disclosure contains no credential | `delegation_disclosure_reference_credential` |
| journal artifact reference contains no credential | `journal_artifact_reference_credential` |
| downstream identifier contains no credential | `downstream_identifier_credential` |
| recall identity is unique | `recall_id_duplicate` |
| recall event remains inside evaluated authority time | `recall_time_outside_authority` |
| runtime stays foreground | `runtime_process_mode_invalid` |
| runtime endpoint stays local | `runtime_endpoint_kind_invalid` |
| downstream overlay set is exact and non-authoritative | `downstream_overlay_set_invalid` |

## Stable T027 deep-binding failure codes

The 26 T026 repair fixtures retain the prior 122 cases and add these stable
typed mappings:

| Invariant | Failure code |
| --- | --- |
| integer primitives do not accept booleans | `integer_invalid` |
| timestamps use the exact portable seconds-only UTC profile | `timestamp_invalid` |
| workspace/source/scope domain is recomputed | `source_scope_digest_mismatch` |
| every assignment authority field is digest-bound | `authority_digest_mismatch` |
| containment evidence binds workspace and ordered scope | `scope_containment_binding_mismatch` |
| containment evidence mandates a fail-closed pre-effect gate | `scope_containment_evidence_invalid` |
| preflight binds exact qualification | `preflight_qualification_identity_mismatch` |
| terminal precedes earliest capability expiry | `terminal_after_capability_expiry` |
| read-only evidence cannot authorize write effects | `assignment_effect_level_insufficient` |
| read-only evidence cannot authorize write tools | `assignment_tool_level_insufficient` |
| zero external-cost budget rejects metered work | `metered_zero_cost_budget` |
| child validation policy binds parent authority | `child_validation_policy_mismatch` |
| child return schema binds parent authority | `child_return_schema_mismatch` |
| every operational/exportable string is credential-screened | `credential_material_detected` |
| supported transports remain endpoint-compatible and local | `runtime_transport_invalid` |
| duplicate JSON keys are rejected before construction | `duplicate_json_key` |

## Stable T029 final-binding repair failure codes

The 15 final-binding fixtures retain the prior 148 cases and add these stable
typed mappings:

| Invariant | Failure code |
| --- | --- |
| containment evidence digest is recomputed over its closed structured domain | `scope_containment_digest_mismatch` |
| scope rotation cannot reuse stale containment identities | `scope_containment_binding_mismatch` |
| authority rotation requires fresh preflight bindings | `preflight_authority_binding_mismatch` |
| effect-ready plan binds exact authority identity | `plan_authority_binding_mismatch` |
| completed execution binds exact effect-recheck identity | `execution_authority_binding_mismatch` |
| effect-time recheck cannot carry stale containment identity | `effect_recheck_binding_mismatch` |
| capability levels use the closed lattice | `capability_level_invalid` |
| unknown capability cannot meet an effect threshold | `assignment_effect_level_insufficient` |
| mutation modes use the closed set | `mutation_mode_invalid` |
| read-only mutation mode cannot authorize filesystem write | `mutation_mode_effect_mismatch` |
| numeric usage requires observed or estimated provenance | `numeric_usage_provenance_invalid` |
| numeric and unknown usage cannot be mixed | `usage_provenance_mixed` |
| percent-encoded credential material is screened | `credential_material_detected` |
| double-percent-encoded credential material is screened | `credential_material_detected` |
| containment effect-gate policy remains fail closed | `scope_containment_evidence_invalid` |

## Stable T034 effect-kernel repair failure codes

The 8 effect-kernel fixtures retain all prior 163 cases unchanged and add these
stable typed mappings:

| Invariant | Failure code |
| --- | --- |
| every closed containment field participates in its evidence digest | `scope_containment_digest_mismatch` |
| effect recheck cannot precede run creation | `effect_recheck_pre_run` |
| every requested true effect is covered exactly once | `effect_recheck_effect_uncovered` |
| receipts and effect boundaries are single use | `effect_recheck_receipt_reused` |
| receipts follow requested effect sequence | `effect_recheck_order_mismatch` |
| recheck is immediately before its effect boundary | `effect_recheck_stale` |
| receipt target identity matches authority | `effect_recheck_target_mismatch` |
| effect-boundary identity is independently digest bound | `effect_recheck_boundary_mismatch` |

## Deterministic validation

Run:

```sh
python3 -B plugins/codexmax-orchestrator/scripts/validate_standalone_runtime_contract.py \
  tests/fixtures/standalone-runtime-contract/valid-spine.json
```

The validator reads one regular JSON file, rejects aliases and malformed or
extra fields, rejects duplicate JSON keys before object construction, performs
structural and cross-component semantic checks, and
prints canonical JSON. Pass/fail output is evidence only and grants no runtime
authority.
