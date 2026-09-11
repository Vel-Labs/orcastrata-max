# Route Fabric Contract

`route_fabric.py` is a deterministic, local, advisory evidence layer. It does
not replace the route registry, provider-input contract, preflight broker,
scheduler, provider adapter, VisibleProviderReconciliation, dispatch ledger,
GoalBuddy, or the invoking Parent.

## Exact identity

Every route identity has exactly these keys:

`route_name`, `provider`, `exact_model`, `route_id`, `runtime`, `runtime_host`,
`reasoning`, `billing_basis`, `independence_group`, `adapter_id`, and
`adapter_sha256`.

Scheduler consumption compares all eleven fields at plan time and again under
the admission lock. `adapter_id` and `adapter_sha256` are evidence-owned
compiler outputs bound to the product dispatcher and resolver receipt; route
configuration and Worker prose cannot self-attest them. Any adapter ID or
digest drift rejects the advisory before selection or ledger mutation.

`model` and `billing` are rejected aliases. Provider prose can be compared to
transport identity to report a mismatch, but it can never establish identity.
Command Code is a gateway identity and is not interchangeable with the exact
underlying model. Its configured candidates use distinct route IDs and the
shared `commandcode_gateway` independence group; separately configured Claude,
MiniMax, and Grok candidates remain separate routes. Configuration is not
qualification and cannot establish availability or capability.

## Immutable evidence objects

`capability_card_v1` has exactly `artifact_type`, `registry_entry_sha256`,
`provider_input_contract_sha256`, `capabilities`, `scopes`, `limits`,
`identity_evidence`, `capability_evidence`, `observed_at`, `expires_at`, and
`card_sha256`. It is immutable observation only; it cannot qualify or authorize
a route. Its digest excludes only `card_sha256` and binds every other field.

`qualification_certificate_v1` binds the exact route identity and task profile
to `task_profile_sha256`, `provider_input_contract_sha256`, `issuer`,
`registry_entry_sha256`, `capability_card_sha256`, `preflight_sha256`,
`adapter_sha256`, `evaluation_manifest_sha256`, issuance/expiry timestamps,
`issuance_sha256`, and an initially empty recall-event list. Effective status is derived only in this
order: `recalled > expired > stale > active`. Active status is eligibility
evidence only and grants no dispatch, retry, fallback, mutation, or acceptance
authority. `issuance_sha256` is recomputed over every other immutable
certificate field. Issued certificates are immutable and are never reissued to
add recall IDs. A recall status requires a validated post-issuance hash chain
whose event subjects match the certificate or its route; the chain, not a
mutated certificate, is the recall evidence. A non-empty issued recall list is
accepted only when the supplied validated chain matches it exactly.

Recall events are append-only and hash chained. Each event has exactly
`subject_scope`, `subject_id`, `subject_sha256`, `reason_code`, `created_at`,
`authority_sha256`, `previous_event_sha256`, and `event_sha256`.

## Deterministic trajectory and decisions

`trajectory_signal_v1` binds assignment and attempt IDs, ledger sequence start
and end, ledger heads before and after, `policy_sha256`, bounded evidence
descriptors, tri-state signals including `execution_unknown`, and explicit
unknowns. Its `trajectory_sha256` is the canonical digest of all other fields.
Signals are derived only from bounded ledger/dispatch/quality/continuity facts;
provider prose and raw prompts/source/tool output are not inputs.
Omitted optional `execution_unknown` and `provider_unavailable` outcome facts
aggregate to `unknown`, never to false.

`route_fabric_decision_v1` includes the current route identity,
`current_certificate_sha256`, a null advisory `target_route_identity`, source
bindings, trajectory digest, one closed action, and `decision_sha256`. Retry,
fallback, dispatch, board mutation, and acceptance flags are always false. The
scheduler alone may re-resolve and admit a later route.
Any non-null target route in decision input is rejected; the fabric never
selects a replacement.

The scheduler-facing `RouteFabricSchedulerAdvisory v1` wrapper has exactly
`schema_version`, `artifact_type`, `decision`, `bindings`, and
`advisory_sha256`. Its bindings contain the assignment ID, validated envelope
digest, prior ledger head, and decision digest. The scheduler validates the
wrapper and decision again against the live envelope and ledger. `continue`
leaves normal scheduler eligibility and selection unchanged. `switch` only
excludes the bound current route; the scheduler still selects the next eligible
route. `clean_handoff`, `unavailable`, and `human_gate` are non-admission
outcomes. No advisory action can acquire a lease, retry, fallback, dispatch,
mutate a ledger, authorize, or accept work.

## Handoff and economics

`clean_handoff_v1` retains source bindings, accepted artifact descriptors,
attempted strategies, target route identity, named failures, and next proof.
Every bounded list uses closed code/digest descriptors; it rejects arbitrary
values plus credentials, raw prompts, raw source, raw tool output, raw
transcripts, provider reasoning, and stale narration. The handoff digest binds
the complete retained object.

`correction_economics_v1` is recommendation-only telemetry with separate
`attempt_count`, `correction_attempts`, `pm_correction_ms`, `elapsed_ms`, token
dimensions, cash effect, quality-receipt digests, explicit unknown paths, and
`economics_sha256`. Usage has exactly `input_tokens`, `output_tokens`,
`total_tokens`, and `cash_effect_usd`; each value is numeric or an unknown with
a reason. Unknown values are never zero-filled.

## Precedence and ownership

Malformed, duplicate-key, non-finite, contradictory, or tampered evidence
yields a typed validation failure and no action.
Authority, credential, billing, scope, identity, and terminal
`execution_unknown` evidence require a human gate. Budget pressure requires a
human gate; quality rejection cannot continue. External exhaustion and
validation/quality failure outrank candidate readiness. Context pressure emits a
clean handoff; bounded repeated failures may emit an advisory switch.

The fabric never selects, admits, launches, retries, falls back, authorizes,
mutates GoalBuddy, rewrites raw provider bytes, or accepts work. Existing
continuity remains canonical; its `candidate_ready` path is checked only after
external exhaustion and validation failure.

The default operator pools retain six route slots and exclude Sol/Terra Worker
routes from default Worker execution. OpenCode uses a historical internal
`Qwopus` compatibility identity and is
reference-only and disabled by default. Sage/API routing is not part of this
local fabric; any future service is a separately authorized, unlinkable,
shadow-only experiment.

## Digest and CLI rules

Digests are `sha256:<hex>` over UTF-8 canonical JSON using sorted keys, compact
separators, and no ASCII escaping. Digest-bearing objects exclude only their
own digest field. The strict CLI accepts one request object and returns one
JSON receipt with exit `2` on typed validation failure. It copies inputs and
never mutates the request payload.
