# Codexmax Route Registry Contract

## Boundary

The route registry is a versioned configuration and evidence schema. It records
fixed control identities, Worker route candidates, capability observations,
task requirements, ordered route preferences, and the provenance needed for a
later dispatch preflight. It does not call a provider, authenticate, select a
live route, dispatch work, or prove current availability.

Registry validation is fail closed. Historical evidence may prove an exact
identity or a bounded capability, but it never proves current health,
authentication, quota, billing eligibility, or source delivery. Those fields
remain `unknown` or `unverified` until a fresh run-scoped preflight records
them. Model identity alone never grants browser, web-search, connector,
command, local-file, or write access.

Schema-3 configuration also projects policy-owned scheduler task classes.
Planner and Architect are semantic roles resolved by effective policy. Worker,
Tester, Documenter, and Auditor scheduler
lanes use artifact-only profiles; they do not authorize provider mutation of
repository source.

For scheduler selection, semantic role order remains fallback order, not a
provider-share target. After at least five ledger-recorded `quality_accepted`
observations, soft diversity may move an already eligible Worker, Tester,
Documenter, or Auditor route by no more than one rank. Planner and Architect
displacement is zero. Capacity, authority, independence, scope, allowance,
quality, and exact-key preflight remain hard gates.

The preflight broker defaults to a 60-second TTL with a 300-second maximum. It
caches only exact route callability evidence, never credentials, task
authority, scope, source compatibility, capability, quota, billing permission,
or independence. A cache hit never proves scheduler admission.

An `ExplicitToolModelSelection v1` is a stricter task-local route constraint.
It binds one configured OpenCode or Command Code session observation to the
task, task-grant digest, effective config, adapter, binding, and exact route.
The resolver requires a single-route profile and forbids fallback. The
selection does not grant authority. See `explicit-tool-model-routing.md`.

Automatic Worker selection is the model-agnostic counterpart for ordinary
read-only work. It accepts no model or provider name from the operator. It
considers only enabled bindings for package-owned Command Code or OpenCode
Worker transports supported by the fixed session verifier. It orders those
bindings by the effective Worker role priority and package ordinal ranks, then
probes each exact configured model. A probe denial may advance to the next
candidate because no provider process started. After selection, the task has
one route and one provider-attempt budget; a started attempt never falls back.
The receipt records every considered candidate and separates configured,
probed, selected, called, completed, rejected, and usage states. This lane is
not global interception and does not replace native Worker execution.

## Versions

- Codexmax configuration schema: `3`.
- Route registry schema: `1`.
- Route entry schema: `1`.
- Task-profile schema: `2`.
- Headless-dispatch and role-priority schema: `2`.
- Capability-model and reasoning-policy schema: `2`.

Unsupported versions fail validation. Schema-v1 configuration overlays are
migrated deterministically to schema 3 before precedence resolution. The
migration retains the legacy `routing.auxiliary` values for read compatibility
and projects only `enabled` and `token_limit` into their registry routes.
Migration never promotes identity, capability, health, billing, authorization,
or acceptance. Nested schema-v1 profiles and role priorities gain only an
explicit empty sixth slot before validation.

## Provider-neutral capability ranks

`capability_model.reasoning.route_capability_policy` is package-owned. It binds
each Worker route identity to ordinal `cost_rank` and `effort_rank` values.
Provider and model names do not define cost, effort, authority, or quality.
Configuration cannot change the rank table or its route fingerprints.

Cost ranks are `0` for low or local cost, `1` for standard cost, and `2` for
elevated cost. Effort ranks are `0` for low, `1` for medium or provider default,
`2` for high, `3` for xhigh, `4` for max, and `5` for ultra. A native
`task_selected` route binds its effective effort to fresh preflight evidence.
The stored rank is its compatibility default, not proof of the dispatched
effort.

The safe Parent compatibility ceiling is cost rank `1` and effort rank `1`.
A schema-v1 packet that has no escalation fields receives only this ceiling. It
cannot request a higher rank. A schema-v2 packet can exceed its Parent ceiling
only with explicit operator approval, pre-escalation work evidence, and the
exact task-grant digest. The same gate applies to native and external routes.

Rank eligibility does not repair identity. A missing route policy, mismatched
fingerprint, incomplete callable identity, missing fresh preflight, or unknown
rank fails closed. Approval cannot repair an unknown route identity.

## Fixed Control Routes

| Registry key | Exact model | Reasoning | Authority | Automatic failover |
| --- | --- | --- | --- | --- |
| `parent_sol` | `unknown` until active host exposes identity | `unknown` until active host exposes identity | Parent-only acceptance | forbidden |
| `supervisor_terra_high` | `unknown` until active host exposes identity | `unknown` until active host exposes identity | one goal-lifetime visible Supervisor | forbidden; model change requires Parent decision |

Compatibility keys preserve role authority. They do not select or prove a model.
Explicit qualified model and reasoning preferences may change. The invoking host
supplies Parent identity. The Supervisor route is disabled by explicit escalation
policy and cannot be enabled by an overlay. Neither control route belongs in a
Worker task profile.

## Terra explicit escalation

`supervisor_terra_high`, `worker_terra_high`, and `worker_terra_medium` carry
`escalation_policy: explicit_only`. All three remain disabled for ordinary
selection. Resolution admits one only for an exact operator selection or a
closed explicit escalation reason bound to the task grant.

The Parent does not automatically use Terra-backed Planner, Architect, Auditor,
Tester, Worker, or Supervisor agent types while this guard is active.

## Initial Worker Candidates

Every row is a candidate, not a global ranking. `Current health` is deliberately
`unknown` for every route because T010 makes no provider call.

| Registry key | Exact callable identity | Bounded historical capability | Quota observability | Current health |
| --- | --- | --- | --- | --- |
| `worker_sol_high` | target model `gpt-5.6-sol`, route `codex-sol-high`, task-selected reasoning | unverified until fresh exact preflight; compatibility route name | `unknown` | `unknown` |
| `worker_sol_medium` | target model `gpt-5.6-sol`, route `codex-sol-medium`, task-selected reasoning | unverified until fresh exact preflight; compatibility route name | `unknown` | `unknown` |
| `worker_terra_high` | target model `gpt-5.6-terra`, route `codex-terra-high`, reasoning `high` | unverified until fresh exact preflight; non-control implementation lane | `unknown` | `unknown` |
| `worker_terra_medium` | model `gpt-5.6-terra`; callable route id remains `unknown` | prior Terra local-file/command evidence; medium reasoning remains a requested setting | `unknown` | `unknown` |
| `worker_luna_xhigh` | model `gpt-5.6-luna`, route `codex-luna` | historical local-file, command, and native-write observations are retained outside the package; the packaged CLI adapter is not freshly qualified | `unknown` | `unknown` |
| `worker_codex_spark` | model `gpt-5.3-codex-spark`, route `codex-spark` | prior read-only local-file and command evidence | `unknown` | `unknown` |
| `worker_claude_sonnet_5` | `unknown`; the product label has no exact callable repository evidence | `unknown` | `unknown` | `unknown` |
| `worker_deepseek_v4_pro` | `deepseek/deepseek-v4-pro`, route `commandcode-subscription-deepseek-v4-pro` | local reads observed; command execution is contradictory and remains `unknown` | `unknown` | `unknown` |
| `worker_deepseek_v4_flash` | `deepseek/deepseek-v4-flash`, route `commandcode-subscription-deepseek-v4-flash` | embedded-only result evidence; commands and writes are `no` | `unsupported` | `unknown` |
| `worker_minimax_m3` | `MiniMax-M3`, route `standalone-minimax-m3` | embedded-fact review, no local files or commands | `unknown` | `unknown` |
| `worker_minimax_m3_tool_loop` | `MiniMax-M3`, route `minimax-subscription-m3-tool-loop` | disabled adapter-owned JSON text file loop; production write unqualified; commands disabled | `unknown` | `unknown` |
| `worker_qwopus_opencode` | `qwopus36-35b-a3b-coder-mtp-q5_k_m`, route `qwopus-opencode-local` | accepted embedded audit envelope; OpenCode wrapper health is not current proof | `unknown` | `unknown` |

Historical evidence, including native write observations, remains in immutable RC7 and report archives. Shipped
defaults store `unknown` evidence locators and unverified or unknown status.
A later fresh preflight may produce a separate receipt and scoped overlay. A
durable historical path does not make `availability`, `health`, or
`authentication` current.

## Route Entry Shape

Each mapping under `route_registry.routes` has all of these fields:

- schema and identity: `route_schema_version`, `route_kind`,
  `candidate_label`, `provider`, `exact_model`, `route_id`, `runtime`, and
  `reasoning`;
- economics and live state: `billing_basis`, `token_limit`, `availability`,
  `health`, and `authentication`;
- evidence state: `identity_status`, `capability_status`,
  `identity_evidence`, `capability_evidence`, and `quota_observability`;
- source and tools: `source_access`, `input_delivery`,
  `commands_executable`, `local_file_access`, `browser_access`,
  `web_search_access`, `connector_access`, and `write_access`;
- routing metadata: `recommended_role`, `concurrency_limit`,
  `consequence_floor`, `independence_group`, and `enabled`.

`recommended_role` is a hypothesis and never changes the route's authority.
Provider identity and role identity remain separate. `token_limit` defaults to
`null`; null leaves turn, attempt, no-improvement, concurrency, authority, and
stop controls active.

Configuration may disable a known route, lower its concurrency, or set a
positive token cap. Configuration cannot self-attest or replace evidence-owned
identity, runtime, billing, health, authentication, capability, tool, access,
quota-observability, or authority fields. A future Worker route may be added only with unknown or
unverified callable identity and capability fields. Live discovery must produce
a separate receipt before those fields can satisfy dispatch.

`quota_observability` is `supported`, `unsupported`, or `unknown`. Missing
legacy full-registry rows normalize to `unknown`; configuration overlays cannot
alter this evidence-owned field. The only initially `unsupported` row is the
exact `worker_deepseek_v4_flash` identity shown above. Every other shipped,
legacy, future, or custom row is `unknown` unless separately qualified by a
later evidence-governed change.

## Capability Values

Source access and input delivery reuse the canonical enums in
`provider-task-input.md`. `commands_executable` is `yes`, `no`, or `unknown`.
The tool-specific fields are explicit because one tool never implies another:

- `local_file_access`: `read_only`, `read_write`, `none`, `unknown`, or
  `unverified`;
- `browser_access`, `web_search_access`, and `connector_access`: `yes`, `no`,
  `unknown`, or `unverified`;
- `write_access`: `scoped`, `none`, `unknown`, or `unverified`.

Unknown and unverified values never satisfy a required task capability. An
embedded-only route may support `received_embedded` claims but cannot claim it
read a named local path. Browser access does not imply web search, and either
does not imply network authority or citation handling.

## Capability composition and task authority

The adapter maximum is a package-owned potential ceiling. It is separate from
the route's observed capability fields and from task authority. The
`native_codex` maximum includes the declared local-read, scoped-write,
command, tool-loop, browser, connector, web-search, and artifact primitives.
This declaration is not a qualification record and does not prove that a host
can currently provide any primitive.

Fresh adapter proof and the task lease are intersected for each task. The
lease supplies the access mode and scope. `read_only` permits read tasks when
the adapter proof covers the task's required primitives. `scoped_write` also
requires an active lease, local read, scoped-write proof, and a non-empty
write scope. A model, route label, reasoning effort, or profile rank cannot
grant this authority. A stale, missing, or unknown proof fails closed.

Reasoning is selected compositionally from host-supported Sol and Luna efforts.
The task consequence floor chooses the minimum declared effort that meets the
floor. Reasoning selection affects quality settings only. It does not change
adapter maximum, task authority, qualification, or current availability.

The route fields `local_file_access` and `write_access` remain evidence
observations. They do not encode a permanent read-only policy for an adapter.
Historical native Luna write observations in route-fabric state are retained
for provenance, not as fresh proof for this packaged CLI adapter.

## Task Profiles

Task profiles express requirements and route order without assigning a provider
as a role. Each profile records:

- `profile_schema_version`;
- required source access, commands, write, browser, web-search, and connector
  capabilities;
- non-metered billing ceiling;
- consequence floor and independence requirement;
- one `primary_route` and ordered `secondary_01` through `secondary_05`.

Empty secondary positions use `none`. Populated positions are contiguous,
unique, reference Worker routes, and may not reference either control route.
The shipped profiles remain `bounded_implementation`, `fast_read_only`,
`deep_review`, `independent_test`, and `embedded_audit`. Semantic role policy
adds `sol_plan_architecture`, `semantic_worker_implementation`,
`semantic_independent_test`, and `semantic_embedded_audit` without weakening
the legacy profiles.

The unknown-identity historical Claude candidate remains for compatibility.
The native Claude Code candidate occupies the current profile slot. Its profile
position does not make unverified identity, health, authentication, or
capability eligible.

Command Code routes for Claude, MiniMax, and Grok are disabled compatibility
records. Current routing uses Claude Code, `mmx`, and Grok CLI respectively.
DeepSeek V4 Pro and Flash remain Command Code subscription routes. They share
provider-session authentication and provider concurrency. Exact model
entitlement, route capacity, identity, and capability remain per-model checks.

The package-owned `worker_commandcode_model` route is the generic Command Code
transport for a configured exact model. It keeps provider, runtime, billing,
and transport fixed while the binding supplies the exact model identity. An
explicit request may use this route for any model when the operator names
Command Code and the fresh session probe confirms the exact model. Automatic
selection never creates this route from the Command Code catalog. The route is
not permission to invent a model, endpoint, executable, or provider.

Luna is the default low-cost fallback after the task's preferred specialist.
This rule applies to substantial implementation, review, test, document, and
audit profiles. Read and artifact work prefers DeepSeek V4 Flash, then Luna,
MiniMax M3, and Spark. Substantial implementation prefers DeepSeek V4 Pro,
then Luna, then MiniMax where its capability is compatible. Grok uses one
model-parameterized adapter boundary; only the latest configured model appears
in current task profiles.

Luna remains a valid candidate for a scoped-write task when fresh adapter proof
and the task lease satisfy the capability intersection. A direct mutation task
without that proof and lease still fails closed. The Parent can continue to
select Luna for analysis, artifact, or implementation work according to the
task consequence floor and current preflight.

MiniMax has a provider and `mmx 1.0.16` runtime-host concurrency ceiling of
five. Each exact MiniMax route has a ceiling no greater than five. Concurrency
does not grant qualification, retry authority, or write authority.

## Operating tiers

Observational development permits bounded read-only or artifact-only provider
calls after provider-session authentication, exact model identity, declared
runtime isolation, and explicit turn and cost limits. It grants no repository
mutation or production authority.

Governed mutation and release additionally require an isolated worktree,
exact scope and task grant, protected credential delivery, durable evidence,
validation, and Parent acceptance. A possibly mutating or uncertain attempt is
never retried automatically.

Write-capable selection also follows `provider-scoped-work.md`. A route entry
states a capability ceiling only. A fresh capability card and one exact task
grant must intersect before the scheduler can admit `scoped_write`.

Flexible harness behavior follows `provider-flexible-execution.md`. Route
order and task-profile requirements remain the route-selection floor. The
`ParentTaskIntent` controls task-specific reasoning, verbosity, context, token,
turn, latency, and cost settings after route selection. These settings never
weaken a task-profile capability requirement or upgrade route authority.

A profile order is not an eligibility decision. The route runtime filters the primary
and each secondary through fresh source, input-delivery, tool, scope,
authority, billing, consequence, health, and independence gates. A route whose
registered or preflight capability is unknown is ineligible for that required
capability. If no route passes, resolution fails closed; it does not widen the
profile or choose a metered route.

The named profile is also an authoritative requirement floor, not merely a
route-order lookup. Before considering any preflight or attempt, the runtime
binds the packet to the profile's required source access, commands, writes,
browser, web search, connector, non-metered billing ceiling, consequence floor,
and independence requirement. It also derives `local_files: true` when the
profile requires `local_filesystem` access. The packet's provider-input
`commands_required` value must equal its capability requirement.

A packet may add stricter capability requirements, require a higher consequence
floor, narrow the non-metered billing allowlist, or add independence exclusions.
It may not turn a profile `true` requirement to false, remove the profile's
source mode, make a source-backed profile source-free, lower consequence, allow
metered billing, or disable required independence. Required independence needs
at least one excluded prior-work group and applies regardless of whether the
current role label is Worker, Tester, or Auditor. Any weakening raises
`profile_requirement_weakened` before route eligibility or attempts.

## Semantic Role Priorities

`headless_dispatch.role_priorities` defines exactly six mapping-only role
preferences. Every entry has schema version 2, one existing task profile, and
contiguous `route_01` through `route_06` slots with a `none` suffix.

| Role | Profile | Shipped order |
| --- | --- | --- |
| `planner` | `sol_plan_architecture` | Luna, Sol, DeepSeek Pro, MiniMax-M3, Claude, explicit Terra |
| `architect` | `sol_plan_architecture` | Luna, Sol, DeepSeek Pro, MiniMax-M3, Claude, explicit Terra |
| `worker` | `semantic_worker_implementation` | DeepSeek Pro, Luna, MiniMax tool loop, Claude, Grok, Spark |
| `tester` | `semantic_independent_test` | DeepSeek Pro, Luna, MiniMax-M3, Claude, Grok, Spark |
| `documenter` | `fast_read_only` | DeepSeek Flash, Luna, MiniMax-M3, Spark, Claude, Grok |
| `auditor` | `semantic_embedded_audit` | Luna, DeepSeek Pro, MiniMax-M3, Claude, Grok, explicit Terra |

A role may only reorder or subset routes already present in its profile. It
cannot add unknown, duplicate, control, or profile-external routes and cannot
weaken any profile gate. Consumers call
`registry_for_role(effective_config, role)` for a validated copied registry and
use the role entry's `task_profile`; the helper performs no dispatch.
Planner and Architect therefore fail closed when no policy-selected lane is
freshly eligible. MiniMax-M3's
Worker position does not bypass its current embedded-only, no-command, no-write
capability evidence, and DeepSeek Pro's Auditor position must independently
prove compatible embedded-fact delivery.

The six semantic role-to-profile bindings and all shipped profile fields are
policy-owned. A configuration layer may add a custom profile for a separate
direct resolver use, but it cannot retarget a semantic role to that profile or
mutate a shipped profile. Operator customization is limited to contiguous
reordering or subsetting of the routes already admitted by the bound profile.

## Capability Candidate Projection

Before runtime resolution, `resolve_capability_candidates` can apply the
validated user lane order to a supplied set of currently qualified routes. It
returns only the intersection of:

- the frozen lane primitive requirements;
- package-owned adapter and route compatibility;
- supplied current qualification identities;
- the user order and subset.

The helper rejects a qualification route that is not compatible with the
lane. It performs no preflight, provider call, dispatch, or scheduling. Its
receipt keeps eligibility, authority, execution, and acceptance false. The
existing route resolver remains the later fresh-preflight and task-scope gate.

## Runtime Resolution and Failover

`scripts/resolve_worker_route.py` consumes a deterministic JSON packet and
emits a route-resolution receipt. It performs no provider, network,
authentication, credential, or billing call. Callers must supply a fresh,
task-scoped preflight for each candidate they want considered and must preserve
the durable preflight evidence separately.

Freshness is deterministic rather than host-clock implicit. The packet carries
an ISO-8601 UTC `resolution_time`; every preflight carries `observed_at` and
`expires_at`. A preflight observed after resolution, expired before resolution,
or using an invalid window is ineligible. `fresh: true` alone is insufficient.

The runtime considers the profile primary and populated secondaries in their
declared order. A candidate is eligible only when all of these are true:

- the route is an enabled Worker route and its fresh preflight establishes the
  exact callable provider, model, route, runtime, reasoning, and billing identity;
- availability, health, authentication, quota, identity, and capability are
  current and demonstrated, with named evidence and no credential access;
- the canonical provider-input gate accepts the route's demonstrated source
  access and the task's actual input delivery;
- required commands, local files, writes, browser, web search, connector,
  network authority, and citation support are explicitly demonstrated;
- read scope, write scope, and authority scope match the task packet exactly;
- billing remains in the packet's explicit non-metered allowlist,
  `token_limit` remains equal to the task policy, and the consequence floor is
  not downgraded;
- a Tester or Auditor route does not share an excluded independence group.

An unknown or mismatched field makes that candidate ineligible; it is never
filled from provider reputation or profile position. `resolution_phase`
defaults to `evidence`, where an eligible route requires a supplied attempt and
missing facts preserve the existing missing-attempt receipt exactly.

One narrow exception exists for a provider that has no authoritative quota
probe: quota may remain literal `unknown` only when the immutable registry row
is exact `worker_deepseek_v4_flash` with `quota_observability: unsupported`, the
provider/model/route/runtime/subscription identity matches exactly,
`allowed_billing` is exactly `[subscription]`, `resolution_phase` is
`pre_dispatch`, the selected profile contains exactly that one route, and all
checkpoint, route, circuit, and no-improvement ceilings equal one. Unknown or
metered billing remains ineligible. A provider refusal or quota error consumes
the single attempt and is terminal; retry, fallback, substitution, and hedging
remain forbidden.

In `pre_dispatch`, supplied retry, hard-stop, success, circuit, and budget facts
are processed identically. The first eligible bounded attempt lacking a result
returns `status: dispatch_required` and `next_attempt` with global
`attempt_index`, per-route `route_attempt_index`, `route_name`, and the complete
preflight-bound `identity`. It calls nothing: `selected_route` remains null and
`external_call_performed` remains false. An untripped retry can name the same
route again; an opened circuit advances to the next eligible route.

Automatic Worker failover is bounded by the packet's per-route and checkpoint
attempt ceilings, each no greater than the repository ceiling of three.
Consecutive failures open the route circuit at the declared threshold, and a
separate no-improvement window opens it when repeated attempts do not improve.
Model-start failure, rate limit, quota exhaustion, provider failure, stale
context, weak output, failed validation, and no improvement may advance to the
next fully compatible route. Credential prompts, billing violations, source or
scope violations, and authority violations are hard stops and do not trigger
automatic fallback.

The receipt records ordered candidates, every eligibility decision, every
attempt, the first preferred-route failure, the selected actual route, and
explicit tokens, quota, cost, and elapsed time. Missing accounting is an
object with `value: unknown` and a reason. Failed preferred attempts are copied
verbatim into `failed_preferred_route`; they are not rewritten as a successful
secondary. `external_call_performed` is always `false` for this deterministic
runtime.

Pre-dispatch receipts add `resolution_phase: pre_dispatch` and `next_attempt`
(null after terminal success, hard stop, or exhaustion). Evidence receipt shape
is unchanged even when `resolution_phase: evidence` is explicit. CLI exit 0
includes `dispatch_required` as well as selected and control-decision receipts.

Parent and Supervisor routes never enter Worker resolution. A recorded control
route failure returns `parent_decision_required` with
`automatic_control_route_failover_forbidden`; neither exact control identity is
silently replaced.

## Provenance

Every registry leaf participates in normal Codexmax precedence and receives a
source, source path, lifetime, active state, and effective-state history. The
resolver also emits:

- `migrations`: every schema-v1-to-v2 projection and mapped field;
- `route_registry_receipt`: registry and task-profile counts, fresh-preflight
  requirement, current health `unknown`, no configuration availability claim,
  and `selection_executed: false`.

The receipt is configuration proof only. It is not a route attempt, health
receipt, input-access receipt, failover receipt, or dispatch receipt.

## Codex Collaboration Projection

An eligible native OpenAI route is still not a Codex child binding. Before
`spawn_agent`, apply the
[Codex Collaboration Runtime Projection](codex-runtime-projection.md) and save
its complete receipt. The projection binds the semantic role to an allowed
native `agent_type`, exact model, reasoning effort, history mode, fallback, and
route authority. A fixed native role whose immutable model conflicts with the
selected route fails closed. A configurable `default` agent may inherit only
for the explicitly recorded ordinary native default or when its exact Parent
identity matches the selected special route.

This projection is a native collaboration control and records
`provider_dispatch: false`. External provider dispatch continues through the
headless dispatcher and must not reuse a native collaboration receipt as
provider-execution proof.

## Fail-Closed Validation

Validation rejects:

- unsupported config, registry, route, or profile versions;
- unknown fields, wrong types, invalid enums, or incomplete full entries;
- changed Parent or Supervisor identity, Supervisor reasoning, or control
  authority;
- control routes inside Worker profiles or configuration-added control routes;
- unknown, duplicate, or non-contiguous task-profile route positions;
- missing or extra semantic roles, bad role schema versions, and unknown,
  duplicate, control, non-contiguous, or profile-external role routes;
- metered billing ceilings or silent metered fallback;
- zero or negative token limits or concurrency;
- a proven identity/capability status without named evidence;
- configuration attempts to claim availability, health, authentication,
  identity, billing, source, tool, browser, search, connector, or write access;
- a future route that starts with anything stronger than unknown or unverified
  callable/capability state.

The configuration resolver remains inspection-only. The route runtime owns
deterministic primary/secondary resolution, attempt preservation, circuit
breaking, and bounded failover over supplied fresh-preflight and attempt facts.
It does not itself establish provider availability or dispatch work.
