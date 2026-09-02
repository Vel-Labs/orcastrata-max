---
name: codexmax-route
description: "Advanced composable capability — Route work using access gates, role fit, healthy subscription capacity, correction cost, independence, and latency."
---

# Codexmax Route

Read `../../assets/contracts/route-registry.md` and
`../../assets/contracts/provider-task-input.md` before selecting a route. The
effective registry comes from the schema-v2 Codexmax configuration receipt.
Configuration-time order is a candidate order only; current availability,
health, authentication, source delivery, billing, token policy, and tools need
fresh run-scoped preflight.

For deterministic local resolution, construct a schema-v1 JSON packet and run:

```sh
python3 <plugin-root>/scripts/resolve_worker_route.py \
  --packet <route-resolution-packet.json>
```

The resolver has two distinct phases. Legacy `evidence` resolution is the
default and preserves the existing behavior: it resolves only from supplied
attempt evidence, including the historical missing-attempt receipt shape.
`pre_dispatch` is proactive: after the same hard gates, it may return
`status: dispatch_required` plus a fully preflight-bound `next_attempt` before
an attempt result exists. It still calls no provider. The command prints the
complete receipt, exits `0` for a selected Worker route, `dispatch_required`,
or required Parent control decision, `3` for a fail-closed unresolved route,
and `2` for malformed input. Preserve the packet and stdout receipt together;
neither proves that a provider call happened.

For an explicit `Use model X through tool Y` request, first read
`../../assets/contracts/explicit-tool-model-routing.md`. Require the complete
previewed `ExplicitToolModelSelection v1` and the matching
`task_grant_sha256`. Restrict the task profile, preflight map, and attempt map
to its one exact route. The resolver rejects a changed task, grant, model,
provider, runtime, route, billing path, selection digest, or fallback-bearing
profile before dispatch.

For scheduler-backed work, first require a compiled `DispatchTaskEnvelope v1`,
exact board/config/authority/WorkGraph/Supervisor bindings, an exact-key broker
observation, and a valid scheduler plan. Treat role priority as failover order.
Soft diversity only breaks ties among already eligible routes within the
one-rank displacement and five-quality-observation warmup; it never overrides a
hard gate. Admission must reserve route/provider/runtime-host, writer/scope,
independence, allowance, and optional token capacity in the locked ledger.

Use `schedule_headless_dispatch.py plan` for non-executing inspection. Do not
invoke `admit` or `run-one` without exact execution authority. If admitted,
`run-one` executes only the leased route; return retryable failure to the
scheduler for fresh admission instead of allowing dispatcher-owned fallback.
Require a deterministic quality receipt after transport success. Stop on
`execution_unknown`; it is not automatically retry-safe.

For an exact, already-authorized headless assignment, use the shipped runner
only after the assignment's source, profile, scope, billing, credential mechanism, network,
retention, identity, capability, health, freshness, and command preflight all
match. Inspect the concrete attempt without launching it:

```sh
python3 <plugin-root>/scripts/run_headless_provider_dispatch.py plan \
  --repo-root <absolute-repository-root> \
  --assignment <absolute-assignment-path>
```

Then run only within that exact authority:

```sh
python3 <plugin-root>/scripts/run_headless_provider_dispatch.py run \
  --repo-root <absolute-repository-root> \
  --assignment <absolute-assignment-path> \
  --allow-provider-call
```

Do not add `--allow-provider-call` for planning, infer it from configuration,
or use `run` after a mismatched or missing preflight. Simulated repository proof
uses the separately allowlisted fake-adapter flags defined by the package-local
`../../assets/contracts/headless-provider-dispatch.md`; it is not live
qualification.

For the installed, read-only operator journey, use
`scripts/run_task_scoped_provider_task.py`. Give it one exact model/tool
request, the repository workspace configuration, a bounded prompt,
`--read-scope .`, and `--allow-provider-call`. It derives the closed task grant
from that operator invocation. It composes the fixed session probe and the
`task_scoped_live` dispatcher. It does not accept transport details,
caller-supplied grant digests, or credentials. It never falls back.

Treat the named task profile as the accepted minimum requirement set. Packet
requirements may be equal or stricter, but must not remove required source
access, commands, writes, browser, search, connector, consequence, billing, or
independence constraints. Profile binding happens before route eligibility; a
`profile_requirement_weakened` error is a packet revision event, not permission
to try a more permissive secondary.

Apply route selection in this order:

1. authentication, source access, input delivery, scope, tool, and billing hard
   gates;
2. consequence and reliability floor;
3. healthy subscription capacity and role fit;
4. expected correction-adjusted cost;
5. provider diversity for Tester and Auditor;
6. latency.

Default hypotheses:

- Sol: Parent revision/final acceptance on the fixed control route; separate
  non-control Sol-high Planner/Architect and Sol-medium Worker candidates;
- Terra: fixed high-reasoning Supervisor control plus a distinct Terra-high
  Worker candidate;
- Luna or Spark: scouting, compression, test triage;
- Claude Sonnet: difficult implementation and synthesis, quota-conscious;
- Claude Opus: exceptional planning or review escalation;
- DeepSeek through CommandCode: high-volume bounded implementation;
- MiniMax Token Plan: PM, documentation, synthesis, inline review. New
  standalone dispatches use exact model `MiniMax-M3`, route id
  `standalone-minimax-m3`, and an explicit `--model MiniMax-M3`; never rely on
  the current CLI default;
- Qwopus/OpenCode: local functional testing and reproduction.

The fixed Parent is exact `gpt-5.6-sol`. The visible goal-lifetime Supervisor is
exact `gpt-5.6-terra` at `high`. Neither control route is a Worker fallback and
changing the Supervisor model requires Parent approval. Worker profiles name
one primary route and ordered secondaries. Unknown or unverified capability
never satisfies a requirement, and profile order never overrides a hard gate.
The shipped semantic defaults start Planner, Architect, and ordinary Auditor
work with Luna. The effective config owns the complete route order. Terra is
explicit-only and requires an exact operator selection or a closed escalation
reason bound to the task grant. These are candidates, not usage quotas;
fresh preflight may skip any incompatible route.

Provider is not role identity. Record route, runtime, billing basis, quota state,
and fallback. Never silently switch a subscription route to metered API billing.
MiniMax M2.7 is a historical or parent-approved explicit fallback, not a default
for new work. Preserve historical M2.7 receipts instead of relabeling them M3.

For a native OpenAI route, route selection is not complete until the
[Codex Collaboration Runtime Projection](../../assets/contracts/codex-runtime-projection.md)
binds it to the actual Codex `agent_type`, exact model, and reasoning effort.
`default` otherwise inherits the Parent; fixed native roles select their own
predefined identity. A conflict returns an approval preview or rejection, never
a silent substitution. This path is native Codex collaboration, not external
provider dispatch.

## Provider Input Capability Gate

Read `../../assets/contracts/provider-task-input.md` before dispatch. Record the
route's demonstrated `source_access`, the task's actual `input_delivery`, named
source categories, and whether commands are executable. Do not infer any of
these capabilities from provider name, model family, assigned role, or a prior
run. Missing capability is `unknown`, not an optimistic default.

Fail closed before dispatch when the task requires source-backed claims and any
of these is true:

- access is `unknown`, `unverified`, or incompatible with delivery;
- a path-only packet is assigned to an embedded-only route;
- a connector reference is assigned without demonstrated connector access;
- an embedded fact pack omits a required source category;
- required commands are not demonstrably executable.

When a route is embedded-only, deliver a contract-shaped embedded fact pack and
require the provider-neutral read receipt. Embedded delivery permits
`received_embedded` claims only; it never proves a local-file observation.
Source, tool, authentication, and billing access remain hard gates. Role-fit or
cost hypotheses never override a failed input-capability gate.

## Route Packet Fields

Every dispatched lane records:

- provider and exact model or `unknown`;
- route id and role id;
- runtime surface such as Codex Desktop, Codex CLI, CommandCode, local runner,
  or connector;
- reasoning level or provider equivalent when available;
- billing basis: native included, subscription, local compute, metered API, or
  `unknown`;
- quota state, token counts, elapsed runtime, and marginal cost, using
  `unknown` when not measurable;
- preferred route attempted, fallback route used, and failure reason when a
  requested route fails;
- declared source access, actual input delivery, named source categories,
  command executability, and compatibility-gate decision and reason;
- read scope, write scope, stop conditions, and artifact path.

## Failure Routing

- Authentication, authorization, tool absence, credential prompts, package
  installation needs, forbidden billing fallback, and out-of-scope writes are
  hard stops for that lane.
- Model start failure, rate limit, quota exhaustion, weak output, stale context,
  or failed validation are revision or reassignment events.
- A native `usage_limit`, `quota_exhausted`, or `rate_limit` result rotates
  automatically to the next fresh eligible model when the projection records
  `route_rotation_policy: automatic_within_authority`. Preserve the failed
  attempt, rerun Orcastrata route resolution, and create a new exact projection;
  do not let Codex silently substitute inside the failed spawn. Exact
  tool/model selections and authority or billing changes remain non-rotating.
- Use provider-diverse correction when the likely defect is reasoning,
  interpretation, or implementation quality.
- Use parent repair when integration requires global context, shared-file
  judgment, or an authority decision outside the Worker packet.
- Use `waiting_external` only when no approved local or provider route can
  proceed without human action, credentials, unavailable infrastructure, or an
  irreversible decision.

Do not rename a failed preferred route as if it succeeded. Preserve both the
attempted route and the actual route in the result artifact.

The registry and configuration validator remain static route-order proof. The
route resolver provides deterministic filtering, attempt preservation, circuit
breaking, no-improvement handling, and bounded automatic Worker failover over
supplied facts. It is not a live provider preflight or dispatch engine: do not
claim availability, execution, or cost merely because the local resolver
selected a route. Only the separately authorized headless runner crosses the
execution seam, and its returned manifest remains evidence for Supervisor
verification rather than acceptance.

The standalone scheduler is locally fake-qualified only. Do not claim live
authentication, CLI compatibility, quota, provider use, model spreading, cost,
or allowance. Direct provider repository writes and hedging remain disabled;
unknown remains unknown.
For explicit multi-model review, treat each exact model request as a separate
route assignment. Do not use the worker priority list as fan-out. Use the
adversarial fan-out controller when the operator provides a frozen candidate
and rubric. Preserve one evidence directory per lane and report missing or
rejected lanes without substituting another model.
