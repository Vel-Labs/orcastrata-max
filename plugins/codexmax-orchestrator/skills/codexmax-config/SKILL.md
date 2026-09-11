---
name: codexmax-config
description: "Public Configure entry — Inspect, explain, or safely initialize an explicitly requested effective policy."
---

# Codexmax Config

Treat this skill as non-executing. Never dispatch a worker, call a provider,
install a package, mutate GoalBuddy, or claim acceptance while using it.

1. Read `../../assets/contracts/codexmax-config.md`.
2. When route configuration is involved, also read
   `../../assets/contracts/route-registry.md`.
   When adapter bindings are involved, also read
   `../../assets/contracts/adapter-registry.md`.
3. Resolve `<plugin-root>` with `<plugin-root> = Path(SKILL.md).parents[2]`.
4. Run `python3 <plugin-root>/scripts/resolve_codexmax_config.py <command>`.
5. Pass `--workspace-config` only for an explicitly selected file and
   `--repo-root` for repository discovery.
6. For scoped overrides, pass the override path plus its declared and active
   goal or checkpoint identity. Do not promote expired values.
7. Use `--json` when a machine-readable receipt is required.

## Natural Language Preference Compilation

When the operator expresses a natural-language role/model preference (e.g.,
"Use Luna for the worker role" or "Prefer DeepSeek for testing"), compile it
into the existing scoped configuration fields without inventing new APIs.

### Precedence Order

Effective leaves resolve in this order (lowest to highest precedence):

1. **User scope** — `--workspace-config` when explicitly supplied.
2. **Project scope** — `<repo-root>/codexmax.config.yaml` when present.
3. **Task scope** — active goal override, then active checkpoint override.
4. **Invocation scope** — current invocation operator override.
5. **Non-overridable constraints** — hard constraints from the package.

Precedence is user < project < task. Task/session or active goal/checkpoint
identity must survive resume. One-turn operator overrides are invocation-scoped
and do not persist beyond the current invocation. Project or user scope requires
an explicit request from the operator.

### PM as Invoking Host

The PM (Project Manager) is the invoking host. Worker model selection is a
preference, not an authority grant. A native work-role preference is stored in
the existing `role_preferences.roles.<role>` mapping with
`selection_mode`, `exact_model`, and `reasoning_effort`; the resolver preserves
its scope and provenance. Use `default` for no preference, `prefer` for an
eligible preference that may retain the existing route when unsupported, and
`exact` for a required model with no silent fallback.

Store the controller preference in the existing `role_preferences.controller`
mapping. Keep it separate from the six semantic task-priority roles. When
`controller_execution` is enabled, compile controller, worker, and auditor as
the reviewer reference from one resolver receipt. Preserve each preference's
source and lifetime. Use the caller's runtime surface for each role. Never infer
a provider from a model name.

For Claude session use, the invoking chat is the Parent/PM. Use the documented
Agent surface, session-only `--agents` configuration, and full model ID or
`inherit` as described at
https://code.claude.com/docs/en/sub-agents. These are usable only after current
host preflight exposes and authorizes them. Do not invent a Claude tool name,
worker API, model enum, runtime, or child-ID field. Missing or unsupported
Claude capability returns `resolution_need` or an explicit unsupported result
and does not substitute another route. Claude session use must not create a
persistent account or disruptive default. Configuration candidates do not prove
capability, authentication, billing, usage, cost, or readiness.

Headless route ordering remains separate. Requests for compatible headless
routes use `headless_dispatch.role_priorities.<role>.route_01..06`; those fields
do not select a native Codex child. For a native Codex child, pass the resolver JSON
receipt and the current goal/checkpoint context to the runtime projector:

```sh
python3 <plugin-root>/scripts/project_codex_runtime.py \
  <packet.json> --config-receipt <resolver-receipt.json> \
  --receipt <new-exclusive-receipt.json>
```

The PM remains the invoking host. An unavailable `exact_model` returns
`resolution_need`; it never silently selects another model. An unknown or unset
`reasoning_effort` means that no effort preference was requested.

The same resolver receipt may feed an opt-in `controller_execution` packet. The
projector binds the effective native controller identity to `selected_route`,
checks worker and reviewer capability evidence by runtime surface, and emits
bounded assignment text. The Parent passes that text to the native host tool
and records its child ID. Scope is an instruction; actual enforcement depends on independently
configured host permissions; the projection grants no sandbox. This packet is scoped to one complete task and keeps repair authority
with the controller while Parent retains final acceptance. It is an execution
projection, not a new role registry or a local-model dependency. Missing host
support returns `resolution_need` and does not fall back silently.

### Resolution Need on Unavailable Model

An exact unavailable model request must produce `resolution_need` during
routing preflight. The configuration resolver records preference and provenance;
it does not itself perform preflight or emit this runtime result. The active PM
must not substitute another model or route without explicit operator approval.

Supported commands are `show`, `roles`, `explain <leaf>`, `validate`, `init`,
`explicit-route preview`, and `adapter-binding onboard|add|update|remove`. Inspect the effective semantic-role
route order without dispatching:

```sh
python3 <plugin-root>/scripts/resolve_codexmax_config.py roles \
  --repo-root <absolute-repository-root>
```

The output lists Planner, Architect, Worker, Tester, Documenter, and Auditor
with their effective task profile and `route_01` through `route_06`, followed
by the effective provider, model, reasoning, enablement, evidence status, and
health catalog for every referenced route. To change
a repository's preference order, edit
`headless_dispatch.role_priorities.<role>.route_01..06` in its
`codexmax.config.yaml`, where `<role>` is one of those six lowercase semantic
roles. The numbered fields are ordered fallback preferences: the dispatcher
tries the first currently eligible route and advances only after a retryable,
bounded failure. They are not weights, round-robin slots, provider spreading,
or authorization to fan out.

Only the six numbered route slots are operator priority controls. The semantic
role's `task_profile` binding and shipped profile fields are policy-owned;
reject attempts to retarget a role, expand its admitted pool, or weaken its
capability floor.

The `roles` view proves only resolved configuration and provenance. A listed
route is not thereby eligible, healthy, authenticated, available, affordable,
or authorized. Fresh task-scoped profile, identity, capability, source,
billing, scope, independence, and authority preflight still decides dispatch
eligibility.

## Explicit Tool And Model Preview

When the operator says `Use model X through tool Y`, read
`../../assets/contracts/explicit-tool-model-routing.md`. Accept only the exact
public tools `OpenCode` and `Command Code`. Preserve the exact model text.
Run `explicit-route preview` with the current task ID and task-grant digest:

```sh
python3 <plugin-root>/scripts/resolve_codexmax_config.py explicit-route preview \
  --repo-root <absolute-repository-root> \
  --request 'Use deepseek/deepseek-v4-pro through Command Code.' \
  --task-id <task-id> \
  --task-grant-sha256 <sha256:task-grant-digest> --json
```

The command uses two fixed, bounded adapter-owned commands. OpenCode uses
`opencode providers list` and the non-refreshing generic command
`opencode models`. It strips ANSI output, requires a positive credential count,
and binds the requested provider through the exact `provider/model` token.
Command Code uses `commandcode status --json` and
`commandcode --list-models`. It validates the closed status shape and reads
exact model tokens from the first output column while ignoring bounded headers.
The probe does not log in, return credential-store paths or status identity
values, execute the task, grant authority, or save a preference. Treat a
missing session, exact-model mismatch, credential prompt, disabled or ambiguous
binding, malformed or oversized output, or probe error as a hard stop. Never
continue through another tool or model.

## Adapter Bindings

The `adapter_registry` branch selects only package-owned adapter types. Start
from a shipped binding, keep its route identity matched to the
route registry, use only an opaque `none`, `host_managed`, or
`external_profile` reference, and recompute the canonical reference/binding
digests after a permitted binding change. Never add argv, executable, URL,
module, environment, path, secret, or transport fields.

Native-only setup creates no configuration file. Runtime readiness must be observed in the current host.

```sh
python3 <plugin-root>/scripts/resolve_codexmax_config.py \
  adapter-binding onboard --repo-root <absolute-repository-root> \
  --native-only --json
```

Public V1 first-use setup offers only OpenCode, Command Code, or native-only.
The CLI keeps the closed compatibility names `opencode`, `claude`, `deepseek`,
`minimax`, and `grok`; names outside the public OpenCode and Command Code paths
create configured candidates only. They do not establish public support,
availability, billing authority, or readiness. The internal compatibility name
for the Command Code path is `deepseek`.

For the public external choices, pass `opencode`, `deepseek`, or both to one
preview:

```sh
python3 <plugin-root>/scripts/resolve_codexmax_config.py \
  adapter-binding onboard --repo-root <absolute-repository-root> \
  --account opencode --account deepseek --json
```

Review the preview. Add `--write-new` only with authority to create the absent
repository-root `codexmax.adapters.yaml`. The command creates all selected
bindings together and enables only their package-owned candidate routes. It
never overwrites. It does not authenticate, qualify, call, or authorize an
adapter. It also does not authorize sending task content or using an external
account, privacy terms, quota, or billing path. Use provider-owned sign-in and
fresh task-scoped preflight before use.
The user-facing name is OpenCode; internal compatibility IDs may retain older
model-specific names.

Resolved bindings remain `configured`, not `qualified`. Configuration must
leave certificate, preflight, capability, evaluation, binding-evidence, recall,
timestamps, and TTL null. It also preserves billing, usage, and cost as literal
`unknown`; it never resolves the opaque reference. Qualification is a separate,
fresh, action-authorized evidence flow with a maximum 300-second TTL. Stale,
expired, recalled, revoked, failed, unavailable, and `execution_unknown`
bindings are ineligible, and `execution_unknown` forbids automatic retry or
fallback.

Author a binding through the closed CLI instead of hand-copying route identity
or digest fields. The default is preview; add `--write-new` only to create the
named absent output:

```sh
python3 <plugin-root>/scripts/resolve_codexmax_config.py adapter-binding add \
  --output <absolute-existing-parent>/codexmax.adapters.yaml \
  --adapter-type commandcode --route worker_deepseek_v4_pro \
  --credential-kind host_managed --opaque-id commandcode-local \
  --enabled --concurrency-cap 1 --token-cap 1200 --json
```

Add derives the binding ID printed in the receipt. Pass that ID to update or
remove with both `--input <existing-snapshot>` and `--output <distinct-absent-
path>`. Update may change only `--enabled`/`--disabled`,
`--concurrency-cap`/`--clear-concurrency-cap`, and `--token-cap`. Changing
adapter, route, reference kind, or opaque ID requires explicit remove then add.
Use `--write-new` only after reviewing the preview. Mutable `--write` is
rejected. Every output must be a new dedicated `.yaml`, `.yml`, or `.json`
overlay in an existing canonical parent directory. Existing files, aliases,
hardlinks, special files, absent parents, observed input drift, observed output
fd/path drift, unrelated root branches, and package-default binding replacement
fail without a success receipt. Update and remove never replace, delete, or
mutate their input.

Public authoring is immutable candidate creation. It is safe against aliases,
hardlinks, malformed input, and observed accidental or cooperative concurrent
changes. It does not protect an operator-selected directory from a malicious
same-UID process with directory write access; portable Python/macOS has no
atomic verified-fd-to-destination replacement primitive. A successful receipt
proves only the verified filesystem state at its final check. Mutable
activation, replacement, deletion, or a current-pointer change requires a
separately authorized trusted host layer and is not performed by this CLI.

Compatibility is package-owned: native Codex adapters accept only Codex Worker
routes; Claude CLI accepts `worker_claude_sonnet_5` and
`worker_claude_code_sonnet_5`; Command Code accepts the
package `worker_deepseek_*` and `worker_commandcode_*` routes; MiniMax accepts
`worker_minimax_m3`; OpenCode accepts the internal
`worker_qwopus_opencode` compatibility route. A valid
authoring receipt proves only deterministic local configuration bytes with
status `configured`. It does not prove qualification, provider activity,
runtime capability, eligibility, or authority.

`init` is dry-run by default; use `--write` only when file creation is explicitly
requested. It never overwrites and never creates a parent directory.

Keep `token_limit: null` distinct from unknown usage. Null does not disable
turn, attempt, no-improvement, concurrency, authorization, or operator-stop
controls. Reject zero token limits, silent metered fallback, authorization
grants, acceptance transfer, and other hard-constraint weakening.

Schema-v1 and schema-v2 overlays migrate to schema 3 with an explicit receipt. Treat registry
identity and capabilities as evidence-owned. Configuration may disable or cap a
route, but it cannot self-attest health, availability, authentication, billing,
tools, local files, browser, web search, connectors, writes, or a replacement
model. The resolver does not select or dispatch a route.

When scheduler policy is requested, explain that `scheduler.activation` remains
`explicit_only`; configuration does not enqueue or admit work. Show the
artifact-only role task profiles, 60-second default/300-second maximum broker
TTL, hard lease/capacity/allowance/scope gates, and deterministic quality
policy. Distinguish ordered failover from the bounded soft-diversity tie-break:
Planner/Architect never move, and other roles may move one rank only after five
quality-accepted observations. Stop if the request would enable hedging, direct
provider repository writes, provider calls, or unknown-as-zero accounting.

## Loop Policy Inspection

When loop configuration is requested, read the workspace `_ops/loops/README.md`,
the selected `registry.yaml`, and the plugin loop registry/event contracts.
Use `$codexmax-orchestrator:codexmax-loop` and checked-in `loopctl.py` only for
`list`, `show`, `validate`, and `status` inspection or explicitly requested
match/dry-run/receipt verification. State the resolved registry identity,
lifecycle, trigger, contained scope, fixed action-profile IDs, budgets,
references, and current proof boundary.

Configuration can explain, validate, disable, or cap loop policy. It cannot
grant authority, bind an action, mutate GoalBuddy or WorkGraph, install a hook,
activate a schedule, deliver a notification, promote lifecycle, or claim
acceptance. A valid registry is local source policy only. Preserve unavailable,
stale, unbound, `not_run`, and `unknown` values rather than defaulting them to
healthy, executable, or active.
