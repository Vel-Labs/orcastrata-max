# Codexmax Configuration Contract

## Capability preferences

`capability_preferences` is a non-executing user preference layer. It contains
the six frozen lane profiles: `read`, `artifact`, `scoped_write`,
`implementation`, `tool_loop`, and `audit`.

Each lane contains one to six contiguous route slots and a positive
`user_concurrency_limit`. A layer may reorder or subset only the package-owned
compatible candidates for that lane. A layer may lower the user cap from five.
It cannot raise the cap, add a profile-external route, add a control route,
make an escalation-only route automatic, or release Qwopus.

The preference layer does not contain adapter code, transport settings,
qualification evidence, health, capability evidence, task grants, or
authority. Its receipt keeps qualification, capability grant, eligibility,
authority, provider call, execution, and acceptance false.

Effective runtime concurrency is not a configuration claim. The execution
policy computes the minimum of user, adapter, task, fleet, provider, and
runtime-host caps after exact qualification. Scoped-write task cap remains one.

## Boundary

`codexmax-config` is a standalone policy inspection surface. It resolves,
shows, explains, validates, and safely initializes configuration. It never
dispatches work, calls a provider, installs a package, mutates GoalBuddy, or
claims acceptance.

`explicit-route preview` is the narrow exception to static inspection. It runs
two fixed, bounded status and model-list commands against an already configured
OpenCode or Command Code installation. It accepts only a closed Command Code
active-session identity or exact OpenCode provider token, plus the exact model
token. It cannot log in, refresh or read
credentials, execute the requested task, grant authority, or persist a preference. Read
`explicit-tool-model-routing.md` for its fail-closed contract.

## Schema And Precedence

Schema version 3 is the exact shape in
`../templates/codexmax.config.yaml`. It adds the versioned route registry and
task profiles defined in the shipped template, plus mapping-only
`headless_dispatch` schema version 2 and `scheduler` schema version 1. Unknown fields, wrong types, and
unsupported YAML syntax fail closed. A partial override may omit fields.
Future Worker route keys are extensible only through the registry contract and
begin with unknown or unverified identity and capability state.

`headless_dispatch.role_priorities` and `scheduler.task_class_profiles` are the
data-driven semantic routing authority. Runtime task compilation and scheduler
validation consume these mappings. They do not keep a separate role-to-model
table. A semantic role never identifies a model.

An explicit schema-v1 or schema-v2 overlay is migrated deterministically before precedence
resolution. Legacy auxiliary `enabled` and `token_limit` values project to the
matching schema-v2 route entries and remain visible in a migration receipt.
Migration cannot add availability, capability, billing, authority, or
acceptance. Nested task-profile and role-priority schema-v1 mappings migrate by
adding only an empty `secondary_05` or `route_06` slot and recording it in the
migration receipt. Migration to schema 3 adds policy-owned artifact task
profiles and explicit-only scheduler defaults; it does not activate the
scheduler or authorize a call. Unsupported schema versions fail closed.

Effective leaves resolve in this order:

1. plugin defaults;
2. `--workspace-config` when explicitly supplied;
3. `<repo-root>/codexmax.config.yaml` when present;
4. `<repo-root>/codexmax.adapters.yaml` when present and not already selected
   explicitly as the workspace layer;
5. active goal override, then active checkpoint override;
6. current invocation operator override;
7. non-overridable constraints.

Every effective leaf has source, source path, and lifetime provenance. Goal and
checkpoint identity mismatches remain in history with an expiry reason and are
not effective. Operator overrides last for the current invocation.

## Safety

- `token_limit: null` means no configured cap; zero is invalid.
- Missing usage is `unknown`, never zero.
- A null token limit does not disable turn, attempt, no-improvement,
  concurrency, authorization, or operator-stop controls.
- `execution.max_write_workers` defaults to 1 and may not exceed the board hard
  ceiling of 2.
- Silent metered fallback, config-granted authorization, billing-policy
  weakening, acceptance transfer, and config-driven execution are forbidden.
- `hard_spend_limit_usd: null` does not authorize metered billing.
- Parent remains exact `gpt-5.6-sol`; the goal-lifetime Supervisor remains
  exact `gpt-5.6-terra` at `high`. Configuration cannot add a control route.
- Registry health and availability are not configuration facts. Model identity
  never implies local files, commands, browser, search, connectors, or writes.
- Command Code is a gateway identity, not a model identity. The shipped
  `worker_commandcode_claude_sonnet_5`, `worker_commandcode_minimax_m3`, and
  `worker_commandcode_grok_4_5` candidates retain exact underlying model slugs,
  unique route IDs, and the shared `commandcode_gateway` independence group.
  Separately
  configured Claude, MiniMax, and Grok candidates remain distinct.
- The default pools use policy-ordered exact routes. Luna is first for Planner,
  Architect, and ordinary Auditor work. Terra is explicit-only. The internal
  OpenCode compatibility route is
  historical reference-only, disabled, and absent from default pools.
- Configuration lists candidates only. A route remains unavailable until its
  exact provider/model/runtime passes fresh preflight and capability checks.
- Route `token_limit` defaults to null. A positive override is a cap, not route
  authority.
- `headless_dispatch.role_priorities` contains exactly `planner`, `architect`,
  `worker`, `tester`, `documenter`, and `auditor`. Each maps to an existing
  profile and contiguous `route_01` through `route_06` slots with a `none`
  suffix. Routes may only reorder or subset that profile; unknown, duplicate,
  control, and profile-external routes fail closed.
- Each semantic role's task-profile binding and every field of a shipped task
  profile are policy-owned. Configuration may reorder or subset only the
  role's existing route slots; it cannot retarget a role to a custom profile,
  expand a shipped pool, or weaken its capability floor.
- `registry_for_role(effective_config, role)` returns a validated copied
  registry with the role order applied. It never mutates config or executes.
- `scheduler.activation` remains `explicit_only`. Broker TTL defaults to 60
  seconds and may never exceed 300 seconds.
- Role order remains failover preference. Soft diversity is an eligible-route
  tie-breaker after five accepted quality observations, with maximum rank
  displacement one for Worker, Tester, Documenter, and Auditor and zero for
  Planner and Architect.
- Scheduler task-class profiles are policy-owned and artifact-only where
  applicable. Hedging and direct provider repository writes remain false.
- Admission independently enforces leases, concurrency, allowance, scope
  overlap, WorkGraph fencing, deterministic quality, and Supervisor bindings.

## Commands

Run the resolver at `<plugin-root>/scripts/resolve_codexmax_config.py`, with
`<plugin-root> = Path(SKILL.md).parents[2]`.

- `show` emits a stable human view; `show --json` emits the complete effective
  receipt.
- `explain <leaf>` emits the effective value and history.
- `validate` validates every selected layer without side effects.
- `roles` emits the effective six-role table plus a provider/model/reasoning
  catalog; `roles --json` emits the stable schema-v3 machine view. Both are
  non-executing.
- `init` is a dry run. `init --write` creates only an absent file whose parent
  already exists. Neither mode overwrites or creates parent directories.
- `adapter-binding onboard --native-only` proves that the embedded native
  defaults need no file and performs no write. Repeated `--account` selections
  from `opencode`, `claude`, `deepseek`, `minimax`, and `grok` preview one
  deterministic repository-root `codexmax.adapters.yaml`; `--write-new`
  creates it only when absent. The result can enable only its selected
  package-owned candidate routes. It remains configured, unauthenticated,
  unqualified, unauthorized, and not run.
- `adapter-binding add|update|remove` previews a deterministic dedicated
  adapter-only candidate at `--output`. `--write-new` creates only that absent
  path in an existing canonical parent directory. Add accepts a package-owned
  adapter type and compatible Worker route, opaque reference kind/ID, enabled
  state, optional concurrency cap, and positive token cap. Update and remove
  require an explicit `--input`, create a distinct absent output, and leave the
  input byte-identical. Update accepts only the derived binding ID and mutable
  enabled/concurrency/token fields; remove accepts only the derived binding ID.
  Identity changes require remove then add. Mutable `--write`, replacement,
  deletion, activation, and current-pointer changes are unsupported.
- `explicit-route preview` accepts the exact conversational form, task ID, and
  task-grant digest. It resolves one enabled configured binding, verifies the
  existing tool session and exact model through two fixed bounded commands, and
  emits a task-local non-authoritative selection. It never falls back or saves
  the pairing.

Machine-readable output is written to stdout and diagnostics to stderr. Exit
codes are 0 success, 2 invalid config, 3 unsafe override, 4 existing
destination, and 5 invocation or I/O error.

The accepted YAML subset supports nested mappings, comments, and null, boolean,
integer, floating-point, quoted-string, and plain-string scalars. It rejects
sequences, aliases, anchors, tags, merge keys, block scalars, duplicate keys,
tabs, and malformed indentation.

`show --json` includes complete leaf provenance, schema migration receipts, and
a route-registry receipt. `roles --json` is the compact semantic-role view.
Neither executes route selection, fresh preflight, scheduler admission,
dispatch, or provider work. Unknown usage and cost remain unknown.
