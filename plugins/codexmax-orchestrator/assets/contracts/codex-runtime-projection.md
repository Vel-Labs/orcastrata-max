# Codex Collaboration Runtime Projection

## Boundary

This contract applies only after Orcastrata has selected an eligible native
OpenAI route and before the Parent calls Codex `spawn_agent`. It projects the
semantic route decision into the collaboration runtime's `agent_type`, exact
model, reasoning effort, and history mode. It performs no spawn, provider call,
authentication, billing action, or acceptance decision.

Native Codex collaboration is not provider dispatch. Its runtime surface is
`codex_collaboration`; external OpenCode, Command Code, standalone CLI, and
connector work continues through the provider-dispatch contracts and receipts.

## Host-Ownership And Non-Interception Boundary

The Codex host owns `spawn_agent` and the native child runtime. Orcastrata does
not register model weights, replace a Codex model with an "Orcastrata model,"
or install a global pre-spawn hook. This projection is mandatory only when an
active Orcastrata Parent is preparing a native child. A Codex task or spawn
outside that governed path continues under the host's own defaults.

When Orcastrata owns a supported external adapter dispatch, it resolves and
binds the exact provider route before launching that adapter. This is stronger
dispatch ownership than the native Codex projection, but it applies only to a
configured, freshly qualified route within task authority. Provider-neutral
contracts, dormant bindings, and standalone schemas do not prove an installed
host package, authenticated provider, or live execution.

An arbitrary host that creates its own workers remains host-owned unless that
host explicitly integrates an Orcastrata package or dispatch boundary.

## Native Agent-Type Facts

| Native agent type | Model | Reasoning | Semantic roles allowed |
| --- | --- | --- | --- |
| `default` | inherited or explicit | inherited or explicit | planner, architect, worker, tester, documenter, auditor |
| `codex_planner` | `gpt-5.6-terra` | `high` | planner |
| `codex_integrator` | `gpt-5.6-sol` | `medium` | worker |
| `codex_architect` | `gpt-5.6-terra` | `xhigh` | planner, architect |
| `codex_auditor` | `gpt-5.6-terra` | `xhigh` | tester, auditor |
| `codex_luna_analyst` | `gpt-5.6-luna` | `medium` | tester, documenter, auditor |
| `spark_scout` | `gpt-5.3-codex-spark` | `low` | planner |
| `spark_test_triage` | `gpt-5.3-codex-spark` | `low` | tester |
| `spark_diff_reviewer` | `gpt-5.3-codex-spark` | `medium` | tester, auditor |
| `spark_doc_draft` | `gpt-5.3-codex-spark` | `low` | documenter |
| `spark_prompt_compressor` | `gpt-5.3-codex-spark` | `low` | documenter |

Fixed-role identities are runtime facts, not Orcastrata role policy. A matching
name does not authorize a fixed role when its model or effort conflicts with
the selected route. Runtime roles whose current host contract does not expose
an exact model are excluded from this projection; they cannot satisfy a special
route identity by name or reputation.

## Host Capability Packet

The Parent supplies a task-bound `host_snapshot` captured from the active
collaboration host. The snapshot is evidence, not a model preference. Its
bounded shape is:

```json
{
  "supported_pairs": [
    {"exact_model": "gpt-6-astra", "reasoning_effort": "high"}
  ],
  "role_capabilities": {
    "worker": [
      {"runtime_surface": "authorized_runtime", "model": "model-id", "reasoning_effort": "effort"}
    ]
  }
}
```

The projector requires `host_snapshot.supported_pairs` for a `ready` result.
An absent, empty, or non-matching catalog returns `resolution_need`. A malformed
catalog is an invalid packet. The projector does not fall back to a shipped
static model list. A catalog entry proves only that the active host reported the
pair for this packet; it does not prove spawn, installation, authentication, or
completion.

The Parent remains the source of the observed Parent identity. The packet uses
`parent_runtime` for that identity and records it separately from the selected
child model. If the active host does not report the Parent model or effort, the
receipt records `unknown`; it must not copy the child identity into the Parent
field. The source for the snapshot and Parent identity is the active
collaboration-tool metadata, not the selected route label.

To create a host-bound projection, the Parent reads the current collaboration
metadata and writes a task-local packet with the supported pairs and the
reported Parent identity. It preserves `unknown` when the host does not report
that identity. The Parent then runs:

```sh
python3 <plugin-root>/scripts/project_codex_runtime.py \
  <packet.json> --receipt <new-exclusive-receipt.json>
```

The receipt path must be a new exclusive path. This command proves only
host-metadata-to-projection validation. It does not spawn a child or prove an
installed host integration. The Parent records the actual child ID returned by
the collaboration runtime and runs the projector's finalize operation only
then. The task-local packet and receipt are retained as evidence for the
specific host observation.

## Projection Rules

1. Require a stable child task ID, one of the six Orcastrata semantic roles,
   `runtime_surface: codex_collaboration`, and a nonempty route-authority
   reference.
2. A special native route requires an exact supported model and reasoning
   effort. `unknown`, `task_selected`, or provider-default effort is unresolved
   and fails closed before spawn.
3. `default` may inherit only when no special route is required and the Parent
   model and effort are both exact. Record this as an explicit native-default
   decision with `selection_mode: inherited`.
4. A special route uses `default` with explicit model and reasoning overrides
   when the history projection permits overrides. Full-history inheritance is
   allowed only when the exact Parent model and effort already equal the route.
5. A fixed native role is allowed only when both its semantic-role allowlist and
   immutable model/effort exactly match the Orcastrata selection.
6. Any requested fixed-role conflict, semantic-role mismatch, or full-history
   model change returns `resolution_need` with one exact proposed projection.
   It never silently substitutes or inherits. An approved mapping change must
   carry a nonempty approval reference and an approval route-authority value
   that exactly equals the projected route authority.
7. Runtime fallback is `forbidden` for special routes and `not_applicable` for
   the ordinary native default. Any requested automatic fallback is rejected.
8. Projection never expands task authority. Model, effort, or `agent_type`
   selection grants no read, write, provider, board, or acceptance authority.

## Usage-Limit Rotation

Fallback inside one native spawn remains forbidden. Route rotation is a
separate Orcastrata decision. Every projection records
`route_rotation_policy: automatic_within_authority | forbidden`.

When Codex returns `usage_limit`, `quota_exhausted`, or `rate_limit` under
`automatic_within_authority`, finalize the failed attempt with the actual child
ID and return `rotation_required`. Preserve the failed route and model, set
`automatic_substitution: false`, and rerun semantic route resolution against
the remaining fresh eligible candidates. The newly selected model receives a
new task ID, projection, and receipt. No operator approval is needed when the
new route stays inside the existing task authority, billing, capability,
reasoning ceiling, and fallback policy.

An exact user-selected tool/model route, forbidden billing transition, unknown
identity, authority expansion, or exhausted eligible set does not rotate. It
returns `failed_no_rotation` or the existing approval preview.

## Durable Receipt

Every projected or approved native spawn is saved before dispatch as a unique
JSON receipt. It contains child task ID, semantic role, native agent type,
exact model, reasoning effort, inherited versus explicit selection, runtime
surface, fallback, route authority, route ID, special-route status, provider
dispatch status, projection status, and approval reference. It also preserves
requested versus effective agent type and history mode, plus
`runtime_child_id: null` with `runtime_child_id_status: pending_spawn`.

The receipt is a spawn projection, not proof that Codex created or completed a
child. After `spawn_agent` returns, the Parent passes the returned canonical
child ID to the projector's finalize operation. That operation accepts only a
ready, not-yet-dispatched native projection, changes the child-ID status to
`recorded` and dispatch status to `spawned`, and preserves
`provider_dispatch: false`. Save the finalized receipt at a new unique path; do
not overwrite the pre-spawn receipt. A missing or incomplete receipt blocks the
spawn.

There is no `auto` agent selector. The Parent must name `default` or one exact
fixed native type so the policy choice is durable and reviewable.

## Operator Advice

When a methodology recommends Luna, Sol, or Terra, Orcastrata must show the
actual projected Codex call. Warn that `default` without an explicit override
inherits the Parent and that fixed native roles select their own model. If the
runtime cannot express the intended binding under the requested history mode,
show the approval preview and stop.

## Optional Controller Execution Package

An opt-in `controller_execution` packet binds one controller, worker, and
reviewer role to a complete task scope. The packet contains `enabled: true`,
`scope` with `task_id`, `objective`, `allowed_files`, `validation` command
arrays, and `exclusions`, plus `roles.controller`, `roles.worker`, and
`roles.reviewer` with `runtime_surface`, exact `model`, and
`reasoning_effort` values. A role may include an exact runtime endpoint when
the caller has observed one. It also
requires `repair_authority: controller`, `final_acceptance_authority: parent`,
and `reporting: exceptions_and_final_only`.

When a resolver receipt is supplied, `role_preferences.controller` selects the
controller preference, `role_preferences.roles.worker` selects the worker, and
`role_preferences.roles.auditor` selects the reviewer. The six semantic roles
remain unchanged. Each compiled role retains selection mode, source, and
lifetime provenance. `exact` is required and returns `resolution_need` when
the selected runtime cannot support it. `prefer` changes a role only when its
own capability evidence supports the pair. `default` retains the caller's
role reference. Runtime surface is never inferred from a model name.

Each `codex_collaboration` role pair must appear in the current packet's
`host_snapshot.supported_pairs`. A non-native role pair must appear in
`host_snapshot.role_capabilities[role]` with the same runtime surface. A missing pair returns
`resolution_need` with `controller_execution_capability_unavailable` and no
dispatch. The package is copied into a ready receipt for later native child
dispatch. The receipt's top-level `role_preference` describes the controller;
worker and reviewer preferences remain on their package roles. It grants no board, provider, write, or acceptance authority.
Omission keeps the existing projection behavior and receipt shape. The
invoking chat remains the observed Parent identity; the package never rewrites
that identity or claims final acceptance. The projector binds
`scope.task_id` to `child_task_id` and binds the controller role to the actual
effective native model and effort. It emits bounded assignment text with the
complete scope, role references, reporting and authority boundaries, and a
fresh-review requirement. The Parent passes that text to the native host tool
and records the returned controller child ID. Scope is an instruction; actual enforcement depends on independently configured
host permissions; the projection grants no sandbox.
