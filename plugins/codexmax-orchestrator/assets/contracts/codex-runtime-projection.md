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
   model change returns `approval_required` with one exact proposed projection.
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
