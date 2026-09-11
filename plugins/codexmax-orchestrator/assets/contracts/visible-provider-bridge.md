# Visible Provider Bridge Contract

`VisibleProviderTaskState v1` is a deterministic, non-executing composition
layer. It truthfully separates the native Codex Desktop host, visible task,
semantic role, external provider execution, and invoking Parent decision. An
external provider is never described as the native model behind a Codex task.

## Compilation boundary

`visible_provider_bridge.py` accepts one strict assignment plus a separately
supplied trusted authority record. The assignment's authority self-attestation
is insufficient: both exact records and their valid canonical digests must
match or compilation fails `authority_unproven`. The CLI therefore requires
both `--assignment` and `--trusted-authority`.

The trusted authority record is Parent-derived input from the active goal's
approved authority boundary. It must be supplied independently of the worker
assignment; a worker-produced record or digest is not trusted provenance. The
Parent also supplies the current live-concurrency observation used to enforce
the authority's exact concurrency ceiling. Neither field may be inferred from
provider output or task labels.

The trusted authority route and its canonical digest bind the registry-owned
`quota_observability` capability. Assignment packets and preflight self-report
cannot promote or alter it. Missing legacy or custom capability values remain
`unknown` and do not gain the exception below.

The bridge calls the existing route resolver in `pre_dispatch` mode. Exactly
one current preflight must bind the requested route. The bridge itself parses
`resolution_time`, `observed_at`, and `expires_at` as UTC timestamps and
requires `observed_at <= resolution_time < expires_at`; it does not rely only
on imported resolver behavior for currentness. Billing is subscription-only,
external write access and credential action are forbidden, and resolver
controls permit one attempt with no retry, fallback, or hedging.

Quota normally must be `available`. Literal `unknown` is accepted only for the
exact `worker_deepseek_v4_flash` route whose immutable capability is
`quota_observability: unsupported`, with exact Command Code subscription
identity, `allowed_billing: [subscription]`, one profile route, and every
attempt/circuit/no-improvement ceiling equal to one. Unknown or metered billing
is never admitted. A provider refusal remains terminal with no retry or
fallback.

The locally composable routes are `worker_deepseek_v4_flash`,
`worker_deepseek_v4_pro`, and `worker_minimax_m3`. Claude Sonnet and Grok fail
closed until separate qualification freezes their exact registry, adapter,
identity, billing, capability, and current-preflight tuples.

The output contains a Spark-medium Codex Desktop presentation request with
`host_action_performed: false`. It does not create, open, message, read, or
archive a task and proves no sidebar behavior. It names the existing scheduler,
binder, runner, quality, and manifest artifact chain that must execute later;
it does not reproduce those responsibilities.

The presentation request binds `request_id`, `requested_by`, `requested_at`,
`assignment_id`, `dispatch_id`, and `semantic_role`. Provenance records a
Parent request only; it never upgrades `host_action_performed` or claims the
Desktop acted.

## Reconciliation boundary

`reconcile_visible_provider_result.py` consumes the immutable task state, a
digest-valid `DispatchScheduleManifest`, the existing runner's
`DispatchReturnManifest`, and a deterministic `ArtifactQualityReceipt`. It
requires exact goal, task, assignment, dispatch, semantic-role, provider,
model, route, runtime, and reasoning identity; at most one attempt; no fallback
or retry; no Supervisor or GoalBuddy application; and literal unknown
accounting. A successful return and its quality receipt must each carry a
non-null artifact descriptor with the same path, SHA-256, and byte size. The
quality receipt's expected descriptor must match too. Raw-byte validation
remains the responsibility of the existing artifact validator, and the raw
provider return plus that validator's immutable evidence must be retained. A
selected successful return is rejected unless `external_call_performed` is
exactly `true`; synthetic transport or artifact evidence cannot become a Sol
review candidate.

The real scheduler manifest keeps the legacy goal/checkpoint/task/assignment
`identity` exact and adds a digest-bound `visible_identity` containing
`dispatch_id` and `semantic_role` derived from the verified immutable return
manifest. Runner descriptors may use the canonical
`sha256:` prefix while the artifact validator uses raw hexadecimal; the
reconciler normalizes that representation only after validating its shape.
Paths, byte counts, and digest values must still match exactly.

`finalize_visible_provider_dispatch.py` closes the no-call evidence gap after
one already-completed live attempt. It accepts only `proof_mode: live`, exactly
one selected route and attempt, `external_call_performed: true`, no fallback,
and mutually consistent task/admission/envelope/assignment/binding/ledger/
return/event/artifact bytes. It calls the existing deterministic artifact
validator, emits three new immutable receipt files, and is idempotent only when
all existing output bytes are exact. Partial or changed output paths are
collisions. The finalizer never imports or invokes the provider runner and
cannot perform a retry, provider call, Supervisor write, GoalBuddy write, or
Sol decision.

The result is either `terminal_dispatch_failure`, the distinct terminal
`terminal_execution_unknown`, deterministic quality rejection, or
`candidate_ready_for_sol_review`. `execution_unknown` is never collapsed into
provider failure, and both terminal classes expose `retry_allowed: false` plus
typed diagnostics. Every outcome keeps
`sol_decision: pending` and `accepted: false`. Only the invoking Parent may accept,
reject, request repair, mutate GoalBuddy, or authorize a native writer.

`sol_decision` is a legacy field name. It does not select a Parent model; the
invoking chat retains acceptance authority.

## Proof boundary

Tests use injected dictionaries and fake evidence only. This contract proves
local compilation and reconciliation, not provider authentication, quota,
billing, network execution, Codex Desktop task creation, sidebar visibility,
installation, external native-model hosting, or product completion.
`host_action_performed: true` may be recorded only from real Codex Desktop host
evidence after the host action occurs. Local compilation, tests, or operator
labels cannot set it. Local validation also proves neither live provider use
nor invoking Parent acceptance.
