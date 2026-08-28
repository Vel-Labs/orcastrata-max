# Headless Provider Dispatch Contract

## Boundary

`run_headless_provider_dispatch.py` is an additive execution seam between the
deterministic Codexmax route resolver and a bounded provider CLI. It does not
own GoalBuddy, Supervisor state, acceptance, provider credentials, or billing
authority. `plan` is read-only and never starts a process. `run` emits a
`DispatchReturnManifest` and an unapplied Supervisor event bundle.

Version 1 resolves one eligible route and permits exactly one provider attempt
for one assignment. Provider or validation failure is terminal for that
dispatch: there is no retry, fallback, substitution, hedging, fanout, or load
balancing.

`isolated_development_live_write` is a separate task-scoped development lane.
It is not `task_scoped_live`, protected `live`, shared-tree, production, or
T062 authority. It requires one exact configured Command Code model, one
separate linked Git worktree, one existing regular-file target, one complete
guarded write grant, one provider attempt, and exact change reconciliation.

Scheduler mode uses the additive `run-one` command. It requires a compiled
`DispatchTaskEnvelope v1` and current scheduler lease binding, restricts the
configured scheduler role profile to the exact leased route, and executes at
most that one attempt. Neither `run` nor `run-one` tries another route after any
transport, schema, or identity failure.

When a route packet contains `ExplicitToolModelSelection v1`, the complete
selection is inside the resolver-packet digest. The candidate compiler carries
the complete selection and digest. The scheduler revalidates the task-bound
resolver packet and requires its single selected route. `run-one` revalidates
the selection, task grant, exact route identity, adapter, and model argv before
process start. It uses the existing exact-model adapter argv and lease. It does
not authenticate, select a second route, or create another execution adapter.
Read and write behavior still comes only from the task envelope and task grant.

## Assignment

The strict JSON assignment has `schema_version: 1`, stable dispatch and
Supervisor assignment/lane IDs, an explicit six-value `semantic_role`, a
literal `prompt`, canonical repository-relative `working_directory`,
`expected_artifact`, and `evidence_directory`, `proof_mode` (`simulated`,
`task_scoped_live`, `isolated_development_live_write`, or `live`), a strict `response_schema`, an explicit dispatcher-owned
`dispatch_output_scope`, explicit authority facts, and a normal route packet. The dispatcher
loads layered Codexmax configuration, calls the public `registry_for_role`
helper, replaces the packet profile with the configured semantic-role profile,
and requests `resolution_phase: pre_dispatch` from the route resolver. Semantic
Planner, Architect, and Documenter assignments use resolver role `worker`;
Worker, Tester, and Auditor use their corresponding resolver roles. Any
semantic/resolver role mismatch fails before resolution.

`task_scoped_live` is the standalone read-only provider lane. It requires all
six assignment authority facts plus the explicit `--allow-provider-call`
switch. It rejects a scoped-write execution profile before process start. It
uses the same one-attempt, response-identity, output-limit, timeout, no-fallback,
and retained-evidence rules as other dispatches. It does not use or claim the
enterprise protected receiver. The `live` mode remains the protected receiver
lane.

Use `scripts/run_task_scoped_provider_write.py` for the installed development
write canary. The command accepts no executable, argv, endpoint, credential,
caller grant, callback, or replacement content. It derives deterministic
canary bytes from the task ID and bounded prompt digest. Evidence and the
result artifact stay in a sibling directory outside the worktree. The guarded
read-write-read sequence may change only the exact target. The receipt always
starts with `accepted_by_parent: false` and retains exact rollback bytes.
The operator must create the linked worktree before the V1 runner starts.
The runner does not create or delete that worktree. A failed or uncertain
attempt retains its control files for forensic review. A new task requires a
fresh linked worktree and fresh evidence paths.

Use `scripts/run_task_scoped_provider_task.py` for the installed operator
journey. The command requires `--workspace-config`, `--read-scope .`, and
`--allow-provider-call`. It derives the task grant from the exact request,
prompt digest, canonical repository root, repository-root read scope, output
paths, subscription billing, and the explicit call flag. It does not accept a
caller-supplied task-grant digest. Resolve the workspace configuration before
assignment construction. Use the same effective configuration for dispatch.

Scheduler Worker artifacts use `semantic_worker_artifact`, whose shipped route
order contains only embedded-capable Flash, MiniMax, and Qwopus routes. The
profile requires `embedded_only` delivery and forbids local-file access,
commands, and provider writes. A selected route outside that profile, or local
work bound to it, returns `profile_incompatible` before transport rather than
widening the profile or substituting another route.

The authority object declares these booleans exactly once:

- `provider_call_authorized`;
- `network_authorized`;
- `billing_authorized`;
- `credential_mechanism_authorized`;
- `scope_authorized`; and
- `retention_authorized`.

Configuration, executable presence, a registry identity, or prior success
never supplies a missing authority fact.

`response_schema` is a bounded, locally validated JSON Schema subset. The root
must be an object with `additionalProperties: false`. It must require a strict
`route_identity` object containing exactly `declared_route`, `actual_provider`,
`actual_model`, `fallback_used`, and `retry_count`. The dispatcher binds the
expected route name, provider, and model from the selected preflight before
transport; requires `fallback_used: false` and `retry_count: 0`; and appends the
schema and expected tuple to the literal task prompt. A missing, null, unknown,
extra, or mismatched identity fails before artifact publication.

## Adapter And Process Rules

The code-owned registry contains fixed argv scaffolds for Claude CLI,
CommandCode, `mmx` MiniMax, OpenCode-compatible MiniMax, OpenCode Qwopus, and
native Codex. Every launch uses
an argv array, `shell=False`, a canonical in-repository cwd, a new process
session, a bounded timeout, process-group termination, and independent stdout
and stderr byte ceilings. Claude and CommandCode request plan mode, and native
Codex requests the route's exact configured reasoning
effort plus a read-only sandbox. The distinct Sol/Terra Worker routes are not
Parent or Supervisor control identities. A canonical cwd is not itself a
filesystem sandbox; provider-specific containment remains part of live
qualification. The child environment passed by the dispatcher contains only
inherited
`PATH`, `HOME`, `TMPDIR`, and locale fields. The dispatcher never reads a
credential or auth-status source.

The original `mmx` MiniMax scaffold is message-only. It cannot gain local file
or command authority from task intent. A distinct disabled
`minimax_mmx_tool_loop` adapter owns a closed JSON text file-tool protocol. It
does not pass `--tool` to `mmx` and never enables commands. Its version-pinned
parser accepts one exact Messages wrapper with one text block and
`stop_reason: end_turn`. The text must contain one duplicate-key-free JSON
object. A tool request has exactly `tool` and `path`, plus `content` only for a
write. The adapter returns a canonical text `TOOL_RESULT` message. A response
without `tool` is the final JSON artifact and then enters the existing closed
response-schema and route-identity validator. Native `tool_use`, OpenAI
`tool_calls`, arrays, extra fields, and multiple requests fail closed without
retry. The distinct MiniMax OpenCode-compatible
scaffold is a future coding harness. It remains disabled and unqualified until a fresh
capability card binds the exact OpenCode runtime, MiniMax model, subscription
billing path, provider-managed credential reference, and demonstrated tool-loop
behavior. No Command Code route is used for MiniMax.

T115 observed this exact two-process read flow through authenticated `mmx
1.0.16` and `MiniMax-M3`. This proves observational read capability. It does
not qualify writes or activate the disabled binding.

The MiniMax wrapper parser cannot append a successful terminal row. It returns
pending metadata to the outer dispatcher. Only successful unwrapped JSON,
response-schema, and exact route-identity validation can append
`final_result_validated`. A validation failure appends
`final_result_validation_failed` with no retry. A terminal-journal append
failure becomes `execution_unknown` and cannot publish an artifact.

The Qwopus scaffold models `llama.cpp` `llama-server` plus OpenCode. Its current
route is disabled because the retained wrapper evidence is stale or broken.
Historical direct llama-server smoke output cannot qualify the wrapper.

The shared OpenCode adapter uses declarative backend bindings. Each binding
fixes the backend variant, provider, model, route, runtime, billing basis,
`opencode run` mode, exact task-grant tool policy, pending JSONL protocol, and
isolated worktree current directory. Provider or runtime text cannot select a
backend. The selector binds the requested identity. It does not prove which
backend OpenCode used. A nonzero result that reports a missing model becomes a
typed backend unavailable result. The attempt does not retry or select the
other backend. A zero exit cannot qualify or publish an artifact until a
version-pinned OpenCode event parser is accepted.

The adapter passes the binding's exact code-owned `provider/model` selector and
`--pure`. This flag disables external plugins. It does not prove that project,
provider, or other ambient configuration cannot affect execution. The adapter
does not pass the route's bare model label. It accepts no endpoint, plugin,
environment, configuration, or selector from the assignment. OpenCode receives
no max-turns flag. The dispatcher bounds the child wall time by the
intent/runtime wall ceiling and the remaining capability-card, task-grant, and
single-attempt binding lifetimes, minus the receiver guard. Missing deadline
evidence prevents process start. After all preparation, the dispatcher reads
the executor-owned clock again. It revalidates each expiry and converts the
remaining duration to one absolute monotonic deadline before process creation.
Expiry terminalizes a consumed scoped attempt as `execution_unknown`. It does
not start a child and does not retry.

Current MiniMax OpenCode and Qwopus OpenCode routes remain unqualified. Current
Claude command containment and exact command-allowlist enforcement also remain
unqualified. Source-local canaries are observational only. Positive route cards
and production scoped-write authority remain owned by the protected receiver
and deployment qualification boundary.

Live mode requires every packet authority fact plus `--allow-provider-call`.
Failure becomes an `authority_violation` attempt outcome, which is a hard stop
and cannot fall back. `external_call_performed` is a version 1 Boolean. It
becomes true only when authenticated, exact external-call evidence satisfies
the version 1 proof contract. A local process spawn or captured CLI output is
not that proof. MiniMax source-local observations record separate process and
capture counts and raw descriptors. `provider_network_performed` remains
`unknown` without an authenticated host event. No live call is authorized by
this contract or its tests.

A task-scoped live process return is not external-call proof by itself. The
manifest sets `external_call_performed: true` only after exact normalized
provider output or a validated provider observation. Once a live provider
process starts, `provider_network_performed` is `unknown` unless an
authenticated host event proves `true` or `false`. A startup failure before
process creation retains `false` for both fields.

Simulated mode is the only mode that accepts `--test-adapter-manifest`, and a
child starts only with `--allow-simulated-process`. Version 1 allowlists the
exact shipped fixture manifest and fake executable paths and SHA-256 digests;
an arbitrary repository executable is not eligible. Simulated execution always reports
`external_call_performed: false`.

Unknown route/provider/runtime identities fail before process creation.
The built-in live argv shapes are scaffolds, not live-qualified provider syntax;
each requires separate provider-specific qualification before use.
Preflight billing, credential, source, scope, identity, freshness, health, and
capability failures remain resolver facts. Authority, billing, credential,
scope, and source-access violations are hard stops and never enable fallback.

## Result And Evidence

Exit zero is necessary but not sufficient. Stdout must be exactly one UTF-8
JSON object matching `response_schema` and the bound route identity. JSON
arrays, duplicate keys, markdown fences, prose prefixes or suffixes, provider
wrappers, missing fields, extra fields, schema drift, and identity drift are
`validation_failure`. The dispatcher never strips fences, extracts an inner
object, unwraps provider output, normalizes prose, or backfills identity.
Nonzero exit, timeout, or output-cap termination is `provider_failure`. Every
non-success outcome is a non-retryable single-attempt hard stop.

That acceptance is transport-level only. Scheduler results must also pass the
fixed deterministic artifact-quality contract in
`dispatch-ledger-and-quality.md`; rejected quality cannot become a Supervisor
result. The schedule manifest binds the quality receipt and legacy evidence but
sets all application and acceptance flags false.

Raw stdout and stderr, the byte-identical JSON artifact, `DispatchReturnManifest` v1,
and a Supervisor event bundle are mode-0600 atomic writes with byte counts and
SHA-256 descriptors. Accepted stdout is copied without trimming or
reserialization. Missing tokens, quota, and cost remain literal `unknown` with
a reason; task response fields never convert unknown transport accounting to
zero. Receipts use assignment identity and resolution time rather than invented
provider facts.

The expected artifact, evidence directory, and every runner-created child path
must be inside `dispatch_output_scope`. This is dispatcher evidence authority,
not provider write authority. The route packet's `write_scope` remains separate
and profile-governed, including an empty scope for read-only provider roles.
Existing symlink, hardlink, or special-file targets fail closed.

Assignment path validation permits an absent expected-artifact parent only when it
is exactly the same canonical repository-relative `evidence_directory` named
by that assignment. This exception does not follow output-scope breadth and
does not apply to any unrelated missing parent. Every existing path component
must be a real directory; traversal and symlinks fail closed. Legacy expected
artifacts whose parent already exists remain supported.
Post-execution lifecycle readers may revalidate the immutable assignment after
the evidence directory exists; that path-shape validation does not grant a new
execution. The binder separately requires absence before emitting a binding,
and `run`/`run-one` independently reject every pre-existing evidence directory
before process creation.

Each `run` uses a new, absent evidence directory. The directory is a single-use
dispatch boundary: an empty or populated pre-existing target fails with
`evidence_collision` before any provider process starts. A separately authorized
repaired assignment uses a fresh `dispatch_id`, evidence directory, and expected
output path; it never deletes, resumes into, or overwrites preserved attempt evidence.
`plan` validates the target but does not create or reserve it.
`run` and `run-one` revalidate absence, then atomically claim the exact
directory before process creation. This closes the intentional handoff from a
read-only scheduler binding to the single execution owner without weakening
the collision or one-attempt boundaries.

The event bundle binds the dispatch to the declared pre-existing Supervisor
assignment and lane IDs, expected artifact digest, and final route-packet
digest. A semantic Worker bundle contains a final evidence-mode
`route_resolved` event and, on success, a `worker_result` event. It is shaped
for the existing Supervisor
validator after that Supervisor has accepted the corresponding normal
`assignment_created` event. The dispatcher only writes the bundle; it does not
apply events, mutate a board, or claim Parent acceptance.

Planner and Architect outputs remain advisory references. Tester, Documenter,
and Auditor outputs are typed unapplied references for the Supervisor adapter
to validate and construct as `independent_test`, `documentation_result`, or
`audit_result` at the appropriate lifecycle phase. They are never mislabeled
as `worker_result`.

The additive adapter in `role-lifecycle.md` consumes only a scheduled reference
whose manifest, envelope, assignment, return, quality, route, profile, and
artifact all reverify. Provider artifacts supply bounded role markers; they
cannot supply trusted command evidence, apply their own event, close a
candidate, mutate GoalBuddy, or accept work.

Supervisor runtime v2 may advance multiple eligible disjoint lanes through
their own phases, but the dispatcher still applies no event. GoalBuddy remains
board truth. Live provider behavior remains unqualified; external calls require
exact separate authority. Hedging is disabled, and unknown accounting remains
unknown. Additive `scoped_write` scheduling follows `provider-scoped-work.md`.
It requires a fresh capability card, an exact task grant, an isolated worktree
or exclusive shared-tree lane, a current lease and fence, and a Parent-review
change receipt. The headless transport stays artifact-only until each provider
write invocation has separate qualification.

Optional task-specific behavior follows `provider-flexible-execution.md`. The
dispatcher accepts a closed Parent task intent, exact harness card, route
capability card, task grant, and current runtime constraints. It binds the
resolved turn and wall-time limits into the provider invocation. It does not
derive write or tool authority from reasoning, verbosity, context, tokens,
latency, or cost.

For version 2 provider work, the dispatcher derives `scoped_write` only from
the resolved execution profile. Every adapter argument builder rejects a write
flag that differs from that profile. The exact harness and capability-card
binding controls write transport; a route-name check cannot grant or deny it.

The dispatcher and scheduled-dispatch binder validate the same exact selected
identity for read-only and scoped-write work. They compare provider, model,
route, runtime, billing, card route, grant route, and harness digest before
adapter selection or execution binding.

When a read-only external route has no resolved execution profile, the adapter
uses the accepted route ceiling instead of the legacy three-turn fallback.
DeepSeek V4 Flash and DeepSeek V4 Pro preserve Command Code's 100-turn ceiling
for read-only work. Their guarded mutation lane remains capped at 20 turns.
Claude Sonnet 5 and Grok 4.6 use a maximum of 20 turns. A resolved execution
profile can narrow these values but cannot widen the route harness ceiling.

The dispatcher normalizes version-pinned native response wrappers before it
validates the assignment response schema. MiniMax `mmx 1.0.16` uses its exact
Messages wrapper. Grok CLI 1.0.4 can use its aggregate JSON wrapper or its
streaming JSON terminal event. Wrapper normalization retains emitted model,
token, and cost evidence when present. A wrapper cannot grant route authority
or replace the required response identity tuple.
