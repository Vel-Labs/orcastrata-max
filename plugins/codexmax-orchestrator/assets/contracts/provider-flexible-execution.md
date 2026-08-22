# Provider Flexible Execution Contract

## Purpose

Codexmax separates task behavior from task authority. A larger token budget,
deeper reasoning level, longer turn limit, or more verbose answer never grants a
file, command, tool, browser, connector, network, or billing capability.

The execution decision uses three layers:

1. `ParentTaskIntent` states the approved task need.
2. `AdapterToolLoopCapability` and `RouteCapabilityCard v2` state harness
   potential and freshly demonstrated route capability.
3. `ResolvedExecutionProfile` intersects the intent, capability,
   `TaskExecutionGrant v2`, and current runtime constraints.

Runtime configuration can only narrow the result.

## Universal capability intersection

Universal Adapter Capability V1 adds a source-local check before runtime
admission. A lane requests only frozen primitives. The exact model
qualification proves a subset of the adapter's potential primitives. A later
task grant remains the only execution authority.

The shared conformance harness checks the exact compatibility key, current
qualification, lane primitive subset, exact tool allowlist, and concurrency.
It does not call a provider or start work. Its receipt keeps `provider_called`,
`execution_started`, `eligibility_granted`, `authority_granted`, and
`acceptance_granted` false.

Effective concurrency is the minimum of user, adapter, task, fleet, provider,
and runtime-host caps. A scoped-write task must supply task cap one. This keeps
writes serialized. It does not replace or change T170 scheduling.

Reasoning, verbosity, model identity, route order, budget, cost, and
conformance output cannot add a primitive or authority. `no_retry: true` and
`execution_unknown_policy: preserve_and_stop` remain fixed.

## Parent task intent

`ParentTaskIntent` records task size, complexity, consequence, independence,
reasoning depth, answer verbosity, context strategy, input and output token
ceilings, turn, wall-time, and cost ceilings, capability needs, mutation mode,
source delivery, and the no-retry policy.

Codexmax ships five closed presets:

- `advisory_micro`: 1 turn;
- `fast_read`: 3 turns;
- `deep_review`: 20 turns;
- `bounded_implementation`: 20 turns;
- `independent_audit`: 20 turns.

The substantial presets use 20 as a practical task-intent ceiling. This is not
an unlimited loop. The exact adapter harness, current route capability, live
runtime budget, and wall-time or lease expiry can only narrow this ceiling.

The Parent can select explicit behavior values within the closed schema. The
selection requests capability. It does not create capability or authority.

## Harness and route capability

An `AdapterToolLoopCapability` records the maximum behavior that the product
knows how to express for one adapter. It is static harness potential. It is not
live route proof.

A `RouteCapabilityCard v2` binds one fresh route qualification to the exact
harness digest. It records the demonstrated file, command, write, browser,
search, connector, network, reasoning, verbosity, context, turn, and wall-time
ceilings. An adapter declaration such as `acceptEdits` cannot qualify writes.

The shipped harness profiles cover DeepSeek V4 Pro and Flash through Command
Code, Claude Sonnet through Claude Code, MiniMax M3 through its subscription
CLI, and Grok 4.5 and 4.6 through Grok CLI. The static catalog also contains a
disabled MiniMax OpenCode-compatible coding harness and the retained local
Qwopus harness. Static harness presence is potential only. It is not current
route qualification.

MiniMax remains `message_only`. Its write and command transports remain
`qualification_required`. A future adapter-owned tool loop can qualify those
capabilities without changing the task-intent schema.

The distinct `minimax_m3_json_text_tool_loop` harness does not widen the advisory
route. It binds `worker_minimax_m3_tool_loop`, `mmx 1.0.16`, and `MiniMax-M3`.
Codexmax owns a closed JSON text `read_file` and `write_file` protocol.
Commands remain disabled. The adapter does not use `--tool`. The parser accepts
only one exact MiniMax Messages wrapper and one duplicate-key-free JSON object
in its text block. It permits one exact tool request or one final JSON artifact.
It appends one canonical assistant tool-request string and one canonical user
`TOOL_RESULT` string. The T115 canary observed this exact two-process read flow.
T117 also observed one exact five-byte write in an isolated task worktree after
the adapter enforced the exact governed scope. This is observational task-
scoped capability. It does not qualify protected production writes. Commands
remain disabled, and `write_access` remains `unverified` in the route catalog.

Wrapper parsing is not final acceptance. The adapter records the wrapper as
pending. The outer dispatcher must validate the unwrapped JSON, the closed
response schema, and the exact route identity before it appends
`final_result_validated`. A schema or identity failure appends
`final_result_validation_failed`, records no retry, and cannot publish an
artifact. Failure to append either terminal row becomes `execution_unknown`.

The file tools use descriptor-relative traversal beneath the isolated
worktree. They reject absolute paths, parent traversal, symlinks, non-regular
files, multi-link files, non-UTF-8 reads, and oversized files. Writes apply the
exact UTF-8 tool-input bytes. They do not repair a missing newline. T105 binary
diff reconciliation and Parent review decide if the bytes satisfy the task.
The adapter advertises only tools in the resolved task-grant intersection. It
checks the exact read or write scope before every descriptor open and action.
It treats the resolved input-token ceiling as a stricter full-request byte
ceiling. It does not use a token-to-byte multiplier. The canonical wire-size
check includes messages, tool schemas, model, route, runtime, provider, output
limit, output format, and message transport. It derives a per-result byte cap
from that ceiling. It checks the full request before every provider call and
after every tool result.

This route is disabled and qualification-pending. The source-local serializer
and final-result parser are inputs to independent audit. They do not create a
positive capability card. Timeout, turn exhaustion, or failure after a write is
`execution_unknown` and cannot retry. The protected receiver remains the only
write-authority path.

`mmx 1.0.16 --dry-run` performs provider-region and key validation before it
renders the request. It is not a non-networking qualification primitive. T115
instead observed an explicitly authorized live JSON text read flow. The direct
and adapter-loop bindings remain disabled. The catalog records the observed
read capability, but it does not make a binding callable. A write-capable
qualification still requires protected process, provider/model, grant, and
reconciliation evidence.

Before each `mmx` spawn, the protected attempt area records and fsyncs a
hash-chained process-spawn intent. After capture, it writes stdout and stderr as
absent-only raw byte artifacts and records their byte counts and SHA-256 digests
in a fsynced `capture_completed` event before parsing. These events prove local
process and capture counts only. Provider-call and network activity remain
`unknown` without an authenticated host event. Unsupported final output or
parser failure adds `observation_pending`, the exact process and capture counts,
and terminal `execution_unknown`. The public manifest retains this structured
observation and forbids retry. Raw receipt or journal failure permits no retry
and leaves durable residue for reconciliation.
The public v1 `external_call_performed` field remains Boolean and stays `false`
unless the v1 proof contract establishes the call. A separate
`provider_network_performed` field is `unknown` for these local observations.
Every timeout, nonzero exit, output-limit result, and parser rejection attempts
to append the terminal `observation_pending` and no-retry row before returning.
If that append fails, the structured result records the append failure and the
protected attempt terminalizes as durable `execution_unknown`.

The separate `minimax_m3_opencode` harness uses an OpenCode-compatible agentic
tool loop. It can express local reads, scoped worktree writes, and commands.
Its route remains disabled and unqualified. It requires a fresh exact route
identity, provider-managed credential reference, capability card, grant, lease,
fence, and runtime gate before use. The dispatcher does not read or copy the
provider credential.

OpenCode is one provider-neutral tool-loop adapter. A declarative backend
binding supplies the exact backend variant, provider, model, route, runtime,
billing basis, runner mode, task-grant permission policy, pending JSONL output
protocol, and isolated-worktree current directory. MiniMax and Qwopus use distinct backend
bindings and digests. The dispatcher does not infer a backend from a provider
label or a runtime substring. Any backend substitution fails before process
start.

The binding also supplies the code-owned OpenCode `provider/model` selector.
MiniMax uses `minimax/MiniMax-M3`. Qwopus uses
`llama-server/qwopus36-35b-a3b-coder-mtp-q5_k_m`. The dispatcher rejects a bare
model label and never accepts a caller-supplied selector. The selector binds the
requested identity. It does not prove the backend that OpenCode used. The
dispatcher launches `opencode run --pure` to disable external plugins. Project,
provider, and other ambient configuration influence remains unproven.

The configured MiniMax OpenCode binding is disabled. Its credential reference
is opaque and provider-managed. Configuration cannot supply an endpoint,
environment, executable, token, or credential value. Fresh qualification must
bind the executable descriptor, OpenCode version and build, closed MiniMax
backend variant, exact provider and model, opaque credential-reference digest,
subscription billing observation, isolated current directory, and parsed JSONL
result. Unknown backend or billing evidence denies the route. A missing-model
failure is unavailable and non-retryable. The bounded OpenCode JSON event
normalizer requires one session, no error event, exactly one final text result,
and one terminal `stop`. It preserves valid terminal token and cost reports.
Missing reports remain `unknown`. Malformed, ambiguous, mixed-session, or
unterminated output cannot publish an artifact.

The `qwopus_llamacpp_opencode` harness records the retained local architecture:
`llama.cpp` `llama-server` supplies the model endpoint and OpenCode supplies the
coding tool loop. Historical direct smoke evidence does not qualify the current
OpenCode wrapper. The route remains disabled with unknown current capability
until the stale wrapper and model binding pass fresh qualification.

## Runtime resolution

The runtime requires current eligible health, budget, lease, fence, and
worktree state. It chooses the minimum of the task, harness, and current runtime
ceilings for input tokens, output tokens, turns, wall time, and cost. The
resolved profile binds the runtime budget digest.

The execution deadline is no later than the minimum of the intent wall-time
ceiling and the remaining capability-card, grant, and attempt-binding lifetime,
minus the fixed receiver guard. After all preparation, the executor reads its
trusted clock again and revalidates all expiries. It binds the remaining time to
one absolute monotonic deadline before process creation. This rule applies to
every version 2 external provider profile, including read-only Command Code and
Claude Code work. It does not depend on scoped-write context. Expiry starts no
child. A consumed scoped attempt terminalizes as `execution_unknown` and permits
no retry. The executor checks the bindings again at completion. Explicit legacy
version 1 work has no resolved version 2 profile and retains its configured
timeout behavior. Native Codex does not use the external-provider authority
envelope. It is excluded from both this expiry calculation and the external
fresh-clock requirement.

OpenCode `run` has no supported max-turns control in this harness. The OpenCode
backend binding records turn enforcement as unavailable. Codexmax does not add
or claim a turn flag. It enforces the child wall deadline above. If current
card, grant, binding, start-time, or expiry evidence is missing, the OpenCode
attempt remains pending and no child starts.

The runtime rejects a cost-inappropriate task, a harness substitution, a
missing route or grant capability, an unsupported behavior control, a closed
runtime gate, or an unsafe retry policy.

The intent and grant use a strict authority matrix. Artifact-only intent
requires an authority-free grant. Read-only intent requires a read-only grant
with no write scope. Scoped-write intent requires a scoped-write grant with a
nonempty write scope. The task-intent digest must match the grant. The envelope
mutation mode and requested write scope must match the resolved profile and
grant before lease start, protected-receiver use, process start, or receipt
creation.

Every version 2 read or write profile also binds the selected route. The
selected route name must equal both the capability-card route name and the
task-grant route name. The selected provider, model, callable route, runtime,
and billing identity must equal the capability card before adapter selection.
The capability card must bind the exact harness digest. A provider, runtime,
route, model, billing, card, grant, or harness substitution fails before
process or manifest creation.

The exact harness digest on the fresh route card controls tool-loop and write
transport eligibility. Provider or route names do not deny or grant writes.
Current MiniMax remains denied because its bound harness is message-only. A
future harness on the same route can become eligible only with a fresh exact
card, exact intent-bound grant, and all runtime gates.

Routing economics keep four facts separate:

- observed input and cache-token volume;
- provider-reported or host-reported monetary cost, when exposed;
- billing basis, including a subscription or local compute;
- task quality and operator preference.

Token volume is not monetary expense. Cached token volume can materially change
provider economics. Codexmax does not infer a charge from context size, and it
does not reject a small task only because a harness reports a large fixed
context. Runtime cost and latency ceilings can still reject a task when current
facts exceed the exact task budget.

DeepSeek V4 Pro is the preferred substantial delegate. DeepSeek V4 Flash is a
high-quality low-cost alternative. This preference changes route order only.
It grants no file, command, network, tool, or mutation authority.

## Direct work

Scoped writes continue through the T105 flow. The executor owns an isolated
worktree. A protected receiver issues one use of the exact grant. The provider
changes allowed files once. The executor captures a binary before and after
diff and validation receipt. The Parent reviews the actual diff and accepts or
rejects it.

The Parent does not reimplement provider prose. A mutation followed by a turn
limit is `execution_unknown` for that one attempt. The state means that the
controller cannot prove a clean terminal result after a possible side effect.
It requires preservation and reconciliation and cannot retry. It is not a
permanent statement that the provider or model cannot edit files.

Claude Code supports a larger bounded turn ceiling. The Parent intent and live
runtime can narrow that ceiling for each task. Turn exhaustion before any
mutation is a failed attempt. Turn exhaustion after a possible mutation is
`execution_unknown` for that attempt. Neither result changes the static model
capability or permits automatic retry.

The Claude Code 2.1.231 argv uses print mode with
`--no-session-persistence`, `--no-chrome`, and `--safe-mode`. Safe mode removes
ambient customizations and integrations. It keeps built-in tools and permission
modes. The read-only route uses `dontAsk` with the exact built-in tool set
`Read,Glob,Grep`. It does not use `plan`, because a live 20-turn observation
showed that plan mode wrote a plan outside the governed workspace despite the
isolation flags. A governed scoped-write route keeps `acceptEdits` and does not
apply the read-only tool restriction. The isolation flags do not grant or
remove its task grant.

The configured V1 route uses the stable runtime identity `Command Code`. Its
session probe records the sanitized installed version and verifies the exact
model without making that observed version a new hard-coded route identity.

The separate historical `protected-commandcode-session-v1` contract remains
bound to Command Code 1.23.2. Its argv uses `--no-session` and `--no-skills`.
It also keeps `--skip-onboarding` and `--no-auto-update`. These flags prevent
session persistence, skill discovery, onboarding, and an automatic update
during that protected attempt. Its runtime binding includes the installed
`package.json` descriptor, exact version and bin map, and digest
`sha256:d7d4fcc49a4bb8b1579ba06deff235964d2dfb311c0f051cbaa97351adc25cb6`.
It also includes the command link, entry, Node, and sandbox identities. This
historical contract does not set the configured V1 route version.

Read-only work uses `plan` in one fresh run. Scoped-write work uses the
installed CLI's exact `auto-accept` permission mode in a different fresh run.
A write run requires a closed Parent-accepted read envelope that binds the
prior read receipt digest, model, and runtime version. The envelope records
user intent. It is caller-constructible and does not mint provider authority.
The task grant and isolated worktree remain the authority boundary; the mode
name does not grant scope.

The Grok CLI route is unsafe and unqualified for dispatch. A live startup
observation found ambient Claude skills despite `--no-memory` and
`--no-subagents`. The current Grok argv still disables web search, memory, and
subagents, but these flags do not establish a no-config or no-session boundary.
Do not dispatch Grok until an installed, tested boundary exists. This contract
does not infer or add an unsupported Grok flag.

## Compatibility

`RouteCapabilityCard v1` and `TaskExecutionGrant v1` remain readable. Their
migrations are deterministic and conservative. Migration disables all new
tool, browser, search, and connector permissions. It sets the smallest behavior
ceiling. Migration never upgrades evidence. A v1 provider-work envelope must
set `legacy_schema_v1: true`; the dispatcher does not infer legacy mode.
