# Loop Compilation And Fixed Action Contract

## Boundary

`LoopCompilation v1` deterministically binds one validated and uniquely matched
loop definition to current source-owned action profiles and a bounded WorkGraph
document. It does not grant authority, execute an action, mutate WorkGraph or
GoalBuddy, install a hook, activate a schedule, or accept a result.

### In-process threat model

Registry configuration, events, receipts, filesystem subjects, authority
references, profiles on disk, and durable artifacts are untrusted inputs.
First-party plugin Python already executing in the same interpreter is trusted
code. V1 does not claim process isolation or an unforgeable capability against
arbitrary in-process Python; such code can import process APIs independently.
Defending against malicious first-party Python requires a separately designed
process or sandbox boundary and is outside this contract.

The supported and statically enforced adapter API is raw-current
`loop_compile.run_loop`. T050/T060 adapters must use
`from loop_compile import run_loop`; they must not import `loop_actions`,
`subprocess`, another `loop_compile` symbol, dynamic import/code-construction
modules, or reconstruct/execute code objects. Their tests must include
`tests.test_loop_actions`, whose import-policy check scans those adapter paths
when present.

The adapter policy is deny-by-default. Allowed standard-library modules are
`argparse`, `copy`, `dataclasses`, `datetime`, `hashlib`, `json`, `pathlib`,
`sys`, and `typing`; allowed imported symbols and calls are the bounded parsing,
typing, hashing, path-read, collection, string, CLI parsing, local-helper, and
`run_loop` operations enumerated by `adapter_import_policy_errors` in
`tests/test_loop_actions.py`. All other imports and calls fail. In particular,
`os`, `subprocess`, `asyncio`, `builtins`, `types`, `marshal`, `importlib`,
`ctypes`, `sys.modules`, `getattr`, `__import__`, `exec`, `eval`, `compile`,
process methods, dynamic call targets, and code-object reconstruction are
forbidden. Import aliases and any local shadowing of `run_loop` are also
forbidden so the reviewed symbol remains the called execution entry. T050/T060
may extend the safe parsing allowlist only through an
explicit reviewed contract/test change; runtime event data cannot change it.

Registry and event input never supplies an executable, argv, cwd, environment,
or parameter. The compiler emits profile IDs, schema versions, exact source
digests, command identities, capabilities, and effective limits only. Runtime
must re-resolve the checked-in profile and reproduce the digest before use.

## Source-Owned Profiles

Profiles live only in `assets/action-profiles/<profile-id>.json` and are selected
through a code-owned ID-to-file mapping. Each strict JSON object has exactly:

- `schema_version: 1`, `profile_id`, and stable `command_identity`;
- a nonempty fixed `argv` whose executable is an absolute source-owned value;
- one fixed logical `cwd` under `workspace` or `codexmax_repo`;
- a closed capability mapping for mutation, network, credentials, cash, tokens;
- fixed timeout/output ceilings, validation IDs, and an empty parameter list.

V1 profiles are read-only apart from the code-owned output and receipt sink.
They authorize no network, credentials, external cash, model tokens, caller
environment, or caller parameters. Unknown, malformed, stale, unavailable, or
incompatible profiles fail closed.

## Compilation

Compilation validates registry and event identity, performs T020 matching,
requires one match, binds current authority evidence, validates referenced
WorkGraph JSON with the WorkGraph v1 validator, retains an optional GoalBuddy
locator as non-authorizing evidence, and creates one bounded WorkGraph work item
per action. Every evidence row has `authority_effect: none` and
`acceptance_effect: none`. Static cycles or stale reference digests reject the
compilation. Compilation never writes its source references.

Canonical JSON digests cover the registry/event semantic objects. The
compilation ID covers those digests, evaluation time, definition identity,
authority digest, exact profile bindings, references, and compiled WorkGraph.
Repeated compilation of the same inputs and evaluation time is byte-identical.

## Execution And Receipts

Execution is available only through `loop_compile.run_loop`, which accepts the
raw registry, raw event, explicit evaluation time, and optional dedupe ledger.
It does not accept a prior compilation, profile object, proof assertion, or
caller-selected logical roots. A compilation artifact is never executable
input. The entrypoint compiles from raw current input for admission, recompiles
again immediately before every subprocess, rejects any authority, reference,
sink, or profile drift, re-resolves the current profile digest, and invokes its
fixed argv directly with `shell=False`, a fixed minimal environment, fixed cwd,
one process group, and the narrower of profile and loop timeout/output caps.
Process creation and capture are nested inside that raw-current entrypoint;
there is no module-level callable that accepts a profile object, argv, cwd, or
prior compilation and can reach `Popen`.

Output is bounded while the process runs. Timeout, nonzero exit, truncation,
sink collision, and unavailable executable remain explicit. Output evidence
and one `LoopRunReceipt v1` per action are local create-once files under the
definition's validated report root. Existing files, symlinks, aliases, path
escape, or rewrites fail closed. A receipt records command identity, never argv.

`pass` requires admitted current authority, compatible capability, completed
zero-exit execution, known timing, known zero token/cash evidence for these
local non-model profiles, exact output evidence, all mandatory validation rows
completed/pass, and a successfully persisted receipt. Rejection is
`not_run/rejected`; timeout or execution failure is `failed/fail`; unknown or
missing evidence cannot become `pass` or `proved`.

## Proof Boundary

T040 proves local source compilation, fixed-profile fixture execution, bounded
evidence, and truthful receipt semantics. It does not prove installed code,
live hooks, scheduler activation, connectors, publication, Parent acceptance,
or GoalBuddy/WorkGraph mutation.
