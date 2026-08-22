# Provider-Neutral Harness Loop Adapter Contract

## Boundary

This adapter accepts one bounded JSON fixture from a file or stdin and
constructs exactly one `LoopEvent v1`. It is not coupled to a proprietary
harness. It does not install or activate a hook, service, scheduler, provider,
or background process and does not read user configuration or credentials.

The CLI is preview-only. Its file/stdin bytes contain only
`HarnessLoopInput`; registry, ledger, evaluation time, trust, and execution are
not CLI JSON fields. `--dry-run --json` is mandatory, and no CLI option can
call core execution. The reusable first-party function may call T040 only
through exact `from loop_compile import run_loop` when its trusted caller sets
both `trusted=True` and `execute=True`. JSON cannot assert trust, evaluation
time, ledger state, authority, execution, or acceptance.

## Closed Input

`HarnessLoopInput` contains exactly:

- schema/artifact version;
- one canonical LoopEvent event type;
- bounded source event and session IDs;
- RFC3339 UTC occurrence and observation timestamps;
- at most 256 relative logical workspace paths;
- the exact LoopEvent origin object.

Unknown or duplicate keys fail closed. Command, argv, executable, shell, cwd,
environment, profile, authority, proof, requested scope/write, credential,
provider, and receipt fields are therefore impossible in a valid payload.
Paths reject absolute form, backslashes, parent traversal, emptiness, and
oversized values. File and stdin streams are asked for exactly 65,537 bytes;
the adapter rejects a returned extra byte immediately without waiting for EOF.
Accepted input is capped at 65,536 bytes and serialized output at 262,144
bytes. Parsed JSON is separately capped at depth 16 and 2,048 total value
nodes. Non-UTF-8, malformed JSON, non-finite numbers, oversized input, excess
depth, and excess nodes produce stable harness errors before core execution.

Origin validation precedes event construction: depth is a non-boolean integer
`0..8`; ancestry is an exact-length list of unique valid lower-kebab strings;
element types are checked before uniqueness; root events have null loop/run
identity; non-root events require valid loop/run identity and final-ancestry
loop consistency. Invalid input never calls `run_loop`.

## Trust And Identity

File/stdin preview emits `source.trust: generic_stdin`. An explicit trusted
first-party invocation emits `local_adapter`; the JSON payload cannot choose
the value. The adapter owns `adapter_id: harness-json`, hashed event/source
identity, and a hashed dedupe identity.

Codex and generic transport identities intentionally differ:
`event_id`, `source`, and `dedupe_key` are adapter-specific. Parity requires
the same canonical event type, timestamps, subject locators, requested
read-only scope, origin, authority mutation mode, and registry match/action
outcome for semantically equivalent input. Registry policy must explicitly
list each adapter ID; trust never widens matching or authority.

## Result And Execution

`HarnessLoopResult` preview records the normalized event, `installed: false`,
`executed: false`, false adapter/source/GoalBuddy/WorkGraph mutations, and no
receipts. Invalid CLI input returns a stable rejected JSON object and a short
diagnostic on stderr.

Trusted execution forwards only the raw current registry, constructed event,
trusted evaluation time, and optional code-owned ledger to `run_loop`. T040
owns current authority, freshness, dedupe, recursion, matching, fixed-profile
resolution, process limits, persistence, receipt truth, and proof. A returned
receipt does not prove installation, live delivery, scheduling, acceptance,
publication, network/provider behavior, or external service readiness.
