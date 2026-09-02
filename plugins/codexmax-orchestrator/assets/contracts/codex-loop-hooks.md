# Codex Hook Contracts

## Installed Context Hook

The plugin manifest installs `hooks/hooks.json`. `SessionStart` and
`SubagentStart` call `hooks/orcastrata_context.py`. The program reads one host
event from stdin and returns bounded `additionalContext`. It does not read the
repository, write state, call a provider, schedule work, or execute the loop
adapter below. Malformed and unsupported events return an empty JSON object.

Source validation proves the hook shape. Package validation proves inclusion.
An isolated installation proves discovery. Only an explicit hash-bound trust
decision followed by a fresh host event proves live activation.

## Source-Fixture Loop Adapter

## Proof Boundary

The remainder of this contract defines local source and fixture behavior for
`scripts/codex_loop_hook.py` only. That adapter does not install or activate a
hook, read or write user Codex configuration, or schedule work. Its
`SessionStart`, `UserPromptSubmit`, `PostToolUse`, and `Stop` names remain a
fixed mock-source vocabulary; unavailable or differently named source events
are unsupported and are not silently simulated.

## Supported Source Mapping

| Source fixture name | Required discriminator | LoopEvent v1 type |
| --- | --- | --- |
| `SessionStart` | no paths, tool, or outcome | `session.start` |
| `UserPromptSubmit` | no prompt content, paths, tool, or outcome | `prompt.submitted` |
| `PostToolUse` | `tool_name: apply_patch`, `outcome: completed`, contained paths | `file.changed` |
| `Stop` | `outcome: completed` | `run.completed` |
| `Stop` | `outcome: failed` | `run.failed` |

Git hook names and every other host name are unsupported in this adapter until
a separate verified host contract admits them. T050 does not create a generic
harness mapping.

## Input Boundary

The adapter accepts a closed fixture object with only event name, source event
ID, session ID, timestamps, tool/outcome discriminators, logical workspace
paths, and the exact LoopEvent origin object. It never accepts prompt text,
commands, argv, executables, cwd, environment, credentials, authority
references, action profiles, receipt proof, evaluation time, or a requested
write scope from the hook payload.

Paths are relative POSIX workspace paths. Absolute paths, backslashes, parent
traversal, empty paths, oversized values, mixed batches, duplicate source event
IDs, unsupported tools, and unknown fields fail closed. Duplicate source IDs
are rejected even when their observations differ; they cannot alter event or
normalized source identity. The adapter emits exactly `LoopEvent v1` with
`source.adapter_id: codex-local`, `trust: local_adapter`, read-only requested
scope, no copied GoalBuddy/WorkGraph state, and
`mutation_mode: advisory_report_only`.

## Debounce, Dedupe, Freshness, And Recursion

Only `PostToolUse` observations from the same session, event name, and exact
origin may be coalesced. Their total observed window must not exceed the
code-owned configuration ceiling. Paths and source IDs are sorted and unique.
Event identity binds source IDs and occurrence time; the dedupe key binds the
stable normalized type, session, paths, and origin so event storms reach T040
as duplicates. T040 remains the authority for freshness, retained-ledger
dedupe, recursion, registry admission, profile resolution, timeout, output
bounding, receipts, and proof state. The adapter does not soften a rejection or
blindly retry it.

Before preview or execution, origin validation locally enforces the complete
LoopEvent-v1 shape: depth is a non-boolean integer from zero through eight;
ancestry contains valid unique lower-kebab loop IDs and has exactly `depth`
members; a root has null loop/run IDs and empty ancestry; a loop-originated
event has valid non-null loop/run IDs and its loop ID is the final ancestry
member. Malformed types, negative or excessive depth, duplicate ancestry,
count mismatch, invalid IDs, missing loop/run identity, and root/loop
inconsistency run nothing. T040 still decides whether a structurally valid
origin is recursive for the matched loop.

Element types are checked before ancestry hashing or uniqueness. Unhashable
list, object, or other non-string members therefore produce the same stable
`HookError("hook_origin_invalid")` in preview and explicit trusted-execution
entry paths; raw container `TypeError` is never the rejection interface.

## Execution Boundary

The only supported execution import is exactly:

```python
from loop_compile import run_loop
```

`--dry-run` always emits a preview and never calls `run_loop`. The reusable
`dispatch_hooks` function also previews by default. Only trusted first-party
Python under T040's in-process threat model may set the explicit `execute`
argument and forward the raw current registry plus constructed event to
`run_loop`. The caller-supplied config grants no execution authority, and there
is no CLI execution switch in T050.

The adapter does not import action helpers, subprocess/process APIs, dynamic
imports, reflection, or code-construction facilities. It owns no alternate
profile, argv, cwd, root, or receipt path. Returned LoopRunReceipt values remain
T040 evidence and do not imply GoalBuddy mutation, acceptance, installation,
live hook compatibility, scheduling, publication, or external delivery.

## Advisory Result

`CodexLoopHookResult` is transport evidence, not a LoopRunReceipt. It records
the normalized event, whether core execution was requested, the returned
receipts, `installed: false`, explicit false adapter/source/GoalBuddy/WorkGraph
mutation fields, and whether receipt artifacts were returned. T040 owns any
create-once output/receipt persistence during an admitted execution; those
artifacts are evidence, not a hidden adapter mutation. Preview has no receipts.
Unsupported, malformed, mixed, outside-window, or execution-disabled input
raises a stable `HookError` and runs nothing.
