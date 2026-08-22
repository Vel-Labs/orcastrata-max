# Dispatch Task Envelope And Context Pack Contract

## Boundary

`compile_dispatch_task.py` consumes explicit JSON. It never infers a role,
task class, authority, scope, consequence, independence, budget, or route from
prompt prose. `DispatchTaskEnvelope` v1 is an admission input, not an admission
decision and not permission to call a provider.

This tranche permits only `read_only` and `artifact_only` mutation modes.
`repository_write`, hedging, external cash, live-provider qualification, and
credential inspection fail closed or remain downstream concerns.

## Context Pack v1

A context pack binds a stable identifier, creation and expiry timestamps,
explicit source/input modes, a short operator-authored summary, exclusions,
and zero or more source descriptors. Local-filesystem descriptors contain a
repository-relative path and its exact `sha256:` digest. The compiler resolves
each descriptor inside the declared repository root, rejects symlinks and
non-files, and compares bytes to the supplied digest. `embedded_only` packs
must contain no path entries. Duplicate source IDs or paths are ambiguous and
rejected.

The canonical pack digest is SHA-256 over sorted, compact UTF-8 JSON. The task
envelope must bind that digest and the exact context-pack ID. A pack created in
the future, expired at the injected clock, or expiring before creation is
stale. No transcript or hidden runtime context is inherited.

## Task Envelope v1

The strict envelope binds goal, checkpoint, task, assignment, board,
configuration, authority, WorkGraph, Supervisor, semantic role, task class,
mutation mode, sources, requested and authorized scopes, commands,
consequence, independence, retry safety, queue timing, priority, budget,
accounting state, deterministic artifact-quality policy, context, and one
route identity. Unknown or duplicate fields fail closed at every object level.

Requested scopes must be exact members of the declared authority scopes. This
conservative rule deliberately avoids interpreting glob containment. A
read-only task has no write scope; an artifact-only task has an explicit write
scope. Commands are argv arrays with explicit working directories. Their
presence is data, not permission to execute them.

Pre-execution token and cost accounting remains typed `unknown` with a reason.
It is never normalized to zero. Queue freshness uses an injected `--now`:
future enqueue times, elapsed maximum queue age, and reached deadlines fail.
`hedge_requested` and `external_cash_authorized` must be false.

Planner and Architect envelopes must bind provider `openai`, model
`gpt-5.6-sol`, and reasoning `high`, `xhigh`, `max`, or `ultra`. Other role
routes remain explicit but are evaluated by downstream configured policy and
fresh preflight evidence.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/compile_dispatch_task.py compile \
  --repo-root /absolute/repository/root \
  --input dispatch-task-envelope.json \
  --context-pack dispatch-context-pack.json \
  --now 2026-07-27T12:00:00Z
```

`compile` validates a draft and adds only `artifact_type` and `compiled_at`.
`validate` accepts a compiled envelope and requires `compiled_at` to fall from
enqueue time through the injected `--now`; queue and deadline freshness are
re-evaluated at that clock. Successful JSON is written to stdout. Rejection is
typed JSON on stderr with exit status 2.
