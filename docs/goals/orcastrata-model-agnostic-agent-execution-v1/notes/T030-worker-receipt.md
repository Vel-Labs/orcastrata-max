# T030 Worker Receipt

## Result

Repaired the read-only provider execution seam from first principles.

The seam now resolves the workspace configuration before assignment build. It
uses the same effective configuration for selection and dispatch. It matches an
enabled binding by exact declared model. It preserves every package-owned
transport identity field. It clones only that binding model into the
per-assignment route registry.

The operator must provide `--allow-provider-call`. The seam derives a closed
task grant from that invocation. The grant binds the exact request, execution
prompt digest, canonical repository root, repository-root read scope, evidence
and artifact paths, and subscription billing. The command accepts no free-form
grant digest. The actual T030 read boundary is repository root (`.`).

The resolver reuses package capability ranks for a model overlay only when the
validated explicit selection and package transport identity agree. A packet
route override without that selection cannot inherit the rank.

Lifecycle reporting now distinguishes configuration, selection, process start,
response validation, and completion. A pre-call denial does not dispatch. A
spawn failure reports `called=false`. A started invalid response reports
`called=true` and `completed=false`. Completion requires selected status, an
artifact descriptor, and validated response identity.

## Files changed

- `plugins/codexmax-orchestrator/scripts/run_task_scoped_provider_task.py`
- `plugins/codexmax-orchestrator/scripts/verify_configured_tool_session.py`
- `plugins/codexmax-orchestrator/scripts/resolve_worker_route.py`
- `plugins/codexmax-orchestrator/assets/contracts/headless-provider-dispatch.md`
- `plugins/codexmax-orchestrator/assets/contracts/standalone-provider-usability.md`
- `plugins/codexmax-orchestrator/skills/codexmax-route/SKILL.md`
- `tests/test_task_scoped_provider_task.py`
- `tests/test_configured_tool_session.py`
- `docs/goals/orcastrata-model-agnostic-agent-execution-v1/notes/T030-worker-receipt.md`

## Validation

- Focused T020 and T030 unit suite: 19 tests passed.
- Python compilation: passed for all three changed scripts.
- `git diff --check`: passed.

The tests cover exact binding match, model mismatch, transport mismatch,
workspace configuration ordering and object identity, the explicit call gate,
generic model propagation through packet, argv, expected identity, and
artifact, invalid and valid overlay rank behavior, pre-call denial, spawn
failure, invalid started output, and artifact and identity completion gates.

## Assumptions and proof boundary

- The configured provider tool keeps authentication opaque.
- The provider account uses subscription billing.
- No provider, network, install, login, or credential operation occurred in
  this work package.
- The source and focused execution harness are proven. Installed package parity
  and one real provider execution remain Parent acceptance gates.
