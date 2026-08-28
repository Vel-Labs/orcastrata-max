# Orcastrata Dynamic Routing V2 Acceptance

## Outcome

Orcastrata 1.1.0 is accepted as a source and immutable-package candidate.
The normal route does not require the operator to name a worker model. The
Parent selects a role. Orcastrata ranks enabled or discovered models from
declared route metadata, performs a fresh session probe, and starts at most one
provider process. An exact `Use MODEL through Command Code` request remains an
override. Explicit adversarial fan-out remains a separate operation.

The candidate also supports bounded implementation. The provider can author a
unified diff but cannot write the repository. Orcastrata applies the diff only
to named existing files in a linked worktree, runs allowlisted validation, and
writes a rollback bundle outside that worktree. Parent acceptance remains
false until the Parent reviews the result.

The active plugin under `~/.codex` was not changed. Workspace policy prohibits
that write. Therefore, this receipt does not claim that a fresh Codex host task
loaded 1.1.0. That install and fresh host journey are the remaining deployment
proof, not a candidate defect.

## Changed files

Runtime:

- `plugins/codexmax-orchestrator/scripts/provider_task_execution.py`
- `plugins/codexmax-orchestrator/scripts/run_task_scoped_provider_task.py`
- `plugins/codexmax-orchestrator/scripts/run_automatic_provider_task.py`
- `plugins/codexmax-orchestrator/scripts/run_adversarial_provider_fanout.py`
- `plugins/codexmax-orchestrator/scripts/provider_patch_application.py`
- `plugins/codexmax-orchestrator/scripts/run_isolated_provider_implementation.py`
- `plugins/codexmax-orchestrator/scripts/resolve_worker_route.py`

Contracts and package:

- `plugins/codexmax-orchestrator/GETTING_STARTED.md`
- `plugins/codexmax-orchestrator/CHANGELOG.md`
- `plugins/codexmax-orchestrator/assets/contracts/explicit-tool-model-routing.md`
- `plugins/codexmax-orchestrator/assets/contracts/provider-scoped-work.md`
- `plugins/codexmax-orchestrator/skills/codexmax-orchestrate/SKILL.md`
- `plugins/codexmax-orchestrator/.codex-plugin/plugin.json`
- `plugins/codexmax-orchestrator/.codex-plugin/release-manifest.json`
- `plugins/codexmax-orchestrator/scripts/verify_release_parity.py`

Tests:

- `tests/test_provider_task_execution.py`
- `tests/test_task_scoped_provider_task.py`
- `tests/test_automatic_provider_task.py`
- `tests/test_adversarial_provider_fanout.py`
- `tests/test_provider_patch_application.py`
- `tests/test_isolated_provider_implementation.py`
- `tests/test_installed_provider_task_journey.py`

Goal and plan:

- `docs/goals/orcastrata-dynamic-routing-v2/goal.md`
- `docs/goals/orcastrata-dynamic-routing-v2/state.yaml`
- `docs/goals/orcastrata-dynamic-routing-v2/notes/final-acceptance.md`
- `docs/plans/orcastrata-dynamic-routing-v2.md`

The superseded 1.0.4 goal packet and plan were deleted. This removes 84 tracked
files and 1,071,653 bytes of duplicate receipts and raw provider evidence. No
external consumer reference was found. Git commit `75952f7` retains recovery.

## Validation

- `python3 -B -m unittest discover -s tests -p 'test_*.py' -q`: 62 tests passed.
- Focused automatic, implementation, and rollback tests: 18 tests passed.
- Release manifest build and source verification: passed.
- Immutable package stage verification: passed.
- Package version: 1.1.0.
- Package files: 392.
- Release manifest SHA-256: `1f0be86195e152a0756fbf3241620f672737a98415e93a7c81e5e6294fbd4a93`.
- Source and staged tree SHA-256: `11e3e84c930e2e4dff8324ea05f2ca75360d9ffcea07ff0746cc9036ae0d4174`.
- `git diff --check`: passed.
- Goal state validator: passed at each milestone and must pass after closeout.

## Live behavior

- Automatic no-model task: selected `deepseek/deepseek-v4-flash` through
  Command Code 1.38.1 and completed with validated response identity.
- Exact task-local task: selected `minimaxai/minimax-m3` without a saved binding,
  completed, and did not persist the temporary binding.
- Three-lane adversarial review: DeepSeek Pro, MiniMax M3, and Grok 4.6 were each
  admitted and called once with one frozen input. MiniMax completed. DeepSeek
  and Grok timed out at 45 seconds. Orcastrata did not retry or substitute.
- Isolated implementation: MiniMax authored one patch. Orcastrata changed one
  authorized file, passed validation, generated rollback evidence, restored the
  exact original bytes, and removed the disposable worktree.
- Immutable staged no-model task: the provider process started, but the provider
  returned non-JSON output. Orcastrata rejected it as
  `response_not_one_json_object` and did not fall back. This proves truthful
  failure handling, not successful staged provider output.

Provider cost, token, and quota data remain `unknown` when Command Code does not
report them. Orcastrata no longer invents zero usage or qualification.

## Independent audit

The Luna auditor returned `ACCEPT` with no blocking candidate defects and
9.5/10 confidence. It independently reran the 62-test suite, checked the task
identifier security boundary, confirmed metadata-only model ranking, verified
source and staged package parity, and confirmed the old evidence bloat removal.

## Remaining risk

The candidate cannot score 10/10 until an authorized deployment replaces the
active installed plugin and a fresh Codex task proves that ordinary language
loads this exact 1.1.0 package. The current active installation is older and was
not modified. Direct MiniMax and Grok CLI transports also remain separate
code-owned adapter work; current generic model selection is supported through
the approved Command Code and OpenCode transports.
