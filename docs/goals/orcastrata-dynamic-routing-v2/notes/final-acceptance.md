# Orcastrata Dynamic Routing V2 Acceptance

## Outcome

Orcastrata 1.1.1 is accepted as a source and immutable-package candidate.
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

The installed 1.1.0 host journey failed because its catalog discovery did not
admit candidates from the formatted Command Code 1.38.1 model list. The active
plugin under `~/.codex` was not changed by this repair because workspace policy
prohibits that write. Therefore, this receipt does not claim that a fresh Codex
host task loaded 1.1.1. That install and fresh host journey remain required.

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

The 1.1.1 repair changed only the automatic catalog parser, its two formatted
catalog fixtures, the package version, changelog, release manifest, goal state,
and this receipt.

Goal and plan:

- `docs/goals/orcastrata-dynamic-routing-v2/goal.md`
- `docs/goals/orcastrata-dynamic-routing-v2/state.yaml`
- `docs/goals/orcastrata-dynamic-routing-v2/notes/final-acceptance.md`
- `docs/plans/orcastrata-dynamic-routing-v2.md`

The superseded 1.0.4 goal packet and plan were deleted. This removes 84 tracked
files and 1,071,653 bytes of duplicate receipts and raw provider evidence. No
external consumer reference was found. Git commit `75952f7` retains recovery.

## Validation

- `python3 -B -m unittest discover -s tests -p 'test_*.py' -q`: 63 tests passed.
- Focused automatic and installed-package journey tests: 9 tests passed.
- Release manifest build and source verification: passed.
- Immutable package stage verification: passed.
- Package version: 1.1.1.
- Package files: 392.
- Release manifest SHA-256: `9e694a4c598b417db21ad90c1911a2845df161d922e4a811b84326732e78149c`.
- Source and staged tree SHA-256: `653267205ec52c4a24eba7a8a08f0a93597bb326436dfded4804af11665b834e`.
- `git diff --check`: passed.
- Goal state validator: passed at each milestone and must pass after closeout.

## Live behavior

- Installed 1.1.0 host task: loaded the skill but reported zero discovered
  candidates, then recorded one DeepSeek Pro process exit with return code 6.
  No worker result or fallback was accepted. This rejected 1.1.0 as the final
  installed candidate.
- Current Command Code 1.38.1 catalog: 62 model rows parsed. Section headings,
  summary text, examples, and documentation footer text were excluded.
- Exact DeepSeek Pro diagnostic after the failure: returned valid JSON with
  process exit code 0 under the same read-only isolation flags.
- Repaired 1.1.1 source automatic task: selected
  `deepseek/deepseek-v4-flash`, called one process, completed with validated
  exact response identity, and used no fallback.
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

The original Luna audit accepted 1.1.0 before installed-host testing. That
acceptance was superseded by the host failure. The narrow 1.1.1 Luna re-audit
returned `ACCEPT`. It verified the formatted row parser, metadata-only ranking,
both installed-style regression fixtures, 63 passing tests, and source/stage
parity. It found no source change justified for the non-reproduced exit code 6.

## Remaining risk

The candidate cannot score 10/10 until an authorized deployment replaces the
active installed 1.1.0 plugin and a fresh Codex task proves that ordinary
language loads this exact 1.1.1 package. Direct MiniMax and Grok CLI transports remain separate
code-owned adapter work; current generic model selection is supported through
the approved Command Code and OpenCode transports.
