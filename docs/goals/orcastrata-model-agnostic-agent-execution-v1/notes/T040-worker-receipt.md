# T040 worker receipt

Implemented the automatic read-only external Worker selector.

## Behavior

- Resolves the effective configuration once.
- Considers only enabled package-owned Command Code and OpenCode Worker bindings.
- Orders candidates by Worker role priority and package ordinal ranks.
- Probes exact configured sessions before selection.
- Continues after probe denial because no provider process started.
- Builds the existing T030 assignment and dispatches at most one provider task.
- Does not fall back after a provider process starts.
- Reports every candidate and separates configured, probed, selected, called,
  completed, rejected, and usage states.
- Does not accept model, provider, executable, endpoint, credential, or grant
  digest input.

## Files changed

- `plugins/codexmax-orchestrator/scripts/run_automatic_provider_task.py`
- `plugins/codexmax-orchestrator/skills/codexmax-orchestrate/SKILL.md`
- `plugins/codexmax-orchestrator/assets/contracts/route-registry.md`
- `tests/test_automatic_provider_task.py`

## Validation

- `python3 -m unittest tests/test_automatic_provider_task.py -v` — 3 passed.
- `python3 -m py_compile plugins/codexmax-orchestrator/scripts/run_automatic_provider_task.py` — passed.
- No provider, network, install, login, credential, or installed-file action was performed.

## Proof boundary

This is source and synthetic focused proof. It does not prove package parity,
installed projection, or a real provider call. T030 and package-level
validation must establish those boundaries.
