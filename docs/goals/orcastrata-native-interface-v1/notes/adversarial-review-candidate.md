# Orcastrata Native Interface Review Candidate

## Goal

Expose Orcastrata's accepted workflows through native Codex controls. Do not
build a second orchestration runtime.

## Proposed Change

1. Add nine native command TOML files:
   `/orcastrata-orchestrate`, `/orcastrata-discover`, `/orcastrata-plan`,
   `/orcastrata-route`, `/orcastrata-supervise`, `/orcastrata-audit`,
   `/orcastrata-closeout`, `/orcastrata-config`, and `/orcastrata-loop`.
2. Each TOML prompt invokes exactly one existing
   `$codexmax-orchestrator:codexmax-*` skill. Existing skill IDs remain.
3. Add a plugin manifest `hooks` path.
4. Add one hook JSON file for `SessionStart` and `SubagentStart`.
5. Both events call one standard-library program. It reads the host event JSON
   from stdin and returns a small JSON `additionalContext` value.
6. Session context says the visible task is Parent/PM, GoalBuddy is board truth,
   WorkGraph holds dependencies, delegation must be bounded, and acceptance
   stays with the Parent.
7. Subagent context says the agent owns only its assigned packet, must not
   widen scope or merge, and must return evidence to the Parent.
8. The hook does not read the repository, mutate a board, call a provider,
   schedule work, or persist state.

## Existing Boundary

The plugin already owns planning, automatic routing, exact routing, explicit
fan-out, supervision, verification, closeout, GoalBuddy, and WorkGraph. The
existing `codex_loop_hook.py` remains a separate source-fixture adapter with
`installed: false`; it is not reused for operator context.

## Proof

- Parse every TOML and assert the exact nine command filenames.
- Assert each command references one existing skill and contains no workflow
  policy beyond invocation and user arguments.
- Run the hook program for both admitted events and malformed input.
- Assert valid JSON, bounded output, event-specific context, and no filesystem
  or network imports.
- Run package parity checks.
- Install into an isolated Codex home and inspect discovered commands.
- Treat plugin trust as a separate hash-bound gate. Do not claim live hook
  activation from source, package, or subprocess proof alone.

## Non-Goals

No GitHub issue automation, PR bot, scheduler, new board, new route resolver,
skill rename, provider call from hooks, AOL integration, or prompt-based fake
slash commands.

## Review Rubric

Return `ACCEPT` or `REVISE`. Rank only P0-P2 failures. Cite the section. Explain
the observable failure and the smallest remedy. Test command thinness, hook
context creep, trust accuracy, skill compatibility, user-visible proof, and
the one-runtime boundary. Reject speculative features.
