# Implementation Planning Contract

## Purpose

Codexmax implementation planning turns one roadmap item, one feature, or a
tightly coupled set of roadmap items into a decision-complete build plan. It is
supplemental to roadmap orchestration:

```text
roadmap item(s)
  -> implementation plan
  -> optional GoalBuddy board
  -> assignment, supervision, and verification
  -> evidence-backed feature closeout
  -> roadmap evidence and status update
```

A roadmap selects and sequences outcomes. An implementation plan specifies how
one selected outcome will be built, tested, gated, handed over, and proved.
Planning is never implementation proof.

## Authority And Truth

- The operator owns the intended outcome and new or expanded authority.
- Parent Codex owns plan acceptance and final implementation acceptance.
- GoalBuddy owns live task, dependency, receipt, and active-task truth whenever
  a `state.yaml` board exists.
- The Markdown task ledger is a human-facing projection of GoalBuddy state, not
  a second board.
- WorkGraph remains the dependency and reviewed-update substrate.
- Existing plans are audit-only unless the operator explicitly authorizes
  repair.
- A plan may cite one or more roadmap items, but it may not silently edit,
  complete, or reprioritize the source roadmap.

## Planning Modes

Exactly one mode is recorded:

| Mode | Durable output | Execution meaning |
| --- | --- | --- |
| `document_only` | one standalone Markdown implementation plan | no board or execution state |
| `board_prepared` | `goal.md`, `state.yaml`, and `notes/` | the board and current task are prepared; execution authority is not implied |
| `execution_authorized` | board-backed plan plus explicit recorded authority | orchestration may begin only inside the recorded scope |

`document_only` is the default for bounded work. Select GoalBuddy backing when
any of these are true:

- work likely spans more than one session;
- the plan contains four or more implementation tasks;
- dependency gates or independent audit are required;
- parallel or tandem lanes are useful;
- external authorization, retention, privacy, or other fail-closed constraints
  affect the work;
- the operator requests persistent progress, handoffs, continuous execution,
  GoalBuddy, or `/goal`.

When repository conventions do not provide a planning location,
`document_only` plans default to `docs/plans/`. Board-backed plans default to
`docs/goals/<plan-id>/goal.md`, `state.yaml`, and `notes/`.

## Roadmap Selection Boundary

One implementation plan may cover multiple roadmap items only when all of them
share:

- one observable acceptance oracle;
- one architecture boundary;
- one delivery sequence;
- compatible authority and proof requirements.

Otherwise split the items into separate implementation plans and preserve the
relationship in their roadmap provenance. Do not turn a product roadmap into
one giant implementation plan.

## Required Plan Surface

Use `../templates/implementation-plan.md`. Every plan contains:

1. TL;DR;
2. plan identity and lifecycle;
3. selected roadmap sources or an explicit standalone origin;
4. current task;
5. high-level task ledger;
6. objective and acceptance oracle;
7. current-state assessment;
8. scope and non-goals;
9. implementation architecture and data flow;
10. critical path and parallel waves;
11. progressive phases and gates;
12. detailed task contracts;
13. validation ladder;
14. risks, blockers, and stop conditions;
15. change-control protocol;
16. handover notes;
17. roadmap-return contract;
18. decision and progress history.

The current-task and task-ledger regions use the template's bounded HTML
markers. A renderer may replace only bytes inside those two regions. It never
mutates GoalBuddy.

## Task Contract

Every task records:

- objective and rationale;
- inputs and prerequisites;
- deliverables;
- allowed and excluded files;
- dependencies and downstream unlocks;
- parallel mode and write owner;
- implementation steps;
- validation commands;
- acceptance evidence;
- stop and escalation conditions;
- rollback or recovery behavior;
- documentation obligations;
- next-owner handoff.

Parallel mode is exactly one of:

- `serial`;
- `parallel_read_only`;
- `parallel_disjoint_write`;
- `tandem_handoff`;
- `independent_gate`.

`parallel_disjoint_write` requires explicit non-overlapping ownership. Otherwise
one writer is the default.

For `document_only`, task status is `planned`. For board-backed modes, task
status is exactly one of GoalBuddy's canonical values: `queued`, `active`,
`blocked`, or `done`. Human prose may say completed, but the ledger and
`state.yaml` may not use `completed`.

## Validation And Synchronization

Use `../../scripts/validate_implementation_plan.py` before reporting a plan
ready. Board-backed plans must also pass the official GoalBuddy checker before
execution or a clean transition is claimed. The packaged validator performs
the local canonical GoalBuddy parity checks; an unavailable external checker is
reported as a proof limitation, never silently treated as having run.

After a GoalBuddy transition:

1. the GoalBuddy owner updates `state.yaml`;
2. the official GoalBuddy checker runs;
3. `render_implementation_plan_status.py` updates the bounded Markdown
   projection;
4. the owner adds the receipt and handover;
5. the implementation-plan validator runs;
6. operator status is generated from the validated files.

If the board is valid but the Markdown projection differs, report
`board_valid_plan_mirror_drift`. If the board is invalid, report the exact board
failure. Never claim a clean transition from chat memory.

## Change Control And Roadmap Return

New scope, tasks, paths, providers, irreversible actions, or acceptance claims
must be recorded as a plan revision and revalidated. Superseded tasks remain
visible with their replacement and reason; they are not deleted to make the
plan appear cleaner.

Feature closeout returns to the originating roadmap:

- accepted outcome and proof boundary;
- changed files or product surfaces;
- validation and independent review evidence;
- deferred work and remaining risks;
- roadmap items unlocked, revised, or still blocked.

The closeout may propose a roadmap update. It may not perform one without the
roadmap owner's authority.

