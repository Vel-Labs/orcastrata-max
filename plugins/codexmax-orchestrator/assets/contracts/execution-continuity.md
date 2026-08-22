# Execution Continuity Contract

## Purpose

Codexmax owns the efficient continuation of an authorized execution tranche.
Once the operator has approved the outcome, writable scope, action classes,
billing basis, and proof boundary, ordinary execution decisions are Supervisor
work rather than repeated operator homework.

This contract separates planning estimates from authority limits and defines
the durable decision surface used by the local runtime and a future
Orcastrata/AOL operator client.

## Authority Boundary

The Supervisor may automatically continue, revise a task packet, compress
context, start a fresh continuation run, split work, reroute, retry, repair,
reforecast, and propose the next GoalBuddy transition when all actions remain
inside recorded authority.

The Parent/PM owns outcome integration and successor routing. A failed repair
round changes strategy; it does not create a human gate. Repair-budget
exhaustion stops repeated micro-patching, not project management. When a safe
in-scope successor exists, the Parent/PM must continue through an authorized
redesign or explicit task split.

Pause for operator or Parent authority only when at least one of these is true:

- the outcome, writable paths, action class, proof boundary, or permitted
  consequence expands;
- a new provider, billing basis, credential mechanism, install, destructive
  action, push, publication, or irreversible action is required;
- expected external cash spend increases beyond recorded cost authority;
- an explicit operator token cap is reached;
- acceptance requires a waiver, release decision, public naming decision, or
  other reserved human judgment;
- the architecture path is exhausted after the permitted redesign, split,
  reroute, and repair strategies have been attempted and recorded;
- useful authorized local work is exhausted by a named external condition.

Difficulty, an inaccurate estimate, context pressure, a failed attempt, or a
soft forecast crossing is not new authority.

## Forecasts Are Not Caps

Use distinct fields:

- `token_forecast`: the current planning estimate. It is soft, revisable, and
  measured when telemetry exists.
- `explicit_token_cap`: a hard operator-authored ceiling. The default is
  `null`. Codexmax must not manufacture one from a forecast, task packet,
  historical estimate, or goal prompt.
- `cost_authority`: the recorded provider and external-cash boundary. It
  remains hard even when `explicit_token_cap` is null.

When usage reaches or exceeds `token_forecast` and no explicit cap or cost
boundary is crossed, the Supervisor must:

1. record oracle movement, accepted artifacts, failures, and remaining work;
2. diagnose the estimate miss and identify avoidable context or routing cost;
3. revise, split, narrow, or reroute the next packet when useful;
4. replace the forecast with an evidence-backed estimate;
5. continue in the current run or create a durable rollover pack and continue
   in a fresh run.

It must not mark the goal `blocked`, request a token-ceiling increase, or
disable Workers solely because its own forecast was low.

## Continuity Decision Loop

At every milestone, forecast crossing, context-pressure signal, failed
attempt, or candidate closeout:

1. `observe`: read GoalBuddy board truth and hash-bound execution evidence.
2. `classify decision owner`: use `pm` unless a real human fact, material
   product or structural UX decision, external action, credential action,
   material risk decision, goal or oracle change, or authority expansion is
   required.
3. `choose successor`: select a repair, changed hypothesis, redesign, task
   split, reroute, rollover, or candidate-integration action.
4. `implement`: execute the successor inside recorded authority.
5. `verify`: run the efficient validation action for the exact source revision.
6. `integrate`: accept or reject the candidate, integrate evidence, and
   transition the task. Delegation alone is incomplete PM work.
7. `continue`: repeat the loop or emit the exact consequential human-owned
   decision.

The compact form is:

`observe -> classify decision owner -> choose successor -> implement -> verify -> integrate -> continue`

Before dispatching validation or repeating a validation command, apply the
[Efficient Delivery Contract](efficient-delivery.md) and run
`../../scripts/plan_efficient_validation.py`. Bind focused proof, Parent review,
source freeze, and the one Owner-executed full-suite pass to the exact source
revision. Worker, Tester, Documenter, and Auditor lanes never own the repository
full suite. A report-only correction after a matching Owner pass uses artifact
validation; unchanged source does not justify another full-suite run.

Canonical continuity actions are:

- `continue_current`
- `continue_rollover`
- `revise_packet`
- `split_work`
- `reroute`
- `repair`
- `candidate_closeout`
- `request_authority`
- `explicit_cap_reached`
- `needs_parent_repair`
- `waiting_external`

`continue_rollover`, `revise_packet`, `split_work`, `reroute`, and `repair`
remain execution, not acceptance. GoalBuddy remains board truth and Parent
Codex remains final acceptance authority.

### Advisory Candidate Precedence

Route-Fabric `candidate_ready` is an advisory observation, never an acceptance
or dispatch command. Continuity assessment applies hard-stop precedence before
candidate closeout: operator or authority expansion, an explicit token cap,
useful authorized work exhaustion, validation failure, and terminal
`execution_unknown` or identity/integrity failure all block
`candidate_closeout`. A validation failure selects bounded `repair` when one
is available; otherwise it selects `needs_parent_repair` and requires a parent
decision. External exhaustion selects `waiting_external`. No candidate may
retry, reroute, authorize, mutate the board, or bypass validation.

## Progress And No-Improvement

Progress is evidence-backed movement toward the acceptance oracle. It may be:

- a newly passing oracle row;
- a Supervisor-accepted expected artifact;
- a verified defect removal;
- a completed dependency that unblocks a checkpoint;
- a reduced uncertainty or risk that changes the next executable action.

Token use, elapsed time, command count, prose volume, and Worker claims are not
progress by themselves. Preserve cumulative usage as telemetry.

The configured `no_improvement_window` counts consecutive completed attempts
without evidence-backed progress. Before `needs_parent_repair`, the Supervisor
must evaluate packet revision, work splitting, compatible rerouting, and
bounded repair. It may select the applicable subset, but the receipt must name
why each unused strategy was inapplicable. A single failure never proves an
impasse.

`needs_parent_repair` is an internal routing state. It does not mean that the
human must decide a technical implementation detail. The Parent must choose an
authorized redesign or explicit task split when one exists. Only a consequential
human-owned condition may set `operator_decision_required: true`.

## Decision ownership and terminal stops

The deterministic assessor accepts an optional `decision_context`. It records
concepts equivalent to:

- `decision_owner: pm | human`;
- `escalation_class`;
- `safe_successor`;
- `human_fact_required`;
- `material_product_decision_required`.

It also records external-action, credential-action, oracle-change,
authority-expansion, terminal-platform-error, architecture-exhaustion, and
repair-budget facts when they apply. A human-owned decision must name at least
one consequential condition. A human gate cannot also name a safe PM successor.

The assessor rejects a ceremonial human gate. It sets `stop_allowed: false`
when the PM owns the decision and a safe successor exists. It may set
`stop_allowed: true` only for a real human-owned condition, an operator-authored
cap or stop, a terminal platform error, or an explicitly exhausted architecture
path.

Do not request human approval for implementation details already determined by
the goal, oracle, authority, and safety boundaries. Human approval must be
informed, consequential, and expressed in product or risk terms.

## PM status contract

Keep each human update to one screen. Include:

- outcome state;
- accepted or rejected candidate;
- current gate;
- exact blocker;
- PM decision;
- next automatic action;
- actual human action, if any.

Put commands, hashes, repair history, and detailed evidence in durable receipts.
Use `none` when no human action is required.

## Durable Rollover Pack

When context pressure makes a fresh run more efficient, persist a bounded
rollover pack before continuing. It contains:

- goal and board paths, hashes, active checkpoint, and authority receipt;
- acceptance oracle with satisfied, unsatisfied, and disputed rows;
- accepted artifact paths and hashes;
- failures, rejected claims, and attempted repair strategies;
- current route and replacement constraints;
- changed files, commit/rollback boundary, and dirty-worktree ownership;
- commands already run and their results;
- old forecast, actual usage, new forecast, and estimate rationale;
- the next packet, exact first action, verification ladder, and stop rules.

The fresh run must read this pack and current board truth, reject drift, and
continue the same authorized tranche. It must not reconstruct state from chat,
repeat completed discovery, or ask the operator to rewrite the goal.

## Progressive Git Checkpoints

For repository work, create reviewable local commits at accepted architectural,
contract, implementation, verification, and closeout boundaries when the
repository policy and operator authority allow commits. Record parent and
resulting SHAs plus exact included paths. Never include unrelated dirty files,
push without authority, or use a commit as acceptance proof.

## Orcastrata/AOL Runtime Projection

Codexmax owns execution events and continuity decisions. GoalBuddy owns board
truth. AOL Core may ingest their typed, versioned projections and join them
with policy, approval, evidence, and assurance state. The Orcastrata/AOL client
may render and act on that joined read model.

The minimum operator projection includes:

- goal, checkpoint, phase, current action, and canonical owner;
- oracle coverage and movement since the prior milestone;
- active and completed lanes, routes, attempts, failures, and repairs;
- token forecast versus observed usage, explicit cap, external cost authority,
  and reforecast rationale;
- context pressure, rollover-pack identity, and continuation status;
- changed paths, progressive commits, validation results, evidence links, and
  proof boundary;
- pending GoalBuddy transition and any exact operator or Parent decision.

The GUI is a projection and command surface, not a second source of truth.
Operator actions create typed command or authority proposals. Codexmax and AOL
Core validate those proposals against current hashes and policy before runtime
or GoalBuddy state changes. Stale projections fail closed.

This repository contract defines the producer and projection boundary only. It
does not prove an AOL adapter, installed GUI, native Desktop continuation, or
cross-repository integration.
