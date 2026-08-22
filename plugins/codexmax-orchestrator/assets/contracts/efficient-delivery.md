# Efficient Delivery Contract

## Purpose

Codexmax must optimize for accepted outcomes, not validation volume. Validation
remains proportional to risk and bound to the exact source revision, while
repeated proof that cannot change the Parent decision is treated as avoidable
work.

Use `../../scripts/plan_efficient_validation.py` when selecting validation for
a candidate or considering a repeated validation command. Persist its result
only when it changes the next action or identifies a policy violation. The
planner is deterministic and non-executing: it selects the next proof action
but does not run commands, mutate GoalBuddy, call a provider, or claim
acceptance.

## Default Validation Ladder

For source or behavior changes, use this order:

1. Define a compact acceptance matrix with the required functional, boundary,
   regression, and artifact checks.
2. Materialize a durable receipt or bounded diff summary. Do not make a live
   transcript the review surface.
3. The Worker runs focused tests that exercise the changed behavior and its
   nearest regression boundary, then returns the candidate.
4. Tester and Auditor lanes perform only the targeted independent checks named
   by the acceptance matrix. They do not run the repository full suite.
5. The final Owner or Parent performs read-only diff and design review against
   the acceptance matrix and freezes the reviewed source revision.
6. The final Owner or Parent runs the repository full suite exactly once
   against that frozen revision.
7. The final Owner or Parent decides acceptance from the exact proof.

Any source change after step 3 invalidates later proof for the old revision and
restarts the ladder at focused validation. A failed focused or full check
routes to repair; it does not authorize repetitive unchanged reruns.

For report, receipt, or documentation-only corrections after a matching full
source pass, run artifact validation only. Do not repeat focused or full source
suites unless source bytes changed or the Parent explicitly identifies a new
source-level risk.

## Full-Suite Authorization

The full suite is authorized only when all are true:

- the requesting role is the final `owner`;
- the acceptance matrix is ready;
- a durable review surface exists;
- focused validation passed on the current source revision;
- Parent review approved that same source revision;
- that revision is frozen; and
- no matching full pass already exists.

The planner emits `run_full_validation` only to the final Owner at this
boundary. Worker, Tester, Documenter, and Auditor requests resolve to
`handoff_to_owner_for_full_validation`. A full result executed by any non-Owner
role is non-authoritative, remains visible as wasted work, and cannot satisfy
the acceptance gate. A second Owner full run for the same frozen revision is
redundant and must be disclosed. If a matching Owner full pass already exists,
continue to artifact validation or candidate closeout instead.

If the Owner suite fails, return a bounded repair packet. The repaired source
receives a new revision identity, focused proof, Owner review, and one new Owner
full-suite run. Do not rerun the suite against an unchanged failed revision.

## External Advisory Use

External advisory or provider-diverse review is optional support, not ordinary
proof. Use it only for a major architecture, security, release, or final
acceptance gate with current authority. Routine checkpoints use repository
evidence, the Parent review, and independent local validation. A routine
advisory request resolves to `skip_routine_advisory`; a major advisory without
authority resolves to `request_advisory_authority` and does not block useful
authorized local work.

## Coordination Defaults

- One writer owns each overlapping source surface. Add early read-only review
  when design risk is material.
- Worker packets authorize focused checks only. Tester and Auditor packets may
  authorize targeted independent checks, never the repository full suite.
- The final Owner session owns the sole full-suite command and receipt for the
  frozen source revision.
- Build new assignments from GoalBuddy board truth and bounded durable
  receipts. Do not replay completed discovery or paste full transcript history.
- Keep prompts to the active task, authority, owned paths, acceptance matrix,
  current hashes, next action, and stop rule.
- Read receipts and diffs first. Read raw transcripts only for a named disputed
  claim that cannot be resolved from bounded evidence.
- Preserve failed evidence and known baseline failures without rerunning them
  at every report-only milestone.

Parent Codex remains the only acceptance authority. This policy changes the
default proof sequence; it does not weaken a repository-required release,
security, legal, or safety gate.
