# Repository Discovery Contract

## Purpose

Discover is the Codexmax front door for an operator who has a repository but no
preselected outcome. It converts bounded local evidence into a useful choice of
directions. It does not execute a recommendation, replace GoalBuddy, or claim
that a roadmap item is current merely because it appears in Markdown.

## Read Boundary

Run `scripts/discover_repository.py` against one explicitly selected absolute
repository root. The scanner reads filesystem metadata for bounded regular
files. It reads content only from bounded Markdown roadmap candidates, and
projects only headings and unchecked checklist items.

It excludes common generated, dependency, VCS, cache, archived-report,
GoalBuddy-backup, raw-evidence, and virtual-environment directories. It does not
follow symlinks, read special files, read
secret-named files, or read roadmap files that are oversized or have more than
one filesystem link. Secret-like assignments in roadmap text are replaced by a
redaction marker. Output contains repository-relative paths only. Each signal
projects at most 100 relative paths and reports its total observed count
separately, so large repositories cannot make the result unbounded.

## Opportunity Model

Every opportunity has:

- a stable ID, category, score, horizon, title, and confidence;
- `basis.observed`: relative paths or an empty list;
- `basis.inferred`: the bounded reasoning from those signals;
- `basis.proposed`: the outcome Codexmax could pursue;
- a ready-to-run `$codexmax-orchestrator:codexmax-orchestrate` prompt.

Presence is an observation. Meaning, priority, and leverage are inferences.
Execution is always a proposal until the operator chooses it and Orchestrate
checks repository rules, active GoalBuddy state, scope, authority, validation,
and stop conditions.

## Operator Interaction

Render at most eight opportunities and lead with the highest-scored current
signal. Group choices as `next`, `quick_win`, or `strategic`. Include a compact
repository map and the proof limitations. Ask the operator to choose a numbered
direction, combine compatible directions, request a deeper read-only scan, or
describe a different ambition.

If the operator chooses, hand the selected proposed outcome and evidence paths
to Orchestrate. Do not ask them to rewrite the generated prompt or author an
internal goal packet.

## Fail-Closed Rules

- A truncated index cannot support absence-based recommendations.
- A filename does not prove current architecture, priority, completion, or
  ownership.
- Roadmap text does not outrank GoalBuddy board truth.
- Redacted, unreadable, invalid UTF-8, aliased, hard-linked, oversized, or
  excluded content supports no content claim.
- Discovery performs no write, dispatch, network call, credential access,
  dependency installation, acceptance, publication, or installation.
- Unknown or missing evidence stays unknown; polished wording is not proof.
