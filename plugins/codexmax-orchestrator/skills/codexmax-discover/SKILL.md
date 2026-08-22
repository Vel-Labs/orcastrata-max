---
name: codexmax-discover
description: "Public Discover entry — Show how Codexmax can help a repository by mapping files, roadmap work, risks, and high-leverage project opportunities."
---

# Codexmax Discover

Use this when the operator has a repository but no fixed outcome, asks how
Codexmax can help, wants ideas, asks what to improve next, or wants Codexmax to
lead from current project evidence.

## Method

1. Read the nearest repository rules and inspect active GoalBuddy state before
   treating any planning artifact as current truth.
2. Read the [Repository Discovery Contract](../../assets/contracts/repository-discovery.md)
   and the [Orcastrata Project Context Contract](../../assets/contracts/orcastrata-project-context.md).
3. Resolve the nearest valid `.orcastrata/project.json` marker. Treat its
   bounded context descriptor as evidence only. If a workspace marker exists,
   read explicit registered roots only.
4. Resolve `<plugin-root>` with `<plugin-root> = Path(SKILL.md).parents[2]`.
5. Run:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python3 -B <plugin-root>/scripts/discover_repository.py \
     --repo-root <absolute-repository-root>
   ```

   For an explicit registered-workspace review, use `--workspace-root
   <absolute-workspace-root>` instead. Do not combine the two root options.

6. Render the canonical result using the
   [Repository Opportunity Report](../../assets/templates/repository-opportunity-report.md).
7. Present a concise numbered menu, normally three to eight directions. Lead
   with current GoalBuddy or roadmap-backed work when it is demonstrably
   current; otherwise show quick wins and strategic options without inventing
   urgency.
8. Let the operator choose a number, combine compatible directions, request a
   deeper read-only inspection, or describe another ambition.
9. Pass the chosen proposed outcome and evidence paths to
   `$codexmax-orchestrator:codexmax-orchestrate`. The operator does not need to
   copy or rewrite the generated handoff.

## Evidence Language

Keep `Observed`, `Inferred`, and `Proposed` separate. A path or filename proves
only that the entry was indexed. An unchecked roadmap item is a planning signal,
not accepted board truth. An absent file supports a recommendation only when the
index is complete. Use relative evidence paths and name every limitation that
changes the recommendation.

## Read-Only Boundary

Discovery itself performs no file write, GoalBuddy transition, provider call,
network access, credential access, dependency installation, recommendation
execution, acceptance, installation, push, publication, or deployment. If the
operator selects a direction, Orchestrate performs its normal conflict,
preview, authority, validation, and stop-rule sequence before any action.
