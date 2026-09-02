# AOL Integration Handoff for Orcastrata GitHub Umbrella V1

## Purpose

This document is a downstream handoff for the closed-source AOL product. It is
not the implementation plan for open-source Orcastrata. The Orcastrata plan is
`orcastrata-github-umbrella-plan.md`.

AOL can consume the accepted Orcastrata behavior after standalone dogfood. AOL
must keep its own product state, user consent, connector policy, Assurance,
economics, recovery, and user experience. Orcastrata must remain usable without
AOL.

## Product Boundary

| Concern | Open-source Orcastrata | Closed-source AOL |
| --- | --- | --- |
| Standalone execution | Owns umbrella planning, worker routing, PR monitoring, and audit contracts | Consumes or adapts them |
| Durable work state | Existing GoalBuddy and WorkGraph contracts | AOL workspace, goal, and product state |
| GitHub access | Local authenticated `gh` through a credential-blind adapter | AOL chooses local `gh` or its existing OAuth/API connector |
| User authority | Operator packet and explicit effect confirmation | AOL consent UX, action policy, and Assurance decision |
| Acceptance | Orcastrata package and standalone dogfood oracle | AOL product and real-user journey oracle |
| Search and recall | Emits versioned events and receipts | AOL Atlas and Graph Engineering can index accepted artifacts |

## What AOL Receives

A frozen accepted Orcastrata release should expose versioned public contracts
for:

- umbrella request and deterministic preview;
- issue packet, dependency edges, scope, non-goals, acceptance, and validation;
- worker assignment, attempt, branch ownership, repair, and PR observations;
- normalized external-effect and reconciliation receipts;
- scoped audit and `/orcastrata-audit-full` verdicts;
- token, latency, cost, correction, and provider fields, with `unknown` when the
  runtime cannot prove them.

These contracts are the handoff surface. AOL must not depend on Orcastrata
internal files, private board layouts, hook implementation details, or an
unreleased worktree.

## AOL Integration Choices

AOL can use one of three approaches after Orcastrata acceptance:

1. Embed or vendor the public Orcastrata runtime.
2. Invoke a supported Orcastrata runtime adapter as a product component.
3. Reimplement the accepted public behavior inside AOL when eliminating the
   external runtime dependency has enough product value.

The initial AOL plan should select one approach. Do not build a generic adapter
for all three before that decision.

## GitHub Connector Placement

Local `gh` is valid for AOL desktop or local-runtime use. AOL can discover the
trusted executable and authenticated session without reading a token. The
operator or AOL product state must bind the exact host and repository. Terminal
authentication proves readiness only.

AOL already has a GitHub OAuth/API connector for hosted or non-`gh` operation.
Keep it. AOL chooses one transport before each effect and records the choice in
the prepare receipt. It must not switch transports after a possibly-started
effect. AOL must not add a second OAuth implementation only to match Orcastrata.

## AOL-Owned Responsibilities

AOL owns:

- workspace, goal, umbrella, issue, dependency, consent, and action-decision state;
- connector discovery, account selection, repository binding, and product UX;
- privacy, provider, economics, route, retention, and Assurance policy;
- effect admission, idempotency, reconciliation, unknown-outcome recovery, and merge;
- real-interface proof and the final AOL acceptance decision;
- Atlas and Graph Engineering ingestion after accepted effects and receipts.

Orcastrata receipts are evidence. They do not mutate AOL canonical state or
grant AOL action authority.

## Required Translation Layer

The AOL integration should translate, not mirror, the public Orcastrata
contracts:

```text
AOL goal and consent
  -> Orcastrata umbrella request
  -> versioned Orcastrata plan, worker, PR, and audit events
  -> AOL normalized observations and Assurance evidence
  -> AOL connector effect decision
  -> GitHub through local gh or existing OAuth/API connector
  -> AOL reconciliation and accepted product state
  -> Atlas and Graph Engineering indexing
```

Use stable source IDs and immutable digests across the translation. Keep AOL
state IDs and Orcastrata IDs distinct. Record their mapping in AOL rather than
changing the Orcastrata package.

## AOL Acceptance Oracle

AOL integration is accepted only when a separate AOL plan proves:

1. A user can select or confirm the exact GitHub account and repository.
2. AOL displays the umbrella preview and every proposed write before consent.
3. Repeated actions do not duplicate GitHub effects.
4. AOL can recover an unknown `gh` or API outcome by observation.
5. Orcastrata worker and audit evidence maps into AOL without granting authority.
6. Local `gh` and existing OAuth/API routes produce the same normalized AOL
   observations where both are supported.
7. Merge requires fresh AOL Assurance and explicit product policy.
8. Atlas and Graph Engineering receive accepted artifacts with provenance,
   uncertainty, and relationship edges.
9. The real AOL interface proves the complete user journey. Contract or
   synthetic tests alone are insufficient.

## Admission Gates

Start an AOL implementation board only after:

- standalone Orcastrata T090 accepts a frozen package candidate;
- AOL selects embed, invoke, or reimplement;
- the AOL owner selects local-only, hosted-only, or dual connector support;
- AOL freezes its consent and merge behavior;
- a clean AOL worktree and exact source paths are assigned;
- current AOL connector, Assurance, Atlas, and Graph Engineering contracts are
  re-read from checkout truth.

## Non-Goals for This Handoff

- No AOL source change or roadmap mutation now.
- No claim that current Orcastrata is accepted or released.
- No requirement that AOL depend on an external Orcastrata runtime.
- No duplicate GitHub client, OAuth flow, GoalBuddy board, or graph engine.
- No schedules, autonomous merge, production GitHub effect, or credential access.

## Handoff Receipt

- Source: standalone Orcastrata plan and its frozen adversarial review artifacts.
- Current status: advisory handoff only.
- Implementation authority: not granted.
- GitHub effects: none.
- AOL files changed: none.
- Main open decision: embed, invoke, or reimplement after Orcastrata dogfood.
