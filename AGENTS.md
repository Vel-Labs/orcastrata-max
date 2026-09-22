# Orcastrata Max Agent Guide

## Start In Ordinary Language

1. Read the user's request.
2. Read this guide and the nearest local `AGENTS.md`.
3. Inspect the relevant files before you propose a change.
4. Preserve the requested outcome, scope, and safety boundaries.
5. Ask only when a decision is materially ambiguous or needs approval.

## Execution Priority

1. Preserve safety, authority, user data, and external-effect boundaries.
2. Prove the primary product hypothesis through the smallest real end-to-end path.
3. Implement the smallest change that improves that observable result.
4. Run proportional validation.
5. Record governance, audit, package, and lifecycle evidence.

Governance artifacts do not count as product progress. Do not let them delay a
safe product proof.

## Parent Ownership

- Keep one visible Parent responsible for the outcome.
- The Parent plans, integrates, verifies, and gives the final answer.
- Keep simple work in the Parent.
- Delegate only independent work that improves confidence or shortens the path.
- Give each worker a bounded task, allowed files, and acceptance condition.
- Preserve other contributors' work in a dirty repository.
- Do not create workers, tests, or reports only to increase activity.
- Available model capacity is not a reason to delegate.

## Tool And Model Requests

- Public V1 exact-tool requests support only OpenCode and Command Code.
- Treat other provider entries as configured candidates, not supported routes.
- Treat `Use model X through tool Y` as an exact instruction.
- Verify the configured tool session and exact model before dispatch.
- Preview the task-local route before execution.
- Stop if the tool, model, route, or billing path does not match.
- Do not silently substitute another tool or model.
- Before an external call, verify authority to send the task content and use the
  selected provider account, privacy terms, quota, and billing path.
- Do not log in, refresh authentication, or copy credentials.
- Keep provider authentication inside the provider's installed tool.
- Do not save a tool/model pairing without explicit approval.

## Authority

- Task grants control read and write scope.
- Model identity, provider identity, and reasoning effort grant no authority.
- Intersect the task grant with fresh adapter capability evidence.
- Fail closed when scope, identity, or evidence is missing.
- Never expose credentials, private keys, tokens, or private task content.
- Do not publish, install, or call external providers without current authority.

## Changes

- Keep diffs small and reviewable.
- Change only files required for the outcome.
- Do not delete, move, or rename files without explicit authority.
- Do not use blanket staging such as `git add .`.
- Do not revert unrelated changes.
- Use clear names and keep compatibility IDs stable unless migration is approved.
- Keep `codexmax-orchestrator` and `codexmax-*` as V1 compatibility IDs.

## Validation

- Test observable behavior and the risk introduced by the change.
- Add tests only for a distinct behavior, regression, or authority boundary.
- Use focused tests during implementation.
- Check known consumers when a shared contract changes.
- Run the full repository suite once at package or release freeze.
- Do not rerun an expensive green command without changed inputs or a stated reason.
- A passing synthetic test does not prove installation or a real user journey.
- Classify failures as product, baseline, or harness/environment defects.
- For a benchmark, retrieval system, model pipeline, or optimization, inspect
  exact input, output, and failure behavior on one or two representative cases
  before a broad study, package freeze, release candidate, or aggregate claim.
- After two harness failures before product evidence exists, stop extending the
  harness and use a direct executable path.
- Do not package or name a release candidate with a known material regression.
- Keep work status separate from accounting status. Report missing usage as
  `unknown`; do not infer it from configured routes or worker count.

## Operator Burden

- Own routine commands, retries, environment checks, and validation inside the
  approved scope.
- Do not ask the operator to run a command only to satisfy an Orcastrata-created gate.
- Validate every non-secret prerequisite before one complete unavoidable operator action.

## Handoff

- List files changed.
- List commands and validation results.
- State assumptions and remaining risks.
- Distinguish source, package, install, provider, and publication proof.
- Do not claim completion beyond the evidence.
