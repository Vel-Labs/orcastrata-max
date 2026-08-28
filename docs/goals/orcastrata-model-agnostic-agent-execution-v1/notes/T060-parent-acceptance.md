# T060 Parent Acceptance Receipt

## Result

T060 is accepted for explicit adversarial fan-out behavior.

The installed controller admitted three exact Command Code model lanes from one
frozen candidate and rubric. It created distinct task IDs, evidence paths, and
artifact paths. It started one process per lane. It did not retry or substitute.

## Live evidence

- DeepSeek Pro: admitted and started. It timed out after 90 seconds. It returned
  no artifact. A prior installed T030 task completed with this exact model in
  12.4 seconds, so this is a task-completion failure, not an admission failure.
- MiniMax M3: admitted, started, and completed in 8.4 seconds. The response
  identity matched `minimaxai/minimax-m3` through Command Code. The artifact
  passed the strict response schema. No fallback or retry occurred.
- Grok 4.6: admitted and started. It timed out after 90 seconds. It returned no
  artifact.

The live aggregate correctly reported one completed lane and two rejected
lanes. Usage, quota, and cost remained unknown because Command Code did not
report them.

Evidence root:
`docs/goals/orcastrata-model-agnostic-agent-execution-v1/notes/T060-installed-fanout-v4/`

## Validation

- 33 focused T020-T060 tests passed after the timeout and CLI repairs.
- Source and installed hashes matched for the fan-out and task runners.
- Two independent Luna audits were used. The first found the generic-route
  identity blocker. The second accepted the repair before live execution.

## Parent synthesis

MiniMax returned two proposed defects. The Parent did not accept them. The first
claimed possible path collisions, but the controller derives unique lane IDs and
the focused test rejects duplicate requests and proves unique task, evidence,
and artifact paths. The second requested signed provider attestation. The
current boundary instead binds the fixed preflight, exact model CLI argument,
task grant, strict returned identity, and no-fallback fields. It is a possible
future hardening measure, not a defect established by the reviewed facts.

## Remaining risk

DeepSeek Pro and Grok 4.6 did not complete these adversarial prompts through
Command Code. Orcastrata now reports that condition truthfully. It does not
misstate it as a configuration failure or silently replace either model.
