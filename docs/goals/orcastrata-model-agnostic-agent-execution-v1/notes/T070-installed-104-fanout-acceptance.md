# T070 Installed 1.0.4 Fan-out Acceptance

Status: accepted for independent re-audit

The exact installed Orcastrata Max 1.0.4 package ran three explicit lanes from
one frozen candidate, prompt, and rubric. Each lane had one attempt, a distinct
task ID, a distinct evidence directory, and a 30-second timeout. Parent
synthesis remained separate.

| Exact model | Result | Duration | Identity | Retry or fallback |
| --- | --- | ---: | --- | --- |
| `deepseek/deepseek-v4-pro` | timeout | 30,012 ms | bound before launch | none |
| `minimaxai/minimax-m3` | completed | 3,355 ms | validated | none |
| `xai/grok-4.6` | timeout | 30,012 ms | bound before launch | none |

All three lanes were configured, selected, and called through the approved
Command Code transport. The DeepSeek and Grok manifests record one terminal
non-retryable timeout. Their empty provider output did not pass response
identity validation and was not promoted as a result. The MiniMax manifest
records one successful attempt and validated response identity.

Evidence is retained at
`docs/goals/orcastrata-model-agnostic-agent-execution-v1/notes/T070-installed-104-fanout/fanout/`.
The lane directories are `lane-01-9408f7e20680`,
`lane-02-7181e131da13`, and `lane-03-a0b61af9fe73`.

This receipt proves installed 1.0.4 fan-out behavior. It does not claim that
DeepSeek Pro or Grok 4.6 completed the review.
