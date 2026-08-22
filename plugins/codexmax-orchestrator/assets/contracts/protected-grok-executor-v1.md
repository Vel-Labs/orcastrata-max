# Protected Grok executor v1

## Status

This source-local Parent observer cannot launch Grok. It validates a future or
synthetic event stream against one prepared scoped-write session.

## Observation contract

Every event may repeat the bound task, attempt, session, and model. A different
value fails closed. The observer accepts at most 20 assistant turns and exactly
three file events: one read, one bound write or edit, and one final read. Each
event uses the exact target. Write content must equal the bound after content.
Edit content must equal the bound before and after content. Early, repeated, or
missing terminal results fail closed.

The source-local journal models one attempt. Interruption becomes
`execution_unknown`. Consumed and unknown states reject replay. No retry,
fallback, hedge, or substitution is allowed.

## Proof boundary

An observer receipt has `provider_called: false`, `accepted_by_parent: false`,
`protected_production: false`, and `t062_proved: false`. Synthetic events and
public digests cannot promote these values or prove billing, clean isolation,
provider execution, installation, release, or protected-host facts.
