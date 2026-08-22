# Desktop Thread Bridge Contract

## Identity

- Goal: `codexmax-desktop-supervision-v1`; checkpoint: `T004`.
- Role: native Desktop bridge contract.

## Outcome

- Outcome: define a fail-clear durable bridge for exactly one goal-lifetime
  visible Supervisor and zero ordinary top-level Worker chats.
- Proof boundary: contract/runtime design; fresh native functional proof remains
  required from Builder and independent Auditor tasks.

## Evidence

- T004 Scout observed native same-directory create, bounded read, message, and
  open controls while forward subscription remains unknown.

## Purpose

The bridge binds a Parent to one native visible Supervisor through an explicit
host adapter. The Supervisor is reused across checkpoints. Worker roles are
internal Supervisor activities unless a justified visible exception is
required. It persists opaque IDs and bounded read state; reports, transcripts,
and a growing collection of independent chats are rejected.

## Functional Topology Oracle

- Exactly one active Parent.
- Exactly one active visible Supervisor for the goal.
- Zero ordinary top-level Worker chats.
- Only recorded visible exceptions for operator request, required direct
  interaction, or material failure/audit evidence.
- A terminal visible exception is archive-ready.
- Checkpoint transitions reuse the same Supervisor ID and do not grow visible
  chat count.

Before creating any chat, the Parent preflights a persistent Supervisor plus
`internal_supervisor_activity`, `nested_hidden`, `grouped`, or an equivalent
bounded presentation. Separate thread IDs without containment do not pass. The
bridge fails before creation with a named `host_ux_limitation:*` reason.
The preflight also returns a durable receipt with `chat_creation_allowed`, the
named limitation, observed presentation, and `closest_truthful_design`. A
failed receipt always sets `chat_creation_allowed: false`; raising the stable
error does not replace that operator-facing decision record.

## Durable State

State contains `goal_id`, `active_checkpoint_id`, `checkpoint_history`,
`checkpoint_supervisor_ids`,
`parent_thread_id`,
`supervisor_thread_id`, `host_id`, `read_cursor`, deduplicated item IDs,
`recovery_epoch`, lifecycle, forward-subscription status, topology preflight,
internal activities, and visible exceptions.
Every checkpoint-history row has the same Supervisor ID. A missing row, a
different Supervisor ID, or a checkpoint transition that creates a new
Supervisor fails `checkpoint_supervisor_identity_changed` or a malformed-state
gate before the chat-volume oracle can pass.

## Native Controls

The adapter must supply `create`, `open`, `read`, and `message`. The topology
preflight must separately prove persistent Supervisor and internal Worker
presentation support. Missing capabilities fail with stable errors; a created
ID equal to the Parent ID, duplicate Supervisor, stale/fabricated ID, malformed
read, report/transcript input, ordinary visible Worker, and uncontained fanout
are rejected.

## Continuity

Forward subscription is explicitly `unknown` unless proven. Bounded newest
reads deduplicate item IDs. If subscription is unavailable and no durable cursor
exists, the bridge fails `continuity_loss_fail_clear`.

## Authority

The bridge does not grant authority, mutate GoalBuddy, or accept a checkpoint.
Only an actual native host adapter and fresh visible controls can satisfy the
Desktop oracle.

## Validation

- Focused bridge tests, full suite, repository validator, style, and whitespace
  checks must pass.

## Risks And Gaps

- Forward subscription remains unknown; continuity loss fails clearly.
- A report or transcript cannot substitute for a native adapter.
- The currently exposed Desktop create/fork surface declares separate threads
  but no containment/grouping control; until a host-level equivalent is
  demonstrated, new chat creation fails
  `host_ux_limitation:worker_containment_unavailable`.

## Handoff

- Produced: durable native bridge contract.
- Not produced: GoalBuddy mutation, authority grant, or acceptance.
- Validated: structural contract boundary.
- Not validated: independent native functional audit.
- Safe to use: as T004 Builder and Auditor input.
- Must verify: real visible create/open/read/message behavior plus the full
  chat-volume oracle across at least two checkpoints.
- Next owner: T004 Supervisor and T004-J Auditor.
- Requested state transition: `ready_for_review`.
- Parent decision requested: none; Parent alone accepts T004.
