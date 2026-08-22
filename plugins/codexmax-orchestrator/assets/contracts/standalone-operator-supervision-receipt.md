# Standalone operator supervision receipt V1

This receipt is a closed, externally authenticated, read-only snapshot from the
pinned package-host TLS channel. It binds the admitted workspace, source and
candidate, service and binding state, runtime thread/generation, preset
selection, native identity chain, topology, continuity, recovery, and a
monotonic snapshot chain. Its self-digests provide integrity only; the TLS host
response authenticates the external seal.

A positive receipt requires `live_host`, `native_available`, `corroborated`,
and `native_proved`; a validated native identity digest/chain/event sequence;
Desktop thread locators returned by the host; exactly one Parent and one active
stable Supervisor; no ordinary top-level Worker; bounded internal Worker count;
current host read/subscription cursor; and current or reconciled recovery.
Model, reasoning effort, and route remain literal `unknown`.

The receipt is veto-only. It cannot enable an operator control, issue context,
alter an effect request, register an action, or write state. Collaboration data
cannot satisfy this contract. Missing or unproved evidence produces an
`unavailable` wrapper and clears cached positive supervision.

Proof from test fixtures is mechanics-only, never native/Desktop proof.
