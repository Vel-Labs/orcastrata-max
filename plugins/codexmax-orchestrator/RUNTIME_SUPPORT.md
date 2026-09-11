# Runtime Support And Ownership

Orcastrata is an orchestration layer, not a model. It defines semantic
roles, selects eligible routes, limits task authority, and records receipts.
The selected route still uses the exact model and runtime named in its receipt.

## Current Support Matrix

| Runtime surface | Current Orcastrata behavior | Ownership boundary | Not provided |
| --- | --- | --- | --- |
| Native Codex with Orcastrata loaded or explicitly invoked | The Parent projects an Orcastrata semantic role onto an allowed Codex `agent_type`, exact model, and reasoning effort before calling `spawn_agent` | Codex owns `spawn_agent` and executes the native child | No global interception of unrelated Codex spawns; no Orcastrata model weights |
| Native Codex without an active Orcastrata task path | No Orcastrata projection is promised | Codex owns routing and native defaults | Installing the plugin alone does not govern every task or child spawn |
| Configured OpenCode exact route | Orcastrata verifies and binds the exact tool, model, route, authority, and billing basis before provider dispatch | Orcastrata owns the supported adapter launch; OpenCode and its provider own their session and runtime | No login automation, credential storage, or eligibility from configuration alone |
| Configured Command Code exact route | Orcastrata verifies and binds a declarative exact model over the package-owned Command Code transport before read-only or isolated-development dispatch | Orcastrata owns selection, task authority, launch, identity checks, and receipts; Command Code and its provider own their session, quota, billing, and runtime | No login automation, credential storage, arbitrary executable configuration, or eligibility from configuration alone |
| Standalone and provider-neutral contracts | Contracts, schemas, adapters, and conformance checks can describe a future or separately qualified dispatch boundary | Each new transport requires its own package-owned adapter, qualification, and task authority | Their presence in the package is not installed live-provider execution for that transport |
| Claude session-only plugin path | Candidate-supported; uses observed native Agent surface and session-only `--agents` configuration | Claude host owns its workers; Orcastrata provides bounded assignment packets | No automatic worker interception; requires authorized host validation and strict manifest validation |
| Grok, standalone MiniMax, and other host-native packages | Roadmap or retained candidate work only | The external host owns its workers until an Orcastrata integration exists | No current public V1 host package or automatic worker interception |

## What Native Codex Governance Means

For an Orcastrata-controlled native task, the Parent must run the Codex runtime
projection before spawning a child. A fixed-role conflict or ambiguous default
inheritance fails closed. A valid projection records the semantic role, native
agent type, exact model, reasoning effort, inheritance, fallback, runtime
surface, and route authority.

This is governed spawning, not a global Codex hook. An ordinary Codex task can
still spawn a native child without Orcastrata if Orcastrata was not loaded or
invoked for that task.

## What External Dispatch Governance Means

For a supported OpenCode or Command Code route, Orcastrata owns the route
resolution and adapter-dispatch decision. The external tool still owns its
authentication, provider session, quota, billing, and execution runtime. Fresh
preflight must establish those facts before each dispatch.

Provider-neutral contracts are reusable architecture. They become an
operational harness only after an exact adapter, runtime, capability,
qualification, authority, and execution receipt are established.

## Research Boundary

A future Codex integration may investigate host-supported pre-spawn middleware,
custom native agent registration, or another enforceable collaboration hook.
Until that capability is demonstrated, Orcastrata documentation and receipts
must describe the Codex surface as Parent-governed rather than globally
intercepted. The Claude session-only candidate path follows the same principle:
the invoking chat is Parent/PM and owns scope, integration, verification, and
final acceptance. Claude Agent/model availability, authentication, hooks,
delegation, telemetry, and runtime acceptance require a later authorized host validation step. Static package files do not prove installation, release, live
execution, provider qualification, or acceptance.
