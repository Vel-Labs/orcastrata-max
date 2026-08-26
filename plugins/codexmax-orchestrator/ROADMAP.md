# Orcastrata Roadmap

Orcastrata is the product family. Orcastrata Max is the open agentic
orchestration layer. This roadmap separates current behavior from planned
work. It does not promise a release date or prove an untested host.

## Product Family

```text
Orcastrata
├── Orcastrata Max       agent orchestration plugin
├── Orcastrata Ground    workspace preparation
└── Orcastrata Control   future interface and assurance plane
```

## V1: Native-First Codex

V1 starts useful work with native Codex. One visible Parent owns the outcome,
integration, and final acceptance. Native workers can assist when they add
material value. Optional provider adapters can add task-scoped worker routes,
but they are not required for first use.

OpenCode and Command Code are the public V1 exact-tool request surfaces. Their
configured models still require fresh session, identity, privacy, quota,
billing, and task-scope checks before use.

V1 also provides on-demand project, month, and explicitly registered-workspace
usage readouts. It does not provide recurring scheduled summaries. It does not
guarantee counters that a host does not report.

The current package name is `codexmax-orchestrator`. Current skills use the
`codexmax-*` namespace. These technical IDs remain supported for compatibility.
Read [Getting Started](GETTING_STARTED.md) for the first-use journey.
Read [Runtime Support And Ownership](RUNTIME_SUPPORT.md) for the current
host-by-host boundary.

Native V1 governance is Parent-controlled: Orcastrata projects a route before
an active Orcastrata Parent calls Codex `spawn_agent`. It is not a global Codex
spawn hook and does not replace Codex models with Orcastrata models.

## Next: Public Package

The first public package must provide:

- a clear license, support route, security policy, and repository identity;
- a self-contained install source and reversible upgrade path;
- exact package, cache, and installation evidence for one frozen candidate;
- compatibility guidance for the existing technical IDs; and
- an independent public-package audit.

Publication is a separate operator action. Local source or package validation
does not prove publication.

## Later: Provider-Neutral Hosts

Future versions can package Orcastrata Max for Claude, Grok, standalone
MiniMax, and other supported agent environments. Current configuration entries
for these providers are candidates, not public V1 dispatch support. Each host
package must use that host's trusted authentication and capability surfaces.
Adapter configuration describes the maximum operations a route can support.
The task grants its actual read or write scope.

No other host package is current V1 proof. Provider-neutral contracts do not
prove provider authentication, availability, billing, quota, or production
readiness.

## Research: Codex Host Interception

Research may determine whether Codex exposes supported pre-spawn middleware,
custom native agent registration, or another enforceable collaboration hook.
Until demonstrated, the supported architecture remains an Orcastrata-governed
Parent path. Installation alone does not place Orcastrata between every Codex
task and `spawn_agent`.

## Future: Orcastrata Control

Orcastrata Control can become the interface and assurance plane for execution
state from Orcastrata Max. It must not replace the Parent's acceptance
authority or GoalBuddy board truth.

Orcastrata Control is roadmap work. AOL C60 remains inactive.
