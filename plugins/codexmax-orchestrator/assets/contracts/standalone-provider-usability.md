# Standalone Provider Usability

## Purpose

This contract defines the external-provider claims that the standalone plugin
can present to an operator. It does not grant provider-call authority. Each live
call still requires a fresh task packet and current operator authorization.

## Current Installed Evidence

| Route | Current task-scoped status | Read-only ceiling | Important limit |
| --- | --- | ---: | --- |
| DeepSeek V4 Flash | usable for installed file-based read-only work | 100 turns | usage and cost can remain unknown |
| DeepSeek V4 Pro | usable for installed embedded-auditor read-only work | 100 turns | file-based Documenter parity is not proved |
| MiniMax M3 | transport usable for installed read-only work | adapter bounded | Parent review is mandatory because one dogfood result invented execution facts |
| Grok 4.6 | usable for installed file-based read-only work | 20 turns | reported usage and cost are retained when emitted |
| Claude Sonnet 5 | unavailable | 20 turns | the installed CLI session was not logged in |

The DeepSeek guarded-write lane remains capped at 20 turns. Current installed
acceptance is read-only. Historical task-scoped write canaries do not prove the
current integrated candidate's arbitrary write usability.

## Operator Sequence

1. Select one exact route. Do not allow automatic fallback.
2. Create one fresh task-owned working directory and evidence directory.
3. Bind the exact route, model, runtime, billing class, prompt, response schema,
   read scope, output scope, attempt count, and time limit.
4. Run the dispatcher plan command. Stop if the selected route is not eligible.
5. Obtain action-specific authority for the provider call.
6. Run one provider process. Do not retry, hedge, or substitute a model.
7. Validate the return manifest, exact response identity, output hash, changed
   paths, and compact telemetry.
8. Let Parent accept, revise, or reject the result before board integration.

## Truth Rules

- A requested model or route is not an observed identity unless the runtime
  emits bound evidence or the exact adapter contract supplies the identity.
- Unknown usage, cost, quota, or billing detail remains unknown.
- A successful provider process does not automatically accept its content.
- Advisory evaluations can influence review. They cannot choose a route or
  grant execution authority.
- Installed task-scoped usability is not protected-production qualification.
- Enterprise protected roots, service identity, credential agents, and
  production fan-out are deferred to AOL.

## Rollback Boundary

Keep the prior installed candidate and marketplace until the new candidate
passes installed parity and the operator accepts its usage result. Do not remove
or overwrite a rollback candidate during provider validation.
