# Standalone Runtime Python Client v1

`scripts/standalone_runtime_client.py` is a standard-library-only client for
the accepted local standalone runtime read surface. `CLIENT_VERSION` is `1`
and the only supported API version is string `"1"`.

## Boundary

`StandaloneRuntimeClientV1` exposes `inspect`, `reconnect`, and `shutdown`.
Each method accepts a workspace identifier and one closed
`WorkspaceSelection` v1 object containing exactly `api_version`,
`workspace_id`, and `workspace_path_sha256`.

The default transport is the fixed package-sibling
`standalone_runtime_service` in-process surface. It resolves only the closed
workspace identifier in the current local service context. There is no URL,
server, socket, subprocess, executable, module, filesystem locator, dynamic
import, environment selector, credential, provider, MCP, GoalBuddy, or AOL
route. A directly injected callable is an embedding/test seam only. It receives
exactly `(operation, workspace_id, selection)` and does not change validation,
authority, or proof boundaries.

The packaged OpenAPI document is discovered only relative to the client's own
compiled source location. The client requires the exact accepted v1 OpenAPI
byte identity (`bcdb0866…9b311`) before parsing it. This prevents same-version
changes to schema consts, enums, required fields, operation discriminators,
errors, or effects from becoming a second trust path. The accepted document is
OpenAPI 3.1.0 with runtime/API/client version 1, exactly the three v1
operations, the known closed schemas, no `servers`, `local_only: true`,
`network_bound: false`, and the explicit `in_process`/`local_cli` transport
boundary.

## Validation

Inputs and outputs are deep-copied. Requests are closed and bind the method
workspace to the selected workspace digest. Responses must have the exact
operation-specific field set, v1 service/result discriminators, matching
operation and workspace, well-formed and cross-bound workspace digests, and
runtime/API version 1. Every nested `RuntimeManifest`, `LifecycleResult`,
`Endpoint`, `Health`, `ReconnectCapability`, `ShutdownCapability`, and
`EffectGuarantees` object is closed and complete. All OpenAPI const, enum,
identifier, digest, timestamp, array uniqueness/minimum, and nonempty-string
constraints are enforced. Lifecycle history, endpoint kind/address,
manifest-health facts, health windows, recovery instructions, and workspace
identity are cross-checked. Every effect remains exact-typed and false.

Service error envelopes are closed and versioned. `code` must be an Identifier
and `path` a nonempty string; neither is coerced. Unknown or missing nested
fields, malformed values, cross-operation fields, invalid discriminators,
positive effects, mismatched identities or digests, unsafe endpoint addresses,
and unsupported versions fail closed as `ClientError`.

Success is deterministic local read evidence only. It does not start or bind a
service, reconnect a live client, observe shutdown, use a network, call a
provider, create a lease, dispatch, write a ledger, mutate policy, grant
authority or acceptance, install, release, publish, or interact with MCP,
GoalBuddy, or AOL.
