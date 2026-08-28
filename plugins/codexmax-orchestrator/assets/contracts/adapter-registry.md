# Approved Adapter Registry V1

## Boundary

Users may select and constrain package-owned adapters; they may not load
adapter code. The registry is closed to `native_codex`, `claude_cli`,
`commandcode`, `minimax_mmx`, `minimax_mmx_tool_loop`, `opencode_tool_loop`,
`grok_cli`, and `opencode_qwopus`. Each type selects a
code-owned implementation and immutable digest. No user field may introduce an
argv, command, executable, URL, endpoint, module, path, environment value,
secret, token, provider transport, or control route.

The eight cards and their SHA-256 digests are built into the package. Registry
validation requires the exact complete card set, unique type/ID/digest values,
and the code-owned root digest. User configuration may add or constrain only
`bindings`; it cannot replace cards or registry identity. A binding may declare
a new exact `route.exact_model` over an existing compatible Worker route. The
route name remains the package-owned transport anchor. All other route identity
fields remain package-owned. The candidate starts `configured` and requires
fresh qualification.

Configuration creates `configured`, never `qualified`. Static conformance and
synthetic tests prove parser behavior only. Live qualification requires a
fresh, exact evidence chain under separate action authority.

## Registry and bindings

The root artifact contains exact registry identity, approved adapter cards,
configured bindings, and a root digest. Each card declares adapter ID/type and
digest, worker-only route support, permitted opaque credential-reference
kinds, and five all-false arbitrary-execution flags.

A binding includes:

- known route name/provider/exact model/route ID/runtime/runtime host,
  reasoning, billing basis, independence group, adapter ID and digest;
- enabled flag, optional lower concurrency cap, and positive token cap;
- opaque credential reference `{kind, opaque_id}` and its digest;
- task-profile and provider-input digests;
- registry, binding, qualification-certificate, preflight, capability, and
  evaluation digests;
- qualification issue/expiry timestamps, status, and unknowns.

Opaque IDs are identifiers, not environment-variable names, paths, URLs, or
credential values. Registry/config inspection never resolves them.

## Self-service binding authoring

`resolve_codexmax_config.py adapter-binding onboard` creates one absent
repository-root `codexmax.adapters.yaml` for the optional accounts selected in
the first-use interview. It accepts only the closed public names `opencode`,
`claude`, `deepseek`, `minimax`, and `grok`. It creates their bindings in one
deterministic overlay and sets only the matching package-owned candidate route
`enabled` flags. Native-only onboarding creates no file. Every optional result
remains configured, unauthenticated, unqualified, unauthorized, and not run.

`resolve_codexmax_config.py adapter-binding add|update|remove` authors one
dedicated adapter-only YAML or JSON overlay. Preview is the default. Public
persistence is only immutable candidate creation through `--write-new --output
<absent-path>`. Add creates a new overlay. Update and remove require an explicit
`--input` snapshot and create a distinct absent output; they never replace,
delete, or mutate the input. Mutable `--write` is not accepted.

When the output is the repository-root `codexmax.adapters.yaml`, ordinary
configuration resolution discovers it as an optional repository adapter layer.
Native capability defaults remain embedded and do not require this file. An
explicit `--workspace-config` pointer to the same file remains supported and
does not apply the overlay twice.

New output creation requires an existing verified canonical parent and opens
the final name directly with `O_CREAT|O_EXCL|O_NOFOLLOW`. Existing regular
files, aliases, hardlinks, special files, absent parents, observed input drift,
and observed output descriptor/path drift fail without a success receipt. The
CLI never creates a parent directory or overwrites an unrelated configuration
branch. Repeating the same preview produces byte-identical candidate output.

The immutable selector is adapter type, Worker route, exact model when supplied,
credential-reference kind, and opaque ID. Code derives the binding ID from that
selector. Update
changes only enabled, concurrency cap, or token cap; identity changes require
remove followed by add. Every other identity, digest, configured qualification
state, and unknown observation is rebuilt from package-owned cards, routes,
and task profiles.

Compatibility is code-owned and closed:

- `native_codex`: package-owned Codex Worker routes only;
- `claude_cli`: `worker_claude_sonnet_5` and
  `worker_claude_code_sonnet_5`;
- `commandcode`: package-owned `worker_deepseek_*` and
  `worker_commandcode_*` routes;
- `minimax_mmx`: `worker_minimax_m3`;
- `minimax_mmx_tool_loop`: `worker_minimax_m3_tool_loop`;
- `opencode_tool_loop`: `worker_minimax_m3_opencode`;
- `grok_cli`: `worker_grok_4_5` and `worker_grok_4_6`;
- `opencode_qwopus`: `worker_qwopus_opencode`.

Control routes, user-added routes, generic adapter/route pairing, and unknown
cards remain forbidden. Authoring receipts are closed and keep credentials
resolved, provider called, execution started, eligibility, authority, and
acceptance false.

### Filesystem threat boundary

Public adapter-binding authoring is immutable candidate creation. It is safe
against aliases, hardlinks, malformed input, and observed accidental or
cooperative concurrent changes. It does not protect an operator-selected
directory from a malicious same-UID process with directory write access;
portable Python/macOS has no atomic verified-fd-to-destination replacement
primitive. A successful receipt proves only the verified filesystem state at
its final check. Mutable activation, replacement, deletion, or a current-
pointer change requires a separately authorized trusted host layer and is not
performed by this CLI.

The global secret/transport scanner is unchanged except for two exact binding
contexts: positive `token_cap` at the binding root, and the closed
`credential_reference` mapping with exactly `kind`, `opaque_id`, and the
derived `reference_sha256`. Secret, token, credential, URL, endpoint, path,
argv, module, environment, transport, or arbitrary nested fields anywhere else
remain rejected.

## Qualification state

| State | Eligible | Recovery |
| --- | --- | --- |
| `unconfigured`, `configured`, `qualification_required` | no | explicit qualification |
| `qualified` | evidence-eligible only | separately authorized dispatch |
| `expired`, `stale`, `recalled`, `revoked`, `unavailable`, `qualification_failed` | no | fresh requalification |
| `execution_unknown` | no | preserve evidence; Parent/human recovery decision |

Qualification TTL is positive, no longer than every bound evidence expiry, and
at most 300 seconds. Recall precedence is `recalled > expired > stale > active`.
Any changed route, adapter, profile, credential-reference, preflight,
capability, certificate, or evaluation digest makes the binding stale.

Billing and usage are independent known-or-unknown observations. Unknown is
never zero. Existing exact-route one-attempt exceptions do not generalize.
There is no implicit retry, fallback, substitution, or replacement after
failure or `execution_unknown`.

Each qualified record binds the certificate, preflight, capability, evaluation,
and current adapter-binding digest. Its issued/expires interval must equal the
declared TTL. Recall requires both a recall digest and timestamp. A binding
digest mismatch is `stale`; an expired interval is `expired`; recall wins over
both. Configuration-origin records must remain `configured` with every evidence
and TTL field null and both recovery flags false.

## Canonical examples

Safe examples may bind the known Command Code/DeepSeek and MiniMax routes with
opaque `host_managed` or `external_profile` references. They must state
`configured`, contain no endpoint or credential, and make no live claim.

## Universal capability registry

Universal Adapter Capability V1 adds a separate source-local registry. It does
not change configuration-owned binding qualification. The registry freezes
eight provider-neutral primitives and six lane profiles. Adapter cards declare
potential primitive support. Exact model qualification declares a proved
subset.

The exact compatibility key is `provider + provider_transport + exact_model +
adapter_id + adapter_version`. A changed model, transport, adapter ID, or
adapter version changes the key and fails validation. Qualification also binds
evidence digests, issue and expiry times, recall state, exact tool allowlist,
and adapter concurrency cap.

Configuration cannot supply this evidence. A universal registry validated as
`configuration_only` must contain no qualification records. Terra remains
denied. Qwopus remains on hold. Unknown, stale, expired, recalled, failed, and
`execution_unknown` records cannot match a lane.

See `universal-adapter-capability-v1.md` and
`universal-adapter-capability-v1-schema.json`.

## Ownership

T040-ADAPTER alone owns `adapter_registry.py`, `runtime_adapter.py`,
`resolve_codexmax_config.py`, this contract/schema, the config template and
config skill, and the three adapter/config tests. It must not edit native-host,
route-fabric, resolver, preflight, dispatcher, effect, operator, or board
surfaces. Existing certificate and recall semantics are consumed, not forked.

## Mandatory negatives

Reject unknown adapter types, non-worker bindings, forbidden launch/transport
fields, secret-like values, claimed health/auth/capability/usage/qualification,
identity drift, stale or recalled evidence, and automatic recovery from
`execution_unknown`. Every receipt keeps provider called, execution started,
eligibility granted, authority granted, and acceptance granted false unless a
separate owning effect receipt proves the specific field.
