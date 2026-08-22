# Standalone Downstream Fork Kit v2

## Boundary

This contract defines one closed, digest-chained, read-only handoff envelope for
a possible downstream Codexmax distribution. The envelope is planning and
compatibility evidence only. It does not create a fork, admit AOL, execute a
provider, install or publish software, mutate GoalBuddy or AOL, grant broker
write authority, or establish Assurance, economics, Home/Now, C50, or C60
truth.

The canonical example is `proposed_not_created` and its handoff is always
`proposed_not_admitted`. A future downstream owner may supply a real
`candidate_created_not_admitted` identity. There is no admitted, accepted, or
production branch. Existing `StandaloneRuntimeContract v1` downstream metadata
applies only after that real identity exists.

## Immutable upstream anchor

The only accepted upstream release anchor is:

- package `codexmax-orchestrator`;
- version `0.6.0-rc.6+codex.20260816`;
- release-manifest SHA-256
  `c7abb4abc0d6ec92b631bfcee9cd0a40e58c45caad8df065fc21610ad4b59865`;
- payload-tree SHA-256
  `c40a9f18462faa917963121f18db022044af90d877e8d087a5e860ae0938cc92`;
- 362 manifest payload rows and 363 physical regular files including the
  manifest.

The release manifest and content-addressed stage are release authority. A git
identity is contextual only and is deliberately absent from the proposed kit.

## Overlay and shared-contract law

The exact overlay classes are `client_adapter` and `read_model_projection`.
They may translate or project already validated facts. They cannot grant
capability or authority; allocate capacity or a lease; normalize billing;
count usage; create receipt truth; accept work; mutate board or policy truth;
call a provider; include executable downstream logic; or change shared
components.

The forbidden duplicate-authority set is exactly `capacity`,
`assignment_authority`, and `acceptance`. Shared conformance is version 1 for
exactly `runtime`, `event`, `receipt`, `adapter`, `route_identity`,
`assignment_authority`, `delegation`, `task_journal`, and
`capacity_authority`. Missing, boolean, zero, unknown, or future versions fail
closed.

## Divergence and lifecycle

Every divergence row is hash chained from the all-zero genesis digest. The
canonical proposed kit contains two unapplied `overlay_declaration` rows, one
for each allowed overlay. Rows contain no patch body or downstream code, and
`shared_component_changes` is always empty. The ledger digest binds its ordered
rows and predecessor.

Upgrade, backport, upstream return, compatibility, and rollback remain
unperformed. Upgrade requires a new downstream identity. Backports are
digest-only downstream candidates. Upstream return is `proposed_unsubmitted`.
Rollback may target only the exact upstream anchor or a separately validated
prior downstream identity. No lifecycle declaration grants mutation authority
or rewrites history.

## External ownership mappings

Mappings are reference-only and unimplemented:

| Codexmax source | External semantic | External owner |
| --- | --- | --- |
| `route_fabric_decision_v1` | `RouteDecision` | `AOL Core` |
| `runtime_quality_receipt_v1` | `Assurance` | `AOL Core` |
| `correction_economics_v1` | `economics` | `AOL Core` |
| `execution_continuity_v1` | `Home/Now` | `AOL Home/Now` |

These labels do not implement AOL logic or assert external truth. Each row says
that implementation, truth, authority, and acceptance are false.

## Hash-bound evidence catalog

Version 2 binds six workspace-relative evidence sources in a fixed order:

1. installed standalone journey;
2. one task-scoped provider dispatch;
3. compact advisory telemetry;
4. accepted advisory evaluation evidence;
5. Parent-reviewed real-work dogfood; and
6. the enterprise proof explicitly deferred to AOL.

The validator resolves each path under the supplied repository root and checks
its exact SHA-256. It rejects missing files, byte drift, path traversal,
symlinks, hard links, non-regular files, reordering, extra rows, and authority
promotion. These references do not grant execution or routing authority. They
do not prove provider qualification, protected production, or AOL admission.

## Sanitization and integrity

Raw prompts, transcripts, provider output, credentials, authentication
material, private environment data, secret-bearing paths, broker-write
authority, and GoalBuddy-write authority are excluded. The validator also
rejects hidden fields, duplicate JSON keys, non-finite numbers, unsafe text,
absolute or traversing paths, and positive effect or admission claims.

Canonical SHA-256 uses sorted-key compact ASCII JSON with floats forbidden.
Each divergence entry binds its predecessor. The ledger, upstream anchor,
overlay policy, compatibility, lifecycle, external mappings, handoff, and full
kit have independent digests. Digests prove byte-domain integrity, not
authenticity or admission.

## Validator

The standard-library validator reads only the kit and exact upstream stage. It
does not import or execute downstream, AOL, adapter, provider, or service code.
It verifies every staged payload against the frozen release manifest and emits
canonical `static_local_non_authoritative` JSON with every effect, authority,
execution, admission, and acceptance boolean false.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  plugins/codexmax-orchestrator/scripts/validate_standalone_downstream_fork_kit.py \
  --kit plugins/codexmax-orchestrator/assets/templates/standalone-downstream-fork-kit-example.json \
  --repo-root /absolute/path/to/codexmax-orchestrator \
  --upstream-stage /absolute/path/to/the/exact/rc6/stage
```
