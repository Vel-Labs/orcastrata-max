# Provider Task Input Contract

## Purpose

Provider and role names do not prove that a lane can read a local file, resolve
a connector resource, or execute a command. This contract makes source access,
input delivery, and read evidence explicit before dispatch and at integration.
Missing fields default to `unknown` and never satisfy a source-backed gate.

Task-specific context size and delivery strategy follow
`provider-flexible-execution.md`. A larger context or token ceiling cannot
change source access, input delivery, command capability, or local-file
authority. Runtime limits can only narrow the Parent task intent.

## Canonical Enums

<!-- provider-task-input-enums:start -->
```json
{
  "source_access": [
    "local_filesystem",
    "embedded_only",
    "connector_resource",
    "mixed",
    "none",
    "unknown",
    "unverified"
  ],
  "input_delivery": [
    "paths_only",
    "embedded_fact_pack",
    "connector_references",
    "mixed",
    "none",
    "unknown",
    "unverified"
  ],
  "read_status": [
    "read_local",
    "read_connector",
    "received_embedded",
    "unavailable",
    "not_supplied",
    "not_read",
    "unknown",
    "unverified"
  ],
  "commands_executable": [
    "yes",
    "no",
    "unknown"
  ],
  "compatibility_decision": [
    "compatible",
    "incompatible",
    "not_required",
    "unknown"
  ],
  "fact_representation": [
    "verbatim",
    "normalized"
  ],
  "omission_reason": [
    "unavailable",
    "not_supplied",
    "excluded",
    "unknown"
  ],
  "source_basis": [
    "local_file",
    "connector",
    "embedded"
  ],
  "validation_execution_status": [
    "completed",
    "failed",
    "not_run",
    "not_applicable"
  ],
  "validation_result": [
    "pass",
    "fail",
    "not_run",
    "not_applicable"
  ]
}
```
<!-- provider-task-input-enums:end -->

### `source_access`

- `local_filesystem`: the runtime demonstrated access to authorized local paths.
- `embedded_only`: the lane can use facts in its prompt or task payload but
  cannot read named paths or connector resources.
- `connector_resource`: the runtime demonstrated access to authorized connector
  or resource identifiers, not local paths.
- `mixed`: two or more access modes were demonstrated and individually scoped.
- `none`: the lane has no source-reading capability for this task.
- `unknown`: capability information is absent.
- `unverified`: capability was asserted but not demonstrated by the runtime.

### `input_delivery`

- `paths_only`: the assignment supplies path or locator strings only.
- `embedded_fact_pack`: the assignment supplies the evidence facts inline.
- `connector_references`: the assignment supplies connector/resource handles.
- `mixed`: two or more delivery modes are used and identified per source.
- `none`: no evidence input was supplied.
- `unknown`: delivery cannot be established from the durable packet.
- `unverified`: delivery was asserted but no durable payload or receipt proves it.

### `read_status`

- `read_local`: the lane actually read the authorized local source.
- `read_connector`: the lane actually resolved the authorized connector source.
- `received_embedded`: the lane received facts inline; this is not a local or
  connector read.
- `unavailable`: the source was named or delivered but the lane could not use it.
- `not_supplied`: the source category was required or named but no content or
  usable locator was delivered.
- `not_read`: access was possible, but the lane did not read the source.
- `unknown`: the result does not establish what happened.
- `unverified`: the result asserts a read without supporting evidence.

`commands_executable` is exactly `yes`, `no`, or `unknown`.
`compatibility_decision` is exactly `compatible`, `incompatible`,
`not_required`, or `unknown`. `unknown` and `unverified` are recordable states,
not demonstrated capabilities.
Material claims use `local_file`, `connector`, or `embedded` as their
`source_basis`. Validation execution status is `completed`, `failed`,
`not_run`, or `not_applicable`; its result is `pass`, `fail`, `not_run`, or
`not_applicable`.

## Task Input Shape

Task packets use this compact additive block. Older packets remain readable,
but omitted capability fields are interpreted as `unknown`.

```yaml
provider_input:
  required_source_access: []
  source_access: unknown
  input_delivery: unknown
  source_backed_claims_required: false
  commands_required: false
  commands_executable: unknown
  named_source_categories: []
  embedded_fact_pack: null
  read_receipt_required: true
  compatibility_gate:
    decision: unknown
    reason: unknown
```

Each named source category has a stable `category_id`, a `source_label`, whether
it is `required`, and its expected source kind. A path in a prompt is only a
label until a lane with demonstrated `local_filesystem` access reads it.
`required_source_access` lists the demonstrated access modes the work needs; a
source-backed task cannot leave it empty. When either top-level mode is `mixed`,
every category also declares a non-`mixed` `access_mode` and `input_delivery`.
`read_receipt_required` is exactly `true` for every provider-neutral task;
false, missing, or non-boolean values are incompatible.

## Pre-Dispatch Compatibility Gate

Run this gate after route authentication/tool/billing checks and before sending
the task:

1. Treat absent, `unknown`, or `unverified` access or delivery as unavailable
   for any required source-backed claim.
2. Reject `paths_only` delivery when the route is `embedded_only`, `none`,
   `unknown`, or `unverified`.
3. Reject `connector_references` unless `source_access` is
   `connector_resource` or a demonstrated compatible part of `mixed`.
4. For `embedded_fact_pack`, validate the complete fact-pack schema and account
   for every named category with one or more facts or one explicit omission.
   Optional omissions are valid. An omission for a required category sends the
   task to revision or reassignment; it is not evidence.
5. If commands are required, require `commands_executable: yes`. `no` or
   `unknown` fails the route gate.
6. For `mixed`, check every required category against its specific delivery and
   access mode. The word `mixed` alone grants no capability.
7. Compute the compatibility decision and reason, then require the dispatched
   packet's declared decision and reason to match them exactly. Provider
   reputation, role fit, or a prior successful run cannot override a failed
   gate.

Source-free tasks may proceed with unknown access only when the packet says
`source_backed_claims_required: false` and the result makes no source or command
claim.

### Route-runtime binding

The route runtime reuses the repository's canonical compatibility function; it
does not implement a second source/input decision engine. For each considered
candidate it binds the task packet to that candidate's fresh-preflight
`source_access`, `input_delivery`, and `commands_executable`, then requires the
declared `compatibility_gate.decision` and `reason` to equal the computed result.
An incompatible binding makes only that route ineligible. It does not mutate
the provider input, broaden source authority, convert path labels into embedded
facts, or change the task's claims.

Each fresh preflight is task-scoped. A prior result, registry capability row,
model identity, or success on another task cannot substitute for the current
binding. The route-resolution receipt records the exact access and delivery
values used for every actual attempt.

When a route packet names a registry task profile, that profile's source and
command requirements are minimums. `required_source_access` must contain the
profile's required mode, source-backed claims remain enabled, and
`commands_required` must match the packet's effective command requirement.
Changing the provider-input block to source-free or command-free cannot weaken
the named profile; the runtime rejects the packet before compatibility or route
selection.

## Embedded Fact Pack

An embedded fact pack delivers evidence content to an embedded-only lane. It
does not prove that the lane read the source named by a label.

```yaml
embedded_fact_pack:
  schema_version: 1
  pack_id: "<stable-pack-id>"
  facts:
    - claim_id: "C001"
      category_id: "<named source category>"
      representation: "verbatim | normalized"
      fact: "<bounded fact text>"
      source_label: "<human-readable source label>"
      source_locator: "<optional path, URL, or resource label>"
      content_hash: "sha256:<hex> | unknown"
      uncertainty: "<none or explicit caveat>"
  omissions:
    - category_id: "<required or optional category>"
      source_label: "<source label>"
      reason: "unavailable | not_supplied | excluded | unknown"
```

Only schema version `1` is supported. Pack IDs and claim IDs are nonempty stable
identifiers, and claim IDs must be unique inside the pack. Every fact is
nonempty and at most 4,000 characters. `representation: verbatim` means the fact
text is copied without normalization; `normalized` must preserve technical
meaning and uncertainty. Every fact has a nonempty source label, explicit
uncertainty, and either `sha256:` followed by 64 hexadecimal characters or
`unknown`. Omissions use a named category, nonempty source label, and one of the
canonical omission reasons. The `facts` and `omissions` lists are explicit even
when empty.

## Provider-Neutral Read Receipt

Every provider-neutral result includes this receipt:

```yaml
input_access_receipt:
  declared_source_access: unknown
  actual_input_delivery: unknown
  commands_executable: unknown
  compatibility_gate_decision: unknown
  compatibility_gate_reason: unknown
  sources_observed: []
  sources_unavailable: []
  sources_not_supplied: []
  explicit_unknowns: []
  sources:
    - category_id: "<named category>"
      source_label: "<source label>"
      read_status: unknown
      supported_claim_ids: []
      evidence: "<receipt, command, connector result, or embedded pack id>"
```

There is exactly one valid `sources` row for every named source category and no
unknown or duplicate row. `sources_observed`, `sources_unavailable`, and
`sources_not_supplied` contain category IDs, not paths or free-form labels; they
must agree with each other and with each row's `read_status`. Embedded facts use
`received_embedded`, never `read_local` or `read_connector`. A listed path alone
does not belong in `sources_observed`. If commands were not run, their
validation status remains `not_run`; command executability does not convert them
to a pass. Missing receipt fields fail closed. Integration validation always
receives the associated `provider_input`; a receipt alone cannot establish
gate, source, claim, or command consistency.

## Integration Gate

The Supervisor or Integrator compares every material claim with the read
receipt before reuse:

- reject or revise local-file observations unless the matching source row is
  `read_local` and the declared access supports local reads;
- reject or revise connector observations unless the row is `read_connector`;
- label facts backed only by `received_embedded` as embedded facts;
- reject source-backed claims whose category is `unavailable`, `not_supplied`,
  `not_read`, `unknown`, or `unverified`;
- require every material claim to name a canonical source basis and known
  category; when it has a claim ID, the source row must list that ID in
  `supported_claim_ids`;
- require validation rows to use canonical execution/result states; `pass`
  requires `execution_status: completed` and `commands_executable: yes`;
- keep `not_run` commands as `not_run`, regardless of prose confidence;
- treat a missing or internally contradictory receipt as `needs_revision` or
  `needs_reassignment`, never as implicit access.

## Examples

### Embedded-only Example

```yaml
provider_input:
  required_source_access: [embedded_only]
  source_access: embedded_only
  input_delivery: embedded_fact_pack
  source_backed_claims_required: true
  commands_required: false
  commands_executable: no
  read_receipt_required: true
  named_source_categories:
    - {category_id: worker_receipt, source_label: "Worker receipt", required: true}
    - {category_id: tester_receipt, source_label: "Tester receipt", required: true}
  embedded_fact_pack:
    schema_version: 1
    pack_id: t006b-documenter-facts
    facts:
      - {claim_id: C001, category_id: worker_receipt, representation: normalized, fact: "Worker tests passed.", source_label: "Worker receipt", content_hash: unknown, uncertainty: none}
      - {claim_id: C002, category_id: tester_receipt, representation: normalized, fact: "Tester found no open defect.", source_label: "Tester receipt", content_hash: unknown, uncertainty: none}
    omissions: []
  compatibility_gate:
    decision: compatible
    reason: compatible
input_access_receipt:
  declared_source_access: embedded_only
  actual_input_delivery: embedded_fact_pack
  commands_executable: no
  compatibility_gate_decision: compatible
  compatibility_gate_reason: compatible
  sources_observed: [worker_receipt, tester_receipt]
  sources_unavailable: []
  sources_not_supplied: []
  explicit_unknowns: ["source content hashes"]
  sources:
    - {category_id: worker_receipt, source_label: "Worker receipt", read_status: received_embedded, supported_claim_ids: [C001], evidence: t006b-documenter-facts}
    - {category_id: tester_receipt, source_label: "Tester receipt", read_status: received_embedded, supported_claim_ids: [C002], evidence: t006b-documenter-facts}
```

The lane may cite C001 and C002 as embedded facts. It may not say it opened or
read either repository path.

### Local-filesystem Example

```yaml
provider_input:
  required_source_access: [local_filesystem]
  source_access: local_filesystem
  input_delivery: paths_only
  source_backed_claims_required: true
  commands_required: true
  commands_executable: yes
  read_receipt_required: true
  named_source_categories:
    - {category_id: contract, source_label: "assets/contracts/provider-task-input.md", required: true}
    - {category_id: tests, source_label: "tests/test_repository.py", required: true}
  compatibility_gate:
    decision: compatible
    reason: compatible
input_access_receipt:
  declared_source_access: local_filesystem
  actual_input_delivery: paths_only
  commands_executable: yes
  compatibility_gate_decision: compatible
  compatibility_gate_reason: compatible
  sources_observed: [contract, tests]
  sources_unavailable: []
  sources_not_supplied: []
  explicit_unknowns: []
  sources:
    - {category_id: contract, source_label: "assets/contracts/provider-task-input.md", read_status: read_local, supported_claim_ids: [], evidence: "read command receipt"}
    - {category_id: tests, source_label: "tests/test_repository.py", read_status: read_local, supported_claim_ids: [], evidence: "read command receipt"}
```

The result may claim local observation only for sources with `read_local`. A
required command still needs a recorded command result; `commands_executable:
yes` alone is not validation.
