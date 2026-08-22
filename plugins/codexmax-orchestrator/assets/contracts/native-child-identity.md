# Native Child Identity V1

## Purpose and authority

`NativeChildIdentity` proves one current, candidate-bound Parent/child
relationship observed by a supported native host. The admitted evidence ABIs
are `codex_desktop_parent_action_v1`,
`codex_collaboration_parent_action_v1`, and the separate
`codex_collaboration_filtered_parent_action_v1`. The Parent action layer
performs create, list, and read/final capture; package code validates the
captured evidence. Package code does not automate either host, mint host IDs,
or infer native identity from a role, requested model, subprocess, fixture,
report, or transcript.

No host is admitted by this contract alone. If the host cannot provide the
required evidence, capability is `native_unavailable` and claim status is
`not_proved`.

The fail-clear assessment surface may return only an unavailable status and
reason for missing host evidence. It never returns a partial identity as
`native_proved`; the bridge requires a fully validated identity before binding
any Supervisor relationship.

## Required binding

Before create, Parent freezes an intent containing an opaque ID, 32-byte
base64url nonce, packet descriptor, exact candidate manifest digest, Parent
thread ID, requested semantic role, and requested route/model/reasoning/agent
path. Requested values are never copied into observed fields.

The Desktop evidence bundle contains:

- exact candidate and intent digests;
- host-returned host, Parent, and child IDs;
- raw create/list/read request and response descriptors;
- a create and read event, host timestamps, and a forward or snapshot cursor;
- relationship matches for create, list, and read;
- observed agent path/model/reasoning/route as known-or-unknown values;
- an echoed nonce or host-produced binding derived from the intent;
- an append-only previous/current receipt digest.

The package validator consumes this bundle as data only. It has no host adapter
parameter and cannot create, open, read, message, or dynamically load a Desktop
or collaboration task. A current Parent action receipt is the only admissible source of host
observations.

Every raw descriptor names a canonical workspace-owned path, MIME type,
positive byte length, SHA-256, capture timestamp, and `write_once: true`.

### Parent capture envelope

Each captured response JSON file must be a closed
`codex_desktop_parent_action_v1` object with exactly these common fields:

```json
{
  "schema_version": 1,
  "artifact_type": "codex_desktop_parent_action_v1",
  "operation": "create|list|read",
  "observation_source": "parent_action_receipt",
  "action_receipt_id": "opaque-parent-action-id",
  "raw_host_output": {"path": "raw/create.json", "size_bytes": 1, "sha256": "sha256:..."},
  "payload": {}
}
```

`create.payload` contains `host_id`, `parent_thread_id`, `child_thread_id`,
`intent_nonce`, `lifecycle_event_id`, and `observed_identity`. `list.payload`
contains the three IDs. `read.payload` contains the three IDs,
`lifecycle_event_id`, `lifecycle_timestamp`, `cursor`, `observed_status`, and
`observed_identity`. The response payload is parsed from the declared response
file; the raw host output reference is separately byte-verified when proving
native. The envelope is not a package signature or self-authenticating claim;
the Parent action receipt remains the external authority.

Known observed identity fields must carry `source: parsed_host_evidence` and
unknown fields must carry `source: host_unobserved`. The requested model,
reasoning, route, and agent path may equal independently observed values; the
validator rejects provenance mismatch, not legitimate equality.

### Collaboration capture envelope

The collaboration ABI uses typed agent-path locators and never stores an agent
path in `host_id`, `parent_thread_id`, or `child_thread_id`. Its
`host_returned_identity` contains `locator_kind: collaboration_agent_path`, an
explicitly unknown `host_instance`, exact `parent_agent_path` and
`child_agent_path`, a host-parsed known `agent_path`, and known-or-unknown
model/reasoning/route fields. The v1 collaboration results expose no host
instance, model, reasoning, or route, so those fields remain unknown.

Each collaboration response capture is a closed
`codex_collaboration_parent_action_v1` action envelope with the same common
fields as the Desktop envelope and no topology booleans. The validator
byte-verifies and directly parses the referenced raw host-result JSON:

- create raw bytes are exactly `{"task_name":"/parent/direct-child"}`;
- list raw bytes are a closed `{"agents":[...]}` object whose rows contain
  only `agent_name` and `agent_status`; exact Parent and child rows must exist,
  and the child path must be exactly one segment below the Parent;
- read raw bytes are a closed host-delivery object with `message_type`,
  `task_name`, `sender`, `recipient`, and `payload_text`. The first four fields
  are host metadata outside child text. `payload_text` must be closed JSON that
  echoes only `intent_id`, `nonce`, `candidate_snapshot_sha256`,
  `packet_sha256`, `agent_path`, `parent_path`, and `changed_paths`.

The normalized action-envelope payload must exactly equal facts derived from
those raw bytes. Create establishes only the host-returned child path; list
independently corroborates exact Parent and child rows plus status; final
delivery binds host sender and recipient separately from the child payload.
The payload cannot establish sender, topology, model, reasoning, route, or host
instance.

Collaboration binding is derived, not asserted. Its receipt binding has only
`relationship_kind: host_collaboration_direct_child`; it has no host nonce
echo or caller-supplied topology booleans. The nonce is bound by the
host-delivered payload after host sender/recipient and list topology have been
corroborated.

The durable bridge state preserves the same locator union. Desktop state uses
`parent_thread_id`, `supervisor_thread_id`, `host_id`, and
`checkpoint_supervisor_ids`. Collaboration state instead uses
`parent_agent_path`, `supervisor_agent_path`, an explicitly unknown
`native_host_instance`, and `checkpoint_supervisor_agent_paths`; all Desktop
identity fields remain null. Collaboration state is created only through
`empty_collaboration_state`, which accepts no caller host identifier. Desktop
action-receipt helpers reject collaboration state rather than placing agent
paths in a `thread_id` field. The Desktop visible-chat UI oracle also rejects
collaboration state; agent-path inventory cannot satisfy it until a separate
collaboration UI evidence ABI is contracted and admitted.

### Filtered terminal collaboration capture envelope

`codex_collaboration_filtered_parent_action_v1` is a separate closed ABI for a
terminal child observed through the host's exact child-path filter. It does not
relax or reinterpret `codex_collaboration_parent_action_v1`. All three action
captures in one identity must use the same ABI.

The filtered ABI requires byte-verified files with these exact closed shapes:

- create raw response: `{"task_name":"/parent/direct-child"}`;
- list request: `{"path_prefix":"/parent/direct-child"}` with no broad
  Parent prefix, missing key, mismatch, or extra field;
- terminal list raw response: exactly one child row with only `agent_name` and
  `agent_status`, where status is exactly
  `{"completed":"<payload_text>"}` and has no second key; and
- read/final raw response: the same closed host-delivery metadata and child
  payload used by the unfiltered collaboration ABI.

The validator parses the create result, filtered request, terminal response,
and final response directly from the declared bytes. The normalized list
payload contains only `filter_path_prefix`, `child_agent_path`,
`terminal_status`, and `completed_payload_text` and must exactly equal the
parsed facts. The terminal completion text must byte-equal the final
`payload_text`; that one text is parsed once as the closed child echo.

The frozen Parent path plus create path must establish an exact direct child.
Final `task_name` and sender must equal that child, and final recipient must
equal the Parent. The create response capture, read/final response capture,
and list/terminal response capture timestamps must be nondecreasing in that
order. A terminal status or child payload cannot prove topology, sender,
recipient, host instance, model, reasoning, or route. Those fields continue to
come only from admitted outer host evidence or remain explicit unknowns.

All existing live-workspace, exact-descriptor, action-ID, nonce, raw-output
path/digest, receipt-chain, and replay-context requirements remain mandatory.
Missing final metadata, a broad filter, a sibling or nested path, a nonterminal
or malformed status, or mixed action ABIs fails closed.

## Proof states

| Capability | Proof state | Claim |
| --- | --- | --- |
| `native_unavailable` | `intent_recorded` | `not_proved` |
| `native_available` | `created_unverified` | `not_proved` |
| `native_available` | `corroborated` | `native_proved` only when every live rule passes |

`native_proved` requires `proof_boundary: live_host`, one internally
consistent supported ABI, matching typed locators and relationship across
create/list/read, valid raw bytes and digests, exact nonce/candidate/packet
binding, current lifecycle evidence, and a current receipt-chain digest. A
fully valid synthetic fixture remains `not_proved`.

For `native_proved`, validation must receive both `workspace_root` and
`verify_files: true`. It parses and compares all three declared response files;
caller-supplied relationship booleans or arbitrary JSON cannot establish the
claim. The bridge persists goal-bound replay sets for nonce, action receipt
IDs, raw-output paths, raw-output digests, and the receipt-chain tip; every
later receipt must extend that exact tip.

The receipt digest is SHA-256 over canonical UTF-8 JSON with sorted keys and
compact separators, excluding only `evidence_chain.receipt_sha256`. The intent
digest uses the same rule, excluding only `intent.intent_sha256`. Nonces are
32-byte base64url values and may be accepted once per Parent-owned replay set.
Raw descriptors must be relative, workspace-owned, write-once paths. Optional
byte verification reads only those explicitly declared paths and rejects a
missing file, symlink, size mismatch, digest mismatch, or digest collision.

Requested and observed values may be equal only when the observed value was
independently parsed from admitted host bytes. Equality alone is never proof.
An observed field is either a host-captured known value or an explicit unknown
value with a reason; requested values never populate observed fields.

Unknown actual model, reasoning, route, or agent path is preserved as
`{state: unknown, value: null, reason: host_field_not_exposed}`. It does not
forge a known value and blocks every claim that depends on that field.

## Stable failures

- `native_host_abi_unavailable`
- `native_host_capability_missing`
- `native_action_authority_missing`
- `native_intent_nonce_missing`, `native_intent_nonce_replayed`,
  `native_intent_nonce_echo_mismatch`
- `native_packet_binding_mismatch`, `native_candidate_binding_mismatch`
- `native_create_response_malformed`,
  `native_create_identity_not_host_returned`
- `native_list_corroboration_missing`, `native_read_corroboration_missing`
- `native_parent_child_relation_mismatch`, `native_host_id_mismatch`
- `native_requested_identity_promoted`
- `native_raw_evidence_missing`, `native_raw_evidence_digest_mismatch`,
  `native_raw_evidence_collision`
- `native_lifecycle_event_missing`, `native_cursor_invalid`,
  `native_event_nonmonotonic`
- `native_topology_unavailable`
- `native_intent_digest_mismatch`, `native_receipt_digest_mismatch`,
  `native_proof_incomplete`, `native_unproved_reason_missing`
- `native_raw_evidence_path_invalid`, `native_raw_evidence_workspace_escape`,
  `native_raw_evidence_missing`, `native_raw_evidence_size_mismatch`,
  `native_raw_evidence_symlink`, `native_known_unknown_state_invalid`
- `native_live_workspace_proof_required`, `native_host_response_malformed`,
  `native_host_observation_mismatch`, `native_lifecycle_observation_mismatch`,
  `native_observed_identity_provenance_mismatch`,
  `native_observation_provenance_invalid`, `native_action_receipt_collision`,
  `native_raw_evidence_reference_invalid`
- `native_host_abi_unsupported`, `native_agent_path_invalid`,
  `native_collaboration_host_result_malformed`,
  `native_create_identity_not_host_returned`,
  `native_list_corroboration_disagrees`, `native_list_status_unproved`,
  `native_host_sender_recipient_mismatch`, `native_child_payload_mismatch`,
  `native_action_receipt_replayed`, `native_raw_output_replayed`,
  `native_receipt_chain_mismatch`, `native_receipt_chain_context_required`,
  `native_replay_context_required`
- `native_filtered_list_request_malformed`,
  `native_filtered_list_request_mismatch`,
  `native_filtered_list_result_malformed`,
  `native_filtered_list_corroboration_disagrees`,
  `native_filtered_terminal_status_unproved`,
  `native_filtered_terminal_payload_mismatch`,
  `native_filtered_capture_nonmonotonic`

## Topology boundary

Child identity does not prove a persistent goal-lifetime Supervisor, internal
Worker containment, stable visible chat count, forward subscription, provider
identity, quality, authority, or acceptance. Those remain separate Desktop UX,
provider, and Parent gates.

## Implementation ownership

T042 Native R2/R4 owns the Desktop and unfiltered collaboration behavior,
including the Desktop-only visible-chat oracle rejection. T043 R5 adds only the
filtered-terminal action ABI in `native_host_adapter.py`, this contract/schema,
`codexmax-orchestrate/SKILL.md`, and the native adapter tests. It validates
Parent-captured action receipts; it does not add a generic host loader or
change `desktop_thread_bridge.py`. Native activation waits for a fresh
Parent-owned T045 capture using a new candidate, packet, intent, nonce, child,
and raw evidence; attempt 02 is invalidated by the source change.
