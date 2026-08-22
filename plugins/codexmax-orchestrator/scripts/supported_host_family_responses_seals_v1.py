#!/usr/bin/env python3
"""Service-owned persistence for the complete accepted T066 ledger.

This module owns structural mechanism records. It does not produce an available
fact. The fixed operation methods accept scalar digest references only. They do
not accept a caller ledger, family head, principal, source, callback, or complete
positive value.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterator, Mapping

import supported_host_responses_seals_v1 as t066


LEDGER_ID = "first-party-responses-seals-ledger-v1"
MANIFEST_TYPE = "supported_host_family_responses_seals_manifest_v1"
ANCHOR_TYPE = "supported_host_family_responses_seals_anchor_v1"
OWNER_STATE_TYPE = "supported_host_family_responses_seals_owner_state_v1"
TRANSITION_TYPE = "supported_host_family_responses_seals_transition_v1"
ACTION_EVIDENCE_TYPE = "supported_host_family_responses_action_evidence_v1"
CONTEXT_ARTIFACT_TYPE = "supported_host_family_responses_context_v1"
BRIDGE_ARTIFACT_TYPE = "supported_host_family_responses_bridge_v1"
RECORD_ARTIFACT_TYPE = "supported_host_family_record_seal_v1"
PROJECTION_ARTIFACT_TYPE = "supported_host_family_projection_seal_v1"
PENDING_TYPE = "supported_host_family_responses_seals_pending_v1"
PROOF_BOUNDARY = "source_local_structural_mechanism_only"
CATALOG_IMPORT_EDGE = "catalog_selection_to_responses_selection_v1"
NATIVE_IMPORT_EDGE = "native_supervision_to_responses_context_v1"
ACTION_IMPORT_EDGE = "registered_action_to_responses_bridge_v1"
IMPORT_EDGES = frozenset({CATALOG_IMPORT_EDGE, NATIVE_IMPORT_EDGE, ACTION_IMPORT_EDGE})

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMPTY = {
    field: t066.canonical_digest(
        {"schema_version": 1, "artifact_type": "supported_host_binding_absent_v1", "field": field}
    )
    for field in t066.BINDING_FIELDS
}


class ResponsesSealsFamilyError(ValueError):
    """Stable rejection that does not echo input data."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _digest(value: Any) -> str:
    return t066.canonical_digest(value)


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ResponsesSealsFamilyError("family_digest_invalid", path)
    return value


def _import_heads(value: Any, path: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not set(value).issubset(IMPORT_EDGES):
        raise ResponsesSealsFamilyError("family_import_heads_invalid", path)
    row = deepcopy(dict(value))
    for edge, head in row.items():
        _sha(head, path + "." + edge)
    return row


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ResponsesSealsFamilyError("family_utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ResponsesSealsFamilyError("family_canonical_value_invalid") from exc


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ResponsesSealsFamilyError(code, path)
    return deepcopy(dict(value))


def _sealed(value: Mapping[str, Any], seal_field: str) -> dict[str, Any]:
    row = deepcopy(dict(value))
    row[seal_field] = _digest({key: item for key, item in row.items() if key != seal_field})
    return row


def _assert_seal(value: Mapping[str, Any], seal_field: str, code: str, path: str) -> None:
    _sha(value.get(seal_field), path + "." + seal_field)
    if value[seal_field] != _digest({key: item for key, item in value.items() if key != seal_field}):
        raise ResponsesSealsFamilyError(code, path + "." + seal_field)


def _validate_window(observed_at: datetime, expires_at: datetime) -> tuple[datetime, datetime]:
    observed = _utc(observed_at, "$.observed_at")
    expires = _utc(expires_at, "$.expires_at")
    if expires <= observed or expires - observed > timedelta(minutes=5):
        raise ResponsesSealsFamilyError("family_freshness_invalid", "$.expires_at")
    return observed, expires


def _manifest() -> dict[str, Any]:
    return _sealed(
        {
            "schema_version": 1,
            "artifact_type": MANIFEST_TYPE,
            "ledger_id": LEDGER_ID,
            "operations": list(t066.OPERATIONS),
            "accepted_mechanism": t066.LEDGER_TYPE,
            "proof_boundary": PROOF_BOUNDARY,
            "manifest_sha256": "",
        },
        "manifest_sha256",
    )


def _validate_manifest(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {"schema_version", "artifact_type", "ledger_id", "operations", "accepted_mechanism", "proof_boundary", "manifest_sha256"}
    )
    row = _closed(value, fields, "family_manifest_shape_invalid", "$.manifest")
    if row != _manifest():
        raise ResponsesSealsFamilyError("family_manifest_mismatch", "$.manifest")
    return row


def _anchor(ledger: Mapping[str, Any]) -> dict[str, Any]:
    ledger_bytes = _canonical_bytes(ledger)
    return _sealed(
        {
            "schema_version": 1,
            "artifact_type": ANCHOR_TYPE,
            "ledger_id": LEDGER_ID,
            "sequence": len(ledger["events"]),
            "head_sha256": ledger["head_sha256"],
            "ledger_bytes_sha256": _bytes_digest(ledger_bytes),
            "anchor_sha256": "",
        },
        "anchor_sha256",
    )


def _validate_anchor(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {"schema_version", "artifact_type", "ledger_id", "sequence", "head_sha256", "ledger_bytes_sha256", "anchor_sha256"}
    )
    row = _closed(value, fields, "family_anchor_shape_invalid", "$.anchor")
    if row["schema_version"] != 1 or row["artifact_type"] != ANCHOR_TYPE or row["ledger_id"] != LEDGER_ID:
        raise ResponsesSealsFamilyError("family_anchor_identity_invalid", "$.anchor")
    if type(row["sequence"]) is not int or row["sequence"] < 0:
        raise ResponsesSealsFamilyError("family_anchor_sequence_invalid", "$.anchor.sequence")
    for field in ("head_sha256", "ledger_bytes_sha256", "anchor_sha256"):
        _sha(row[field], "$.anchor." + field)
    _assert_seal(row, "anchor_sha256", "family_anchor_digest_mismatch", "$.anchor")
    return row


def _initial_owner_state() -> dict[str, Any]:
    return _sealed(
        {
            "schema_version": 1,
            "artifact_type": OWNER_STATE_TYPE,
            "ledger_id": LEDGER_ID,
            "action_evidence": [],
            "transitions": [],
            "dependency_import_heads": {},
            "owner_state_sha256": "",
        },
        "owner_state_sha256",
    )


def _pending(
    predecessor_ledger: Mapping[str, Any],
    predecessor_owner: Mapping[str, Any],
    predecessor_anchor: Mapping[str, Any],
    successor_ledger: Mapping[str, Any],
    successor_owner: Mapping[str, Any],
) -> dict[str, Any]:
    successor_anchor = _anchor(successor_ledger)
    return _sealed(
        {
            "schema_version": 1,
            "artifact_type": PENDING_TYPE,
            "ledger_id": LEDGER_ID,
            "predecessor_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(predecessor_ledger)),
            "predecessor_owner_state_sha256": predecessor_owner["owner_state_sha256"],
            "predecessor_anchor_sha256": predecessor_anchor["anchor_sha256"],
            "successor_ledger": deepcopy(dict(successor_ledger)),
            "successor_owner_state": deepcopy(dict(successor_owner)),
            "successor_anchor": successor_anchor,
            "pending_sha256": "",
        },
        "pending_sha256",
    )


def _validate_pending(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema_version", "artifact_type", "ledger_id", "predecessor_ledger_bytes_sha256",
            "predecessor_owner_state_sha256", "predecessor_anchor_sha256", "successor_ledger",
            "successor_owner_state", "successor_anchor", "pending_sha256",
        }
    )
    row = _closed(value, fields, "family_pending_shape_invalid", "$.pending")
    if row["schema_version"] != 1 or row["artifact_type"] != PENDING_TYPE or row["ledger_id"] != LEDGER_ID:
        raise ResponsesSealsFamilyError("family_pending_identity_invalid", "$.pending")
    for field in (
        "predecessor_ledger_bytes_sha256", "predecessor_owner_state_sha256",
        "predecessor_anchor_sha256", "pending_sha256",
    ):
        _sha(row[field], "$.pending." + field)
    try:
        ledger = t066.validate_ledger(row["successor_ledger"])
    except t066.ResponsesSealsError as exc:
        raise ResponsesSealsFamilyError("family_pending_ledger_invalid", "$.pending.successor_ledger") from exc
    owner = _validate_owner_state(row["successor_owner_state"])
    anchor = _validate_anchor(row["successor_anchor"])
    if anchor != _anchor(ledger):
        raise ResponsesSealsFamilyError("family_pending_anchor_mismatch", "$.pending.successor_anchor")
    transitions = owner["transitions"]
    expected = t066.new_ledger(LEDGER_ID) if not transitions else _parse_exact_ledger(
        transitions[-1]["successor_ledger_json"], "$.pending.successor_owner_state.transitions[-1].successor_ledger_json"
    )
    if ledger != expected:
        raise ResponsesSealsFamilyError("family_pending_owner_fork", "$.pending.successor_owner_state")
    _assert_seal(row, "pending_sha256", "family_pending_digest_mismatch", "$.pending")
    return row


def _validate_action_evidence(value: Any, path: str) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema_version", "artifact_type", "ledger_id", "context_decision_sha256",
            "action_receipt_sha256", "observed_at", "evidence_sha256",
        }
    )
    row = _closed(value, fields, "family_action_evidence_shape_invalid", path)
    if row["schema_version"] != 1 or row["artifact_type"] != ACTION_EVIDENCE_TYPE or row["ledger_id"] != LEDGER_ID:
        raise ResponsesSealsFamilyError("family_action_evidence_identity_invalid", path)
    _sha(row["context_decision_sha256"], path + ".context_decision_sha256")
    _sha(row["action_receipt_sha256"], path + ".action_receipt_sha256")
    try:
        t066._time(row["observed_at"], path + ".observed_at")
    except t066.ResponsesSealsError as exc:
        raise ResponsesSealsFamilyError("family_action_evidence_time_invalid", path + ".observed_at") from exc
    _assert_seal(row, "evidence_sha256", "family_action_evidence_digest_mismatch", path)
    return row


def _parse_exact_ledger(text: Any, path: str) -> dict[str, Any]:
    if not isinstance(text, str):
        raise ResponsesSealsFamilyError("family_transition_ledger_invalid", path)
    raw = text.encode("utf-8")
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ResponsesSealsFamilyError("family_transition_ledger_invalid", path) from exc
    if raw != _canonical_bytes(value):
        raise ResponsesSealsFamilyError("family_transition_ledger_noncanonical", path)
    try:
        return t066.validate_ledger(value)
    except t066.ResponsesSealsError as exc:
        raise ResponsesSealsFamilyError("family_transition_ledger_invalid", path) from exc


def _validate_owner_artifact(value: Any, operation: str, path: str) -> dict[str, Any]:
    common = {"schema_version", "artifact_type", "operation", "proof_boundary", "artifact_sha256"}
    operation_fields = {
        "issue_responses_context": {
            "identity_sha256", "request_sha256", "dependency_receipts_sha256", "selection_sha256",
            "supervision_sha256", "runtime_sha256", "route_sha256", "context_sha256",
        },
        "verify_responses_bridge": {
            "context_decision_sha256", "action_receipt_sha256", "effect_request_sha256",
            "effect_receipt_sha256", "bridge_sha256",
        },
        "commit_or_verify_record": {
            "mode", "context_decision_sha256", "bridge_decision_sha256", "record_sha256",
            "owner_seal_sha256",
        },
        "seal_or_verify_projection": {
            "mode", "context_decision_sha256", "record_decision_sha256", "projection_sha256",
            "owner_seal_sha256",
        },
    }
    row = _closed(value, frozenset(common | operation_fields[operation]), "family_owner_artifact_invalid", path)
    expected_type = {
        "issue_responses_context": CONTEXT_ARTIFACT_TYPE,
        "verify_responses_bridge": BRIDGE_ARTIFACT_TYPE,
        "commit_or_verify_record": RECORD_ARTIFACT_TYPE,
        "seal_or_verify_projection": PROJECTION_ARTIFACT_TYPE,
    }[operation]
    if row.get("schema_version") != 1 or row.get("artifact_type") != expected_type:
        raise ResponsesSealsFamilyError("family_owner_artifact_invalid", path)
    if row.get("operation") != operation or row.get("proof_boundary") != PROOF_BOUNDARY:
        raise ResponsesSealsFamilyError("family_owner_artifact_invalid", path)
    if set(row).intersection({"producer_principal_id", "canonical_source_id", "family_head", "promotion_state"}):
        raise ResponsesSealsFamilyError("family_authority_field_forbidden", path)
    for field in operation_fields[operation] - {"mode"}:
        _sha(row[field], path + "." + field)
    if operation == "commit_or_verify_record" and row["mode"] not in {"commit", "verify"}:
        raise ResponsesSealsFamilyError("family_owner_artifact_invalid", path + ".mode")
    if operation == "seal_or_verify_projection" and row["mode"] not in {"seal", "verify"}:
        raise ResponsesSealsFamilyError("family_owner_artifact_invalid", path + ".mode")
    _assert_seal(row, "artifact_sha256", "family_owner_artifact_digest_mismatch", path)
    return row


def _validate_transition(value: Any, path: str = "$.transition") -> dict[str, Any]:
    fields = frozenset(
        {
            "schema_version", "artifact_type", "ledger_id", "operation", "event_type",
            "decision_sha256", "predecessor_sequence", "predecessor_head_sha256",
            "successor_sequence", "successor_head_sha256", "predecessor_ledger_json",
            "successor_ledger_json", "predecessor_ledger_bytes_sha256",
            "successor_ledger_bytes_sha256", "owner_artifact", "dependency_import_heads",
            "transition_sha256",
        }
    )
    row = _closed(value, fields, "family_transition_shape_invalid", path)
    if row["schema_version"] != 1 or row["artifact_type"] != TRANSITION_TYPE or row["ledger_id"] != LEDGER_ID:
        raise ResponsesSealsFamilyError("family_transition_identity_invalid", path)
    if row["operation"] not in t066.OPERATION_SET or row["event_type"] not in {"issue", "revoke"}:
        raise ResponsesSealsFamilyError("family_transition_operation_invalid", path)
    _import_heads(row["dependency_import_heads"], path + ".dependency_import_heads")
    _sha(row["decision_sha256"], path + ".decision_sha256")
    before = _parse_exact_ledger(row["predecessor_ledger_json"], path + ".predecessor_ledger_json")
    after = _parse_exact_ledger(row["successor_ledger_json"], path + ".successor_ledger_json")
    if type(row["predecessor_sequence"]) is not int or type(row["successor_sequence"]) is not int:
        raise ResponsesSealsFamilyError("family_transition_sequence_invalid", path)
    if row["predecessor_sequence"] != len(before["events"]) or row["successor_sequence"] != len(after["events"]):
        raise ResponsesSealsFamilyError("family_transition_sequence_invalid", path)
    if row["predecessor_head_sha256"] != before["head_sha256"] or row["successor_head_sha256"] != after["head_sha256"]:
        raise ResponsesSealsFamilyError("family_transition_head_invalid", path)
    if len(after["events"]) != len(before["events"]) + 1 or after["events"][:-1] != before["events"]:
        raise ResponsesSealsFamilyError("family_transition_chain_invalid", path)
    event = after["events"][-1]
    if event["operation"] != row["operation"] or event["event_type"] != row["event_type"] or event["decision_sha256"] != row["decision_sha256"]:
        raise ResponsesSealsFamilyError("family_transition_event_invalid", path)
    before_bytes = row["predecessor_ledger_json"].encode("utf-8")
    after_bytes = row["successor_ledger_json"].encode("utf-8")
    if row["predecessor_ledger_bytes_sha256"] != _bytes_digest(before_bytes) or row["successor_ledger_bytes_sha256"] != _bytes_digest(after_bytes):
        raise ResponsesSealsFamilyError("family_transition_bytes_digest_mismatch", path)
    if row["event_type"] == "issue":
        artifact = _validate_owner_artifact(row["owner_artifact"], row["operation"], path + ".owner_artifact")
        decision = event["decision"]
        expected_decision = _decision(
            row["operation"],
            decision["bindings"],
            artifact["artifact_sha256"],
            t066._time(decision["observed_at"], path + ".decision.observed_at"),
            t066._time(decision["expires_at"], path + ".decision.expires_at"),
        )
        if decision != expected_decision:
            raise ResponsesSealsFamilyError("family_transition_owner_decision_mismatch", path)
    elif row["owner_artifact"] is not None:
        raise ResponsesSealsFamilyError("family_transition_revoke_artifact_invalid", path + ".owner_artifact")
    _assert_seal(row, "transition_sha256", "family_transition_digest_mismatch", path)
    return row


def _validate_owner_state(value: Any) -> dict[str, Any]:
    fields = frozenset(
        {"schema_version", "artifact_type", "ledger_id", "action_evidence", "transitions", "dependency_import_heads", "owner_state_sha256"}
    )
    row = _closed(value, fields, "family_owner_state_shape_invalid", "$.owner_state")
    if row["schema_version"] != 1 or row["artifact_type"] != OWNER_STATE_TYPE or row["ledger_id"] != LEDGER_ID:
        raise ResponsesSealsFamilyError("family_owner_state_identity_invalid", "$.owner_state")
    if not isinstance(row["action_evidence"], list) or not isinstance(row["transitions"], list):
        raise ResponsesSealsFamilyError("family_owner_state_list_invalid", "$.owner_state")
    evidence_ids: set[str] = set()
    for index, item in enumerate(row["action_evidence"]):
        evidence = _validate_action_evidence(item, f"$.owner_state.action_evidence[{index}]")
        if evidence["evidence_sha256"] in evidence_ids:
            raise ResponsesSealsFamilyError("family_action_evidence_duplicate", f"$.owner_state.action_evidence[{index}]")
        evidence_ids.add(evidence["evidence_sha256"])
    previous = t066.new_ledger(LEDGER_ID)
    artifacts: dict[str, dict[str, Any]] = {}
    transition_ids: set[str] = set()
    current_import_heads: dict[str, str] = {}
    for index, item in enumerate(row["transitions"]):
        transition = _validate_transition(item, f"$.owner_state.transitions[{index}]")
        transition_heads = transition["dependency_import_heads"]
        if transition["event_type"] == "revoke":
            expected_heads = current_import_heads
        elif transition["operation"] == "issue_responses_context":
            expected_heads = {
                edge: transition_heads.get(edge)
                for edge in (CATALOG_IMPORT_EDGE, NATIVE_IMPORT_EDGE)
            }
            if None in expected_heads.values() or set(transition_heads) != set(expected_heads):
                raise ResponsesSealsFamilyError("family_import_heads_transition_mismatch", f"$.owner_state.transitions[{index}]")
        elif transition["operation"] == "verify_responses_bridge":
            expected_heads = {**current_import_heads, ACTION_IMPORT_EDGE: transition_heads.get(ACTION_IMPORT_EDGE)}
            if None in expected_heads.values() or transition_heads != expected_heads:
                raise ResponsesSealsFamilyError("family_import_heads_transition_mismatch", f"$.owner_state.transitions[{index}]")
        else:
            expected_heads = current_import_heads
        if transition_heads != expected_heads:
            raise ResponsesSealsFamilyError("family_import_heads_transition_mismatch", f"$.owner_state.transitions[{index}]")
        current_import_heads = deepcopy(transition_heads)
        before = _parse_exact_ledger(transition["predecessor_ledger_json"], f"$.owner_state.transitions[{index}].predecessor_ledger_json")
        after = _parse_exact_ledger(transition["successor_ledger_json"], f"$.owner_state.transitions[{index}].successor_ledger_json")
        if before != previous:
            raise ResponsesSealsFamilyError("family_transition_fork_detected", f"$.owner_state.transitions[{index}]")
        if transition["transition_sha256"] in transition_ids:
            raise ResponsesSealsFamilyError("family_transition_replay", f"$.owner_state.transitions[{index}]")
        transition_ids.add(transition["transition_sha256"])
        if transition["event_type"] == "issue":
            artifact = transition["owner_artifact"]
            operation = transition["operation"]
            if operation == "issue_responses_context":
                expected_context = _digest(
                    {
                        "schema_version": 1,
                        "artifact_type": "responses_context_material_v1",
                        "ledger_id": LEDGER_ID,
                        **{
                            field: artifact[field]
                            for field in (
                                "identity_sha256", "request_sha256", "dependency_receipts_sha256",
                                "selection_sha256", "supervision_sha256", "runtime_sha256", "route_sha256",
                            )
                        },
                    }
                )
                if artifact["context_sha256"] != expected_context:
                    raise ResponsesSealsFamilyError("family_context_derivation_mismatch", f"$.owner_state.transitions[{index}]")
            elif operation == "verify_responses_bridge":
                context = artifacts.get(artifact["context_decision_sha256"])
                if context is None or context["operation"] != "issue_responses_context":
                    raise ResponsesSealsFamilyError("family_bridge_context_unavailable", f"$.owner_state.transitions[{index}]")
                if not any(
                    evidence["context_decision_sha256"] == artifact["context_decision_sha256"]
                    and evidence["action_receipt_sha256"] == artifact["action_receipt_sha256"]
                    for evidence in row["action_evidence"]
                ):
                    raise ResponsesSealsFamilyError("family_bridge_action_unavailable", f"$.owner_state.transitions[{index}]")
                expected_bridge = _digest(
                    {
                        "schema_version": 1,
                        "artifact_type": "responses_bridge_material_v1",
                        "ledger_id": LEDGER_ID,
                        "context_decision_sha256": artifact["context_decision_sha256"],
                        "context_sha256": context["context_sha256"],
                        "action_receipt_sha256": artifact["action_receipt_sha256"],
                        "effect_request_sha256": artifact["effect_request_sha256"],
                        "effect_receipt_sha256": artifact["effect_receipt_sha256"],
                    }
                )
                if artifact["bridge_sha256"] != expected_bridge:
                    raise ResponsesSealsFamilyError("family_bridge_derivation_mismatch", f"$.owner_state.transitions[{index}]")
            elif operation == "commit_or_verify_record":
                context = artifacts.get(artifact["context_decision_sha256"])
                bridge = artifacts.get(artifact["bridge_decision_sha256"])
                if context is None or bridge is None or bridge.get("context_decision_sha256") != artifact["context_decision_sha256"]:
                    raise ResponsesSealsFamilyError("family_record_dependency_mismatch", f"$.owner_state.transitions[{index}]")
                expected_seal = _digest(
                    {
                        "schema_version": 1,
                        "artifact_type": "responses_record_owner_seal_v1",
                        "ledger_id": LEDGER_ID,
                        "context_decision_sha256": artifact["context_decision_sha256"],
                        "bridge_decision_sha256": artifact["bridge_decision_sha256"],
                        "record_sha256": artifact["record_sha256"],
                    }
                )
                if artifact["owner_seal_sha256"] != expected_seal:
                    raise ResponsesSealsFamilyError("family_record_derivation_mismatch", f"$.owner_state.transitions[{index}]")
            else:
                context = artifacts.get(artifact["context_decision_sha256"])
                record = artifacts.get(artifact["record_decision_sha256"])
                if context is None or record is None or record.get("context_decision_sha256") != artifact["context_decision_sha256"]:
                    raise ResponsesSealsFamilyError("family_projection_dependency_mismatch", f"$.owner_state.transitions[{index}]")
                expected_seal = _digest(
                    {
                        "schema_version": 1,
                        "artifact_type": "responses_projection_owner_seal_v1",
                        "ledger_id": LEDGER_ID,
                        "context_decision_sha256": artifact["context_decision_sha256"],
                        "record_decision_sha256": artifact["record_decision_sha256"],
                        "record_owner_seal_sha256": record["owner_seal_sha256"],
                        "projection_sha256": artifact["projection_sha256"],
                    }
                )
                if artifact["owner_seal_sha256"] != expected_seal:
                    raise ResponsesSealsFamilyError("family_projection_derivation_mismatch", f"$.owner_state.transitions[{index}]")
            artifacts[transition["decision_sha256"]] = artifact
        previous = after
    if _import_heads(row["dependency_import_heads"], "$.owner_state.dependency_import_heads") != current_import_heads:
        raise ResponsesSealsFamilyError("family_import_heads_state_mismatch", "$.owner_state.dependency_import_heads")
    _assert_seal(row, "owner_state_sha256", "family_owner_state_digest_mismatch", "$.owner_state")
    return row


def _owner_artifact(operation: str, values: Mapping[str, Any]) -> dict[str, Any]:
    artifact_type = {
        "issue_responses_context": CONTEXT_ARTIFACT_TYPE,
        "verify_responses_bridge": BRIDGE_ARTIFACT_TYPE,
        "commit_or_verify_record": RECORD_ARTIFACT_TYPE,
        "seal_or_verify_projection": PROJECTION_ARTIFACT_TYPE,
    }[operation]
    return _sealed(
        {
            "schema_version": 1,
            "artifact_type": artifact_type,
            "operation": operation,
            **deepcopy(dict(values)),
            "proof_boundary": PROOF_BOUNDARY,
            "artifact_sha256": "",
        },
        "artifact_sha256",
    )


def _decision(operation: str, bindings: Mapping[str, str], artifact_sha256: str, observed: datetime, expires: datetime) -> dict[str, Any]:
    basis = {
        "schema_version": 1,
        "artifact_type": "supported_host_family_responses_decision_identity_v1",
        "ledger_id": LEDGER_ID,
        "operation": operation,
        "bindings": dict(bindings),
        "owner_artifact_sha256": artifact_sha256,
        "observed_at": _format(observed),
        "expires_at": _format(expires),
    }
    row = {
        "schema_version": 1,
        "artifact_type": t066.DECISION_TYPE,
        "decision_id": "decision-" + _digest(basis).removeprefix("sha256:"),
        "decision_source_id": t066.SOURCE_IDS[operation],
        "decision": t066.DECISIONS[operation],
        "ledger_id": LEDGER_ID,
        "operation": operation,
        "bindings": dict(bindings),
        "observed_at": _format(observed),
        "expires_at": _format(expires),
        "decision_sha256": "",
    }
    row["decision_sha256"] = _digest({key: item for key, item in row.items() if key != "decision_sha256"})
    return t066.validate_structural_decision(
        row,
        expected_ledger_id=LEDGER_ID,
        expected_operation=operation,
        expected_bindings=bindings,
        now=observed,
    )


class ResponsesSealsFamilyStore:
    """Durably retain and byte-for-byte recover the accepted T066 ledger."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.manifest_path = self.root / "manifest.json"
        self.ledger_path = self.root / "t066-ledger.json"
        self.anchor_path = self.root / "anchor.json"
        self.owner_state_path = self.root / "owner-state.json"
        self.pending_path = self.root / "pending.json"
        self.lock_path = self.root / ".lock"
        self._initialize()

    def _initialize(self) -> None:
        if self.root.is_symlink():
            raise ResponsesSealsFamilyError("family_root_symlink_forbidden", "$.root")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise ResponsesSealsFamilyError("family_root_invalid", "$.root")
        if self.lock_path.is_symlink():
            raise ResponsesSealsFamilyError("family_file_symlink_forbidden", "$.store")
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with self._lock():
            if not any(path.exists() for path in (self.manifest_path, self.ledger_path, self.anchor_path, self.owner_state_path)):
                ledger = t066.new_ledger(LEDGER_ID)
                self._publish(self.manifest_path, _manifest())
                self._publish(self.ledger_path, ledger)
                self._publish(self.anchor_path, _anchor(ledger))
                self._publish(self.owner_state_path, _initial_owner_state())
            self._recover_locked()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _publish(path: Path, value: Any) -> None:
        if path.is_symlink():
            raise ResponsesSealsFamilyError("family_file_symlink_forbidden", "$.store")
        descriptor, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        try:
            data = _canonical_bytes(value)
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _clear_pending(self) -> None:
        self.pending_path.unlink(missing_ok=True)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _read(path: Path, code: str) -> Any:
        if path.is_symlink():
            raise ResponsesSealsFamilyError("family_file_symlink_forbidden", "$.store")
        try:
            data = path.read_bytes()
            value = json.loads(data)
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponsesSealsFamilyError(code, "$.store") from exc
        if data != _canonical_bytes(value):
            raise ResponsesSealsFamilyError("family_file_noncanonical", "$.store")
        return value

    def _recover_locked(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        _validate_manifest(self._read(self.manifest_path, "family_manifest_unavailable"))
        if self.pending_path.exists():
            pending = _validate_pending(self._read(self.pending_path, "family_pending_unavailable"))
            current_ledger = self._read(self.ledger_path, "family_ledger_unavailable")
            current_owner = self._read(self.owner_state_path, "family_owner_state_unavailable")
            current_anchor = self._read(self.anchor_path, "family_anchor_unavailable")
            ledger_hashes = {
                pending["predecessor_ledger_bytes_sha256"],
                _bytes_digest(_canonical_bytes(pending["successor_ledger"])),
            }
            owner_hashes = {
                pending["predecessor_owner_state_sha256"],
                pending["successor_owner_state"]["owner_state_sha256"],
            }
            anchor_hashes = {
                pending["predecessor_anchor_sha256"],
                pending["successor_anchor"]["anchor_sha256"],
            }
            if _bytes_digest(_canonical_bytes(current_ledger)) not in ledger_hashes:
                raise ResponsesSealsFamilyError("family_pending_ledger_collision", "$.ledger")
            if not isinstance(current_owner, Mapping) or current_owner.get("owner_state_sha256") not in owner_hashes:
                raise ResponsesSealsFamilyError("family_pending_owner_collision", "$.owner_state")
            if not isinstance(current_anchor, Mapping) or current_anchor.get("anchor_sha256") not in anchor_hashes:
                raise ResponsesSealsFamilyError("family_pending_anchor_collision", "$.anchor")
            self._publish(self.owner_state_path, pending["successor_owner_state"])
            self._publish(self.ledger_path, pending["successor_ledger"])
            self._publish(self.anchor_path, pending["successor_anchor"])
            self._clear_pending()
        try:
            ledger = t066.validate_ledger(self._read(self.ledger_path, "family_ledger_unavailable"))
        except t066.ResponsesSealsError as exc:
            raise ResponsesSealsFamilyError("family_ledger_invalid", "$.ledger") from exc
        anchor = _validate_anchor(self._read(self.anchor_path, "family_anchor_unavailable"))
        owner = _validate_owner_state(self._read(self.owner_state_path, "family_owner_state_unavailable"))
        try:
            t066.recover_ledger(
                ledger,
                trusted_sequence=anchor["sequence"],
                trusted_head_sha256=anchor["head_sha256"],
            )
        except t066.ResponsesSealsError as exc:
            code = "family_rollback_or_fork_detected"
            raise ResponsesSealsFamilyError(code, "$.ledger") from exc
        if anchor != _anchor(ledger):
            raise ResponsesSealsFamilyError("family_anchor_ledger_mismatch", "$.anchor")
        transitions = owner["transitions"]
        expected = t066.new_ledger(LEDGER_ID) if not transitions else _parse_exact_ledger(
            transitions[-1]["successor_ledger_json"], "$.owner_state.transitions[-1].successor_ledger_json"
        )
        if ledger != expected:
            raise ResponsesSealsFamilyError("family_owner_ledger_fork", "$.owner_state")
        return ledger, anchor, owner

    def _publish_successor(
        self,
        predecessor_ledger: Mapping[str, Any],
        predecessor_owner: Mapping[str, Any],
        predecessor_anchor: Mapping[str, Any],
        successor_ledger: Mapping[str, Any],
        successor_owner: Mapping[str, Any],
    ) -> None:
        pending = _pending(
            predecessor_ledger,
            predecessor_owner,
            predecessor_anchor,
            successor_ledger,
            successor_owner,
        )
        _validate_pending(pending)
        self._publish(self.pending_path, pending)
        self._publish(self.owner_state_path, successor_owner)
        self._publish(self.ledger_path, successor_ledger)
        self._publish(self.anchor_path, pending["successor_anchor"])
        self._clear_pending()

    def recover(self) -> dict[str, Any]:
        """Recover the exact current ledger against the retained anchor."""

        with self._lock():
            ledger, anchor, owner = self._recover_locked()
            return {
                "ledger": deepcopy(ledger),
                "ledger_json": _canonical_bytes(ledger).decode("utf-8"),
                "anchor": deepcopy(anchor),
                "owner_state_sha256": owner["owner_state_sha256"],
                "transition_count": len(owner["transitions"]),
                "dependency_import_heads": deepcopy(owner["dependency_import_heads"]),
                "proof_boundary": PROOF_BOUNDARY,
            }

    def transitions(self) -> list[dict[str, Any]]:
        with self._lock():
            _, _, owner = self._recover_locked()
            return deepcopy(owner["transitions"])

    @staticmethod
    def _find_issue(ledger: Mapping[str, Any], decision_sha256: str, operation: str) -> dict[str, Any]:
        _sha(decision_sha256, "$.decision_sha256")
        revoked = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "revoke"}
        for event in ledger["events"]:
            if event["event_type"] == "issue" and event["decision_sha256"] == decision_sha256:
                if event["operation"] != operation:
                    raise ResponsesSealsFamilyError("family_dependency_operation_mismatch", "$.decision_sha256")
                if decision_sha256 in revoked:
                    raise ResponsesSealsFamilyError("family_dependency_revoked", "$.decision_sha256")
                return event
        raise ResponsesSealsFamilyError("family_dependency_unavailable", "$.decision_sha256")

    @staticmethod
    def _artifact_for(owner: Mapping[str, Any], decision_sha256: str) -> dict[str, Any]:
        for transition in owner["transitions"]:
            if transition["event_type"] == "issue" and transition["decision_sha256"] == decision_sha256:
                return deepcopy(transition["owner_artifact"])
        raise ResponsesSealsFamilyError("family_owner_artifact_unavailable", "$.decision_sha256")

    def _commit_issue(self, operation: str, bindings: Mapping[str, str], artifact: Mapping[str, Any], observed: datetime, expires: datetime, dependency_import_heads: Mapping[str, str] | None = None) -> dict[str, Any]:
        decision = _decision(operation, bindings, artifact["artifact_sha256"], observed, expires)
        with self._lock():
            ledger, anchor, owner = self._recover_locked()
            heads = _import_heads(
                owner["dependency_import_heads"] if dependency_import_heads is None else dependency_import_heads,
                "$.dependency_import_heads",
            )
            for transition in owner["transitions"]:
                if transition["event_type"] == "issue" and transition["decision_sha256"] == decision["decision_sha256"]:
                    if transition["owner_artifact"] != artifact or transition["dependency_import_heads"] != heads:
                        raise ResponsesSealsFamilyError("family_decision_collision", "$.owner_artifact")
                    return deepcopy(transition)
            before_json = _canonical_bytes(ledger).decode("utf-8")
            try:
                successor = t066.issue_decision(ledger, decision, expected_head_sha256=ledger["head_sha256"])
            except t066.ResponsesSealsError as exc:
                raise ResponsesSealsFamilyError(exc.code, exc.path) from exc
            after_json = _canonical_bytes(successor).decode("utf-8")
            transition = _sealed(
                {
                    "schema_version": 1,
                    "artifact_type": TRANSITION_TYPE,
                    "ledger_id": LEDGER_ID,
                    "operation": operation,
                    "event_type": "issue",
                    "decision_sha256": decision["decision_sha256"],
                    "predecessor_sequence": len(ledger["events"]),
                    "predecessor_head_sha256": ledger["head_sha256"],
                    "successor_sequence": len(successor["events"]),
                    "successor_head_sha256": successor["head_sha256"],
                    "predecessor_ledger_json": before_json,
                    "successor_ledger_json": after_json,
                    "predecessor_ledger_bytes_sha256": _bytes_digest(before_json.encode("utf-8")),
                    "successor_ledger_bytes_sha256": _bytes_digest(after_json.encode("utf-8")),
                    "owner_artifact": deepcopy(dict(artifact)),
                    "dependency_import_heads": heads,
                    "transition_sha256": "",
                },
                "transition_sha256",
            )
            _validate_transition(transition)
            successor_owner = deepcopy(owner)
            successor_owner["transitions"].append(transition)
            successor_owner["dependency_import_heads"] = deepcopy(heads)
            successor_owner = _sealed(successor_owner, "owner_state_sha256")
            _validate_owner_state(successor_owner)
            self._publish_successor(ledger, owner, anchor, successor, successor_owner)
            return deepcopy(transition)

    def issue_responses_context(
        self,
        *,
        identity_sha256: str,
        request_sha256: str,
        dependency_receipts_sha256: str,
        selection_sha256: str,
        supervision_sha256: str,
        runtime_sha256: str,
        route_sha256: str,
        catalog_import_head_sha256: str,
        native_import_head_sha256: str,
        observed_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        observed, expires = _validate_window(observed_at, expires_at)
        inputs = {
            "identity_sha256": _sha(identity_sha256, "$.identity_sha256"),
            "request_sha256": _sha(request_sha256, "$.request_sha256"),
            "dependency_receipts_sha256": _sha(dependency_receipts_sha256, "$.dependency_receipts_sha256"),
            "selection_sha256": _sha(selection_sha256, "$.selection_sha256"),
            "supervision_sha256": _sha(supervision_sha256, "$.supervision_sha256"),
            "runtime_sha256": _sha(runtime_sha256, "$.runtime_sha256"),
            "route_sha256": _sha(route_sha256, "$.route_sha256"),
        }
        context_sha256 = _digest(
            {"schema_version": 1, "artifact_type": "responses_context_material_v1", "ledger_id": LEDGER_ID, **inputs}
        )
        artifact = _owner_artifact(
            "issue_responses_context",
            {**inputs, "context_sha256": context_sha256},
        )
        bindings = {
            **{field: _EMPTY[field] for field in t066.BINDING_FIELDS},
            **inputs,
            "output_sha256": context_sha256,
        }
        heads = {
            CATALOG_IMPORT_EDGE: _sha(catalog_import_head_sha256, "$.catalog_import_head_sha256"),
            NATIVE_IMPORT_EDGE: _sha(native_import_head_sha256, "$.native_import_head_sha256"),
        }
        return self._commit_issue("issue_responses_context", bindings, artifact, observed, expires, heads)

    def retain_registered_action_evidence(
        self,
        *,
        context_decision_sha256: str,
        action_receipt_sha256: str,
        observed_at: datetime,
    ) -> dict[str, Any]:
        observed = _utc(observed_at, "$.observed_at")
        action_sha = _sha(action_receipt_sha256, "$.action_receipt_sha256")
        context_sha = _sha(context_decision_sha256, "$.context_decision_sha256")
        with self._lock():
            ledger, anchor, owner = self._recover_locked()
            self._find_issue(ledger, context_sha, "issue_responses_context")
            evidence = _sealed(
                {
                    "schema_version": 1,
                    "artifact_type": ACTION_EVIDENCE_TYPE,
                    "ledger_id": LEDGER_ID,
                    "context_decision_sha256": context_sha,
                    "action_receipt_sha256": action_sha,
                    "observed_at": _format(observed),
                    "evidence_sha256": "",
                },
                "evidence_sha256",
            )
            for existing in owner["action_evidence"]:
                if existing["evidence_sha256"] == evidence["evidence_sha256"]:
                    return deepcopy(existing)
            successor = deepcopy(owner)
            successor["action_evidence"].append(evidence)
            successor = _sealed(successor, "owner_state_sha256")
            _validate_owner_state(successor)
            self._publish_successor(ledger, owner, anchor, ledger, successor)
            return deepcopy(evidence)

    def verify_responses_bridge(
        self,
        *,
        context_decision_sha256: str,
        action_receipt_sha256: str,
        effect_request_sha256: str,
        effect_receipt_sha256: str,
        action_import_head_sha256: str,
        observed_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        observed, expires = _validate_window(observed_at, expires_at)
        context_sha = _sha(context_decision_sha256, "$.context_decision_sha256")
        action_sha = _sha(action_receipt_sha256, "$.action_receipt_sha256")
        effect_request = _sha(effect_request_sha256, "$.effect_request_sha256")
        effect_receipt = _sha(effect_receipt_sha256, "$.effect_receipt_sha256")
        with self._lock():
            ledger, _, owner = self._recover_locked()
            context_event = self._find_issue(ledger, context_sha, "issue_responses_context")
            context_artifact = self._artifact_for(owner, context_sha)
            if not any(
                item["context_decision_sha256"] == context_sha and item["action_receipt_sha256"] == action_sha
                for item in owner["action_evidence"]
            ):
                raise ResponsesSealsFamilyError("family_action_evidence_unavailable", "$.action_receipt_sha256")
            dependency_heads = {
                **owner["dependency_import_heads"],
                ACTION_IMPORT_EDGE: _sha(action_import_head_sha256, "$.action_import_head_sha256"),
            }
        bridge_sha256 = _digest(
            {
                "schema_version": 1,
                "artifact_type": "responses_bridge_material_v1",
                "ledger_id": LEDGER_ID,
                "context_decision_sha256": context_sha,
                "context_sha256": context_artifact["context_sha256"],
                "action_receipt_sha256": action_sha,
                "effect_request_sha256": effect_request,
                "effect_receipt_sha256": effect_receipt,
            }
        )
        artifact = _owner_artifact(
            "verify_responses_bridge",
            {
                "context_decision_sha256": context_sha,
                "action_receipt_sha256": action_sha,
                "effect_request_sha256": effect_request,
                "effect_receipt_sha256": effect_receipt,
                "bridge_sha256": bridge_sha256,
            },
        )
        context_bindings = context_event["decision"]["bindings"]
        bindings = {
            **context_bindings,
            "dependency_receipts_sha256": _digest(
                {
                    "context_decision_sha256": context_sha,
                    "action_receipt_sha256": action_sha,
                    "effect_receipt_sha256": effect_receipt,
                }
            ),
            "action_sha256": action_sha,
            "output_sha256": bridge_sha256,
            "record_sha256": _EMPTY["record_sha256"],
            "projection_sha256": _EMPTY["projection_sha256"],
        }
        return self._commit_issue("verify_responses_bridge", bindings, artifact, observed, expires, dependency_heads)

    def commit_or_verify_record(
        self,
        *,
        mode: str,
        context_decision_sha256: str,
        bridge_decision_sha256: str,
        record_sha256: str,
        presented_seal_sha256: str | None,
        observed_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        if mode not in {"commit", "verify"}:
            raise ResponsesSealsFamilyError("family_record_mode_invalid", "$.mode")
        observed, expires = _validate_window(observed_at, expires_at)
        context_sha = _sha(context_decision_sha256, "$.context_decision_sha256")
        bridge_sha = _sha(bridge_decision_sha256, "$.bridge_decision_sha256")
        record_sha = _sha(record_sha256, "$.record_sha256")
        with self._lock():
            ledger, _, owner = self._recover_locked()
            self._find_issue(ledger, context_sha, "issue_responses_context")
            bridge_event = self._find_issue(ledger, bridge_sha, "verify_responses_bridge")
            self._artifact_for(owner, context_sha)
            bridge_artifact = self._artifact_for(owner, bridge_sha)
            if bridge_artifact["context_decision_sha256"] != context_sha:
                raise ResponsesSealsFamilyError("family_record_dependency_mismatch", "$.bridge_decision_sha256")
        seal_sha256 = _digest(
            {
                "schema_version": 1,
                "artifact_type": "responses_record_owner_seal_v1",
                "ledger_id": LEDGER_ID,
                "context_decision_sha256": context_sha,
                "bridge_decision_sha256": bridge_sha,
                "record_sha256": record_sha,
            }
        )
        if mode == "commit" and presented_seal_sha256 is not None:
            raise ResponsesSealsFamilyError("family_record_presented_seal_forbidden", "$.presented_seal_sha256")
        if mode == "verify" and _sha(presented_seal_sha256, "$.presented_seal_sha256") != seal_sha256:
            raise ResponsesSealsFamilyError("family_record_seal_mismatch", "$.presented_seal_sha256")
        artifact = _owner_artifact(
            "commit_or_verify_record",
            {
                "mode": mode,
                "context_decision_sha256": context_sha,
                "bridge_decision_sha256": bridge_sha,
                "record_sha256": record_sha,
                "owner_seal_sha256": seal_sha256,
            },
        )
        inherited = bridge_event["decision"]["bindings"]
        bindings = {
            **inherited,
            "dependency_receipts_sha256": _digest(
                {"context_decision_sha256": context_sha, "bridge_decision_sha256": bridge_sha}
            ),
            "output_sha256": seal_sha256,
            "record_sha256": record_sha,
            "projection_sha256": _EMPTY["projection_sha256"],
        }
        return self._commit_issue("commit_or_verify_record", bindings, artifact, observed, expires)

    def seal_or_verify_projection(
        self,
        *,
        mode: str,
        context_decision_sha256: str,
        record_decision_sha256: str,
        projection_sha256: str,
        presented_seal_sha256: str | None,
        observed_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        if mode not in {"seal", "verify"}:
            raise ResponsesSealsFamilyError("family_projection_mode_invalid", "$.mode")
        observed, expires = _validate_window(observed_at, expires_at)
        context_sha = _sha(context_decision_sha256, "$.context_decision_sha256")
        record_decision_sha = _sha(record_decision_sha256, "$.record_decision_sha256")
        projection_sha = _sha(projection_sha256, "$.projection_sha256")
        with self._lock():
            ledger, _, owner = self._recover_locked()
            self._find_issue(ledger, context_sha, "issue_responses_context")
            record_event = self._find_issue(ledger, record_decision_sha, "commit_or_verify_record")
            self._artifact_for(owner, context_sha)
            record_artifact = self._artifact_for(owner, record_decision_sha)
            if record_artifact["context_decision_sha256"] != context_sha:
                raise ResponsesSealsFamilyError("family_projection_dependency_mismatch", "$.record_decision_sha256")
        seal_sha256 = _digest(
            {
                "schema_version": 1,
                "artifact_type": "responses_projection_owner_seal_v1",
                "ledger_id": LEDGER_ID,
                "context_decision_sha256": context_sha,
                "record_decision_sha256": record_decision_sha,
                "record_owner_seal_sha256": record_artifact["owner_seal_sha256"],
                "projection_sha256": projection_sha,
            }
        )
        if mode == "seal" and presented_seal_sha256 is not None:
            raise ResponsesSealsFamilyError("family_projection_presented_seal_forbidden", "$.presented_seal_sha256")
        if mode == "verify" and _sha(presented_seal_sha256, "$.presented_seal_sha256") != seal_sha256:
            raise ResponsesSealsFamilyError("family_projection_seal_mismatch", "$.presented_seal_sha256")
        artifact = _owner_artifact(
            "seal_or_verify_projection",
            {
                "mode": mode,
                "context_decision_sha256": context_sha,
                "record_decision_sha256": record_decision_sha,
                "projection_sha256": projection_sha,
                "owner_seal_sha256": seal_sha256,
            },
        )
        inherited = record_event["decision"]["bindings"]
        bindings = {
            **inherited,
            "dependency_receipts_sha256": _digest(
                {"context_decision_sha256": context_sha, "record_decision_sha256": record_decision_sha}
            ),
            "output_sha256": seal_sha256,
            "record_sha256": record_artifact["record_sha256"],
            "projection_sha256": projection_sha,
        }
        return self._commit_issue("seal_or_verify_projection", bindings, artifact, observed, expires)

    def revoke(
        self,
        *,
        decision_sha256: str,
        reason: str,
        occurred_at: datetime,
    ) -> dict[str, Any]:
        decision_sha = _sha(decision_sha256, "$.decision_sha256")
        occurred = _utc(occurred_at, "$.occurred_at")
        with self._lock():
            ledger, anchor, owner = self._recover_locked()
            issue = next(
                (
                    event
                    for event in ledger["events"]
                    if event["event_type"] == "issue" and event["decision_sha256"] == decision_sha
                ),
                None,
            )
            if issue is None:
                raise ResponsesSealsFamilyError("family_dependency_unavailable", "$.decision_sha256")
            before_json = _canonical_bytes(ledger).decode("utf-8")
            try:
                successor = t066.revoke_decision(
                    ledger,
                    decision_sha256=decision_sha,
                    reason=reason,
                    expected_head_sha256=ledger["head_sha256"],
                    occurred_at=occurred,
                )
            except t066.ResponsesSealsError as exc:
                raise ResponsesSealsFamilyError(exc.code, exc.path) from exc
            after_json = _canonical_bytes(successor).decode("utf-8")
            transition = _sealed(
                {
                    "schema_version": 1,
                    "artifact_type": TRANSITION_TYPE,
                    "ledger_id": LEDGER_ID,
                    "operation": issue["operation"],
                    "event_type": "revoke",
                    "decision_sha256": decision_sha,
                    "predecessor_sequence": len(ledger["events"]),
                    "predecessor_head_sha256": ledger["head_sha256"],
                    "successor_sequence": len(successor["events"]),
                    "successor_head_sha256": successor["head_sha256"],
                    "predecessor_ledger_json": before_json,
                    "successor_ledger_json": after_json,
                    "predecessor_ledger_bytes_sha256": _bytes_digest(before_json.encode("utf-8")),
                    "successor_ledger_bytes_sha256": _bytes_digest(after_json.encode("utf-8")),
                    "owner_artifact": None,
                    "dependency_import_heads": deepcopy(owner["dependency_import_heads"]),
                    "transition_sha256": "",
                },
                "transition_sha256",
            )
            _validate_transition(transition)
            successor_owner = deepcopy(owner)
            successor_owner["transitions"].append(transition)
            successor_owner = _sealed(successor_owner, "owner_state_sha256")
            _validate_owner_state(successor_owner)
            self._publish_successor(ledger, owner, anchor, successor, successor_owner)
            return deepcopy(transition)
