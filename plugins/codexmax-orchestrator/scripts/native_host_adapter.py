#!/usr/bin/env python3
"""Validate Parent-captured native-child evidence without touching a host.

This module is deliberately a validator, not a Desktop adapter.  A Parent
action layer captures host exchanges and supplies only their immutable
descriptors.  Repository code validates those descriptors and never creates,
opens, reads, messages, or dynamically loads a Desktop or collaboration task.
"""

from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, MutableSet


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
AGENT_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

ROOT_FIELDS = {
    "schema_version", "artifact_type", "receipt_id", "captured_at",
    "proof_boundary", "capability_state", "proof_state", "claim_status",
    "unproved_reason", "candidate", "intent", "host_returned_identity",
    "binding", "lifecycle", "raw_evidence", "evidence_chain",
}
DESCRIPTOR_FIELDS = {"path", "mime_type", "size_bytes", "sha256", "captured_at", "write_once"}
KNOWN_UNKNOWN_FIELDS = {"state", "value", "reason", "source"}
DESKTOP_OBSERVATION_TYPE = "codex_desktop_parent_action_v1"
COLLABORATION_OBSERVATION_TYPE = "codex_collaboration_parent_action_v1"
COLLABORATION_FILTERED_OBSERVATION_TYPE = "codex_collaboration_filtered_parent_action_v1"
OBSERVATION_SOURCE = "parent_action_receipt"
COLLABORATION_ACTIVE_STATUSES = {"running", "idle", "completed"}
_CHAIN_UNSET = object()


class NativeIdentityError(ValueError):
    """Stable semantic failure for untrusted native evidence."""

    def __init__(self, code: str, path: str = "$") -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise NativeIdentityError("native_canonicalization_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _closed(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeIdentityError("native_shape_invalid", path)
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NativeIdentityError("native_text_invalid", path)
    return value.strip()


def _identifier(value: Any, path: str) -> str:
    value = _text(value, path)
    if IDENTIFIER.fullmatch(value) is None:
        raise NativeIdentityError("native_identifier_invalid", path)
    return value


def _agent_path(value: Any, path: str) -> str:
    value = _text(value, path)
    if not value.startswith("/") or "//" in value or value.endswith("/"):
        raise NativeIdentityError("native_agent_path_invalid", path)
    parts = PurePosixPath(value).parts
    if len(parts) < 2 or parts[0] != "/" or any(AGENT_SEGMENT.fullmatch(part) is None for part in parts[1:]):
        raise NativeIdentityError("native_agent_path_invalid", path)
    if str(PurePosixPath(value)) != value:
        raise NativeIdentityError("native_agent_path_invalid", path)
    return value


def _direct_child(parent: str, child: str) -> bool:
    parent_parts = PurePosixPath(parent).parts
    child_parts = PurePosixPath(child).parts
    return len(child_parts) == len(parent_parts) + 1 and child_parts[:-1] == parent_parts


def validate_agent_path(value: Any) -> str:
    """Return one canonical collaboration agent path or fail closed."""
    return _agent_path(value, "$.agent_path")


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise NativeIdentityError("native_digest_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> str:
    value = _text(value, path)
    if TIMESTAMP.fullmatch(value) is None:
        raise NativeIdentityError("native_timestamp_invalid", path)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NativeIdentityError("native_timestamp_invalid", path) from exc
    return value


def _descriptor(value: Any, path: str, workspace_root: str | Path | None) -> dict[str, Any]:
    row = _closed(value, DESCRIPTOR_FIELDS, path)
    raw_path = _text(row["path"], f"{path}.path")
    if "\\" in raw_path or raw_path.startswith("/"):
        raise NativeIdentityError("native_raw_evidence_path_invalid", f"{path}.path")
    parts = Path(raw_path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise NativeIdentityError("native_raw_evidence_path_invalid", f"{path}.path")
    _text(row["mime_type"], f"{path}.mime_type")
    if type(row["size_bytes"]) is not int or row["size_bytes"] < 1:
        raise NativeIdentityError("native_raw_evidence_size_invalid", f"{path}.size_bytes")
    _digest(row["sha256"], f"{path}.sha256")
    _timestamp(row["captured_at"], f"{path}.captured_at")
    if row["write_once"] is not True:
        raise NativeIdentityError("native_raw_evidence_not_write_once", f"{path}.write_once")
    if workspace_root is not None:
        root = Path(workspace_root).resolve()
        target = (root / Path(*parts)).resolve(strict=False)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise NativeIdentityError("native_raw_evidence_workspace_escape", f"{path}.path") from exc
        candidate = root.joinpath(*parts)
        if candidate.exists() and candidate.is_symlink():
            raise NativeIdentityError("native_raw_evidence_symlink", f"{path}.path")
    return copy.deepcopy(row)


def _known_unknown(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, KNOWN_UNKNOWN_FIELDS, path)
    if row["state"] == "known":
        if row["source"] != "parsed_host_evidence":
            raise NativeIdentityError("native_observation_provenance_invalid", f"{path}.source")
        if row["reason"] is not None:
            raise NativeIdentityError("native_known_reason_invalid", f"{path}.reason")
        _text(row["value"], f"{path}.value")
    elif row["state"] == "unknown":
        if row["source"] != "host_unobserved":
            raise NativeIdentityError("native_observation_provenance_invalid", f"{path}.source")
        if row["value"] is not None:
            raise NativeIdentityError("native_unknown_value_present", f"{path}.value")
        _text(row["reason"], f"{path}.reason")
    else:
        raise NativeIdentityError("native_known_unknown_state_invalid", f"{path}.state")
    return copy.deepcopy(row)


def _verify_descriptor_files(value: Any, workspace_root: str | Path) -> None:
    """Verify only the paths explicitly named by the Parent evidence."""
    root = Path(workspace_root).resolve()
    seen_paths: set[str] = set()
    seen_digests: set[str] = set()
    for path, row in _iter_descriptors(value):
        target = root / row["path"]
        if not target.is_file() or target.is_symlink():
            raise NativeIdentityError("native_raw_evidence_missing", path)
        data = target.read_bytes()
        if len(data) != row["size_bytes"]:
            raise NativeIdentityError("native_raw_evidence_size_mismatch", path)
        if "sha256:" + hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise NativeIdentityError("native_raw_evidence_digest_mismatch", path)
        if row["path"] in seen_paths or row["sha256"] in seen_digests:
            raise NativeIdentityError("native_raw_evidence_collision", path)
        seen_paths.add(row["path"])
        seen_digests.add(row["sha256"])


def _iter_descriptors(value: dict[str, Any]):
    yield "$.candidate.manifest", value["candidate"]["manifest"]
    yield "$.intent.packet", value["intent"]["packet"]
    for operation in ("create", "list", "read"):
        exchange = value["raw_evidence"][operation]
        yield f"$.raw_evidence.{operation}.request", exchange["request"]
        yield f"$.raw_evidence.{operation}.response", exchange["response"]


def _raw_reference(value: Any, path: str, response_path: str, workspace_root: Path) -> dict[str, Any]:
    row = _closed(value, {"path", "size_bytes", "sha256"}, path)
    raw_path = _text(row["path"], f"{path}.path")
    if "\\" in raw_path or raw_path.startswith("/") or any(part in {"", ".", ".."} for part in Path(raw_path).parts):
        raise NativeIdentityError("native_raw_evidence_path_invalid", f"{path}.path")
    if raw_path == response_path:
        raise NativeIdentityError("native_raw_evidence_reference_invalid", f"{path}.path")
    if type(row["size_bytes"]) is not int or row["size_bytes"] < 1:
        raise NativeIdentityError("native_raw_evidence_size_invalid", f"{path}.size_bytes")
    _digest(row["sha256"], f"{path}.sha256")
    target = (workspace_root / Path(*Path(raw_path).parts)).resolve(strict=False)
    try:
        target.relative_to(workspace_root)
    except ValueError as exc:
        raise NativeIdentityError("native_raw_evidence_workspace_escape", f"{path}.path") from exc
    if not target.is_file() or target.is_symlink():
        raise NativeIdentityError("native_raw_evidence_missing", f"{path}.path")
    data = target.read_bytes()
    if len(data) != row["size_bytes"] or "sha256:" + hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise NativeIdentityError("native_raw_evidence_digest_mismatch", path)
    return copy.deepcopy(row)


def _read_json_file(target: Path, error_code: str, context: str) -> Any:
    try:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            row: dict[str, Any] = {}
            for key, item in items:
                if key in row:
                    raise NativeIdentityError(error_code, context)
                row[key] = item
            return row

        return json.loads(target.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except NativeIdentityError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeIdentityError(error_code, context) from exc


def _parse_child_payload(value: Any) -> dict[str, Any]:
    row = _closed(value, {
        "intent_id", "nonce", "candidate_snapshot_sha256", "packet_sha256",
        "agent_path", "parent_path", "changed_paths",
    }, "$.raw_evidence.read.raw_host_output.payload_text")
    _identifier(row["intent_id"], "$.raw_evidence.read.raw_host_output.payload_text.intent_id")
    nonce = _text(row["nonce"], "$.raw_evidence.read.raw_host_output.payload_text.nonce")
    if NONCE.fullmatch(nonce) is None:
        raise NativeIdentityError("native_intent_nonce_missing", "$.raw_evidence.read.raw_host_output.payload_text.nonce")
    _digest(row["candidate_snapshot_sha256"], "$.raw_evidence.read.raw_host_output.payload_text.candidate_snapshot_sha256")
    _digest(row["packet_sha256"], "$.raw_evidence.read.raw_host_output.payload_text.packet_sha256")
    _agent_path(row["agent_path"], "$.raw_evidence.read.raw_host_output.payload_text.agent_path")
    _agent_path(row["parent_path"], "$.raw_evidence.read.raw_host_output.payload_text.parent_path")
    if not isinstance(row["changed_paths"], list) or len(row["changed_paths"]) != len(set(row["changed_paths"])):
        raise NativeIdentityError("native_child_payload_mismatch", "$.raw_evidence.read.raw_host_output.payload_text.changed_paths")
    for index, changed in enumerate(row["changed_paths"]):
        changed = _text(changed, f"$.raw_evidence.read.raw_host_output.payload_text.changed_paths[{index}]")
        if (
            changed.startswith("/") or "\\" in changed
            or str(PurePosixPath(changed)) != changed
            or any(part in {"", ".", ".."} for part in PurePosixPath(changed).parts)
        ):
            raise NativeIdentityError("native_child_payload_mismatch", f"$.raw_evidence.read.raw_host_output.payload_text.changed_paths[{index}]")
    return copy.deepcopy(row)


def _parse_collaboration_raw(
    raw_reference: dict[str, Any], operation: str, workspace_root: Path,
    *, preserve_payload_text: bool = False,
) -> dict[str, Any]:
    target = (workspace_root / raw_reference["path"]).resolve(strict=False)
    document = _read_json_file(target, "native_collaboration_host_result_malformed", operation)
    if operation == "create":
        try:
            row = _closed(document, {"task_name"}, "$.raw_evidence.create.raw_host_output")
        except NativeIdentityError as exc:
            raise NativeIdentityError("native_collaboration_host_result_malformed", "create") from exc
        return {"child_agent_path": _agent_path(row["task_name"], "$.raw_evidence.create.raw_host_output.task_name")}
    if operation == "list":
        row = _closed(document, {"agents"}, "$.raw_evidence.list.raw_host_output")
        if not isinstance(row["agents"], list) or not row["agents"]:
            raise NativeIdentityError("native_list_corroboration_missing", "$.raw_evidence.list.raw_host_output.agents")
        agents: dict[str, Any] = {}
        for index, item in enumerate(row["agents"]):
            item = _closed(item, {"agent_name", "agent_status"}, f"$.raw_evidence.list.raw_host_output.agents[{index}]")
            name = _agent_path(item["agent_name"], f"$.raw_evidence.list.raw_host_output.agents[{index}].agent_name")
            if name in agents:
                raise NativeIdentityError("native_list_corroboration_disagrees", f"$.raw_evidence.list.raw_host_output.agents[{index}]")
            agents[name] = copy.deepcopy(item["agent_status"])
        return {"agents": agents}
    row = _closed(
        document, {"message_type", "task_name", "sender", "recipient", "payload_text"},
        "$.raw_evidence.read.raw_host_output",
    )
    if row["message_type"] != "FINAL_ANSWER":
        raise NativeIdentityError("native_read_corroboration_missing", "$.raw_evidence.read.raw_host_output.message_type")
    task_name = _agent_path(row["task_name"], "$.raw_evidence.read.raw_host_output.task_name")
    sender = _agent_path(row["sender"], "$.raw_evidence.read.raw_host_output.sender")
    recipient = _agent_path(row["recipient"], "$.raw_evidence.read.raw_host_output.recipient")
    payload_text = row["payload_text"]
    if not isinstance(payload_text, str) or not payload_text.strip():
        raise NativeIdentityError("native_text_invalid", "$.raw_evidence.read.raw_host_output.payload_text")
    parsed_payload_text = payload_text if preserve_payload_text else payload_text.strip()
    try:
        payload = json.loads(parsed_payload_text, object_pairs_hook=lambda items: _closed_pairs(items, "native_child_payload_mismatch"))
    except NativeIdentityError:
        raise
    except json.JSONDecodeError as exc:
        raise NativeIdentityError("native_child_payload_mismatch", "$.raw_evidence.read.raw_host_output.payload_text") from exc
    result = {
        "message_type": "FINAL_ANSWER", "task_name": task_name,
        "sender_agent_path": sender, "recipient_agent_path": recipient,
        "child_payload": _parse_child_payload(payload),
    }
    if preserve_payload_text:
        result["payload_text"] = payload_text
    return result


def _parse_filtered_collaboration_raw(
    raw_reference: dict[str, Any], request_descriptor: dict[str, Any],
    operation: str, workspace_root: Path,
) -> dict[str, Any]:
    if operation in {"create", "read"}:
        return _parse_collaboration_raw(
            raw_reference, operation, workspace_root,
            preserve_payload_text=operation == "read",
        )

    request_target = (workspace_root / request_descriptor["path"]).resolve(strict=False)
    request_document = _read_json_file(
        request_target, "native_filtered_list_request_malformed", "list",
    )
    try:
        request = _closed(
            request_document, {"path_prefix"},
            "$.raw_evidence.list.request.filtered_host_input",
        )
        path_prefix = _agent_path(
            request["path_prefix"],
            "$.raw_evidence.list.request.filtered_host_input.path_prefix",
        )
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_filtered_list_request_malformed", "list") from exc

    target = (workspace_root / raw_reference["path"]).resolve(strict=False)
    document = _read_json_file(
        target, "native_filtered_list_result_malformed", "list",
    )
    try:
        row = _closed(document, {"agents"}, "$.raw_evidence.list.raw_host_output")
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_filtered_list_result_malformed", "list") from exc
    if not isinstance(row["agents"], list) or len(row["agents"]) != 1:
        raise NativeIdentityError(
            "native_filtered_list_corroboration_disagrees",
            "$.raw_evidence.list.raw_host_output.agents",
        )
    try:
        agent = _closed(
            row["agents"][0], {"agent_name", "agent_status"},
            "$.raw_evidence.list.raw_host_output.agents[0]",
        )
        child = _agent_path(
            agent["agent_name"],
            "$.raw_evidence.list.raw_host_output.agents[0].agent_name",
        )
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_filtered_list_result_malformed", "list") from exc
    try:
        status = _closed(
            agent["agent_status"], {"completed"},
            "$.raw_evidence.list.raw_host_output.agents[0].agent_status",
        )
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_filtered_terminal_status_unproved", "list") from exc
    completed_payload_text = status["completed"]
    if not isinstance(completed_payload_text, str) or not completed_payload_text.strip():
        raise NativeIdentityError("native_filtered_terminal_status_unproved", "list")
    if path_prefix != child:
        raise NativeIdentityError("native_filtered_list_request_mismatch", "list")
    return {
        "filter_path_prefix": path_prefix,
        "child_agent_path": child,
        "terminal_status": "completed",
        "completed_payload_text": completed_payload_text,
    }


def _closed_pairs(items: list[tuple[str, Any]], error_code: str) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for key, value in items:
        if key in row:
            raise NativeIdentityError(error_code)
        row[key] = value
    return row


def _load_capture(
    request_descriptor: dict[str, Any], response_descriptor: dict[str, Any],
    operation: str, workspace_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    response_path = response_descriptor["path"]
    target = (workspace_root / response_path).resolve(strict=False)
    try:
        target.relative_to(workspace_root)
    except ValueError as exc:
        raise NativeIdentityError("native_raw_evidence_workspace_escape", "$.raw_evidence") from exc
    document = _read_json_file(target, "native_host_response_malformed", operation)
    common = {"schema_version", "artifact_type", "operation", "observation_source", "action_receipt_id", "raw_host_output", "payload"}
    try:
        row = _closed(document, common, f"$.raw_evidence.{operation}.response.capture")
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_host_response_malformed", operation) from exc
    if row["schema_version"] != 1 or row["operation"] != operation:
        raise NativeIdentityError("native_host_response_malformed", operation)
    if row["artifact_type"] not in {
        DESKTOP_OBSERVATION_TYPE,
        COLLABORATION_OBSERVATION_TYPE,
        COLLABORATION_FILTERED_OBSERVATION_TYPE,
    }:
        raise NativeIdentityError("native_host_abi_unsupported", operation)
    if row["observation_source"] != OBSERVATION_SOURCE:
        raise NativeIdentityError("native_observation_provenance_invalid", operation)
    _identifier(row["action_receipt_id"], f"$.raw_evidence.{operation}.response.action_receipt_id")
    raw_reference = _raw_reference(row["raw_host_output"], f"$.raw_evidence.{operation}.response.raw_host_output", response_path, workspace_root)
    if row["artifact_type"] == COLLABORATION_OBSERVATION_TYPE:
        facts = _parse_collaboration_raw(raw_reference, operation, workspace_root)
        expected_fields = {
            "create": {"child_agent_path"},
            "list": {"parent_agent_path", "parent_observed_status", "child_agent_path", "child_observed_status"},
            "read": {"message_type", "task_name", "sender_agent_path", "recipient_agent_path", "child_payload"},
        }[operation]
        payload = _closed(row["payload"], expected_fields, f"$.raw_evidence.{operation}.response.capture.payload")
        if operation == "create":
            _agent_path(payload["child_agent_path"], "$.raw_evidence.create.response.payload.child_agent_path")
            if payload != facts:
                raise NativeIdentityError("native_create_identity_not_host_returned", "$.raw_evidence.create")
        elif operation == "list":
            parent = _agent_path(payload["parent_agent_path"], "$.raw_evidence.list.response.payload.parent_agent_path")
            child = _agent_path(payload["child_agent_path"], "$.raw_evidence.list.response.payload.child_agent_path")
            parent_status = facts["agents"].get(parent)
            child_status = facts["agents"].get(child)
            if not isinstance(parent_status, str) or not isinstance(child_status, str):
                raise NativeIdentityError("native_list_corroboration_missing", "$.raw_evidence.list")
            if parent_status != payload["parent_observed_status"] or child_status != payload["child_observed_status"]:
                raise NativeIdentityError("native_list_corroboration_disagrees", "$.raw_evidence.list")
            if child_status not in COLLABORATION_ACTIVE_STATUSES:
                raise NativeIdentityError("native_list_status_unproved", "$.raw_evidence.list")
            facts = copy.deepcopy(payload)
        else:
            if payload != facts:
                raise NativeIdentityError("native_host_sender_recipient_mismatch", "$.raw_evidence.read")
        return copy.deepcopy(row), facts
    if row["artifact_type"] == COLLABORATION_FILTERED_OBSERVATION_TYPE:
        facts = _parse_filtered_collaboration_raw(
            raw_reference, request_descriptor, operation, workspace_root,
        )
        expected_fields = {
            "create": {"child_agent_path"},
            "list": {
                "filter_path_prefix", "child_agent_path", "terminal_status",
                "completed_payload_text",
            },
            "read": {
                "message_type", "task_name", "sender_agent_path",
                "recipient_agent_path", "child_payload",
            },
        }[operation]
        payload = _closed(
            row["payload"], expected_fields,
            f"$.raw_evidence.{operation}.response.capture.payload",
        )
        comparable_facts = {
            key: value for key, value in facts.items() if key != "payload_text"
        }
        if payload != comparable_facts:
            code = {
                "create": "native_create_identity_not_host_returned",
                "list": "native_filtered_list_corroboration_disagrees",
                "read": "native_host_sender_recipient_mismatch",
            }[operation]
            raise NativeIdentityError(code, f"$.raw_evidence.{operation}")
        return copy.deepcopy(row), facts
    payload_fields = {
        "create": {"host_id", "parent_thread_id", "child_thread_id", "intent_nonce", "lifecycle_event_id", "observed_identity"},
        "list": {"host_id", "parent_thread_id", "child_thread_id"},
        "read": {"host_id", "parent_thread_id", "child_thread_id", "lifecycle_event_id", "lifecycle_timestamp", "cursor", "observed_status", "observed_identity"},
    }[operation]
    try:
        payload = _closed(row["payload"], payload_fields, f"$.raw_evidence.{operation}.response.capture.payload")
    except NativeIdentityError as exc:
        raise NativeIdentityError("native_host_response_malformed", operation) from exc
    for field in ("host_id", "parent_thread_id", "child_thread_id"):
        _identifier(payload[field], f"$.raw_evidence.{operation}.response.payload.{field}")
    if operation == "create":
        _text(payload["intent_nonce"], f"$.raw_evidence.create.response.payload.intent_nonce")
        if NONCE.fullmatch(payload["intent_nonce"]) is None:
            raise NativeIdentityError("native_intent_nonce_missing", "$.raw_evidence.create.response.payload.intent_nonce")
    _identifier(payload["lifecycle_event_id"], f"$.raw_evidence.{operation}.response.payload.lifecycle_event_id") if operation in {"create", "read"} else None
    if operation == "read":
        _timestamp(payload["lifecycle_timestamp"], "$.raw_evidence.read.response.payload.lifecycle_timestamp")
        cursor = _closed(payload["cursor"], {"kind", "value", "direction"}, "$.raw_evidence.read.response.payload.cursor")
        if cursor["kind"] not in {"host_event_cursor", "host_turn_cursor"} or cursor["direction"] not in {"forward", "snapshot"}:
            raise NativeIdentityError("native_cursor_invalid", "$.raw_evidence.read.response.payload.cursor")
        _identifier(cursor["value"], "$.raw_evidence.read.response.payload.cursor.value")
        _text(payload["observed_status"], "$.raw_evidence.read.response.payload.observed_status")
    if operation in {"create", "read"}:
        identity = _closed(payload["observed_identity"], {"agent_path", "actual_model", "actual_reasoning", "actual_route_id"}, f"$.raw_evidence.{operation}.response.payload.observed_identity")
        for field in ("agent_path", "actual_model", "actual_reasoning", "actual_route_id"):
            _known_unknown(identity[field], f"$.raw_evidence.{operation}.response.payload.observed_identity.{field}")
    return copy.deepcopy(row), copy.deepcopy(payload)


def _verify_intent(value: dict[str, Any]) -> str:
    intent = _closed(value["intent"], {
        "intent_id", "intent_nonce", "intent_sha256", "created_at", "packet",
        "candidate_manifest_sha256", "requested_identity",
    }, "$.intent")
    _identifier(intent["intent_id"], "$.intent.intent_id")
    nonce = _text(intent["intent_nonce"], "$.intent.intent_nonce")
    if NONCE.fullmatch(nonce) is None:
        raise NativeIdentityError("native_intent_nonce_missing", "$.intent.intent_nonce")
    try:
        if len(base64.urlsafe_b64decode(nonce + "=") ) != 32:
            raise ValueError
    except (ValueError, binascii.Error) as exc:
        raise NativeIdentityError("native_intent_nonce_missing", "$.intent.intent_nonce") from exc
    _digest(intent["intent_sha256"], "$.intent.intent_sha256")
    intent_body = copy.deepcopy(intent)
    intent_body.pop("intent_sha256")
    if digest(intent_body) != value["intent"]["intent_sha256"]:
        raise NativeIdentityError("native_intent_digest_mismatch", "$.intent.intent_sha256")
    _timestamp(intent["created_at"], "$.intent.created_at")
    _digest(intent["candidate_manifest_sha256"], "$.intent.candidate_manifest_sha256")
    requested = intent["requested_identity"]
    desktop_fields = {
        "parent_thread_id", "semantic_role", "requested_model", "requested_reasoning",
        "requested_route_id", "requested_agent_path",
    }
    collaboration_fields = {
        "locator_kind", "parent_agent_path", "semantic_role", "requested_model",
        "requested_reasoning", "requested_route_id", "requested_agent_path",
    }
    if isinstance(requested, dict) and set(requested) == desktop_fields:
        requested_kind = "desktop_thread_id"
        _identifier(requested["parent_thread_id"], "$.intent.requested_identity.parent_thread_id")
    elif isinstance(requested, dict) and set(requested) == collaboration_fields:
        requested_kind = "collaboration_agent_path"
        if requested["locator_kind"] != requested_kind:
            raise NativeIdentityError("native_host_abi_unsupported", "$.intent.requested_identity.locator_kind")
        _agent_path(requested["parent_agent_path"], "$.intent.requested_identity.parent_agent_path")
    else:
        raise NativeIdentityError("native_shape_invalid", "$.intent.requested_identity")
    _text(requested["semantic_role"], "$.intent.requested_identity.semantic_role")
    for field in ("requested_model", "requested_reasoning", "requested_route_id", "requested_agent_path"):
        if requested[field] is not None:
            _text(requested[field], f"$.intent.requested_identity.{field}")
    return requested_kind


def _validate_host_identity(value: Any) -> tuple[dict[str, Any], str]:
    desktop_fields = {
        "host_id", "parent_thread_id", "child_thread_id", "agent_path", "actual_model",
        "actual_reasoning", "actual_route_id",
    }
    collaboration_fields = {
        "locator_kind", "host_instance", "parent_agent_path", "child_agent_path",
        "agent_path", "actual_model", "actual_reasoning", "actual_route_id",
    }
    if isinstance(value, dict) and set(value) == desktop_fields:
        row = value
        kind = "desktop_thread_id"
        for field in ("host_id", "parent_thread_id", "child_thread_id"):
            _identifier(row[field], f"$.host_returned_identity.{field}")
        if row["parent_thread_id"] == row["child_thread_id"]:
            raise NativeIdentityError("native_parent_child_relation_mismatch", "$.host_returned_identity")
    elif isinstance(value, dict) and set(value) == collaboration_fields:
        row = value
        kind = "collaboration_agent_path"
        if row["locator_kind"] != kind:
            raise NativeIdentityError("native_host_abi_unsupported", "$.host_returned_identity.locator_kind")
        _known_unknown(row["host_instance"], "$.host_returned_identity.host_instance")
        if row["host_instance"]["state"] != "unknown":
            raise NativeIdentityError("native_observed_identity_provenance_mismatch", "$.host_returned_identity.host_instance")
        parent = _agent_path(row["parent_agent_path"], "$.host_returned_identity.parent_agent_path")
        child = _agent_path(row["child_agent_path"], "$.host_returned_identity.child_agent_path")
        if not _direct_child(parent, child):
            raise NativeIdentityError("native_parent_child_relation_mismatch", "$.host_returned_identity")
    else:
        raise NativeIdentityError("native_shape_invalid", "$.host_returned_identity")
    for field in ("agent_path", "actual_model", "actual_reasoning", "actual_route_id"):
        _known_unknown(row[field], f"$.host_returned_identity.{field}")
    return row, kind


def _validate_binding(value: Any) -> tuple[dict[str, Any], str]:
    desktop_fields = {
        "host_binding_echo", "relationship_kind", "create_parent_child_match",
        "list_parent_child_match", "read_parent_child_match",
    }
    if isinstance(value, dict) and set(value) == desktop_fields:
        if value["relationship_kind"] not in {"host_create_parent_child", "host_read_delegation_source"}:
            raise NativeIdentityError("native_parent_child_relation_mismatch", "$.binding.relationship_kind")
        return value, "desktop_thread_id"
    row = _closed(value, {"relationship_kind"}, "$.binding")
    if row["relationship_kind"] != "host_collaboration_direct_child":
        raise NativeIdentityError("native_parent_child_relation_mismatch", "$.binding.relationship_kind")
    return row, "collaboration_agent_path"


def _validate_lifecycle(value: Any) -> tuple[dict[str, Any], str]:
    desktop_fields = {
        "create_host_event_id", "create_host_timestamp", "read_host_event_id",
        "read_host_timestamp", "read_cursor", "observed_status",
    }
    collaboration_fields = {
        "create_action_receipt_id", "list_action_receipt_id", "read_action_receipt_id",
        "list_observed_status", "read_message_type",
    }
    if isinstance(value, dict) and set(value) == desktop_fields:
        create_event = _identifier(value["create_host_event_id"], "$.lifecycle.create_host_event_id")
        read_event = _identifier(value["read_host_event_id"], "$.lifecycle.read_host_event_id")
        if create_event == read_event:
            raise NativeIdentityError("native_event_nonmonotonic", "$.lifecycle")
        create_at = _timestamp(value["create_host_timestamp"], "$.lifecycle.create_host_timestamp")
        read_at = _timestamp(value["read_host_timestamp"], "$.lifecycle.read_host_timestamp")
        if read_at < create_at:
            raise NativeIdentityError("native_event_nonmonotonic", "$.lifecycle.read_host_timestamp")
        cursor = _closed(value["read_cursor"], {"kind", "value", "direction"}, "$.lifecycle.read_cursor")
        if cursor["kind"] not in {"host_event_cursor", "host_turn_cursor"} or cursor["direction"] not in {"forward", "snapshot"}:
            raise NativeIdentityError("native_cursor_invalid", "$.lifecycle.read_cursor")
        _identifier(cursor["value"], "$.lifecycle.read_cursor.value")
        _text(value["observed_status"], "$.lifecycle.observed_status")
        return value, "desktop_thread_id"
    row = _closed(value, collaboration_fields, "$.lifecycle")
    action_ids = [
        _identifier(row[field], f"$.lifecycle.{field}")
        for field in ("create_action_receipt_id", "list_action_receipt_id", "read_action_receipt_id")
    ]
    if len(set(action_ids)) != 3:
        raise NativeIdentityError("native_action_receipt_collision", "$.lifecycle")
    if row["list_observed_status"] not in COLLABORATION_ACTIVE_STATUSES:
        raise NativeIdentityError("native_list_status_unproved", "$.lifecycle.list_observed_status")
    if row["read_message_type"] != "FINAL_ANSWER":
        raise NativeIdentityError("native_read_corroboration_missing", "$.lifecycle.read_message_type")
    return row, "collaboration_agent_path"


def _verify_claim_semantics(value: dict[str, Any]) -> None:
    boundary = value["proof_boundary"]
    capability = value["capability_state"]
    proof = value["proof_state"]
    claim = value["claim_status"]
    reason = value["unproved_reason"]
    if boundary not in {"source_contract", "synthetic", "live_host"}:
        raise NativeIdentityError("native_proof_boundary_invalid", "$.proof_boundary")
    if capability not in {"native_available", "native_unavailable"}:
        raise NativeIdentityError("native_capability_state_invalid", "$.capability_state")
    if proof not in {"intent_recorded", "created_unverified", "corroborated"}:
        raise NativeIdentityError("native_proof_state_invalid", "$.proof_state")
    if claim not in {"native_proved", "not_proved"}:
        raise NativeIdentityError("native_claim_status_invalid", "$.claim_status")
    if claim == "native_proved":
        if boundary != "live_host":
            raise NativeIdentityError("native_requested_identity_promoted", "$.claim_status")
        if capability != "native_available" or proof != "corroborated":
            raise NativeIdentityError("native_proof_incomplete", "$.claim_status")
        if reason is not None:
            raise NativeIdentityError("native_proved_reason_present", "$.unproved_reason")
    elif not isinstance(reason, str) or not reason.strip():
        raise NativeIdentityError("native_unproved_reason_missing", "$.unproved_reason")


def validate_native_child_identity(
    value: Any,
    *,
    workspace_root: str | Path | None = None,
    verify_files: bool = False,
    seen_nonces: MutableSet[str] | None = None,
    seen_action_receipt_ids: MutableSet[str] | None = None,
    seen_raw_output_digests: MutableSet[str] | None = None,
    seen_raw_output_paths: MutableSet[str] | None = None,
    expected_previous_receipt_sha256: str | None | object = _CHAIN_UNSET,
) -> dict[str, Any]:
    """Validate a Parent-captured identity and return a detached copy.

    ``verify_files`` reads only the descriptors and raw-output references named
    by the receipt and requires them to remain below ``workspace_root``. It
    never discovers or loads an adapter.
    """
    value = copy.deepcopy(value)
    row = _closed(value, ROOT_FIELDS, "$")
    if row["schema_version"] != 1 or row["artifact_type"] != "NativeChildIdentity":
        raise NativeIdentityError("native_version_or_type_unsupported")
    _identifier(row["receipt_id"], "$.receipt_id")
    _timestamp(row["captured_at"], "$.captured_at")
    _verify_claim_semantics(row)
    if row["claim_status"] == "native_proved" and (workspace_root is None or verify_files is not True):
        raise NativeIdentityError("native_live_workspace_proof_required")
    if row["unproved_reason"] is not None:
        _text(row["unproved_reason"], "$.unproved_reason")

    candidate = _closed(row["candidate"], {"candidate_id", "manifest"}, "$.candidate")
    _identifier(candidate["candidate_id"], "$.candidate.candidate_id")
    _descriptor(candidate["manifest"], "$.candidate.manifest", workspace_root)
    requested_kind = _verify_intent(row)
    nonce = row["intent"]["intent_nonce"]
    if seen_nonces is not None and nonce in seen_nonces:
        raise NativeIdentityError("native_intent_nonce_replayed", "$.intent.intent_nonce")
    if row["intent"]["candidate_manifest_sha256"] != row["candidate"]["manifest"]["sha256"]:
        raise NativeIdentityError("native_candidate_binding_mismatch", "$.candidate.manifest.sha256")
    _descriptor(row["intent"]["packet"], "$.intent.packet", workspace_root)

    host, host_kind = _validate_host_identity(row["host_returned_identity"])
    requested = row["intent"]["requested_identity"]
    binding, binding_kind = _validate_binding(row["binding"])
    lifecycle, lifecycle_kind = _validate_lifecycle(row["lifecycle"])
    if len({requested_kind, host_kind, binding_kind, lifecycle_kind}) != 1:
        raise NativeIdentityError("native_host_abi_unsupported", "$.host_returned_identity")
    if host_kind == "desktop_thread_id":
        if host["parent_thread_id"] != requested["parent_thread_id"]:
            raise NativeIdentityError("native_parent_child_relation_mismatch", "$.host_returned_identity.parent_thread_id")
        if binding["host_binding_echo"] != row["intent"]["intent_nonce"]:
            raise NativeIdentityError("native_intent_nonce_echo_mismatch", "$.binding.host_binding_echo")
        for field in ("create_parent_child_match", "list_parent_child_match", "read_parent_child_match"):
            if binding[field] is not True and row["claim_status"] == "native_proved":
                raise NativeIdentityError("native_parent_child_relation_mismatch", f"$.binding.{field}")
    else:
        if host["parent_agent_path"] != requested["parent_agent_path"]:
            raise NativeIdentityError("native_parent_child_relation_mismatch", "$.host_returned_identity.parent_agent_path")

    raw = _closed(row["raw_evidence"], {"create", "list", "read"}, "$.raw_evidence")
    for operation in ("create", "list", "read"):
        exchange = _closed(raw[operation], {"request", "response"}, f"$.raw_evidence.{operation}")
        _descriptor(exchange["request"], f"$.raw_evidence.{operation}.request", workspace_root)
        _descriptor(exchange["response"], f"$.raw_evidence.{operation}.response", workspace_root)
    if verify_files:
        if workspace_root is None:
            raise NativeIdentityError("native_workspace_root_required")
        _verify_descriptor_files(row, workspace_root)

    chain = _closed(row["evidence_chain"], {
        "event_sequence", "previous_receipt_sha256", "receipt_sha256",
    }, "$.evidence_chain")
    if type(chain["event_sequence"]) is not int or chain["event_sequence"] < 1:
        raise NativeIdentityError("native_event_nonmonotonic", "$.evidence_chain.event_sequence")
    if chain["previous_receipt_sha256"] is not None:
        _digest(chain["previous_receipt_sha256"], "$.evidence_chain.previous_receipt_sha256")
        if chain["previous_receipt_sha256"] == chain["receipt_sha256"]:
            raise NativeIdentityError("native_raw_evidence_collision", "$.evidence_chain")
    _digest(chain["receipt_sha256"], "$.evidence_chain.receipt_sha256")
    body = copy.deepcopy(row)
    body["evidence_chain"] = copy.deepcopy(chain)
    body["evidence_chain"].pop("receipt_sha256")
    if digest(body) != chain["receipt_sha256"]:
        raise NativeIdentityError("native_receipt_digest_mismatch", "$.evidence_chain.receipt_sha256")
    if expected_previous_receipt_sha256 is not _CHAIN_UNSET:
        if expected_previous_receipt_sha256 is not None:
            _digest(expected_previous_receipt_sha256, "$.expected_previous_receipt_sha256")
        if chain["previous_receipt_sha256"] != expected_previous_receipt_sha256:
            raise NativeIdentityError("native_receipt_chain_mismatch", "$.evidence_chain.previous_receipt_sha256")

    action_receipt_ids: set[str] = set()
    raw_output_digests: set[str] = set()
    raw_output_paths: set[str] = set()
    if row["claim_status"] == "native_proved":
        if row["proof_boundary"] != "live_host" or row["capability_state"] != "native_available" or row["proof_state"] != "corroborated":
            raise NativeIdentityError("native_proof_incomplete")
        if host_kind == "desktop_thread_id" and (
            row["binding"]["create_parent_child_match"] is not True
            or row["binding"]["list_parent_child_match"] is not True
            or row["binding"]["read_parent_child_match"] is not True
        ):
            raise NativeIdentityError("native_parent_child_relation_mismatch")
        root = Path(workspace_root).resolve()
        loaded = {
            operation: _load_capture(
                raw[operation]["request"], raw[operation]["response"],
                operation, root,
            )
            for operation in ("create", "list", "read")
        }
        captures = {operation: item[0] for operation, item in loaded.items()}
        facts = {operation: item[1] for operation, item in loaded.items()}
        observation_types = {capture["artifact_type"] for capture in captures.values()}
        collaboration_observation_type: str | None = None
        if host_kind == "desktop_thread_id":
            if observation_types != {DESKTOP_OBSERVATION_TYPE}:
                raise NativeIdentityError("native_host_abi_unsupported", "$.raw_evidence")
        else:
            admitted_collaboration_types = {
                COLLABORATION_OBSERVATION_TYPE,
                COLLABORATION_FILTERED_OBSERVATION_TYPE,
            }
            if len(observation_types) != 1 or not observation_types <= admitted_collaboration_types:
                raise NativeIdentityError("native_host_abi_unsupported", "$.raw_evidence")
            collaboration_observation_type = next(iter(observation_types))
        action_receipt_ids = {capture["action_receipt_id"] for capture in captures.values()}
        if len(action_receipt_ids) != 3:
            raise NativeIdentityError("native_action_receipt_collision", "$.raw_evidence")
        raw_output_digests = {capture["raw_host_output"]["sha256"] for capture in captures.values()}
        raw_output_paths = {capture["raw_host_output"]["path"] for capture in captures.values()}
        if len(raw_output_digests) != 3 or len(raw_output_paths) != 3:
            raise NativeIdentityError("native_raw_evidence_collision", "$.raw_evidence")
        descriptor_paths = {item["path"] for _, item in _iter_descriptors(row)}
        descriptor_digests = {item["sha256"] for _, item in _iter_descriptors(row)}
        if descriptor_paths & raw_output_paths or descriptor_digests & raw_output_digests:
            raise NativeIdentityError("native_raw_evidence_collision", "$.raw_evidence")
        if seen_action_receipt_ids is not None and action_receipt_ids & seen_action_receipt_ids:
            raise NativeIdentityError("native_action_receipt_replayed", "$.raw_evidence")
        if seen_raw_output_digests is not None and raw_output_digests & seen_raw_output_digests:
            raise NativeIdentityError("native_raw_output_replayed", "$.raw_evidence")
        if seen_raw_output_paths is not None and raw_output_paths & seen_raw_output_paths:
            raise NativeIdentityError("native_raw_output_replayed", "$.raw_evidence")
        if host_kind == "collaboration_agent_path":
            create_facts = facts["create"]
            list_facts = facts["list"]
            read_facts = facts["read"]
            parent = host["parent_agent_path"]
            child = host["child_agent_path"]
            if create_facts["child_agent_path"] != child:
                raise NativeIdentityError("native_create_identity_not_host_returned", "$.raw_evidence.create")
            if not _direct_child(parent, child):
                raise NativeIdentityError("native_parent_child_relation_mismatch", "$.raw_evidence.list")
            if read_facts["task_name"] != child or read_facts["sender_agent_path"] != child or read_facts["recipient_agent_path"] != parent:
                raise NativeIdentityError("native_host_sender_recipient_mismatch", "$.raw_evidence.read")
            if collaboration_observation_type == COLLABORATION_OBSERVATION_TYPE:
                if list_facts["parent_agent_path"] != parent or list_facts["child_agent_path"] != child:
                    raise NativeIdentityError("native_list_corroboration_disagrees", "$.raw_evidence.list")
                observed_list_status = list_facts["child_observed_status"]
            else:
                if (
                    list_facts["filter_path_prefix"] != child
                    or list_facts["child_agent_path"] != child
                ):
                    raise NativeIdentityError(
                        "native_filtered_list_corroboration_disagrees",
                        "$.raw_evidence.list",
                    )
                if list_facts["completed_payload_text"] != read_facts["payload_text"]:
                    raise NativeIdentityError(
                        "native_filtered_terminal_payload_mismatch",
                        "$.raw_evidence.list",
                    )
                create_at = datetime.fromisoformat(
                    raw["create"]["response"]["captured_at"].replace("Z", "+00:00")
                )
                final_at = datetime.fromisoformat(
                    raw["read"]["response"]["captured_at"].replace("Z", "+00:00")
                )
                terminal_at = datetime.fromisoformat(
                    raw["list"]["response"]["captured_at"].replace("Z", "+00:00")
                )
                if not create_at <= final_at <= terminal_at:
                    raise NativeIdentityError(
                        "native_filtered_capture_nonmonotonic",
                        "$.raw_evidence",
                    )
                observed_list_status = list_facts["terminal_status"]
            payload = read_facts["child_payload"]
            expected_payload = {
                "intent_id": row["intent"]["intent_id"],
                "nonce": row["intent"]["intent_nonce"],
                "candidate_snapshot_sha256": row["candidate"]["manifest"]["sha256"],
                "packet_sha256": row["intent"]["packet"]["sha256"],
                "agent_path": child,
                "parent_path": parent,
            }
            for field, expected in expected_payload.items():
                if payload[field] != expected:
                    code = "native_intent_nonce_echo_mismatch" if field == "nonce" else "native_child_payload_mismatch"
                    raise NativeIdentityError(code, f"$.raw_evidence.read.child_payload.{field}")
            parsed_agent_path = {
                "state": "known", "value": child, "reason": None,
                "source": "parsed_host_evidence",
            }
            if host["agent_path"] != parsed_agent_path:
                raise NativeIdentityError("native_observed_identity_provenance_mismatch", "$.host_returned_identity.agent_path")
            for field in ("actual_model", "actual_reasoning", "actual_route_id"):
                if host[field]["state"] != "unknown" or host[field]["source"] != "host_unobserved":
                    raise NativeIdentityError("native_observed_identity_provenance_mismatch", f"$.host_returned_identity.{field}")
            if lifecycle != {
                "create_action_receipt_id": captures["create"]["action_receipt_id"],
                "list_action_receipt_id": captures["list"]["action_receipt_id"],
                "read_action_receipt_id": captures["read"]["action_receipt_id"],
                "list_observed_status": observed_list_status,
                "read_message_type": read_facts["message_type"],
            }:
                raise NativeIdentityError("native_lifecycle_observation_mismatch", "$.lifecycle")
        else:
            create_payload = captures["create"]["payload"]
            list_payload = captures["list"]["payload"]
            read_payload = captures["read"]["payload"]
            for operation, payload in (("create", create_payload), ("list", list_payload), ("read", read_payload)):
                if payload["host_id"] != host["host_id"] or payload["parent_thread_id"] != host["parent_thread_id"] or payload["child_thread_id"] != host["child_thread_id"]:
                    raise NativeIdentityError("native_host_observation_mismatch", operation)
            if create_payload["intent_nonce"] != row["intent"]["intent_nonce"]:
                raise NativeIdentityError("native_intent_nonce_echo_mismatch", "$.raw_evidence.create.response.payload.intent_nonce")
            if create_payload["lifecycle_event_id"] != lifecycle["create_host_event_id"]:
                raise NativeIdentityError("native_lifecycle_event_mismatch", "$.raw_evidence.create.response.payload.lifecycle_event_id")
            if read_payload["lifecycle_event_id"] != lifecycle["read_host_event_id"] or read_payload["lifecycle_timestamp"] != lifecycle["read_host_timestamp"] or read_payload["cursor"] != lifecycle["read_cursor"] or read_payload["observed_status"] != lifecycle["observed_status"]:
                raise NativeIdentityError("native_lifecycle_observation_mismatch", "$.raw_evidence.read.response.payload")
            create_identity = create_payload["observed_identity"]
            read_identity = read_payload["observed_identity"]
            for field in ("agent_path", "actual_model", "actual_reasoning", "actual_route_id"):
                if create_identity[field] != host[field] or read_identity[field] != host[field]:
                    raise NativeIdentityError("native_observed_identity_provenance_mismatch", f"$.host_returned_identity.{field}")

    if row["claim_status"] == "native_proved" and host_kind == "collaboration_agent_path":
        if expected_previous_receipt_sha256 is _CHAIN_UNSET:
            raise NativeIdentityError("native_receipt_chain_context_required", "$.evidence_chain")
        if any(item is None for item in (
            seen_nonces, seen_action_receipt_ids,
            seen_raw_output_digests, seen_raw_output_paths,
        )):
            raise NativeIdentityError("native_replay_context_required", "$.raw_evidence")
    if seen_nonces is not None:
        seen_nonces.add(nonce)
    if seen_action_receipt_ids is not None:
        seen_action_receipt_ids.update(action_receipt_ids)
    if seen_raw_output_digests is not None:
        seen_raw_output_digests.update(raw_output_digests)
    if seen_raw_output_paths is not None:
        seen_raw_output_paths.update(raw_output_paths)
    return row


def native_claim_status(value: Any, **kwargs: Any) -> str:
    """Validate and return the only claim status the evidence earns."""
    return validate_native_child_identity(value, **kwargs)["claim_status"]


UNAVAILABLE_CODES = {
    "native_shape_invalid", "native_intent_nonce_missing", "native_raw_evidence_missing",
    "native_lifecycle_event_missing", "native_candidate_binding_mismatch",
    "native_raw_evidence_path_invalid", "native_raw_evidence_workspace_escape",
}


def assess_native_child_identity(value: Any, **kwargs: Any) -> dict[str, Any]:
    """Return a fail-clear status without converting malformed input to proof."""
    try:
        validated = validate_native_child_identity(value, **kwargs)
    except NativeIdentityError as exc:
        if exc.code not in UNAVAILABLE_CODES:
            raise
        return {
            "accepted": False,
            "capability_state": "native_unavailable",
            "proof_state": "intent_recorded",
            "claim_status": "not_proved",
            "unproved_reason": exc.code,
        }
    return {
        "accepted": True,
        "capability_state": validated["capability_state"],
        "proof_state": validated["proof_state"],
        "claim_status": validated["claim_status"],
        "unproved_reason": validated["unproved_reason"],
    }


__all__ = [
    "NativeIdentityError", "assess_native_child_identity", "canonical", "digest",
    "native_claim_status", "validate_agent_path", "validate_native_child_identity",
]
