#!/usr/bin/env python3
"""Synchronize typed local Parent/Supervisor events without transcript reads."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
PARENT_EVENTS = {
    "parent_pause",
    "parent_resume",
    "parent_message",
    "parent_open",
    "parent_request_candidate_closeout",
    "parent_authority_response",
}
SUPERVISOR_EVENTS = {
    "milestone",
    "decision_needed",
    "failure",
    "validation",
    "candidate_closeout",
    "side_user_comment",
    "side_authority_change_request",
}
SYSTEM_EVENTS = {"sync_initialized"}
STATE_CURSOR_FIELDS = {"event_sequence", "last_event_hash"}
RELAY_EVENT_MAP = {
    "assignment_created": "milestone",
    "route_resolved": "milestone",
    "worker_result": "milestone",
    "repair_result": "milestone",
    "worker_self_test": "validation",
    "independent_test": "validation",
    "documentation_result": "milestone",
    "audit_result": "validation",
    "candidate_closeout": "candidate_closeout",
}
FORBIDDEN_KEYS = {
    "transcript",
    "raw_transcript",
    "chat_history",
    "conversation_history",
    "accepted",
    "accepted_by",
    "acceptance_authority",
    "goal_complete",
    "authority_granted",
    "scope_granted",
}


def _load_loop_runtime() -> Any:
    path = Path(__file__).with_name("run_goalbuddy_supervisor.py")
    spec = importlib.util.spec_from_file_location("codexmax_goalbuddy_loop_for_sync", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GoalBuddy Supervisor runtime")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_loop = _load_loop_runtime()


class SyncError(ValueError):
    """Fail-closed synchronization error with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SyncError("invalid_input", field)
    return value.strip()


def _timestamp(value: Any, field: str = "timestamp") -> str:
    value = _text(value, field)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise SyncError("invalid_input", field)
    return value


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SyncError("invalid_input", field)
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise SyncError("invalid_input", field)
    return [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _reject_forbidden(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in FORBIDDEN_KEYS:
                code = "transcript_ingestion_forbidden" if "transcript" in lowered or "history" in lowered else "authority_or_acceptance_self_grant_forbidden"
                raise SyncError(code, f"{path}.{key}")
            _reject_forbidden(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def _board_receipt(goal_path: Path, board_path: Path) -> dict[str, Any]:
    try:
        receipt = _loop.inspect_goalbuddy(
            goal_path,
            board_path,
            accepted_dependency_decisions={"accept", "accepted"},
        )
    except _loop.LoopError as exc:
        raise SyncError("goalbuddy_board_invalid", f"{exc.code}:{exc.detail}") from exc
    if receipt["active_task"] != "T005":
        raise SyncError("active_checkpoint_mismatch", receipt["active_task"])
    return receipt


def initial_state(receipt: dict[str, Any], parent_id: str, supervisor_id: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "goal_id": receipt["goal_slug"],
        "checkpoint_id": receipt["active_task"],
        "goal_sha256": receipt["goal_sha256"],
        "board_sha256": receipt["board_sha256"],
        "parent_id": _text(parent_id, "parent_id"),
        "supervisor_id": _text(supervisor_id, "supervisor_id"),
        "parent_route_contract": "gpt-5.6-sol",
        "supervisor_route_contract": "gpt-5.6-terra:high",
        "native_identity_verified": False,
        "state_epoch": 0,
        "status": "active",
        "paused": False,
        "pause_reason": None,
        "pending_authority_request": None,
        "last_authority_response": None,
        "closeout_requested": False,
        "candidate_closeout": None,
        "relayed_loop_event_hashes": [],
        "event_sequence": 0,
        "last_event_hash": ZERO_HASH,
        "last_event_id": None,
        "board_mutated": False,
        "transcript_ingested": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
        "external_action_performed": False,
    }


def _validate_state(value: Any, receipt: dict[str, Any]) -> dict[str, Any]:
    state = copy.deepcopy(_mapping(value, "state"))
    if state.get("schema_version") != SCHEMA_VERSION:
        raise SyncError("state_invalid", "schema_version")
    for field in ("goal_id", "checkpoint_id", "parent_id", "supervisor_id"):
        _text(state.get(field), f"state.{field}")
    if state.get("goal_id") != receipt["goal_slug"] or state.get("checkpoint_id") != receipt["active_task"]:
        raise SyncError("active_checkpoint_mismatch", str(state.get("checkpoint_id")))
    if state.get("goal_sha256") != receipt["goal_sha256"]:
        raise SyncError("locked_plan_changed", receipt["goal_sha256"])
    if state.get("board_sha256") != receipt["board_sha256"]:
        raise SyncError("board_changed_requires_reconcile", receipt["board_sha256"])
    if state.get("parent_route_contract") != "gpt-5.6-sol" or state.get("supervisor_route_contract") != "gpt-5.6-terra:high":
        raise SyncError("control_route_contract_changed")
    if state["parent_id"] == state["supervisor_id"]:
        raise SyncError("control_identity_collision")
    if state.get("native_identity_verified") is not False:
        raise SyncError("native_identity_claim_forbidden")
    if type(state.get("state_epoch")) is not int or state["state_epoch"] < 0:
        raise SyncError("state_invalid", "state_epoch")
    for field in ("board_mutated", "transcript_ingested", "native_side_proof", "acceptance_claimed", "external_action_performed"):
        if state.get(field) is not False:
            raise SyncError("local_boundary_violated", field)
    if state.get("status") not in {"active", "paused", "candidate_complete"}:
        raise SyncError("state_invalid", "status")
    if not isinstance(state.get("paused"), bool):
        raise SyncError("state_invalid", "paused")
    hashes = state.get("relayed_loop_event_hashes")
    if not isinstance(hashes, list) or len(hashes) != len(set(hashes)):
        raise SyncError("state_invalid", "relayed_loop_event_hashes")
    if type(state.get("event_sequence")) is not int or state["event_sequence"] < 0:
        raise SyncError("state_invalid", "event_sequence")
    if not isinstance(state.get("last_event_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", state["last_event_hash"]):
        raise SyncError("state_invalid", "last_event_hash")
    _text(state.get("last_event_id"), "state.last_event_id")
    return state


def _state_projection(state: dict[str, Any]) -> dict[str, Any]:
    """Return durable state with the event ID bound and cyclic head fields excluded."""

    return {key: copy.deepcopy(value) for key, value in state.items() if key not in STATE_CURSOR_FIELDS}


def _state_projection_hash(state: dict[str, Any]) -> str:
    return _hash(_state_projection(state))


def _event(value: Any) -> dict[str, Any]:
    event = copy.deepcopy(_mapping(value, "event"))
    required = {"schema_version", "event_id", "timestamp", "source_role", "actor_id", "event_type", "payload"}
    if set(event) != required or event.get("schema_version") != SCHEMA_VERSION:
        raise SyncError("event_invalid", "fields")
    for field in ("event_id", "timestamp", "source_role", "actor_id", "event_type"):
        event[field] = _text(event.get(field), f"event.{field}")
    event["timestamp"] = _timestamp(event["timestamp"], "event.timestamp")
    if event["source_role"] == "parent":
        if event["event_type"] not in PARENT_EVENTS:
            raise SyncError("event_role_mismatch", event["event_type"])
    elif event["source_role"] == "supervisor":
        if event["event_type"] not in SUPERVISOR_EVENTS:
            raise SyncError("event_role_mismatch", event["event_type"])
    else:
        raise SyncError("event_role_mismatch", event["source_role"])
    event["payload"] = copy.deepcopy(_mapping(event["payload"], "event.payload"))
    _reject_forbidden(event["payload"])
    return event


def _validate_payload(event_type: str, payload: dict[str, Any], *, relay_verified: bool) -> dict[str, Any]:
    payload = copy.deepcopy(payload)
    if event_type in {"milestone", "decision_needed", "failure", "validation"}:
        allowed = {"summary", "source_loop_event"} if relay_verified else {"summary"}
        if set(payload) != allowed:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("summary"), "payload.summary")
        if payload.get("source_loop_event") is not None and not relay_verified:
            raise SyncError("unverified_loop_relay")
    elif event_type == "candidate_closeout":
        if not relay_verified:
            raise SyncError("candidate_closeout_requires_verified_loop_event")
        if set(payload) != {"summary", "source_loop_event", "status", "applied_to_goalbuddy"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        if payload.get("status") != "candidate_complete" or payload.get("applied_to_goalbuddy") is not False:
            raise SyncError("candidate_closeout_invalid")
    elif event_type == "side_user_comment":
        if set(payload) != {"comment_id", "side_task_id", "observed_item_id", "text", "requires_parent_response"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("comment_id"), "payload.comment_id")
        _text(payload.get("side_task_id"), "payload.side_task_id")
        _text(payload.get("observed_item_id"), "payload.observed_item_id")
        _text(payload.get("text"), "payload.text")
        if not isinstance(payload.get("requires_parent_response"), bool):
            raise SyncError("invalid_input", "payload.requires_parent_response")
    elif event_type == "side_authority_change_request":
        if set(payload) != {"request_id", "side_task_id", "observed_item_id", "summary", "exact_scope", "status", "applied_to_execution"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("request_id"), "payload.request_id")
        _text(payload.get("side_task_id"), "payload.side_task_id")
        _text(payload.get("observed_item_id"), "payload.observed_item_id")
        _text(payload.get("summary"), "payload.summary")
        _string_list(payload.get("exact_scope"), "payload.exact_scope")
        if payload.get("status") != "pending" or payload.get("applied_to_execution") is not False:
            raise SyncError("authority_or_acceptance_self_grant_forbidden", "authority request")
    elif event_type == "parent_pause":
        if set(payload) != {"reason"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("reason"), "payload.reason")
    elif event_type == "parent_resume":
        if set(payload) != {"reason"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("reason"), "payload.reason")
    elif event_type == "parent_message":
        if set(payload) != {"message_id", "text"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("message_id"), "payload.message_id")
        _text(payload.get("text"), "payload.text")
    elif event_type == "parent_open":
        if set(payload) != {"reason", "native_open_performed"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("reason"), "payload.reason")
        if payload.get("native_open_performed") is not False:
            raise SyncError("native_action_claim_forbidden")
    elif event_type == "parent_request_candidate_closeout":
        if set(payload) != {"reason"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("reason"), "payload.reason")
    elif event_type == "parent_authority_response":
        if set(payload) != {"request_id", "decision", "authority_record_ref", "applied_to_execution"}:
            raise SyncError("event_payload_fields_invalid", event_type)
        _text(payload.get("request_id"), "payload.request_id")
        if payload.get("decision") not in {"approve", "deny"}:
            raise SyncError("invalid_input", "payload.decision")
        _text(payload.get("authority_record_ref"), "payload.authority_record_ref")
        if payload.get("applied_to_execution") is not False:
            raise SyncError("authority_or_acceptance_self_grant_forbidden", "authority response")
    return payload


def transition(state_value: Any, receipt: dict[str, Any], event_value: Any, *, relay_verified: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    state = _validate_state(state_value, receipt)
    event = _event(event_value)
    expected_actor = state["parent_id"] if event["source_role"] == "parent" else state["supervisor_id"]
    if event["actor_id"] != expected_actor:
        raise SyncError("actor_identity_mismatch", event["actor_id"])
    event_type = event["event_type"]
    payload = _validate_payload(event_type, event["payload"], relay_verified=relay_verified)
    if state["status"] == "candidate_complete" and event_type not in {"parent_open", "parent_message", "side_user_comment"}:
        raise SyncError("candidate_already_closed")
    if state["paused"] and event["source_role"] == "supervisor" and event_type in {"milestone", "validation", "candidate_closeout"}:
        raise SyncError("supervisor_progress_while_paused", event_type)

    if event_type == "parent_pause":
        state["paused"] = True
        state["status"] = "paused"
        state["pause_reason"] = payload["reason"]
    elif event_type == "parent_resume":
        if state["pending_authority_request"] is not None:
            raise SyncError("authority_response_required", state["pending_authority_request"]["request_id"])
        state["paused"] = False
        state["status"] = "active"
        state["pause_reason"] = None
    elif event_type == "parent_open":
        payload["control_status"] = "local_request_recorded"
        payload["target_supervisor_id"] = state["supervisor_id"]
    elif event_type == "parent_message":
        payload["control_status"] = "local_request_recorded"
        payload["target_supervisor_id"] = state["supervisor_id"]
    elif event_type == "parent_request_candidate_closeout":
        state["closeout_requested"] = True
        payload["control_status"] = "requested_not_accepted"
    elif event_type == "side_user_comment" and payload["requires_parent_response"]:
        state["paused"] = True
        state["status"] = "paused"
        state["pause_reason"] = f"side_user_comment:{payload['comment_id']}"
    elif event_type == "side_authority_change_request":
        if state["pending_authority_request"] is not None:
            raise SyncError("authority_request_already_pending", state["pending_authority_request"]["request_id"])
        state["pending_authority_request"] = {
            "request_id": payload["request_id"],
            "source_event_id": event["event_id"],
            "exact_scope": copy.deepcopy(payload["exact_scope"]),
        }
        state["paused"] = True
        state["status"] = "paused"
        state["pause_reason"] = f"authority_change:{payload['request_id']}"
    elif event_type == "parent_authority_response":
        pending = state["pending_authority_request"]
        if pending is None or pending["request_id"] != payload["request_id"]:
            raise SyncError("authority_request_mismatch", payload["request_id"])
        state["last_authority_response"] = {
            "request_id": payload["request_id"],
            "decision": payload["decision"],
            "authority_record_ref": payload["authority_record_ref"],
            "applied_to_execution": False,
        }
        state["pending_authority_request"] = None
        payload["resume_required"] = True
    elif event_type == "candidate_closeout":
        state["candidate_closeout"] = copy.deepcopy(payload)
        state["status"] = "candidate_complete"
        state["paused"] = False

    source_loop = payload.get("source_loop_event")
    if source_loop is not None:
        source_loop = _mapping(source_loop, "payload.source_loop_event")
        source_hash = _text(source_loop.get("event_hash"), "source_loop_event.event_hash")
        if source_hash in state["relayed_loop_event_hashes"]:
            raise SyncError("loop_event_already_relayed", source_hash)
        state["relayed_loop_event_hashes"].append(source_hash)
    for field in ("board_mutated", "transcript_ingested", "native_side_proof", "acceptance_claimed", "external_action_performed"):
        state[field] = False
    return state, payload


def _record(before: dict[str, Any], after: dict[str, Any], event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    record = {
        "schema_version": SCHEMA_VERSION,
        "sequence": before["event_sequence"] + 1,
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "goal_id": before["goal_id"],
        "checkpoint_id": before["checkpoint_id"],
        "source_role": event["source_role"],
        "actor_id": event["actor_id"],
        "event_type": event["event_type"],
        "payload": payload,
        "previous_event_hash": before["last_event_hash"],
        "board_sha256": before["board_sha256"],
        "state_before_hash": _state_projection_hash(before),
        "state_after_hash": _state_projection_hash(after),
        "audience": "parent" if event["source_role"] == "supervisor" else "supervisor",
        "proof_boundary": "local_not_native",
        "external_action_performed": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }
    record["event_hash"] = _hash(record)
    return record


def _initialization_record(state: dict[str, Any], timestamp: str) -> dict[str, Any]:
    projection_hash = _state_projection_hash(state)
    record = {
        "schema_version": SCHEMA_VERSION,
        "sequence": 1,
        "event_id": "sync-initialized",
        "timestamp": _timestamp(timestamp),
        "goal_id": state["goal_id"],
        "checkpoint_id": state["checkpoint_id"],
        "source_role": "system",
        "actor_id": "synchronization-runtime",
        "event_type": "sync_initialized",
        "payload": {
            "goal_id": state["goal_id"],
            "checkpoint_id": state["checkpoint_id"],
            "parent_id": state["parent_id"],
            "supervisor_id": state["supervisor_id"],
            "parent_route_contract": state["parent_route_contract"],
            "supervisor_route_contract": state["supervisor_route_contract"],
            "board_sha256": state["board_sha256"],
            "state_epoch": state["state_epoch"],
            "state_projection_hash": projection_hash,
        },
        "previous_event_hash": ZERO_HASH,
        "board_sha256": state["board_sha256"],
        "state_before_hash": ZERO_HASH,
        "state_after_hash": projection_hash,
        "audience": "none",
        "proof_boundary": "local_not_native",
        "external_action_performed": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }
    record["event_hash"] = _hash(record)
    return record


def verify_event_log(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SyncError("event_log_unreadable", str(exc)) from exc
    previous = ZERO_HASH
    records: list[dict[str, Any]] = []
    ids: set[str] = set()
    previous_state_hash = ZERO_HASH
    initialization_identity: dict[str, Any] | None = None
    for sequence, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SyncError("event_log_invalid", f"{sequence}:{exc.msg}") from exc
        if not isinstance(record, dict) or record.get("sequence") != sequence or record.get("previous_event_hash") != previous:
            raise SyncError("event_log_chain_mismatch", str(sequence))
        candidate = copy.deepcopy(record)
        recorded_hash = candidate.pop("event_hash", None)
        if recorded_hash != _hash(candidate):
            raise SyncError("event_log_hash_mismatch", str(sequence))
        if record.get("event_id") in ids:
            raise SyncError("event_id_duplicate", str(record.get("event_id")))
        if record.get("schema_version") != SCHEMA_VERSION or record.get("proof_boundary") != "local_not_native":
            raise SyncError("event_log_boundary_invalid", str(sequence))
        if record.get("external_action_performed") is not False or record.get("native_side_proof") is not False or record.get("acceptance_claimed") is not False:
            raise SyncError("event_log_boundary_invalid", str(sequence))
        role = record.get("source_role")
        event_type = record.get("event_type")
        if sequence == 1:
            if role != "system" or event_type not in SYSTEM_EVENTS or record.get("audience") != "none":
                raise SyncError("event_log_initialization_invalid")
            initialization_identity = _mapping(record.get("payload"), "initialization.payload")
            expected_initialization_fields = {
                "goal_id", "checkpoint_id", "parent_id", "supervisor_id",
                "parent_route_contract", "supervisor_route_contract",
                "board_sha256", "state_epoch", "state_projection_hash",
            }
            if set(initialization_identity) != expected_initialization_fields:
                raise SyncError("event_log_initialization_invalid")
            if record.get("state_before_hash") != ZERO_HASH or record.get("state_after_hash") != initialization_identity["state_projection_hash"]:
                raise SyncError("event_log_state_chain_mismatch", str(sequence))
        elif (role == "parent" and event_type not in PARENT_EVENTS) or (role == "supervisor" and event_type not in SUPERVISOR_EVENTS) or role not in {"parent", "supervisor"}:
            raise SyncError("event_log_type_invalid", str(sequence))
        expected_audience = "none" if role == "system" else ("parent" if role == "supervisor" else "supervisor")
        if record.get("audience") != expected_audience:
            raise SyncError("event_log_audience_invalid", str(sequence))
        if record.get("state_before_hash") != previous_state_hash:
            raise SyncError("event_log_state_chain_mismatch", str(sequence))
        state_after_hash = record.get("state_after_hash")
        if not isinstance(state_after_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", state_after_hash):
            raise SyncError("event_log_state_chain_mismatch", str(sequence))
        ids.add(record["event_id"])
        previous = recorded_hash
        previous_state_hash = state_after_hash
        records.append(record)
    if initialization_identity is None:
        raise SyncError("event_log_initialization_invalid")
    return {
        "records": records,
        "event_count": len(records),
        "last_event_hash": previous,
        "last_event_id": records[-1]["event_id"],
        "last_state_projection_hash": previous_state_hash,
        "initialization_identity": initialization_identity,
        "event_ids": ids,
    }


def _bind_state_to_log(state: dict[str, Any], log: dict[str, Any]) -> None:
    state_head = (state["event_sequence"], state["last_event_id"], state["last_event_hash"])
    replayed_head = (log["event_count"], log["last_event_id"], log["last_event_hash"])
    if state_head != replayed_head:
        raise SyncError("runtime_state_event_log_mismatch")
    if _state_projection_hash(state) != log["last_state_projection_hash"]:
        raise SyncError("runtime_state_projection_mismatch")
    identity = log["initialization_identity"]
    expected = {
        "goal_id": state["goal_id"],
        "checkpoint_id": state["checkpoint_id"],
        "parent_id": state["parent_id"],
        "supervisor_id": state["supervisor_id"],
        "parent_route_contract": state["parent_route_contract"],
        "supervisor_route_contract": state["supervisor_route_contract"],
        "board_sha256": state["board_sha256"],
        "state_epoch": state["state_epoch"],
        "state_projection_hash": identity.get("state_projection_hash"),
    }
    if identity != expected:
        raise SyncError("initialization_identity_mismatch")


def _append(path: Path, value: dict[str, Any], *, create: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x" if create else "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _create_empty(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.flush()
        os.fsync(stream.fileno())


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _cursor_record(previous: dict[str, Any] | None, state: dict[str, Any], event_sequence: int, event_hash: str, delta_count: int, timestamp: str) -> dict[str, Any]:
    record = {
        "schema_version": SCHEMA_VERSION,
        "cursor_sequence": 1 if previous is None else previous["cursor_sequence"] + 1,
        "goal_id": state["goal_id"],
        "checkpoint_id": state["checkpoint_id"],
        "reader_role": "parent",
        "last_event_sequence": event_sequence,
        "last_event_hash": event_hash,
        "delta_count": delta_count,
        "timestamp": timestamp,
        "previous_cursor_hash": ZERO_HASH if previous is None else previous["cursor_hash"],
    }
    record["cursor_hash"] = _hash(record)
    return record


def verify_cursor_log(path: Path, event_records: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SyncError("cursor_log_unreadable", str(exc)) from exc
    if not lines:
        raise SyncError("cursor_log_invalid", "empty")
    previous_hash = ZERO_HASH
    previous_event_sequence = -1
    last: dict[str, Any] | None = None
    for cursor_sequence, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SyncError("cursor_log_invalid", f"{cursor_sequence}:{exc.msg}") from exc
        candidate = copy.deepcopy(record)
        recorded_hash = candidate.pop("cursor_hash", None)
        if record.get("cursor_sequence") != cursor_sequence or record.get("previous_cursor_hash") != previous_hash or recorded_hash != _hash(candidate):
            raise SyncError("cursor_log_chain_mismatch", str(cursor_sequence))
        event_sequence = record.get("last_event_sequence")
        if type(event_sequence) is not int or event_sequence < previous_event_sequence or event_sequence > len(event_records):
            raise SyncError("cursor_not_monotonic", str(event_sequence))
        expected_hash = ZERO_HASH if event_sequence == 0 else event_records[event_sequence - 1]["event_hash"]
        if record.get("last_event_hash") != expected_hash:
            raise SyncError("cursor_event_hash_mismatch", str(event_sequence))
        if record.get("goal_id") != state["goal_id"] or record.get("checkpoint_id") != state["checkpoint_id"] or record.get("reader_role") != "parent":
            raise SyncError("cursor_identity_mismatch")
        if type(record.get("delta_count")) is not int or record["delta_count"] < 0:
            raise SyncError("cursor_log_invalid", "delta_count")
        _timestamp(record.get("timestamp"), "cursor.timestamp")
        previous_event_sequence = event_sequence
        previous_hash = recorded_hash
        last = record
    assert last is not None
    return last


def initialize_files(goal_path: Path, board_path: Path, state_path: Path, events_path: Path, cursor_path: Path, parent_id: str, supervisor_id: str, timestamp: str) -> dict[str, Any]:
    if state_path.exists() or events_path.exists() or cursor_path.exists():
        raise SyncError("runtime_already_exists")
    receipt = _board_receipt(goal_path, board_path)
    state = initial_state(receipt, parent_id, supervisor_id)
    state["last_event_id"] = "sync-initialized"
    initialization = _initialization_record(state, timestamp)
    state["event_sequence"] = 1
    state["last_event_hash"] = initialization["event_hash"]
    state["last_event_id"] = initialization["event_id"]
    _append(events_path, initialization, create=True)
    cursor = _cursor_record(None, state, 0, ZERO_HASH, 0, _timestamp(timestamp))
    _append(cursor_path, cursor, create=True)
    _atomic_json(state_path, state)
    return {"state": state, "cursor": cursor}


def _append_event_core(state: dict[str, Any], receipt: dict[str, Any], event: dict[str, Any], events_path: Path, *, relay_verified: bool) -> dict[str, Any]:
    log = verify_event_log(events_path)
    _bind_state_to_log(state, log)
    if event["event_id"] in log["event_ids"]:
        raise SyncError("event_id_duplicate", event["event_id"])
    updated, payload = transition(state, receipt, event, relay_verified=relay_verified)
    updated["last_event_id"] = event["event_id"]
    record = _record(state, updated, event, payload)
    updated["event_sequence"] = record["sequence"]
    updated["last_event_hash"] = record["event_hash"]
    updated["last_event_id"] = record["event_id"]
    _append(events_path, record)
    return {"state": updated, "delta": record}


def apply_event_files(goal_path: Path, board_path: Path, state_path: Path, events_path: Path, cursor_path: Path, event_path: Path) -> dict[str, Any]:
    receipt = _board_receipt(goal_path, board_path)
    state = _validate_state(json.loads(state_path.read_text(encoding="utf-8")), receipt)
    current_log = verify_event_log(events_path)
    verify_cursor_log(cursor_path, current_log["records"], state)
    event = _event(json.loads(event_path.read_text(encoding="utf-8")))
    result = _append_event_core(state, receipt, event, events_path, relay_verified=False)
    _atomic_json(state_path, result["state"])
    return result


def _verify_loop_record(value: Any) -> dict[str, Any]:
    record = copy.deepcopy(_mapping(value, "loop_record"))
    recorded_hash = record.pop("event_hash", None)
    if not isinstance(recorded_hash, str) or recorded_hash != _hash(record):
        raise SyncError("loop_event_hash_mismatch")
    record["event_hash"] = recorded_hash
    if record.get("proof_boundary") != "local" or record.get("native_side_proof") is not False or record.get("external_call_performed") is not False or record.get("acceptance_claimed") is not False:
        raise SyncError("loop_event_boundary_invalid")
    if record.get("event_type") not in RELAY_EVENT_MAP:
        raise SyncError("loop_event_not_relayable", str(record.get("event_type")))
    return record


def _read_verified_loop_record(path: Path, sequence: int, state: dict[str, Any]) -> dict[str, Any]:
    if type(sequence) is not int or sequence < 1:
        raise SyncError("invalid_input", "loop_sequence")
    try:
        verified = _loop.verify_event_log(path)
    except _loop.LoopError as exc:
        raise SyncError("loop_event_log_invalid", f"{exc.code}:{exc.detail}") from exc
    if sequence > verified["event_count"]:
        raise SyncError("loop_event_sequence_missing", str(sequence))
    try:
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        record = records[sequence - 1]
    except (OSError, json.JSONDecodeError, IndexError) as exc:
        raise SyncError("loop_event_sequence_missing", str(sequence)) from exc
    first = records[0]
    board_receipt = first.get("payload", {}).get("board_receipt", {})
    if first.get("event_type") != "loop_initialized" or board_receipt.get("goal_slug") != state["goal_id"] or board_receipt.get("active_task") != state["checkpoint_id"]:
        raise SyncError("loop_event_identity_mismatch")
    if any(item.get("board_sha256") != state["board_sha256"] for item in records):
        raise SyncError("loop_event_board_mismatch")
    for item in records:
        if item.get("proof_boundary") != "local" or item.get("native_side_proof") is not False or item.get("external_call_performed") is not False or item.get("acceptance_claimed") is not False:
            raise SyncError("loop_event_boundary_invalid")
    return _verify_loop_record(record)


def relay_loop_event_files(goal_path: Path, board_path: Path, state_path: Path, events_path: Path, cursor_path: Path, loop_events_path: Path, loop_sequence: int, event_id: str, timestamp: str) -> dict[str, Any]:
    receipt = _board_receipt(goal_path, board_path)
    state = _validate_state(json.loads(state_path.read_text(encoding="utf-8")), receipt)
    current_log = verify_event_log(events_path)
    verify_cursor_log(cursor_path, current_log["records"], state)
    loop_record = _read_verified_loop_record(loop_events_path, loop_sequence, state)
    event_type = RELAY_EVENT_MAP[loop_record["event_type"]]
    payload = loop_record.get("payload", {})
    if event_type == "validation":
        failed = payload.get("result") == "fail" or any(row.get("result") != "pass" for row in payload.get("commands", []))
        if failed:
            event_type = "failure"
    summary = f"Supervisor loop {loop_record['event_type']} at sequence {loop_record['sequence']}"
    relay_payload: dict[str, Any] = {
        "summary": summary,
        "source_loop_event": {
            "sequence": loop_record["sequence"],
            "event_id": loop_record["event_id"],
            "event_type": loop_record["event_type"],
            "event_hash": loop_record["event_hash"],
        },
    }
    if event_type == "candidate_closeout":
        relay_payload.update({"status": "candidate_complete", "applied_to_goalbuddy": False})
    event = _event({
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "timestamp": timestamp,
        "source_role": "supervisor",
        "actor_id": state["supervisor_id"],
        "event_type": event_type,
        "payload": relay_payload,
    })
    result = _append_event_core(state, receipt, event, events_path, relay_verified=True)
    _atomic_json(state_path, result["state"])
    return result


def consume_parent_deltas(goal_path: Path, board_path: Path, state_path: Path, events_path: Path, cursor_path: Path, timestamp: str, scan_limit: int = 50) -> dict[str, Any]:
    if type(scan_limit) is not int or not 1 <= scan_limit <= 100:
        raise SyncError("invalid_input", "scan_limit")
    receipt = _board_receipt(goal_path, board_path)
    state = _validate_state(json.loads(state_path.read_text(encoding="utf-8")), receipt)
    log = verify_event_log(events_path)
    _bind_state_to_log(state, log)
    cursor = verify_cursor_log(cursor_path, log["records"], state)
    start = cursor["last_event_sequence"]
    batch = log["records"][start : start + scan_limit]
    if not batch:
        return {"deltas": [], "cursor": cursor, "scanned": 0}
    deltas = [copy.deepcopy(record) for record in batch if record["audience"] == "parent"]
    last = batch[-1]
    next_cursor = _cursor_record(cursor, state, last["sequence"], last["event_hash"], len(deltas), _timestamp(timestamp))
    _append(cursor_path, next_cursor)
    return {"deltas": deltas, "cursor": next_cursor, "scanned": len(batch)}


def snapshot_files(goal_path: Path, board_path: Path, state_path: Path, events_path: Path, cursor_path: Path) -> dict[str, Any]:
    receipt = _board_receipt(goal_path, board_path)
    state = _validate_state(json.loads(state_path.read_text(encoding="utf-8")), receipt)
    log = verify_event_log(events_path)
    _bind_state_to_log(state, log)
    cursor = verify_cursor_log(cursor_path, log["records"], state)
    return {
        "schema_version": SCHEMA_VERSION,
        "goal_id": state["goal_id"],
        "checkpoint_id": state["checkpoint_id"],
        "status": state["status"],
        "paused": state["paused"],
        "event_count": log["event_count"],
        "parent_last_read_sequence": cursor["last_event_sequence"],
        "unread_event_count": log["event_count"] - cursor["last_event_sequence"],
        "pending_authority_request": state["pending_authority_request"],
        "candidate_closeout": state["candidate_closeout"],
        "board_mutated": False,
        "transcript_ingested": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {name: sub.add_parser(name) for name in ("initialize", "apply", "relay-loop", "consume", "snapshot")}
    for child in commands.values():
        child.add_argument("--goal", type=Path, required=True)
        child.add_argument("--board", type=Path, required=True)
        child.add_argument("--state", type=Path, required=True)
        child.add_argument("--events", type=Path, required=True)
        child.add_argument("--cursor", type=Path, required=True)
    commands["initialize"].add_argument("--parent-id", required=True)
    commands["initialize"].add_argument("--supervisor-id", required=True)
    commands["initialize"].add_argument("--timestamp", required=True)
    commands["apply"].add_argument("--event", type=Path, required=True)
    commands["relay-loop"].add_argument("--loop-events", type=Path, required=True)
    commands["relay-loop"].add_argument("--loop-sequence", type=int, required=True)
    commands["relay-loop"].add_argument("--event-id", required=True)
    commands["relay-loop"].add_argument("--timestamp", required=True)
    commands["consume"].add_argument("--timestamp", required=True)
    commands["consume"].add_argument("--scan-limit", type=int, default=50)
    args = parser.parse_args(argv)
    try:
        if args.command == "initialize":
            result = initialize_files(args.goal, args.board, args.state, args.events, args.cursor, args.parent_id, args.supervisor_id, args.timestamp)
        elif args.command == "apply":
            result = apply_event_files(args.goal, args.board, args.state, args.events, args.cursor, args.event)
        elif args.command == "relay-loop":
            result = relay_loop_event_files(args.goal, args.board, args.state, args.events, args.cursor, args.loop_events, args.loop_sequence, args.event_id, args.timestamp)
        elif args.command == "consume":
            result = consume_parent_deltas(args.goal, args.board, args.state, args.events, args.cursor, args.timestamp, args.scan_limit)
        else:
            result = snapshot_files(args.goal, args.board, args.state, args.events, args.cursor)
    except (OSError, json.JSONDecodeError, SyncError) as exc:
        code = exc.code if isinstance(exc, SyncError) else "io_or_json_error"
        detail = exc.detail if isinstance(exc, SyncError) else str(exc)
        print(json.dumps({"status": "failed", "code": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
