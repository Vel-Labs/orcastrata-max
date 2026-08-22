#!/usr/bin/env python3
"""Recover local Supervisor control state from verified GoalBuddy/T012/T005 history."""

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
EVENT_TYPES = {
    "goalbuddy_reconciled",
    "pause",
    "resume",
    "revise",
    "repair_assignment_authorized",
    "repair_assignment_acknowledged",
    "stop",
    "restart_verified",
    "cursor_recovered",
}
PARENT_EVENTS = {"goalbuddy_reconciled", "pause", "resume", "revise", "repair_assignment_authorized", "stop", "cursor_recovered"}
SUPERVISOR_EVENTS = {"repair_assignment_acknowledged", "restart_verified"}
PROJECTION_EXCLUDED_FIELDS = {"event_sequence", "last_event_hash"}
FORBIDDEN_KEYS = {
    "transcript",
    "raw_transcript",
    "chat_history",
    "conversation_history",
    "board_from_transcript",
    "authority_from_transcript",
    "accepted",
    "accepted_by",
    "authority_granted",
    "goal_complete",
}


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SCRIPT_PATH = Path(__file__).resolve()
_loop = _load_module("codexmax_loop_for_recovery", SCRIPT_PATH.with_name("run_goalbuddy_supervisor.py"))
_sync = _load_module("codexmax_sync_for_recovery", SCRIPT_PATH.with_name("synchronize_parent_supervisor.py"))


class RecoveryError(ValueError):
    """Fail-closed recovery error with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("invalid_input", field)
    return value


def _text(value: Any, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise RecoveryError("invalid_input", field)
    return value.strip()


def _timestamp(value: Any) -> str:
    value = _text(value, "timestamp")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise RecoveryError("invalid_input", "timestamp")
    return value


def _string_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise RecoveryError("invalid_input", field)
    result = [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise RecoveryError("invalid_input", f"{field}:duplicates")
    return result


def _reject_forbidden(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in FORBIDDEN_KEYS:
                code = "transcript_reconstruction_forbidden" if "transcript" in lowered else "authority_or_board_reconstruction_forbidden"
                raise RecoveryError(code, f"{path}.{key}")
            _reject_forbidden(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def _load_json(path: Path, code: str) -> dict[str, Any]:
    try:
        return copy.deepcopy(_mapping(json.loads(path.read_text(encoding="utf-8")), str(path)))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError(code, str(exc)) from exc


def _board_receipt(goal_path: Path, board_path: Path) -> dict[str, Any]:
    try:
        receipt = _loop.inspect_goalbuddy(
            goal_path,
            board_path,
            accepted_dependency_decisions={"accept", "accepted"},
        )
    except _loop.LoopError as exc:
        raise RecoveryError("goalbuddy_reconciliation_failed", f"{exc.code}:{exc.detail}") from exc
    if receipt["active_task"] != "T006":
        raise RecoveryError("stale_goalbuddy_task", receipt["active_task"])
    accepted = {item["task_id"] for item in receipt["dependencies"]}
    if "T005" not in accepted:
        raise RecoveryError("accepted_predecessor_missing", "T005")
    return receipt


def _loop_binding(
    state_path: Path,
    events_path: Path,
    goal_path: Path,
    board_path: Path,
    receipt: dict[str, Any],
    repository_root: Path,
) -> dict[str, Any]:
    state = _load_json(state_path, "loop_state_unreadable")
    try:
        log = _loop.verify_event_log(events_path)
    except _loop.LoopError as exc:
        raise RecoveryError("loop_history_invalid", f"{exc.code}:{exc.detail}") from exc
    state_head = (state.get("event_sequence"), state.get("last_event_id"), state.get("last_event_hash"))
    log_head = (log["event_count"], log["last_event_id"], log["last_event_hash"])
    if state_head != log_head:
        raise RecoveryError("loop_state_event_log_mismatch")
    if state.get("goal_slug") != receipt["goal_slug"] or state.get("checkpoint_id") != "T006":
        raise RecoveryError("loop_identity_mismatch")
    if state.get("goal_path") != str(goal_path) or state.get("board_path") != str(board_path):
        raise RecoveryError("loop_source_path_mismatch")
    if state.get("goal_sha256") != receipt["goal_sha256"] or state.get("board_sha256") != receipt["board_sha256"]:
        raise RecoveryError("loop_goalbuddy_mismatch")
    for field in ("board_mutated", "transcript_used", "native_side_proof", "acceptance_claimed"):
        if state.get(field) is not False:
            raise RecoveryError("loop_boundary_violated", field)
    lanes = _mapping(state.get("lanes"), "loop.lanes")
    try:
        consumed_assignment_ids, reserved_artifact_paths = _loop._lane_history(lanes)
        _loop._verify_preserved_artifacts(repository_root, lanes)
    except _loop.LoopError as exc:
        raise RecoveryError("loop_preservation_invalid", f"{exc.code}:{exc.detail}") from exc
    try:
        records = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError("loop_history_invalid", str(exc)) from exc
    replayed = _loop.initial_runtime_state(receipt, str(goal_path), str(board_path))
    for index, record in enumerate(records):
        if (
            record.get("goal_slug") != receipt["goal_slug"]
            or record.get("checkpoint_id") != "T006"
            or record.get("board_sha256") != receipt["board_sha256"]
            or record.get("proof_boundary") != "local"
            or record.get("native_side_proof") is not False
            or record.get("external_call_performed") is not False
            or record.get("acceptance_claimed") is not False
        ):
            raise RecoveryError("loop_history_boundary_invalid", str(index + 1))
        if index == 0:
            if record.get("event_type") != "loop_initialized":
                raise RecoveryError("loop_initialization_invalid")
            board_payload = record.get("payload", {}).get("board_receipt", {})
            if board_payload.get("goal_slug") != receipt["goal_slug"] or board_payload.get("active_task") != "T006":
                raise RecoveryError("loop_initialization_invalid")
            _loop._advance_event_cursor(replayed, record)
            continue
        payload = copy.deepcopy(_mapping(record.get("payload"), f"loop.record[{index}].payload"))
        for derived_key in ("route_receipt", "artifact_descriptor", "board_delta"):
            payload.pop(derived_key, None)
        event = {
            "schema_version": 1,
            "event_id": record.get("event_id"),
            "timestamp": record.get("timestamp"),
            "event_type": record.get("event_type"),
            "lane_id": record.get("lane_id"),
            "payload": payload,
        }
        try:
            replayed, enriched = _loop.transition_runtime(replayed, receipt, event, repository_root)
        except _loop.LoopError as exc:
            raise RecoveryError("loop_history_replay_failed", f"{index + 1}:{exc.code}:{exc.detail}") from exc
        if enriched != record.get("payload"):
            raise RecoveryError("loop_history_replay_payload_mismatch", str(index + 1))
        _loop._advance_event_cursor(replayed, record)
    if replayed != state:
        raise RecoveryError("loop_state_replay_mismatch")
    repair_evidence: list[dict[str, Any]] = []
    open_failures: list[dict[str, Any]] = []
    current_lane: dict[str, Any] | None = None
    for lane_id, lane in lanes.items():
        current_id = lane.get("assignment_id")
        if lane_id == state.get("active_lane_id"):
            current_lane = {
                field: copy.deepcopy(lane.get(field))
                for field in (
                    "lane_id",
                    "assignment_id",
                    "task_id",
                    "role",
                    "lane_mode",
                    "route_profile",
                    "read_scope",
                    "write_scope",
                    "expected_artifact",
                    "current_work_artifact",
                    "status",
                    "work_kind",
                )
            }
        if isinstance(lane.get("failed_evidence"), list) and lane["failed_evidence"]:
            open_failures.append(
                {
                    "lane_id": lane_id,
                    "assignment_id": current_id,
                    "task_id": lane.get("task_id"),
                    "role": lane.get("role"),
                    "lane_mode": lane.get("lane_mode"),
                    "route_profile": lane.get("route_profile"),
                    "read_scope": copy.deepcopy(lane.get("read_scope")),
                    "write_scope": copy.deepcopy(lane.get("write_scope")),
                    "expected_artifact": lane.get("expected_artifact"),
                    "failure_hash": _hash(lane["failed_evidence"]),
                }
            )
        for predecessor in lane.get("preserved_predecessors", []):
            predecessor = _mapping(predecessor, f"loop.{lane_id}.predecessor")
            predecessor_id = _text(predecessor.get("assignment_id"), "predecessor.assignment_id")
            if predecessor_id == current_id or predecessor.get("terminal_for_replacement") is not True:
                raise RecoveryError("repair_assignment_not_fresh", predecessor_id)
            failed = predecessor.get("failed_evidence")
            if not isinstance(failed, list) or not failed:
                raise RecoveryError("original_failure_not_preserved", predecessor_id)
            repair_evidence.append(
                {
                    "lane_id": lane_id,
                    "predecessor_assignment_id": predecessor_id,
                    "repair_assignment_id": current_id,
                    "failure_hash": _hash(failed),
                    "predecessor_artifact_hashes": [item.get("sha256") for item in predecessor.get("artifacts", [])],
                }
            )
    return {
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "board_sha256": state["board_sha256"],
        "state_sha256": _hash(state),
        "event_count": log["event_count"],
        "last_event_id": log["last_event_id"],
        "last_event_hash": log["last_event_hash"],
        "phase": state.get("phase"),
        "repair_cycles": state.get("repair_cycles"),
        "repair_evidence": repair_evidence,
        "open_failures": open_failures,
        "current_lane": current_lane,
        "consumed_assignment_ids": sorted(consumed_assignment_ids),
        "reserved_artifact_paths": sorted(reserved_artifact_paths),
    }


def _sync_binding(
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    state = _load_json(state_path, "sync_state_unreadable")
    try:
        log = _sync.verify_event_log(events_path)
        _sync._bind_state_to_log(state, log)
        cursor = _sync.verify_cursor_log(cursor_path, log["records"], state)
    except _sync.SyncError as exc:
        raise RecoveryError("sync_history_invalid", f"{exc.code}:{exc.detail}") from exc
    if state.get("goal_id") != receipt["goal_slug"] or state.get("goal_sha256") != receipt["goal_sha256"]:
        raise RecoveryError("sync_goal_mismatch")
    if state.get("checkpoint_id") != "T005":
        raise RecoveryError("sync_predecessor_mismatch", str(state.get("checkpoint_id")))
    for field in ("board_mutated", "transcript_ingested", "native_side_proof", "acceptance_claimed", "external_action_performed"):
        if state.get(field) is not False:
            raise RecoveryError("sync_boundary_violated", field)
    unresolved = state.get("pending_authority_request") is not None or (
        state.get("paused") is True and state.get("last_authority_response") is not None
    )
    if unresolved:
        raise RecoveryError("unresolved_authority")
    return {
        "goal_slug": state["goal_id"],
        "checkpoint_id": state["checkpoint_id"],
        "predecessor_board_sha256": state["board_sha256"],
        "state_projection_sha256": _sync._state_projection_hash(state),
        "event_count": log["event_count"],
        "last_event_id": log["last_event_id"],
        "last_event_hash": log["last_event_hash"],
        "cursor_sequence": cursor["cursor_sequence"],
        "cursor_hash": cursor["cursor_hash"],
        "parent_id": state["parent_id"],
        "supervisor_id": state["supervisor_id"],
        "state_epoch": state["state_epoch"],
        "was_paused": state["paused"],
        "pause_reason": state.get("pause_reason"),
    }


def _inventory(value: Any, goal_slug: str) -> list[dict[str, Any]]:
    value = copy.deepcopy(_mapping(value, "inventory"))
    if set(value) != {"schema_version", "goal_slug", "supervisors", "transcript_used", "board_reconstructed_from_transcript", "authority_reconstructed_from_transcript"}:
        raise RecoveryError("inventory_invalid", "fields")
    if value.get("schema_version") != 1 or value.get("goal_slug") != goal_slug:
        raise RecoveryError("inventory_identity_mismatch")
    if value.get("transcript_used") is not False:
        raise RecoveryError("transcript_reconstruction_forbidden", "inventory")
    if value.get("board_reconstructed_from_transcript") is not False or value.get("authority_reconstructed_from_transcript") is not False:
        raise RecoveryError("authority_or_board_reconstruction_forbidden", "inventory")
    supervisors = value.get("supervisors")
    if not isinstance(supervisors, list) or not supervisors:
        raise RecoveryError("inventory_invalid", "supervisors")
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    required = {"supervisor_id", "goal_slug", "checkpoint_id", "epoch", "status", "disclosed", "terminal"}
    for index, item in enumerate(supervisors):
        item = copy.deepcopy(_mapping(item, f"supervisors[{index}]"))
        if set(item) != required:
            raise RecoveryError("inventory_invalid", f"supervisors[{index}].fields")
        item["supervisor_id"] = _text(item.get("supervisor_id"), f"supervisors[{index}].supervisor_id")
        item["goal_slug"] = _text(item.get("goal_slug"), f"supervisors[{index}].goal_slug")
        item["checkpoint_id"] = _text(item.get("checkpoint_id"), f"supervisors[{index}].checkpoint_id")
        if type(item.get("epoch")) is not int or item["epoch"] < 0:
            raise RecoveryError("inventory_invalid", f"supervisors[{index}].epoch")
        if item.get("status") not in {"active", "stale", "stopped"}:
            raise RecoveryError("inventory_invalid", f"supervisors[{index}].status")
        if not isinstance(item.get("disclosed"), bool) or not isinstance(item.get("terminal"), bool):
            raise RecoveryError("inventory_invalid", f"supervisors[{index}].flags")
        identity = f"{item['supervisor_id']}:{item['epoch']}"
        if identity in ids:
            raise RecoveryError("inventory_duplicate_identity", identity)
        ids.add(identity)
        result.append(item)
    return result


def _inventory_disclosures(
    supervisors: list[dict[str, Any]],
    goal_slug: str,
    checkpoint_id: str,
    supervisor_id: str,
    epoch: int,
) -> list[dict[str, Any]]:
    nonterminal = [item for item in supervisors if not item["terminal"]]
    active_for_goal = [item for item in nonterminal if item["goal_slug"] == goal_slug and item["status"] == "active"]
    duplicate = len(active_for_goal) > 1
    disclosures: list[dict[str, Any]] = []
    for item in nonterminal:
        current = (
            item["goal_slug"] == goal_slug
            and item["checkpoint_id"] == checkpoint_id
            and item["supervisor_id"] == supervisor_id
            and item["epoch"] == epoch
            and item["status"] == "active"
        )
        if not current or duplicate:
            if item["disclosed"] is not True:
                code = "duplicate_supervisor_undisclosed" if duplicate else "stale_supervisor_undisclosed"
                raise RecoveryError(code, item["supervisor_id"])
            disclosures.append(
                {
                    "supervisor_id": item["supervisor_id"],
                    "checkpoint_id": item["checkpoint_id"],
                    "epoch": item["epoch"],
                    "reason": "duplicate_active" if duplicate else "stale_task_or_epoch",
                }
            )
    return disclosures


def _clean_inventory(
    supervisors: list[dict[str, Any]], goal_slug: str, checkpoint_id: str, supervisor_id: str, epoch: int
) -> None:
    active = [item for item in supervisors if not item["terminal"] and item["status"] == "active"]
    expected = [
        item for item in active
        if item["goal_slug"] == goal_slug and item["checkpoint_id"] == checkpoint_id
        and item["supervisor_id"] == supervisor_id and item["epoch"] == epoch
    ]
    if len(active) != 1 or len(expected) != 1:
        raise RecoveryError("supervisor_inventory_not_reconciled")
    for item in supervisors:
        if item is expected[0]:
            continue
        if item["disclosed"] is not True or item["terminal"] is not True:
            raise RecoveryError("stale_supervisor_not_terminal", item["supervisor_id"])


def _projection(state: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in state.items() if key not in PROJECTION_EXCLUDED_FIELDS}


def _projection_hash(state: dict[str, Any]) -> str:
    return _hash(_projection(state))


def _cursor_record(
    previous: dict[str, Any] | None,
    state: dict[str, Any],
    event_sequence: int,
    event_id: str | None,
    event_hash: str,
    timestamp: str,
    reason: str,
) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "cursor_sequence": 1 if previous is None else previous["cursor_sequence"] + 1,
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "last_event_sequence": event_sequence,
        "last_event_id": event_id,
        "last_event_hash": event_hash,
        "reason": reason,
        "timestamp": _timestamp(timestamp),
        "previous_cursor_hash": ZERO_HASH if previous is None else previous["cursor_hash"],
    }
    record["cursor_hash"] = _hash(record)
    return record


def verify_cursor_log(path: Path, event_records: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RecoveryError("cursor_history_unreadable", str(exc)) from exc
    if not lines:
        raise RecoveryError("cursor_history_invalid", "empty")
    previous_hash = ZERO_HASH
    previous_event_sequence = -1
    last: dict[str, Any] | None = None
    for sequence, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RecoveryError("cursor_history_invalid", f"{sequence}:{exc.msg}") from exc
        candidate = copy.deepcopy(_mapping(record, f"cursor[{sequence}]"))
        recorded_hash = candidate.pop("cursor_hash", None)
        if record.get("cursor_sequence") != sequence or record.get("previous_cursor_hash") != previous_hash or recorded_hash != _hash(candidate):
            raise RecoveryError("cursor_history_chain_mismatch", str(sequence))
        target = record.get("last_event_sequence")
        if type(target) is not int or target < previous_event_sequence or target > len(event_records):
            raise RecoveryError("cursor_not_monotonic", str(target))
        expected = None if target == 0 else event_records[target - 1]
        expected_id = None if expected is None else expected["event_id"]
        expected_hash = ZERO_HASH if expected is None else expected["event_hash"]
        if record.get("last_event_id") != expected_id or record.get("last_event_hash") != expected_hash:
            raise RecoveryError("cursor_event_head_mismatch", str(target))
        if record.get("goal_slug") != state["goal_slug"] or record.get("checkpoint_id") != state["checkpoint_id"]:
            raise RecoveryError("cursor_identity_mismatch")
        _timestamp(record.get("timestamp"))
        previous_event_sequence = target
        previous_hash = recorded_hash
        last = record
    assert last is not None
    state_head = (state.get("cursor_sequence"), state.get("last_cursor_hash"), state.get("consumed_event_sequence"), state.get("consumed_event_id"), state.get("consumed_event_hash"))
    cursor_head = (last["cursor_sequence"], last["cursor_hash"], last["last_event_sequence"], last["last_event_id"], last["last_event_hash"])
    if state_head != cursor_head:
        raise RecoveryError("runtime_cursor_mismatch")
    return last


def _initial_record(state: dict[str, Any], timestamp: str) -> dict[str, Any]:
    projection_hash = _projection_hash(state)
    record = {
        "schema_version": 1,
        "sequence": 1,
        "event_id": "recovery-initialized",
        "timestamp": _timestamp(timestamp),
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "source_role": "system",
        "actor_id": "recovery-runtime",
        "event_type": "recovery_initialized",
        "payload": {
            "board_sha256": state["board_sha256"],
            "supervisor_id": state["supervisor_id"],
            "supervisor_epoch": state["supervisor_epoch"],
            "loop_state_sha256": state["loop_binding"]["state_sha256"],
            "sync_state_projection_sha256": state["sync_binding"]["state_projection_sha256"],
            "state_projection_sha256": projection_hash,
        },
        "previous_event_hash": ZERO_HASH,
        "state_before_hash": ZERO_HASH,
        "state_after_hash": projection_hash,
        "proof_boundary": "local_not_native",
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }
    record["event_hash"] = _hash(record)
    return record


def _event_record(before: dict[str, Any], after: dict[str, Any], event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "sequence": before["event_sequence"] + 1,
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "goal_slug": before["goal_slug"],
        "checkpoint_id": before["checkpoint_id"],
        "source_role": event["source_role"],
        "actor_id": event["actor_id"],
        "event_type": event["event_type"],
        "payload": payload,
        "previous_event_hash": before["last_event_hash"],
        "state_before_hash": _projection_hash(before),
        "state_after_hash": _projection_hash(after),
        "proof_boundary": "local_not_native",
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }
    record["event_hash"] = _hash(record)
    return record


def verify_event_log(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RecoveryError("recovery_history_unreadable", str(exc)) from exc
    previous = ZERO_HASH
    previous_state = ZERO_HASH
    ids: set[str] = set()
    records: list[dict[str, Any]] = []
    identity: dict[str, Any] | None = None
    for sequence, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RecoveryError("recovery_history_invalid", f"{sequence}:{exc.msg}") from exc
        candidate = copy.deepcopy(_mapping(record, f"recovery[{sequence}]"))
        recorded_hash = candidate.pop("event_hash", None)
        if record.get("sequence") != sequence or record.get("previous_event_hash") != previous:
            raise RecoveryError("recovery_history_chain_mismatch", str(sequence))
        if recorded_hash != _hash(candidate):
            raise RecoveryError("recovery_history_hash_mismatch", str(sequence))
        if record.get("event_id") in ids:
            raise RecoveryError("event_id_duplicate", str(record.get("event_id")))
        if record.get("proof_boundary") != "local_not_native" or any(record.get(field) is not False for field in ("board_mutated", "transcript_used", "native_side_proof", "acceptance_claimed")):
            raise RecoveryError("recovery_history_boundary_invalid", str(sequence))
        if record.get("state_before_hash") != previous_state:
            raise RecoveryError("recovery_state_chain_mismatch", str(sequence))
        state_after = record.get("state_after_hash")
        if not isinstance(state_after, str) or not re.fullmatch(r"[0-9a-f]{64}", state_after):
            raise RecoveryError("recovery_state_chain_mismatch", str(sequence))
        if sequence == 1:
            if record.get("event_type") != "recovery_initialized" or record.get("source_role") != "system":
                raise RecoveryError("recovery_initialization_invalid")
            identity = copy.deepcopy(_mapping(record.get("payload"), "recovery.initialization"))
            if state_after != identity.get("state_projection_sha256"):
                raise RecoveryError("recovery_initialization_invalid")
        ids.add(record["event_id"])
        previous = recorded_hash
        previous_state = state_after
        records.append(record)
    if identity is None:
        raise RecoveryError("recovery_initialization_invalid")
    return {
        "records": records,
        "event_count": len(records),
        "last_event_id": records[-1]["event_id"],
        "last_event_hash": previous,
        "last_state_projection_hash": previous_state,
        "event_ids": ids,
        "initialization_identity": identity,
    }


def _validate_state(state: dict[str, Any]) -> None:
    if state.get("schema_version") != 1 or state.get("checkpoint_id") != "T006":
        raise RecoveryError("recovery_state_invalid", "identity")
    for field in ("goal_slug", "parent_id", "supervisor_id", "last_event_id", "last_event_hash", "last_cursor_hash", "consumed_event_hash"):
        _text(state.get(field), f"state.{field}")
    for field in ("supervisor_epoch", "event_sequence", "cursor_sequence", "consumed_event_sequence"):
        if type(state.get(field)) is not int or state[field] < 0:
            raise RecoveryError("recovery_state_invalid", field)
    if state.get("status") not in {"reconciliation_required", "active", "paused", "revision_required", "stopped"}:
        raise RecoveryError("recovery_state_invalid", "status")
    if not isinstance(state.get("loop_transition_ids"), list) or len(state["loop_transition_ids"]) != len(set(state["loop_transition_ids"])):
        raise RecoveryError("recovery_state_invalid", "loop_transition_ids")
    pending = state.get("pending_loop_transition")
    if pending is not None and not isinstance(pending, dict):
        raise RecoveryError("recovery_state_invalid", "pending_loop_transition")
    revision = state.get("revision")
    if revision is not None:
        revision = _mapping(revision, "state.revision")
        authorization = revision.get("authorization")
        if authorization is not None:
            authorization = _mapping(authorization, "state.revision.authorization")
            required = set(_authorization_binding(authorization))
            if any(field not in authorization for field in required):
                raise RecoveryError("repair_authorization_state_invalid", "missing_binding")
            if authorization.get("status") not in {
                "authorized",
                "assignment_prepared",
                "assignment_committed",
                "result_prepared",
                "result_committed",
                "invalidated",
            }:
                raise RecoveryError("repair_authorization_state_invalid", "status")
            if authorization.get("authorization_epoch") != state["supervisor_epoch"]:
                raise RecoveryError("repair_authorization_expired", "epoch")
            if authorization.get("authorization_board_sha256") != state.get("board_sha256"):
                raise RecoveryError("repair_authorization_expired", "board")
    for field in ("board_mutated", "transcript_used", "native_side_proof", "acceptance_claimed", "external_action_performed"):
        if state.get(field) is not False:
            raise RecoveryError("recovery_boundary_violated", field)


def _bind_state(state: dict[str, Any], log: dict[str, Any], cursor_path: Path) -> dict[str, Any]:
    _validate_state(state)
    state_head = (state["event_sequence"], state["last_event_id"], state["last_event_hash"])
    log_head = (log["event_count"], log["last_event_id"], log["last_event_hash"])
    if state_head != log_head:
        raise RecoveryError("recovery_state_event_log_mismatch")
    if _projection_hash(state) != log["last_state_projection_hash"]:
        raise RecoveryError("recovery_state_projection_mismatch")
    identity = log["initialization_identity"]
    # The initialization record pins the substrate heads that existed when the
    # recovery runtime was created.  The current loop and sync bindings are
    # intentionally allowed to advance through verified append-only
    # transitions, so they must not be compared to those immutable initial
    # heads on every restart.
    if (
        identity.get("board_sha256") != state["board_sha256"]
        or identity.get("supervisor_id") != state["supervisor_id"]
        or identity.get("supervisor_epoch") != state["supervisor_epoch"]
        or any(
            not isinstance(identity.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity[field])
            for field in (
                "loop_state_sha256",
                "sync_state_projection_sha256",
                "state_projection_sha256",
            )
        )
    ):
        raise RecoveryError("recovery_initialization_identity_mismatch")
    return verify_cursor_log(cursor_path, log["records"], state)


def _append(path: Path, value: dict[str, Any], *, create: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x" if create else "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _atomic(path: Path, value: dict[str, Any]) -> None:
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


def _event(value: Any, state: dict[str, Any]) -> dict[str, Any]:
    event = copy.deepcopy(_mapping(value, "event"))
    required = {"schema_version", "event_id", "timestamp", "source_role", "actor_id", "event_type", "payload"}
    if set(event) != required or event.get("schema_version") != 1:
        raise RecoveryError("event_invalid", "fields")
    for field in ("event_id", "source_role", "actor_id", "event_type"):
        event[field] = _text(event.get(field), f"event.{field}")
    event["timestamp"] = _timestamp(event.get("timestamp"))
    if event["event_type"] not in EVENT_TYPES:
        raise RecoveryError("event_type_unsupported", event["event_type"])
    expected_role = "parent" if event["event_type"] in PARENT_EVENTS else "supervisor"
    expected_actor = state["parent_id"] if expected_role == "parent" else state["supervisor_id"]
    if event["source_role"] != expected_role or event["actor_id"] != expected_actor:
        raise RecoveryError("actor_identity_mismatch", event["actor_id"])
    event["payload"] = copy.deepcopy(_mapping(event.get("payload"), "event.payload"))
    _reject_forbidden(event["payload"])
    return event


def _action_id(event_type: str, payload: dict[str, Any]) -> str:
    field = {
        "goalbuddy_reconciled": "reconciliation_id",
        "pause": "control_id",
        "resume": "control_id",
        "revise": "revision_id",
        "repair_assignment_authorized": "authorization_id",
        "repair_assignment_acknowledged": "acknowledgement_id",
        "stop": "control_id",
        "restart_verified": "restart_id",
        "cursor_recovered": "recovery_id",
    }[event_type]
    return _text(payload.get(field), f"payload.{field}")


def _normalized_scope_list(value: Any, field: str) -> list[str]:
    scopes = _string_list(value, field)
    try:
        return [_loop._normalize_relative_path(scope, f"{field}[{index}]") for index, scope in enumerate(scopes)]
    except _loop.LoopError as exc:
        raise RecoveryError("repair_authorization_invalid", f"{exc.code}:{exc.detail}") from exc


def _scope_list_bounded(scopes: list[str], allowed: list[str]) -> bool:
    return all(_loop._scope_is_allowed(scope, allowed) for scope in scopes)


def _repair_authorization(
    state: dict[str, Any],
    event: dict[str, Any],
    action_id: str,
    board_receipt: dict[str, Any],
) -> dict[str, Any]:
    payload = event["payload"]
    required = {
        "authorization_id",
        "revision_id",
        "authorization_epoch",
        "predecessor_assignment_id",
        "repair_assignment_id",
        "expected_artifact",
        "result_artifact",
        "read_scope",
        "write_scope",
        "route_profile",
        "task_id",
        "lane_id",
        "role",
        "lane_mode",
    }
    if set(payload) != required:
        missing = sorted(required - set(payload))
        extra = sorted(set(payload) - required)
        raise RecoveryError("repair_authorization_fields_invalid", f"missing={missing};extra={extra}")
    revision = _mapping(state.get("revision"), "state.revision")
    if _text(payload.get("revision_id"), "payload.revision_id") != revision.get("revision_id"):
        raise RecoveryError("repair_revision_mismatch")
    if payload.get("authorization_epoch") != state["supervisor_epoch"]:
        raise RecoveryError("repair_authorization_epoch_mismatch")
    predecessor = _text(payload.get("predecessor_assignment_id"), "payload.predecessor_assignment_id")
    repair = _text(payload.get("repair_assignment_id"), "payload.repair_assignment_id")
    if predecessor == repair or repair in state["loop_binding"]["consumed_assignment_ids"]:
        raise RecoveryError("repair_assignment_not_fresh", repair)
    failures = [item for item in state["loop_binding"]["open_failures"] if item["assignment_id"] == predecessor]
    if len(failures) != 1:
        raise RecoveryError("repair_failure_not_open", predecessor)
    failure = failures[0]
    expected_artifact = _text(payload.get("expected_artifact"), "payload.expected_artifact")
    result_artifact = _text(payload.get("result_artifact"), "payload.result_artifact")
    try:
        expected_artifact = _loop._normalize_relative_path(expected_artifact, "payload.expected_artifact")
        result_artifact = _loop._normalize_relative_path(result_artifact, "payload.result_artifact")
    except _loop.LoopError as exc:
        raise RecoveryError("repair_authorization_invalid", f"{exc.code}:{exc.detail}") from exc
    if expected_artifact != result_artifact:
        raise RecoveryError("repair_result_artifact_mismatch", result_artifact)
    if expected_artifact in state["loop_binding"]["reserved_artifact_paths"]:
        raise RecoveryError("repair_artifact_not_fresh", expected_artifact)
    read_scope = _normalized_scope_list(payload.get("read_scope"), "payload.read_scope")
    write_scope = _normalized_scope_list(payload.get("write_scope"), "payload.write_scope")
    exact_scope = revision["exact_scope"]
    board_scope = board_receipt["allowed_files"]
    if not _scope_list_bounded(read_scope + write_scope, exact_scope):
        raise RecoveryError("repair_scope_outside_revision")
    if not _scope_list_bounded(read_scope + write_scope, board_scope):
        raise RecoveryError("repair_scope_outside_board")
    if not _scope_list_bounded(read_scope, failure["read_scope"]) or not _scope_list_bounded(write_scope, failure["write_scope"]):
        raise RecoveryError("repair_scope_broadened")
    if not _loop._scope_is_allowed(expected_artifact, write_scope):
        raise RecoveryError("repair_artifact_outside_write_scope", expected_artifact)
    exact_identity = {
        "task_id": _text(payload.get("task_id"), "payload.task_id"),
        "lane_id": _text(payload.get("lane_id"), "payload.lane_id"),
        "lane_mode": _text(payload.get("lane_mode"), "payload.lane_mode"),
        "route_profile": _text(payload.get("route_profile"), "payload.route_profile"),
    }
    for field, value in exact_identity.items():
        if value != failure[field]:
            raise RecoveryError("repair_authorization_identity_mismatch", field)
    role = _text(payload.get("role"), "payload.role")
    if role != "repair_worker":
        raise RecoveryError("repair_authorization_identity_mismatch", "role")
    return {
        "authorization_action_id": action_id,
        "authorization_event_id": event["event_id"],
        "authorization_epoch": state["supervisor_epoch"],
        "authorization_board_sha256": state["board_sha256"],
        "revision_id": revision["revision_id"],
        "predecessor_assignment_id": predecessor,
        "repair_assignment_id": repair,
        "expected_artifact": expected_artifact,
        "result_artifact": result_artifact,
        "read_scope": read_scope,
        "write_scope": write_scope,
        "route_profile": exact_identity["route_profile"],
        "task_id": exact_identity["task_id"],
        "lane_id": exact_identity["lane_id"],
        "role": role,
        "lane_mode": exact_identity["lane_mode"],
        "predecessor_failure_hash": failure["failure_hash"],
        "status": "authorized",
    }


def _transition(
    state: dict[str, Any], event: dict[str, Any], board_receipt: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    updated = copy.deepcopy(state)
    payload = copy.deepcopy(event["payload"])
    event_type = event["event_type"]
    action_id = _action_id(event_type, payload)
    if action_id in updated["processed_action_ids"]:
        raise RecoveryError("action_id_duplicate", action_id)
    if updated.get("pending_loop_transition") is not None:
        raise RecoveryError("loop_transition_pending", updated["pending_loop_transition"]["transition_id"])
    if updated["status"] == "reconciliation_required" and event_type not in {"goalbuddy_reconciled", "stop", "cursor_recovered"}:
        raise RecoveryError("goalbuddy_reconciliation_required")
    if updated["status"] == "stopped" and event_type not in {"cursor_recovered"}:
        raise RecoveryError("supervisor_stopped")

    if event_type == "goalbuddy_reconciled":
        supervisors = _inventory(payload.get("inventory"), updated["goal_slug"])
        _clean_inventory(supervisors, updated["goal_slug"], updated["checkpoint_id"], updated["supervisor_id"], updated["supervisor_epoch"])
        updated["status"] = "paused" if updated["sync_binding"]["was_paused"] else "active"
        updated["phase"] = "reconciled"
        updated["reconciled_inventory_sha256"] = _hash(supervisors)
    elif event_type == "pause":
        if updated["status"] != "active":
            raise RecoveryError("pause_state_invalid", updated["status"])
        updated["status"] = "paused"
        updated["phase"] = "paused"
        updated["pause_reason"] = _text(payload.get("reason"), "payload.reason")
    elif event_type == "resume":
        if updated["status"] != "paused":
            raise RecoveryError("resume_state_invalid", updated["status"])
        if updated["unresolved_authority"]:
            raise RecoveryError("unresolved_authority")
        updated["status"] = "active"
        updated["phase"] = "resumed"
        updated["pause_reason"] = None
        _text(payload.get("reason"), "payload.reason")
    elif event_type == "revise":
        if updated["status"] not in {"active", "paused"}:
            raise RecoveryError("revision_state_invalid", updated["status"])
        updated["status"] = "revision_required"
        updated["phase"] = "revision_required"
        updated["revision"] = {
            "revision_id": action_id,
            "reason": _text(payload.get("reason"), "payload.reason"),
            "exact_scope": _normalized_scope_list(payload.get("exact_scope"), "payload.exact_scope"),
            "repair_assignment_id": None,
            "authorization": None,
        }
    elif event_type == "repair_assignment_authorized":
        if updated["status"] != "revision_required" or updated.get("revision") is None:
            raise RecoveryError("repair_authorization_state_invalid", updated["status"])
        authorization = _repair_authorization(updated, event, action_id, board_receipt)
        predecessor = authorization["predecessor_assignment_id"]
        repair = authorization["repair_assignment_id"]
        updated["revision"]["predecessor_assignment_id"] = predecessor
        updated["revision"]["repair_assignment_id"] = repair
        updated["revision"]["preserved_failure_hash"] = authorization["predecessor_failure_hash"]
        updated["revision"]["authorization"] = authorization
        updated["status"] = "active"
        updated["phase"] = "repair_assignment_authorized"
    elif event_type == "repair_assignment_acknowledged":
        if updated["status"] != "active" or updated.get("revision") is None:
            raise RecoveryError("repair_acknowledgement_state_invalid", updated["status"])
        predecessor = _text(payload.get("predecessor_assignment_id"), "payload.predecessor_assignment_id")
        repair = _text(payload.get("repair_assignment_id"), "payload.repair_assignment_id")
        if predecessor == repair:
            raise RecoveryError("repair_assignment_not_fresh", repair)
        if updated["revision"].get("predecessor_assignment_id") != predecessor or updated["revision"].get("repair_assignment_id") != repair:
            raise RecoveryError("repair_assignment_not_authorized", f"{predecessor}->{repair}")
        authorization = _mapping(updated["revision"].get("authorization"), "state.revision.authorization")
        if authorization.get("status") not in {"assignment_committed", "result_prepared", "result_committed"}:
            raise RecoveryError("repair_assignment_not_committed", str(authorization.get("status")))
        matches = [
            item for item in updated["loop_binding"]["repair_evidence"]
            if item["predecessor_assignment_id"] == predecessor and item["repair_assignment_id"] == repair
        ]
        if len(matches) != 1:
            raise RecoveryError("repair_evidence_missing", f"{predecessor}->{repair}")
        updated["revision"]["preserved_failure_hash"] = matches[0]["failure_hash"]
        updated["phase"] = "repair_assignment_acknowledged"
    elif event_type == "stop":
        updated["status"] = "stopped"
        updated["phase"] = "stopped"
        updated["stop_reason"] = _text(payload.get("reason"), "payload.reason")
        if updated.get("revision") and updated["revision"].get("authorization"):
            updated["revision"]["authorization"]["status"] = "invalidated"
            updated["revision"]["authorization"]["invalidated_by"] = event["event_id"]
            updated["revision"]["authorization"]["invalidated_epoch"] = updated["supervisor_epoch"]
    elif event_type == "restart_verified":
        if updated["status"] not in {"active", "paused", "revision_required"}:
            raise RecoveryError("restart_state_invalid", updated["status"])
        updated["last_restart"] = {"restart_id": action_id, "event_head_verified": True, "cursor_head_verified": True}
    elif event_type == "cursor_recovered":
        payload["cursor_target"] = {
            "event_sequence": state["event_sequence"],
            "event_id": state["last_event_id"],
            "event_hash": state["last_event_hash"],
        }
    updated["processed_action_ids"].append(action_id)
    updated["last_event_id"] = event["event_id"]
    for field in ("board_mutated", "transcript_used", "native_side_proof", "acceptance_claimed", "external_action_performed"):
        updated[field] = False
    return updated, payload


def _verify_substrates(
    state: dict[str, Any],
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    receipt = _board_receipt(goal_path, board_path)
    loop_binding = _loop_binding(loop_state_path, loop_events_path, goal_path, board_path, receipt, repository_root)
    sync_binding = _sync_binding(sync_state_path, sync_events_path, sync_cursor_path, receipt)
    if state["board_sha256"] != receipt["board_sha256"] or state["goal_sha256"] != receipt["goal_sha256"]:
        raise RecoveryError("goalbuddy_binding_changed")
    if loop_binding != state["loop_binding"]:
        raise RecoveryError("loop_binding_changed")
    if sync_binding != state["sync_binding"]:
        raise RecoveryError("sync_binding_changed")
    return receipt


def _verified_recovery_context(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    state = _load_json(state_path, "recovery_state_unreadable")
    recovery_log = verify_event_log(events_path)
    cursor = _bind_state(state, recovery_log, cursor_path)
    receipt = _board_receipt(goal_path, board_path)
    sync_binding = _sync_binding(sync_state_path, sync_events_path, sync_cursor_path, receipt)
    if sync_binding != state["sync_binding"]:
        raise RecoveryError("sync_binding_changed")
    loop_binding = _loop_binding(
        loop_state_path,
        loop_events_path,
        goal_path,
        board_path,
        receipt,
        repository_root,
    )
    return state, recovery_log, cursor, receipt, loop_binding


def _authorization_binding(authorization: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "authorization_action_id",
        "authorization_event_id",
        "authorization_epoch",
        "authorization_board_sha256",
        "revision_id",
        "predecessor_assignment_id",
        "repair_assignment_id",
        "expected_artifact",
        "result_artifact",
        "read_scope",
        "write_scope",
        "route_profile",
        "task_id",
        "lane_id",
        "role",
        "lane_mode",
        "predecessor_failure_hash",
    )
    return {field: copy.deepcopy(authorization.get(field)) for field in fields}


def _validate_lane_authorization(lane: dict[str, Any], authorization: dict[str, Any]) -> None:
    mapping = {
        "assignment_id": "repair_assignment_id",
        "expected_artifact": "expected_artifact",
        "read_scope": "read_scope",
        "write_scope": "write_scope",
        "route_profile": "route_profile",
        "task_id": "task_id",
        "lane_id": "lane_id",
        "role": "role",
        "lane_mode": "lane_mode",
    }
    for lane_field, authorization_field in mapping.items():
        if lane.get(lane_field) != authorization.get(authorization_field):
            raise RecoveryError("repair_assignment_not_authorized", lane_field)


def _repair_authorization_use(
    state: dict[str, Any], current_loop: dict[str, Any], loop_event: dict[str, Any]
) -> dict[str, Any] | None:
    revision = state.get("revision")
    authorization = None if revision is None else revision.get("authorization")
    event_type = loop_event.get("event_type")
    if event_type == "assignment_created" and current_loop.get("phase") == "repair_required":
        if not isinstance(authorization, dict):
            raise RecoveryError("repair_assignment_not_authorized", "missing")
        if authorization.get("status") != "authorized":
            raise RecoveryError("repair_authorization_consumed", str(authorization.get("status")))
        assignment = _mapping(loop_event.get("payload"), "loop_event.payload").get("assignment")
        assignment = _mapping(assignment, "loop_event.payload.assignment")
        _validate_lane_authorization(assignment, authorization)
        current_lane = _mapping(current_loop.get("current_lane"), "loop.current_lane")
        if current_lane.get("assignment_id") != authorization["predecessor_assignment_id"]:
            raise RecoveryError("repair_predecessor_mismatch", str(current_lane.get("assignment_id")))
        failures = [
            item for item in current_loop["open_failures"]
            if item["assignment_id"] == authorization["predecessor_assignment_id"]
            and item["failure_hash"] == authorization["predecessor_failure_hash"]
        ]
        if len(failures) != 1:
            raise RecoveryError("repair_failure_not_open", authorization["predecessor_assignment_id"])
        kind = "assignment"
    else:
        lane = current_loop.get("current_lane")
        if not isinstance(lane, dict) or lane.get("work_kind") != "repair":
            return None
        if not isinstance(authorization, dict):
            raise RecoveryError("repair_assignment_not_authorized", "missing")
        _validate_lane_authorization(lane, authorization)
        if event_type != "repair_result":
            return None
        if authorization.get("status") != "assignment_committed":
            raise RecoveryError("repair_result_not_authorized", str(authorization.get("status")))
        payload = _mapping(loop_event.get("payload"), "loop_event.payload")
        if payload.get("artifact") != authorization["result_artifact"]:
            raise RecoveryError("repair_result_artifact_mismatch", str(payload.get("artifact")))
        changed_files = _string_list(payload.get("changed_files"), "loop_event.payload.changed_files")
        if not _scope_list_bounded(changed_files, authorization["write_scope"]):
            raise RecoveryError("repair_result_scope_mismatch")
        kind = "result"
    if (
        authorization.get("authorization_epoch") != state["supervisor_epoch"]
        or authorization.get("authorization_board_sha256") != state["board_sha256"]
    ):
        raise RecoveryError("repair_authorization_expired")
    return {
        "kind": kind,
        "authorization_action_id": authorization["authorization_action_id"],
        "authorization_epoch": authorization["authorization_epoch"],
        "authorization_binding_sha256": _hash(_authorization_binding(authorization)),
    }


def _validate_committed_authorization_use(
    state: dict[str, Any], current_loop: dict[str, Any], use: dict[str, Any]
) -> None:
    authorization = _mapping(state.get("revision"), "state.revision").get("authorization")
    authorization = _mapping(authorization, "state.revision.authorization")
    kind = use.get("kind")
    if authorization.get("status") != f"{kind}_prepared":
        raise RecoveryError("repair_authorization_state_mismatch", str(authorization.get("status")))
    if (
        use.get("authorization_action_id") != authorization.get("authorization_action_id")
        or use.get("authorization_epoch") != state["supervisor_epoch"]
        or use.get("authorization_binding_sha256") != _hash(_authorization_binding(authorization))
    ):
        raise RecoveryError("repair_authorization_binding_mismatch")
    lane = _mapping(current_loop.get("current_lane"), "loop.current_lane")
    _validate_lane_authorization(lane, authorization)
    if kind == "assignment":
        matches = [
            item for item in current_loop["repair_evidence"]
            if item["predecessor_assignment_id"] == authorization["predecessor_assignment_id"]
            and item["repair_assignment_id"] == authorization["repair_assignment_id"]
            and item["failure_hash"] == authorization["predecessor_failure_hash"]
        ]
        if len(matches) != 1:
            raise RecoveryError("repair_evidence_missing", authorization["repair_assignment_id"])
    elif kind == "result":
        if lane.get("current_work_artifact") != authorization["result_artifact"]:
            raise RecoveryError("repair_result_artifact_mismatch", str(lane.get("current_work_artifact")))
    else:
        raise RecoveryError("repair_authorization_use_invalid", str(kind))


def begin_loop_transition_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
    transition_id: str,
    supervisor_id: str,
    supervisor_epoch: int,
    loop_event: dict[str, Any],
    expected_loop_record: dict[str, Any],
) -> dict[str, Any]:
    transition_id = _text(transition_id, "transition_id")
    supervisor_id = _text(supervisor_id, "supervisor_id")
    if type(supervisor_epoch) is not int or supervisor_epoch < 0:
        raise RecoveryError("invalid_input", "supervisor_epoch")
    state, recovery_log, _, _, current_loop = _verified_recovery_context(
        goal_path, board_path, loop_state_path, loop_events_path,
        sync_state_path, sync_events_path, sync_cursor_path,
        state_path, events_path, cursor_path, repository_root,
    )
    if state["supervisor_id"] != supervisor_id or state["supervisor_epoch"] != supervisor_epoch:
        raise RecoveryError("stale_recovery_control")
    if state["status"] != "active" or state["unresolved_authority"] is not False:
        code = "unresolved_authority" if state["unresolved_authority"] else "recovery_control_blocked"
        raise RecoveryError(code, state["status"])
    if state["checkpoint_id"] != "T006" or current_loop["goal_slug"] != state["goal_slug"] or current_loop["checkpoint_id"] != state["checkpoint_id"]:
        raise RecoveryError("recovery_loop_identity_mismatch")
    pending = state.get("pending_loop_transition")
    event_hash = _hash(loop_event)
    expected_head = {
        "event_count": expected_loop_record.get("sequence"),
        "last_event_id": expected_loop_record.get("event_id"),
        "last_event_hash": expected_loop_record.get("event_hash"),
    }
    before_head = {
        "event_count": current_loop["event_count"],
        "last_event_id": current_loop["last_event_id"],
        "last_event_hash": current_loop["last_event_hash"],
    }
    if pending is not None:
        expected_pending = {
            "transition_id": transition_id,
            "loop_event_id": loop_event.get("event_id"),
            "loop_event_type": loop_event.get("event_type"),
            "loop_event_sha256": event_hash,
            "timestamp": _timestamp(loop_event.get("timestamp")),
            "before_head": pending.get("before_head"),
            "expected_after_head": expected_head,
        }
        comparable = {key: pending.get(key) for key in expected_pending}
        if comparable != expected_pending or before_head != pending.get("before_head"):
            raise RecoveryError("loop_transition_pending", pending.get("transition_id", "unknown"))
        return {"status": "already_prepared", "pending": copy.deepcopy(pending), "recovery_event_count": recovery_log["event_count"]}
    if current_loop != state["loop_binding"]:
        raise RecoveryError("loop_binding_changed")
    if transition_id in state["loop_transition_ids"]:
        raise RecoveryError("loop_transition_duplicate", transition_id)
    if (
        expected_head["event_count"] != before_head["event_count"] + 1
        or expected_head["last_event_id"] != loop_event.get("event_id")
        or expected_loop_record.get("previous_event_hash") != before_head["last_event_hash"]
    ):
        raise RecoveryError("loop_transition_receipt_invalid")
    authorization_use = _repair_authorization_use(state, current_loop, loop_event)
    pending = {
        "transition_id": transition_id,
        "loop_event_id": _text(loop_event.get("event_id"), "loop_event.event_id"),
        "loop_event_type": _text(loop_event.get("event_type"), "loop_event.event_type"),
        "loop_event_sha256": event_hash,
        "timestamp": _timestamp(loop_event.get("timestamp")),
        "before_head": before_head,
        "expected_after_head": expected_head,
        "authorization_use": authorization_use,
    }
    updated = copy.deepcopy(state)
    if authorization_use is not None:
        authorization = updated["revision"]["authorization"]
        authorization["status"] = f"{authorization_use['kind']}_prepared"
        authorization["prepared_transition_id"] = transition_id
        authorization["prepared_loop_event_id"] = pending["loop_event_id"]
    updated["pending_loop_transition"] = pending
    updated["loop_transition_ids"].append(transition_id)
    updated["last_event_id"] = f"{transition_id}:prepared"
    event = {
        "event_id": updated["last_event_id"],
        "timestamp": _timestamp(loop_event.get("timestamp")),
        "source_role": "system",
        "actor_id": "recovery-runtime",
        "event_type": "loop_transition_prepared",
    }
    record = _event_record(state, updated, event, pending)
    updated["event_sequence"] = record["sequence"]
    updated["last_event_hash"] = record["event_hash"]
    _append(events_path, record)
    _atomic(state_path, updated)
    return {"status": "prepared", "pending": copy.deepcopy(pending), "delta": record}


def complete_loop_transition_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
    transition_id: str,
) -> dict[str, Any]:
    transition_id = _text(transition_id, "transition_id")
    state, _, _, _, current_loop = _verified_recovery_context(
        goal_path, board_path, loop_state_path, loop_events_path,
        sync_state_path, sync_events_path, sync_cursor_path,
        state_path, events_path, cursor_path, repository_root,
    )
    pending = state.get("pending_loop_transition")
    if pending is None:
        if transition_id in state["loop_transition_ids"]:
            return {"status": "already_committed", "loop_binding": copy.deepcopy(state["loop_binding"])}
        raise RecoveryError("loop_transition_not_prepared", transition_id)
    if pending.get("transition_id") != transition_id:
        raise RecoveryError("loop_transition_pending", pending.get("transition_id", "unknown"))
    current_head = {
        "event_count": current_loop["event_count"],
        "last_event_id": current_loop["last_event_id"],
        "last_event_hash": current_loop["last_event_hash"],
    }
    if current_head != pending["expected_after_head"]:
        if current_head == pending["before_head"]:
            raise RecoveryError("loop_transition_not_written", transition_id)
        raise RecoveryError("loop_transition_reconciliation_mismatch", transition_id)
    authorization_use = pending.get("authorization_use")
    if authorization_use is not None:
        _validate_committed_authorization_use(state, current_loop, authorization_use)
    updated = copy.deepcopy(state)
    if authorization_use is not None:
        authorization = updated["revision"]["authorization"]
        authorization["status"] = f"{authorization_use['kind']}_committed"
        authorization["committed_transition_id"] = transition_id
        authorization["committed_loop_event_id"] = pending["loop_event_id"]
    updated["loop_binding"] = current_loop
    updated["pending_loop_transition"] = None
    updated["last_event_id"] = f"{transition_id}:committed"
    event = {
        "event_id": updated["last_event_id"],
        "timestamp": pending["timestamp"],
        "source_role": "system",
        "actor_id": "recovery-runtime",
        "event_type": "loop_transition_committed",
    }
    payload = {
        "transition_id": transition_id,
        "loop_event_id": pending["loop_event_id"],
        "before_head": pending["before_head"],
        "after_head": current_head,
        "loop_state_sha256": current_loop["state_sha256"],
    }
    record = _event_record(state, updated, event, payload)
    updated["event_sequence"] = record["sequence"]
    updated["last_event_hash"] = record["event_hash"]
    _append(events_path, record)
    _atomic(state_path, updated)
    return {"status": "committed", "loop_binding": copy.deepcopy(current_loop), "delta": record}


def reconcile_pending_loop_transition_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    state, _, _, _, current_loop = _verified_recovery_context(
        goal_path, board_path, loop_state_path, loop_events_path,
        sync_state_path, sync_events_path, sync_cursor_path,
        state_path, events_path, cursor_path, repository_root,
    )
    pending = state.get("pending_loop_transition")
    if pending is None:
        if current_loop != state["loop_binding"]:
            raise RecoveryError("loop_binding_changed")
        return {"status": "nothing_pending"}
    current_head = {
        "event_count": current_loop["event_count"],
        "last_event_id": current_loop["last_event_id"],
        "last_event_hash": current_loop["last_event_hash"],
    }
    if current_head == pending["before_head"]:
        return {"status": "prepared_not_written", "transition_id": pending["transition_id"]}
    if current_head == pending["expected_after_head"]:
        return complete_loop_transition_files(
            goal_path, board_path, loop_state_path, loop_events_path,
            sync_state_path, sync_events_path, sync_cursor_path,
            state_path, events_path, cursor_path, repository_root,
            pending["transition_id"],
        )
    raise RecoveryError("loop_transition_reconciliation_mismatch", pending["transition_id"])


def initialize_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    inventory_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
    timestamp: str,
) -> dict[str, Any]:
    if state_path.exists() or events_path.exists() or cursor_path.exists():
        raise RecoveryError("recovery_runtime_already_exists")
    receipt = _board_receipt(goal_path, board_path)
    loop_binding = _loop_binding(loop_state_path, loop_events_path, goal_path, board_path, receipt, repository_root)
    sync_binding = _sync_binding(sync_state_path, sync_events_path, sync_cursor_path, receipt)
    epoch = sync_binding["state_epoch"] + 1
    supervisors = _inventory(_load_json(inventory_path, "inventory_unreadable"), receipt["goal_slug"])
    disclosures = _inventory_disclosures(supervisors, receipt["goal_slug"], "T006", sync_binding["supervisor_id"], epoch)
    state = {
        "schema_version": 1,
        "goal_slug": receipt["goal_slug"],
        "checkpoint_id": "T006",
        "goal_sha256": receipt["goal_sha256"],
        "board_sha256": receipt["board_sha256"],
        "parent_id": sync_binding["parent_id"],
        "supervisor_id": sync_binding["supervisor_id"],
        "supervisor_epoch": epoch,
        "status": "reconciliation_required",
        "phase": "initialized",
        "pause_reason": None,
        "unresolved_authority": False,
        "revision": None,
        "stop_reason": None,
        "last_restart": None,
        "disclosures": disclosures,
        "processed_action_ids": [],
        "loop_transition_ids": [],
        "pending_loop_transition": None,
        "loop_binding": loop_binding,
        "sync_binding": sync_binding,
        "event_sequence": 0,
        "last_event_id": "recovery-initialized",
        "last_event_hash": ZERO_HASH,
        "cursor_sequence": 0,
        "last_cursor_hash": ZERO_HASH,
        "consumed_event_sequence": 0,
        "consumed_event_id": None,
        "consumed_event_hash": ZERO_HASH,
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
        "external_action_performed": False,
    }
    cursor = _cursor_record(None, state, 0, None, ZERO_HASH, timestamp, "initialized")
    state["cursor_sequence"] = cursor["cursor_sequence"]
    state["last_cursor_hash"] = cursor["cursor_hash"]
    record = _initial_record(state, timestamp)
    state["event_sequence"] = 1
    state["last_event_hash"] = record["event_hash"]
    _append(events_path, record, create=True)
    _append(cursor_path, cursor, create=True)
    _atomic(state_path, state)
    return {"state": state, "delta": record, "cursor": cursor}


def apply_event_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    event_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    state = _load_json(state_path, "recovery_state_unreadable")
    log = verify_event_log(events_path)
    cursor = _bind_state(state, log, cursor_path)
    board_receipt = _verify_substrates(
        state, goal_path, board_path, loop_state_path, loop_events_path,
        sync_state_path, sync_events_path, sync_cursor_path, repository_root,
    )
    event = _event(_load_json(event_path, "event_unreadable"), state)
    if event["event_id"] in log["event_ids"]:
        raise RecoveryError("event_id_duplicate", event["event_id"])
    updated, payload = _transition(state, event, board_receipt)
    next_cursor: dict[str, Any] | None = None
    if event["event_type"] == "cursor_recovered":
        next_cursor = _cursor_record(
            cursor,
            state,
            state["event_sequence"],
            state["last_event_id"],
            state["last_event_hash"],
            event["timestamp"],
            "recovered",
        )
        updated["cursor_sequence"] = next_cursor["cursor_sequence"]
        updated["last_cursor_hash"] = next_cursor["cursor_hash"]
        updated["consumed_event_sequence"] = next_cursor["last_event_sequence"]
        updated["consumed_event_id"] = next_cursor["last_event_id"]
        updated["consumed_event_hash"] = next_cursor["last_event_hash"]
    record = _event_record(state, updated, event, payload)
    updated["event_sequence"] = record["sequence"]
    updated["last_event_hash"] = record["event_hash"]
    _append(events_path, record)
    if next_cursor is not None:
        _append(cursor_path, next_cursor)
    _atomic(state_path, updated)
    return {"state": updated, "delta": record, "cursor": next_cursor or cursor}


def snapshot_files(
    goal_path: Path,
    board_path: Path,
    loop_state_path: Path,
    loop_events_path: Path,
    sync_state_path: Path,
    sync_events_path: Path,
    sync_cursor_path: Path,
    state_path: Path,
    events_path: Path,
    cursor_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    state = _load_json(state_path, "recovery_state_unreadable")
    log = verify_event_log(events_path)
    cursor = _bind_state(state, log, cursor_path)
    _verify_substrates(state, goal_path, board_path, loop_state_path, loop_events_path, sync_state_path, sync_events_path, sync_cursor_path, repository_root)
    return {
        "schema_version": 1,
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "status": state["status"],
        "phase": state["phase"],
        "supervisor_id": state["supervisor_id"],
        "supervisor_epoch": state["supervisor_epoch"],
        "disclosures": copy.deepcopy(state["disclosures"]),
        "event_count": log["event_count"],
        "event_head": {"sequence": log["event_count"], "event_id": log["last_event_id"], "event_hash": log["last_event_hash"]},
        "cursor_head": copy.deepcopy(cursor),
        "unread_event_count": log["event_count"] - cursor["last_event_sequence"],
        "loop_binding_verified": True,
        "sync_binding_verified": True,
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {name: sub.add_parser(name) for name in ("initialize", "apply", "snapshot")}
    for child in commands.values():
        child.add_argument("--goal", type=Path, required=True)
        child.add_argument("--board", type=Path, required=True)
        child.add_argument("--loop-state", type=Path, required=True)
        child.add_argument("--loop-events", type=Path, required=True)
        child.add_argument("--sync-state", type=Path, required=True)
        child.add_argument("--sync-events", type=Path, required=True)
        child.add_argument("--sync-cursor", type=Path, required=True)
        child.add_argument("--state", type=Path, required=True)
        child.add_argument("--events", type=Path, required=True)
        child.add_argument("--cursor", type=Path, required=True)
        child.add_argument("--repository-root", type=Path, default=Path.cwd())
    commands["initialize"].add_argument("--inventory", type=Path, required=True)
    commands["initialize"].add_argument("--timestamp", required=True)
    commands["apply"].add_argument("--event", type=Path, required=True)
    args = parser.parse_args(argv)
    common = (
        args.goal,
        args.board,
        args.loop_state,
        args.loop_events,
        args.sync_state,
        args.sync_events,
        args.sync_cursor,
    )
    try:
        if args.command == "initialize":
            result = initialize_files(*common, args.inventory, args.state, args.events, args.cursor, args.repository_root, args.timestamp)
        elif args.command == "apply":
            result = apply_event_files(*common, args.state, args.events, args.cursor, args.event, args.repository_root)
        else:
            result = snapshot_files(*common, args.state, args.events, args.cursor, args.repository_root)
    except (RecoveryError, OSError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, RecoveryError) else "io_or_json_error"
        detail = exc.detail if isinstance(exc, RecoveryError) else str(exc)
        print(json.dumps({"status": "failed", "code": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
