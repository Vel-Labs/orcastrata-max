#!/usr/bin/env python3
"""Fail-clear durable bridge for the bounded Codex Desktop supervision UX."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import native_host_adapter


class BridgeError(ValueError):
    """A deterministic bridge boundary error."""


CONTAINMENT_PRESENTATIONS = {"internal_supervisor_activity", "nested_hidden", "grouped"}
VISIBLE_EXCEPTION_REASONS = {
    "operator_requested", "direct_operator_interaction", "material_failure_evidence",
}
STATE_KEYS = {
    "schema_version", "goal_id", "active_checkpoint_id", "checkpoint_history",
    "checkpoint_supervisor_ids", "checkpoint_supervisor_agent_paths",
    "parent_thread_id", "supervisor_thread_id", "host_id",
    "parent_agent_path", "supervisor_agent_path", "native_host_instance",
    "native_child_identity_sha256",
    "native_locator_kind", "native_nonce_replay_scope", "native_nonce_replay",
    "native_action_receipt_replay", "native_raw_output_digest_replay",
    "native_raw_output_path_replay", "native_receipt_chain_tip",
    "read_cursor", "seen_item_ids",
    "recovery_epoch", "lifecycle", "forward_subscription",
    "topology_preflight", "internal_activities", "visible_exceptions",
}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BridgeError(f"bridge_malformed:{label}")
    return value.strip()


def _desktop_identifier(value: Any, label: str) -> str:
    value = _text(value, label)
    if native_host_adapter.IDENTIFIER.fullmatch(value) is None:
        raise BridgeError(f"bridge_malformed:{label}")
    return value


def _agent_path(value: Any, label: str) -> str:
    try:
        return native_host_adapter.validate_agent_path(value)
    except native_host_adapter.NativeIdentityError as exc:
        raise BridgeError(f"bridge_malformed:{label}") from exc


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assess_topology(capabilities: Any) -> dict[str, Any]:
    """Return a durable pass/fail receipt before any visible chat creation."""
    closest = (
        "create_no_chat_and_use_parent_direct_local_repair_until_"
        "internal_supervisor_activity_is_available"
    )
    if not isinstance(capabilities, dict):
        return {
            "status": "failed", "chat_creation_allowed": False,
            "persistent_visible_supervisor": False,
            "internal_worker_activity": False, "worker_presentation": "unknown",
            "limitation": "host_ux_limitation:topology_preflight_unavailable",
            "closest_truthful_design": closest,
        }
    presentation = capabilities.get("worker_presentation")
    if capabilities.get("persistent_visible_supervisor") is not True:
        limitation = "host_ux_limitation:persistent_supervisor_unavailable"
    elif presentation not in CONTAINMENT_PRESENTATIONS:
        limitation = "host_ux_limitation:worker_containment_unavailable"
    elif capabilities.get("internal_worker_activity") is not True:
        limitation = "host_ux_limitation:internal_worker_activity_unavailable"
    else:
        limitation = None
    if limitation is not None:
        return {
            "status": "failed", "chat_creation_allowed": False,
            "persistent_visible_supervisor": capabilities.get("persistent_visible_supervisor") is True,
            "internal_worker_activity": capabilities.get("internal_worker_activity") is True,
            "worker_presentation": presentation if isinstance(presentation, str) else "unknown",
            "limitation": limitation, "closest_truthful_design": closest,
        }
    return {
        "status": "passed", "chat_creation_allowed": True,
        "persistent_visible_supervisor": True,
        "internal_worker_activity": True,
        "worker_presentation": presentation,
        "limitation": None, "closest_truthful_design": None,
    }


def preflight_topology(capabilities: Any) -> dict[str, Any]:
    """Reject hosts that can only fan workers out as independent visible chats."""
    receipt = assess_topology(capabilities)
    if receipt["status"] != "passed":
        raise BridgeError(receipt["limitation"])
    return receipt


def empty_state(
    goal_id: str,
    checkpoint_id: str,
    parent_thread_id: str,
    host_id: str,
    topology_preflight: dict[str, Any],
) -> dict[str, Any]:
    parent_thread_id = _desktop_identifier(parent_thread_id, "parent_thread_id")
    host_id = _desktop_identifier(host_id, "host_id")
    return {
        "schema_version": 2, "goal_id": _text(goal_id, "goal_id"),
        "active_checkpoint_id": _text(checkpoint_id, "active_checkpoint_id"),
        "checkpoint_history": [_text(checkpoint_id, "checkpoint_id")],
        "checkpoint_supervisor_ids": [], "checkpoint_supervisor_agent_paths": [],
        "parent_thread_id": parent_thread_id, "supervisor_thread_id": None,
        "host_id": host_id, "parent_agent_path": None,
        "supervisor_agent_path": None, "native_host_instance": None,
        "native_child_identity_sha256": None, "native_locator_kind": "desktop_thread_id",
        "native_nonce_replay_scope": f"{goal_id}:desktop_thread_id:{parent_thread_id}", "native_nonce_replay": [],
        "native_action_receipt_replay": [], "native_raw_output_digest_replay": [],
        "native_raw_output_path_replay": [], "native_receipt_chain_tip": None,
        "read_cursor": None, "seen_item_ids": [], "recovery_epoch": 0,
        "lifecycle": "pending", "forward_subscription": "unknown",
        "topology_preflight": preflight_topology(topology_preflight),
        "internal_activities": [], "visible_exceptions": [],
    }


def empty_collaboration_state(
    goal_id: str,
    checkpoint_id: str,
    parent_agent_path: str,
    topology_preflight: dict[str, Any],
) -> dict[str, Any]:
    """Create state with collaboration locators and no caller host identity."""
    parent_agent_path = _agent_path(parent_agent_path, "parent_agent_path")
    return {
        "schema_version": 2, "goal_id": _text(goal_id, "goal_id"),
        "active_checkpoint_id": _text(checkpoint_id, "active_checkpoint_id"),
        "checkpoint_history": [_text(checkpoint_id, "checkpoint_id")],
        "checkpoint_supervisor_ids": [], "checkpoint_supervisor_agent_paths": [],
        "parent_thread_id": None, "supervisor_thread_id": None, "host_id": None,
        "parent_agent_path": parent_agent_path, "supervisor_agent_path": None,
        "native_host_instance": {
            "state": "unknown", "value": None,
            "reason": "collaboration_host_instance_not_exposed",
            "source": "host_unobserved",
        },
        "native_child_identity_sha256": None,
        "native_locator_kind": "collaboration_agent_path",
        "native_nonce_replay_scope": f"{goal_id}:collaboration_agent_path:{parent_agent_path}",
        "native_nonce_replay": [], "native_action_receipt_replay": [],
        "native_raw_output_digest_replay": [], "native_raw_output_path_replay": [],
        "native_receipt_chain_tip": None, "read_cursor": None,
        "seen_item_ids": [], "recovery_epoch": 0, "lifecycle": "pending",
        "forward_subscription": "unknown",
        "topology_preflight": preflight_topology(topology_preflight),
        "internal_activities": [], "visible_exceptions": [],
    }


def validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise BridgeError("bridge_malformed:state_fields")
    if value.get("schema_version") != 2:
        raise BridgeError("bridge_malformed:schema_version")
    for key in ("goal_id", "active_checkpoint_id", "lifecycle", "forward_subscription"):
        _text(value.get(key), key)
    if not isinstance(value["checkpoint_history"], list) or not value["checkpoint_history"]:
        raise BridgeError("bridge_malformed:checkpoint_history")
    if not all(isinstance(item, str) and item for item in value["checkpoint_history"]):
        raise BridgeError("bridge_malformed:checkpoint_history")
    if value["checkpoint_history"][-1] != value["active_checkpoint_id"]:
        raise BridgeError("bridge_malformed:active_checkpoint_history")
    if not isinstance(value["checkpoint_supervisor_ids"], list):
        raise BridgeError("bridge_malformed:checkpoint_supervisor_ids")
    if not isinstance(value["checkpoint_supervisor_agent_paths"], list):
        raise BridgeError("bridge_malformed:checkpoint_supervisor_agent_paths")
    locator_kind = value.get("native_locator_kind")
    if locator_kind == "desktop_thread_id":
        parent = _desktop_identifier(value.get("parent_thread_id"), "parent_thread_id")
        _desktop_identifier(value.get("host_id"), "host_id")
        if value.get("parent_agent_path") is not None or value.get("supervisor_agent_path") is not None:
            raise BridgeError("bridge_malformed:collaboration_locator_in_desktop_state")
        if value.get("native_host_instance") is not None or value["checkpoint_supervisor_agent_paths"]:
            raise BridgeError("bridge_malformed:collaboration_identity_in_desktop_state")
        supervisor = value.get("supervisor_thread_id")
        if supervisor is not None:
            supervisor = _desktop_identifier(supervisor, "supervisor_thread_id")
            if supervisor == parent:
                raise BridgeError("duplicate_thread_id:parent_supervisor")
            if len(value["checkpoint_supervisor_ids"]) != len(value["checkpoint_history"]):
                raise BridgeError("bridge_malformed:checkpoint_supervisor_history")
            if not all(item == supervisor for item in value["checkpoint_supervisor_ids"]):
                raise BridgeError("checkpoint_supervisor_identity_changed")
        elif value["checkpoint_supervisor_ids"]:
            raise BridgeError("bridge_malformed:checkpoint_supervisor_without_supervisor")
        expected_nonce_scope = f"{value['goal_id']}:desktop_thread_id:{parent}"
    elif locator_kind == "collaboration_agent_path":
        if value.get("parent_thread_id") is not None or value.get("supervisor_thread_id") is not None or value.get("host_id") is not None:
            raise BridgeError("bridge_malformed:desktop_identity_in_collaboration_state")
        if value["checkpoint_supervisor_ids"]:
            raise BridgeError("bridge_malformed:desktop_identity_in_collaboration_state")
        parent = _agent_path(value.get("parent_agent_path"), "parent_agent_path")
        host_instance = value.get("native_host_instance")
        if not isinstance(host_instance, dict) or set(host_instance) != {"state", "value", "reason", "source"}:
            raise BridgeError("bridge_malformed:native_host_instance")
        if host_instance.get("state") != "unknown" or host_instance.get("value") is not None or host_instance.get("source") != "host_unobserved":
            raise BridgeError("bridge_malformed:native_host_instance")
        _text(host_instance.get("reason"), "native_host_instance.reason")
        supervisor = value.get("supervisor_agent_path")
        if supervisor is not None:
            supervisor = _agent_path(supervisor, "supervisor_agent_path")
            if supervisor == parent:
                raise BridgeError("duplicate_agent_path:parent_supervisor")
            if len(value["checkpoint_supervisor_agent_paths"]) != len(value["checkpoint_history"]):
                raise BridgeError("bridge_malformed:checkpoint_supervisor_history")
            if not all(item == supervisor for item in value["checkpoint_supervisor_agent_paths"]):
                raise BridgeError("checkpoint_supervisor_identity_changed")
        elif value["checkpoint_supervisor_agent_paths"]:
            raise BridgeError("bridge_malformed:checkpoint_supervisor_without_supervisor")
        expected_nonce_scope = f"{value['goal_id']}:collaboration_agent_path:{parent}"
    else:
        raise BridgeError("bridge_malformed:native_locator_kind")
    identity_digest = value.get("native_child_identity_sha256")
    if identity_digest is not None:
        if not isinstance(identity_digest, str) or native_host_adapter.DIGEST.fullmatch(identity_digest) is None:
            raise BridgeError("bridge_malformed:native_child_identity_sha256")
    if value.get("native_nonce_replay_scope") != expected_nonce_scope:
        raise BridgeError("bridge_malformed:native_nonce_replay_scope")
    replay = value.get("native_nonce_replay")
    if not isinstance(replay, list) or len(replay) != len(set(replay)):
        raise BridgeError("bridge_malformed:native_nonce_replay")
    if not all(isinstance(item, str) and native_host_adapter.NONCE.fullmatch(item) for item in replay):
        raise BridgeError("bridge_malformed:native_nonce_replay")
    action_replay = value.get("native_action_receipt_replay")
    if not isinstance(action_replay, list) or len(action_replay) != len(set(action_replay)):
        raise BridgeError("bridge_malformed:native_action_receipt_replay")
    if not all(isinstance(item, str) and native_host_adapter.IDENTIFIER.fullmatch(item) for item in action_replay):
        raise BridgeError("bridge_malformed:native_action_receipt_replay")
    digest_replay = value.get("native_raw_output_digest_replay")
    if not isinstance(digest_replay, list) or len(digest_replay) != len(set(digest_replay)):
        raise BridgeError("bridge_malformed:native_raw_output_digest_replay")
    if not all(isinstance(item, str) and native_host_adapter.DIGEST.fullmatch(item) for item in digest_replay):
        raise BridgeError("bridge_malformed:native_raw_output_digest_replay")
    path_replay = value.get("native_raw_output_path_replay")
    if not isinstance(path_replay, list) or len(path_replay) != len(set(path_replay)):
        raise BridgeError("bridge_malformed:native_raw_output_path_replay")
    if not all(
        isinstance(item, str) and item and not item.startswith("/")
        and ".." not in Path(item).parts for item in path_replay
    ):
        raise BridgeError("bridge_malformed:native_raw_output_path_replay")
    chain_tip = value.get("native_receipt_chain_tip")
    if chain_tip is not None and (not isinstance(chain_tip, str) or native_host_adapter.DIGEST.fullmatch(chain_tip) is None):
        raise BridgeError("bridge_malformed:native_receipt_chain_tip")
    if identity_digest is None:
        if chain_tip is not None:
            raise BridgeError("bridge_malformed:native_receipt_chain_tip")
    else:
        if chain_tip != identity_digest:
            raise BridgeError("bridge_malformed:native_receipt_chain_tip")
        if locator_kind == "desktop_thread_id" and value["supervisor_thread_id"] is None:
            raise BridgeError("bridge_malformed:native_child_without_supervisor")
        if locator_kind == "collaboration_agent_path" and value["supervisor_agent_path"] is None:
            raise BridgeError("bridge_malformed:native_child_without_supervisor")
    if value["read_cursor"] is not None:
        _text(value["read_cursor"], "read_cursor")
    if not isinstance(value["seen_item_ids"], list) or len(set(value["seen_item_ids"])) != len(value["seen_item_ids"]):
        raise BridgeError("bridge_malformed:seen_item_ids")
    if not all(isinstance(item, str) and item for item in value["seen_item_ids"]):
        raise BridgeError("bridge_malformed:seen_item_id")
    if not isinstance(value["recovery_epoch"], int) or value["recovery_epoch"] < 0:
        raise BridgeError("bridge_malformed:recovery_epoch")
    if value["lifecycle"] not in {"pending", "active", "stale", "stopped"}:
        raise BridgeError("bridge_malformed:lifecycle")
    if value["forward_subscription"] not in {"unknown", "available", "unavailable"}:
        raise BridgeError("bridge_malformed:forward_subscription")
    expected_preflight_keys = {
        "status", "chat_creation_allowed", "persistent_visible_supervisor",
        "internal_worker_activity", "worker_presentation", "limitation",
        "closest_truthful_design",
    }
    if not isinstance(value["topology_preflight"], dict) or set(value["topology_preflight"]) != expected_preflight_keys:
        raise BridgeError("bridge_malformed:topology_preflight")
    if value["topology_preflight"].get("status") != "passed" or value["topology_preflight"].get("chat_creation_allowed") is not True:
        raise BridgeError("host_ux_limitation:topology_preflight_not_passed")
    if not isinstance(value["internal_activities"], list):
        raise BridgeError("bridge_malformed:internal_activities")
    for activity in value["internal_activities"]:
        if not isinstance(activity, dict) or set(activity) != {"activity_id", "role", "status"}:
            raise BridgeError("bridge_malformed:internal_activity")
        for key in ("activity_id", "role", "status"):
            _text(activity.get(key), key)
    if not isinstance(value["visible_exceptions"], list):
        raise BridgeError("bridge_malformed:visible_exceptions")
    for exception in value["visible_exceptions"]:
        required = {"exception_id", "thread_id", "reason", "justification", "lifecycle", "archive_ready"}
        if not isinstance(exception, dict) or set(exception) != required:
            raise BridgeError("bridge_malformed:visible_exception")
        if exception.get("reason") not in VISIBLE_EXCEPTION_REASONS:
            raise BridgeError("visible_exception_unjustified")
        if exception.get("lifecycle") not in {"active", "terminal"}:
            raise BridgeError("bridge_malformed:visible_exception_lifecycle")
        if not isinstance(exception.get("archive_ready"), bool):
            raise BridgeError("bridge_malformed:visible_exception_lifecycle")
        if exception["lifecycle"] == "terminal" and exception["archive_ready"] is not True:
            raise BridgeError("terminal_visible_exception_not_archive_ready")
    return value


def create_supervisor(
    state: dict[str, Any],
    native_identity: Any,
    *,
    workspace_root: str | Path | None = None,
) -> dict[str, Any]:
    """Bind state to a validated Parent-captured host identity.

    This function intentionally has no host adapter parameter and performs no
    Desktop action.  The Parent action layer must capture and receipt create,
    list, and read before this binding is accepted.
    """
    state = json.loads(canonical(validate_state(state)))
    try:
        replay = set(state["native_nonce_replay"])
        action_replay = set(state["native_action_receipt_replay"])
        raw_digest_replay = set(state["native_raw_output_digest_replay"])
        raw_path_replay = set(state["native_raw_output_path_replay"])
        identity = native_host_adapter.validate_native_child_identity(
            native_identity,
            workspace_root=workspace_root,
            verify_files=True,
            seen_nonces=replay,
            seen_action_receipt_ids=action_replay,
            seen_raw_output_digests=raw_digest_replay,
            seen_raw_output_paths=raw_path_replay,
            expected_previous_receipt_sha256=state["native_receipt_chain_tip"],
        )
    except native_host_adapter.NativeIdentityError as exc:
        raise BridgeError(exc.code) from exc
    if state["supervisor_thread_id"] is not None or state["supervisor_agent_path"] is not None:
        raise BridgeError("duplicate_supervisor")
    if identity["claim_status"] != "native_proved":
        raise BridgeError("native_identity_not_proved")
    host = identity["host_returned_identity"]
    if "parent_thread_id" in host:
        locator_kind = "desktop_thread_id"
        parent = host["parent_thread_id"]
        created = host["child_thread_id"]
        if state["native_locator_kind"] != locator_kind or parent != state["parent_thread_id"]:
            raise BridgeError("native_parent_state_mismatch")
        state["host_id"] = host["host_id"]
        state["supervisor_thread_id"] = created
        state["checkpoint_supervisor_ids"] = [created]
    else:
        locator_kind = "collaboration_agent_path"
        parent = host["parent_agent_path"]
        created = host["child_agent_path"]
        if state["native_locator_kind"] != locator_kind or parent != state["parent_agent_path"]:
            raise BridgeError("native_parent_state_mismatch")
        state["native_host_instance"] = json.loads(canonical(host["host_instance"]))
        state["supervisor_agent_path"] = created
        state["checkpoint_supervisor_agent_paths"] = [created]
    state["native_child_identity_sha256"] = identity["evidence_chain"]["receipt_sha256"]
    state["native_nonce_replay"] = sorted(replay)
    state["native_action_receipt_replay"] = sorted(action_replay)
    state["native_raw_output_digest_replay"] = sorted(raw_digest_replay)
    state["native_raw_output_path_replay"] = sorted(raw_path_replay)
    state["native_receipt_chain_tip"] = identity["evidence_chain"]["receipt_sha256"]
    state["lifecycle"] = "active"
    return state


def advance_checkpoint(state: dict[str, Any], checkpoint_id: str) -> dict[str, Any]:
    """Reuse the goal-lifetime Supervisor instead of creating a checkpoint chat."""
    state = json.loads(canonical(validate_state(state)))
    if state["native_locator_kind"] == "desktop_thread_id":
        supervisor = state["supervisor_thread_id"]
        history_key = "checkpoint_supervisor_ids"
    else:
        supervisor = state["supervisor_agent_path"]
        history_key = "checkpoint_supervisor_agent_paths"
    if state["lifecycle"] != "active" or supervisor is None:
        raise BridgeError("persistent_supervisor_not_active")
    checkpoint_id = _text(checkpoint_id, "checkpoint_id")
    if checkpoint_id != state["active_checkpoint_id"]:
        state["checkpoint_history"].append(checkpoint_id)
        state[history_key].append(supervisor)
        state["active_checkpoint_id"] = checkpoint_id
    return state


def register_internal_activity(state: dict[str, Any], activity: Any) -> dict[str, Any]:
    state = json.loads(canonical(validate_state(state)))
    if not isinstance(activity, dict) or set(activity) != {"activity_id", "role", "status"}:
        raise BridgeError("bridge_malformed:internal_activity")
    row = {key: _text(activity[key], key) for key in ("activity_id", "role", "status")}
    if any(item["activity_id"] == row["activity_id"] for item in state["internal_activities"]):
        raise BridgeError("duplicate_internal_activity")
    state["internal_activities"].append(row)
    return state


def register_visible_exception(state: dict[str, Any], exception: Any) -> dict[str, Any]:
    state = json.loads(canonical(validate_state(state)))
    required = {"exception_id", "thread_id", "reason", "justification", "lifecycle", "archive_ready"}
    if not isinstance(exception, dict) or set(exception) != required:
        raise BridgeError("bridge_malformed:visible_exception")
    row = dict(exception)
    for key in ("exception_id", "thread_id", "reason", "justification", "lifecycle"):
        row[key] = _text(row[key], key)
    if row["reason"] not in VISIBLE_EXCEPTION_REASONS:
        raise BridgeError("visible_exception_unjustified")
    if row["lifecycle"] not in {"active", "terminal"} or not isinstance(row["archive_ready"], bool):
        raise BridgeError("bridge_malformed:visible_exception_lifecycle")
    if row["lifecycle"] == "terminal" and row["archive_ready"] is not True:
        raise BridgeError("terminal_visible_exception_not_archive_ready")
    if any(item["thread_id"] == row["thread_id"] for item in state["visible_exceptions"]):
        raise BridgeError("duplicate_visible_exception")
    state["visible_exceptions"].append(row)
    return state


def evaluate_visible_chat_oracle(state: dict[str, Any], inventory: Any) -> dict[str, Any]:
    state = validate_state(state)
    if state["native_locator_kind"] != "desktop_thread_id":
        raise BridgeError("desktop_visible_chat_oracle_abi_unsupported")
    if not isinstance(inventory, list):
        raise BridgeError("bridge_malformed:visible_inventory")
    parents = [row for row in inventory if isinstance(row, dict) and row.get("role") == "parent" and row.get("active") is True]
    supervisors = [row for row in inventory if isinstance(row, dict) and row.get("role") == "supervisor" and row.get("active") is True]
    ordinary_workers = [row for row in inventory if isinstance(row, dict) and row.get("role") == "worker" and row.get("exception_id") is None]
    exception_ids = {row["exception_id"] for row in state["visible_exceptions"]}
    visible_exception_ids = {
        row.get("exception_id") for row in inventory
        if isinstance(row, dict) and row.get("role") == "worker" and row.get("exception_id") is not None
    }
    parent_locator = state["parent_thread_id"]
    supervisor_locator = state["supervisor_thread_id"]
    history = state["checkpoint_supervisor_ids"]
    checks = {
        "exactly_one_parent": len(parents) == 1 and parents[0].get("thread_id") == parent_locator,
        "exactly_one_active_supervisor": len(supervisors) == 1 and supervisors[0].get("thread_id") == supervisor_locator,
        "zero_ordinary_top_level_workers": len(ordinary_workers) == 0,
        "visible_exceptions_justified": visible_exception_ids <= exception_ids,
        "chat_count_checkpoint_invariant": (
            len(history) == len(state["checkpoint_history"])
            and set(history) == {supervisor_locator}
        ),
    }
    return {"status": "pass" if all(checks.values()) else "fail", "checks": checks}


def require_active(state: dict[str, Any], thread_id: str) -> None:
    validate_state(state)
    if state["native_locator_kind"] != "desktop_thread_id":
        raise BridgeError("host_action_abi_unsupported")
    if state["lifecycle"] != "active" or state["supervisor_thread_id"] != _text(thread_id, "thread_id"):
        raise BridgeError("stale_or_fabricated_thread_id")
    return None


def _action_evidence(value: Any, operation: str, thread_id: str, *, read: bool = False) -> dict[str, Any]:
    expected = {"operation", "thread_id", "observed", "action_receipt_id", "observed_at"}
    if read:
        expected |= {"items", "cursor"}
    else:
        if operation == "message":
            expected.add("message_sha256")
    if not isinstance(value, dict) or set(value) != expected:
        raise BridgeError("host_action_evidence_malformed")
    if value["operation"] != operation or value["thread_id"] != thread_id or value["observed"] is not True:
        raise BridgeError("host_action_evidence_mismatch")
    _text(value["action_receipt_id"], "action_receipt_id")
    _text(value["observed_at"], "observed_at")
    if operation == "message":
        if not isinstance(value["message_sha256"], str) or native_host_adapter.DIGEST.fullmatch(value["message_sha256"]) is None:
            raise BridgeError("host_action_evidence_malformed")
    if read:
        if not isinstance(value["items"], list):
            raise BridgeError("host_read_malformed")
        for item in value["items"]:
            if not isinstance(item, dict) or set(item) != {"id"} or not isinstance(item["id"], str) or not item["id"]:
                raise BridgeError("host_read_malformed")
        if value["cursor"] is not None:
            _text(value["cursor"], "cursor")
    return value


def open_thread(state: dict[str, Any], host_evidence: Any) -> None:
    require_active(state, state.get("supervisor_thread_id"))
    _action_evidence(host_evidence, "open", state["supervisor_thread_id"])


def message_thread(state: dict[str, Any], host_evidence: Any) -> None:
    require_active(state, state.get("supervisor_thread_id"))
    _action_evidence(host_evidence, "message", state["supervisor_thread_id"])


def read_newest(state: dict[str, Any], host_evidence: Any, limit: int = 20) -> tuple[dict[str, Any], dict[str, Any]]:
    state = json.loads(canonical(validate_state(state)))
    if state["forward_subscription"] == "unavailable" and state["read_cursor"] is None:
        raise BridgeError("continuity_loss_fail_clear")
    if not isinstance(limit, int) or limit < 1 or limit > 100:
        raise BridgeError("bridge_malformed:read_limit")
    require_active(state, state.get("supervisor_thread_id"))
    result = _action_evidence(host_evidence, "read", state["supervisor_thread_id"], read=True)
    seen = set(state["seen_item_ids"])
    for item in result["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise BridgeError("host_read_malformed")
        seen.add(item["id"])
    state["seen_item_ids"] = sorted(seen)
    cursor = result.get("cursor")
    if cursor is not None:
        state["read_cursor"] = _text(cursor, "cursor")
    return state, result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(canonical(validate_state(json.loads(args.state.read_text(encoding="utf-8")))))
    except (OSError, json.JSONDecodeError, BridgeError) as error:
        print(canonical({"status": "error", "error": str(error)}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
