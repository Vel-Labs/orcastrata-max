#!/usr/bin/env python3
"""Compile and validate a non-executing terminal lifecycle gate."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RESOURCE_CLASSES = {
    "native_visible_thread", "collaboration_agent", "provider_process",
    "board_server", "worktree", "persistent_session", "parent_thread",
}
OWNERSHIPS = {"goal_owned", "shared", "unrelated", "unknown"}
LIFECYCLES = {"active", "terminal", "absent", "unknown"}
ACTIONS = {
    "none", "archive", "unpin", "archive_unpin", "interrupt",
    "stop_provider", "stop_server", "remove_worktree",
    "retain_terminal_host_record", "retain_persistent",
}
CAPABILITY_KEYS = {"archive", "unpin", "interrupt", "remove"}
TRUST_ANCHOR_KEYS = {
    "schema_version", "artifact_type", "goal_id", "parent_authority",
    "inventory_authority", "allowed_persistence_authority_sha256s",
    "goal_contract_sha256", "pre_transition_board_projection_sha256",
    "pre_transition_board_source_sha256", "final_audit_sha256",
    "initial_inventory_sha256", "persistence_authorities_sha256",
    "parent_child_closeout_plan_sha256",
}
AUTHORITY_KEYS = {"authority_kind", "authority_id", "authority_sha256"}
EVIDENCE_KEYS = {"goal_id", "source_id", "source_kind", "sha256"}
EVIDENCE_SOURCE_KINDS = {"goalbuddy", "host_inventory", "parent_inventory"}
PERSISTENCE_AUTHORITY_KEYS = {
    "artifact_type", "resource_id", "authority_sha256", "operator_approved",
    "issued_at", "retain_until", "artifact_sha256",
}
PUBLIC_FAILURE_CODES = {
    "schema_invalid": "terminal_lifecycle_schema_invalid",
    "stale_board": "terminal_lifecycle_board_snapshot_stale",
    "final_audit_missing": "terminal_lifecycle_final_audit_missing",
    "final_audit_not_complete": "terminal_lifecycle_final_audit_not_complete",
    "full_outcome_missing": "terminal_lifecycle_full_outcome_missing",
    "nonterminal_tasks": "terminal_lifecycle_nonterminal_tasks",
    "inventory_incomplete": "terminal_lifecycle_inventory_incomplete",
    "ownership_ambiguous": "terminal_lifecycle_ownership_ambiguous",
    "owned_resource_active": "terminal_lifecycle_owned_resource_active",
    "owned_resource_unknown": "terminal_lifecycle_owned_resource_unknown",
    "parent_action_forbidden": "terminal_lifecycle_parent_task_action_forbidden",
    "persistence_authority_missing": "terminal_lifecycle_persistence_authority_missing",
    "unknown_mutation_forbidden": "terminal_lifecycle_unknown_resource_mutation_forbidden",
    "action_receipt_missing": "terminal_lifecycle_action_receipt_missing",
    "action_receipt_mismatch": "terminal_lifecycle_action_receipt_mismatch",
    "action_authority_invalid": "terminal_lifecycle_action_authority_invalid",
    "action_failed": "terminal_lifecycle_action_failed",
    "post_inventory_missing": "terminal_lifecycle_post_inventory_missing",
    "pid_reused": "terminal_lifecycle_process_identity_reused",
    "target_changed": "terminal_lifecycle_target_identity_changed",
    "provider_remains": "terminal_lifecycle_provider_process_remains",
    "listener_remains": "terminal_lifecycle_server_listener_remains",
    "worktree_unsafe": "terminal_lifecycle_worktree_unsafe",
    "worktree_current_forbidden": "terminal_lifecycle_worktree_current_forbidden",
    "worktree_dirty": "terminal_lifecycle_worktree_dirty",
    "worktree_unintegrated": "terminal_lifecycle_worktree_unintegrated",
    "plan_digest_mismatch": "terminal_lifecycle_plan_digest_mismatch",
    "premature_board_mutation": "terminal_lifecycle_board_mutation_premature",
    "official_checker_failed": "terminal_lifecycle_official_checker_failed",
    "stop_checker_failed": "terminal_lifecycle_stop_checker_failed",
    "terminal_state_mismatch": "terminal_lifecycle_terminal_state_mismatch",
    "parent_child_plan_missing": "terminal_lifecycle_parent_child_plan_missing",
    "parent_child_plan_mismatch": "terminal_lifecycle_parent_child_plan_mismatch",
    "parent_child_receipt_missing": "terminal_lifecycle_parent_child_receipt_missing",
    "parent_child_receipt_mismatch": "terminal_lifecycle_parent_child_receipt_mismatch",
    "parent_child_action_order": "terminal_lifecycle_parent_child_action_order_invalid",
}
TARGET_KEYS = {
    "native_visible_thread": {"thread_id", "host_id"},
    "collaboration_agent": {"agent_id", "host_id"},
    "provider_process": {"pid", "process_started_at", "executable_sha256"},
    "board_server": {"pid", "process_started_at", "listener"},
    "worktree": {"path", "worktree_sha256", "safe_to_remove", "current", "dirty", "integrated"},
    "persistent_session": {"session_id", "host_id"},
    "parent_thread": {"thread_id", "host_id"},
}


class LifecycleError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        public_code = PUBLIC_FAILURE_CODES.get(code, "terminal_lifecycle_schema_invalid")
        super().__init__(f"{public_code}: {detail}" if detail else public_code)
        self.code = public_code
        self.internal_code = code
        self.detail = detail


def canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=False,
            separators=(",", ":"), sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise LifecycleError("schema_invalid", "non-canonical value") from error


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_action_id(resource_id: str, action: str, target: dict[str, Any]) -> str:
    return "action-" + hashlib.sha256(
        canonical_json({"resource_id": resource_id, "action": action, "target": target}).encode("utf-8")
    ).hexdigest()


def _validate_trust_anchors(value: Any, expected_sha256: str) -> dict[str, Any]:
    _sha(expected_sha256, "expected_trust_anchors_sha256")
    anchors = _object(value, "trust_anchors", TRUST_ANCHOR_KEYS)
    if anchors["schema_version"] != SCHEMA_VERSION or anchors["artifact_type"] != "TerminalLifecycleTrustAnchors":
        raise LifecycleError("schema_invalid", "trust_anchors")
    _text(anchors["goal_id"], "trust_anchors.goal_id")
    for field in ("parent_authority", "inventory_authority"):
        authority = _object(anchors[field], f"trust_anchors.{field}", AUTHORITY_KEYS)
        _text(authority["authority_kind"], f"trust_anchors.{field}.authority_kind")
        _text(authority["authority_id"], f"trust_anchors.{field}.authority_id")
        _sha(authority["authority_sha256"], f"trust_anchors.{field}.authority_sha256")
    allowed = anchors["allowed_persistence_authority_sha256s"]
    if not isinstance(allowed, list) or allowed != sorted(set(allowed)):
        raise LifecycleError("schema_invalid", "trust_anchors.allowed_persistence_authority_sha256s")
    for index, value_sha in enumerate(allowed):
        _sha(value_sha, f"trust_anchors.allowed_persistence_authority_sha256s[{index}]")
    for field in (
        "goal_contract_sha256", "pre_transition_board_projection_sha256",
        "pre_transition_board_source_sha256", "final_audit_sha256",
        "initial_inventory_sha256", "persistence_authorities_sha256",
        "parent_child_closeout_plan_sha256",
    ):
        _sha(anchors[field], f"trust_anchors.{field}")
    if digest(anchors) != expected_sha256:
        raise LifecycleError("schema_invalid", "trust_anchors.digest")
    return anchors


def _validate_evidence(value: Any, field: str, goal_id: str) -> dict[str, Any]:
    evidence = _object(value, field, EVIDENCE_KEYS)
    if evidence["goal_id"] != goal_id:
        raise LifecycleError("schema_invalid", f"{field}.goal_id")
    _text(evidence["source_id"], f"{field}.source_id")
    if evidence["source_kind"] not in EVIDENCE_SOURCE_KINDS:
        raise LifecycleError("schema_invalid", f"{field}.source_kind")
    _sha(evidence["sha256"], f"{field}.sha256")
    body = {key: evidence[key] for key in evidence if key != "sha256"}
    if evidence["sha256"] != digest(body):
        raise LifecycleError("schema_invalid", f"{field}.digest")
    return evidence


READY_STAGE_MANIFEST_KEYS = {
    "schema_version", "artifact_type", "trust_anchors_sha256", "plan_sha256",
    "parent_action_receipt_sha256", "post_inventory_sha256",
    "pre_transition_board_source_sha256", "ready_receipt_sha256",
}
CONFIRM_STAGE_MANIFEST_KEYS = {
    "schema_version", "artifact_type", "trust_anchors_sha256",
    "ready_stage_manifest_sha256", "ready_receipt_sha256",
    "pre_transition_board_source_sha256", "post_transition_board_source_sha256",
    "post_transition_board_projection_sha256", "official_checker_receipt_sha256",
    "stop_checker_receipt_sha256",
}


def _validate_stage_manifest(value: Any, expected_sha256: str, artifact_type: str) -> dict[str, Any]:
    _sha(expected_sha256, "expected_stage_manifest_sha256")
    keys = READY_STAGE_MANIFEST_KEYS if artifact_type == "TerminalLifecycleReadyStageManifest" else CONFIRM_STAGE_MANIFEST_KEYS
    manifest = _object(value, "stage_manifest", keys)
    if manifest["schema_version"] != SCHEMA_VERSION or manifest["artifact_type"] != artifact_type:
        raise LifecycleError("schema_invalid", "stage_manifest")
    for key, value_sha in manifest.items():
        if key.endswith("sha256"):
            _sha(value_sha, f"stage_manifest.{key}")
    if digest(manifest) != expected_sha256:
        raise LifecycleError("schema_invalid", "stage_manifest.digest")
    return manifest


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleError("schema_invalid", f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise LifecycleError("schema_invalid", f"nonfinite_number:{value}")


def load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except LifecycleError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LifecycleError("schema_invalid", str(path)) from error


def _object(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleError("schema_invalid", field)
    return copy.deepcopy(value)


def _text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LifecycleError("schema_invalid", field)
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise LifecycleError("schema_invalid", field)
    return value


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise LifecycleError("schema_invalid", field)
    return value


def _timestamp(value: Any, field: str) -> dt.datetime:
    text = _text(value, field)
    if not text.endswith("Z"):
        raise LifecycleError("schema_invalid", field)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise LifecycleError("schema_invalid", field) from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise LifecycleError("schema_invalid", field)
    return parsed


def _path(value: Any, field: str) -> str:
    text = _text(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text or path.as_posix() in {"", "."}:
        raise LifecycleError("schema_invalid", field)
    return path.as_posix()


def _validate_board(value: Any) -> dict[str, Any]:
    board = _object(value, "board_snapshot", {"goal_id", "status", "active_task", "tasks", "source_sha256"})
    _text(board["goal_id"], "board_snapshot.goal_id")
    _sha(board["source_sha256"], "board_snapshot.source_sha256")
    if board["status"] not in {"active", "blocked", "done"}:
        raise LifecycleError("schema_invalid", "board_snapshot.status")
    if board["active_task"] is not None:
        _text(board["active_task"], "board_snapshot.active_task")
    if not isinstance(board["tasks"], list):
        raise LifecycleError("schema_invalid", "board_snapshot.tasks")
    seen: set[str] = set()
    tasks: list[dict[str, str]] = []
    for index, raw in enumerate(board["tasks"]):
        task = _object(raw, f"board_snapshot.tasks[{index}]", {"task_id", "type", "status"})
        task_id = _text(task["task_id"], f"board_snapshot.tasks[{index}].task_id")
        if task_id in seen:
            raise LifecycleError("schema_invalid", f"duplicate_task:{task_id}")
        seen.add(task_id)
        _text(task["type"], f"board_snapshot.tasks[{index}].type")
        if task["status"] not in {"queued", "active", "blocked", "done"}:
            raise LifecycleError("schema_invalid", f"board_snapshot.tasks[{index}].status")
        tasks.append(task)
    board["tasks"] = tasks
    return board


def _validate_target(resource_class: str, value: Any, field: str) -> dict[str, Any]:
    target = _object(value, field, TARGET_KEYS[resource_class])
    if resource_class in {"native_visible_thread", "parent_thread"}:
        _text(target["thread_id"], f"{field}.thread_id")
        _text(target["host_id"], f"{field}.host_id")
    elif resource_class == "collaboration_agent":
        _text(target["agent_id"], f"{field}.agent_id")
        _text(target["host_id"], f"{field}.host_id")
    elif resource_class in {"provider_process", "board_server"}:
        if not isinstance(target["pid"], int) or isinstance(target["pid"], bool) or target["pid"] <= 0:
            raise LifecycleError("schema_invalid", f"{field}.pid")
        _timestamp(target["process_started_at"], f"{field}.process_started_at")
        if resource_class == "provider_process":
            _sha(target["executable_sha256"], f"{field}.executable_sha256")
        else:
            _text(target["listener"], f"{field}.listener")
    elif resource_class == "worktree":
        _path(target["path"], f"{field}.path")
        _sha(target["worktree_sha256"], f"{field}.worktree_sha256")
        _bool(target["safe_to_remove"], f"{field}.safe_to_remove")
        _bool(target["current"], f"{field}.current")
        _bool(target["dirty"], f"{field}.dirty")
        _bool(target["integrated"], f"{field}.integrated")
    else:
        _text(target["session_id"], f"{field}.session_id")
        _text(target["host_id"], f"{field}.host_id")
    return target


def _validate_resource(value: Any, field: str, goal_id: str, *, anchors: dict[str, Any] | None = None) -> dict[str, Any]:
    resource = _object(
        value, field,
        {"resource_id", "resource_class", "ownership", "lifecycle", "target", "capabilities", "persistence_authority_sha256", "ownership_evidence"},
    )
    _text(resource["resource_id"], f"{field}.resource_id")
    if resource["resource_class"] not in RESOURCE_CLASSES:
        raise LifecycleError("schema_invalid", f"{field}.resource_class")
    if resource["ownership"] not in OWNERSHIPS:
        raise LifecycleError("ownership_ambiguous", resource["resource_id"])
    if resource["lifecycle"] not in LIFECYCLES:
        raise LifecycleError("schema_invalid", f"{field}.lifecycle")
    resource["ownership_evidence"] = _validate_evidence(resource["ownership_evidence"], f"{field}.ownership_evidence", goal_id)
    resource["target"] = _validate_target(resource["resource_class"], resource["target"], f"{field}.target")
    capabilities = _object(resource["capabilities"], f"{field}.capabilities", CAPABILITY_KEYS)
    for key in CAPABILITY_KEYS:
        _bool(capabilities[key], f"{field}.capabilities.{key}")
    resource["capabilities"] = capabilities
    if resource["persistence_authority_sha256"] is not None:
        _sha(resource["persistence_authority_sha256"], f"{field}.persistence_authority_sha256")
    return resource


def _validate_inventory(value: Any, field: str, anchors: dict[str, Any]) -> dict[str, Any]:
    if value is None:
        raise LifecycleError("post_inventory_missing" if field == "post_inventory" else "inventory_incomplete")
    inventory = _object(value, field, {"inventory_id", "observed_at", "complete", "inventory_authority", "scope_evidence", "resources", "inventory_sha256"})
    _text(inventory["inventory_id"], f"{field}.inventory_id")
    _timestamp(inventory["observed_at"], f"{field}.observed_at")
    authority = _object(inventory["inventory_authority"], f"{field}.inventory_authority", AUTHORITY_KEYS)
    if authority != anchors["inventory_authority"]:
        raise LifecycleError("schema_invalid", f"{field}.inventory_authority")
    inventory["scope_evidence"] = _validate_evidence(inventory["scope_evidence"], f"{field}.scope_evidence", anchors["goal_id"])
    if _bool(inventory["complete"], f"{field}.complete") is not True:
        raise LifecycleError("inventory_incomplete", field)
    if not isinstance(inventory["resources"], list):
        raise LifecycleError("schema_invalid", f"{field}.resources")
    seen: set[str] = set()
    resources = []
    for index, raw in enumerate(inventory["resources"]):
        resource = _validate_resource(raw, f"{field}.resources[{index}]", anchors["goal_id"], anchors=anchors)
        if resource["resource_id"] in seen:
            raise LifecycleError("inventory_incomplete", f"duplicate:{resource['resource_id']}")
        seen.add(resource["resource_id"])
        resources.append(resource)
    inventory["resources"] = resources
    supplied = _sha(inventory["inventory_sha256"], f"{field}.inventory_sha256")
    base = {key: inventory[key] for key in inventory if key != "inventory_sha256"}
    if supplied != digest(base):
        raise LifecycleError("inventory_incomplete", f"{field}:digest")
    return inventory


def _validate_authorities(value: Any, observed_at: dt.datetime, anchors: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise LifecycleError("schema_invalid", "persistence_authorities")
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(value):
        authority = _object(
            raw, f"persistence_authorities[{index}]",
            PERSISTENCE_AUTHORITY_KEYS,
        )
        if authority["artifact_type"] != "TerminalLifecyclePersistenceAuthority":
            raise LifecycleError("schema_invalid", f"persistence_authorities[{index}].artifact_type")
        resource_id = _text(authority["resource_id"], f"persistence_authorities[{index}].resource_id")
        if resource_id in result:
            raise LifecycleError("schema_invalid", f"duplicate_authority:{resource_id}")
        _sha(authority["authority_sha256"], f"persistence_authorities[{index}].authority_sha256")
        _sha(authority["artifact_sha256"], f"persistence_authorities[{index}].artifact_sha256")
        body = {key: authority[key] for key in authority if key != "artifact_sha256"}
        if authority["artifact_sha256"] != digest(body):
            raise LifecycleError("persistence_authority_missing", resource_id)
        if authority["artifact_sha256"] not in anchors["allowed_persistence_authority_sha256s"]:
            raise LifecycleError("persistence_authority_missing", resource_id)
        if _bool(authority["operator_approved"], f"persistence_authorities[{index}].operator_approved") is not True:
            raise LifecycleError("persistence_authority_missing", resource_id)
        issued = _timestamp(authority["issued_at"], f"persistence_authorities[{index}].issued_at")
        if issued > observed_at:
            raise LifecycleError("persistence_authority_missing", resource_id)
        if authority["retain_until"] is not None:
            if _timestamp(authority["retain_until"], f"persistence_authorities[{index}].retain_until") <= observed_at:
                raise LifecycleError("persistence_authority_missing", resource_id)
        result[resource_id] = authority
    return result


def _visible_action(capabilities: dict[str, bool]) -> str | None:
    if capabilities["archive"] and capabilities["unpin"]:
        return "archive_unpin"
    if capabilities["archive"]:
        return "archive"
    if capabilities["unpin"]:
        return "unpin"
    return None


def _compile_action(resource: dict[str, Any], authorities: dict[str, dict[str, Any]]) -> tuple[str, str]:
    resource_id = resource["resource_id"]
    resource_class = resource["resource_class"]
    ownership = resource["ownership"]
    lifecycle = resource["lifecycle"]
    capabilities = resource["capabilities"]
    if resource_class == "parent_thread":
        if ownership == "goal_owned" or any(capabilities.values()):
            raise LifecycleError("parent_action_forbidden", resource_id)
        return "none", "parent_thread_preserved"
    if ownership != "goal_owned":
        return "none", f"{ownership}_resource_preserved"
    if lifecycle == "unknown":
        raise LifecycleError("owned_resource_unknown", resource_id)
    if resource_class == "persistent_session" and lifecycle == "active":
        authority = authorities.get(resource_id)
        if (
            authority is None
            or resource["persistence_authority_sha256"] != authority["artifact_sha256"]
        ):
            raise LifecycleError("persistence_authority_missing", resource_id)
        return "retain_persistent", "prior_operator_persistence_authority"
    if lifecycle in {"terminal", "absent"}:
        if (
            resource_class == "collaboration_agent" and lifecycle == "terminal"
            and not capabilities["archive"] and not capabilities["remove"]
        ):
            return "retain_terminal_host_record", "terminal_agent_host_record_only"
        action = _visible_action(capabilities) if resource_class == "native_visible_thread" else None
        return (action, "terminal_visible_task_cleanup") if action else ("none", "already_terminal_or_absent")
    if resource_class == "native_visible_thread":
        action = _visible_action(capabilities)
        if action is None:
            raise LifecycleError("owned_resource_active", resource_id)
        return action, "dispose_goal_owned_visible_task"
    if resource_class == "collaboration_agent":
        if not capabilities["interrupt"]:
            raise LifecycleError("owned_resource_active", resource_id)
        return "interrupt", "stop_goal_owned_collaboration_agent"
    if resource_class == "provider_process":
        return "stop_provider", "stop_goal_owned_provider_process"
    if resource_class == "board_server":
        return "stop_server", "stop_goal_owned_board_server"
    if resource_class == "worktree":
        target = resource["target"]
        if target["current"] is True:
            raise LifecycleError("worktree_current_forbidden", resource_id)
        if target["dirty"] is True:
            raise LifecycleError("worktree_dirty", resource_id)
        if target["integrated"] is not True:
            raise LifecycleError("worktree_unintegrated", resource_id)
        if not capabilities["remove"] or target["safe_to_remove"] is not True:
            raise LifecycleError("worktree_unsafe", resource_id)
        return "remove_worktree", "remove_goal_owned_safe_worktree"
    raise LifecycleError("owned_resource_active", resource_id)


def _validate_parent_child_plan(value: Any, goal_id: str, terminal_task_id: str) -> dict[str, Any]:
    if value is None:
        raise LifecycleError("parent_child_plan_missing")
    plan = _object(value, "parent_child_closeout_plan", {
        "schema_version", "artifact_type", "goal_id", "terminal_task_id", "parent",
        "descendants", "actions", "retained_persistent_children",
        "board_mutation_allowed", "plan_sha256",
    })
    if (
        plan["schema_version"] != SCHEMA_VERSION
        or plan["artifact_type"] != "ParentChildCloseoutPlan"
        or plan["goal_id"] != goal_id
        or plan["terminal_task_id"] != terminal_task_id
        or plan["board_mutation_allowed"] is not False
    ):
        raise LifecycleError("parent_child_plan_mismatch", "identity")
    parent = _object(plan["parent"], "parent_child_closeout_plan.parent", {"thread_id", "host_id", "agent_path"})
    for key in parent:
        _text(parent[key], f"parent_child_closeout_plan.parent.{key}")
    if plan["retained_persistent_children"] != []:
        raise LifecycleError("parent_child_plan_mismatch", "nested_persistence")
    if not isinstance(plan["descendants"], list) or not isinstance(plan["actions"], list):
        raise LifecycleError("parent_child_plan_mismatch", "collections")
    descendants: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for index, raw in enumerate(plan["descendants"]):
        row = _object(raw, f"parent_child_closeout_plan.descendants[{index}]", {
            "thread_id", "agent_path", "last_event_kind", "live_status",
            "persistence_authority_sha256",
        })
        thread_id = _text(row["thread_id"], f"parent_child_closeout_plan.descendants[{index}].thread_id")
        agent_path = _text(row["agent_path"], f"parent_child_closeout_plan.descendants[{index}].agent_path")
        if not agent_path.startswith(parent["agent_path"].rstrip("/") + "/"):
            raise LifecycleError("parent_child_plan_mismatch", "ownership")
        if row["last_event_kind"] not in {"started", "interacted", "completed", "interrupted", "failed"}:
            raise LifecycleError("parent_child_plan_mismatch", "last_event_kind")
        if row["live_status"] not in {"running", "pending_init", "waiting", "blocked", "idle", "completed", "interrupted", "failed", "cancelled", "not_loaded"}:
            raise LifecycleError("parent_child_plan_mismatch", "live_status")
        if row["persistence_authority_sha256"] is not None or thread_id in descendants or agent_path in paths:
            raise LifecycleError("parent_child_plan_mismatch", "descendants")
        descendants[thread_id] = row
        paths.add(agent_path)
    seen_actions: set[str] = set()
    action_pairs: set[tuple[str, str]] = set()
    for index, raw in enumerate(plan["actions"]):
        row = _object(raw, f"parent_child_closeout_plan.actions[{index}]", {
            "action_id", "sequence", "action", "thread_id", "host_id", "agent_path",
        })
        action_id = _text(row["action_id"], f"parent_child_closeout_plan.actions[{index}].action_id")
        thread_id = _text(row["thread_id"], f"parent_child_closeout_plan.actions[{index}].thread_id")
        if action_id in seen_actions or thread_id not in descendants:
            raise LifecycleError("parent_child_plan_mismatch", "actions")
        child = descendants[thread_id]
        if row["agent_path"] != child["agent_path"] or row["host_id"] != parent["host_id"]:
            raise LifecycleError("parent_child_plan_mismatch", "action_target")
        expected_sequence = 1 if row["action"] == "interrupt_agent" else 2 if row["action"] == "archive_thread" else None
        if row["sequence"] != expected_sequence:
            raise LifecycleError("parent_child_plan_mismatch", "action_sequence")
        expected_action_id = "action-" + hashlib.sha256(canonical_json({
            "action": row["action"], "thread_id": thread_id, "agent_path": row["agent_path"],
        }).encode("utf-8")).hexdigest()
        if action_id != expected_action_id:
            raise LifecycleError("parent_child_plan_mismatch", "action_id")
        seen_actions.add(action_id)
        action_pairs.add((thread_id, row["action"]))
    for thread_id in descendants:
        if (thread_id, "archive_thread") not in action_pairs:
            raise LifecycleError("parent_child_plan_mismatch", "archive_missing")
        active = descendants[thread_id]["live_status"] in {"running", "pending_init", "waiting", "blocked", "idle"}
        if ((thread_id, "interrupt_agent") in action_pairs) is not active:
            raise LifecycleError("parent_child_plan_mismatch", "interrupt_policy")
    supplied = _sha(plan["plan_sha256"], "parent_child_closeout_plan.plan_sha256")
    if supplied != digest({key: plan[key] for key in plan if key != "plan_sha256"}):
        raise LifecycleError("parent_child_plan_mismatch", "digest")
    return plan


def _protected_parent(
    child_plan: dict[str, Any], resources: list[dict[str, Any]], anchors: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    parent = child_plan["parent"]
    if anchors["parent_authority"]["authority_id"] != parent["thread_id"]:
        raise LifecycleError("parent_child_plan_mismatch", "parent_authority")
    threads = [
        row for row in resources
        if row["resource_class"] == "parent_thread"
        and row["target"] == {"thread_id": parent["thread_id"], "host_id": parent["host_id"]}
        and row["ownership"] == "shared" and row["lifecycle"] == "active"
    ]
    agents = [
        row for row in resources
        if row["resource_class"] == "collaboration_agent"
        and row["target"] == {"agent_id": parent["agent_path"], "host_id": parent["host_id"]}
        and row["ownership"] == "shared" and row["lifecycle"] == "active"
    ]
    if len(threads) != 1 or len(agents) != 1:
        raise LifecycleError("parent_child_plan_mismatch", "protected_parent")
    return {"thread": threads[0], "agent": agents[0]}


def _child_resource_maps(
    child_plan: dict[str, Any], resources: list[dict[str, Any]],
    anchors: dict[str, Any], actions: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    protected = _protected_parent(child_plan, resources, anchors)
    parent_host = child_plan["parent"]["host_id"]
    by_thread: dict[tuple[str, str], dict[str, Any]] = {}
    by_agent: dict[tuple[str, str], dict[str, Any]] = {}
    for resource in resources:
        if resource["resource_class"] == "native_visible_thread":
            key = (resource["target"]["thread_id"], resource["target"]["host_id"])
            if key in by_thread:
                raise LifecycleError("parent_child_plan_mismatch", "duplicate_visible_target")
            by_thread[key] = resource
        elif resource["resource_class"] == "collaboration_agent":
            key = (resource["target"]["agent_id"], resource["target"]["host_id"])
            if key in by_agent:
                raise LifecycleError("parent_child_plan_mismatch", "duplicate_agent_target")
            by_agent[key] = resource
    descendant_threads = {row["thread_id"] for row in child_plan["descendants"]}
    descendant_paths = {row["agent_path"] for row in child_plan["descendants"]}
    if protected["thread"]["target"]["thread_id"] in descendant_threads or protected["agent"]["target"]["agent_id"] in descendant_paths:
        raise LifecycleError("parent_action_forbidden", "parent_child_target")
    visible_children = [
        row for row in resources
        if row["resource_class"] == "native_visible_thread"
        and row["ownership"] == "goal_owned" and row["target"]["host_id"] == parent_host
    ]
    agent_children = [
        row for row in resources
        if row["resource_class"] == "collaboration_agent"
        and row["ownership"] == "goal_owned" and row["target"]["host_id"] == parent_host
        and row["target"]["agent_id"].startswith(child_plan["parent"]["agent_path"].rstrip("/") + "/")
    ]
    authoritative_threads = {row["target"]["thread_id"] for row in visible_children}
    authoritative_paths = {row["target"]["agent_id"] for row in agent_children}
    if (
        len(authoritative_threads) != len(visible_children)
        or len(authoritative_paths) != len(agent_children)
        or descendant_threads != authoritative_threads
        or descendant_paths != authoritative_paths
        or len(descendant_threads) != len(descendant_paths)
    ):
        raise LifecycleError("parent_child_plan_mismatch", "bijective_child_coverage")
    action_by_resource = {row["resource_id"]: row for row in actions or []}
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for child in child_plan["descendants"]:
        thread = by_thread.get((child["thread_id"], parent_host))
        agent = by_agent.get((child["agent_path"], parent_host))
        if thread is None or agent is None or thread["ownership"] != "goal_owned" or agent["ownership"] != "goal_owned":
            raise LifecycleError("parent_child_plan_mismatch", f"inventory:{child['thread_id']}")
        result[child["thread_id"]] = {"thread": thread, "agent": agent}
        if actions is not None:
            terminal_archive = action_by_resource[thread["resource_id"]]["action"]
            if terminal_archive not in {"archive", "archive_unpin"}:
                raise LifecycleError("parent_child_plan_mismatch", f"archive:{child['thread_id']}")
            child_actions = {row["action"] for row in child_plan["actions"] if row["thread_id"] == child["thread_id"]}
            if "interrupt_agent" in child_actions and action_by_resource[agent["resource_id"]]["action"] != "interrupt":
                raise LifecycleError("parent_child_plan_mismatch", f"interrupt:{child['thread_id']}")
    return result


def _validate_parent_child_receipt(
    value: Any, child_plan: dict[str, Any], terminal_plan: dict[str, Any],
    parent_action_receipt: dict[str, Any], post_inventory: dict[str, Any],
) -> dict[str, Any]:
    if value is None:
        raise LifecycleError("parent_child_receipt_missing")
    receipt = _object(value, "parent_child_closeout_receipt", {
        "schema_version", "artifact_type", "goal_id", "terminal_task_id",
        "parent_thread_id", "plan_sha256", "action_results", "post_live_agents",
        "closeout_complete", "terminal_lifecycle_allowed", "board_mutation_allowed",
        "receipt_sha256",
    })
    if (
        receipt["schema_version"] != SCHEMA_VERSION
        or receipt["artifact_type"] != "ParentChildCloseoutReceipt"
        or receipt["goal_id"] != terminal_plan["goal_id"]
        or receipt["terminal_task_id"] != terminal_plan["terminal_task_id"]
        or receipt["parent_thread_id"] != child_plan["parent"]["thread_id"]
        or receipt["plan_sha256"] != child_plan["plan_sha256"]
        or receipt["closeout_complete"] is not True
        or receipt["terminal_lifecycle_allowed"] is not True
        or receipt["board_mutation_allowed"] is not False
    ):
        raise LifecycleError("parent_child_receipt_mismatch", "identity")
    if not isinstance(receipt["action_results"], list) or not isinstance(receipt["post_live_agents"], list):
        raise LifecycleError("parent_child_receipt_mismatch", "collections")
    result_ids: set[str] = set()
    for index, raw in enumerate(receipt["action_results"]):
        row = _object(raw, f"parent_child_closeout_receipt.action_results[{index}]", {"action_id", "status", "evidence_sha256"})
        action_id = _text(row["action_id"], f"parent_child_closeout_receipt.action_results[{index}].action_id")
        if action_id in result_ids or row["status"] != "success":
            raise LifecycleError("parent_child_receipt_mismatch", "action_results")
        _sha(row["evidence_sha256"], f"parent_child_closeout_receipt.action_results[{index}].evidence_sha256")
        result_ids.add(action_id)
    if result_ids != {row["action_id"] for row in child_plan["actions"]}:
        raise LifecycleError("parent_child_receipt_mismatch", "action_set")
    for index, raw in enumerate(receipt["post_live_agents"]):
        row = _object(raw, f"parent_child_closeout_receipt.post_live_agents[{index}]", {"agent_path", "status"})
        _text(row["agent_path"], f"parent_child_closeout_receipt.post_live_agents[{index}].agent_path")
        _text(row["status"], f"parent_child_closeout_receipt.post_live_agents[{index}].status")
    if _sha(receipt["receipt_sha256"], "parent_child_closeout_receipt.receipt_sha256") != digest({key: receipt[key] for key in receipt if key != "receipt_sha256"}):
        raise LifecycleError("parent_child_receipt_mismatch", "digest")

    maps = _child_resource_maps(
        child_plan, terminal_plan["resources"],
        {"parent_authority": parent_action_receipt["parent_authority"]}, terminal_plan["actions"],
    )
    terminal_actions = {row["resource_id"]: row for row in terminal_plan["actions"]}
    host_results = {row["action_id"]: row for row in parent_action_receipt["actions"]}
    post_resources = {row["resource_id"]: row for row in post_inventory["resources"]}
    for child in child_plan["descendants"]:
        child_id = child["thread_id"]
        pair = maps[child_id]
        archive_action = terminal_actions[pair["thread"]["resource_id"]]
        archive_result = host_results.get(archive_action["action_id"])
        if archive_result is None or archive_result["status"] != "completed":
            raise LifecycleError("parent_child_receipt_mismatch", f"archive_receipt:{child_id}")
        interrupt_result = None
        if any(row["thread_id"] == child_id and row["action"] == "interrupt_agent" for row in child_plan["actions"]):
            interrupt_action = terminal_actions[pair["agent"]["resource_id"]]
            interrupt_result = host_results.get(interrupt_action["action_id"])
            if interrupt_result is None or interrupt_result["status"] != "completed":
                raise LifecycleError("parent_child_receipt_mismatch", f"interrupt_receipt:{child_id}")
            if _timestamp(archive_result["completed_at"], "archive.completed_at") < _timestamp(interrupt_result["completed_at"], "interrupt.completed_at"):
                raise LifecycleError("parent_child_action_order", child_id)
        for resource in pair.values():
            post = post_resources.get(resource["resource_id"])
            if post is None or post["lifecycle"] not in {"terminal", "absent"}:
                raise LifecycleError("parent_child_receipt_mismatch", f"post_inventory:{child_id}")
    return receipt


def _validate_plan(value: Any) -> dict[str, Any]:
    plan = _object(
        value, "plan",
        {"schema_version", "artifact_type", "goal_id", "terminal_task_id", "board_path", "accepted_final_audit_path", "trust_anchors_sha256", "bindings", "inventory_sha256", "parent_child_closeout_plan_sha256", "created_at", "resources", "actions", "retained_resources", "host_actions_executed", "board_mutated", "acceptance_claimed", "plan_sha256"},
    )
    if plan["schema_version"] != SCHEMA_VERSION or plan["artifact_type"] != "TerminalLifecyclePlan":
        raise LifecycleError("schema_invalid", "plan")
    _text(plan["goal_id"], "plan.goal_id")
    _text(plan["terminal_task_id"], "plan.terminal_task_id")
    _path(plan["board_path"], "plan.board_path")
    _path(plan["accepted_final_audit_path"], "plan.accepted_final_audit_path")
    _sha(plan["trust_anchors_sha256"], "plan.trust_anchors_sha256")
    bindings = _object(
        plan["bindings"], "plan.bindings",
        {"goal_contract_sha256", "pre_transition_board_projection_sha256", "pre_transition_board_source_sha256", "final_audit_sha256", "initial_inventory_sha256", "persistence_authorities_sha256"},
    )
    for key, value in bindings.items():
        _sha(value, f"plan.bindings.{key}")
    _sha(plan["inventory_sha256"], "plan.inventory_sha256")
    _sha(plan["parent_child_closeout_plan_sha256"], "plan.parent_child_closeout_plan_sha256")
    _timestamp(plan["created_at"], "plan.created_at")
    for field in ("resources", "actions", "retained_resources"):
        if not isinstance(plan[field], list):
            raise LifecycleError("schema_invalid", f"plan.{field}")
    resources: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(plan["resources"]):
        row = _object(
            raw, f"plan.resources[{index}]",
            {"resource_id", "resource_class", "ownership", "lifecycle", "target", "capabilities", "persistence_authority_sha256", "persistence_retain_until", "ownership_evidence"},
        )
        resource_id = _text(row["resource_id"], f"plan.resources[{index}].resource_id")
        if resource_id in resources or row["resource_class"] not in RESOURCE_CLASSES or row["ownership"] not in OWNERSHIPS or row["lifecycle"] not in LIFECYCLES:
            raise LifecycleError("schema_invalid", f"plan.resources[{index}]")
        if row["persistence_authority_sha256"] is not None:
            _sha(row["persistence_authority_sha256"], f"plan.resources[{index}].persistence_authority_sha256")
        if row["persistence_retain_until"] is not None:
            _timestamp(row["persistence_retain_until"], f"plan.resources[{index}].persistence_retain_until")
        row["target"] = _validate_target(row["resource_class"], row["target"], f"plan.resources[{index}].target")
        capabilities = _object(row["capabilities"], f"plan.resources[{index}].capabilities", CAPABILITY_KEYS)
        for key in CAPABILITY_KEYS:
            _bool(capabilities[key], f"plan.resources[{index}].capabilities.{key}")
        row["ownership_evidence"] = _validate_evidence(row["ownership_evidence"], f"plan.resources[{index}].ownership_evidence", plan["goal_id"])
        resources[resource_id] = row
    actions: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(plan["actions"]):
        row = _object(raw, f"plan.actions[{index}]", {"action_id", "resource_id", "resource_class", "action", "exact_target_identity", "reason"})
        _text(row["action_id"], f"plan.actions[{index}].action_id")
        resource_id = _text(row["resource_id"], f"plan.actions[{index}].resource_id")
        if resource_id in actions or resource_id not in resources or row["resource_class"] != resources[resource_id]["resource_class"] or row["action"] not in ACTIONS:
            raise LifecycleError("schema_invalid", f"plan.actions[{index}]")
        row["exact_target_identity"] = _validate_target(row["resource_class"], row["exact_target_identity"], f"plan.actions[{index}].exact_target_identity")
        if row["action_id"] != stable_action_id(resource_id, row["action"], row["exact_target_identity"]):
            raise LifecycleError("action_receipt_mismatch", resource_id)
        _text(row["reason"], f"plan.actions[{index}].reason")
        if resources[resource_id]["ownership"] != "goal_owned" and row["action"] != "none":
            raise LifecycleError("unknown_mutation_forbidden", resource_id)
        if row["resource_class"] == "parent_thread" and row["action"] != "none":
            raise LifecycleError("parent_action_forbidden", resource_id)
        actions[resource_id] = row
    if set(resources) != set(actions):
        raise LifecycleError("schema_invalid", "plan.resource_action_set")
    retained_ids: set[str] = set()
    for index, raw in enumerate(plan["retained_resources"]):
        row = _object(raw, f"plan.retained_resources[{index}]", {"resource_id", "reason"})
        resource_id = _text(row["resource_id"], f"plan.retained_resources[{index}].resource_id")
        if resource_id in retained_ids or resource_id not in actions or actions[resource_id]["action"] not in {"retain_terminal_host_record", "retain_persistent"}:
            raise LifecycleError("schema_invalid", f"plan.retained_resources[{index}]")
        _text(row["reason"], f"plan.retained_resources[{index}].reason")
        retained_ids.add(resource_id)
    for field in ("host_actions_executed", "board_mutated", "acceptance_claimed"):
        if _bool(plan[field], f"plan.{field}") is not False:
            raise LifecycleError("schema_invalid", f"plan.{field}")
    supplied = _sha(plan["plan_sha256"], "plan.plan_sha256")
    base = {key: plan[key] for key in plan if key != "plan_sha256"}
    if supplied != digest(base):
        raise LifecycleError("plan_digest_mismatch")
    return plan


def plan(value: Any, trust_anchors: Any, expected_trust_anchors_sha256: str) -> dict[str, Any]:
    anchors = _validate_trust_anchors(trust_anchors, expected_trust_anchors_sha256)
    request = _object(
        value, "plan_request",
        {"schema_version", "operation", "terminal_task_id", "bindings", "goal_contract", "board_snapshot", "final_audit", "inventory", "persistence_authorities", "parent_child_closeout_plan"},
    )
    if request["schema_version"] != SCHEMA_VERSION or request["operation"] != "plan":
        raise LifecycleError("schema_invalid", "plan_request")
    terminal_task_id = _text(request["terminal_task_id"], "terminal_task_id")
    bindings = _object(
        request["bindings"], "bindings",
        {"goal_contract_sha256", "pre_transition_board_projection_sha256", "pre_transition_board_source_sha256", "final_audit_sha256", "initial_inventory_sha256", "persistence_authorities_sha256"},
    )
    for field, value_sha in bindings.items():
        _sha(value_sha, f"bindings.{field}")
    goal = _object(request["goal_contract"], "goal_contract", {"goal_id", "board_path", "final_audit_path", "continuous_until_full_outcome"})
    goal_id = _text(goal["goal_id"], "goal_contract.goal_id")
    if goal_id != anchors["goal_id"]:
        raise LifecycleError("schema_invalid", "goal_contract.goal_id")
    _path(goal["board_path"], "goal_contract.board_path")
    _path(goal["final_audit_path"], "goal_contract.final_audit_path")
    _bool(goal["continuous_until_full_outcome"], "goal_contract.continuous_until_full_outcome")
    if digest(goal) != bindings["goal_contract_sha256"] or digest(goal) != anchors["goal_contract_sha256"]:
        raise LifecycleError("schema_invalid", "goal_binding_mismatch")
    board = _validate_board(request["board_snapshot"])
    if digest(board) != bindings["pre_transition_board_projection_sha256"] or digest(board) != anchors["pre_transition_board_projection_sha256"]:
        raise LifecycleError("stale_board")
    if board["source_sha256"] != bindings["pre_transition_board_source_sha256"] or board["source_sha256"] != anchors["pre_transition_board_source_sha256"]:
        raise LifecycleError("stale_board", "source_sha256")
    if board["goal_id"] != goal_id:
        raise LifecycleError("stale_board", "goal_id")
    if board["status"] != "active":
        raise LifecycleError("premature_board_mutation")
    tasks = {task["task_id"]: task for task in board["tasks"]}
    if terminal_task_id not in tasks or board["active_task"] != terminal_task_id or tasks[terminal_task_id]["status"] != "active":
        raise LifecycleError("terminal_state_mismatch", terminal_task_id)
    unfinished = sorted(
        task_id
        for task_id, task in tasks.items()
        if task_id != terminal_task_id and task["status"] in {"queued", "active"}
    )
    if unfinished:
        raise LifecycleError("nonterminal_tasks", ",".join(unfinished))
    if request["final_audit"] is None:
        raise LifecycleError("final_audit_missing")
    audit = _object(request["final_audit"], "final_audit", {"goal_id", "board_sha256", "decision", "full_outcome_complete"})
    if digest(audit) != bindings["final_audit_sha256"] or digest(audit) != anchors["final_audit_sha256"]:
        raise LifecycleError("final_audit_missing", "digest")
    if audit["goal_id"] != goal_id or audit["board_sha256"] != bindings["pre_transition_board_projection_sha256"]:
        raise LifecycleError("final_audit_missing", "binding")
    if audit["decision"] != "complete":
        raise LifecycleError("final_audit_not_complete")
    _bool(audit["full_outcome_complete"], "final_audit.full_outcome_complete")
    if goal["continuous_until_full_outcome"] and audit["full_outcome_complete"] is not True:
        raise LifecycleError("full_outcome_missing")
    inventory = _validate_inventory(request["inventory"], "inventory", anchors)
    if digest(request["inventory"]) != bindings["initial_inventory_sha256"] or digest(request["inventory"]) != anchors["initial_inventory_sha256"]:
        raise LifecycleError("inventory_incomplete", "initial_inventory_binding")
    if digest(request["persistence_authorities"]) != bindings["persistence_authorities_sha256"] or digest(request["persistence_authorities"]) != anchors["persistence_authorities_sha256"]:
        raise LifecycleError("persistence_authority_missing", "authority_binding")
    observed_at = _timestamp(inventory["observed_at"], "inventory.observed_at")
    authorities = _validate_authorities(request["persistence_authorities"], observed_at, anchors)
    child_plan = _validate_parent_child_plan(request["parent_child_closeout_plan"], goal_id, terminal_task_id)
    if child_plan["plan_sha256"] != anchors["parent_child_closeout_plan_sha256"]:
        raise LifecycleError("parent_child_plan_mismatch", "trust_anchor")
    _child_resource_maps(child_plan, inventory["resources"], anchors)
    actions = []
    resources = []
    retained = []
    for resource in sorted(inventory["resources"], key=lambda item: item["resource_id"]):
        action, reason = _compile_action(resource, authorities)
        actions.append({
            "action_id": stable_action_id(resource["resource_id"], action, resource["target"]),
            "resource_id": resource["resource_id"], "resource_class": resource["resource_class"],
            "action": action, "exact_target_identity": copy.deepcopy(resource["target"]), "reason": reason,
        })
        resources.append({
            "resource_id": resource["resource_id"], "resource_class": resource["resource_class"],
            "ownership": resource["ownership"], "lifecycle": resource["lifecycle"],
            "target": copy.deepcopy(resource["target"]), "capabilities": copy.deepcopy(resource["capabilities"]),
            "persistence_authority_sha256": resource["persistence_authority_sha256"],
            "persistence_retain_until": authorities.get(resource["resource_id"], {}).get("retain_until"),
            "ownership_evidence": copy.deepcopy(resource["ownership_evidence"]),
        })
        if action in {"retain_terminal_host_record", "retain_persistent"}:
            retained.append({"resource_id": resource["resource_id"], "reason": reason})
    base = {
            "schema_version": SCHEMA_VERSION, "artifact_type": "TerminalLifecyclePlan",
        "goal_id": goal_id, "terminal_task_id": terminal_task_id,
        "board_path": goal["board_path"], "accepted_final_audit_path": goal["final_audit_path"],
        "trust_anchors_sha256": expected_trust_anchors_sha256,
        "bindings": bindings, "inventory_sha256": inventory["inventory_sha256"],
        "parent_child_closeout_plan_sha256": child_plan["plan_sha256"],
        "created_at": inventory["observed_at"], "resources": resources, "actions": actions,
        "retained_resources": retained, "host_actions_executed": False,
        "board_mutated": False, "acceptance_claimed": False,
    }
    return {**base, "plan_sha256": digest(base)}


ACTION_STATUSES = {"completed", "retained", "not_required", "failed"}


def _validate_parent_authority(value: Any) -> dict[str, Any]:
    try:
        authority = _object(value, "parent_action_receipt.parent_authority", {"authority_kind", "authority_id", "authority_sha256"})
        if authority["authority_kind"] != "parent_codex":
            raise LifecycleError("action_authority_invalid", "authority_kind")
        _text(authority["authority_id"], "parent_action_receipt.parent_authority.authority_id")
        _sha(authority["authority_sha256"], "parent_action_receipt.parent_authority.authority_sha256")
        return authority
    except LifecycleError as error:
        if error.internal_code == "schema_invalid":
            raise LifecycleError("action_authority_invalid", error.detail) from error
        raise


def _validate_action_evidence(value: Any, field: str, expected_action: dict[str, Any], status: str, completed_at: str) -> dict[str, Any]:
    evidence = _object(value, field, {"artifact_type", "action_id", "status", "exact_target_identity", "completed_at", "evidence_sha256"})
    if evidence["artifact_type"] != "ParentHostActionEvidence":
        raise LifecycleError("action_receipt_mismatch", field)
    if evidence["action_id"] != expected_action["action_id"] or evidence["status"] != status or evidence["exact_target_identity"] != expected_action["exact_target_identity"] or evidence["completed_at"] != completed_at:
        raise LifecycleError("action_receipt_mismatch", field)
    _timestamp(evidence["completed_at"], f"{field}.completed_at")
    _sha(evidence["evidence_sha256"], f"{field}.evidence_sha256")
    body = {key: evidence[key] for key in evidence if key != "evidence_sha256"}
    if evidence["evidence_sha256"] != digest(body):
        raise LifecycleError("action_receipt_mismatch", f"{field}.digest")
    return evidence


def _validate_action_receipt(
    value: Any, plan_value: dict[str, Any], anchors: dict[str, Any], post_inventory_sha256: str | None = None,
) -> dict[str, Any]:
    if value is None:
        raise LifecycleError("action_receipt_missing")
    receipt = _object(value, "parent_action_receipt", {"schema_version", "artifact_type", "plan_sha256", "parent_authority", "actions", "post_inventory_sha256", "completed_at", "receipt_sha256"})
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["artifact_type"] != "ParentTerminalActionReceipt":
        raise LifecycleError("action_receipt_mismatch", "type")
    if receipt["plan_sha256"] != plan_value["plan_sha256"]:
        raise LifecycleError("action_receipt_mismatch", "plan")
    if receipt["parent_authority"] != anchors["parent_authority"]:
        raise LifecycleError("action_authority_invalid", "anchored_parent_authority")
    _validate_parent_authority(receipt["parent_authority"])
    _sha(receipt["post_inventory_sha256"], "parent_action_receipt.post_inventory_sha256")
    if post_inventory_sha256 is not None and receipt["post_inventory_sha256"] != post_inventory_sha256:
        raise LifecycleError("action_receipt_mismatch", "post_inventory_sha256")
    receipt_completed_at = _timestamp(receipt["completed_at"], "parent_action_receipt.completed_at")
    if receipt_completed_at < _timestamp(plan_value["created_at"], "plan.created_at"):
        raise LifecycleError("action_receipt_mismatch", "receipt_before_plan")
    if not isinstance(receipt["actions"], list):
        raise LifecycleError("action_receipt_mismatch", "actions")
    expected = {row["action_id"]: row for row in plan_value["actions"]}
    actual: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(receipt["actions"]):
        row = _object(raw, f"parent_action_receipt.actions[{index}]", {"action_id", "status", "exact_target_identity", "evidence", "completed_at"})
        action_id = _text(row["action_id"], f"parent_action_receipt.actions[{index}].action_id")
        if action_id in actual or action_id not in expected:
            raise LifecycleError("action_receipt_mismatch", action_id)
        expected_action = expected[action_id]
        try:
            target = _validate_target(expected_action["resource_class"], row["exact_target_identity"], f"parent_action_receipt.actions[{index}].exact_target_identity")
        except LifecycleError as error:
            raise LifecycleError("action_receipt_mismatch", action_id) from error
        if target != expected_action["exact_target_identity"]:
            raise LifecycleError("action_receipt_mismatch", action_id)
        status = _text(row["status"], f"parent_action_receipt.actions[{index}].status")
        if status not in ACTION_STATUSES:
            raise LifecycleError("action_receipt_mismatch", action_id)
        required_status = "not_required" if expected_action["action"] == "none" else "retained" if expected_action["action"].startswith("retain_") else "completed"
        if status == "failed":
            raise LifecycleError("action_failed", action_id)
        if status != required_status:
            raise LifecycleError("action_receipt_mismatch", action_id)
        completed_at = _timestamp(row["completed_at"], f"parent_action_receipt.actions[{index}].completed_at")
        if completed_at < _timestamp(plan_value["created_at"], "plan.created_at") or completed_at > receipt_completed_at:
            raise LifecycleError("action_receipt_mismatch", action_id)
        _validate_action_evidence(row["evidence"], f"parent_action_receipt.actions[{index}].evidence", expected_action, status, row["completed_at"])
        if expected_action["resource_class"] == "parent_thread" and expected_action["action"] != "none":
            raise LifecycleError("parent_action_forbidden", expected_action["resource_id"])
        actual[action_id] = row
    if set(actual) != set(expected):
        raise LifecycleError("action_receipt_mismatch", "resource_set")
    supplied = _sha(receipt["receipt_sha256"], "parent_action_receipt.receipt_sha256")
    base = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    if supplied != digest(base):
        raise LifecycleError("action_receipt_mismatch", "digest")
    return receipt


def _target_drift(before: dict[str, Any], after: dict[str, Any], resource_class: str, resource_id: str) -> None:
    if before == after:
        return
    if resource_class in {"provider_process", "board_server"} and before.get("pid") == after.get("pid") and before.get("process_started_at") != after.get("process_started_at"):
        raise LifecycleError("pid_reused", resource_id)
    raise LifecycleError("target_changed", resource_id)


def _compute_ready(value: Any, trust_anchors: Any, expected_trust_anchors_sha256: str, stage_manifest_sha256: str) -> dict[str, Any]:
    anchors = _validate_trust_anchors(trust_anchors, expected_trust_anchors_sha256)
    request = _object(value, "ready_request", {"schema_version", "operation", "plan", "parent_child_closeout_plan", "parent_child_closeout_receipt", "parent_action_receipt", "post_inventory", "current_board_snapshot"})
    if request["schema_version"] != SCHEMA_VERSION or request["operation"] != "ready":
        raise LifecycleError("schema_invalid", "ready_request")
    plan_value = _validate_plan(request["plan"])
    if plan_value["trust_anchors_sha256"] != expected_trust_anchors_sha256 or plan_value["goal_id"] != anchors["goal_id"]:
        raise LifecycleError("plan_digest_mismatch", "trust_anchors")
    board = _validate_board(request["current_board_snapshot"])
    if digest(board) != plan_value["bindings"]["pre_transition_board_projection_sha256"] or board["status"] == "done":
        raise LifecycleError("premature_board_mutation")
    post = _validate_inventory(request["post_inventory"], "post_inventory", anchors)
    action_receipt = _validate_action_receipt(request["parent_action_receipt"], plan_value, anchors, post["inventory_sha256"])
    child_plan = _validate_parent_child_plan(request["parent_child_closeout_plan"], plan_value["goal_id"], plan_value["terminal_task_id"])
    if child_plan["plan_sha256"] != plan_value["parent_child_closeout_plan_sha256"]:
        raise LifecycleError("parent_child_plan_mismatch", "plan_binding")
    child_receipt = _validate_parent_child_receipt(
        request["parent_child_closeout_receipt"], child_plan, plan_value, action_receipt, post,
    )
    if _timestamp(post["observed_at"], "post_inventory.observed_at") <= _timestamp(action_receipt["completed_at"], "parent_action_receipt.completed_at"):
        raise LifecycleError("post_inventory_missing", "not_fresh")
    if _timestamp(post["observed_at"], "post_inventory.observed_at") <= _timestamp(plan_value["created_at"], "plan.created_at"):
        raise LifecycleError("post_inventory_missing", "not_after_plan")
    planned_resources = {row["resource_id"]: row for row in plan_value["resources"]}
    planned_actions = {row["resource_id"]: row for row in plan_value["actions"]}
    post_resources = {row["resource_id"]: row for row in post["resources"]}
    if set(planned_resources) != set(post_resources):
        missing = set(planned_resources) - set(post_resources)
        extra = set(post_resources) - set(planned_resources)
        if any(
            resource_id in planned_resources and planned_resources[resource_id]["ownership"] != "goal_owned"
            for resource_id in missing
        ) or extra:
            raise LifecycleError("unknown_mutation_forbidden", "resource_set_changed")
        raise LifecycleError("inventory_incomplete", "resource_set_changed")
    results = []
    retained = []
    for resource_id in sorted(planned_resources):
        before = planned_resources[resource_id]
        after = post_resources[resource_id]
        action = planned_actions[resource_id]
        if after["resource_class"] != before["resource_class"]:
            raise LifecycleError("target_changed", resource_id)
        if after["ownership"] != before["ownership"]:
            raise LifecycleError("unknown_mutation_forbidden", resource_id)
        _target_drift(action["exact_target_identity"], after["target"], after["resource_class"], resource_id)
        for field in ("ownership_evidence",):
            if after[field] != before[field]:
                raise LifecycleError("unknown_mutation_forbidden", resource_id)
        if before["ownership"] != "goal_owned" and action["action"] != "none":
            raise LifecycleError("unknown_mutation_forbidden", resource_id)
        if before["ownership"] != "goal_owned":
            for field in ("ownership", "lifecycle", "capabilities", "persistence_authority_sha256"):
                if after[field] != before[field]:
                    raise LifecycleError("unknown_mutation_forbidden", resource_id)
        lifecycle = after["lifecycle"]
        resource_class = after["resource_class"]
        if before["ownership"] == "goal_owned":
            if lifecycle == "unknown":
                raise LifecycleError("owned_resource_unknown", resource_id)
            if lifecycle == "active":
                if resource_class == "provider_process":
                    raise LifecycleError("provider_remains", resource_id)
                if resource_class == "board_server":
                    raise LifecycleError("listener_remains", resource_id)
                if resource_class == "worktree":
                    target = after["target"]
                    if target["current"] is True:
                        raise LifecycleError("worktree_current_forbidden", resource_id)
                    if target["dirty"] is True:
                        raise LifecycleError("worktree_dirty", resource_id)
                    if target["integrated"] is not True:
                        raise LifecycleError("worktree_unintegrated", resource_id)
                    raise LifecycleError("worktree_unsafe", resource_id)
                if resource_class == "persistent_session" and action["action"] == "retain_persistent" and before["persistence_authority_sha256"] is not None:
                    retain_until = before["persistence_retain_until"]
                    if retain_until is not None and _timestamp(retain_until, "plan.persistence_retain_until") <= _timestamp(post["observed_at"], "post_inventory.observed_at"):
                        raise LifecycleError("persistence_authority_missing", resource_id)
                    retained.append({"resource_id": resource_id, "reason": "prior_operator_persistence_authority"})
                else:
                    raise LifecycleError("owned_resource_active", resource_id)
            elif resource_class == "collaboration_agent" and lifecycle == "terminal" and action["action"] == "retain_terminal_host_record":
                retained.append({"resource_id": resource_id, "reason": "terminal_agent_host_record_only"})
        results.append({"resource_id": resource_id, "resource_class": resource_class, "ownership": before["ownership"], "lifecycle": lifecycle, "action": action["action"]})
    base = {
        "schema_version": SCHEMA_VERSION, "artifact_type": "TerminalLifecycleReadyReceipt",
        "goal_id": plan_value["goal_id"], "plan_sha256": plan_value["plan_sha256"],
        "trust_anchors_sha256": expected_trust_anchors_sha256,
        "ready_stage_manifest_sha256": stage_manifest_sha256,
        "parent_action_receipt_sha256": action_receipt["receipt_sha256"],
        "parent_child_closeout_receipt_sha256": child_receipt["receipt_sha256"],
        "post_inventory_sha256": post["inventory_sha256"],
        "current_board_sha256": digest(board), "resources": results,
        "retained_resources": retained, "transition_allowed": True, "board_mutated": False,
    }
    ready_digest_base = {key: value for key, value in base.items() if key != "ready_stage_manifest_sha256"}
    return {**base, "ready_sha256": digest(ready_digest_base)}


def ready(
    value: Any, trust_anchors: Any, expected_trust_anchors_sha256: str,
    stage_manifest: Any, expected_stage_manifest_sha256: str,
) -> dict[str, Any]:
    anchors = _validate_trust_anchors(trust_anchors, expected_trust_anchors_sha256)
    if stage_manifest is None or expected_stage_manifest_sha256 is None:
        raise LifecycleError("schema_invalid", "ready_stage_manifest_missing")
    manifest = _validate_stage_manifest(
        stage_manifest, expected_stage_manifest_sha256, "TerminalLifecycleReadyStageManifest",
    )
    request = _object(value, "ready_request", {
        "schema_version", "operation", "terminal_task_id", "bindings",
        "goal_contract", "board_snapshot", "pre_transition_board",
        "final_audit", "pre_inventory", "persistence_authorities", "plan",
        "parent_child_closeout_plan", "parent_child_closeout_receipt",
        "parent_action_receipt", "post_inventory",
    })
    if request["schema_version"] != SCHEMA_VERSION or request["operation"] != "ready":
        raise LifecycleError("schema_invalid", "ready_request")
    if request["board_snapshot"] != request["pre_transition_board"]:
        raise LifecycleError("schema_invalid", "pre_transition_board")
    original_plan_request = {
        "schema_version": SCHEMA_VERSION, "operation": "plan",
        "terminal_task_id": request["terminal_task_id"], "bindings": request["bindings"],
        "goal_contract": request["goal_contract"], "board_snapshot": request["board_snapshot"],
        "final_audit": request["final_audit"], "inventory": request["pre_inventory"],
        "persistence_authorities": request["persistence_authorities"],
        "parent_child_closeout_plan": request["parent_child_closeout_plan"],
    }
    recompiled_plan = plan(original_plan_request, anchors, expected_trust_anchors_sha256)
    if canonical_json(recompiled_plan) != canonical_json(request["plan"]):
        raise LifecycleError("plan_digest_mismatch", "recompile")
    pre_board = _validate_board(request["pre_transition_board"])
    post_inventory = _validate_inventory(request["post_inventory"], "post_inventory", anchors)
    receipt = request["parent_action_receipt"]
    if not isinstance(receipt, Mapping):
        raise LifecycleError("action_receipt_missing")
    receipt_sha256 = receipt.get("receipt_sha256")
    _sha(receipt_sha256, "parent_action_receipt.receipt_sha256")
    if (
        manifest["trust_anchors_sha256"] != expected_trust_anchors_sha256
        or manifest["plan_sha256"] != recompiled_plan["plan_sha256"]
        or manifest["parent_action_receipt_sha256"] != receipt_sha256
        or manifest["post_inventory_sha256"] != post_inventory["inventory_sha256"]
        or manifest["pre_transition_board_source_sha256"] != pre_board["source_sha256"]
    ):
        raise LifecycleError("schema_invalid", "ready_stage_manifest_binding")
    core_request = {
        "schema_version": SCHEMA_VERSION, "operation": "ready",
        "plan": recompiled_plan,
        "parent_child_closeout_plan": request["parent_child_closeout_plan"],
        "parent_child_closeout_receipt": request["parent_child_closeout_receipt"],
        "parent_action_receipt": request["parent_action_receipt"],
        "post_inventory": request["post_inventory"],
        "current_board_snapshot": request["pre_transition_board"],
    }
    candidate = _compute_ready(
        core_request, anchors, expected_trust_anchors_sha256,
        expected_stage_manifest_sha256,
    )
    if candidate["ready_sha256"] != manifest["ready_receipt_sha256"]:
        raise LifecycleError("action_receipt_mismatch", "ready_stage_manifest_receipt")
    return candidate


def _validate_ready(value: Any) -> dict[str, Any]:
    ready_value = _object(
        value, "ready_receipt",
        {"schema_version", "artifact_type", "goal_id", "plan_sha256", "trust_anchors_sha256", "ready_stage_manifest_sha256", "parent_action_receipt_sha256", "parent_child_closeout_receipt_sha256", "post_inventory_sha256", "current_board_sha256", "resources", "retained_resources", "transition_allowed", "board_mutated", "ready_sha256"},
    )
    if ready_value["schema_version"] != SCHEMA_VERSION or ready_value["artifact_type"] != "TerminalLifecycleReadyReceipt":
        raise LifecycleError("schema_invalid", "ready_receipt")
    for field in ("plan_sha256", "trust_anchors_sha256", "ready_stage_manifest_sha256", "parent_action_receipt_sha256", "parent_child_closeout_receipt_sha256", "post_inventory_sha256", "current_board_sha256"):
        _sha(ready_value[field], f"ready_receipt.{field}")
    if ready_value["transition_allowed"] is not True or ready_value["board_mutated"] is not False:
        raise LifecycleError("terminal_state_mismatch", "ready_receipt")
    base = {key: ready_value[key] for key in ready_value if key not in {"ready_sha256", "ready_stage_manifest_sha256"}}
    if _sha(ready_value["ready_sha256"], "ready_receipt.ready_sha256") != digest(base):
        raise LifecycleError("plan_digest_mismatch", "ready_receipt")
    return ready_value


def _checker(value: Any, field: str, code: str, expected_checker_id: str, board_source_sha256: str, board_projection_sha256: str) -> dict[str, Any]:
    checker = _object(value, field, {"checker_id", "post_transition_board_source_sha256", "post_transition_board_sha256", "executed", "status", "evidence_sha256", "receipt_sha256"})
    if checker["checker_id"] != expected_checker_id:
        raise LifecycleError(code, "checker_id")
    _text(checker["checker_id"], f"{field}.checker_id")
    if checker["post_transition_board_source_sha256"] != board_source_sha256 or checker["post_transition_board_sha256"] != board_projection_sha256:
        raise LifecycleError(code, "board_binding")
    _sha(checker["post_transition_board_source_sha256"], f"{field}.post_transition_board_source_sha256")
    _sha(checker["post_transition_board_sha256"], f"{field}.post_transition_board_sha256")
    _sha(checker["evidence_sha256"], f"{field}.evidence_sha256")
    _sha(checker["receipt_sha256"], f"{field}.receipt_sha256")
    if checker["evidence_sha256"] == checker["receipt_sha256"]:
        raise LifecycleError(code, "evidence_receipt_collision")
    body = {key: checker[key] for key in checker if key != "receipt_sha256"}
    if checker["receipt_sha256"] != digest(body):
        raise LifecycleError(code, "digest")
    if checker["executed"] is not True or checker["status"] != "pass":
        raise LifecycleError(code)
    return checker


def _validate_terminal_transition(pre: dict[str, Any], post: dict[str, Any]) -> None:
    if pre["goal_id"] != post["goal_id"] or pre["status"] != "active" or post["status"] != "done" or pre["active_task"] is None or post["active_task"] is not None:
        raise LifecycleError("terminal_state_mismatch")
    pre_tasks = {task["task_id"]: task for task in pre["tasks"]}
    post_tasks = {task["task_id"]: task for task in post["tasks"]}
    if set(pre_tasks) != set(post_tasks) or any(pre_tasks[key]["type"] != post_tasks[key]["type"] for key in pre_tasks):
        raise LifecycleError("terminal_state_mismatch", "task_set_or_type")
    for task_id, task in pre_tasks.items():
        if task_id == pre["active_task"]:
            if task["status"] != "active" or post_tasks[task_id]["status"] != "done":
                raise LifecycleError("terminal_state_mismatch", "terminal_task_transition")
        elif (
            task["status"] not in {"done", "blocked"}
            or post_tasks[task_id]["status"] != task["status"]
        ):
            raise LifecycleError("terminal_state_mismatch", "nonterminal_task_transition")


def confirm(
    value: Any, trust_anchors: Any, expected_trust_anchors_sha256: str,
    stage_manifest: Any, expected_stage_manifest_sha256: str,
) -> dict[str, Any]:
    anchors = _validate_trust_anchors(trust_anchors, expected_trust_anchors_sha256)
    if stage_manifest is None or expected_stage_manifest_sha256 is None:
        raise LifecycleError("schema_invalid", "confirm_stage_manifest_missing")
    confirm_manifest = _validate_stage_manifest(
        stage_manifest, expected_stage_manifest_sha256, "TerminalLifecycleConfirmStageManifest",
    )
    request = _object(value, "confirm_request", {
        "schema_version", "operation", "trust_anchors", "expected_trust_anchors_sha256",
        "terminal_task_id", "bindings", "goal_contract", "board_snapshot",
        "final_audit", "persistence_authorities", "plan", "parent_action_receipt",
        "parent_child_closeout_plan", "parent_child_closeout_receipt",
        "pre_inventory", "post_inventory", "pre_transition_board",
        "ready_stage_manifest", "ready_receipt", "post_transition_board",
        "official_checker", "stop_checker",
    })
    if request["schema_version"] != SCHEMA_VERSION or request["operation"] != "confirm":
        raise LifecycleError("schema_invalid", "confirm_request")
    if request["expected_trust_anchors_sha256"] != expected_trust_anchors_sha256 or request["trust_anchors"] != anchors:
        raise LifecycleError("schema_invalid", "trust_anchor_context")
    if request["board_snapshot"] != request["pre_transition_board"]:
        raise LifecycleError("schema_invalid", "pre_transition_board")
    original_plan_request = {
        "schema_version": SCHEMA_VERSION, "operation": "plan",
        "terminal_task_id": request["terminal_task_id"], "bindings": request["bindings"],
        "goal_contract": request["goal_contract"], "board_snapshot": request["board_snapshot"],
        "final_audit": request["final_audit"], "inventory": request["pre_inventory"],
        "persistence_authorities": request["persistence_authorities"],
        "parent_child_closeout_plan": request["parent_child_closeout_plan"],
    }
    recompiled_plan = plan(original_plan_request, anchors, expected_trust_anchors_sha256)
    if canonical_json(recompiled_plan) != canonical_json(request["plan"]):
        raise LifecycleError("plan_digest_mismatch", "confirm_recompile")
    plan_value = _validate_plan(recompiled_plan)
    pre_board = _validate_board(request["pre_transition_board"])
    post_board = _validate_board(request["post_transition_board"])
    pre_inventory = _validate_inventory(request["pre_inventory"], "pre_inventory", anchors)
    post_inventory = _validate_inventory(request["post_inventory"], "post_inventory", anchors)
    if pre_inventory["inventory_sha256"] != plan_value["inventory_sha256"]:
        raise LifecycleError("plan_digest_mismatch", "pre_inventory")
    recomputed_ready = ready({
        "schema_version": SCHEMA_VERSION, "operation": "ready",
        "terminal_task_id": request["terminal_task_id"], "bindings": request["bindings"],
        "goal_contract": request["goal_contract"], "board_snapshot": request["board_snapshot"],
        "pre_transition_board": request["pre_transition_board"], "final_audit": request["final_audit"],
        "pre_inventory": request["pre_inventory"], "persistence_authorities": request["persistence_authorities"],
        "plan": request["plan"],
        "parent_child_closeout_plan": request["parent_child_closeout_plan"],
        "parent_child_closeout_receipt": request["parent_child_closeout_receipt"],
        "parent_action_receipt": request["parent_action_receipt"],
        "post_inventory": request["post_inventory"],
    }, anchors, expected_trust_anchors_sha256, request["ready_stage_manifest"], confirm_manifest["ready_stage_manifest_sha256"])
    if canonical_json(recomputed_ready) != canonical_json(request["ready_receipt"]):
        raise LifecycleError("action_receipt_mismatch", "ready_receipt")
    ready_value = recomputed_ready
    _validate_terminal_transition(pre_board, post_board)
    post_board_sha256 = digest(post_board)
    official = _checker(request["official_checker"], "official_checker", "official_checker_failed", "goalbuddy_official_checker", post_board["source_sha256"], post_board_sha256)
    stop = _checker(request["stop_checker"], "stop_checker", "stop_checker_failed", "goalbuddy_stop_checker", post_board["source_sha256"], post_board_sha256)
    if official["evidence_sha256"] == stop["evidence_sha256"] or official["receipt_sha256"] == stop["receipt_sha256"]:
        raise LifecycleError("official_checker_failed", "duplicate_checker_receipt")
    if (
        confirm_manifest["trust_anchors_sha256"] != expected_trust_anchors_sha256
        or confirm_manifest["ready_receipt_sha256"] != ready_value["ready_sha256"]
        or confirm_manifest["pre_transition_board_source_sha256"] != pre_board["source_sha256"]
        or confirm_manifest["post_transition_board_source_sha256"] != post_board["source_sha256"]
        or confirm_manifest["post_transition_board_projection_sha256"] != post_board_sha256
        or confirm_manifest["official_checker_receipt_sha256"] != official["receipt_sha256"]
        or confirm_manifest["stop_checker_receipt_sha256"] != stop["receipt_sha256"]
    ):
        raise LifecycleError("action_receipt_mismatch", "confirm_stage_manifest_binding")
    base = {
        "schema_version": SCHEMA_VERSION, "artifact_type": "TerminalLifecycleConfirmation",
        "goal_id": ready_value["goal_id"], "ready_sha256": ready_value["ready_sha256"],
        "trust_anchors_sha256": expected_trust_anchors_sha256,
        "confirm_stage_manifest_sha256": expected_stage_manifest_sha256,
        "plan_sha256": plan_value["plan_sha256"],
        "parent_child_closeout_plan_sha256": plan_value["parent_child_closeout_plan_sha256"],
        "parent_child_closeout_receipt_sha256": ready_value["parent_child_closeout_receipt_sha256"],
        "pre_inventory_sha256": pre_inventory["inventory_sha256"],
        "post_inventory_sha256": post_inventory["inventory_sha256"],
        "post_transition_board_sha256": post_board_sha256,
        "official_checker_receipt_sha256": official["receipt_sha256"],
        "stop_checker_receipt_sha256": stop["receipt_sha256"],
        "terminal_confirmed": True, "acceptance_claimed": False,
    }
    return {**base, "confirmation_sha256": digest(base)}


def compile_operation(
    value: Any, trust_anchors: Any, expected_trust_anchors_sha256: str,
    stage_manifest: Any = None, expected_stage_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LifecycleError("schema_invalid", "request")
    operation = value.get("operation")
    if operation == "plan":
        return plan(value, trust_anchors, expected_trust_anchors_sha256)
    if operation == "ready":
        return ready(value, trust_anchors, expected_trust_anchors_sha256, stage_manifest, expected_stage_manifest_sha256)
    if operation == "confirm":
        return confirm(value, trust_anchors, expected_trust_anchors_sha256, stage_manifest, expected_stage_manifest_sha256)
    raise LifecycleError("schema_invalid", "operation")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--trust-anchors", type=Path, required=True)
    parser.add_argument("--expected-trust-anchors-sha256", required=True)
    parser.add_argument("--stage-manifest", type=Path)
    parser.add_argument("--expected-stage-manifest-sha256")
    args = parser.parse_args(argv)
    try:
        request = load_json(args.input)
        operation = request.get("operation") if isinstance(request, Mapping) else None
        if operation in {"ready", "confirm"} and (args.stage_manifest is None or args.expected_stage_manifest_sha256 is None):
            raise LifecycleError("schema_invalid", "stage_manifest_missing")
        supplied_stage_manifest = load_json(args.stage_manifest) if args.stage_manifest is not None else None
        result = compile_operation(request, load_json(args.trust_anchors), args.expected_trust_anchors_sha256, supplied_stage_manifest, args.expected_stage_manifest_sha256)
    except LifecycleError as error:
        print(canonical_json({"ok": False, "error": {"code": error.code, "detail": error.detail}}), file=sys.stderr)
        return 2
    print(canonical_json({"ok": True, "result": result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
