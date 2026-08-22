#!/usr/bin/env python3
"""Compile and confirm exact Parent-owned Codex child cleanup for terminal T999."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
EVENT_KINDS = {"started", "interacted", "completed", "interrupted", "failed"}
ACTIVE_STATUSES = {"running", "pending_init", "waiting", "blocked", "idle"}
TERMINAL_STATUSES = {"completed", "interrupted", "failed", "cancelled", "not_loaded"}
REQUEST_KEYS = {
    "schema_version", "operation", "goal_id", "terminal_task_id", "parent",
    "history_pages", "live_agents", "persistence_authorities", "plan",
    "action_results", "post_live_agents",
}
PARENT_KEYS = {"thread_id", "host_id", "agent_path"}
PAGE_KEYS = {"request_cursor", "has_more", "next_cursor", "child_events"}
EVENT_KEYS = {"thread_id", "agent_path", "kind"}
AGENT_KEYS = {"agent_path", "status"}
RESULT_KEYS = {"action_id", "status", "evidence_sha256"}


class CloseoutError(ValueError):
    """Stable fail-closed Parent-child cleanup error."""


def canonical(value: object) -> str:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=False,
            separators=(",", ":"), sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CloseoutError("parent_child_closeout_schema_invalid") from error


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CloseoutError(f"parent_child_closeout_duplicate_key:{key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CloseoutError("parent_child_closeout_input_invalid") from error
    if not isinstance(value, dict):
        raise CloseoutError("parent_child_closeout_schema_invalid")
    return value


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CloseoutError(f"parent_child_closeout_schema_invalid:{label}")
    return dict(value)


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CloseoutError(f"parent_child_closeout_schema_invalid:{label}")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise CloseoutError(f"parent_child_closeout_schema_invalid:{label}")
    return value


def _agent_rows(value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise CloseoutError(f"parent_child_closeout_schema_invalid:{label}")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        row = _object(raw, AGENT_KEYS, f"{label}[{index}]")
        path = _text(row["agent_path"], f"{label}[{index}].agent_path")
        status = _text(row["status"], f"{label}[{index}].status")
        if status not in ACTIVE_STATUSES | TERMINAL_STATUSES:
            raise CloseoutError(f"parent_child_closeout_status_unknown:{status}")
        if path in seen:
            raise CloseoutError(f"parent_child_closeout_inventory_duplicate:{path}")
        seen.add(path)
        rows.append({"agent_path": path, "status": status})
    return sorted(rows, key=lambda item: item["agent_path"])


def _history(value: Any, parent: dict[str, str]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise CloseoutError("parent_child_closeout_history_incomplete:no_pages")
    children: dict[str, dict[str, str]] = {}
    paths: dict[str, str] = {}
    expected_cursor: str | None = None
    for index, raw in enumerate(value):
        page = _object(raw, PAGE_KEYS, f"history_pages[{index}]")
        if page["request_cursor"] != expected_cursor:
            raise CloseoutError(f"parent_child_closeout_history_incomplete:cursor:{index}")
        if type(page["has_more"]) is not bool:
            raise CloseoutError(f"parent_child_closeout_schema_invalid:history_pages[{index}].has_more")
        next_cursor = page["next_cursor"]
        if page["has_more"]:
            expected_cursor = _text(next_cursor, f"history_pages[{index}].next_cursor")
        else:
            if next_cursor is not None or index != len(value) - 1:
                raise CloseoutError(f"parent_child_closeout_history_incomplete:terminal_page:{index}")
            expected_cursor = None
        events = page["child_events"]
        if not isinstance(events, list):
            raise CloseoutError(f"parent_child_closeout_schema_invalid:history_pages[{index}].child_events")
        for event_index, raw_event in enumerate(events):
            event = _object(raw_event, EVENT_KEYS, f"history_pages[{index}].child_events[{event_index}]")
            thread_id = _text(event["thread_id"], "child.thread_id")
            agent_path = _text(event["agent_path"], "child.agent_path")
            kind = _text(event["kind"], "child.kind")
            if kind not in EVENT_KINDS:
                raise CloseoutError(f"parent_child_closeout_schema_invalid:child.kind:{kind}")
            if thread_id == parent["thread_id"] or agent_path == parent["agent_path"]:
                raise CloseoutError("parent_child_closeout_parent_mutation_forbidden")
            prefix = parent["agent_path"].rstrip("/") + "/"
            if not agent_path.startswith(prefix):
                raise CloseoutError(f"parent_child_closeout_ownership_unproven:{agent_path}")
            if thread_id in children and children[thread_id]["agent_path"] != agent_path:
                raise CloseoutError(f"parent_child_closeout_identity_conflict:{thread_id}")
            if agent_path in paths and paths[agent_path] != thread_id:
                raise CloseoutError(f"parent_child_closeout_identity_conflict:{agent_path}")
            if thread_id not in children:
                # Native Parent history is supplied newest-first. Preserve the
                # first observed event as the latest event; older pages may
                # repeat the same child but cannot replace its latest state.
                children[thread_id] = {"thread_id": thread_id, "agent_path": agent_path, "last_event_kind": kind}
            paths[agent_path] = thread_id
    if value[-1]["has_more"] is not False:
        raise CloseoutError("parent_child_closeout_history_incomplete:more_pages")
    return sorted(children.values(), key=lambda item: (item["agent_path"], item["thread_id"]))


def _authorities(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise CloseoutError("parent_child_closeout_schema_invalid:persistence_authorities")
    # Nested children are execution-scoped implementation details. Persistent
    # sessions are represented and authorized by the broader Terminal
    # Lifecycle inventory, never by this caller-supplied pre-gate.
    if value:
        raise CloseoutError("parent_child_closeout_child_persistence_forbidden")
    return {}


def _action_id(action: str, thread_id: str, agent_path: str) -> str:
    return "action-" + hashlib.sha256(
        canonical({"action": action, "thread_id": thread_id, "agent_path": agent_path}).encode("utf-8")
    ).hexdigest()


def compile_plan(request: dict[str, Any]) -> dict[str, Any]:
    parent = _object(request["parent"], PARENT_KEYS, "parent")
    for key in PARENT_KEYS:
        parent[key] = _text(parent[key], f"parent.{key}")
    children = _history(request["history_pages"], parent)
    live = _agent_rows(request["live_agents"], "live_agents")
    live_by_path = {row["agent_path"]: row["status"] for row in live}
    if live_by_path.get(parent["agent_path"]) not in ACTIVE_STATUSES:
        raise CloseoutError("parent_child_closeout_parent_inventory_missing")
    child_by_path = {row["agent_path"]: row for row in children}
    unknown_live = sorted(
        path for path, status in live_by_path.items()
        if path != parent["agent_path"] and status in ACTIVE_STATUSES and path not in child_by_path
    )
    if unknown_live:
        raise CloseoutError(f"parent_child_closeout_inventory_incomplete:{unknown_live[0]}")
    authorities = _authorities(request["persistence_authorities"])
    descendants: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    retained: list[dict[str, str]] = []
    for child in children:
        thread_id = child["thread_id"]
        status = live_by_path.get(child["agent_path"], "not_loaded")
        descendant = dict(child)
        descendant["live_status"] = status
        descendant["persistence_authority_sha256"] = authorities.get(thread_id)
        descendants.append(descendant)
        if thread_id in authorities:
            retained.append({
                "thread_id": thread_id, "agent_path": child["agent_path"],
                "authority_sha256": authorities[thread_id],
            })
            continue
        if status in ACTIVE_STATUSES:
            actions.append({
                "action_id": _action_id("interrupt_agent", thread_id, child["agent_path"]),
                "sequence": 1, "action": "interrupt_agent", "thread_id": thread_id,
                "host_id": parent["host_id"], "agent_path": child["agent_path"],
            })
        actions.append({
            "action_id": _action_id("archive_thread", thread_id, child["agent_path"]),
            "sequence": 2, "action": "archive_thread", "thread_id": thread_id,
            "host_id": parent["host_id"], "agent_path": child["agent_path"],
        })
    actions.sort(key=lambda item: (item["sequence"], item["agent_path"], item["thread_id"]))
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ParentChildCloseoutPlan",
        "goal_id": request["goal_id"],
        "terminal_task_id": request["terminal_task_id"],
        "parent": parent,
        "descendants": descendants,
        "actions": actions,
        "retained_persistent_children": retained,
        "board_mutation_allowed": False,
        "plan_sha256": "",
    }
    plan["plan_sha256"] = digest({key: value for key, value in plan.items() if key != "plan_sha256"})
    return plan


def confirm(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request["plan"], dict):
        raise CloseoutError("parent_child_closeout_plan_missing")
    expected = compile_plan({**request, "operation": "plan", "plan": None, "action_results": [], "post_live_agents": []})
    if request["plan"] != expected:
        raise CloseoutError("parent_child_closeout_plan_mismatch")
    results = request["action_results"]
    if not isinstance(results, list):
        raise CloseoutError("parent_child_closeout_schema_invalid:action_results")
    result_by_id: dict[str, dict[str, str]] = {}
    for index, raw in enumerate(results):
        row = _object(raw, RESULT_KEYS, f"action_results[{index}]")
        action_id = _text(row["action_id"], f"action_results[{index}].action_id")
        if action_id in result_by_id:
            raise CloseoutError(f"parent_child_closeout_action_duplicate:{action_id}")
        if row["status"] != "success":
            raise CloseoutError(f"parent_child_closeout_action_failed:{action_id}")
        result_by_id[action_id] = {
            "action_id": action_id, "status": "success",
            "evidence_sha256": _sha(row["evidence_sha256"], f"action_results[{index}].evidence_sha256"),
        }
    expected_ids = {row["action_id"] for row in expected["actions"]}
    if set(result_by_id) != expected_ids:
        raise CloseoutError("parent_child_closeout_action_receipts_incomplete")
    post = _agent_rows(request["post_live_agents"], "post_live_agents")
    post_by_path = {row["agent_path"]: row["status"] for row in post}
    parent_path = expected["parent"]["agent_path"]
    if post_by_path.get(parent_path) not in ACTIVE_STATUSES:
        raise CloseoutError("parent_child_closeout_parent_inventory_missing")
    retained_paths = {row["agent_path"] for row in expected["retained_persistent_children"]}
    remaining = sorted(
        path for path, status in post_by_path.items()
        if path != parent_path and path not in retained_paths and status in ACTIVE_STATUSES
    )
    if remaining:
        raise CloseoutError(f"parent_child_closeout_child_remains_active:{remaining[0]}")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ParentChildCloseoutReceipt",
        "goal_id": expected["goal_id"],
        "terminal_task_id": expected["terminal_task_id"],
        "parent_thread_id": expected["parent"]["thread_id"],
        "plan_sha256": expected["plan_sha256"],
        "action_results": [result_by_id[key] for key in sorted(result_by_id)],
        "post_live_agents": post,
        "closeout_complete": True,
        "terminal_lifecycle_allowed": True,
        "board_mutation_allowed": False,
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = digest({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    return receipt


def process(value: dict[str, Any]) -> dict[str, Any]:
    request = _object(value, REQUEST_KEYS, "request")
    if request["schema_version"] != SCHEMA_VERSION:
        raise CloseoutError("parent_child_closeout_schema_invalid:schema_version")
    _text(request["goal_id"], "goal_id")
    if request["terminal_task_id"] != "T999":
        raise CloseoutError("parent_child_closeout_terminal_task_invalid")
    if request["operation"] == "plan":
        if request["plan"] is not None or request["action_results"] != [] or request["post_live_agents"] != []:
            raise CloseoutError("parent_child_closeout_schema_invalid:plan_inputs")
        return compile_plan(request)
    if request["operation"] == "confirm":
        return confirm(request)
    raise CloseoutError("parent_child_closeout_operation_invalid")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(canonical(process(load_json(args.input))))
    except CloseoutError as error:
        print(canonical({"status": "error", "error": str(error)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
