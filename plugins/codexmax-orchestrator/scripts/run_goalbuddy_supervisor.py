#!/usr/bin/env python3
"""Run a deterministic local GoalBuddy-backed Supervisor execution loop.

The runtime reads GoalBuddy board truth, never mutates it, never reconstructs
it from transcript, and never calls a provider. Runtime evidence is a separate
append-only hash-chained JSONL event log plus a resumable JSON projection.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True


SCRIPT_PATH = Path(__file__).resolve()
PLUGIN_ROOT = SCRIPT_PATH.parents[1]
REPOSITORY_ROOT = SCRIPT_PATH.parents[3]
ZERO_HASH = "0" * 64
SCHEMA_VERSION = 1
RUNTIME_SCHEMA_VERSION = 2
ABSOLUTE_MAX_WRITE_WORKERS = 2
CANONICAL_LANE_STATUSES = {
    "assigned",
    "in_progress",
    "ready_for_review",
    "candidate_complete",
    "needs_revision",
    "needs_reassignment",
    "needs_parent_repair",
    "waiting_external",
}
FORBIDDEN_EVENT_TYPES = {"parent_acceptance", "checkpoint_accepted", "goal_accepted"}
FORBIDDEN_TRANSCRIPT_KEYS = {
    "transcript",
    "raw_transcript",
    "chat_history",
    "conversation_history",
}
PARENT_ONLY_KEYS = {"accepted", "accepted_by", "acceptance_authority", "goal_complete"}


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_route_runtime = _load_module(
    "codexmax_route_runtime_for_supervisor_loop",
    PLUGIN_ROOT / "scripts" / "resolve_worker_route.py",
)
_recovery_runtime: Any | None = None


def _load_recovery_runtime() -> Any:
    global _recovery_runtime
    if _recovery_runtime is None:
        _recovery_runtime = _load_module(
            "codexmax_recovery_runtime_for_supervisor_loop",
            PLUGIN_ROOT / "scripts" / "recover_supervisor_runtime.py",
        )
    return _recovery_runtime


class LoopError(ValueError):
    """Fail-closed Supervisor-loop error with a stable code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    number: int
    content: str


_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise LoopError("source_unreadable", f"{path}: {exc}") from exc


def _yaml_lines(text: str) -> list[_YamlLine]:
    lines: list[_YamlLine] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise LoopError("board_parse_error", f"line {number}: tabs are unsupported")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise LoopError("board_parse_error", f"line {number}: indentation must use two spaces")
        lines.append(_YamlLine(indent, number, raw[indent:]))
    return lines


def _split_inline_list(value: str, line_number: int) -> list[str]:
    body = value[1:-1].strip()
    if not body:
        return []
    result: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for character in body:
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            current.append(character)
        elif character == "," and quote is None:
            item = "".join(current).strip()
            if not item:
                raise LoopError("board_parse_error", f"line {line_number}: empty inline-list item")
            result.append(item)
            current = []
        else:
            current.append(character)
    if quote is not None:
        raise LoopError("board_parse_error", f"line {line_number}: unterminated quote")
    item = "".join(current).strip()
    if not item:
        raise LoopError("board_parse_error", f"line {line_number}: empty inline-list item")
    result.append(item)
    return result


def _yaml_scalar(raw: str, line_number: int) -> Any:
    value = raw.strip()
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if value == "{}":
        return {}
    if value.startswith("["):
        if not value.endswith("]"):
            raise LoopError("board_parse_error", f"line {line_number}: invalid inline list")
        return [_yaml_scalar(item, line_number) for item in _split_inline_list(value, line_number)]
    if value.startswith(("{", "&", "*", "!", "|", ">")):
        raise LoopError("board_parse_error", f"line {line_number}: unsupported YAML syntax")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        if value[0] == '"':
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:
                raise LoopError("board_parse_error", f"line {line_number}: invalid quoted string") from exc
            return parsed
        return value[1:-1].replace("''", "'")
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]+", value):
        return float(value)
    return value


def _mapping_entry(content: str, line_number: int) -> tuple[str, str]:
    if ":" not in content:
        raise LoopError("board_parse_error", f"line {line_number}: expected mapping entry")
    key, raw_value = content.split(":", 1)
    key = key.strip()
    if not _KEY.fullmatch(key):
        raise LoopError("board_parse_error", f"line {line_number}: invalid key {key!r}")
    return key, raw_value.strip()


def _parse_yaml_block(lines: list[_YamlLine], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines) or lines[index].indent != indent:
        line = lines[index].number if index < len(lines) else "end"
        raise LoopError("board_parse_error", f"line {line}: invalid indentation")
    if lines[index].content.startswith("- "):
        return _parse_yaml_sequence(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(lines: list[_YamlLine], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise LoopError("board_parse_error", f"line {line.number}: unexpected indentation")
        if line.content.startswith("- "):
            break
        key, raw_value = _mapping_entry(line.content, line.number)
        if key in result:
            raise LoopError("board_parse_error", f"line {line.number}: duplicate key {key}")
        index += 1
        if raw_value:
            result[key] = _yaml_scalar(raw_value, line.number)
        elif index < len(lines) and lines[index].indent > indent:
            result[key], index = _parse_yaml_block(lines, index, lines[index].indent)
        else:
            result[key] = None
    return result, index


def _parse_yaml_sequence(lines: list[_YamlLine], index: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent != indent or not line.content.startswith("- "):
            break
        raw_value = line.content[2:].strip()
        index += 1
        if not raw_value:
            if index < len(lines) and lines[index].indent > indent:
                item, index = _parse_yaml_block(lines, index, lines[index].indent)
            else:
                item = None
            result.append(item)
            continue
        first_key: str | None = None
        if ":" in raw_value:
            candidate = raw_value.split(":", 1)[0].strip()
            if _KEY.fullmatch(candidate):
                first_key = candidate
        if first_key is None:
            result.append(_yaml_scalar(raw_value, line.number))
            continue
        key, scalar = _mapping_entry(raw_value, line.number)
        item: dict[str, Any] = {key: _yaml_scalar(scalar, line.number) if scalar else None}
        if index < len(lines) and lines[index].indent > indent:
            continuation_indent = lines[index].indent
            continuation, index = _parse_yaml_mapping(lines, index, continuation_indent)
            overlap = set(item) & set(continuation)
            if overlap:
                raise LoopError("board_parse_error", f"line {line.number}: duplicate key {sorted(overlap)[0]}")
            item.update(continuation)
        result.append(item)
    return result, index


def parse_goalbuddy_yaml(text: str) -> dict[str, Any]:
    """Parse the bounded GoalBuddy YAML subset without executing YAML code."""

    lines = _yaml_lines(text)
    if not lines:
        raise LoopError("board_parse_error", "board is empty")
    value, index = _parse_yaml_block(lines, 0, lines[0].indent)
    if index != len(lines):
        raise LoopError("board_parse_error", f"line {lines[index].number}: unparsed content")
    if not isinstance(value, dict):
        raise LoopError("board_parse_error", "board root must be a mapping")
    return value


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LoopError("invalid_input", f"{field} must be an object")
    return value


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LoopError("invalid_input", f"{field} must be a non-empty string")
    return value.strip()


def _require_string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise LoopError("invalid_input", f"{field} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise LoopError("invalid_input", f"{field} contains duplicates")
    return copy.deepcopy(value)


def _task_index(board: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tasks = board.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise LoopError("board_invalid", "tasks must be a non-empty list")
    index: dict[str, dict[str, Any]] = {}
    for position, task in enumerate(tasks):
        if not isinstance(task, dict):
            raise LoopError("board_invalid", f"tasks[{position}] must be a mapping")
        task_id = _require_string(task.get("id"), f"tasks[{position}].id")
        if task_id in index:
            raise LoopError("board_invalid", f"duplicate task {task_id}")
        index[task_id] = task
    return index


def inspect_goalbuddy(
    goal_path: Path,
    board_path: Path,
    *,
    accepted_dependency_decisions: set[str] | None = None,
) -> dict[str, Any]:
    """Validate locked plan plus immutable GoalBuddy board truth."""

    try:
        goal_text = goal_path.read_text(encoding="utf-8")
        board_text = board_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LoopError("source_unreadable", str(exc)) from exc
    if not goal_text.strip():
        raise LoopError("locked_plan_invalid", "goal is empty")
    board = parse_goalbuddy_yaml(board_text)
    if board.get("version") != 2:
        raise LoopError("board_invalid", "version must equal 2")
    goal = _require_mapping(board.get("goal"), "goal")
    goal_slug = _require_string(goal.get("slug"), "goal.slug")
    if goal.get("status") != "active":
        raise LoopError("board_not_active", str(goal.get("status")))
    rules = _require_mapping(board.get("rules"), "rules")
    for rule in ("pm_owns_state", "one_active_task", "parent_codex_final_acceptance"):
        if rules.get(rule) is not True:
            raise LoopError("board_rule_invalid", f"{rule} must be true")
    configured_max_write_workers = rules.get("max_write_workers")
    if type(configured_max_write_workers) is not int or configured_max_write_workers < 1:
        raise LoopError("board_rule_invalid", "max_write_workers must be a positive integer")
    active_task_id = _require_string(board.get("active_task"), "active_task")
    tasks = _task_index(board)
    if active_task_id not in tasks:
        raise LoopError("active_task_missing", active_task_id)
    active = [task_id for task_id, task in tasks.items() if task.get("status") == "active"]
    if active != [active_task_id]:
        raise LoopError("one_active_task_violation", f"declared={active_task_id}; active={active}")
    active_task = tasks[active_task_id]
    dependencies = active_task.get("dependencies", [])
    if dependencies is None:
        dependencies = []
    dependencies = _require_string_list(dependencies, f"tasks.{active_task_id}.dependencies")
    dependency_receipts: list[dict[str, Any]] = []
    for dependency_id in dependencies:
        dependency = tasks.get(dependency_id)
        if dependency is None:
            raise LoopError("dependency_missing", dependency_id)
        if dependency.get("status") != "done":
            raise LoopError("dependency_not_done", dependency_id)
        receipt = dependency.get("receipt")
        if not isinstance(receipt, dict):
            raise LoopError("dependency_acceptance_missing", dependency_id)
        accepted_decisions = accepted_dependency_decisions or {"accept", "accepted"}
        if receipt.get("decision") not in accepted_decisions or receipt.get("accepted_by") != "Parent Codex":
            raise LoopError("dependency_not_parent_accepted", dependency_id)
        dependency_receipts.append(
            {
                "task_id": dependency_id,
                "decision": "accept",
                "accepted_by": "Parent Codex",
            }
        )
    allowed_files = _require_string_list(active_task.get("allowed_files"), f"tasks.{active_task_id}.allowed_files")
    verify = _require_string_list(active_task.get("verify"), f"tasks.{active_task_id}.verify")
    stop_if = _require_string_list(active_task.get("stop_if"), f"tasks.{active_task_id}.stop_if")
    return {
        "schema_version": SCHEMA_VERSION,
        "board_truth_owner": "GoalBuddy",
        "board_disposition": "reuse_existing_locked_board",
        "goal_slug": goal_slug,
        "goal_status": "active",
        "active_task": active_task_id,
        "active_task_status": "active",
        "active_task_objective": _require_string(active_task.get("objective"), "active_task.objective"),
        "dependencies": dependency_receipts,
        "allowed_files": allowed_files,
        "verify": verify,
        "stop_if": stop_if,
        "goal_sha256": _sha256_bytes(goal_text.encode("utf-8")),
        "board_sha256": _sha256_bytes(board_text.encode("utf-8")),
        "one_active_task": True,
        "parent_acceptance_authority": "Parent Codex",
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "configured_max_write_workers": configured_max_write_workers,
        "max_write_workers": min(configured_max_write_workers, ABSOLUTE_MAX_WRITE_WORKERS),
    }


def _normalize_relative_path(value: Any, field: str) -> str:
    text = _require_string(value, field).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("./"):
        raise LoopError("unsafe_path", f"{field}:{text}")
    return path.as_posix()


def _scope_is_allowed(scope: str, allowed_files: list[str]) -> bool:
    if scope in allowed_files:
        return True
    if any(marker in scope for marker in "*?["):
        return False
    path = PurePosixPath(scope)
    return any(path.match(pattern) for pattern in allowed_files)


def _artifact_descriptor(root: Path, value: Any, field: str) -> dict[str, Any]:
    relative = _normalize_relative_path(value, field)
    candidate = root / relative
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        stat = resolved.stat()
    except OSError as exc:
        raise LoopError("artifact_unavailable", f"{relative}:{exc}") from exc
    if resolved_root not in resolved.parents and resolved != resolved_root:
        raise LoopError("unsafe_path", relative)
    cursor = candidate
    symlink_found = False
    while cursor != root and cursor != cursor.parent:
        if cursor.is_symlink():
            symlink_found = True
            break
        cursor = cursor.parent
    if symlink_found or not resolved.is_file() or stat.st_nlink != 1:
        raise LoopError("artifact_invalid", relative)
    return {
        "path": relative,
        "sha256": _sha256_file(resolved),
        "size_bytes": stat.st_size,
        "link_count": stat.st_nlink,
    }


def _require_board_artifact_scope(descriptor: dict[str, Any], board_receipt: dict[str, Any]) -> None:
    if not _scope_is_allowed(descriptor["path"], board_receipt["allowed_files"]):
        raise LoopError("artifact_outside_board_scope", descriptor["path"])


def _lane_history(lanes: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return every consumed assignment ID and reserved artifact path."""

    assignment_ids: set[str] = set()
    artifact_paths: set[str] = set()
    for lane in lanes.values():
        assignment_id = lane.get("assignment_id")
        if isinstance(assignment_id, str):
            if assignment_id in assignment_ids:
                raise LoopError("assignment_history_not_unique", assignment_id)
            assignment_ids.add(assignment_id)
        expected = lane.get("expected_artifact")
        if isinstance(expected, str):
            artifact_paths.add(expected)
        for descriptor in lane.get("artifacts", []):
            if isinstance(descriptor, dict) and isinstance(descriptor.get("path"), str):
                artifact_paths.add(descriptor["path"])
        for predecessor in lane.get("preserved_predecessors", []):
            if not isinstance(predecessor, dict):
                continue
            predecessor_id = predecessor.get("assignment_id")
            if isinstance(predecessor_id, str):
                if predecessor_id in assignment_ids:
                    raise LoopError("assignment_history_not_unique", predecessor_id)
                assignment_ids.add(predecessor_id)
            predecessor_expected = predecessor.get("expected_artifact")
            if isinstance(predecessor_expected, str):
                artifact_paths.add(predecessor_expected)
            for descriptor in predecessor.get("artifacts", []):
                if isinstance(descriptor, dict) and isinstance(descriptor.get("path"), str):
                    artifact_paths.add(descriptor["path"])
    return assignment_ids, artifact_paths


def _verify_descriptor_unchanged(root: Path, expected: Any, field: str) -> None:
    expected = _require_mapping(expected, field)
    expected_path = _normalize_relative_path(expected.get("path"), f"{field}.path")
    try:
        actual = _artifact_descriptor(root, expected_path, field)
    except LoopError as exc:
        raise LoopError("preserved_artifact_integrity_failed", f"{expected_path}:{exc.code}") from exc
    identity_fields = ("path", "sha256", "size_bytes", "link_count")
    if any(actual.get(key) != expected.get(key) for key in identity_fields):
        raise LoopError("preserved_artifact_integrity_failed", expected_path)


def _verify_preserved_artifacts(root: Path, lanes: dict[str, Any]) -> None:
    """Rehash every historical artifact and reject replacement or aliasing."""

    for lane_id, lane in lanes.items():
        for predecessor_index, predecessor in enumerate(lane.get("preserved_predecessors", [])):
            predecessor = _require_mapping(
                predecessor, f"lanes.{lane_id}.preserved_predecessors[{predecessor_index}]"
            )
            for artifact_index, descriptor in enumerate(predecessor.get("artifacts", [])):
                _verify_descriptor_unchanged(
                    root,
                    descriptor,
                    f"lanes.{lane_id}.preserved_predecessors[{predecessor_index}].artifacts[{artifact_index}]",
                )


def _reject_transcript_or_acceptance(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in FORBIDDEN_TRANSCRIPT_KEYS:
                raise LoopError("transcript_reconstruction_forbidden", f"{path}.{key}")
            allowed_nonclaim = item is False or item is None or item in ("unknown", "not_claimed")
            if lowered in PARENT_ONLY_KEYS and not allowed_nonclaim:
                raise LoopError("parent_acceptance_only", f"{path}.{key}")
            _reject_transcript_or_acceptance(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_transcript_or_acceptance(item, f"{path}[{index}]")


def _validate_assignment(
    assignment: Any,
    board_receipt: dict[str, Any],
    existing_lanes: dict[str, Any],
) -> dict[str, Any]:
    assignment = copy.deepcopy(_require_mapping(assignment, "assignment"))
    required = {
        "schema_version",
        "assignment_id",
        "lane_id",
        "task_id",
        "role",
        "lane_mode",
        "objective",
        "dependencies",
        "read_scope",
        "write_scope",
        "forbidden_actions",
        "route_profile",
        "expected_artifact",
        "self_test",
        "independent_test_required",
        "retry_cap",
    }
    missing = sorted(required - set(assignment))
    if missing:
        raise LoopError("assignment_invalid", f"missing:{missing[0]}")
    if assignment["schema_version"] != 1:
        raise LoopError("assignment_invalid", "schema_version")
    for field in ("assignment_id", "lane_id", "task_id", "role", "lane_mode", "objective", "route_profile"):
        assignment[field] = _require_string(assignment[field], f"assignment.{field}")
    if assignment["task_id"] != board_receipt["active_task"]:
        raise LoopError("assignment_task_mismatch", assignment["task_id"])
    if assignment["role"] not in {"worker", "tester", "documenter", "auditor", "repair_worker"}:
        raise LoopError("assignment_invalid", "role")
    if assignment["lane_mode"] not in {"write_worker", "artifact_only", "read_only"}:
        raise LoopError("assignment_invalid", "lane_mode")
    for field in ("dependencies", "read_scope", "write_scope", "forbidden_actions", "self_test"):
        assignment[field] = _require_string_list(assignment[field], f"assignment.{field}")
    assignment["expected_artifact"] = _normalize_relative_path(
        assignment["expected_artifact"], "assignment.expected_artifact"
    )
    if not _scope_is_allowed(assignment["expected_artifact"], board_receipt["allowed_files"]):
        raise LoopError("assignment_scope_outside_board", assignment["expected_artifact"])
    if assignment["independent_test_required"] is not True:
        raise LoopError("assignment_invalid", "independent_test_required must be true")
    if type(assignment["retry_cap"]) is not int or not 0 <= assignment["retry_cap"] <= 3:
        raise LoopError("assignment_invalid", "retry_cap must be between zero and three")
    for action in ("accept_checkpoint", "accept_goal", "mutate_goalbuddy", "create_desktop_chat"):
        if action not in assignment["forbidden_actions"]:
            raise LoopError("assignment_authority_incomplete", action)
    for scope in assignment["read_scope"] + assignment["write_scope"]:
        normalized = _normalize_relative_path(scope, "assignment.scope")
        if not _scope_is_allowed(normalized, board_receipt["allowed_files"]):
            raise LoopError("assignment_scope_outside_board", normalized)
    if assignment["lane_mode"] == "read_only" and assignment["write_scope"]:
        raise LoopError("assignment_invalid", "read_only lane has write scope")
    if assignment["lane_mode"] == "write_worker":
        if not any(
            _scope_is_allowed(assignment["expected_artifact"], [scope])
            for scope in assignment["write_scope"]
        ):
            raise LoopError("assignment_artifact_outside_write_scope", assignment["expected_artifact"])
        active_writers: list[dict[str, Any]] = []
        for lane in existing_lanes.values():
            if lane.get("lane_id") == assignment["lane_id"]:
                continue
            if lane.get("lane_mode") == "write_worker" and lane.get("status") not in {
                "candidate_complete", "needs_reassignment", "waiting_external"
            }:
                active_writers.append(lane)
        max_write_workers = board_receipt.get("max_write_workers", 1)
        if len(active_writers) >= max_write_workers:
            code = "one_write_worker_violation" if max_write_workers == 1 else "max_write_workers_exceeded"
            raise LoopError(code, str(max_write_workers))
        for lane in active_writers:
            if _write_scopes_overlap(assignment["write_scope"], lane.get("write_scope", [])):
                raise LoopError("write_scope_overlap", lane["lane_id"])
    for dependency in assignment["dependencies"]:
        lane = existing_lanes.get(dependency)
        if lane is None or lane.get("phase") not in {"audited", "candidate_complete"}:
            raise LoopError("assignment_dependency_not_complete", dependency)
    return assignment


def _scope_static_prefix(scope: str) -> tuple[str, ...]:
    parts: list[str] = []
    for part in PurePosixPath(scope).parts:
        if any(marker in part for marker in "*?["):
            break
        parts.append(part)
    return tuple(parts)


def _write_scopes_overlap(left: list[str], right: list[str]) -> bool:
    """Conservatively detect overlap without treating disjoint prefixes as aliases."""

    for left_scope in left:
        for right_scope in right:
            if left_scope == right_scope:
                return True
            left_prefix = _scope_static_prefix(left_scope)
            right_prefix = _scope_static_prefix(right_scope)
            common = min(len(left_prefix), len(right_prefix))
            if left_prefix[:common] != right_prefix[:common]:
                continue
            if common == 0:
                return True
            left_has_glob = len(left_prefix) != len(PurePosixPath(left_scope).parts)
            right_has_glob = len(right_prefix) != len(PurePosixPath(right_scope).parts)
            if left_has_glob or right_has_glob or len(left_prefix) == len(right_prefix):
                return True
    return False


def _route_receipt(
    route_packet: Any,
    assignment: dict[str, Any],
    expected_profile: str | None = None,
    *,
    role_artifact: str | None = None,
) -> dict[str, Any]:
    packet = copy.deepcopy(_require_mapping(route_packet, "route_packet"))
    if packet.get("task_id") != assignment["task_id"]:
        raise LoopError("route_task_mismatch", str(packet.get("task_id")))
    profile = expected_profile or assignment["route_profile"]
    compatible_profiles = {
        "independent_test": {"independent_test", "semantic_independent_artifact"},
        "embedded_audit": {"embedded_audit", "semantic_embedded_audit"},
    }.get(profile, {profile})
    if packet.get("profile") not in compatible_profiles:
        raise LoopError("route_profile_mismatch", str(packet.get("profile")))
    semantic_artifact_profile = packet.get("profile") in {
        "semantic_independent_artifact", "semantic_embedded_audit",
    }
    if semantic_artifact_profile:
        if role_artifact is None:
            raise LoopError("route_scope_mismatch", "role_artifact")
        if not set(packet.get("read_scope", [])).issubset(set(assignment["read_scope"])):
            raise LoopError("route_scope_mismatch", "read_scope")
        if packet.get("write_scope") != [role_artifact]:
            raise LoopError("route_scope_mismatch", "role_artifact_write_scope")
    else:
        if sorted(packet.get("read_scope", [])) != sorted(assignment["read_scope"]):
            raise LoopError("route_scope_mismatch", "read_scope")
        if sorted(packet.get("write_scope", [])) != sorted(assignment["write_scope"]):
            raise LoopError("route_scope_mismatch", "write_scope")
    try:
        receipt = _route_runtime.resolve_worker_route(packet)
    except _route_runtime.ResolutionError as exc:
        raise LoopError("route_resolution_failed", f"{exc.code}:{exc.detail}") from exc
    if receipt.get("status") != "selected" or not receipt.get("selected_route"):
        raise LoopError("route_not_selected", str(receipt.get("status")))
    if receipt.get("external_call_performed") is not False:
        raise LoopError("deterministic_route_boundary_violated", "external_call_performed")
    return receipt


def _command_rows(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise LoopError("validation_invalid", f"{field} must be a non-empty list")
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        row = copy.deepcopy(_require_mapping(row, f"{field}[{index}]"))
        _require_string(row.get("command"), f"{field}[{index}].command")
        if row.get("execution_status") not in {"completed", "failed", "not_run", "not_applicable"}:
            raise LoopError("validation_invalid", f"{field}[{index}].execution_status")
        if row.get("result") not in {"pass", "fail", "not_run", "not_applicable"}:
            raise LoopError("validation_invalid", f"{field}[{index}].result")
        if row["result"] == "pass" and row["execution_status"] != "completed":
            raise LoopError("validation_invalid", f"{field}[{index}]: pass without completed")
        rows.append(row)
    return rows


def _all_commands_pass(rows: list[dict[str, Any]]) -> bool:
    return all(row["execution_status"] == "completed" and row["result"] == "pass" for row in rows)


def _infer_lane_phase(lane: dict[str, Any], legacy_phase: str | None, *, active: bool) -> str:
    if active and isinstance(legacy_phase, str):
        return legacy_phase
    if lane.get("status") == "candidate_complete":
        return "candidate_complete"
    if lane.get("audit_status") == "pass":
        return "audited"
    if lane.get("independent_test_status") == "pass":
        return "independently_tested"
    if lane.get("self_test_status") == "pass":
        return "self_tested"
    if lane.get("artifacts"):
        return "repair_result_received" if lane.get("work_kind") == "repair" else "result_received"
    if lane.get("route_receipts"):
        return "repair_routed" if lane.get("work_kind") == "repair" else "routed"
    return "repair_assigned" if lane.get("work_kind") == "repair" else "assigned"


def _aggregate_projection(state: dict[str, Any]) -> None:
    lanes = state.get("lanes", {})
    if state.get("status") == "candidate_complete":
        state["aggregate_phase"] = "candidate_complete"
        state["aggregate_status"] = "candidate_complete"
        return
    phases = [lane.get("phase") for lane in lanes.values()]
    if not phases:
        aggregate_phase = "initialized"
    elif any(phase == "repair_required" for phase in phases):
        aggregate_phase = "repair_required"
    elif all(phase == "audited" for phase in phases):
        aggregate_phase = "ready_for_closeout"
    else:
        aggregate_phase = "in_progress"
    state["aggregate_phase"] = aggregate_phase
    state["aggregate_status"] = "in_progress"


def migrate_runtime_state(state_value: Any) -> dict[str, Any]:
    """Deterministically upgrade a schema-v1 projection without touching its log."""

    state = copy.deepcopy(_require_mapping(state_value, "state"))
    version = state.get("schema_version")
    if version == RUNTIME_SCHEMA_VERSION:
        _aggregate_projection(state)
        return state
    if version != 1:
        raise LoopError("state_invalid", "schema_version")
    lanes = _require_mapping(state.get("lanes"), "state.lanes")
    active_lane_id = state.get("active_lane_id")
    legacy_phase = state.get("phase")
    legacy_repairs = state.get("repair_cycles", 0)
    for lane_id, lane_value in list(lanes.items()):
        lane = _require_mapping(lane_value, f"state.lanes.{lane_id}")
        lane["phase"] = _infer_lane_phase(lane, legacy_phase, active=lane_id == active_lane_id)
        lane["repair_cycles"] = legacy_repairs if lane_id == active_lane_id else 0
        if lane["phase"] in {"audited", "candidate_complete"} and lane.get("documentation_status") is None:
            lane["documentation_status"] = "pass"
        lanes[lane_id] = lane
    state["lanes"] = lanes
    state["schema_version"] = RUNTIME_SCHEMA_VERSION
    _aggregate_projection(state)
    return state


def initial_runtime_state(board_receipt: dict[str, Any], goal_path: str, board_path: str) -> dict[str, Any]:
    state = {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "goal_slug": board_receipt["goal_slug"],
        "checkpoint_id": board_receipt["active_task"],
        "status": "in_progress",
        "phase": "initialized",
        "aggregate_phase": "initialized",
        "aggregate_status": "in_progress",
        "goal_path": goal_path,
        "board_path": board_path,
        "goal_sha256": board_receipt["goal_sha256"],
        "board_sha256": board_receipt["board_sha256"],
        "board_truth_owner": "GoalBuddy",
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "parent_acceptance_authority": "Parent Codex",
        "acceptance_claimed": False,
        "lanes": {},
        "active_lane_id": None,
        "repair_cycles": 0,
        "candidate_closeout": None,
        "event_sequence": 0,
        "last_event_hash": ZERO_HASH,
        "last_event_id": None,
    }
    return state


def _event_input(value: Any) -> dict[str, Any]:
    event = copy.deepcopy(_require_mapping(value, "event"))
    required = {"schema_version", "event_id", "timestamp", "event_type", "lane_id", "payload"}
    missing = sorted(required - set(event))
    if missing:
        raise LoopError("event_invalid", f"missing:{missing[0]}")
    if event["schema_version"] != 1:
        raise LoopError("event_invalid", "schema_version")
    for field in ("event_id", "timestamp", "event_type", "lane_id"):
        event[field] = _require_string(event[field], f"event.{field}")
    if event["event_type"] in FORBIDDEN_EVENT_TYPES:
        raise LoopError("parent_acceptance_only", event["event_type"])
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", event["timestamp"]):
        raise LoopError("event_invalid", "timestamp must be deterministic ISO-8601 UTC seconds")
    event["payload"] = _require_mapping(event["payload"], "event.payload")
    _reject_transcript_or_acceptance(event["payload"])
    return event


def transition_runtime(
    state_value: Any,
    board_receipt: dict[str, Any],
    event_value: Any,
    repository_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply one validated lifecycle event without writing files."""

    state = migrate_runtime_state(state_value)
    event = _event_input(event_value)
    if state.get("schema_version") != RUNTIME_SCHEMA_VERSION:
        raise LoopError("state_invalid", "schema_version")
    if state.get("board_sha256") != board_receipt["board_sha256"]:
        raise LoopError("board_changed_requires_reconcile", board_receipt["board_sha256"])
    if state.get("goal_sha256") != board_receipt["goal_sha256"]:
        raise LoopError("locked_plan_changed", board_receipt["goal_sha256"])
    if state.get("checkpoint_id") != board_receipt["active_task"]:
        raise LoopError("active_task_changed", board_receipt["active_task"])
    if state.get("board_mutated") is not False:
        raise LoopError("runtime_state_claims_goalbuddy_board_mutation", "runtime state")
    if state.get("transcript_used") is not False:
        raise LoopError("runtime_state_claims_transcript_reconstruction", "runtime state")
    if state.get("native_side_proof") is not False:
        raise LoopError("runtime_state_claims_native_side_proof", "runtime state")
    if state.get("acceptance_claimed") is not False or state.get("parent_acceptance_authority") != "Parent Codex":
        raise LoopError("parent_acceptance_only", "runtime state")
    if state.get("status") == "candidate_complete":
        raise LoopError("candidate_already_closed", state["checkpoint_id"])
    lanes = _require_mapping(state.get("lanes"), "state.lanes")
    _lane_history(lanes)
    event_type = event["event_type"]
    lane_id = event["lane_id"]
    payload = event["payload"]
    enriched: dict[str, Any] = copy.deepcopy(payload)

    if event_type == "assignment_created":
        assignment = _validate_assignment(payload.get("assignment"), board_receipt, lanes)
        consumed_assignment_ids, reserved_artifact_paths = _lane_history(lanes)
        if assignment["assignment_id"] in consumed_assignment_ids:
            raise LoopError("assignment_id_reused", assignment["assignment_id"])
        if assignment["lane_id"] != lane_id:
            raise LoopError("event_lane_mismatch", lane_id)
        prior = lanes.get(lane_id)
        prior_phase = prior.get("phase") if isinstance(prior, dict) else None
        if prior is not None and prior_phase != "repair_required":
            raise LoopError("lane_already_exists", lane_id)
        if prior_phase == "repair_required":
            _verify_preserved_artifacts(repository_root, lanes)
            for artifact_index, descriptor in enumerate(prior.get("artifacts", [])):
                _verify_descriptor_unchanged(
                    repository_root,
                    descriptor,
                    f"lanes.{lane_id}.artifacts[{artifact_index}]",
                )
            prior_repair_cycles = prior.get("repair_cycles", 0)
            if prior_repair_cycles >= prior["retry_cap"]:
                raise LoopError("repair_budget_exhausted", lane_id)
            if assignment["expected_artifact"] in reserved_artifact_paths:
                raise LoopError("repair_artifact_path_reused", assignment["expected_artifact"])
            repair_cycles = prior_repair_cycles + 1
            work_kind = "repair"
            preserved_predecessors = copy.deepcopy(prior.get("preserved_predecessors", []))
            preserved_predecessors.append(
                {
                    "assignment_id": prior["assignment_id"],
                    "expected_artifact": prior["expected_artifact"],
                    "artifacts": copy.deepcopy(prior["artifacts"]),
                    "failed_evidence": copy.deepcopy(prior["failed_evidence"]),
                    "route_receipts": copy.deepcopy(prior["route_receipts"]),
                    "terminal_for_replacement": True,
                }
            )
        else:
            work_kind = "initial"
            preserved_predecessors = []
            repair_cycles = 0
        lanes[lane_id] = {
            "lane_id": lane_id,
            "assignment_id": assignment["assignment_id"],
            "task_id": assignment["task_id"],
            "role": assignment["role"],
            "lane_mode": assignment["lane_mode"],
            "objective": assignment["objective"],
            "route_profile": assignment["route_profile"],
            "read_scope": assignment["read_scope"],
            "write_scope": assignment["write_scope"],
            "expected_artifact": assignment["expected_artifact"],
            "self_test": assignment["self_test"],
            "retry_cap": assignment["retry_cap"],
            "status": "assigned",
            "phase": "repair_assigned" if work_kind == "repair" else "assigned",
            "repair_cycles": repair_cycles,
            "work_kind": work_kind,
            "route_receipts": [],
            "artifacts": [],
            "failed_evidence": [],
            "preserved_predecessors": preserved_predecessors,
        }
        state["active_lane_id"] = lane_id
        state["phase"] = lanes[lane_id]["phase"]
    else:
        lane = lanes.get(lane_id)
        if lane is None:
            raise LoopError("lane_missing", lane_id)
        phase = lane.get("phase")
        state["active_lane_id"] = lane_id
        if lane.get("work_kind") == "repair":
            _verify_preserved_artifacts(repository_root, lanes)

        if event_type == "route_resolved":
            if phase not in {"assigned", "repair_assigned"}:
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            receipt = _route_receipt(payload.get("route_packet"), lane)
            lane["route_receipts"].append(receipt)
            lane["selected_route"] = receipt["selected_route"]
            lane["route_identity"] = receipt["actual_route"]
            lane["status"] = "in_progress"
            lane["phase"] = "repair_routed" if phase == "repair_assigned" else "routed"
            state["phase"] = lane["phase"]
            enriched["route_receipt"] = receipt
        elif event_type in {"worker_result", "repair_result"}:
            expected_phase = "routed" if event_type == "worker_result" else "repair_routed"
            if phase != expected_phase:
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            status = payload.get("status")
            if status not in CANONICAL_LANE_STATUSES - {"candidate_complete"}:
                raise LoopError("result_invalid", "status")
            artifact = _artifact_descriptor(repository_root, payload.get("artifact"), "result.artifact")
            _require_board_artifact_scope(artifact, board_receipt)
            if artifact["path"] != lane["expected_artifact"]:
                raise LoopError("result_artifact_mismatch", artifact["path"])
            changed_files = _require_string_list(payload.get("changed_files"), "result.changed_files")
            _, reserved_artifact_paths = _lane_history(
                {"history": {"preserved_predecessors": lane.get("preserved_predecessors", [])}}
            )
            for changed in changed_files:
                normalized = _normalize_relative_path(changed, "result.changed_files")
                if event_type == "repair_result" and normalized in reserved_artifact_paths:
                    raise LoopError("repair_changed_file_reserved", normalized)
                if not any(_scope_is_allowed(normalized, [scope]) for scope in lane["write_scope"]):
                    raise LoopError("result_write_outside_assignment", normalized)
            receipt = _require_mapping(payload.get("input_access_receipt"), "result.input_access_receipt")
            if receipt.get("compatibility_gate_decision") not in {"compatible", "not_required"}:
                raise LoopError("input_receipt_incompatible", str(receipt.get("compatibility_gate_decision")))
            lane["artifacts"].append(artifact)
            lane["current_work_artifact"] = artifact["path"]
            lane["status"] = status
            lane["phase"] = "repair_result_received" if event_type == "repair_result" else "result_received"
            state["phase"] = lane["phase"]
            enriched["artifact_descriptor"] = artifact
        elif event_type == "worker_self_test":
            if phase not in {"result_received", "repair_result_received"}:
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            rows = _command_rows(payload.get("commands"), "self_test.commands")
            enriched["commands"] = rows
            if _all_commands_pass(rows):
                lane["phase"] = "self_tested"
                lane["self_test_status"] = "pass"
            else:
                lane["phase"] = "repair_required"
                lane["self_test_status"] = "fail"
                lane["failed_evidence"].append(copy.deepcopy(enriched))
            state["phase"] = lane["phase"]
        elif event_type == "independent_test":
            if phase != "self_tested":
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            artifact = _artifact_descriptor(repository_root, payload.get("artifact"), "independent_test.artifact")
            _require_board_artifact_scope(artifact, board_receipt)
            receipt = _route_receipt(
                payload.get("route_packet"), lane,
                expected_profile="independent_test", role_artifact=artifact["path"],
            )
            packet_profile = payload.get("route_packet", {}).get("profile")
            trusted_commands = None
            if packet_profile == "semantic_independent_artifact":
                trusted_commands = _command_rows(
                    payload.get("trusted_commands"),
                    "independent_test.trusted_commands",
                )
            builder_group = lane["route_identity"]["independence_group"]
            packet = payload["route_packet"]
            if packet.get("independence_required") is not True or builder_group not in packet.get("independence_exclusions", []):
                raise LoopError("independent_test_not_independent", builder_group)
            result = payload.get("result")
            if result not in {"pass", "fail"}:
                raise LoopError("independent_test_invalid", str(result))
            if result == "pass" and trusted_commands is not None and not _all_commands_pass(trusted_commands):
                raise LoopError("independent_test_untrusted_pass", "trusted commands did not all pass")
            lane["independent_test_route"] = receipt
            lane["independent_test_artifact"] = artifact["path"]
            lane["artifacts"].append(artifact)
            enriched["route_receipt"] = receipt
            enriched["artifact_descriptor"] = artifact
            if trusted_commands is not None:
                enriched["trusted_commands"] = trusted_commands
            if result == "pass":
                lane["independent_test_status"] = "pass"
                lane["phase"] = "independently_tested"
            else:
                lane["independent_test_status"] = "fail"
                lane["failed_evidence"].append(copy.deepcopy(enriched))
                lane["phase"] = "repair_required"
            state["phase"] = lane["phase"]
        elif event_type == "documentation_result":
            if phase != "independently_tested":
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            artifact = _artifact_descriptor(repository_root, payload.get("artifact"), "documentation.artifact")
            _require_board_artifact_scope(artifact, board_receipt)
            sources = _require_string_list(payload.get("derived_from"), "documentation.derived_from")
            known = {item["path"] for item in lane["artifacts"]}
            if not set(sources).issubset(known):
                raise LoopError("documentation_source_unknown", sorted(set(sources) - known)[0])
            required_sources = {
                lane["current_work_artifact"],
                lane["independent_test_artifact"],
            }
            if not required_sources.issubset(sources):
                raise LoopError("documentation_required_source_missing", sorted(required_sources - set(sources))[0])
            semantic_changes = payload.get("semantic_changes")
            if semantic_changes != "none" and semantic_changes != []:
                raise LoopError("documentation_semantic_change", str(payload.get("semantic_changes")))
            lane["artifacts"].append(artifact)
            lane["documentation_status"] = "pass"
            lane["documentation_artifact"] = artifact["path"]
            lane["phase"] = "documented"
            state["phase"] = lane["phase"]
            enriched["artifact_descriptor"] = artifact
        elif event_type == "audit_result":
            if phase != "documented":
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            artifact = _artifact_descriptor(repository_root, payload.get("artifact"), "audit.artifact")
            _require_board_artifact_scope(artifact, board_receipt)
            receipt = _route_receipt(
                payload.get("route_packet"), lane,
                expected_profile="embedded_audit", role_artifact=artifact["path"],
            )
            result = payload.get("result")
            if result not in {"pass", "fail"}:
                raise LoopError("audit_invalid", str(result))
            builder_group = lane["route_identity"]["independence_group"]
            audit_packet = payload["route_packet"]
            if audit_packet.get("independence_required") is not True or builder_group not in audit_packet.get(
                "independence_exclusions", []
            ):
                raise LoopError("audit_not_independent", builder_group)
            lane["audit_route"] = receipt
            lane["artifacts"].append(artifact)
            enriched["route_receipt"] = receipt
            enriched["artifact_descriptor"] = artifact
            if result == "pass":
                lane["audit_status"] = "pass"
                lane["phase"] = "audited"
            else:
                lane["audit_status"] = "fail"
                lane["failed_evidence"].append(copy.deepcopy(enriched))
                lane["phase"] = "repair_required"
            state["phase"] = lane["phase"]
        elif event_type == "candidate_closeout":
            if phase != "audited":
                raise LoopError("lifecycle_violation", f"{phase}->{event_type}")
            unready = sorted(
                other_lane_id
                for other_lane_id, other_lane in lanes.items()
                if other_lane.get("phase") != "audited"
                or other_lane.get("self_test_status") != "pass"
                or other_lane.get("independent_test_status") != "pass"
                or other_lane.get("documentation_status") != "pass"
                or other_lane.get("audit_status") != "pass"
            )
            if unready:
                raise LoopError("aggregate_closeout_not_ready", unready[0])
            if payload.get("status") != "candidate_complete":
                raise LoopError("closeout_invalid", "status")
            if payload.get("acceptance_claimed") is not False:
                raise LoopError("parent_acceptance_only", "candidate acceptance_claimed")
            if payload.get("requested_parent_decision") not in {"accept", "repair_directly", "issue_revision_packet"}:
                raise LoopError("closeout_invalid", "requested_parent_decision")
            artifact = _artifact_descriptor(repository_root, payload.get("artifact"), "closeout.artifact")
            _require_board_artifact_scope(artifact, board_receipt)
            state["candidate_closeout"] = artifact
            state["status"] = "candidate_complete"
            state["phase"] = "candidate_complete"
            for completed_lane in lanes.values():
                completed_lane["status"] = "candidate_complete"
                completed_lane["phase"] = "candidate_complete"
            lane["artifacts"].append(artifact)
            enriched["artifact_descriptor"] = artifact
            enriched["board_delta"] = {
                "task_id": state["checkpoint_id"],
                "proposed_status": "candidate_complete",
                "requested_parent_decision": payload["requested_parent_decision"],
                "applied_to_goalbuddy": False,
                "acceptance_authority": "Parent Codex",
            }
        else:
            raise LoopError("event_type_unsupported", event_type)

    state["lanes"] = lanes
    state["board_mutated"] = False
    state["transcript_used"] = False
    state["native_side_proof"] = False
    state["acceptance_claimed"] = False
    state["repair_cycles"] = sum(
        lane.get("repair_cycles", 0) for lane in lanes.values() if isinstance(lane, dict)
    )
    _aggregate_projection(state)
    return state, enriched


def _event_record(state: dict[str, Any], event: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    sequence = state["event_sequence"] + 1
    record = {
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "lane_id": event["lane_id"],
        "event_type": event["event_type"],
        "previous_event_hash": state["last_event_hash"],
        "board_sha256": state["board_sha256"],
        "payload": payload,
        "proof_boundary": "local",
        "native_side_proof": False,
        "external_call_performed": False,
        "acceptance_claimed": False,
    }
    record["event_hash"] = _sha256_bytes(_canonical_json(record))
    return record


def _advance_event_cursor(state: dict[str, Any], record: dict[str, Any]) -> None:
    state["event_sequence"] = record["sequence"]
    state["last_event_hash"] = record["event_hash"]
    state["last_event_id"] = record["event_id"]


def verify_event_log(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LoopError("event_log_unreadable", str(exc)) from exc
    previous = ZERO_HASH
    event_ids: set[str] = set()
    last: dict[str, Any] | None = None
    for expected_sequence, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LoopError("event_log_invalid", f"line {expected_sequence}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise LoopError("event_log_invalid", f"line {expected_sequence}: not an object")
        recorded_hash = record.get("event_hash")
        candidate = copy.deepcopy(record)
        candidate.pop("event_hash", None)
        computed = _sha256_bytes(_canonical_json(candidate))
        if record.get("sequence") != expected_sequence:
            raise LoopError("event_log_sequence_mismatch", str(expected_sequence))
        if record.get("previous_event_hash") != previous:
            raise LoopError("event_log_chain_mismatch", str(expected_sequence))
        if recorded_hash != computed:
            raise LoopError("event_log_hash_mismatch", str(expected_sequence))
        event_id = record.get("event_id")
        if event_id in event_ids:
            raise LoopError("event_id_duplicate", str(event_id))
        event_ids.add(event_id)
        previous = recorded_hash
        last = record
    return {
        "event_count": len(lines),
        "last_event_hash": previous,
        "last_event_id": last.get("event_id") if last else None,
        "event_ids": event_ids,
    }


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _append_record(path: Path, record: dict[str, Any], *, create: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "x" if create else "a"
    with path.open(mode, encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def initialize_files(
    goal_path: Path,
    board_path: Path,
    state_path: Path,
    event_log_path: Path,
    event_id: str,
    timestamp: str,
) -> dict[str, Any]:
    if state_path.exists() or event_log_path.exists():
        raise LoopError("runtime_already_exists", f"{state_path} or {event_log_path}")
    board_receipt = inspect_goalbuddy(goal_path, board_path)
    state = initial_runtime_state(board_receipt, str(goal_path), str(board_path))
    event = _event_input(
        {
            "schema_version": 1,
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "loop_initialized",
            "lane_id": "supervisor",
            "payload": {
                "board_receipt": {
                    "board_truth_owner": board_receipt["board_truth_owner"],
                    "board_disposition": board_receipt["board_disposition"],
                    "goal_slug": board_receipt["goal_slug"],
                    "active_task": board_receipt["active_task"],
                    "goal_sha256": board_receipt["goal_sha256"],
                    "board_sha256": board_receipt["board_sha256"],
                    "board_mutated": False,
                    "transcript_used": False,
                    "native_side_proof": False,
                }
            },
        }
    )
    record = _event_record(state, event, event["payload"])
    _advance_event_cursor(state, record)
    _append_record(event_log_path, record, create=True)
    _atomic_write_json(state_path, state)
    return {"state": state, "delta": record}


def _load_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoopError("state_unreadable", str(exc)) from exc
    return _require_mapping(value, "state")


def supervisor_lock_path(state_path: Path) -> Path:
    """Return the shared lock used by every Supervisor state/event writer."""

    return state_path.resolve(strict=True).with_name(state_path.name + ".lock")


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/")
        and str(resolved) == "/private" + str(lexical)
    )


def open_supervisor_lock(state_path: Path, repository_root: Path | None):
    """Open one canonical runtime lock without following filesystem aliases."""

    try:
        root = repository_root.resolve(strict=True) if repository_root is not None else None
        lexical_state = Path(os.path.abspath(state_path))
        named_state = lexical_state.lstat()
        resolved_state = lexical_state.resolve(strict=True)
        if root is not None:
            resolved_state.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise LoopError("runtime_lock_path_invalid", str(state_path)) from exc
    if (
        not _same_canonical_path(lexical_state, resolved_state)
        or stat.S_ISLNK(named_state.st_mode)
        or not stat.S_ISREG(named_state.st_mode)
        or named_state.st_nlink != 1
    ):
        raise LoopError("runtime_lock_path_invalid", str(state_path))
    lock_path = resolved_state.with_name(resolved_state.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        opened = os.fstat(descriptor)
        named_lock = lock_path.lstat()
        resolved_lock = lock_path.resolve(strict=True)
        if root is not None:
            resolved_lock.relative_to(root)
        if (
            resolved_lock != lock_path
            or stat.S_ISLNK(named_lock.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named_lock.st_mode)
            or opened.st_nlink != 1
            or named_lock.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named_lock.st_dev, named_lock.st_ino)
        ):
            raise LoopError("runtime_lock_path_invalid", str(lock_path))
        return os.fdopen(descriptor, "r+b")
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _apply_event_files_unlocked(
    goal_path: Path,
    board_path: Path,
    state_path: Path,
    event_log_path: Path,
    event_path: Path,
    repository_root: Path,
    *,
    recovery_control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = migrate_runtime_state(_load_state(state_path))
    log = verify_event_log(event_log_path)
    if (
        state.get("event_sequence") != log["event_count"]
        or state.get("last_event_id") != log["last_event_id"]
        or state.get("last_event_hash") != log["last_event_hash"]
    ):
        raise LoopError("runtime_state_event_log_mismatch", str(state.get("event_sequence")))
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoopError("event_unreadable", str(exc)) from exc
    event = _event_input(event)
    board_receipt = inspect_goalbuddy(goal_path, board_path)
    recovery_runtime = None
    recovery_receipt = None
    if board_receipt["active_task"] == "T006":
        if not isinstance(recovery_control, dict):
            raise LoopError("recovery_control_required", event["event_id"])
        required = {
            "state_path", "events_path", "cursor_path",
            "sync_state_path", "sync_events_path", "sync_cursor_path",
            "transition_id", "supervisor_id", "supervisor_epoch",
        }
        if set(recovery_control) != required:
            raise LoopError("recovery_control_invalid", "fields")
        recovery_runtime = _load_recovery_runtime()
        try:
            recovery_runtime.reconcile_pending_loop_transition_files(
                goal_path,
                board_path,
                state_path,
                event_log_path,
                Path(recovery_control["sync_state_path"]),
                Path(recovery_control["sync_events_path"]),
                Path(recovery_control["sync_cursor_path"]),
                Path(recovery_control["state_path"]),
                Path(recovery_control["events_path"]),
                Path(recovery_control["cursor_path"]),
                repository_root,
            )
        except recovery_runtime.RecoveryError as exc:
            raise LoopError("recovery_control_rejected", f"{exc.code}:{exc.detail}") from exc
        state = _load_state(state_path)
        log = verify_event_log(event_log_path)
    if event["event_id"] in log["event_ids"]:
        raise LoopError("event_id_duplicate", event["event_id"])
    updated, payload = transition_runtime(state, board_receipt, event, repository_root)
    record = _event_record(state, event, payload)
    if recovery_runtime is not None:
        try:
            recovery_receipt = recovery_runtime.begin_loop_transition_files(
                goal_path,
                board_path,
                state_path,
                event_log_path,
                Path(recovery_control["sync_state_path"]),
                Path(recovery_control["sync_events_path"]),
                Path(recovery_control["sync_cursor_path"]),
                Path(recovery_control["state_path"]),
                Path(recovery_control["events_path"]),
                Path(recovery_control["cursor_path"]),
                repository_root,
                recovery_control["transition_id"],
                recovery_control["supervisor_id"],
                recovery_control["supervisor_epoch"],
                event,
                record,
            )
        except recovery_runtime.RecoveryError as exc:
            raise LoopError("recovery_control_rejected", f"{exc.code}:{exc.detail}") from exc
    _advance_event_cursor(updated, record)
    _append_record(event_log_path, record)
    _atomic_write_json(state_path, updated)
    if recovery_runtime is not None:
        try:
            recovery_receipt = recovery_runtime.complete_loop_transition_files(
                goal_path,
                board_path,
                state_path,
                event_log_path,
                Path(recovery_control["sync_state_path"]),
                Path(recovery_control["sync_events_path"]),
                Path(recovery_control["sync_cursor_path"]),
                Path(recovery_control["state_path"]),
                Path(recovery_control["events_path"]),
                Path(recovery_control["cursor_path"]),
                repository_root,
                recovery_control["transition_id"],
            )
        except recovery_runtime.RecoveryError as exc:
            raise LoopError("recovery_commit_pending", f"{exc.code}:{exc.detail}") from exc
    return {"state": updated, "delta": record, "recovery_receipt": recovery_receipt}


def apply_event_files(
    goal_path: Path,
    board_path: Path,
    state_path: Path,
    event_log_path: Path,
    event_path: Path,
    repository_root: Path,
    *,
    recovery_control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply one event while serializing every writer to the runtime pair."""

    with open_supervisor_lock(state_path, repository_root) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _apply_event_files_unlocked(
            goal_path,
            board_path,
            state_path,
            event_log_path,
            event_path,
            repository_root,
            recovery_control=recovery_control,
        )


def _snapshot_files_unlocked(
    goal_path: Path,
    board_path: Path,
    state_path: Path,
    event_log_path: Path,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    state = migrate_runtime_state(_load_state(state_path))
    log = verify_event_log(event_log_path)
    board = inspect_goalbuddy(goal_path, board_path)
    if state.get("event_sequence") != log["event_count"] or state.get("last_event_hash") != log["last_event_hash"]:
        raise LoopError("runtime_state_event_log_mismatch", str(state.get("event_sequence")))
    if state.get("board_sha256") != board["board_sha256"]:
        raise LoopError("board_changed_requires_reconcile", board["board_sha256"])
    if state.get("goal_sha256") != board["goal_sha256"]:
        raise LoopError("locked_plan_changed", board["goal_sha256"])
    if state.get("board_mutated") is not False:
        raise LoopError("runtime_state_claims_goalbuddy_board_mutation", "runtime state")
    if state.get("transcript_used") is not False:
        raise LoopError("runtime_state_claims_transcript_reconstruction", "runtime state")
    if state.get("native_side_proof") is not False:
        raise LoopError("runtime_state_claims_native_side_proof", "runtime state")
    if state.get("acceptance_claimed") is not False or state.get("parent_acceptance_authority") != "Parent Codex":
        raise LoopError("parent_acceptance_only", "runtime state")
    _verify_preserved_artifacts(repository_root or Path.cwd(), _require_mapping(state.get("lanes"), "state.lanes"))
    _lane_history(_require_mapping(state.get("lanes"), "state.lanes"))
    return {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "goal_slug": state["goal_slug"],
        "checkpoint_id": state["checkpoint_id"],
        "status": state["status"],
        "phase": state["phase"],
        "aggregate_phase": state["aggregate_phase"],
        "aggregate_status": state["aggregate_status"],
        "board_sha256_matches": True,
        "locked_plan_sha256_matches": True,
        "event_count": log["event_count"],
        "last_event_hash": log["last_event_hash"],
        "board_mutated": False,
        "transcript_used": False,
        "native_side_proof": False,
        "acceptance_claimed": False,
        "parent_acceptance_authority": "Parent Codex",
        "candidate_closeout": state.get("candidate_closeout"),
    }


def snapshot_files(
    goal_path: Path,
    board_path: Path,
    state_path: Path,
    event_log_path: Path,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    with open_supervisor_lock(state_path, repository_root) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        return _snapshot_files_unlocked(
            goal_path, board_path, state_path, event_log_path, repository_root,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    initialize_parser = subparsers.add_parser("initialize")
    apply_parser = subparsers.add_parser("apply")
    snapshot_parser = subparsers.add_parser("snapshot")
    for child in (inspect_parser, initialize_parser, apply_parser, snapshot_parser):
        child.add_argument("--goal", type=Path, required=True)
        child.add_argument("--board", type=Path, required=True)
    for child in (initialize_parser, apply_parser, snapshot_parser):
        child.add_argument("--state", type=Path, required=True)
        child.add_argument("--events", type=Path, required=True)
    initialize_parser.add_argument("--event-id", required=True)
    initialize_parser.add_argument("--timestamp", required=True)
    apply_parser.add_argument("--event", type=Path, required=True)
    apply_parser.add_argument("--recovery-state", type=Path)
    apply_parser.add_argument("--recovery-events", type=Path)
    apply_parser.add_argument("--recovery-cursor", type=Path)
    apply_parser.add_argument("--sync-state", type=Path)
    apply_parser.add_argument("--sync-events", type=Path)
    apply_parser.add_argument("--sync-cursor", type=Path)
    apply_parser.add_argument("--recovery-transition-id")
    apply_parser.add_argument("--supervisor-id")
    apply_parser.add_argument("--supervisor-epoch", type=int)
    for child in (apply_parser, snapshot_parser):
        child.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_goalbuddy(args.goal, args.board)
        elif args.command == "initialize":
            result = initialize_files(
                args.goal, args.board, args.state, args.events, args.event_id, args.timestamp
            )
        elif args.command == "apply":
            recovery_values = (
                args.recovery_state, args.recovery_events, args.recovery_cursor,
                args.sync_state, args.sync_events, args.sync_cursor,
                args.recovery_transition_id, args.supervisor_id, args.supervisor_epoch,
            )
            recovery_control = None
            if any(value is not None for value in recovery_values):
                if any(value is None for value in recovery_values):
                    raise LoopError("recovery_control_invalid", "incomplete CLI recovery arguments")
                recovery_control = {
                    "state_path": args.recovery_state,
                    "events_path": args.recovery_events,
                    "cursor_path": args.recovery_cursor,
                    "sync_state_path": args.sync_state,
                    "sync_events_path": args.sync_events,
                    "sync_cursor_path": args.sync_cursor,
                    "transition_id": args.recovery_transition_id,
                    "supervisor_id": args.supervisor_id,
                    "supervisor_epoch": args.supervisor_epoch,
                }
            result = apply_event_files(
                args.goal,
                args.board,
                args.state,
                args.events,
                args.event,
                args.repository_root,
                recovery_control=recovery_control,
            )
        else:
            result = snapshot_files(args.goal, args.board, args.state, args.events, args.repository_root)
    except LoopError as exc:
        print(
            json.dumps({"status": "failed", "code": exc.code, "detail": exc.detail}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
