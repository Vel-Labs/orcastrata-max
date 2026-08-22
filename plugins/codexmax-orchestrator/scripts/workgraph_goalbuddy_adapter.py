#!/usr/bin/env python3
"""Apply Parent-approved WorkGraph updates to canonical GoalBuddy YAML safely."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Sequence

sys.dont_write_bytecode = True


PROTOCOL_VERSION = 1
CURRENT_BOARD_VERSION = 2
NEXT_BOARD_VERSION = 3
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
TOP_VERSION_RE = re.compile(r"^version:[ \t]*([^#\r\n]+?)[ \t]*(?:#.*)?$")
TOP_ACTIVE_RE = re.compile(r"^active_task:[ \t]*([^#\r\n]+?)[ \t]*(?:#.*)?$")
GOAL_STATUS_RE = re.compile(r"^  status:[ \t]*([^#\r\n]+?)[ \t]*(?:#.*)?$")
TASK_ID_RE = re.compile(r"^  - id:[ \t]*([^#\r\n]+?)[ \t]*(?:#.*)?$")
TASK_FIELD_RE = re.compile(r"^    ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*([^#\r\n]*?)[ \t]*(?:#.*)?$")
STATUS_VALUES = {"queued", "active", "blocked", "done"}
GOAL_STATUS_VALUES = {"active", "blocked", "done"}
STATUS_TRANSITIONS = {
    "queued": {"active", "blocked"},
    "active": {"blocked", "done"},
    "blocked": {"active", "done"},
    "done": set(),
}
CREATION_REQUIRED_KEYS = {
    "id", "type", "assignee", "status", "objective", "dependencies", "allowed_files",
    "expected_output", "verify", "stop_if", "receipt",
}
CREATION_OPTIONAL_KEYS = {"reasoning_hint"}
SAFE_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
JOURNAL_PHASES = {"prepared", "board_written", "ledger_written", "resolved_pre_write"}
JOURNAL_KEYS = {
    "schema_version", "operation_id", "update_id", "approved_review_row_hash",
    "expected_board_sha256", "result_board_sha256", "patch_sha256",
    "result_board_base64", "applied_row_id", "reconciliation_row_id",
    "prepared_at", "phase",
}
MAX_ADAPTER_INPUT_BYTES = 4 * 1024 * 1024


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical)
    )


class AdapterError(Exception):
    """Stable adapter protocol failure."""

    def __init__(self, code: str, details: object | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AdapterError(code)
    return value


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(code)
    return value


def _timestamp(value: object) -> str:
    text = _text(value, "adapter_timestamp_invalid")
    if TIMESTAMP_RE.fullmatch(text) is None:
        raise AdapterError("adapter_timestamp_invalid")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise AdapterError("adapter_timestamp_invalid") from error
    return text


def _yaml_scalar(value: str, code: str) -> str:
    text = value.strip()
    if not text:
        raise AdapterError(code)
    if text[0] in {'"', "'"}:
        try:
            if text[0] == '"':
                parsed = json.loads(text)
            elif len(text) >= 2 and text[-1] == "'":
                parsed = text[1:-1].replace("''", "'")
            else:
                raise ValueError
        except (ValueError, json.JSONDecodeError) as error:
            raise AdapterError(code) from error
        if not isinstance(parsed, str) or not parsed:
            raise AdapterError(code)
        return parsed
    if any(character in text for character in "[]{}:,\t\r\n"):
        raise AdapterError(code)
    return text


def _yaml_nullable_scalar(value: str, code: str) -> str | None:
    if value.strip() in {"null", "~"}:
        return None
    return _yaml_scalar(value, code)


def _goalbuddy_clean(value: str) -> str | bool | int | None:
    cleaned = re.sub(r"#.*", "", value).strip()
    if len(cleaned) >= 2 and cleaned[0] in {"'", '"'} and cleaned[-1] == cleaned[0]:
        cleaned = cleaned[1:-1]
    if cleaned in {"", "null"}:
        return None
    if cleaned == "true":
        return True
    if cleaned == "false":
        return False
    if re.fullmatch(r"[0-9]+", cleaned):
        return int(cleaned)
    return cleaned


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise AdapterError(f"adapter_{label}_path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise AdapterError(f"adapter_{label}_missing") from error
    except OSError as error:
        raise AdapterError(f"adapter_{label}_unavailable") from error
    if (
        not _same_canonical_path(lexical, resolved) or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
    ):
        raise AdapterError(f"adapter_{label}_alias_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOENT}:
            raise AdapterError(f"adapter_{label}_identity_changed") from error
        raise AdapterError(f"adapter_{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise AdapterError(f"adapter_{label}_identity_changed")
        raw = bytearray()
        while len(raw) <= MAX_ADAPTER_INPUT_BYTES:
            chunk = os.read(
                descriptor, min(65536, MAX_ADAPTER_INPUT_BYTES + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise AdapterError(f"adapter_{label}_identity_changed")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_ADAPTER_INPUT_BYTES:
        raise AdapterError(f"adapter_{label}_oversize")
    return bytes(raw)


def _read_board(path: Path) -> bytes:
    raw = _read_regular_bytes(path, label="board")
    if not raw:
        raise AdapterError("adapter_board_empty")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError("adapter_board_utf8_invalid") from error
    return raw


def _nested_board_scalar(lines: list[str], section: str, key: str) -> str | None:
    in_section = False
    matches: list[str] = []
    for line_with_ending in lines:
        line = line_with_ending.rstrip("\r\n")
        if line == f"{section}:":
            in_section = True
            continue
        if in_section and line and not line.startswith(" "):
            break
        if in_section:
            match = re.fullmatch(
                rf"  {re.escape(key)}:[ \t]*([^#\r\n]*?)[ \t]*(?:#.*)?$", line
            )
            if match is not None:
                matches.append(match.group(1).strip())
    if len(matches) > 1:
        raise AdapterError("adapter_board_rule_ambiguous", key)
    return matches[0] if matches else None


def _board_boolean(raw_value: str | None) -> bool | None:
    if raw_value is None:
        return None
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    return None


def _task_list(lines: list[str], task: dict[str, Any], key: str) -> list[str]:
    if task["fields"].get(key) != "":
        return []
    values: list[str] = []
    start = task["field_lines"][key] + 1
    for line_with_ending in lines[start:task["end_line"]]:
        line = line_with_ending.rstrip("\r\n")
        if re.match(r"^    \S", line):
            break
        match = re.fullmatch(r"      -[ \t]*(.+?)[ \t]*", line)
        if match is not None:
            value = _goalbuddy_clean(match.group(1))
            if value is not None:
                values.append(str(value))
    return values


def _receipt_metadata(
    lines: list[str], task_id: str, task: dict[str, Any]
) -> dict[str, Any]:
    receipt_value = task["fields"].get("receipt")
    if receipt_value is None or receipt_value.strip() in {"null", "~"}:
        return {
            "present": False, "result": None, "fields": set(), "lists": {},
            "command_statuses": [], "scalars": {},
        }
    receipt_lines: list[str] = []
    if receipt_value == "":
        start = task["field_lines"]["receipt"] + 1
        for line_with_ending in lines[start:task["end_line"]]:
            line = line_with_ending.rstrip("\r\n")
            if re.match(r"^    \S", line):
                break
            receipt_lines.append(line)
        if not receipt_lines or not re.match(r"^(?:      |        )", receipt_lines[0]):
            return {
                "present": False, "result": None, "fields": set(), "lists": {},
                "command_statuses": [], "scalars": {},
            }
    raw = "\n".join(receipt_lines)
    fields = set(re.findall(r"^      ([A-Za-z_][A-Za-z0-9_-]*):", raw, re.MULTILINE))
    scalars: dict[str, str | bool | None] = {}
    for key in fields:
        matches = re.findall(
            rf"^      {re.escape(key)}:[ \t]*([^#\r\n]*?)[ \t]*(?:#.*)?$",
            raw,
            re.MULTILINE,
        )
        if len(matches) > 1:
            raise AdapterError("adapter_board_receipt_field_ambiguous", {"task_id": task_id, "field": key})
        if not matches or matches[0].strip() in {"", "null", "~"}:
            scalars[key] = None
        else:
            scalars[key] = _goalbuddy_clean(matches[0])
    lists: dict[str, list[str]] = {}
    receipt_start = task["field_lines"].get("receipt", -1)
    for key in fields:
        header = None
        for index in range(receipt_start + 1, task["end_line"]):
            if re.fullmatch(rf"      {re.escape(key)}:[ \t]*", lines[index].rstrip("\r\n")):
                header = index
                break
        if header is None:
            continue
        values: list[str] = []
        for line_with_ending in lines[header + 1:task["end_line"]]:
            line = line_with_ending.rstrip("\r\n")
            if re.match(r"^      \S", line):
                break
            match = re.fullmatch(r"        -[ \t]*(.+?)[ \t]*", line)
            if match is not None:
                value = _goalbuddy_clean(match.group(1))
                if value is not None:
                    values.append(str(value))
        lists[key] = values
    command_statuses = [
        str(_goalbuddy_clean(value))
        for value in re.findall(
            r"^          status:[ \t]*([^#\r\n]+?)[ \t]*(?:#.*)?$", raw, re.MULTILINE
        )
        if _goalbuddy_clean(value) is not None
    ]
    return {
        "present": True,
        "result": scalars.get("result"),
        "fields": fields,
        "lists": lists,
        "command_statuses": command_statuses,
        "scalars": scalars,
    }


def _parse_board(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8")
    lines = text.splitlines(keepends=True)
    versions: list[int] = []
    goal_statuses: list[str] = []
    active_tasks: list[str | None] = []
    task_order: list[str] = []
    tasks: dict[str, dict[str, Any]] = {}
    task_sections = 0
    in_tasks = False
    in_goal = False
    current: str | None = None
    for index, line_with_ending in enumerate(lines):
        line = line_with_ending.rstrip("\r\n")
        if line.startswith("version:"):
            match = TOP_VERSION_RE.fullmatch(line)
            if match is None:
                raise AdapterError("adapter_board_version_invalid")
            token = match.group(1).strip()
            if token in {"true", "false", "True", "False"} or not re.fullmatch(r"[0-9]+", token):
                raise AdapterError("adapter_board_version_invalid")
            versions.append(int(token))
        if line.startswith("active_task:"):
            match = TOP_ACTIVE_RE.fullmatch(line)
            if match is None:
                raise AdapterError("adapter_board_active_task_invalid")
            active_tasks.append(_yaml_nullable_scalar(match.group(1), "adapter_board_active_task_invalid"))
        if line == "goal:":
            in_goal = True
        elif in_goal and line and not line.startswith(" "):
            in_goal = False
        if in_goal and line.startswith("  status:"):
            match = GOAL_STATUS_RE.fullmatch(line)
            if match is None:
                raise AdapterError("adapter_board_goal_status_invalid")
            goal_statuses.append(_yaml_scalar(match.group(1), "adapter_board_goal_status_invalid"))
        if line == "tasks:":
            task_sections += 1
            if task_sections != 1:
                raise AdapterError("adapter_board_tasks_ambiguous")
            in_tasks = True
            current = None
            continue
        if in_tasks and line and not line.startswith(" "):
            if current is not None:
                tasks[current]["end_line"] = index
            in_tasks = False
            current = None
        if not in_tasks:
            continue
        id_match = TASK_ID_RE.fullmatch(line)
        if id_match is not None:
            if current is not None:
                tasks[current]["end_line"] = index
            task_id = _yaml_scalar(id_match.group(1), "adapter_board_task_id_invalid")
            if task_id in tasks:
                raise AdapterError("adapter_board_task_id_duplicate", task_id)
            tasks[task_id] = {"fields": {}, "field_lines": {}, "start_line": index}
            task_order.append(task_id)
            current = task_id
            continue
        if current is not None:
            field_match = TASK_FIELD_RE.fullmatch(line)
            if field_match is not None:
                field, raw_value = field_match.groups()
                if field in tasks[current]["fields"]:
                    raise AdapterError("adapter_board_task_field_duplicate", {"task_id": current, "field": field})
                tasks[current]["fields"][field] = raw_value.strip()
                tasks[current]["field_lines"][field] = index
    if len(versions) != 1:
        raise AdapterError("adapter_board_version_ambiguous" if versions else "adapter_board_version_missing")
    if len(active_tasks) != 1:
        raise AdapterError("adapter_board_active_task_ambiguous" if active_tasks else "adapter_board_active_task_missing")
    if len(goal_statuses) != 1:
        raise AdapterError("adapter_board_goal_status_ambiguous" if goal_statuses else "adapter_board_goal_status_missing")
    if task_sections == 0 or not tasks:
        raise AdapterError("adapter_board_tasks_missing")
    if current is not None and "end_line" not in tasks[current]:
        tasks[current]["end_line"] = len(lines)
    statuses: dict[str, str] = {}
    receipts: dict[str, dict[str, Any]] = {}
    for task_id in task_order:
        if "status" not in tasks[task_id]["fields"]:
            raise AdapterError("adapter_board_task_status_missing", task_id)
        statuses[task_id] = _yaml_scalar(
            tasks[task_id]["fields"]["status"], "adapter_board_task_status_invalid"
        )
        tasks[task_id]["type"] = (
            _yaml_scalar(tasks[task_id]["fields"]["type"], "adapter_board_task_type_invalid")
            if "type" in tasks[task_id]["fields"] else None
        )
        tasks[task_id]["allowed_files"] = _task_list(lines, tasks[task_id], "allowed_files")
        tasks[task_id]["verify"] = _task_list(lines, tasks[task_id], "verify")
        tasks[task_id]["stop_if"] = _task_list(lines, tasks[task_id], "stop_if")
        tasks[task_id]["dependencies"] = _task_list(lines, tasks[task_id], "dependencies")
        receipts[task_id] = _receipt_metadata(lines, task_id, tasks[task_id])
    continuous = _board_boolean(_nested_board_scalar(lines, "rules", "continuous_until_full_outcome")) is True
    missing_input_continues = _board_boolean(
        _nested_board_scalar(lines, "rules", "missing_input_or_credentials_do_not_stop_goal")
    ) is True
    return {
        "version": versions[0],
        "goal_status": goal_statuses[0],
        "active_task": active_tasks[0],
        "tasks": tasks,
        "task_order": task_order,
        "task_statuses": statuses,
        "task_receipts": receipts,
        "continuous_until_full_outcome": continuous,
        "missing_input_or_credentials_do_not_stop_goal": missing_input_continues,
        "lines": lines,
    }


def _normalize_path_pattern(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def _matches_allowed_file(path: str, patterns: list[str]) -> bool:
    normalized_path = _normalize_path_pattern(path)
    for pattern in patterns:
        normalized = _normalize_path_pattern(pattern)
        if normalized == normalized_path:
            return True
        token = "__GOALBUDDY_GLOBSTAR__"
        expression = re.escape(normalized).replace(r"\*\*", token).replace(r"\*", "[^/]*")
        expression = expression.replace(token, ".*")
        if re.fullmatch(expression, normalized_path) is not None:
            return True
    return False


def _terminal_approval_wait(parsed: dict[str, Any]) -> bool:
    if parsed["goal_status"] != "blocked" or parsed["active_task"] is not None:
        return False
    statuses = parsed["task_statuses"]
    if any(status == "active" for status in statuses.values()):
        return False
    unfinished = [task_id for task_id, status in statuses.items() if status != "done"]
    if not unfinished or any(statuses[task_id] != "blocked" for task_id in unfinished):
        return False
    return any(
        parsed["task_receipts"][task_id]["present"]
        and parsed["task_receipts"][task_id]["scalars"].get("result") == "blocked"
        and parsed["task_receipts"][task_id]["scalars"].get("waiting_for_user_approval") is True
        and bool(parsed["task_receipts"][task_id]["scalars"].get("required_reply"))
        for task_id in unfinished
    )


def _canonical_invariant_errors(parsed: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    goal_status = parsed["goal_status"]
    statuses = parsed["task_statuses"]
    active_task = parsed["active_task"]
    if goal_status not in GOAL_STATUS_VALUES:
        errors.append("goal_status_invalid")
    for task_id, status in sorted(statuses.items()):
        if status not in STATUS_VALUES:
            errors.append(f"task_status_invalid:{task_id}")
        receipt = parsed["task_receipts"][task_id]
        if status == "blocked" and not receipt["present"]:
            errors.append(f"blocked_receipt_missing:{task_id}")
        if status == "done":
            if not receipt["present"]:
                errors.append(f"done_receipt_missing:{task_id}")
            elif receipt["result"] != "done":
                errors.append(f"done_receipt_result_invalid:{task_id}")
        task = parsed["tasks"][task_id]
        task_type = task["type"]
        if task_type == "worker" and status == "active":
            for field in ("allowed_files", "verify", "stop_if"):
                if not task[field]:
                    errors.append(f"active_worker_{field}_missing:{task_id}")
        if task_type == "worker" and status == "done" and receipt["present"]:
            for field in ("changed_files", "commands", "summary"):
                if field not in receipt["fields"]:
                    errors.append(f"done_worker_receipt_{field}_missing:{task_id}")
            changed_files = receipt["lists"].get("changed_files", [])
            if not changed_files:
                errors.append(f"done_worker_receipt_changed_files_empty:{task_id}")
            for changed_file in changed_files:
                if not _matches_allowed_file(changed_file, task["allowed_files"]):
                    errors.append(f"done_worker_changed_file_outside_scope:{task_id}:{changed_file}")
            if "commands" in receipt["fields"] and not receipt["command_statuses"]:
                errors.append(f"done_worker_receipt_command_status_missing:{task_id}")
            for command_status in receipt["command_statuses"]:
                if command_status != "pass":
                    errors.append(f"done_worker_receipt_command_status_not_pass:{task_id}:{command_status}")
        if task_type == "scout" and status == "done" and receipt["present"]:
            if "summary" not in receipt["fields"]:
                errors.append(f"done_scout_receipt_summary_missing:{task_id}")
            if "evidence" not in receipt["fields"] and "note" not in receipt["fields"]:
                errors.append(f"done_scout_receipt_evidence_or_note_missing:{task_id}")
        if task_type == "judge" and status == "done" and receipt["present"]:
            if "decision" not in receipt["fields"]:
                errors.append(f"done_judge_receipt_decision_missing:{task_id}")
    active_ids = sorted(task_id for task_id, status in statuses.items() if status == "active")
    if goal_status == "active":
        if len(active_ids) != 1:
            errors.append(f"active_goal_active_count:{len(active_ids)}")
        elif active_task != active_ids[0]:
            errors.append("active_task_misaligned")
    elif goal_status == "blocked":
        if len(active_ids) > 1:
            errors.append(f"blocked_goal_active_count:{len(active_ids)}")
        elif len(active_ids) == 1 and active_task != active_ids[0]:
            errors.append("active_task_misaligned")
        if (
            parsed["continuous_until_full_outcome"]
            and parsed["missing_input_or_credentials_do_not_stop_goal"]
            and not _terminal_approval_wait(parsed)
        ):
            errors.append("continuous_goal_status_blocked")
    elif goal_status == "done":
        if active_ids:
            errors.append(f"done_goal_active_count:{len(active_ids)}")
        if active_task is not None:
            errors.append("done_goal_active_task_not_null")
        unfinished_workers = sorted(
            task_id for task_id, status in statuses.items()
            if parsed["tasks"][task_id]["type"] == "worker" and status in {"queued", "active"}
        )
        if unfinished_workers:
            errors.append("done_goal_unfinished_workers:" + ",".join(unfinished_workers))
        final_audits = []
        for task_id, status in statuses.items():
            receipt = parsed["task_receipts"][task_id]
            if (
                parsed["tasks"][task_id]["type"] in {"judge", "pm"}
                and status == "done" and receipt["present"]
                and receipt["scalars"].get("decision") in {"complete", "done"}
            ):
                final_audits.append(receipt)
        if not final_audits:
            errors.append("done_goal_final_audit_missing")
        elif parsed["continuous_until_full_outcome"] and not any(
            receipt["scalars"].get("full_outcome_complete") is True for receipt in final_audits
        ):
            errors.append("done_goal_full_outcome_audit_missing")
    if active_task is not None and active_task not in statuses:
        errors.append("active_task_unknown")
    return sorted(set(errors))


def _validate_canonical_board(parsed: dict[str, Any]) -> None:
    errors = _canonical_invariant_errors(parsed)
    if errors:
        raise AdapterError("adapter_board_canonical_invalid", errors)


def _capabilities(version: int) -> dict[str, Any]:
    return {
        "apply": version == CURRENT_BOARD_VERSION,
        "migration_available": False,
        "migration_required": version == NEXT_BOARD_VERSION,
        "pinned_current_schema_version": CURRENT_BOARD_VERSION,
        "recognized_next_schema_version": NEXT_BOARD_VERSION,
        "recover": version == CURRENT_BOARD_VERSION,
        "snapshot": version in {CURRENT_BOARD_VERSION, NEXT_BOARD_VERSION},
    }


def snapshot(board_path: Path) -> dict[str, Any]:
    raw = _read_board(board_path)
    parsed = _parse_board(raw)
    version = parsed["version"]
    if version not in {CURRENT_BOARD_VERSION, NEXT_BOARD_VERSION}:
        raise AdapterError("adapter_board_schema_unsupported", version)
    _validate_canonical_board(parsed)
    return {
        "active_task": parsed["active_task"],
        "board_sha256": _sha256(raw),
        "canonical_owner": "GoalBuddy",
        "capabilities": _capabilities(version),
        "operation": "snapshot",
        "protocol": "workgraph_goalbuddy_adapter",
        "schema_version": PROTOCOL_VERSION,
        "state_schema_version": version,
        "status": "ok",
        "task_statuses": [
            {"status": parsed["task_statuses"][task_id], "task_id": task_id}
            for task_id in sorted(parsed["task_statuses"])
        ],
    }


def _updates_module() -> Any:
    path = Path(__file__).with_name("workgraph_updates.py")
    spec = importlib.util.spec_from_file_location("codexmax_t003_workgraph_updates", path)
    if spec is None or spec.loader is None:
        raise AdapterError("adapter_updates_runtime_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_updates(path: Path) -> tuple[Any, list[dict[str, Any]]]:
    module = _updates_module()
    try:
        rows = module.read_rows(path)
    except module.UpdateError as error:
        mapped = {
            "update_parent_reviewer_required": "adapter_parent_reviewer_required",
            "update_parent_authority_required": "adapter_parent_authority_required",
            "update_reviewer_independence_unproved": "adapter_reviewer_independence_unproved",
            "update_self_review_forbidden": "adapter_self_review_forbidden",
        }.get(error.code)
        if mapped is not None:
            raise AdapterError(mapped) from error
        raise AdapterError("adapter_updates_invalid", error.code) from error
    return module, rows


def _lineage(rows: list[dict[str, Any]], update_id: str) -> list[dict[str, Any]]:
    selected = [row for row in rows if row["update_id"] == update_id]
    if not selected:
        raise AdapterError("adapter_update_unknown")
    return selected


def _review_for_apply(rows: list[dict[str, Any]], update_id: str) -> dict[str, Any]:
    lineage = _lineage(rows, update_id)
    latest = lineage[-1]
    if latest["transition"] == "reconciled":
        return latest
    if latest["transition"] == "applied":
        return latest
    if latest["transition"] != "reviewed":
        raise AdapterError("adapter_update_not_approved")
    if latest["review_status"] != "approved" or latest["parent_decision"] != "approve":
        raise AdapterError("adapter_update_not_approved")
    reviewer = latest.get("reviewer_identity")
    proposer = latest.get("proposer_identity")
    authority = latest.get("authority_reference")
    if not isinstance(reviewer, dict) or reviewer.get("role") != "Parent":
        raise AdapterError("adapter_parent_reviewer_required")
    if not isinstance(authority, dict) or authority.get("provenance") != "parent_issued":
        raise AdapterError("adapter_parent_authority_required")
    proposer_id = proposer.get("agent_id", {}).get("value") if isinstance(proposer, dict) else None
    reviewer_id = reviewer.get("agent_id", {}).get("value")
    if proposer_id in {None, "unknown"} or reviewer_id in {None, "unknown"}:
        raise AdapterError("adapter_reviewer_independence_unproved")
    if proposer_id == reviewer_id:
        raise AdapterError("adapter_self_review_forbidden")
    return latest


def _safe_creation_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(char) < 0x20 for char in value):
        raise AdapterError(code)
    if value.lstrip().startswith(("!", "&", "*")) or "\x00" in value:
        raise AdapterError(code)
    return value


def _creation_list(value: object, code: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(row, str) for row in value):
        raise AdapterError(code)
    return [_safe_creation_text(row, code) for row in value]


def _validate_creation_value(value: object, task_id: str, parsed: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - (CREATION_REQUIRED_KEYS | CREATION_OPTIONAL_KEYS) or CREATION_REQUIRED_KEYS - set(value):
        raise AdapterError("adapter_creation_shape_invalid")
    if value.get("id") != task_id or SAFE_TASK_ID_RE.fullmatch(task_id) is None:
        raise AdapterError("adapter_creation_id_invalid")
    if task_id in parsed["tasks"]:
        raise AdapterError("adapter_creation_duplicate")
    if value.get("status") != "queued" or value.get("receipt") is not None:
        raise AdapterError("adapter_creation_initial_state_invalid")
    for key in ("type", "assignee", "objective"):
        _safe_creation_text(value.get(key), "adapter_creation_text_invalid")
    if "reasoning_hint" in value:
        _safe_creation_text(value["reasoning_hint"], "adapter_creation_text_invalid")
    dependencies = _creation_list(value.get("dependencies"), "adapter_creation_dependencies_invalid")
    if task_id in dependencies:
        raise AdapterError("adapter_creation_dependency_self")
    missing = sorted(set(dependencies) - set(parsed["tasks"]))
    if missing:
        raise AdapterError("adapter_creation_dependency_missing", missing)
    edges = {existing: list(parsed["tasks"][existing]["dependencies"]) for existing in parsed["task_order"]}
    edges[task_id] = dependencies
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(node: str) -> None:
        if node in visiting:
            raise AdapterError("adapter_creation_dependency_cycle")
        if node in visited:
            return
        visiting.add(node)
        for dependency in edges.get(node, []):
            if dependency in edges:
                visit(dependency)
        visiting.remove(node)
        visited.add(node)
    for node in sorted(edges):
        visit(node)
    for key in ("allowed_files", "expected_output", "verify", "stop_if"):
        _creation_list(value.get(key), "adapter_creation_list_invalid")
    return value


def _validate_patch(review: dict[str, Any], parsed: dict[str, Any]) -> tuple[str, object, int | None]:
    patch = review.get("proposed_patch")
    if not isinstance(patch, list) or len(patch) != 1:
        raise AdapterError("adapter_patch_count_invalid")
    operation = patch[0]
    if not isinstance(operation, dict) or set(operation) != {"op", "path", "value"}:
        raise AdapterError("adapter_patch_operation_invalid")
    path = operation["path"]
    if not isinstance(path, str):
        raise AdapterError("adapter_patch_path_invalid")
    creation = review.get("update_kind") == "task_creation"
    match = re.fullmatch(r"/tasks/([^/~]+(?:~[01][^/~]*)*)" + (r"" if creation else r"/status"), path)
    if match is None:
        raise AdapterError("adapter_patch_path_unsupported")
    raw_task = match.group(1)
    task_id = raw_task.replace("~1", "/").replace("~0", "~")
    if task_id != review["target_task"]:
        raise AdapterError("adapter_patch_target_mismatch")
    if creation:
        if operation["op"] != "add":
            raise AdapterError("adapter_creation_operation_invalid")
        return task_id, _validate_creation_value(operation["value"], task_id, parsed), None
    if operation["op"] != "replace":
        raise AdapterError("adapter_patch_operation_unsupported")
    if task_id not in parsed["tasks"]:
        raise AdapterError("adapter_patch_task_missing")
    value = operation["value"]
    if not isinstance(value, str) or value not in STATUS_VALUES:
        raise AdapterError("adapter_patch_status_invalid")
    current = parsed["task_statuses"][task_id]
    if current not in STATUS_VALUES:
        raise AdapterError("adapter_patch_current_status_unsupported")
    if value == current:
        raise AdapterError("adapter_patch_no_effect")
    if value not in STATUS_TRANSITIONS[current]:
        raise AdapterError("adapter_patch_lifecycle_invalid", {"from": current, "to": value})
    return task_id, value, parsed["tasks"][task_id]["field_lines"]["status"]


def _yaml_creation_block(value: dict[str, Any], newline: str) -> str:
    def scalar(item: str) -> str:
        return json.dumps(item, ensure_ascii=False)
    rows = [f"  - id: {scalar(value['id'])}"]
    for key in ("type", "assignee", "status", "reasoning_hint", "objective"):
        if key in value:
            rows.append(f"    {key}: {scalar(value[key])}")
    for key in ("dependencies", "allowed_files", "expected_output", "verify", "stop_if"):
        if value[key]:
            rows.append(f"    {key}:")
            rows.extend(f"      - {scalar(item)}" for item in value[key])
        else:
            rows.append(f"    {key}: []")
    rows.append("    receipt: null")
    return newline.join(rows) + newline + newline


def _patched_board(raw: bytes, review: dict[str, Any]) -> bytes:
    parsed = _parse_board(raw)
    if parsed["version"] == NEXT_BOARD_VERSION:
        raise AdapterError("adapter_migration_required")
    if parsed["version"] != CURRENT_BOARD_VERSION:
        raise AdapterError("adapter_board_schema_unsupported", parsed["version"])
    _validate_canonical_board(parsed)
    task_id, value, line_index = _validate_patch(review, parsed)
    if review.get("update_kind") == "task_creation":
        assert isinstance(value, dict) and line_index is None
        newline = "\r\n" if b"\r\n" in raw else "\n"
        last = parsed["tasks"][parsed["task_order"][-1]]["start_line"]
        insertion_line = len(parsed["lines"])
        for candidate in range(last + 1, len(parsed["lines"])):
            line = parsed["lines"][candidate]
            if line.strip() and not line.startswith((" ", "\t", "\r", "\n")):
                insertion_line = candidate
                break
        prefix = "".join(parsed["lines"][:insertion_line]).encode("utf-8")
        suffix = "".join(parsed["lines"][insertion_line:]).encode("utf-8")
        separator = b"" if prefix.endswith((b"\n\n", b"\r\n\r\n")) else newline.encode("utf-8")
        result = prefix + separator + _yaml_creation_block(value, newline).encode("utf-8") + suffix
        result_parsed = _parse_board(result)
        errors = _canonical_invariant_errors(result_parsed)
        if errors or result_parsed["active_task"] != parsed["active_task"]:
            raise AdapterError("adapter_board_canonical_invalid", errors)
        return result
    current_status = parsed["task_statuses"][task_id]
    lines = list(parsed["lines"])
    ending = "\n" if lines[line_index].endswith("\n") else ""
    if lines[line_index].endswith("\r\n"):
        ending = "\r\n"
    lines[line_index] = f"    status: {value}{ending}"
    result = "".join(lines).encode("utf-8")
    result_parsed = _parse_board(result)
    errors = _canonical_invariant_errors(result_parsed)
    if errors:
        if current_status == "active" or value == "active" or any(
            code.startswith(("active_goal_active_count", "active_task_misaligned"))
            for code in errors
        ):
            raise AdapterError("adapter_patch_atomic_handoff_unsupported", errors)
        raise AdapterError("adapter_board_canonical_invalid", errors)
    return result


def _atomic_write(path: Path, raw: bytes, code: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        existing_mode = 0o600
    except OSError as error:
        raise AdapterError(code) from error
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), existing_mode)
            if stream.write(raw) != len(raw):
                raise AdapterError(code)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except AdapterError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise AdapterError(code) from error


def _read_journal(path: Path) -> dict[str, Any] | None:
    try:
        raw = _read_regular_bytes(path, label="journal")
    except AdapterError as error:
        if error.code == "adapter_journal_missing":
            return None
        raise
    if not raw:
        raise AdapterError("adapter_journal_corrupt")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterError("adapter_journal_corrupt") from error
    if not isinstance(value, dict) or set(value) != JOURNAL_KEYS:
        raise AdapterError("adapter_journal_corrupt")
    version = value["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise AdapterError("adapter_journal_corrupt")
    for field in (
        "operation_id", "update_id", "approved_review_row_hash", "patch_sha256",
        "result_board_base64", "applied_row_id", "reconciliation_row_id", "prepared_at",
    ):
        _text(value[field], "adapter_journal_corrupt")
    for field in ("expected_board_sha256", "result_board_sha256"):
        _hash(value[field], "adapter_journal_corrupt")
    if not re.fullmatch(r"[0-9a-f]{64}", value["approved_review_row_hash"]):
        raise AdapterError("adapter_journal_corrupt")
    if not re.fullmatch(r"[0-9a-f]{64}", value["patch_sha256"]):
        raise AdapterError("adapter_journal_corrupt")
    try:
        intended = base64.b64decode(value["result_board_base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise AdapterError("adapter_journal_corrupt") from error
    if base64.b64encode(intended).decode("ascii") != value["result_board_base64"]:
        raise AdapterError("adapter_journal_corrupt")
    if _sha256(intended) != value["result_board_sha256"]:
        raise AdapterError("adapter_journal_corrupt")
    try:
        _parse_board(intended)
    except AdapterError as error:
        raise AdapterError("adapter_journal_corrupt") from error
    _timestamp(value["prepared_at"])
    if value["phase"] not in JOURNAL_PHASES:
        raise AdapterError("adapter_journal_corrupt")
    return value


def _write_journal(path: Path, value: dict[str, Any]) -> None:
    _atomic_write(path, (canonical_json(value) + "\n").encode("utf-8"), "adapter_journal_write_failed")


def _operation_ids(review: dict[str, Any], result_hash: str) -> tuple[str, str, str]:
    seed = hashlib.sha256(
        (review["update_id"] + "\0" + review["row_hash"] + "\0" + result_hash).encode("utf-8")
    ).hexdigest()[:24]
    return "apply-" + seed, "adapter-applied-" + seed, "adapter-reconciled-" + seed


def _journal_for(
    review: dict[str, Any], result_raw: bytes, result_hash: str, timestamp: str
) -> dict[str, Any]:
    operation_id, applied_id, reconciled_id = _operation_ids(review, result_hash)
    return {
        "schema_version": 1,
        "operation_id": operation_id,
        "update_id": review["update_id"],
        "approved_review_row_hash": review["row_hash"],
        "expected_board_sha256": review["expected_board_sha256"],
        "result_board_sha256": result_hash,
        "result_board_base64": base64.b64encode(result_raw).decode("ascii"),
        "patch_sha256": hashlib.sha256(canonical_json(review["proposed_patch"]).encode("utf-8")).hexdigest(),
        "applied_row_id": applied_id,
        "reconciliation_row_id": reconciled_id,
        "prepared_at": timestamp,
        "phase": "prepared",
    }


def _transition_draft(
    review: dict[str, Any], journal: dict[str, Any], timestamp: str, transition: str
) -> dict[str, Any]:
    draft = {
        key: review[key]
        for key in (
            "schema_version", "update_id", "target_task", "update_kind", "proposed_patch",
            "proposer_identity", "expected_board_sha256", "authority_reference",
            "reviewer_identity", "parent_decision",
        )
    }
    draft.update({
        "row_id": journal["applied_row_id"] if transition == "applied" else journal["reconciliation_row_id"],
        "timestamp": timestamp,
        "transition": transition,
        "review_status": "applied" if transition == "applied" else "reconciled",
        "applied_state_sha256": journal["result_board_sha256"],
        "superseded_by_update_id": None,
        "reconciliation": None if transition == "applied" else {
            "observed_state_sha256": journal["result_board_sha256"],
            "outcome": "recovered",
        },
    })
    return draft


def _rows_for_journal(rows: list[dict[str, Any]], journal: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    lineage = _lineage(rows, journal["update_id"])
    review = next((row for row in lineage if row["row_hash"] == journal["approved_review_row_hash"]), None)
    if review is None or review["transition"] != "reviewed":
        raise AdapterError("adapter_journal_stale")
    if hashlib.sha256(canonical_json(review["proposed_patch"]).encode("utf-8")).hexdigest() != journal["patch_sha256"]:
        raise AdapterError("adapter_journal_stale")
    applied = next((row for row in lineage if row["row_id"] == journal["applied_row_id"]), None)
    reconciled = next((row for row in lineage if row["row_id"] == journal["reconciliation_row_id"]), None)
    if applied is not None and (
        applied["transition"] != "applied"
        or applied["applied_state_sha256"] != journal["result_board_sha256"]
    ):
        raise AdapterError("adapter_journal_stale")
    if reconciled is not None and (
        reconciled["transition"] != "reconciled"
        or reconciled["applied_state_sha256"] != journal["result_board_sha256"]
        or reconciled["reconciliation"] != {
            "observed_state_sha256": journal["result_board_sha256"], "outcome": "recovered"
        }
    ):
        raise AdapterError("adapter_journal_stale")
    return review, applied, reconciled


def _lock_path(board_path: Path) -> tuple[Path, Path]:
    try:
        resolved = board_path.resolve(strict=True)
    except OSError as error:
        raise AdapterError("adapter_board_unavailable") from error
    lock_path = resolved.parent / ".goalbuddy-board" / (resolved.name + ".workgraph-adapter.lock")
    return resolved, lock_path


def _has_traversal(path: Path) -> bool:
    return ".." in path.parts


def _validate_mutation_paths(
    board_path: Path,
    updates_path: Path,
    journal_path: Path,
    *,
    journal_required: bool,
) -> tuple[Path, Path, Path, Path]:
    if any(_has_traversal(path) for path in (board_path, updates_path, journal_path)):
        raise AdapterError("adapter_path_traversal_forbidden")
    for path, code in (
        (board_path, "adapter_board_path_invalid"),
        (updates_path, "adapter_updates_path_invalid"),
        (journal_path, "adapter_journal_path_invalid"),
    ):
        if path.is_symlink():
            raise AdapterError("adapter_path_symlink_forbidden", code)
    try:
        resolved_board = board_path.resolve(strict=True)
    except OSError as error:
        raise AdapterError("adapter_board_path_invalid") from error
    board_status = board_path.lstat()
    if (
        not stat.S_ISREG(board_status.st_mode) or board_status.st_nlink != 1
        or not resolved_board.is_file()
    ):
        raise AdapterError("adapter_board_path_invalid")
    sidecar = resolved_board.parent / ".goalbuddy-board"
    lexical_board = Path(os.path.abspath(board_path))
    lexical_sidecar = lexical_board.parent / ".goalbuddy-board"
    if sidecar.is_symlink() or not sidecar.is_dir():
        raise AdapterError("adapter_sidecar_path_invalid")
    expected_updates = sidecar / "updates.jsonl"
    try:
        resolved_updates = updates_path.resolve(strict=True)
    except OSError as error:
        raise AdapterError("adapter_updates_path_invalid") from error
    if resolved_updates != expected_updates or not resolved_updates.is_file():
        raise AdapterError("adapter_updates_path_invalid")
    if Path(os.path.abspath(updates_path)) != lexical_sidecar / "updates.jsonl":
        raise AdapterError("adapter_updates_path_alias_forbidden")
    if Path(os.path.abspath(journal_path)) == lexical_sidecar / "updates.jsonl":
        raise AdapterError("adapter_path_duplicate")
    if journal_path.suffix != ".json" or journal_path.name == "updates.jsonl":
        raise AdapterError("adapter_journal_path_unsupported")
    try:
        resolved_journal_parent = journal_path.parent.resolve(strict=True)
    except OSError as error:
        raise AdapterError("adapter_journal_path_invalid") from error
    if (
        resolved_journal_parent != sidecar
        or Path(os.path.abspath(journal_path)).parent != lexical_sidecar
    ):
        raise AdapterError("adapter_journal_path_invalid")
    resolved_journal = sidecar / journal_path.name
    if resolved_journal == resolved_updates:
        raise AdapterError("adapter_path_duplicate")
    if resolved_journal.exists():
        if resolved_journal.is_symlink() or not resolved_journal.is_file():
            raise AdapterError("adapter_journal_path_invalid")
        try:
            if os.path.samefile(resolved_journal, resolved_updates) or os.path.samefile(
                resolved_journal, resolved_board
            ):
                raise AdapterError("adapter_path_duplicate")
        except OSError as error:
            raise AdapterError("adapter_journal_path_invalid") from error
    elif journal_required:
        raise AdapterError("adapter_journal_path_invalid")
    try:
        if os.path.samefile(resolved_updates, resolved_board):
            raise AdapterError("adapter_path_duplicate")
    except OSError as error:
        raise AdapterError("adapter_updates_path_invalid") from error
    lock_path = sidecar / (resolved_board.name + ".workgraph-adapter.lock")
    if resolved_journal == lock_path:
        raise AdapterError("adapter_path_duplicate")
    return resolved_board, resolved_updates, resolved_journal, lock_path


def _open_lock(lock_path: Path):
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise AdapterError("adapter_lock_unavailable") from error
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise AdapterError("adapter_lock_alias_forbidden") from error
        raise AdapterError("adapter_lock_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        named = lock_path.lstat()
    except OSError as error:
        os.close(descriptor)
        raise AdapterError("adapter_lock_unavailable") from error
    if (
        not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
        or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise AdapterError("adapter_lock_alias_forbidden")
    return os.fdopen(descriptor, "r+b")


def _idempotent_receipt(board_hash: str, update_id: str, outcome: str) -> dict[str, Any]:
    return {
        "board_sha256": board_hash,
        "operation": "apply",
        "outcome": outcome,
        "protocol": "workgraph_goalbuddy_adapter",
        "schema_version": 1,
        "status": "ok",
        "update_id": update_id,
    }


def apply_update(
    board_path: Path,
    updates_path: Path,
    journal_path: Path,
    update_id: str,
    *,
    timestamp: str,
    interrupt_after: str | None = None,
) -> dict[str, Any]:
    update_id = _text(update_id, "adapter_update_id_invalid")
    timestamp = _timestamp(timestamp)
    if interrupt_after not in {None, "journal", "board", "ledger"}:
        raise AdapterError("adapter_interrupt_phase_invalid")
    resolved_board, resolved_updates, resolved_journal, lock_path = _validate_mutation_paths(
        board_path, updates_path, journal_path, journal_required=False
    )
    with _open_lock(lock_path) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing_journal = _read_journal(resolved_journal)
        module, rows = _read_updates(resolved_updates)
        latest = _review_for_apply(rows, update_id)
        raw = _read_board(resolved_board)
        current_hash = _sha256(raw)
        if latest["transition"] in {"applied", "reconciled"}:
            if latest["applied_state_sha256"] == current_hash:
                return _idempotent_receipt(current_hash, update_id, "idempotent")
            raise AdapterError("adapter_applied_state_diverged")
        if existing_journal is not None and existing_journal["phase"] not in {"ledger_written", "resolved_pre_write"}:
            raise AdapterError("adapter_recovery_required")
        expected_hash = latest["expected_board_sha256"]
        if current_hash != expected_hash:
            raise AdapterError("adapter_board_stale", {"expected": expected_hash, "observed": current_hash})
        result_raw = _patched_board(raw, latest)
        result_hash = _sha256(result_raw)
        journal = _journal_for(latest, result_raw, result_hash, timestamp)
        _write_journal(resolved_journal, journal)
        observed_after_prepare = _read_board(resolved_board)
        if observed_after_prepare != raw or _sha256(observed_after_prepare) != expected_hash:
            raise AdapterError("adapter_board_stale_after_prepare")
        if interrupt_after == "journal":
            raise AdapterError("adapter_interrupted_after_journal")
        _atomic_write(resolved_board, result_raw, "adapter_board_write_failed")
        journal["phase"] = "board_written"
        _write_journal(resolved_journal, journal)
        if interrupt_after == "board":
            raise AdapterError("adapter_interrupted_after_board")
        try:
            applied = module.append_update(
                resolved_updates,
                _transition_draft(latest, journal, timestamp, "applied"),
                current_board_hash=expected_hash,
            )
        except module.UpdateError as error:
            raise AdapterError("adapter_applied_append_failed", error.code) from error
        if interrupt_after == "ledger":
            raise AdapterError("adapter_interrupted_after_ledger")
        journal["phase"] = "ledger_written"
        _write_journal(resolved_journal, journal)
        return {
            "applied_row_hash": applied["row_hash"],
            "board_sha256": result_hash,
            "operation": "apply",
            "outcome": "applied",
            "protocol": "workgraph_goalbuddy_adapter",
            "schema_version": 1,
            "status": "ok",
            "update_id": update_id,
        }


def recover(
    board_path: Path,
    updates_path: Path,
    journal_path: Path,
    *,
    timestamp: str,
) -> dict[str, Any]:
    timestamp = _timestamp(timestamp)
    resolved_board, resolved_updates, resolved_journal, lock_path = _validate_mutation_paths(
        board_path, updates_path, journal_path, journal_required=True
    )
    with _open_lock(lock_path) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        journal = _read_journal(resolved_journal)
        if journal is None:
            raise AdapterError("adapter_journal_missing")
        module, rows = _read_updates(resolved_updates)
        review, applied, reconciled = _rows_for_journal(rows, journal)
        raw = _read_board(resolved_board)
        board_hash = _sha256(raw)
        expected = journal["expected_board_sha256"]
        result = journal["result_board_sha256"]
        if journal["phase"] == "resolved_pre_write":
            if board_hash != expected:
                raise AdapterError("adapter_board_diverged")
            return _recovery_receipt(journal, board_hash, "already_recovered")
        if board_hash == expected:
            if journal["phase"] != "prepared" or applied is not None or reconciled is not None:
                raise AdapterError("adapter_journal_stale")
            journal["phase"] = "resolved_pre_write"
            _write_journal(resolved_journal, journal)
            return _recovery_receipt(journal, board_hash, "pre_write")
        if board_hash != result:
            raise AdapterError("adapter_board_diverged", {"expected": expected, "result": result, "observed": board_hash})
        intended = base64.b64decode(journal["result_board_base64"], validate=True)
        if raw != intended:
            raise AdapterError("adapter_board_diverged")
        if reconciled is not None:
            journal["phase"] = "ledger_written"
            _write_journal(resolved_journal, journal)
            return _recovery_receipt(journal, board_hash, "already_recovered")
        had_applied = applied is not None
        if applied is None:
            try:
                applied = module.append_update(
                    resolved_updates,
                    _transition_draft(review, journal, timestamp, "applied"),
                    current_board_hash=expected,
                )
            except module.UpdateError as error:
                raise AdapterError("adapter_applied_append_failed", error.code) from error
        try:
            reconciled = module.append_update(
                resolved_updates,
                _transition_draft(review, journal, timestamp, "reconciled"),
                current_board_hash=expected,
            )
        except module.UpdateError as error:
            raise AdapterError("adapter_reconciliation_append_failed", error.code) from error
        journal["phase"] = "ledger_written"
        _write_journal(resolved_journal, journal)
        receipt = _recovery_receipt(journal, board_hash, "ledger_written" if had_applied else "board_written")
        receipt["applied_row_hash"] = applied["row_hash"]
        receipt["reconciliation_row_hash"] = reconciled["row_hash"]
        return receipt


def _recovery_receipt(journal: dict[str, Any], board_hash: str, outcome: str) -> dict[str, Any]:
    return {
        "board_sha256": board_hash,
        "operation": "recover",
        "outcome": outcome,
        "protocol": "workgraph_goalbuddy_adapter",
        "schema_version": 1,
        "status": "ok",
        "update_id": journal["update_id"],
    }


def _error_receipt(operation: str, error: AdapterError) -> dict[str, Any]:
    result: dict[str, Any] = {
        "error": error.code,
        "operation": operation,
        "protocol": "workgraph_goalbuddy_adapter",
        "schema_version": 1,
        "status": "error",
    }
    if error.details is not None:
        result["details"] = error.details
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    child = commands.add_parser("snapshot")
    child.add_argument("board", type=Path)
    for name in ("apply", "recover"):
        child = commands.add_parser(name)
        child.add_argument("board", type=Path)
        child.add_argument("updates", type=Path)
        child.add_argument("journal", type=Path)
        if name == "apply":
            child.add_argument("update_id")
        child.add_argument("--timestamp", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "snapshot":
            result = snapshot(args.board)
        elif args.operation == "apply":
            result = apply_update(
                args.board, args.updates, args.journal, args.update_id,
                timestamp=args.timestamp,
            )
        else:
            result = recover(args.board, args.updates, args.journal, timestamp=args.timestamp)
    except AdapterError as error:
        print(canonical_json(_error_receipt(args.operation, error)))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
