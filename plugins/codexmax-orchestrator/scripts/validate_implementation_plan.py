#!/usr/bin/env python3
"""Validate a Codexmax implementation plan without mutating it or its board."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
PLAN_MODES = {"document_only", "board_prepared", "execution_authorized"}
PLAN_LIFECYCLES = {"draft", "accepted", "active", "blocked", "done", "superseded"}
EXECUTION_AUTHORITIES = {"not_granted", "granted"}
BOARD_STATUSES = {"queued", "active", "blocked", "done"}
PARALLEL_MODES = {
    "serial",
    "parallel_read_only",
    "parallel_disjoint_write",
    "tandem_handoff",
    "independent_gate",
}
REQUIRED_HEADINGS = (
    "tl;dr",
    "plan identity and lifecycle",
    "selected roadmap sources",
    "current task",
    "high-level task ledger",
    "objective and acceptance oracle",
    "current-state assessment",
    "scope and non-goals",
    "implementation architecture and data flow",
    "critical path and parallel waves",
    "progressive phases and gates",
    "detailed task contracts",
    "validation ladder",
    "risks, blockers, and stop conditions",
    "change-control protocol",
    "handover notes",
    "roadmap-return contract",
    "decision and progress history",
)
LEDGER_COLUMNS = (
    "id",
    "task",
    "status",
    "depends on",
    "unlocks",
    "parallel mode",
    "write owner",
    "gate/proof",
    "receipt",
)
TASK_FIELDS = (
    "objective and rationale",
    "inputs and prerequisites",
    "deliverables",
    "allowed files",
    "excluded files",
    "dependencies and unlocks",
    "parallel mode and write owner",
    "implementation steps",
    "validation commands",
    "acceptance evidence",
    "stop and escalation conditions",
    "rollback or recovery",
    "documentation obligations",
    "next-owner handoff",
)
CURRENT_START = "<!-- codexmax-current-task:start -->"
CURRENT_END = "<!-- codexmax-current-task:end -->"
LEDGER_START = "<!-- codexmax-task-ledger:start -->"
LEDGER_END = "<!-- codexmax-task-ledger:end -->"
TASK_ID_RE = re.compile(r"^T[0-9]{3,}$")


class PlanError(ValueError):
    """A stable input or validation error."""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical)
    )


def repository_root(path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PlanError("repository_root_unavailable") from error
    if (
        not _same_canonical_path(lexical, resolved)
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise PlanError("repository_root_invalid")
    return resolved


def bounded_file(root: Path, candidate: Path, label: str) -> tuple[Path, str]:
    if candidate.is_absolute() or ".." in candidate.parts or "\x00" in str(candidate):
        raise PlanError(f"{label}_path_invalid")
    current = root
    for part in candidate.parts:
        current = current / part
        try:
            named = current.lstat()
        except OSError as error:
            raise PlanError(f"{label}_missing") from error
        if stat.S_ISLNK(named.st_mode):
            raise PlanError(f"{label}_alias_forbidden")
    try:
        resolved = current.resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
        named = current.lstat()
    except (OSError, ValueError) as error:
        raise PlanError(f"{label}_path_invalid") from error
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise PlanError(f"{label}_not_regular")
    return resolved, relative


def read_utf8(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise PlanError(f"{label}_utf8_invalid") from error


def sections(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^(#{1,6})\s+(.+?)\s*$", text))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        level = len(match.group(1))
        name = re.sub(r"\s+", " ", match.group(2).strip().lower())
        if name in result:
            raise PlanError(f"plan_duplicate_heading:{name}")
        end = len(text)
        for later in matches[index + 1 :]:
            if len(later.group(1)) <= level:
                end = later.start()
                break
        result[name] = text[match.end() : end].strip()
    return result


def metadata(text: str) -> dict[str, str]:
    fields = {
        "plan_id": "Plan ID",
        "plan_mode": "Plan Mode",
        "plan_lifecycle": "Plan Lifecycle",
        "execution_authority": "Execution Authority",
        "roadmap_origin": "Roadmap Origin",
    }
    result: dict[str, str] = {}
    for key, label in fields.items():
        match = re.search(rf"(?m)^{re.escape(label)}:\s*`?([^`\n]+?)`?\s*$", text)
        if match is not None:
            result[key] = match.group(1).strip()
    return result


def marked_region(text: str, start: str, end: str, label: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise PlanError(f"plan_{label}_markers_invalid")
    if text.find(end) < text.find(start):
        raise PlanError(f"plan_{label}_markers_invalid")
    before, remainder = text.split(start, 1)
    body, after = remainder.split(end, 1)
    if len(before) + len(body) + len(after) + len(start) + len(end) != len(text):
        raise PlanError(f"plan_{label}_markers_invalid")
    return body.strip()


def _cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def parse_ledger(region: str) -> list[dict[str, str]]:
    lines = [line for line in region.splitlines() if line.strip()]
    if len(lines) < 3:
        raise PlanError("plan_ledger_missing")
    headers = [cell.lower() for cell in _cells(lines[0])]
    if tuple(headers) != LEDGER_COLUMNS:
        raise PlanError("plan_ledger_columns_invalid")
    divider = _cells(lines[1])
    if len(divider) != len(headers) or any(
        re.fullmatch(r":?-{3,}:?", cell) is None for cell in divider
    ):
        raise PlanError("plan_ledger_divider_invalid")
    rows: list[dict[str, str]] = []
    for line in lines[2:]:
        values = _cells(line)
        if len(values) != len(headers):
            raise PlanError("plan_ledger_row_invalid")
        rows.append(dict(zip(headers, values)))
    if not rows:
        raise PlanError("plan_ledger_empty")
    return rows


def task_references(value: str) -> list[str]:
    if value.strip() in {"", "—", "-", "none"}:
        return []
    references = re.findall(r"\bT[0-9]{3,}\b", value)
    for first, last in re.findall(r"\bT([0-9]{3,})\s*[-–—]\s*T?([0-9]{3,})\b", value):
        start = int(first)
        end = int(last)
        if end >= start and end - start <= 1000:
            references.extend(f"T{number:0{len(first)}d}" for number in range(start, end + 1))
    return sorted(set(references))


def detailed_tasks(section: str) -> dict[str, str]:
    matches = list(
        re.finditer(r"(?m)^###\s+(T[0-9]{3,})\s+(?:—|-)\s+(.+?)\s*$", section)
    )
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        task_id = match.group(1)
        if task_id in result:
            raise PlanError(f"plan_task_detail_duplicate:{task_id}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        result[task_id] = section[match.end() : end].strip()
    return result


def cycle_errors(edges: dict[str, list[str]]) -> list[str]:
    errors: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            errors.append(f"plan_dependency_cycle:{node}")
            return
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
    return sorted(set(errors))


def parse_state(text: str) -> dict[str, Any]:
    goal_slug: str | None = None
    goal_status: str | None = None
    active_task: str | None = None
    in_goal = False
    tasks: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    current: str | None = None
    current_field: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise PlanError(f"state_tabs_forbidden:{number}")
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line == "goal:":
            in_goal = True
            current = None
            continue
        if not line.startswith(" "):
            in_goal = False
            current = None
            current_field = None
            match = re.fullmatch(r"active_task:\s*(.+?)\s*", line)
            if match:
                value = match.group(1).strip().strip("'\"")
                active_task = None if value in {"null", "~"} else value
            continue
        if in_goal:
            slug_match = re.fullmatch(r"  slug:\s*(.+?)\s*", line)
            status_match = re.fullmatch(r"  status:\s*(.+?)\s*", line)
            if slug_match:
                goal_slug = slug_match.group(1).strip().strip("'\"")
            if status_match:
                goal_status = status_match.group(1).strip().strip("'\"")
        task_match = re.fullmatch(r"  - id:\s*(.+?)\s*", line)
        if task_match:
            task_id = task_match.group(1).strip().strip("'\"")
            if task_id in tasks:
                raise PlanError(f"state_task_duplicate:{task_id}")
            current = task_id
            order.append(task_id)
            tasks[task_id] = {
                "dependencies": [],
                "dependencies_present": False,
                "receipt_present": False,
                "status": None,
            }
            current_field = None
            continue
        if current is None:
            continue
        field_match = re.fullmatch(r"    ([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*", line)
        if field_match:
            current_field = field_match.group(1)
            value = field_match.group(2).strip()
            if current_field == "status":
                tasks[current]["status"] = value.strip("'\"")
            elif current_field == "receipt":
                tasks[current]["receipt_present"] = value not in {"", "null", "~"}
            elif current_field == "dependencies":
                tasks[current]["dependencies_present"] = True
                if value == "[]":
                    tasks[current]["dependencies"] = []
            continue
        item_match = re.fullmatch(r"      -\s*(.+?)\s*", line)
        if item_match and current_field == "dependencies":
            tasks[current]["dependencies"].append(item_match.group(1).strip().strip("'\""))
        elif line.startswith("      ") and current_field == "receipt":
            tasks[current]["receipt_present"] = True
    return {
        "active_task": active_task,
        "goal_slug": goal_slug,
        "goal_status": goal_status,
        "order": order,
        "tasks": tasks,
    }


def _official_checker(
    checker: Path | None, state: Path, *, required: bool
) -> tuple[dict[str, Any], list[str], list[str]]:
    if checker is None:
        errors = ["official_goalbuddy_checker_required"] if required else []
        warnings = [] if required else ["official_goalbuddy_checker_not_run"]
        return {"status": "not_run"}, errors, warnings
    try:
        named = checker.lstat()
        resolved = checker.resolve(strict=True)
    except OSError:
        return {"status": "failed", "reason": "checker_unavailable"}, [
            "official_goalbuddy_checker_unavailable"
        ], []
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        return {"status": "failed", "reason": "checker_alias_forbidden"}, [
            "official_goalbuddy_checker_alias_forbidden"
        ], []
    completed = subprocess.run(
        ["node", str(resolved), str(state)],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = {"status": "failed", "reason": "checker_output_invalid"}
    if completed.returncode != 0 or not isinstance(payload, dict) or payload.get("ok") is not True:
        return payload, ["official_goalbuddy_checker_failed"], []
    return payload, [], []


def validate(
    root: Path,
    plan_path: Path,
    state_path: Path | None = None,
    *,
    checker: Path | None = None,
) -> dict[str, Any]:
    root = repository_root(root)
    plan, plan_relative = bounded_file(root, plan_path, "plan")
    plan_text = read_utf8(plan, "plan")
    errors: list[str] = []
    warnings: list[str] = []
    try:
        plan_sections = sections(plan_text)
        plan_metadata = metadata(plan_text)
        current_region = marked_region(plan_text, CURRENT_START, CURRENT_END, "current_task")
        ledger_region = marked_region(plan_text, LEDGER_START, LEDGER_END, "ledger")
        ledger = parse_ledger(ledger_region)
    except PlanError as error:
        raise error

    for heading in REQUIRED_HEADINGS:
        if not plan_sections.get(heading, "").strip():
            errors.append(f"plan_required_section_missing:{heading}")
    for field in (
        "plan_id",
        "plan_mode",
        "plan_lifecycle",
        "execution_authority",
        "roadmap_origin",
    ):
        if not plan_metadata.get(field):
            errors.append(f"plan_metadata_missing:{field}")
    mode = plan_metadata.get("plan_mode")
    authority = plan_metadata.get("execution_authority")
    if mode not in PLAN_MODES:
        errors.append("plan_mode_invalid")
    if plan_metadata.get("plan_lifecycle") not in PLAN_LIFECYCLES:
        errors.append("plan_lifecycle_invalid")
    if authority not in EXECUTION_AUTHORITIES:
        errors.append("plan_execution_authority_invalid")
    if mode == "execution_authorized" and authority != "granted":
        errors.append("plan_execution_authority_missing")
    if mode in {"document_only", "board_prepared"} and authority != "not_granted":
        errors.append("plan_execution_authority_overstated")

    ledger_ids = [row["id"] for row in ledger]
    if len(set(ledger_ids)) != len(ledger_ids):
        errors.append("plan_ledger_task_duplicate")
    for task_id in ledger_ids:
        if TASK_ID_RE.fullmatch(task_id) is None:
            errors.append(f"plan_task_id_invalid:{task_id}")
    known = set(ledger_ids)
    edges: dict[str, list[str]] = {}
    unlock_edges: dict[str, list[str]] = {}
    for row in ledger:
        dependencies = task_references(row["depends on"])
        unlocks = task_references(row["unlocks"])
        edges[row["id"]] = dependencies
        unlock_edges[row["id"]] = unlocks
        for reference in dependencies + unlocks:
            if reference not in known:
                errors.append(f"plan_task_reference_unknown:{row['id']}:{reference}")
        if row["id"] in dependencies:
            errors.append(f"plan_task_dependency_self:{row['id']}")
        if row["parallel mode"] not in PARALLEL_MODES:
            errors.append(f"plan_parallel_mode_invalid:{row['id']}")
        if row["parallel mode"] == "parallel_disjoint_write" and row["write owner"] in {"", "—", "-"}:
            errors.append(f"plan_parallel_write_owner_missing:{row['id']}")
    for task_id, dependencies in edges.items():
        for dependency in dependencies:
            if task_id not in unlock_edges.get(dependency, []):
                errors.append(f"plan_unlock_mismatch:{dependency}:{task_id}")
    for task_id, unlocks in unlock_edges.items():
        for unlocked in unlocks:
            if task_id not in edges.get(unlocked, []):
                errors.append(f"plan_unlock_mismatch:{task_id}:{unlocked}")
    errors.extend(cycle_errors(edges))

    detail_section = plan_sections.get("detailed task contracts", "")
    details = detailed_tasks(detail_section) if detail_section else {}
    if set(details) != known:
        for task_id in sorted(known - set(details)):
            errors.append(f"plan_task_detail_missing:{task_id}")
        for task_id in sorted(set(details) - known):
            errors.append(f"plan_task_detail_orphan:{task_id}")
    for task_id, body in details.items():
        lowered = body.lower()
        for field in TASK_FIELDS:
            if re.search(rf"\*\*{re.escape(field)}:\*\*\s*\S", lowered) is None:
                errors.append(f"plan_task_field_missing:{task_id}:{field}")

    state_source: dict[str, str] | None = None
    state: dict[str, Any] | None = None
    official: dict[str, Any] = {"status": "not_applicable"}
    board_mode = mode in {"board_prepared", "execution_authorized"}
    if mode == "document_only":
        if state_path is not None:
            errors.append("plan_document_only_state_forbidden")
        if any(row["status"] != "planned" for row in ledger):
            errors.append("plan_document_only_status_invalid")
        if re.search(r"\bT[0-9]{3,}\b", current_region):
            errors.append("plan_document_only_active_task_forbidden")
    elif board_mode:
        if state_path is None:
            errors.append("plan_board_state_required")
        else:
            state_file, state_relative = bounded_file(root, state_path, "state")
            state_text = read_utf8(state_file, "state")
            state = parse_state(state_text)
            state_source = {"path": state_relative, "sha256": _sha256(state_file)}
            state_ids = set(state["tasks"])
            if state.get("goal_slug") != plan_metadata.get("plan_id"):
                errors.append("plan_board_identity_mismatch")
            if state_ids != known:
                errors.append("plan_board_task_set_mismatch")
            active_rows = [
                task_id
                for task_id, task in state["tasks"].items()
                if task["status"] == "active"
            ]
            if state.get("goal_status") == "active" and len(active_rows) != 1:
                errors.append("plan_board_active_task_count_invalid")
            if active_rows and state.get("active_task") != active_rows[0]:
                errors.append("plan_board_active_pointer_mismatch")
            if state.get("active_task") and state["active_task"] not in current_region:
                errors.append("board_valid_plan_mirror_drift:current_task")
            ledger_by_id = {row["id"]: row for row in ledger}
            for task_id, task in state["tasks"].items():
                status = task["status"]
                if status not in BOARD_STATUSES:
                    errors.append(f"plan_board_status_invalid:{task_id}:{status}")
                if task_id in ledger_by_id and ledger_by_id[task_id]["status"] != status:
                    errors.append(f"board_valid_plan_mirror_drift:status:{task_id}")
                if status in {"done", "blocked"}:
                    if not task["receipt_present"]:
                        errors.append(f"plan_board_receipt_missing:{task_id}")
                    if task_id in ledger_by_id and ledger_by_id[task_id]["receipt"] in {"", "—", "-"}:
                        errors.append(f"plan_ledger_receipt_missing:{task_id}")
                state_dependencies = task.get("dependencies", [])
                if not task.get("dependencies_present"):
                    errors.append(f"plan_board_dependencies_missing:{task_id}")
                if sorted(state_dependencies) != sorted(edges.get(task_id, [])):
                    errors.append(f"plan_board_dependency_mismatch:{task_id}")
            done_ids = [
                task_id
                for task_id, task in state["tasks"].items()
                if task["status"] == "done"
            ]
            handover = plan_sections.get("handover notes", "")
            for task_id in done_ids:
                if task_id not in handover:
                    errors.append(f"plan_handover_missing:{task_id}")
            if done_ids and "newly unblocked" not in handover.lower():
                errors.append("plan_handover_unblocked_missing")
            official, checker_errors, checker_warnings = _official_checker(
                checker,
                state_file,
                required=mode == "execution_authorized",
            )
            errors.extend(checker_errors)
            warnings.extend(checker_warnings)

    return {
        "errors": sorted(set(errors)),
        "mode": mode,
        "official_goalbuddy_checker": official,
        "plan_id": plan_metadata.get("plan_id"),
        "schema_version": SCHEMA_VERSION,
        "sources": {
            "plan": {"path": plan_relative, "sha256": _sha256(plan)},
            "state": state_source,
        },
        "status": "valid" if not errors else "invalid",
        "task_count": len(ledger),
        "warnings": sorted(set(warnings)),
    }


def audit_existing(root: Path, plan_path: Path, state_path: Path) -> dict[str, Any]:
    """Audit a pre-contract plan and board without requiring template migration."""
    root = repository_root(root)
    plan, plan_relative = bounded_file(root, plan_path, "plan")
    state_file, state_relative = bounded_file(root, state_path, "state")
    plan_text = read_utf8(plan, "plan")
    state_text = read_utf8(state_file, "state")
    parsed_state = parse_state(state_text)
    errors: list[str] = []
    warnings: list[str] = ["existing_plan_audit_only:no_rewrite"]
    recommendations: list[str] = []

    for task_id, task in parsed_state["tasks"].items():
        status = task["status"]
        if status not in BOARD_STATUSES:
            errors.append(f"plan_board_status_invalid:{task_id}:{status}")
            if status == "completed":
                recommendations.append(
                    f"Replace noncanonical state status `completed` with GoalBuddy "
                    f"`done` for {task_id}, then add the required canonical receipt "
                    "shape and rerun the official checker."
                )
        if status in {"done", "blocked"} and not task["receipt_present"]:
            errors.append(f"plan_board_receipt_missing:{task_id}")

    try:
        plan_sections = sections(plan_text)
    except PlanError as error:
        errors.append(str(error))
        plan_sections = {}
    current = plan_sections.get("current task", "")
    active = parsed_state.get("active_task")
    if active and active not in current:
        errors.append("board_valid_plan_mirror_drift:current_task")
        recommendations.append(
            f"Update the Current Task section from canonical `active_task: {active}`."
        )

    table_section = (
        plan_sections.get("high-level task board")
        or plan_sections.get("high-level task ledger")
        or ""
    )
    legacy_rows: dict[str, dict[str, str]] = {}
    legacy_headers: list[str] = []
    for line in table_section.splitlines():
        values = _cells(line)
        lowered = [value.lower() for value in values]
        if values and not legacy_headers and (
            "status" in lowered
            and any(column in lowered for column in ("id", "task"))
        ):
            legacy_headers = lowered
            continue
        if values and legacy_headers and TASK_ID_RE.fullmatch(values[0]):
            legacy_rows[values[0]] = dict(zip(legacy_headers, values))
    if legacy_rows and set(legacy_rows) != set(parsed_state["tasks"]):
        errors.append("plan_board_task_set_mismatch")
    dependency_state_available = any(
        task.get("dependencies_present") for task in parsed_state["tasks"].values()
    )
    dependency_projection_present = False
    for task_id, row in legacy_rows.items():
        cell = row.get("status", "")
        state_status = parsed_state["tasks"][task_id]["status"]
        tokens = re.findall(r"\b(?:queued|active|blocked|done|completed)\b", cell.lower())
        if tokens and tokens[0] != state_status:
            errors.append(f"board_valid_plan_mirror_drift:status:{task_id}")
        if "completed" in tokens:
            recommendations.append(
                f"Render {task_id} with canonical ledger status `done`; keep the "
                "completion date and receipt in separate evidence text."
            )
        dependency_cell = row.get("depends on", row.get("gate or dependency", ""))
        plan_dependencies = task_references(dependency_cell)
        state_dependencies = parsed_state["tasks"][task_id].get("dependencies", [])
        dependency_projection_present = dependency_projection_present or bool(
            plan_dependencies
        )
        if plan_dependencies and parsed_state["tasks"][task_id].get("dependencies_present"):
            if sorted(plan_dependencies) != sorted(state_dependencies):
                errors.append(f"plan_board_dependency_mismatch:{task_id}")
                recommendations.append(
                    f"Synchronize {task_id} dependency references with canonical "
                    "`state.yaml`."
                )
        elif state_dependencies and dependency_cell.strip() not in {"", "—", "-", "none", "None"}:
            warnings.append(f"existing_plan_dependency_unverifiable:{task_id}")
    if dependency_projection_present and not dependency_state_available:
        warnings.append("existing_plan_dependency_state_unavailable")
        recommendations.append(
            "The legacy board has no explicit dependency fields; compare the "
            "human dependency column with canonical WorkGraph state before repair."
        )

    handover = plan_sections.get("handover notes", "")
    for task_id, task in parsed_state["tasks"].items():
        if task["status"] == "done" and task_id not in handover:
            errors.append(f"plan_handover_missing:{task_id}")
    if any(task["status"] == "done" for task in parsed_state["tasks"].values()):
        if "newly unblocked" not in handover.lower():
            errors.append("plan_handover_unblocked_missing")

    for heading in REQUIRED_HEADINGS:
        if not plan_sections.get(heading):
            warnings.append(f"existing_plan_contract_section_missing:{heading}")
    if CURRENT_START not in plan_text or CURRENT_END not in plan_text:
        warnings.append("existing_plan_current_task_markers_missing")
    if LEDGER_START not in plan_text or LEDGER_END not in plan_text:
        warnings.append("existing_plan_ledger_markers_missing")
    recommendations.append(
        "Adopt the implementation-planning metadata and bounded projection markers "
        "only through a separately authorized migration."
    )
    return {
        "errors": sorted(set(errors)),
        "mode": "audit_existing",
        "plan_id": parsed_state.get("goal_slug"),
        "recommendations": sorted(set(recommendations)),
        "schema_version": SCHEMA_VERSION,
        "sources": {
            "plan": {"path": plan_relative, "sha256": _sha256(plan)},
            "state": {"path": state_relative, "sha256": _sha256(state_file)},
        },
        "status": "compatible" if not errors else "needs_revision",
        "task_count": len(parsed_state["tasks"]),
        "warnings": sorted(set(warnings)),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--goalbuddy-checker", type=Path)
    parser.add_argument("--audit-existing", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.audit_existing:
            if args.state is None:
                raise PlanError("audit_existing_state_required")
            result = audit_existing(args.repo_root, args.plan, args.state)
        else:
            result = validate(
                args.repo_root,
                args.plan,
                args.state,
                checker=args.goalbuddy_checker,
            )
    except PlanError as error:
        result = {
            "error": str(error),
            "schema_version": SCHEMA_VERSION,
            "status": "error",
        }
    print(canonical_json(result))
    return 0 if result.get("status") in {"valid", "compatible"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
