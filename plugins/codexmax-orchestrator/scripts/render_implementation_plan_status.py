#!/usr/bin/env python3
"""Render bounded current-task and ledger status projections from GoalBuddy."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Sequence

sys.dont_write_bytecode = True


def _validator():
    path = Path(__file__).with_name("validate_implementation_plan.py")
    spec = importlib.util.spec_from_file_location("codexmax_implementation_plan", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("implementation_plan_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


V = _validator()


def _replace_region(text: str, start: str, end: str, body: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise V.PlanError("plan_projection_markers_invalid")
    if text.find(end) < text.find(start):
        raise V.PlanError("plan_projection_markers_invalid")
    prefix, remainder = text.split(start, 1)
    _, suffix = remainder.split(end, 1)
    return prefix + start + "\n" + body.rstrip() + "\n" + end + suffix


def _render_ledger(rows: list[dict[str, str]], state: dict) -> str:
    display_columns = (
        "ID",
        "Task",
        "Status",
        "Depends on",
        "Unlocks",
        "Parallel mode",
        "Write owner",
        "Gate/proof",
        "Receipt",
    )
    header = "| " + " | ".join(display_columns) + " |"
    divider = "| " + " | ".join("---" for _ in V.LEDGER_COLUMNS) + " |"
    rendered = [header, divider]
    for row in rows:
        task = state["tasks"].get(row["id"])
        if task is None:
            raise V.PlanError(f"plan_board_task_set_mismatch:{row['id']}")
        values = dict(row)
        values["status"] = task["status"]
        rendered.append("| " + " | ".join(values[column] for column in V.LEDGER_COLUMNS) + " |")
    return "\n".join(rendered)


def render(root: Path, plan_path: Path, state_path: Path) -> tuple[str, str]:
    root = V.repository_root(root)
    plan, _ = V.bounded_file(root, plan_path, "plan")
    state_file, _ = V.bounded_file(root, state_path, "state")
    text = V.read_utf8(plan, "plan")
    state = V.parse_state(V.read_utf8(state_file, "state"))
    rows = V.parse_ledger(V.marked_region(text, V.LEDGER_START, V.LEDGER_END, "ledger"))
    if set(row["id"] for row in rows) != set(state["tasks"]):
        raise V.PlanError("plan_board_task_set_mismatch")
    for row in rows:
        task_id = row["id"]
        task = state["tasks"][task_id]
        if not task.get("dependencies_present"):
            raise V.PlanError(f"plan_board_dependencies_missing:{task_id}")
        if sorted(task["dependencies"]) != sorted(V.task_references(row["depends on"])):
            raise V.PlanError(f"plan_board_dependency_mismatch:{task_id}")
    invalid_statuses = [
        (task_id, task["status"])
        for task_id, task in state["tasks"].items()
        if task["status"] not in V.BOARD_STATUSES
    ]
    if invalid_statuses:
        task_id, status = sorted(invalid_statuses)[0]
        raise V.PlanError(f"plan_board_status_invalid:{task_id}:{status}")
    active_rows = [
        task_id
        for task_id, task in state["tasks"].items()
        if task["status"] == "active"
    ]
    if state.get("goal_status") == "active" and len(active_rows) != 1:
        raise V.PlanError("plan_board_active_task_count_invalid")
    active = state.get("active_task")
    if active_rows and active != active_rows[0]:
        raise V.PlanError("plan_board_active_pointer_mismatch")
    if active is not None and active not in state["tasks"]:
        raise V.PlanError("plan_board_active_pointer_unknown")
    if active is None:
        current = "No active task. GoalBuddy has no active-task pointer."
    else:
        row = next(item for item in rows if item["id"] == active)
        current = f"**{active} — {row['task']}**\n\nStatus: `{state['tasks'][active]['status']}`"
    updated = _replace_region(text, V.CURRENT_START, V.CURRENT_END, current)
    updated = _replace_region(
        updated,
        V.LEDGER_START,
        V.LEDGER_END,
        _render_ledger(rows, state),
    )
    return text, updated


def _atomic_write(path: Path, text: str) -> None:
    directory = path.parent
    descriptor, temporary = tempfile.mkstemp(prefix=".implementation-plan-", dir=directory)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        original, updated = render(args.repo_root, args.plan, args.state)
        if args.check:
            status = "in_sync" if original == updated else "drift"
            print(V.canonical_json({"schema_version": 1, "status": status}))
            return 0 if status == "in_sync" else 2
        root = V.repository_root(args.repo_root)
        plan, _ = V.bounded_file(root, args.plan, "plan")
        named = plan.lstat()
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
            raise V.PlanError("plan_alias_forbidden")
        if original != updated:
            _atomic_write(plan, updated)
        print(V.canonical_json({"changed": original != updated, "schema_version": 1, "status": "ok"}))
        return 0
    except (V.PlanError, OSError, RuntimeError) as error:
        print(V.canonical_json({"error": str(error), "schema_version": 1, "status": "error"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
