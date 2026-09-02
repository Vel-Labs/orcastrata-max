#!/usr/bin/env python3
"""Build a deterministic GitHub umbrella preview from WorkGraph and GoalBuddy truth."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


REQUEST_TYPE = "orcastrata_github_umbrella_projection_request_v1"
RECEIPT_TYPE = "orcastrata_github_umbrella_projection_receipt_v1"
HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 15
MAX_LIST_ITEMS = 100
MAX_TEXT_BYTES = 4096
EFFECT_BOUNDARY = {
    "acceptance_granted": False,
    "authority_granted": False,
    "goalbuddy_mutated": False,
    "github_called": False,
    "github_mutated": False,
    "network_used": False,
    "provider_called": False,
}


class ProjectionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProjectionError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProjectionError("json_duplicate_key")
        value[key] = item
    return value


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProjectionError("shape_invalid", path)
    return value


def _text(value: Any, path: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProjectionError("text_invalid", path)
    return value


def _strings(value: Any, path: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS or (not value and not allow_empty):
        raise ProjectionError("list_invalid", path)
    result = [_text(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise ProjectionError("list_duplicate", path)
    return result


def _target(value: Any) -> dict[str, str]:
    target = _closed(value, {"host", "repository"}, "$.target")
    host = target["host"]
    repository = target["repository"]
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise ProjectionError("host_invalid", "$.target.host")
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise ProjectionError("repository_invalid", "$.target.repository")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise ProjectionError("repository_invalid", "$.target.repository")
    return {"host": host, "repository": repository}


def _workgraph_module() -> Any:
    path = Path(__file__).with_name("workgraph.py")
    spec = importlib.util.spec_from_file_location("orcastrata_projection_workgraph", path)
    if spec is None or spec.loader is None:
        raise ProjectionError("workgraph_runtime_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ProjectionError("workgraph_runtime_unavailable") from exc
    return module


def _workgraph(value: Any) -> tuple[dict[str, Any], dict[str, Mapping[str, Any]]]:
    if not isinstance(value, dict):
        raise ProjectionError("workgraph_invalid", "$.workgraph")
    document = copy.deepcopy(value)
    receipt = _workgraph_module().validate_document(document)
    if receipt.get("status") != "valid":
        raise ProjectionError("workgraph_invalid", "$.workgraph")
    items = document.get("work_items")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise ProjectionError("workgraph_item_count_invalid", "$.workgraph.work_items")
    for index, item in enumerate(items):
        if item.get("clarity_tier") not in {"bounded", "governed"}:
            raise ProjectionError(
                "workgraph_item_not_bounded",
                f"$.workgraph.work_items[{index}].clarity_tier",
            )
    by_id = {item["id"]: item for item in items}
    return document, by_id


def _goalbuddy_snapshot(
    value: Any, work_item_ids: set[str]
) -> tuple[dict[str, Any], dict[str, str]]:
    fields = {
        "active_task", "board_sha256", "canonical_owner", "capabilities",
        "operation", "protocol", "schema_version", "state_schema_version",
        "status", "task_statuses",
    }
    snapshot = _closed(value, fields, "$.goalbuddy_snapshot")
    if (
        snapshot["canonical_owner"] != "GoalBuddy"
        or snapshot["operation"] != "snapshot"
        or snapshot["protocol"] != "workgraph_goalbuddy_adapter"
        or snapshot["schema_version"] != 1
        or snapshot["state_schema_version"] not in {2, 3}
        or snapshot["status"] != "ok"
        or not isinstance(snapshot["board_sha256"], str)
        or not SHA_RE.fullmatch(snapshot["board_sha256"])
    ):
        raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot")
    capabilities = _closed(
        snapshot["capabilities"],
        {
            "apply", "migration_available", "migration_required",
            "pinned_current_schema_version", "recognized_next_schema_version",
            "recover", "snapshot",
        },
        "$.goalbuddy_snapshot.capabilities",
    )
    version = snapshot["state_schema_version"]
    expected_capabilities = {
        "apply": version == 2,
        "migration_available": False,
        "migration_required": version == 3,
        "pinned_current_schema_version": 2,
        "recognized_next_schema_version": 3,
        "recover": version == 2,
        "snapshot": True,
    }
    if capabilities != expected_capabilities:
        raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot.capabilities")
    statuses = snapshot["task_statuses"]
    if not isinstance(statuses, list) or len(statuses) > MAX_ITEMS:
        raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot.task_statuses")
    by_id: dict[str, str] = {}
    for index, raw in enumerate(statuses):
        row = _closed(raw, {"status", "task_id"}, f"$.goalbuddy_snapshot.task_statuses[{index}]")
        task_id = _text(row["task_id"], f"$.goalbuddy_snapshot.task_statuses[{index}].task_id", maximum=256)
        status = row["status"]
        if status not in {"queued", "active", "blocked", "done"} or task_id in by_id:
            raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot.task_statuses")
        by_id[task_id] = status
    if set(by_id) != work_item_ids:
        raise ProjectionError("goalbuddy_workgraph_task_mismatch")
    active_task = snapshot["active_task"]
    if active_task is not None and active_task not in by_id:
        raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot.active_task")
    active_ids = [task_id for task_id, status in by_id.items() if status == "active"]
    if active_ids != ([] if active_task is None else [active_task]):
        raise ProjectionError("goalbuddy_snapshot_invalid", "$.goalbuddy_snapshot.active_task")
    return copy.deepcopy(snapshot), by_id


def _presentation(
    value: Any, work_item_ids: set[str]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    presentation = _closed(value, {"umbrella", "issues"}, "$.presentation")
    raw_umbrella = _closed(
        presentation["umbrella"],
        {"acceptance_criteria", "labels", "non_goals", "outcome", "title"},
        "$.presentation.umbrella",
    )
    umbrella = {
        "acceptance_criteria": _strings(raw_umbrella["acceptance_criteria"], "$.presentation.umbrella.acceptance_criteria"),
        "labels": _strings(raw_umbrella["labels"], "$.presentation.umbrella.labels", allow_empty=True),
        "non_goals": _strings(raw_umbrella["non_goals"], "$.presentation.umbrella.non_goals"),
        "outcome": _text(raw_umbrella["outcome"], "$.presentation.umbrella.outcome"),
        "title": _text(raw_umbrella["title"], "$.presentation.umbrella.title", maximum=256),
    }
    issues = presentation["issues"]
    if not isinstance(issues, list) or len(issues) != len(work_item_ids):
        raise ProjectionError("issue_metadata_mismatch", "$.presentation.issues")
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(issues):
        row = _closed(raw, {"labels", "non_goals", "title", "work_item_id"}, f"$.presentation.issues[{index}]")
        item_id = _text(row["work_item_id"], f"$.presentation.issues[{index}].work_item_id", maximum=256)
        if item_id in by_id:
            raise ProjectionError("issue_metadata_duplicate", f"$.presentation.issues[{index}].work_item_id")
        by_id[item_id] = {
            "labels": _strings(row["labels"], f"$.presentation.issues[{index}].labels", allow_empty=True),
            "non_goals": _strings(row["non_goals"], f"$.presentation.issues[{index}].non_goals"),
            "title": _text(row["title"], f"$.presentation.issues[{index}].title", maximum=256),
        }
    if set(by_id) != work_item_ids:
        raise ProjectionError("issue_metadata_mismatch", "$.presentation.issues")
    return umbrella, by_id


def _bullet(values: list[str]) -> str:
    return "\n".join(f"- {value}" for value in values)


def _marker(kind: str, target: Mapping[str, str], graph_id: str, item_id: str = "umbrella") -> str:
    identity = digest({
        "graph_id": graph_id,
        "host": target["host"],
        "item_id": item_id,
        "kind": kind,
        "repository": target["repository"].lower(),
    })[7:27]
    return f"<!-- orcastrata:{kind}:v1:{identity} -->"


def _issue_body(
    target: Mapping[str, str], graph_id: str, item: Mapping[str, Any],
    metadata: Mapping[str, Any], goalbuddy_status: str,
) -> str:
    relationships = item["relationships"]
    validations = [
        f"`{row['id']}` — {row['instruction']} → {row['expected_result']}"
        for row in item["validation"]
    ]
    read_scope = item["scope"]["read"] or ["None"]
    write_scope = item["scope"]["write"] or ["None"]
    blockers = relationships["blocked_by"] or ["None"]
    return "\n\n".join((
        _marker("issue", target, graph_id, item["id"]),
        f"## Outcome\n{item['objective']}",
        f"## Scope\nRead:\n{_bullet(read_scope)}\n\nWrite:\n{_bullet(write_scope)}",
        f"## Non-goals\n{_bullet(metadata['non_goals'])}",
        f"## Acceptance criteria\n- {item['done_condition']}",
        f"## Validation\n{_bullet(validations)}",
        f"## Dependencies\n{_bullet(blockers)}",
        f"## Stop condition\n{item['stop_rule']}",
        f"## Orcastrata state\n- Work item: `{item['id']}`\n- GoalBuddy status: `{goalbuddy_status}`",
    ))


def _preview(
    target: Mapping[str, str], umbrella: Mapping[str, Any],
    metadata: Mapping[str, Mapping[str, Any]], workgraph: Mapping[str, Any],
    items: Mapping[str, Mapping[str, Any]], statuses: Mapping[str, str],
) -> dict[str, Any]:
    graph_id = workgraph["graph_id"]
    ordered_ids = sorted(items)
    dependency_lines = [
        f"`{item_id}` blocked by " + ", ".join(f"`{blocker}`" for blocker in items[item_id]["relationships"]["blocked_by"])
        for item_id in ordered_ids if items[item_id]["relationships"]["blocked_by"]
    ] or ["No blocked-by dependencies"]
    work_lines = [f"- [ ] `{item_id}` — {metadata[item_id]['title']}" for item_id in ordered_ids]
    umbrella_body = "\n\n".join((
        _marker("umbrella", target, graph_id),
        f"## Outcome\n{umbrella['outcome']}",
        f"## Acceptance criteria\n{_bullet(umbrella['acceptance_criteria'])}",
        f"## Non-goals\n{_bullet(umbrella['non_goals'])}",
        "## Work items\n" + "\n".join(work_lines),
        f"## Dependency order\n{_bullet(dependency_lines)}",
    ))
    issue_previews = []
    for item_id in ordered_ids:
        item = items[item_id]
        blockers = item["relationships"]["blocked_by"]
        ready = statuses[item_id] in {"queued", "active"} and all(
            statuses[blocker] == "done" for blocker in blockers
        )
        issue_previews.append({
            "body": _issue_body(target, graph_id, item, metadata[item_id], statuses[item_id]),
            "dependencies": list(blockers),
            "labels": list(metadata[item_id]["labels"]),
            "ready": ready,
            "stable_id": _marker("issue", target, graph_id, item_id)[4:-4].strip(),
            "title": metadata[item_id]["title"],
            "work_item_id": item_id,
        })
    return {
        "issues": issue_previews,
        "umbrella": {
            "body": umbrella_body,
            "labels": list(umbrella["labels"]),
            "stable_id": _marker("umbrella", target, graph_id)[4:-4].strip(),
            "title": umbrella["title"],
        },
    }


def execute(request: Any) -> dict[str, Any]:
    try:
        envelope = _closed(
            request,
            {"artifact_type", "goalbuddy_snapshot", "presentation", "schema_version", "target", "workgraph"},
            "$",
        )
        if envelope["schema_version"] != 1 or envelope["artifact_type"] != REQUEST_TYPE:
            raise ProjectionError("request_identity_invalid")
        target = _target(envelope["target"])
        workgraph, items = _workgraph(envelope["workgraph"])
        snapshot, statuses = _goalbuddy_snapshot(envelope["goalbuddy_snapshot"], set(items))
        umbrella, metadata = _presentation(envelope["presentation"], set(items))
        preview = _preview(target, umbrella, metadata, workgraph, items, statuses)
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "status": "ok",
            "target": target,
            "canonical_state": {
                "active_task": snapshot["active_task"],
                "board_sha256": snapshot["board_sha256"],
                "owner": "GoalBuddy",
            },
            "graph_id": workgraph["graph_id"],
            "graph_sha256": digest(workgraph),
            "preview": preview,
            "projection_sha256": digest(preview),
            "effect_boundary": dict(EFFECT_BOUNDARY),
        }
    except ProjectionError as error:
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "status": "error",
            "error": {"code": error.code, "path": error.path},
            "effect_boundary": dict(EFFECT_BOUNDARY),
        }
    except Exception:
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "status": "error",
            "error": {"code": "projection_internal_error", "path": "$"},
            "effect_boundary": dict(EFFECT_BOUNDARY),
        }


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        receipt = execute(None)
        receipt["error"] = {"code": "request_too_large", "path": "$"}
    else:
        try:
            request = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ProjectionError):
            request = None
        receipt = execute(request)
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if receipt["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
