#!/usr/bin/env python3
"""Project-scoped, used-only usage projection over the DispatchLedger."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import stat
import sys
from typing import Any

import orcastrata_project

LEDGER_RELATIVE = Path(".orcastrata/usage/dispatch.jsonl")
TOKEN_FIELDS = (
    "input_tokens", "cached_input_tokens", "output_tokens",
    "reasoning_output_tokens", "total_tokens",
)
NOTICE = "Additional configured models were available, but were not used or called."
ACCOUNTING_SCOPE = "orcastrata_admitted_executions"
ACCOUNTED = "accounted"
UNACCOUNTED = "unaccounted"
UNKNOWN_STATUS = "unknown"
MAX_IMPORT_LINES = 10_000
MAX_IMPORT_LINE_BYTES = 1 * 1024 * 1024
MAX_IMPORT_BYTES = 16 * 1024 * 1024
TOKEN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,63})$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _unknown(reason: str = "not_reported") -> dict[str, str]:
    return {"value": "unknown", "reason": reason}


def _value(value: Any, *, reason: str = "not_reported") -> Any:
    if isinstance(value, dict) and "value" in value:
        value = value["value"]
    if type(value) is int and value >= 0:
        return value
    return _unknown(reason)


def _tokens(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {field: _unknown("not_reported") for field in TOKEN_FIELDS}
    result: dict[str, Any] = {}
    for field in TOKEN_FIELDS:
        source = raw.get(field)
        if field == "reasoning_output_tokens" and source is None:
            source = raw.get("reasoning_tokens")
        value = _value(source, reason="provider_not_reported")
        result[field] = value if isinstance(value, dict) else {"value": value, "reason": "provider_reported"}
    return result


def _manifest_usage(manifest: dict[str, Any]) -> tuple[dict[str, Any], str]:
    usage = manifest.get("usage")
    if not isinstance(usage, dict):
        return _tokens(None), "not_reported"
    raw_tokens = usage.get("tokens")
    reason = raw_tokens.get("reason", "provider_not_reported") if isinstance(raw_tokens, dict) else "provider_not_reported"
    return _tokens(raw_tokens.get("value") if isinstance(raw_tokens, dict) else raw_tokens), reason


def _safe_route(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    fields = ("route_name", "route_id", "provider", "model", "runtime", "billing", "reasoning", "tool")
    return {field: value[field] for field in fields if isinstance(value.get(field), (str, int, bool))}


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _host_measurement(value: Any, *, missing_reason: str = "host_counter_missing") -> dict[str, Any]:
    if type(value) is int and value >= 0:
        return {"value": value, "reason": "host_observed", "provenance": "observed"}
    return {"value": "unknown", "reason": missing_reason, "provenance": "unknown"}


def _host_tokens(raw: Any) -> dict[str, Any]:
    usage = raw if isinstance(raw, dict) else {}
    aliases = {
        "input_tokens": ("input_tokens",),
        "cached_input_tokens": ("cached_input_tokens",),
        "output_tokens": ("output_tokens",),
        "reasoning_output_tokens": ("reasoning_output_tokens", "reasoning_tokens"),
        "total_tokens": ("total_tokens",),
    }
    result: dict[str, Any] = {}
    for field, names in aliases.items():
        found = next((usage[name] for name in names if name in usage), None)
        result[field] = _host_measurement(
            found,
            missing_reason=("host_counter_invalid" if field in usage or any(name in usage for name in names)
                            else "host_counter_missing"),
        )
    input_value = result["input_tokens"]["value"]
    output_value = result["output_tokens"]["value"]
    if (
        result["total_tokens"]["value"] == "unknown"
        and type(input_value) is int
        and type(output_value) is int
    ):
        result["total_tokens"] = {
            "value": input_value + output_value,
            "reason": "input_plus_output",
            "provenance": "derived",
            "method": "input_plus_output",
        }
    return result


def _token(value: Any, fallback: str) -> str:
    if isinstance(value, str) and TOKEN.fullmatch(value):
        return value
    return fallback


def _source_lines(source: Any):
    if hasattr(source, "readline"):
        while True:
            line = source.readline(MAX_IMPORT_LINE_BYTES + 1)
            if line in (b"", ""):
                return
            yield line
        return
    try:
        iterator = iter(source)
    except TypeError as exc:
        raise orcastrata_project.ProjectError("usage_import_source_invalid") from exc
    yield from iterator


def import_codex_exec_json(
    project_root: str | Path,
    task_id: str,
    source: Any,
) -> dict[str, Any]:
    """Import only bounded ``turn.completed`` usage from a Codex JSON stream.

    The stream is hashed and discarded line by line. No prompt, response,
    command, stdout, stderr, or transcript content is written to the ledger.
    The project must already be initialized and the task ID is explicit.
    """
    if not isinstance(task_id, str) or not TOKEN.fullmatch(task_id):
        raise orcastrata_project.ProjectError("usage_import_task_id_invalid")
    project = orcastrata_project.find_nearest(project_root)
    if project is None:
        raise orcastrata_project.ProjectError("usage_import_project_not_initialized")
    project_id = project["manifest"]["project_id"]
    digest = hashlib.sha256()
    import_timestamp = _timestamp()
    line_count = 0
    byte_count = 0
    completed: list[dict[str, Any]] = []
    for raw_line in _source_lines(source):
        if isinstance(raw_line, str):
            encoded = raw_line.encode("utf-8")
        elif isinstance(raw_line, bytes):
            encoded = raw_line
        else:
            raise orcastrata_project.ProjectError("usage_import_line_invalid")
        line_count += 1
        byte_count += len(encoded)
        if line_count > MAX_IMPORT_LINES or len(encoded) > MAX_IMPORT_LINE_BYTES or byte_count > MAX_IMPORT_BYTES:
            raise orcastrata_project.ProjectError("usage_import_bounds_exceeded")
        digest.update(encoded)
        try:
            event = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise orcastrata_project.ProjectError("usage_import_json_invalid") from exc
        if not isinstance(event, dict) or event.get("type") != "turn.completed":
            continue
        if len(completed) >= MAX_IMPORT_LINES:
            raise orcastrata_project.ProjectError("usage_import_turns_exceeded")
        action_id = _token(
            event.get("action_id") or event.get("turn_id") or event.get("id"),
            f"turn-{len(completed) + 1}",
        )
        direct_timestamp = event.get("timestamp") or event.get("completed_at")
        try:
            datetime.strptime(direct_timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            direct_timestamp = import_timestamp
        completed.append({
            "action_id": action_id,
            "timestamp": direct_timestamp,
            "tokens": _host_tokens(event.get("usage")),
        })
        del event
    source_sha256 = "sha256:" + digest.hexdigest()
    if not completed:
        return {
            "status": "imported",
            "work_status": UNKNOWN_STATUS,
            "accounting_status": UNKNOWN_STATUS,
            "accounting_scope": ACCOUNTING_SCOPE,
            "project_id": project_id,
            "task_id": task_id,
            "completed_turns": 0,
            "appended": 0,
            "idempotent": 0,
            "source_sha256": source_sha256,
            "source_line_count": line_count,
            "source_bytes": byte_count,
        }
    ledger_path = _project_usage_ledger_path(project)
    import dispatch_ledger
    events: list[dict[str, Any]] = []
    for turn in completed:
        action_id = turn["action_id"]
        event = {
            "schema_version": 1,
            "event_id": _digest([project_id, task_id, action_id]),
            "event_type": "dispatch_finished",
            "timestamp": turn["timestamp"],
            "goal_id": "orcastrata:" + project_id,
            "checkpoint_id": "host_native_usage",
            "task_id": task_id,
            "assignment_id": f"{task_id}:{action_id}",
            "envelope_sha256": _digest([project_id, task_id, action_id]),
            "config_sha256": "sha256:" + "0" * 64,
            "board_sha256": "sha256:" + "0" * 64,
            "route": {
                "route_name": "host_native",
                "runtime": "Codex",
                "tool": "Codex",
                # The host stream does not independently attest model identity.
                "model": "unknown",
            },
            "lease": {},
            "accounting": {
                "project_id": project_id,
                "observed_tokens": turn["tokens"]["total_tokens"]["value"],
                "observed_cost": _unknown("host_cost_not_reported"),
                "token_usage": turn["tokens"],
                "usage_source": "host_codex_exec_json",
                "accounting_status": ACCOUNTED,
                "accounting_scope": ACCOUNTING_SCOPE,
                "accounting_method": "bounded_native_import",
            },
            "evidence": {
                "project_id": project_id,
                "task_id": task_id,
                "action_id": action_id,
                "execution_owner": "host_native",
                "work_status": "completed",
                "dispatch_status": "completed",
                "import_acceptance": "accepted_bounded",
                "lifecycle": "completed_only",
                "external_call_performed": "unknown",
                "source_sha256": source_sha256,
                "source_line_count": line_count,
                "source_bytes": byte_count,
                "source_turn_index": len(events) + 1,
            },
        }
        events.append(event)
    result = dispatch_ledger.append_events_idempotent(ledger_path, events)
    return {
        "status": "imported",
        "work_status": "completed",
        "accounting_status": ACCOUNTED,
        "accounting_scope": ACCOUNTING_SCOPE,
        "project_id": project_id,
        "task_id": task_id,
        "completed_turns": len(completed),
        "appended": result["appended"],
        "idempotent": result["idempotent"],
        "source_sha256": source_sha256,
        "source_line_count": line_count,
        "source_bytes": byte_count,
    }


def _safe_ledger_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return path
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise orcastrata_project.ProjectError("ledger_unreadable") from exc
    if resolved != path or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise orcastrata_project.ProjectError("ledger_unsafe")
    return path


def _project_usage_ledger_path(project: dict[str, Any]) -> Path:
    """Resolve the configured ledger without following an ancestor alias."""
    root = project.get("project_root")
    if not isinstance(root, Path):
        raise orcastrata_project.ProjectError("ledger_unsafe")
    try:
        named_root = root.lstat()
        if (
            stat.S_ISLNK(named_root.st_mode)
            or not stat.S_ISDIR(named_root.st_mode)
            or root.resolve(strict=True) != root
        ):
            raise orcastrata_project.ProjectError("ledger_unsafe")
    except OSError as exc:
        raise orcastrata_project.ProjectError("ledger_unsafe") from exc

    parent = root
    for component in LEDGER_RELATIVE.parts[:-1]:
        parent = parent / component
        try:
            named = parent.lstat()
        except FileNotFoundError:
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise orcastrata_project.ProjectError("ledger_unsafe") from exc
            try:
                named = parent.lstat()
            except OSError as exc:
                raise orcastrata_project.ProjectError("ledger_unsafe") from exc
        except OSError as exc:
            raise orcastrata_project.ProjectError("ledger_unsafe") from exc
        try:
            resolved = parent.resolve(strict=True)
        except OSError as exc:
            raise orcastrata_project.ProjectError("ledger_unsafe") from exc
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or resolved != parent
        ):
            raise orcastrata_project.ProjectError("ledger_unsafe")
    return parent / LEDGER_RELATIVE.parts[-1]


def _validate_month(month: str | None) -> None:
    if month is not None and (
        not isinstance(month, str) or len(month) != 7 or month[4] != "-"
        or not month[:4].isdigit() or not month[5:].isdigit()
        or not 1 <= int(month[5:]) <= 12
    ):
        raise orcastrata_project.ProjectError("month_invalid")


def append_dispatch_manifest(project_root: str | Path, manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Append one metadata-only dispatch result when the project is initialized."""
    # A preview or a rejected/non-started dispatch is not a used lane. The
    # runner supplies this explicit provider-start fact only after a process
    # was authorized and started.
    if manifest.get("external_call_performed") is not True:
        return None
    project = orcastrata_project.find_nearest(project_root)
    if project is None:
        return None
    project_manifest = project["manifest"]
    project_id = project_manifest["project_id"]
    dispatch_id = manifest.get("dispatch_id")
    if not isinstance(dispatch_id, str) or not dispatch_id:
        raise orcastrata_project.ProjectError("usage_dispatch_id_invalid")
    tokens, usage_reason = _manifest_usage(manifest)
    selected = _safe_route(manifest.get("selected_route"))
    if not selected and isinstance(manifest.get("attempts"), list) and manifest["attempts"]:
        last_attempt = manifest["attempts"][-1]
        selected = _safe_route(last_attempt.get("identity"))
        if isinstance(last_attempt.get("route_name"), str):
            selected["route_name"] = last_attempt["route_name"]
    accounting = {
        "project_id": project_id,
        "observed_tokens": tokens["total_tokens"]["value"],
        "observed_cost": _value((manifest.get("usage") or {}).get("cost")),
        "token_usage": tokens,
        "usage_source": usage_reason,
        # This row is written only through the managed append boundary. If the
        # append fails, no accounted row exists and the runner reports that
        # failure separately from work status.
        "accounting_status": ACCOUNTED,
        "accounting_scope": ACCOUNTING_SCOPE,
        "accounting_method": "managed_ledger_append",
    }
    attempts = manifest.get("attempts")
    provider_started_unknown = manifest.get("status") == "execution_unknown" or (
        isinstance(attempts, list) and any(
            isinstance(attempt, dict) and attempt.get("outcome") == "execution_unknown"
            for attempt in attempts
        )
    )
    event = {
        "schema_version": 1,
        "event_id": _digest([project_id, dispatch_id]),
        "event_type": "execution_unknown" if provider_started_unknown else "dispatch_finished",
        "timestamp": _timestamp(),
        "goal_id": "orcastrata:" + project_id,
        "checkpoint_id": str(manifest.get("semantic_role", "dispatch")),
        "task_id": dispatch_id,
        "assignment_id": str(manifest.get("supervisor_assignment_id", dispatch_id)),
        "envelope_sha256": _digest({"dispatch_id": dispatch_id}),
        "config_sha256": str(manifest.get("effective_config_sha256", "sha256:" + "0" * 64)),
        "board_sha256": "sha256:" + "0" * 64,
        "route": selected,
        "lease": {},
        "accounting": accounting,
        "evidence": {
            "project_id": project_id,
            "dispatch_status": manifest.get("status", "unknown"),
            "work_status": manifest.get("work_status", manifest.get("status", "unknown")),
            "execution_owner": "orcastrata_managed",
            "external_call_performed": manifest.get("external_call_performed", "unknown"),
            "manifest_sha256": _digest(manifest),
        },
    }
    ledger_path = _project_usage_ledger_path(project)
    import dispatch_ledger
    return dispatch_ledger.append_event(ledger_path, event)


def _sum_field(rows: list[dict[str, Any]], field: str) -> Any:
    values = [row["accounting"].get("token_usage", {}).get(field, {}).get("value") for row in rows]
    numeric = [value for value in values if type(value) is int and value >= 0]
    return sum(numeric) if len(numeric) == len(values) and values else _unknown("one_or_more_unknown")


def _accounting_status(row: dict[str, Any]) -> str:
    accounting = row.get("accounting") if isinstance(row.get("accounting"), dict) else {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    owner = evidence.get("execution_owner")
    method = accounting.get("accounting_method")
    managed_evidence_valid = (
        evidence.get("external_call_performed") is True
        and isinstance(evidence.get("manifest_sha256"), str)
        and SHA256.fullmatch(evidence["manifest_sha256"]) is not None
    )
    native_evidence_valid = (
        evidence.get("import_acceptance") == "accepted_bounded"
        and evidence.get("lifecycle") == "completed_only"
        and isinstance(evidence.get("source_sha256"), str)
        and SHA256.fullmatch(evidence["source_sha256"]) is not None
        and isinstance(evidence.get("task_id"), str)
        and TOKEN.fullmatch(evidence["task_id"]) is not None
        and evidence["task_id"] == row.get("task_id")
        and isinstance(evidence.get("action_id"), str)
        and TOKEN.fullmatch(evidence["action_id"]) is not None
    )
    if (
        accounting.get("accounting_scope") == ACCOUNTING_SCOPE
        and accounting.get("accounting_status") == ACCOUNTED
        and (
            owner == "orcastrata_managed"
            and method == "managed_ledger_append"
            and managed_evidence_valid
            or owner == "host_native"
            and method == "bounded_native_import"
            and native_evidence_valid
        )
    ):
        return ACCOUNTED
    if accounting.get("accounting_status") == UNACCOUNTED:
        return UNACCOUNTED
    return UNKNOWN_STATUS


def _coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [_accounting_status(row) for row in rows]
    accounted = statuses.count(ACCOUNTED)
    unaccounted = statuses.count(UNACCOUNTED)
    unknown = statuses.count(UNKNOWN_STATUS)
    return {
        "scope": ACCOUNTING_SCOPE,
        "admitted_executions": len(statuses),
        "accounted_executions": accounted,
        "unaccounted_executions": unaccounted,
        "unknown_executions": unknown,
        "complete": unaccounted == 0 and unknown == 0,
    }


def readout(ledger_path: str | Path, *, project_id: str | None = None, month: str | None = None) -> dict[str, Any]:
    import dispatch_ledger
    _validate_month(month)
    verified = dispatch_ledger.verify_ledger(_safe_ledger_path(ledger_path))
    rows = []
    for row in verified["rows"]:
        if row["event_type"] not in {"dispatch_finished", "execution_unknown"}:
            continue
        if project_id and row["accounting"].get("project_id") != project_id:
            continue
        if month and not row["timestamp"].startswith(month):
            continue
        rows.append(row)
    entries: list[dict[str, Any]] = []
    for row in rows:
        route = row["route"]
        accounting_status = _accounting_status(row)
        entries.append({
            "event_id": row["event_id"],
            "project_id": row["accounting"].get("project_id", project_id or "unknown"),
            "ask_id": row["task_id"],
            "action_id": row["evidence"].get("action_id", row["task_id"]),
            "tool": route.get("tool", route.get("provider", "unknown")),
            "model": route.get("model", "unknown"),
            "route": route.get("route_name", route.get("route_id", "unknown")),
            "status": row["evidence"].get("dispatch_status", row["event_type"]),
            "work_status": row["evidence"].get("work_status", row["evidence"].get("dispatch_status", row["event_type"])),
            "accounting_status": accounting_status,
            "execution_owner": row["evidence"].get("execution_owner", "unknown"),
            "usage": row["accounting"].get("token_usage", {field: _unknown() for field in TOKEN_FIELDS}),
            "usage_source": row["accounting"].get("usage_source", "unknown"),
        })
    return {
        "schema_version": 1,
        "project_id": project_id or "unknown",
        "month": month or "all",
        "used_lanes": entries,
        "used_asks": len(entries),
        "used_actions": len(entries),
        "totals": {
            field: _sum_field(
                [row for row in rows if _accounting_status(row) == ACCOUNTED], field
            )
            for field in TOKEN_FIELDS
        },
        "accounting_coverage": _coverage(rows),
        "unknowns": ["host_native_collaboration_usage_unaccounted"],
        "unused_notice": NOTICE,
        "ledger_event_count": verified["event_count"],
        "proof_boundary": "local_dispatch_ledger_metadata_only",
    }


def workspace_readout(workspace_root: str | Path, *, month: str | None = None) -> dict[str, Any]:
    """Aggregate only the ledgers named by an explicit workspace registry."""
    _validate_month(month)
    root = orcastrata_project._root(workspace_root)
    registry = orcastrata_project.registered_projects(root)
    lanes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    project_summaries: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    for project in registry["projects"]:
        project_id = project["project_id"]
        ledger = root / project["root"] / LEDGER_RELATIVE
        project_summary = {"project_id": project_id, "root": project["root"], "used_asks": 0}
        project_summaries.append(project_summary)
        if not ledger.is_file():
            continue
        summary = readout(ledger, project_id=project_id, month=month)
        project_summary["used_asks"] = summary["used_asks"]
        coverage_rows.append(summary["accounting_coverage"])
        for lane in summary["used_lanes"]:
            key = (project_id, str(lane.get("event_id", lane.get("ask_id", "unknown"))))
            if key in seen:
                continue
            seen.add(key)
            lanes.append(lane)
    totals: dict[str, Any] = {}
    for field in TOKEN_FIELDS:
        values = [
            lane["usage"].get(field, {}).get("value")
            for lane in lanes if lane.get("accounting_status") == ACCOUNTED
        ]
        numeric = [value for value in values if type(value) is int and value >= 0]
        totals[field] = sum(numeric) if values and len(numeric) == len(values) else _unknown("one_or_more_unknown")
    coverage = {
        "scope": ACCOUNTING_SCOPE,
        "admitted_executions": sum(row["admitted_executions"] for row in coverage_rows),
        "accounted_executions": sum(row["accounted_executions"] for row in coverage_rows),
        "unaccounted_executions": sum(row["unaccounted_executions"] for row in coverage_rows),
        "unknown_executions": sum(row["unknown_executions"] for row in coverage_rows),
    }
    coverage["complete"] = (
        coverage["unaccounted_executions"] == 0
        and coverage["unknown_executions"] == 0
    )
    return {
        "schema_version": 1,
        "workspace_id": registry["manifest"]["workspace_id"],
        "month": month or "all",
        "registered_projects": project_summaries,
        "used_lanes": lanes,
        "used_asks": len(lanes),
        "used_actions": len(lanes),
        "totals": totals,
        "accounting_coverage": coverage,
        "unknowns": ["host_native_collaboration_usage_unaccounted"],
        "unused_notice": NOTICE,
        "proof_boundary": "registered_project_dispatch_ledgers_metadata_only",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--ledger", type=Path)
    sources.add_argument("--workspace-root", type=Path)
    sources.add_argument("--project-root", type=Path)
    parser.add_argument("--project-id")
    parser.add_argument("--month", help="YYYY-MM")
    parser.add_argument("--import-codex-json", type=Path, metavar="PATH")
    parser.add_argument("--task-id")
    args = parser.parse_args(argv)
    try:
        if args.import_codex_json is not None:
            if args.project_root is None or not args.task_id:
                raise orcastrata_project.ProjectError("usage_import_arguments_required")
            if args.import_codex_json.as_posix() == "-":
                result = import_codex_exec_json(args.project_root, args.task_id, sys.stdin.buffer)
            else:
                with args.import_codex_json.open("rb") as stream:
                    result = import_codex_exec_json(args.project_root, args.task_id, stream)
        elif args.task_id is not None:
            raise orcastrata_project.ProjectError("usage_import_arguments_required")
        elif args.project_root is not None:
            project = orcastrata_project.find_nearest(args.project_root)
            if project is None:
                raise orcastrata_project.ProjectError("project_not_configured")
            result = readout(
                project["project_root"] / LEDGER_RELATIVE,
                project_id=project["manifest"]["project_id"],
                month=args.month,
            )
        else:
            result = (
                readout(args.ledger, project_id=args.project_id, month=args.month)
                if args.ledger is not None
                else workspace_readout(args.workspace_root, month=args.month)
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (orcastrata_project.ProjectError, ValueError) as exc:
        print(json.dumps({"status": "failed", "code": getattr(exc, "code", "usage_invalid")}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
