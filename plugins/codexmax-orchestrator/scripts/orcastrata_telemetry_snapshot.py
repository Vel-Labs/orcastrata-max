#!/usr/bin/env python3
"""Print one verified, local, metadata-only Orcastrata telemetry snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

import dispatch_ledger
import loop_run_trace
import orcastrata_project


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "OrcastrataTelemetrySnapshotV1"
LEDGER_RELATIVE = Path(".orcastrata/usage/dispatch.jsonl")
UNKNOWN = {"value": "unknown", "reason": "not_reported", "provenance": "unknown"}
ACCOUNTING_SCOPE = "orcastrata_admitted_executions"
SNAPSHOT_FIELDS = {"schema_version", "artifact_type", "project", "ledger", "managed_dispatches", "accounting_coverage", "loop_runs", "proof_boundary", "privacy", "unknowns", "snapshot_sha256"}
PROJECT_FIELDS = {"project_id", "configured"}
LEDGER_FIELDS = {"verified", "after_cursor", "cursor"}
CURSOR_FIELDS = {"sequence", "event_hash"}
MANAGED_FIELDS = {"sequence", "event_id", "event_hash", "previous_event_hash", "event_type", "timestamp", "goal_id", "checkpoint_id", "task_id", "assignment_id", "route", "accounting", "evidence"}
ROUTE_FIELDS = {"route_name", "route_id", "provider", "model", "runtime", "billing", "reasoning", "tool"}
ACCOUNTING_FIELDS = {"project_id", "observed_tokens", "observed_cost", "token_usage", "usage_source", "accounting_status", "accounting_scope", "accounting_method"}
TOKEN_FIELDS = {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens"}
MEASUREMENT_FIELDS = {"value", "reason", "provenance", "method"}
EVIDENCE_FIELDS = {"project_id", "dispatch_status", "work_status", "execution_owner", "external_call_performed", "manifest_sha256"}
COVERAGE_FIELDS = {"scope", "admitted_executions", "accounted_executions", "unaccounted_executions", "unknown_executions", "complete"}
TRACE_FIELDS = {"trace_id", "run_id", "parent_run_id", "loop", "ancestry", "relation", "receipt", "event", "execution", "output", "binding_sha256"}
LOOP_FIELDS = {"loop_id", "definition_version"}
RELATION_FIELDS = {"kind", "root_run_id", "parent_run_id"}
RECEIPT_FIELDS = {"receipt_id", "sha256"}
EVENT_FIELDS = {"event_id", "event_type", "dedupe_key", "source", "origin", "sha256"}
SOURCE_FIELDS = {"adapter_id", "source_event_id", "trust"}
ORIGIN_FIELDS = {"run_id", "loop_id", "depth", "ancestry"}
EXECUTION_FIELDS = {"status", "result", "attempt", "started_at", "finished_at", "duration_ms"}
OUTPUT_FIELDS = {"sha256", "captured_chars", "truncated"}
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+~-]{0,127}$")
SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
IMPORT_TOKEN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,63})$")
SAFE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
APPROVED_TOOLS = {"OpenCode", "Command Code", "Codex", "Orcastrata Max"}
SAFE_REASONING = {"low", "medium", "high", "xhigh", "max", "unknown"}
SAFE_BILLING = {"subscription", "metered", "local", "none", "unknown"}
SAFE_REASONS = {
    "observed", "host_observed", "provider_reported", "input_plus_output",
    "host_counter_missing", "host_counter_invalid", "not_reported",
    "provider_unreported", "provider_tokens_not_reported",
    "provider_cost_not_reported", "provider_quota_not_reported",
    "one_or_more_unknown", "unknown",
}
SAFE_STATUSES = {"completed", "failed", "selected", "hard_stop", "dispatch_finished", "execution_unknown", "unknown"}
SAFE_SOURCES = {"host_codex_exec_json", "provider_manifest", "ledger", "unknown", "test"}
SAFE_ACCOUNTING_STATUSES = {"accounted", "unaccounted", "unknown"}
SAFE_ACCOUNTING_METHODS = {"managed_ledger_append", "bounded_native_import", "unknown"}
EXPECTED_UNKNOWNS = {
    "host_native_parent_usage_unless_imported",
    "host_native_collaboration_usage_unaccounted",
    "provider_payloads_and_transcripts",
}


class SnapshotError(ValueError):
    """Stable fail-closed snapshot error."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value) + b"\n").hexdigest()


def _stable_ref(field: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256((field + "\x00" + str(value)).encode("utf-8")).hexdigest()


def _safe_token(value: Any, *, allowed: set[str] | None = None) -> str:
    if not isinstance(value, str) or not SAFE_TOKEN_RE.fullmatch(value):
        return "unknown"
    if allowed is not None and value not in allowed:
        return "unknown"
    return value


def _safe_identifier(value: Any) -> str:
    return value if isinstance(value, str) and SAFE_IDENTIFIER_RE.fullmatch(value) else "unknown"


def _safe_status(value: Any) -> str:
    return _safe_token(value, allowed=SAFE_STATUSES)


def _safe_reason(value: Any) -> str:
    return _safe_token(value, allowed=SAFE_REASONS)


def _safe_timestamp(value: Any) -> str:
    return value if isinstance(value, str) and SAFE_TIMESTAMP_RE.fullmatch(value) else "unknown"


def validate_snapshot(value: dict[str, Any]) -> list[str]:
    """Validate the closed public snapshot envelope and privacy boundary."""
    errors: list[str] = []
    if not isinstance(value, dict) or set(value) != SNAPSHOT_FIELDS:
        errors.append("unknown_field")
        return errors
    def closed(row: Any, fields: set[str]) -> bool:
        if not isinstance(row, dict) or not set(row).issubset(fields):
            errors.append("unknown_field")
            return False
        return True
    def digest_value(item: Any, *, plain: bool = False) -> bool:
        pattern = r"^[0-9a-f]{64}$" if plain else r"^sha256:[0-9a-f]{64}$"
        return isinstance(item, str) and re.fullmatch(pattern, item) is not None
    def measurement(item: Any) -> bool:
        if not isinstance(item, dict) or set(item) - MEASUREMENT_FIELDS or "value" not in item or "reason" not in item:
            return False
        if item["value"] != "unknown" and (
            not isinstance(item["value"], (int, float))
            or isinstance(item["value"], bool)
            or item["value"] < 0
        ):
            return False
        if item.get("provenance") not in {"observed", "derived", "unknown"}:
            return False
        if (item["value"] == "unknown") != (item["provenance"] == "unknown"):
            return False
        return item["reason"] in SAFE_REASONS
    def origin_valid(item: Any) -> bool:
        if not isinstance(item, dict) or set(item) != ORIGIN_FIELDS:
            return False
        run_id, loop_id = item["run_id"], item["loop_id"]
        depth, ancestry = item["depth"], item["ancestry"]
        if type(depth) is not int or depth < 0 or depth > 8 or not isinstance(ancestry, list):
            return False
        if len(ancestry) != depth or len(set(ancestry)) != len(ancestry) or any(not isinstance(row, str) or not loop_run_trace.KEBAB_RE.fullmatch(row) for row in ancestry):
            return False
        if depth == 0:
            return run_id is None and loop_id is None
        return (
            isinstance(run_id, str)
            and _safe_identifier(run_id) != "unknown"
            and isinstance(loop_id, str)
            and loop_run_trace.KEBAB_RE.fullmatch(loop_id) is not None
            and ancestry[-1] == loop_id
        )
    if value["schema_version"] != 1 or value["artifact_type"] != ARTIFACT_TYPE:
        errors.append("schema_invalid")
    if closed(value["project"], PROJECT_FIELDS) and (
        set(value["project"]) != PROJECT_FIELDS
        or not isinstance(value["project"]["project_id"], str)
        or not isinstance(value["project"]["configured"], bool)
    ):
        errors.append("schema_invalid")
    ledger = value["ledger"]
    if not closed(ledger, LEDGER_FIELDS) or set(ledger) != LEDGER_FIELDS:
        errors.append("schema_invalid")
    else:
        if ledger["verified"] is not True:
            errors.append("schema_invalid")
        for field, cursor in (("after_cursor", ledger["after_cursor"]), ("cursor", ledger["cursor"])):
            if cursor is None:
                if field == "cursor":
                    errors.append("schema_invalid")
            elif (
                not closed(cursor, CURSOR_FIELDS)
                or set(cursor) != CURSOR_FIELDS
                or type(cursor["sequence"]) is not int
                or cursor["sequence"] < 0
                or not digest_value(cursor["event_hash"], plain=True)
            ):
                errors.append("schema_invalid")
    dispatches = value["managed_dispatches"]
    if not closed(dispatches, {"projection", "rows"}) or set(dispatches) != {"projection", "rows"}:
        errors.append("schema_invalid")
    elif dispatches["projection"] != "verified_dispatch_ledger_managed_only" or not isinstance(dispatches["rows"], list):
        errors.append("schema_invalid")
    else:
        for row in dispatches["rows"]:
            if not closed(row, MANAGED_FIELDS) or set(row) != MANAGED_FIELDS:
                errors.append("schema_invalid")
                continue
            if type(row["sequence"]) is not int or row["sequence"] < 1 or not all(isinstance(row[field], str) for field in ("event_id", "event_type", "timestamp", "goal_id", "checkpoint_id", "task_id", "assignment_id")):
                errors.append("schema_invalid")
            if not digest_value(row["event_id"]) or not digest_value(row["goal_id"]) or not digest_value(row["checkpoint_id"]) or not digest_value(row["task_id"]) or not digest_value(row["assignment_id"]) or not digest_value(row["event_hash"], plain=True) or not digest_value(row["previous_event_hash"], plain=True):
                errors.append("schema_invalid")
            route = row["route"]
            if not closed(route, ROUTE_FIELDS) or any(not isinstance(item, str) or not SAFE_TOKEN_RE.fullmatch(item) for item in route.values()):
                errors.append("schema_invalid")
            else:
                if any(
                    route.get(field) != "unknown" and not digest_value(route.get(field))
                    for field in ("route_name", "route_id", "provider", "model", "runtime")
                    if field in route
                ):
                    errors.append("schema_invalid")
                if route.get("tool") not in APPROVED_TOOLS | {"unknown"} or route.get("billing", "unknown") not in SAFE_BILLING or route.get("reasoning", "unknown") not in SAFE_REASONING:
                    errors.append("schema_invalid")
            accounting = row["accounting"]
            if not closed(accounting, ACCOUNTING_FIELDS) or set(accounting) != ACCOUNTING_FIELDS:
                errors.append("schema_invalid")
            else:
                observed_tokens = accounting["observed_tokens"]
                if (
                    not isinstance(accounting["project_id"], str)
                    or accounting["usage_source"] not in SAFE_SOURCES
                    or accounting["accounting_status"] not in SAFE_ACCOUNTING_STATUSES
                    or accounting["accounting_scope"] != ACCOUNTING_SCOPE
                    or accounting["accounting_method"] not in SAFE_ACCOUNTING_METHODS
                    or not (
                        observed_tokens == "unknown"
                        or isinstance(observed_tokens, (int, float))
                        and not isinstance(observed_tokens, bool)
                        and observed_tokens >= 0
                    )
                ):
                    errors.append("schema_invalid")
                usage = accounting["token_usage"]
                if not closed(usage, TOKEN_FIELDS) or set(usage) != TOKEN_FIELDS or any(not measurement(item) for item in usage.values()):
                    errors.append("schema_invalid")
                if accounting["observed_cost"] != "unknown" and not measurement(accounting["observed_cost"]):
                    errors.append("schema_invalid")
            evidence = row["evidence"]
            external = evidence.get("external_call_performed")
            if not closed(evidence, EVIDENCE_FIELDS) or set(evidence) != EVIDENCE_FIELDS or evidence.get("execution_owner") != "orcastrata_managed" or evidence.get("dispatch_status") not in SAFE_STATUSES or evidence.get("work_status") not in SAFE_STATUSES or not (external is True or external is False or external == "unknown") or (evidence.get("manifest_sha256") != "unknown" and not digest_value(evidence.get("manifest_sha256"))):
                errors.append("schema_invalid")
    coverage = value["accounting_coverage"]
    if not closed(coverage, COVERAGE_FIELDS) or set(coverage) != COVERAGE_FIELDS:
        errors.append("schema_invalid")
    elif (
        coverage["scope"] != ACCOUNTING_SCOPE
        or any(type(coverage[field]) is not int or coverage[field] < 0 for field in (
            "admitted_executions", "accounted_executions",
            "unaccounted_executions", "unknown_executions",
        ))
        or type(coverage["complete"]) is not bool
        or coverage["admitted_executions"] != (
            coverage["accounted_executions"]
            + coverage["unaccounted_executions"]
            + coverage["unknown_executions"]
        )
        or coverage["complete"] != (
            coverage["unaccounted_executions"] == 0
            and coverage["unknown_executions"] == 0
        )
    ):
        errors.append("schema_invalid")
    if not isinstance(value["loop_runs"], list):
        errors.append("schema_invalid")
        loop_runs: list[Any] = []
    else:
        loop_runs = value["loop_runs"]
    for trace in loop_runs:
        if not closed(trace, TRACE_FIELDS) or set(trace) != TRACE_FIELDS:
            errors.append("schema_invalid")
            continue
        loop = trace["loop"]
        if not closed(loop, LOOP_FIELDS) or set(loop) != LOOP_FIELDS or not isinstance(loop["loop_id"], str) or not loop_run_trace.KEBAB_RE.fullmatch(loop["loop_id"]) or type(loop["definition_version"]) is not int or loop["definition_version"] < 1:
            errors.append("schema_invalid")
        relation = trace["relation"]
        if not closed(relation, RELATION_FIELDS) or set(relation) != RELATION_FIELDS or relation.get("kind") not in {"root", "nested"}:
            errors.append("schema_invalid")
        receipt = trace["receipt"]
        if not closed(receipt, RECEIPT_FIELDS) or set(receipt) != RECEIPT_FIELDS or not isinstance(receipt.get("receipt_id"), str) or _safe_identifier(receipt.get("receipt_id")) == "unknown" or not digest_value(receipt.get("sha256")):
            errors.append("schema_invalid")
        event = trace["event"]
        if closed(event, EVENT_FIELDS) and set(event) == EVENT_FIELDS:
            source = event.get("source")
            if not closed(source, SOURCE_FIELDS) or set(source) != SOURCE_FIELDS or source.get("trust") not in {"local_adapter", "fixture", "generic_stdin"} or not all(_safe_identifier(source.get(field)) != "unknown" for field in ("adapter_id", "source_event_id")):
                errors.append("schema_invalid")
            origin = event.get("origin")
            if not closed(origin, ORIGIN_FIELDS) or not origin_valid(origin):
                errors.append("schema_invalid")
            if not all(_safe_identifier(event.get(field)) != "unknown" for field in ("event_id", "event_type", "dedupe_key")) or not digest_value(event.get("sha256")):
                errors.append("schema_invalid")
        else:
            errors.append("schema_invalid")
        ancestry = trace["ancestry"]
        if not closed(ancestry, ORIGIN_FIELDS) or not origin_valid(ancestry):
            errors.append("schema_invalid")
        execution = trace["execution"]
        if not closed(execution, EXECUTION_FIELDS) or set(execution) != EXECUTION_FIELDS or not isinstance(execution.get("status"), str) or not isinstance(execution.get("result"), str) or type(execution.get("attempt")) is not int or execution.get("attempt") < 0:
            errors.append("schema_invalid")
        elif (
            not SAFE_IDENTIFIER_RE.fullmatch(execution["status"])
            or not SAFE_IDENTIFIER_RE.fullmatch(execution["result"])
            or any(item is not None and _safe_timestamp(item) == "unknown" for item in (execution["started_at"], execution["finished_at"]))
            or not (
                execution["duration_ms"] == "unknown"
                or type(execution["duration_ms"]) is int and execution["duration_ms"] >= 0
            )
        ):
            errors.append("schema_invalid")
        output = trace["output"]
        if not closed(output, OUTPUT_FIELDS) or set(output) != OUTPUT_FIELDS or not (output.get("sha256") == "unknown" or digest_value(output.get("sha256"))) or type(output.get("captured_chars")) is not int or output.get("captured_chars") < 0 or not isinstance(output.get("truncated"), bool):
            errors.append("schema_invalid")
        if not isinstance(trace.get("trace_id"), str) or _safe_identifier(trace.get("trace_id")) == "unknown" or not isinstance(trace.get("run_id"), str) or _safe_identifier(trace.get("run_id")) == "unknown" or not digest_value(trace.get("binding_sha256")):
            errors.append("schema_invalid")
        elif (
            receipt.get("receipt_id") != trace.get("run_id")
            or trace.get("parent_run_id") != ancestry.get("run_id")
            or relation.get("parent_run_id") != trace.get("parent_run_id")
            or (
                relation.get("kind") == "root"
                and (trace.get("parent_run_id") is not None or relation.get("root_run_id") != trace.get("run_id"))
            )
            or (
                relation.get("kind") == "nested"
                and (trace.get("parent_run_id") is None or relation.get("root_run_id") is not None)
            )
            or event.get("origin") != ancestry
            or trace.get("binding_sha256") != loop_run_trace.binding_sha256_projection(receipt["receipt_id"], event, loop)
            or trace.get("trace_id") != "trace-" + trace["binding_sha256"][len(loop_run_trace.SHA256):][:24]
        ):
            errors.append("schema_invalid")
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if any(token in encoded for token in ("\"path\"", "\"stdout\"", "\"stderr\"", "\"prompt\"", "\"response\"", "\"command\"")):
        errors.append("privacy_boundary")
    if value.get("proof_boundary") != "local_read_only_stdout_metadata_only" or value.get("privacy") != "metadata_only" or not isinstance(value.get("unknowns"), list) or set(value["unknowns"]) != EXPECTED_UNKNOWNS or len(value["unknowns"]) != len(EXPECTED_UNKNOWNS):
        errors.append("schema_invalid")
    if not digest_value(value.get("snapshot_sha256")) or value.get("snapshot_sha256") != digest({key: item for key, item in value.items() if key != "snapshot_sha256"}):
        errors.append("snapshot_digest_mismatch")
    return sorted(set(errors))


def _safe_route(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for field in ("route_name", "route_id", "provider", "model", "runtime"):
        if field in value:
            candidate = value.get(field)
            result[field] = (
                _stable_ref("route." + field, candidate)
                if isinstance(candidate, str) and candidate
                else "unknown"
            )
    if "billing" in value:
        result["billing"] = _safe_token(value.get("billing"), allowed=SAFE_BILLING)
    if "reasoning" in value:
        result["reasoning"] = _safe_token(value.get("reasoning"), allowed=SAFE_REASONING)
    if "tool" in value:
        result["tool"] = value["tool"] if isinstance(value["tool"], str) and value["tool"] in APPROVED_TOOLS else "unknown"
    return result


def _safe_tokens(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"input_tokens": dict(UNKNOWN), "cached_input_tokens": dict(UNKNOWN), "output_tokens": dict(UNKNOWN), "reasoning_output_tokens": dict(UNKNOWN), "total_tokens": dict(UNKNOWN)}
    result: dict[str, Any] = {}
    for field in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens"):
        item = value.get(field)
        if isinstance(item, dict) and item.get("value") == "unknown":
            result[field] = _safe_observation("unknown", item)
        elif isinstance(item, dict) and type(item.get("value")) is int and item["value"] >= 0:
            result[field] = _safe_observation(item["value"], item)
        elif type(item) is int and item >= 0:
            result[field] = {
                "value": item,
                "reason": "observed",
                "provenance": "observed",
            }
        else:
            result[field] = dict(UNKNOWN)
    return result


def _managed_row(row: dict[str, Any]) -> dict[str, Any]:
    accounting = row.get("accounting") if isinstance(row.get("accounting"), dict) else {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    return {
        "sequence": row["sequence"],
        "event_id": _stable_ref("event_id", row["event_id"]),
        "event_hash": row["event_hash"],
        "previous_event_hash": row["previous_event_hash"],
        "event_type": _safe_status(row["event_type"]),
        "timestamp": _safe_timestamp(row["timestamp"]),
        "goal_id": _stable_ref("goal_id", row["goal_id"]),
        "checkpoint_id": _stable_ref("checkpoint_id", row["checkpoint_id"]),
        "task_id": _stable_ref("task_id", row["task_id"]),
        "assignment_id": _stable_ref("assignment_id", row["assignment_id"]),
        "route": _safe_route(row.get("route")),
        "accounting": {
            "project_id": _safe_identifier(accounting.get("project_id", "unknown")),
            "observed_tokens": _safe_observed_scalar(accounting.get("observed_tokens", "unknown")),
            "observed_cost": _safe_measurement(accounting.get("observed_cost", dict(UNKNOWN))),
            "token_usage": _safe_tokens(accounting.get("token_usage")),
            "usage_source": _safe_token(accounting.get("usage_source", "unknown"), allowed=SAFE_SOURCES),
            "accounting_status": _row_accounting_status(row),
            "accounting_scope": ACCOUNTING_SCOPE,
            "accounting_method": _safe_token(
                accounting.get("accounting_method", "unknown"),
                allowed=SAFE_ACCOUNTING_METHODS,
            ),
        },
        "evidence": {
            "project_id": _safe_identifier(evidence.get("project_id", "unknown")),
            "dispatch_status": _safe_status(evidence.get("dispatch_status", row["event_type"])),
            "work_status": _safe_status(evidence.get("work_status", evidence.get("dispatch_status", row["event_type"]))),
            "execution_owner": "orcastrata_managed",
            "external_call_performed": evidence.get("external_call_performed") if type(evidence.get("external_call_performed")) is bool else "unknown",
            "manifest_sha256": evidence.get("manifest_sha256") if isinstance(evidence.get("manifest_sha256"), str) and loop_run_trace.SHA256_RE.fullmatch(evidence.get("manifest_sha256")) else "unknown",
        },
    }


def _row_accounting_status(row: dict[str, Any]) -> str:
    accounting = row.get("accounting") if isinstance(row.get("accounting"), dict) else {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    owner = evidence.get("execution_owner")
    method = accounting.get("accounting_method")
    managed_evidence_valid = (
        evidence.get("external_call_performed") is True
        and isinstance(evidence.get("manifest_sha256"), str)
        and loop_run_trace.SHA256_RE.fullmatch(evidence["manifest_sha256"]) is not None
    )
    native_evidence_valid = (
        evidence.get("import_acceptance") == "accepted_bounded"
        and evidence.get("lifecycle") == "completed_only"
        and isinstance(evidence.get("source_sha256"), str)
        and loop_run_trace.SHA256_RE.fullmatch(evidence["source_sha256"]) is not None
        and isinstance(evidence.get("task_id"), str)
        and IMPORT_TOKEN_RE.fullmatch(evidence["task_id"]) is not None
        and evidence["task_id"] == row.get("task_id")
        and isinstance(evidence.get("action_id"), str)
        and IMPORT_TOKEN_RE.fullmatch(evidence["action_id"]) is not None
    )
    if (
        accounting.get("accounting_scope") == ACCOUNTING_SCOPE
        and accounting.get("accounting_status") == "accounted"
        and (
            owner == "orcastrata_managed"
            and method == "managed_ledger_append"
            and managed_evidence_valid
            or owner == "host_native"
            and method == "bounded_native_import"
            and native_evidence_valid
        )
    ):
        return "accounted"
    if accounting.get("accounting_status") == "unaccounted":
        return "unaccounted"
    return "unknown"


def _accounting_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [_row_accounting_status(row) for row in rows]
    result = {
        "scope": ACCOUNTING_SCOPE,
        "admitted_executions": len(statuses),
        "accounted_executions": statuses.count("accounted"),
        "unaccounted_executions": statuses.count("unaccounted"),
        "unknown_executions": statuses.count("unknown"),
    }
    result["complete"] = (
        result["unaccounted_executions"] == 0
        and result["unknown_executions"] == 0
    )
    return result


def _safe_measurement(value: Any) -> Any:
    if isinstance(value, dict) and isinstance(value.get("value"), (int, float)) and not isinstance(value["value"], bool) and value["value"] >= 0:
        return {
            "value": value["value"],
            "reason": _safe_reason(value.get("reason", "observed")),
            "provenance": value.get("provenance") if value.get("provenance") in {"observed", "derived"} else "observed",
        }
    if isinstance(value, dict) and value.get("value") == "unknown":
        return {"value": "unknown", "reason": _safe_reason(value.get("reason")), "provenance": "unknown"}
    return "unknown"


def _safe_observed_scalar(value: Any) -> int | float | str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return value
    return "unknown"


def _safe_observation(value: int | str, source: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "value": value,
        "reason": _safe_reason(source.get("reason", "observed")),
        "provenance": (
            "unknown" if value == "unknown"
            else source.get("provenance") if source.get("provenance") in {"observed", "derived"}
            else "observed"
        ),
    }
    for key in ("provenance", "method"):
        candidate = source.get(key)
        if isinstance(candidate, str) and SAFE_TOKEN_RE.fullmatch(candidate):
            result[key] = candidate
    return result


def _trace_projection(result: dict[str, Any]) -> dict[str, Any]:
    trace = result["trace"]
    # The pair validator has already checked the receipt digest. Return only
    # its bounded metadata projection, never the receipt or trace source text.
    return {
        "trace_id": trace["trace_id"],
        "run_id": trace["run_id"],
        "parent_run_id": trace["parent_run_id"],
        "loop": trace["loop"],
        "ancestry": trace["ancestry"],
        "relation": trace["relation"],
        "receipt": {
            "receipt_id": trace["receipt"]["receipt_id"],
            "sha256": result["receipt_sha256"],
        },
        "event": trace["event"],
        "execution": trace["execution"],
        "output": trace["output"],
        "binding_sha256": trace["binding_sha256"],
    }


def _safe_receipt_path(root: Path, value: str | Path) -> Path:
    """Resolve an explicit receipt only through regular, non-aliased entries."""
    supplied = Path(value)
    if "\x00" in str(supplied) or ".." in supplied.parts:
        raise SnapshotError("receipt_path_invalid")
    lexical = Path(os.path.abspath(supplied if supplied.is_absolute() else root / supplied))
    canonical_root = root.resolve(strict=True)
    try:
        relative = lexical.relative_to(canonical_root)
    except ValueError as exc:
        raise SnapshotError("receipt_path_invalid") from exc
    current = canonical_root
    try:
        for index, part in enumerate(relative.parts):
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise SnapshotError("receipt_path_invalid")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise SnapshotError("receipt_path_invalid")
            if index == len(relative.parts) - 1 and (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            ):
                raise SnapshotError("receipt_path_invalid")
    except OSError as exc:
        raise SnapshotError("receipt_path_invalid") from exc
    return lexical


def _safe_ledger_path(root: Path) -> Path:
    """Verify every ledger path component without following aliases."""
    canonical_root = root.resolve(strict=True)
    relative = LEDGER_RELATIVE
    current = canonical_root
    try:
        for index, part in enumerate(relative.parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return canonical_root / relative
            if stat.S_ISLNK(info.st_mode):
                raise SnapshotError("ledger_path_invalid")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise SnapshotError("ledger_path_invalid")
            if index == len(relative.parts) - 1 and (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            ):
                raise SnapshotError("ledger_path_invalid")
    except OSError as exc:
        raise SnapshotError("ledger_path_invalid") from exc
    return current


def build_snapshot(project_root: str | Path, *, receipt_paths: list[str | Path] | None = None, after_sequence: int | None = None, after_event_hash: str | None = None) -> dict[str, Any]:
    """Build one snapshot without creating or modifying any local artifact."""
    try:
        project = orcastrata_project.find_nearest(project_root)
    except orcastrata_project.ProjectError as exc:
        raise SnapshotError(exc.code) from exc
    if project is None:
        raise SnapshotError("project_not_initialized")
    root = project["project_root"]
    ledger_path = _safe_ledger_path(root)
    try:
        verified = dispatch_ledger.verify_ledger(ledger_path)
    except dispatch_ledger.LedgerError as exc:
        raise SnapshotError(exc.code) from exc
    if (after_sequence is None) != (after_event_hash is None):
        raise SnapshotError("after_cursor_incomplete")
    if after_sequence is not None:
        if type(after_sequence) is not int or after_sequence < 0 or after_sequence > verified["event_count"] or not isinstance(after_event_hash, str):
            raise SnapshotError("after_cursor_invalid")
        if after_sequence == 0:
            expected = dispatch_ledger.ZERO_HASH
        else:
            expected = verified["rows"][after_sequence - 1]["event_hash"]
        if after_event_hash != expected:
            raise SnapshotError("after_cursor_mismatch")
    start = after_sequence or 0
    admitted_rows = [
        row for row in verified["rows"][start:]
        if row.get("event_type") in {"dispatch_finished", "execution_unknown"}
        and (row.get("evidence") or {}).get("execution_owner") in {"orcastrata_managed", "host_native"}
    ]
    managed_rows = [
        row for row in admitted_rows
        if (row.get("evidence") or {}).get("execution_owner") == "orcastrata_managed"
    ]
    traces: list[dict[str, Any]] = []
    for receipt_path_value in receipt_paths or []:
        try:
            receipt_path = _safe_receipt_path(root, receipt_path_value)
        except SnapshotError:
            raise
        try:
            pair = loop_run_trace.validate_pair(
                receipt_path,
                roots=loop_run_trace.loop_registry.default_roots(workspace_root=root),
            )
        except loop_run_trace.TraceError as exc:
            raise SnapshotError(exc.code) from exc
        if not pair["valid"]:
            raise SnapshotError("loop_trace_invalid", ",".join(pair["errors"]))
        receipt_id = pair["trace"]["receipt"]["receipt_id"]
        if any(row["receipt"]["receipt_id"] == receipt_id for row in traces):
            raise SnapshotError("loop_receipt_duplicate")
        traces.append(_trace_projection(pair))
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "project": {"project_id": project["manifest"]["project_id"], "configured": True},
        "ledger": {
            "verified": True,
            "after_cursor": None if after_sequence is None else {"sequence": after_sequence, "event_hash": after_event_hash},
            "cursor": {"sequence": verified["event_count"], "event_hash": verified["head_hash"]},
        },
        "managed_dispatches": {
            "projection": "verified_dispatch_ledger_managed_only",
            "rows": [_managed_row(row) for row in managed_rows],
        },
        "accounting_coverage": _accounting_coverage(admitted_rows),
        "loop_runs": traces,
        "proof_boundary": "local_read_only_stdout_metadata_only",
        "privacy": "metadata_only",
        "unknowns": [
            "host_native_parent_usage_unless_imported",
            "host_native_collaboration_usage_unaccounted",
            "provider_payloads_and_transcripts",
        ],
        "snapshot_sha256": "unknown",
    }
    snapshot["snapshot_sha256"] = digest({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
    errors = validate_snapshot(snapshot)
    if errors:
        raise SnapshotError(errors[0])
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, action="append", default=[])
    parser.add_argument("--after-sequence", type=int)
    parser.add_argument("--after-event-hash")
    args = parser.parse_args(argv)
    try:
        result = build_snapshot(args.project_root, receipt_paths=args.receipt, after_sequence=args.after_sequence, after_event_hash=args.after_event_hash)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except SnapshotError as exc:
        print(json.dumps({"schema_version": 1, "artifact_type": "OrcastrataTelemetrySnapshotError", "valid": False, "errors": [exc.code]}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
