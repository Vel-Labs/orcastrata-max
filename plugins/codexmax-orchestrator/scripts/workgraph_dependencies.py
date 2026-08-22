#!/usr/bin/env python3
"""Deterministic WorkGraph readiness, parallelism, and fenced local leases."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from typing import Any, Callable, Sequence

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")
SCHEDULABLE = {"queued", "blocked", "needs_revision", "needs_reassignment", "needs_parent_repair"}
SAT_KEYS = {"schema_version", "board_sha256", "satisfied_work_item_ids"}
HOLDER_PROVENANCE = {"parent_assigned", "runtime_observed", "receipt_backed"}
REGISTRY_KEYS = {"schema_version", "next_fencing_token", "claims"}
CLAIM_KEYS = {
    "claim_id", "request_id", "work_item_id", "holder", "attempt", "read_scope",
    "write_scope", "board_sha256", "acquired_at", "expires_at", "fencing_token",
    "state", "prior_claim_id", "outcome_history",
}
CLAIM_STATES = {"active", "released", "failed", "recovered"}
PRODUCER_REQUIRED_EVIDENCE_KINDS = {"artifact", "command_result"}


class DependencyError(Exception):
    def __init__(self, code: str, details: object | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DependencyError(code)
    return value


def _time(value: object, code: str = "dependency_timestamp_invalid") -> datetime:
    text = _text(value, code)
    if TIME_RE.fullmatch(text) is None:
        raise DependencyError(code)
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise DependencyError(code) from error


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(".000000+00:00", "Z").replace("+00:00", "Z")


def _hash(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DependencyError(code)
    return value


def _workgraph() -> Any:
    path = Path(__file__).with_name("workgraph.py")
    spec = importlib.util.spec_from_file_location("codexmax_t002_workgraph", path)
    if spec is None or spec.loader is None:
        raise DependencyError("dependency_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _items(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in graph["work_items"]}


def validate_graph(graph: object) -> dict[str, Any]:
    if not isinstance(graph, dict):
        raise DependencyError("dependency_graph_invalid")
    # Preserve the runtime-specific ambiguity receipt when the outer graph is
    # structurally traversable; malformed outer shapes remain T002 errors.
    if isinstance(graph.get("work_items"), list) and isinstance(graph.get("evidence"), list):
        try:
            _artifact_map(graph)
        except DependencyError:
            raise
        except (KeyError, TypeError, AttributeError):
            pass
    receipt = _workgraph().validate_document(graph)
    if receipt.get("status") != "valid":
        raise DependencyError("dependency_graph_invalid", receipt.get("errors", []))
    for item in graph["work_items"]:
        _scopes(item)
    return receipt


def validate_satisfaction(graph: dict[str, Any], value: object, expected_board_hash: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SAT_KEYS:
        raise DependencyError("dependency_satisfaction_shape_invalid")
    version = value["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise DependencyError("dependency_satisfaction_version_invalid")
    if version != 1:
        raise DependencyError("dependency_satisfaction_version_unsupported")
    board_hash = _hash(value["board_sha256"], "dependency_board_hash_invalid")
    if expected_board_hash is not None and board_hash != expected_board_hash:
        raise DependencyError("dependency_satisfaction_stale")
    ids = value["satisfied_work_item_ids"]
    if not isinstance(ids, list) or any(not isinstance(item_id, str) or not item_id for item_id in ids):
        raise DependencyError("dependency_satisfaction_ids_invalid")
    if len(ids) != len(set(ids)):
        raise DependencyError("dependency_satisfaction_ids_duplicate")
    unknown = sorted(set(ids) - set(_items(graph)))
    if unknown:
        raise DependencyError("dependency_satisfaction_id_unknown", unknown)
    return value


def _reason(code: str, reference: str, action: str) -> dict[str, str]:
    messages = {
        "already_satisfied": "This item is already satisfied and must not be scheduled again.",
        "status_not_schedulable": "The canonical status is not currently schedulable.",
        "dependency_unsatisfied": "A declared blocking dependency still needs Parent-reviewed satisfaction.",
        "artifact_rejected": "A required artifact was rejected and must be repaired or replaced.",
        "artifact_unvalidated": "A required artifact does not yet have validated digest-backed evidence.",
        "lease_active": "This item already has an active execution lease.",
        "lease_scope_conflict": "Another active lease overlaps this item's write scope.",
    }
    return {"code": code, "reference": reference, "message": messages[code], "next_action": action}


def _reasons(graph: dict[str, Any], sat: dict[str, Any], item_id: str, claims: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    items = _items(graph)
    if item_id not in items:
        raise DependencyError("dependency_work_item_unknown")
    item = items[item_id]
    result: list[dict[str, str]] = []
    satisfied = set(sat["satisfied_work_item_ids"])
    if item_id in satisfied:
        result.append(_reason("already_satisfied", item_id, "do_not_reschedule"))
    if item["status"] not in SCHEDULABLE:
        result.append(_reason("status_not_schedulable", item["status"], "wait_for_canonical_transition"))
    rel = item.get("relationships", {})
    for blocker in sorted(rel.get("blocked_by", [])):
        if blocker not in satisfied:
            result.append(_reason("dependency_unsatisfied", blocker, "supply_parent_reviewed_satisfaction"))
    evidence = {row["id"]: row for row in graph["evidence"]}
    for artifact in sorted(rel.get("consumes", [])):
        row = evidence[artifact]
        if row["state"] == "rejected":
            result.append(_reason("artifact_rejected", artifact, "repair_or_replace_artifact"))
        elif row["state"] != "validated" or row["digest"] == "unknown":
            result.append(_reason("artifact_unvalidated", artifact, "validate_artifact_with_digest"))
    for claim_row in sorted(claims or [], key=lambda row: row["claim_id"]):
        if claim_row["state"] == "active" and claim_row["work_item_id"] == item_id:
            result.append(_reason("lease_active", claim_row["claim_id"], "renew_release_or_recover_claim"))
        elif claim_row["state"] == "active":
            candidate = {"read_scope": _scopes(item)[0], "write_scope": _scopes(item)[1]}
            if _claim_conflict(candidate, claim_row):
                result.append(_reason("lease_scope_conflict", claim_row["claim_id"], "wait_release_or_recover_claim"))
    return sorted(result, key=lambda row: (row["code"], row["reference"]))


def ready(graph: object, satisfaction: object, *, expected_board_hash: str | None = None, active_claims: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_graph(graph)
    assert isinstance(graph, dict)
    sat = validate_satisfaction(graph, satisfaction, expected_board_hash)
    items = _items(graph)
    ids = [item_id for item_id in sorted(items) if not _reasons(graph, sat, item_id, active_claims)]
    return {
        "schema_version": 1, "status": "ok", "board_sha256": sat["board_sha256"],
        "ready_work_item_ids": ids,
        "next_ready": [
            {"work_item_id": item_id, "objective": items[item_id]["objective"],
             "clarity_tier": items[item_id]["clarity_tier"],
             "basis": "all_dependency_artifact_status_and_lease_gates_satisfied",
             "next_action": "request_parent_assignment_or_claim"}
            for item_id in ids
        ],
    }


def explain_blocked(graph: object, satisfaction: object, item_id: str, *, expected_board_hash: str | None = None, active_claims: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_graph(graph)
    assert isinstance(graph, dict)
    sat = validate_satisfaction(graph, satisfaction, expected_board_hash)
    reasons = _reasons(graph, sat, item_id, active_claims)
    return {"schema_version": 1, "status": "ok", "work_item_id": item_id, "board_sha256": sat["board_sha256"], "blocked": bool(reasons), "reasons": reasons}


def containment(graph: object, item_id: str, direction: str = "descendants") -> dict[str, Any]:
    validate_graph(graph)
    assert isinstance(graph, dict)
    items = _items(graph)
    if item_id not in items:
        raise DependencyError("dependency_work_item_unknown")
    children = {key: sorted(item.get("relationships", {}).get("parent_of", [])) for key, item in items.items()}
    parents = {child: parent for parent, values in children.items() for child in values}
    rows: list[dict[str, object]] = []
    if direction == "descendants":
        queue = [(child, 1) for child in children[item_id]]
        while queue:
            current, depth = queue.pop(0)
            rows.append({"work_item_id": current, "depth": depth})
            queue.extend((child, depth + 1) for child in children[current])
    elif direction == "ancestors":
        current, depth = item_id, 0
        while current in parents:
            current, depth = parents[current], depth + 1
            rows.append({"work_item_id": current, "depth": depth})
    elif direction == "roots":
        rows = [{"work_item_id": key, "depth": 0} for key in sorted(set(items) - set(parents))]
    else:
        raise DependencyError("dependency_containment_direction_invalid")
    return {"schema_version": 1, "status": "ok", "direction": direction, "items": rows}


def _artifact_map(graph: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    evidence = {
        row["id"]: row
        for row in graph.get("evidence", [])
        if isinstance(row, dict) and "id" in row
    }
    ids = set(evidence)
    producers = {key: [] for key in ids}
    consumers = {key: [] for key in ids}
    for item in graph.get("work_items", []):
        rel = item.get("relationships", {}) if isinstance(item, dict) else {}
        for key in rel.get("produces", []):
            if key in producers:
                producers[key].append(item["id"])
        for key in rel.get("consumes", []):
            if key in consumers:
                consumers[key].append(item["id"])
    ambiguous = sorted(key for key, values in producers.items() if len(values) > 1)
    if ambiguous:
        raise DependencyError("dependency_artifact_producer_ambiguous", ambiguous)
    missing = sorted(
        key
        for key, values in producers.items()
        if consumers[key]
        and not values
        and evidence[key].get("kind") in PRODUCER_REQUIRED_EVIDENCE_KINDS
    )
    if missing:
        raise DependencyError("dependency_artifact_producer_missing", missing)
    return {key: {"producers": sorted(producers[key]), "consumers": sorted(consumers[key])} for key in sorted(ids)}


def artifact_flow(graph: object) -> dict[str, Any]:
    validate_graph(graph)
    assert isinstance(graph, dict)
    return {"schema_version": 1, "status": "ok", "artifacts": _artifact_map(graph)}


def normalize_path(value: object) -> str:
    text = _text(value, "dependency_path_invalid")
    if (
        "\\" in text
        or text.startswith("/")
        or text.endswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise DependencyError("dependency_path_invalid")
    path = PurePosixPath(text)
    if text != path.as_posix() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise DependencyError("dependency_path_invalid")
    return text


def paths_overlap(left: str, right: str) -> bool:
    first, second = PurePosixPath(normalize_path(left)).parts, PurePosixPath(normalize_path(right)).parts
    size = min(len(first), len(second))
    return first[:size] == second[:size]


def _scopes(item: dict[str, Any]) -> tuple[list[str], list[str]]:
    reads = sorted(normalize_path(path) for path in item["scope"]["read"])
    writes = sorted(normalize_path(path) for path in item["scope"]["write"])
    if len(reads) != len(set(reads)) or len(writes) != len(set(writes)):
        raise DependencyError("dependency_path_duplicate")
    return reads, writes


def scopes_conflict(first: dict[str, Any], second: dict[str, Any]) -> bool:
    first_reads, first_writes = _scopes(first)
    second_reads, second_writes = _scopes(second)
    return (
        any(paths_overlap(write, path) for write in first_writes for path in [*second_reads, *second_writes])
        or any(paths_overlap(write, read) for write in second_writes for read in first_reads)
    )


def parallel_groups(graph: object, satisfaction: object, *, expected_board_hash: str | None = None, active_claims: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    receipt = ready(graph, satisfaction, expected_board_hash=expected_board_hash, active_claims=active_claims)
    assert isinstance(graph, dict)
    items, groups = _items(graph), []
    for item_id in receipt["ready_work_item_ids"]:
        for group in groups:
            if all(not scopes_conflict(items[item_id], items[other]) for other in group):
                group.append(item_id)
                break
        else:
            groups.append([item_id])
    return {"schema_version": 1, "status": "ok", "board_sha256": receipt["board_sha256"], "groups": groups}


def validate_holder(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"role", "agent_id"}:
        raise DependencyError("dependency_holder_invalid")
    _text(value["role"], "dependency_holder_role_invalid")
    fact = value["agent_id"]
    if not isinstance(fact, dict) or set(fact) != {"value", "provenance"}:
        raise DependencyError("dependency_holder_agent_id_invalid")
    identity = _text(fact["value"], "dependency_holder_agent_id_invalid")
    if identity == "unknown" or fact["provenance"] not in HOLDER_PROVENANCE:
        raise DependencyError("dependency_holder_agent_id_unproved")
    return value


def _history(kind: str, timestamp: str, reason: str) -> dict[str, str]:
    return {"kind": kind, "timestamp": timestamp, "reason": reason}


def _empty_registry() -> dict[str, Any]:
    return {"schema_version": 1, "next_fencing_token": 1, "claims": []}


def verify_registry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REGISTRY_KEYS:
        raise DependencyError("dependency_registry_shape_invalid")
    version, next_token, claims = value["schema_version"], value["next_fencing_token"], value["claims"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise DependencyError("dependency_registry_version_invalid")
    if not isinstance(next_token, int) or isinstance(next_token, bool) or next_token < 1:
        raise DependencyError("dependency_registry_token_invalid")
    if not isinstance(claims, list):
        raise DependencyError("dependency_registry_claims_invalid")
    claim_ids, request_ids, tokens = set(), set(), []
    for claim_row in claims:
        if not isinstance(claim_row, dict) or set(claim_row) != CLAIM_KEYS:
            raise DependencyError("dependency_claim_shape_invalid")
        claim_id = _text(claim_row["claim_id"], "dependency_claim_id_invalid")
        request_id = _text(claim_row["request_id"], "dependency_request_id_invalid")
        if claim_id in claim_ids:
            raise DependencyError("dependency_claim_id_duplicate")
        if request_id in request_ids:
            raise DependencyError("dependency_request_id_duplicate")
        claim_ids.add(claim_id); request_ids.add(request_id)
        _text(claim_row["work_item_id"], "dependency_claim_work_item_invalid")
        validate_holder(claim_row["holder"])
        attempt, token = claim_row["attempt"], claim_row["fencing_token"]
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise DependencyError("dependency_claim_attempt_invalid")
        if not isinstance(token, int) or isinstance(token, bool) or token < 1:
            raise DependencyError("dependency_claim_token_invalid")
        tokens.append(token)
        reads, writes = claim_row["read_scope"], claim_row["write_scope"]
        if not isinstance(reads, list) or reads != sorted(set(normalize_path(path) for path in reads)):
            raise DependencyError("dependency_claim_scope_invalid")
        if not isinstance(writes, list) or writes != sorted(set(normalize_path(path) for path in writes)):
            raise DependencyError("dependency_claim_scope_invalid")
        _hash(claim_row["board_sha256"], "dependency_claim_board_hash_invalid")
        acquired = _time(claim_row["acquired_at"], "dependency_claim_time_invalid")
        expires = _time(claim_row["expires_at"], "dependency_claim_time_invalid")
        if expires <= acquired:
            raise DependencyError("dependency_claim_time_order_invalid")
        if claim_row["state"] not in CLAIM_STATES:
            raise DependencyError("dependency_claim_state_invalid")
        if claim_row["prior_claim_id"] is not None:
            _text(claim_row["prior_claim_id"], "dependency_prior_claim_invalid")
        history = claim_row["outcome_history"]
        if not isinstance(history, list) or not history:
            raise DependencyError("dependency_registry_history_invalid")
        for row in history:
            if not isinstance(row, dict) or set(row) != {"kind", "timestamp", "reason"}:
                raise DependencyError("dependency_registry_history_invalid")
            if row["kind"] not in {"claimed", "renewed", "released", "failed", "recovered"}:
                raise DependencyError("dependency_registry_history_kind_invalid")
            _time(row["timestamp"], "dependency_registry_history_time_invalid")
            _text(row["reason"], "dependency_registry_history_reason_invalid")
    if tokens != sorted(tokens) or len(tokens) != len(set(tokens)):
        raise DependencyError("dependency_registry_fencing_regression")
    if tokens and next_token <= max(tokens):
        raise DependencyError("dependency_registry_next_token_stale")
    by_id = {row["claim_id"]: row for row in claims}
    for row in claims:
        prior_id = row["prior_claim_id"]
        if prior_id is not None:
            prior = by_id.get(prior_id)
            if prior is None:
                raise DependencyError("dependency_prior_claim_missing")
            if prior["fencing_token"] >= row["fencing_token"]:
                raise DependencyError("dependency_registry_fencing_regression")
            if prior["work_item_id"] != row["work_item_id"] or row["attempt"] != prior["attempt"] + 1:
                raise DependencyError("dependency_claim_lineage_invalid")
        expected_last = {"active": {"claimed", "renewed"}, "released": {"released"}, "failed": {"failed"}, "recovered": {"recovered"}}
        if row["outcome_history"][-1]["kind"] not in expected_last[row["state"]]:
            raise DependencyError("dependency_claim_history_state_mismatch")
    active = [row for row in claims if row["state"] == "active"]
    for index, first in enumerate(active):
        for second in active[index + 1:]:
            if first["work_item_id"] == second["work_item_id"] or _claim_conflict(first, second):
                raise DependencyError("dependency_registry_active_conflict")
    return {"schema_version": 1, "status": "valid", "claim_count": len(claims), "head_fencing_token": max(tokens, default=0)}


def _read_registry(path: Path, allow_missing: bool = False) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        if allow_missing:
            return _empty_registry()
        raise DependencyError("dependency_registry_missing")
    except OSError as error:
        raise DependencyError("dependency_registry_unavailable") from error
    if not raw:
        raise DependencyError("dependency_registry_empty")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DependencyError("dependency_registry_json_invalid") from error
    verify_registry(value)
    return value


def read_registry(path: Path) -> dict[str, Any]:
    return _read_registry(path)


def _write_registry(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((canonical_json(value) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise DependencyError("dependency_registry_write_failed") from error


def _mutate(path: Path, operation: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        raise DependencyError("dependency_registry_lock_unavailable") from error
    with os.fdopen(descriptor, "r+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        registry = _read_registry(path, allow_missing=True)
        result = operation(registry)
        verify_registry(registry)
        _write_registry(path, registry)
        return result


def _claim_id(request_id: str, item_id: str, token: int) -> str:
    return "claim-" + hashlib.sha256(f"{request_id}\0{item_id}\0{token}".encode()).hexdigest()[:24]


def _claim_conflict(candidate: dict[str, Any], active: dict[str, Any]) -> bool:
    first = {"scope": {"read": candidate["read_scope"], "write": candidate["write_scope"]}}
    second = {"scope": {"read": active["read_scope"], "write": active["write_scope"]}}
    return scopes_conflict(first, second)


def _new_claim(registry: dict[str, Any], item: dict[str, Any], *, request_id: str, holder: dict[str, Any], board_hash: str, now: str, duration: int, attempt: int, prior: str | None, reason: str) -> dict[str, Any]:
    token = registry["next_fencing_token"]
    registry["next_fencing_token"] += 1
    reads, writes = _scopes(item)
    row = {
        "claim_id": _claim_id(request_id, item["id"], token), "request_id": request_id,
        "work_item_id": item["id"], "holder": holder, "attempt": attempt,
        "read_scope": reads, "write_scope": writes, "board_sha256": board_hash,
        "acquired_at": now, "expires_at": _time_text(_time(now) + timedelta(seconds=duration)),
        "fencing_token": token, "state": "active", "prior_claim_id": prior,
        "outcome_history": [_history("claimed", now, reason)],
    }
    for active in registry["claims"]:
        if active["state"] == "active" and (
            active["work_item_id"] == row["work_item_id"] or _claim_conflict(row, active)
        ):
            raise DependencyError("dependency_claim_conflict", active["claim_id"])
    registry["claims"].append(row)
    return row


def _duration(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 86400:
        raise DependencyError("dependency_claim_duration_invalid")
    return value


def _check_current(row: dict[str, Any], holder: object, board_hash: str, token: object) -> None:
    if row["holder"] != validate_holder(holder):
        raise DependencyError("dependency_claim_holder_mismatch")
    if row["board_sha256"] != board_hash:
        raise DependencyError("dependency_claim_board_hash_mismatch")
    if not isinstance(token, int) or isinstance(token, bool):
        raise DependencyError("dependency_claim_token_invalid")
    if row["fencing_token"] != token:
        raise DependencyError("dependency_claim_fenced")


def claim(registry_path: Path, graph: object, satisfaction: object, item_id: str, *, request_id: str, holder: object, now: str, duration_seconds: int, expected_board_hash: str | None = None) -> dict[str, Any]:
    validate_graph(graph); assert isinstance(graph, dict)
    sat = validate_satisfaction(graph, satisfaction, expected_board_hash)
    holder = validate_holder(holder); request_id = _text(request_id, "dependency_request_id_invalid")
    _time(now); duration = _duration(duration_seconds)
    reasons = _reasons(graph, sat, item_id)
    if reasons:
        raise DependencyError("dependency_work_item_not_ready", reasons)
    item = _items(graph)[item_id]
    def operation(registry: dict[str, Any]) -> dict[str, Any]:
        for existing in registry["claims"]:
            if existing["request_id"] == request_id:
                expected_expiry = _time_text(_time(now) + timedelta(seconds=duration))
                expected_reads, expected_writes = _scopes(item)
                if (
                    existing["work_item_id"] != item_id or existing["holder"] != holder
                    or existing["board_sha256"] != sat["board_sha256"]
                    or existing["acquired_at"] != now or existing["expires_at"] != expected_expiry
                    or existing["read_scope"] != expected_reads
                    or existing["write_scope"] != expected_writes
                ):
                    raise DependencyError("dependency_request_id_reused")
                return existing
        return _new_claim(registry, item, request_id=request_id, holder=holder, board_hash=sat["board_sha256"], now=now, duration=duration, attempt=1, prior=None, reason="initial_claim")
    return _mutate(registry_path, operation)


def renew(registry_path: Path, claim_id: str, *, holder: object, board_hash: str, fencing_token: int, now: str, duration_seconds: int) -> dict[str, Any]:
    _hash(board_hash, "dependency_claim_board_hash_invalid"); current_time = _time(now); duration = _duration(duration_seconds)
    def operation(registry: dict[str, Any]) -> dict[str, Any]:
        row = next((value for value in registry["claims"] if value["claim_id"] == claim_id), None)
        if row is None: raise DependencyError("dependency_claim_unknown")
        _check_current(row, holder, board_hash, fencing_token)
        if row["state"] != "active": raise DependencyError("dependency_claim_not_active")
        if current_time < _time(row["acquired_at"]): raise DependencyError("dependency_clock_reversal")
        if current_time >= _time(row["expires_at"]): raise DependencyError("dependency_claim_expired")
        row["expires_at"] = _time_text(current_time + timedelta(seconds=duration))
        row["outcome_history"].append(_history("renewed", now, "lease_renewed")); return row
    return _mutate(registry_path, operation)


def release(registry_path: Path, claim_id: str, *, holder: object, board_hash: str, fencing_token: int, now: str) -> dict[str, Any]:
    _hash(board_hash, "dependency_claim_board_hash_invalid"); current_time = _time(now)
    def operation(registry: dict[str, Any]) -> dict[str, Any]:
        row = next((value for value in registry["claims"] if value["claim_id"] == claim_id), None)
        if row is None: raise DependencyError("dependency_claim_unknown")
        _check_current(row, holder, board_hash, fencing_token)
        if row["state"] != "active": raise DependencyError("dependency_claim_not_active")
        if current_time < _time(row["acquired_at"]): raise DependencyError("dependency_clock_reversal")
        if current_time >= _time(row["expires_at"]): raise DependencyError("dependency_claim_expired")
        row["state"] = "released"; row["outcome_history"].append(_history("released", now, "lease_released")); return row
    return _mutate(registry_path, operation)


def retry(registry_path: Path, graph: object, claim_id: str, *, request_id: str, holder: object, board_hash: str, fencing_token: int, now: str, duration_seconds: int, reason: str) -> dict[str, Any]:
    validate_graph(graph); assert isinstance(graph, dict)
    holder = validate_holder(holder); _hash(board_hash, "dependency_claim_board_hash_invalid")
    current_time = _time(now); duration = _duration(duration_seconds)
    request_id = _text(request_id, "dependency_request_id_invalid")
    reason = _text(reason, "dependency_retry_reason_invalid")
    items = _items(graph)
    def operation(registry: dict[str, Any]) -> dict[str, Any]:
        if any(row["request_id"] == request_id for row in registry["claims"]):
            existing = next(row for row in registry["claims"] if row["request_id"] == request_id)
            prior = next((row for row in registry["claims"] if row["claim_id"] == claim_id), None)
            expected_expiry = _time_text(current_time + timedelta(seconds=duration))
            existing_item = items.get(existing["work_item_id"])
            if existing_item is None:
                raise DependencyError("dependency_request_id_reused")
            expected_reads, expected_writes = _scopes(existing_item)
            if (
                prior is not None
                and existing["prior_claim_id"] == claim_id
                and existing["holder"] == holder
                and existing["board_sha256"] == board_hash
                and existing["acquired_at"] == now
                and existing["expires_at"] == expected_expiry
                and existing["read_scope"] == expected_reads
                and existing["write_scope"] == expected_writes
                and prior["fencing_token"] == fencing_token
                and prior["outcome_history"][-1] == _history("failed", now, reason)
            ):
                return existing
            raise DependencyError("dependency_request_id_reused")
        row = next((value for value in registry["claims"] if value["claim_id"] == claim_id), None)
        if row is None: raise DependencyError("dependency_claim_unknown")
        _check_current(row, holder, board_hash, fencing_token)
        if row["state"] != "active": raise DependencyError("dependency_claim_not_active")
        if current_time < _time(row["acquired_at"]): raise DependencyError("dependency_clock_reversal")
        if current_time >= _time(row["expires_at"]): raise DependencyError("dependency_claim_expired")
        item = items[row["work_item_id"]]
        maximum = item.get("retry_policy", {}).get("max_attempts", 1)
        if row["attempt"] >= maximum: raise DependencyError("dependency_retry_exhausted")
        row["state"] = "failed"; row["outcome_history"].append(_history("failed", now, reason))
        return _new_claim(registry, item, request_id=request_id, holder=holder, board_hash=board_hash, now=now, duration=duration, attempt=row["attempt"] + 1, prior=row["claim_id"], reason="retry_after_failure")
    return _mutate(registry_path, operation)


def recover(registry_path: Path, graph: object, claim_id: str, *, request_id: str, holder: object, board_hash: str, now: str, duration_seconds: int) -> dict[str, Any]:
    validate_graph(graph); assert isinstance(graph, dict)
    holder = validate_holder(holder); _hash(board_hash, "dependency_claim_board_hash_invalid")
    current_time = _time(now); duration = _duration(duration_seconds)
    request_id = _text(request_id, "dependency_request_id_invalid"); items = _items(graph)
    def operation(registry: dict[str, Any]) -> dict[str, Any]:
        if any(row["request_id"] == request_id for row in registry["claims"]):
            existing = next(row for row in registry["claims"] if row["request_id"] == request_id)
            prior = next((row for row in registry["claims"] if row["claim_id"] == claim_id), None)
            expected_expiry = _time_text(current_time + timedelta(seconds=duration))
            existing_item = items.get(existing["work_item_id"])
            if existing_item is None:
                raise DependencyError("dependency_request_id_reused")
            expected_reads, expected_writes = _scopes(existing_item)
            if (
                prior is not None
                and existing["prior_claim_id"] == claim_id
                and existing["holder"] == holder
                and existing["board_sha256"] == board_hash
                and existing["acquired_at"] == now
                and existing["expires_at"] == expected_expiry
                and existing["read_scope"] == expected_reads
                and existing["write_scope"] == expected_writes
                and prior["outcome_history"][-1]
                == _history("recovered", now, "expired_claim_replaced")
            ):
                return existing
            raise DependencyError("dependency_request_id_reused")
        row = next((value for value in registry["claims"] if value["claim_id"] == claim_id), None)
        if row is None: raise DependencyError("dependency_claim_unknown")
        if row["state"] != "active": raise DependencyError("dependency_claim_not_active")
        if row["board_sha256"] != board_hash: raise DependencyError("dependency_claim_board_hash_mismatch")
        if current_time < _time(row["acquired_at"]): raise DependencyError("dependency_clock_reversal")
        if current_time < _time(row["expires_at"]): raise DependencyError("dependency_claim_not_expired")
        item = items[row["work_item_id"]]
        maximum = item.get("retry_policy", {}).get("max_attempts", 1)
        if row["attempt"] >= maximum: raise DependencyError("dependency_retry_exhausted")
        row["state"] = "recovered"; row["outcome_history"].append(_history("recovered", now, "expired_claim_replaced"))
        return _new_claim(registry, item, request_id=request_id, holder=holder, board_hash=board_hash, now=now, duration=duration, attempt=row["attempt"] + 1, prior=row["claim_id"], reason="stale_claim_recovery")
    return _mutate(registry_path, operation)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DependencyError("dependency_input_missing") from error
    except (OSError, UnicodeDecodeError) as error:
        raise DependencyError("dependency_input_unavailable") from error
    except json.JSONDecodeError as error:
        raise DependencyError("dependency_input_json_invalid") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in ("ready", "parallel"):
        child = commands.add_parser(name); child.add_argument("graph", type=Path); child.add_argument("satisfaction", type=Path); child.add_argument("--board-hash")
    child = commands.add_parser("blocked"); child.add_argument("graph", type=Path); child.add_argument("satisfaction", type=Path); child.add_argument("work_item_id"); child.add_argument("--board-hash")
    child = commands.add_parser("containment"); child.add_argument("graph", type=Path); child.add_argument("work_item_id"); child.add_argument("--direction", choices=("ancestors", "descendants", "roots"), default="descendants")
    child = commands.add_parser("artifacts"); child.add_argument("graph", type=Path)
    child = commands.add_parser("verify-registry"); child.add_argument("registry", type=Path)
    child = commands.add_parser("claim"); child.add_argument("graph", type=Path); child.add_argument("satisfaction", type=Path); child.add_argument("registry", type=Path); child.add_argument("work_item_id"); child.add_argument("request_id"); child.add_argument("holder", type=Path); child.add_argument("now"); child.add_argument("duration_seconds", type=int); child.add_argument("--board-hash")
    child = commands.add_parser("renew"); child.add_argument("registry", type=Path); child.add_argument("claim_id"); child.add_argument("holder", type=Path); child.add_argument("board_hash"); child.add_argument("fencing_token", type=int); child.add_argument("now"); child.add_argument("duration_seconds", type=int)
    child = commands.add_parser("release"); child.add_argument("registry", type=Path); child.add_argument("claim_id"); child.add_argument("holder", type=Path); child.add_argument("board_hash"); child.add_argument("fencing_token", type=int); child.add_argument("now")
    child = commands.add_parser("retry"); child.add_argument("graph", type=Path); child.add_argument("registry", type=Path); child.add_argument("claim_id"); child.add_argument("request_id"); child.add_argument("holder", type=Path); child.add_argument("board_hash"); child.add_argument("fencing_token", type=int); child.add_argument("now"); child.add_argument("duration_seconds", type=int); child.add_argument("reason")
    child = commands.add_parser("recover"); child.add_argument("graph", type=Path); child.add_argument("registry", type=Path); child.add_argument("claim_id"); child.add_argument("request_id"); child.add_argument("holder", type=Path); child.add_argument("board_hash"); child.add_argument("now"); child.add_argument("duration_seconds", type=int)
    args = parser.parse_args(argv)
    try:
        if args.operation == "ready": result = ready(_load_json(args.graph), _load_json(args.satisfaction), expected_board_hash=args.board_hash)
        elif args.operation == "parallel": result = parallel_groups(_load_json(args.graph), _load_json(args.satisfaction), expected_board_hash=args.board_hash)
        elif args.operation == "blocked": result = explain_blocked(_load_json(args.graph), _load_json(args.satisfaction), args.work_item_id, expected_board_hash=args.board_hash)
        elif args.operation == "containment": result = containment(_load_json(args.graph), args.work_item_id, args.direction)
        elif args.operation == "artifacts": result = artifact_flow(_load_json(args.graph))
        elif args.operation == "verify-registry": result = verify_registry(read_registry(args.registry))
        elif args.operation == "claim": result = claim(args.registry, _load_json(args.graph), _load_json(args.satisfaction), args.work_item_id, request_id=args.request_id, holder=_load_json(args.holder), now=args.now, duration_seconds=args.duration_seconds, expected_board_hash=args.board_hash)
        elif args.operation == "renew": result = renew(args.registry, args.claim_id, holder=_load_json(args.holder), board_hash=args.board_hash, fencing_token=args.fencing_token, now=args.now, duration_seconds=args.duration_seconds)
        elif args.operation == "release": result = release(args.registry, args.claim_id, holder=_load_json(args.holder), board_hash=args.board_hash, fencing_token=args.fencing_token, now=args.now)
        elif args.operation == "retry": result = retry(args.registry, _load_json(args.graph), args.claim_id, request_id=args.request_id, holder=_load_json(args.holder), board_hash=args.board_hash, fencing_token=args.fencing_token, now=args.now, duration_seconds=args.duration_seconds, reason=args.reason)
        else: result = recover(args.registry, _load_json(args.graph), args.claim_id, request_id=args.request_id, holder=_load_json(args.holder), board_hash=args.board_hash, now=args.now, duration_seconds=args.duration_seconds)
        print(canonical_json({"protocol": "workgraph_dependencies", "operation": args.operation, "schema_version": 1, "status": "ok", "result": result}))
        return 0
    except DependencyError as error:
        payload = {"protocol": "workgraph_dependencies", "operation": args.operation, "schema_version": 1, "status": "error", "error": error.code}
        if error.details is not None: payload["details"] = error.details
        print(canonical_json(payload)); return 2


if __name__ == "__main__":
    raise SystemExit(main())
