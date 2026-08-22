#!/usr/bin/env python3
"""Append and inspect strict WorkGraph activity-v1 JSONL ledgers."""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Sequence


SCHEMA_VERSION = 1
CURSOR_VERSION = 1
GENESIS_HASH = "0" * 64
EVENT_KINDS = {
    "progress", "observation", "question", "concern", "blocker",
    "test_result", "decision_request", "handoff", "correction",
}
AUTHOR_ROLES = {"Worker", "Tester", "Auditor", "Parent", "user", "system"}
PROVENANCE = {"unknown", "declared", "parent_assigned", "runtime_observed", "receipt_backed"}
OBSERVED_PROVENANCE = {"unknown", "runtime_observed", "receipt_backed"}
IDENTITY_KEYS = {"agent_name", "agent_id", "provider", "model", "route_id", "runtime"}
EVENT_KEYS = {
    "schema_version", "event_id", "task_id", "sequence", "timestamp",
    "event_kind", "author_role", "identity", "body", "evidence",
    "reply_to", "correction_of", "board_sha256", "previous_event_hash",
    "event_hash",
}
DRAFT_KEYS = EVENT_KEYS - {"sequence", "previous_event_hash", "event_hash"}
EVIDENCE_KEYS = {"evidence_id", "locator", "digest"}
SHA256_HEX = set("0123456789abcdef")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")


class ActivityError(Exception):
    """Stable activity protocol failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def row_hash(row: dict[str, Any]) -> str:
    payload = {key: value for key, value in row.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _is_hash(value: object, *, prefixed: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value[7:] if prefixed and value.startswith("sha256:") else value
    if prefixed and not value.startswith("sha256:"):
        return False
    return len(candidate) == 64 and all(character in SHA256_HEX for character in candidate)


def _require_string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ActivityError(code)
    return value


def _validate_timestamp(value: object) -> None:
    text = _require_string(value, "activity_timestamp_invalid")
    if RFC3339_UTC.fullmatch(text) is None:
        raise ActivityError("activity_timestamp_invalid")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ActivityError("activity_timestamp_invalid") from error


def _validate_fact(value: object, field: str, *, observed_only: bool = False) -> None:
    if not isinstance(value, dict) or set(value) != {"value", "provenance"}:
        raise ActivityError(f"activity_identity_{field}_invalid")
    fact = value["value"]
    provenance = value["provenance"]
    allowed = OBSERVED_PROVENANCE if observed_only else PROVENANCE
    if not isinstance(fact, str) or not fact or provenance not in allowed:
        raise ActivityError(f"activity_identity_{field}_invalid")
    if (fact == "unknown") != (provenance == "unknown"):
        raise ActivityError(f"activity_identity_{field}_provenance_invalid")
    if observed_only and fact != "unknown" and provenance not in {"runtime_observed", "receipt_backed"}:
        raise ActivityError(f"activity_identity_{field}_provenance_invalid")


def _validate_identity(value: object) -> None:
    if not isinstance(value, dict) or set(value) != IDENTITY_KEYS:
        raise ActivityError("activity_identity_invalid")
    for field in sorted(IDENTITY_KEYS):
        _validate_fact(value[field], field, observed_only=field == "runtime")


def _validate_evidence(value: object) -> None:
    if not isinstance(value, list):
        raise ActivityError("activity_evidence_invalid")
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != EVIDENCE_KEYS:
            raise ActivityError("activity_evidence_invalid")
        evidence_id = _require_string(entry["evidence_id"], "activity_evidence_id_invalid")
        _require_string(entry["locator"], "activity_evidence_locator_invalid")
        digest = entry["digest"]
        if digest != "unknown" and not _is_hash(digest, prefixed=True):
            raise ActivityError("activity_evidence_digest_invalid")
        if evidence_id in seen:
            raise ActivityError("activity_evidence_duplicate")
        seen.add(evidence_id)


def _validate_shape(row: object) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) != EVENT_KEYS:
        raise ActivityError("activity_row_shape_invalid")
    version = row["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ActivityError("activity_schema_version_invalid")
    if version != SCHEMA_VERSION:
        raise ActivityError("activity_schema_version_unsupported")
    _require_string(row["event_id"], "activity_event_id_invalid")
    _require_string(row["task_id"], "activity_task_id_invalid")
    sequence = row["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ActivityError("activity_sequence_invalid")
    _validate_timestamp(row["timestamp"])
    if row["event_kind"] not in EVENT_KINDS:
        raise ActivityError("activity_event_kind_invalid")
    if row["author_role"] not in AUTHOR_ROLES:
        raise ActivityError("activity_author_role_invalid")
    _validate_identity(row["identity"])
    _require_string(row["body"], "activity_body_invalid")
    _validate_evidence(row["evidence"])
    for field in ("reply_to", "correction_of"):
        if row[field] is not None:
            _require_string(row[field], f"activity_{field}_invalid")
    if row["event_kind"] == "correction" and row["correction_of"] is None:
        raise ActivityError("activity_correction_target_required")
    if row["event_kind"] != "correction" and row["correction_of"] is not None:
        raise ActivityError("activity_correction_kind_required")
    if not _is_hash(row["board_sha256"], prefixed=True):
        raise ActivityError("activity_board_hash_invalid")
    if not _is_hash(row["previous_event_hash"]):
        raise ActivityError("activity_previous_hash_invalid")
    if not _is_hash(row["event_hash"]):
        raise ActivityError("activity_event_hash_invalid")
    return row


def verify_rows(rows: list[object], *, expected_board_hash: str | None = None) -> dict[str, Any]:
    validated = [_validate_shape(raw_row) for raw_row in rows]
    all_by_id: dict[str, dict[str, Any]] = {}
    for row in validated:
        if row["event_id"] in all_by_id:
            raise ActivityError("activity_event_id_duplicate")
        all_by_id[row["event_id"]] = row
    correction_edges = {
        row["event_id"]: row["correction_of"]
        for row in validated if row["correction_of"] is not None
    }
    for event_id in sorted(correction_edges):
        visited: set[str] = set()
        target: str | None = event_id
        while target in correction_edges:
            if target in visited:
                raise ActivityError("activity_correction_cycle")
            visited.add(target)
            target = correction_edges[target]
    previous_hash = GENESIS_HASH
    by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(validated, start=1):
        if row["sequence"] != index:
            raise ActivityError("activity_sequence_non_monotonic")
        event_id = row["event_id"]
        if row["previous_event_hash"] != previous_hash:
            raise ActivityError("activity_hash_chain_broken")
        if row_hash(row) != row["event_hash"]:
            raise ActivityError("activity_event_hash_mismatch")
        if expected_board_hash is not None and row["board_sha256"] != expected_board_hash:
            raise ActivityError("activity_board_hash_mismatch")
        for field in ("reply_to", "correction_of"):
            target_id = row[field]
            if target_id is None:
                continue
            target = by_id.get(target_id)
            if target is None:
                if target_id not in all_by_id:
                    raise ActivityError(f"activity_{field}_target_missing")
                raise ActivityError(f"activity_{field}_target_not_prior")
            if target["task_id"] != row["task_id"]:
                raise ActivityError(f"activity_{field}_task_mismatch")
        by_id[event_id] = row
        previous_hash = row["event_hash"]
    return {
        "event_count": len(rows),
        "head_hash": previous_hash,
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
    }


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ActivityError("activity_json_duplicate_key")
        result[key] = value
    return result


def _parse_bytes(raw: bytes, *, allow_empty: bool) -> list[dict[str, Any]]:
    if not raw:
        if allow_empty:
            return []
        raise ActivityError("activity_log_empty")
    if not raw.endswith(b"\n"):
        raise ActivityError("activity_log_truncated")
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            raise ActivityError("activity_log_blank_line")
        try:
            value = json.loads(line.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
        except ActivityError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivityError("activity_json_invalid") from error
        if not isinstance(value, dict):
            raise ActivityError("activity_row_shape_invalid")
        rows.append(value)
    return rows


def read_rows(path: Path, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise ActivityError("activity_log_missing") from error
    except OSError as error:
        raise ActivityError("activity_log_unavailable") from error
    rows = _parse_bytes(raw, allow_empty=allow_empty)
    verify_rows(rows)
    return rows


def _build_event(draft: object, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(draft, dict) or set(draft) != DRAFT_KEYS:
        raise ActivityError("activity_draft_shape_invalid")
    row = dict(draft)
    row["sequence"] = len(rows) + 1
    row["previous_event_hash"] = rows[-1]["event_hash"] if rows else GENESIS_HASH
    row["event_hash"] = GENESIS_HASH
    row["event_hash"] = row_hash(row)
    verify_rows([*rows, row])
    return row


def append_event(path: Path, draft: object) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        raise ActivityError("activity_log_unavailable") from error
    try:
        with os.fdopen(descriptor, "r+b", closefd=True) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            raw = stream.read()
            rows = _parse_bytes(raw, allow_empty=True)
            if rows:
                verify_rows(rows)
            row = _build_event(draft, rows)
            stream.seek(0, os.SEEK_END)
            payload = (canonical_json(row) + "\n").encode("utf-8")
            written = stream.write(payload)
            if written != len(payload):
                raise ActivityError("activity_append_incomplete")
            stream.flush()
            os.fsync(stream.fileno())
            return row
    except ActivityError:
        raise
    except OSError as error:
        raise ActivityError("activity_append_failed") from error


def replay(path: Path, *, task_id: str | None = None, event_kind: str | None = None) -> list[dict[str, Any]]:
    rows = read_rows(path)
    if event_kind is not None and event_kind not in EVENT_KINDS:
        raise ActivityError("activity_filter_kind_invalid")
    return [
        row for row in rows
        if (task_id is None or row["task_id"] == task_id)
        and (event_kind is None or row["event_kind"] == event_kind)
    ]


def consume(path: Path, cursor: object, *, limit: int | None = None) -> dict[str, Any]:
    rows = read_rows(path)
    if not isinstance(cursor, dict) or set(cursor) != {
        "schema_version", "consumer_id", "next_sequence", "head_hash"
    }:
        raise ActivityError("activity_cursor_invalid")
    cursor_version = cursor["schema_version"]
    if not isinstance(cursor_version, int) or isinstance(cursor_version, bool):
        raise ActivityError("activity_cursor_version_invalid")
    if cursor_version != CURSOR_VERSION:
        raise ActivityError("activity_cursor_version_unsupported")
    _require_string(cursor["consumer_id"], "activity_cursor_consumer_invalid")
    next_sequence = cursor["next_sequence"]
    if not isinstance(next_sequence, int) or isinstance(next_sequence, bool) or next_sequence < 1:
        raise ActivityError("activity_cursor_sequence_invalid")
    if next_sequence > len(rows) + 1:
        raise ActivityError("activity_cursor_ahead")
    expected_prior = GENESIS_HASH if next_sequence == 1 else rows[next_sequence - 2]["event_hash"]
    if cursor["head_hash"] != expected_prior:
        raise ActivityError("activity_cursor_hash_mismatch")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        raise ActivityError("activity_cursor_limit_invalid")
    selected = rows[next_sequence - 1:]
    if limit is not None:
        selected = selected[:limit]
    new_next = next_sequence + len(selected)
    new_head = expected_prior if not selected else selected[-1]["event_hash"]
    return {
        "cursor": {
            "schema_version": CURSOR_VERSION,
            "consumer_id": cursor["consumer_id"],
            "next_sequence": new_next,
            "head_hash": new_head,
        },
        "events": selected,
        "remaining": len(rows) - (new_next - 1),
        "status": "ok",
    }


def _load_json(path: Path) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ActivityError("activity_input_unavailable") from error
    try:
        return json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except ActivityError:
        raise
    except json.JSONDecodeError as error:
        raise ActivityError("activity_input_json_invalid") from error


def _receipt(operation: str, **values: object) -> dict[str, Any]:
    return {"operation": operation, "protocol": "workgraph_activity", "schema_version": 1, "status": "ok", **values}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("log", type=Path)
    append_parser.add_argument("draft", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("log", type=Path)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("log", type=Path)
    replay_parser.add_argument("--task-id")
    replay_parser.add_argument("--event-kind")
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("log", type=Path)
    consume_parser.add_argument("cursor", type=Path)
    consume_parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    try:
        if args.operation == "append":
            row = append_event(args.log, _load_json(args.draft))
            result = _receipt("append", event=row)
        elif args.operation == "verify":
            rows = read_rows(args.log)
            result = _receipt("verify", **verify_rows(rows))
        elif args.operation == "replay":
            events = replay(args.log, task_id=args.task_id, event_kind=args.event_kind)
            result = _receipt("replay", event_count=len(events), events=events)
        else:
            result = _receipt("consume", **consume(args.log, _load_json(args.cursor), limit=args.limit))
    except ActivityError as error:
        print(canonical_json({
            "error": error.code,
            "operation": getattr(args, "operation", "unknown"),
            "protocol": "workgraph_activity",
            "schema_version": 1,
            "status": "error",
        }))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
