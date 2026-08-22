#!/usr/bin/env python3
"""Append and inspect strict WorkGraph updates-v1 JSONL ledgers."""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Sequence


SCHEMA_VERSION = 1
CURSOR_VERSION = 1
GENESIS_HASH = "0" * 64
UPDATE_KINDS = {"task_transition", "task_creation", "dependency_change", "metadata_change", "scope_change"}
TRANSITIONS = {"proposed", "reviewed", "rejected", "superseded", "applied", "reconciled"}
REVIEW_STATUSES = {"pending", "approved", "rejected", "superseded", "applied", "reconciled"}
ACTOR_ROLES = {"Worker", "Tester", "Auditor", "Parent", "user", "system", "GoalBuddyOwner"}
PROVENANCE = {"unknown", "declared", "parent_assigned", "runtime_observed", "receipt_backed"}
OBSERVED_PROVENANCE = {"unknown", "runtime_observed", "receipt_backed"}
IDENTITY_KEYS = {"role", "agent_name", "agent_id", "provider", "model", "route_id", "runtime"}
AUTHORITY_KEYS = {
    "source", "receipt_id", "provenance", "allowed_patch_paths",
    "may_accept", "may_mutate_canonical_state",
}
PATCH_KEYS = {"op", "path", "value"}
RECONCILIATION_KEYS = {"observed_state_sha256", "outcome"}
ROW_KEYS = {
    "schema_version", "row_id", "update_id", "sequence", "timestamp",
    "target_task", "update_kind", "transition", "proposed_patch",
    "proposer_identity", "expected_board_sha256", "authority_reference",
    "review_status", "reviewer_identity", "parent_decision",
    "applied_state_sha256", "superseded_by_update_id", "reconciliation",
    "previous_update_hash", "previous_row_hash", "row_hash",
}
DRAFT_KEYS = ROW_KEYS - {"sequence", "previous_update_hash", "previous_row_hash", "row_hash"}
SHA256_HEX = set("0123456789abcdef")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")


class UpdateError(Exception):
    """Stable update protocol failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def row_hash(row: dict[str, Any]) -> str:
    payload = {key: value for key, value in row.items() if key != "row_hash"}
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
        raise UpdateError(code)
    return value


def _validate_timestamp(value: object) -> None:
    text = _require_string(value, "update_timestamp_invalid")
    if RFC3339_UTC.fullmatch(text) is None:
        raise UpdateError("update_timestamp_invalid")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise UpdateError("update_timestamp_invalid") from error


def _validate_fact(value: object, field: str, *, observed_only: bool = False) -> None:
    if not isinstance(value, dict) or set(value) != {"value", "provenance"}:
        raise UpdateError(f"update_identity_{field}_invalid")
    fact = value["value"]
    provenance = value["provenance"]
    allowed = OBSERVED_PROVENANCE if observed_only else PROVENANCE
    if not isinstance(fact, str) or not fact or provenance not in allowed:
        raise UpdateError(f"update_identity_{field}_invalid")
    if (fact == "unknown") != (provenance == "unknown"):
        raise UpdateError(f"update_identity_{field}_provenance_invalid")
    if observed_only and fact != "unknown" and provenance not in {"runtime_observed", "receipt_backed"}:
        raise UpdateError(f"update_identity_{field}_provenance_invalid")


def _validate_identity(value: object, *, reviewer: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != IDENTITY_KEYS:
        raise UpdateError("update_reviewer_identity_invalid" if reviewer else "update_proposer_identity_invalid")
    if value["role"] not in ACTOR_ROLES:
        raise UpdateError("update_identity_role_invalid")
    for field in sorted(IDENTITY_KEYS - {"role"}):
        _validate_fact(value[field], field, observed_only=field == "runtime")
    return value


def _pointer_segments(pointer: object) -> tuple[str, ...]:
    if not isinstance(pointer, str) or not pointer.startswith("/") or pointer == "/":
        raise UpdateError("update_patch_path_invalid")
    result: list[str] = []
    for raw_segment in pointer[1:].split("/"):
        decoded = ""
        index = 0
        while index < len(raw_segment):
            if raw_segment[index] != "~":
                decoded += raw_segment[index]
                index += 1
                continue
            if index + 1 >= len(raw_segment) or raw_segment[index + 1] not in {"0", "1"}:
                raise UpdateError("update_patch_path_invalid")
            decoded += "~" if raw_segment[index + 1] == "0" else "/"
            index += 2
        if not decoded:
            raise UpdateError("update_patch_path_invalid")
        result.append(decoded)
    return tuple(result)


def _is_under(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(path) >= len(prefix) and path[:len(prefix)] == prefix


def _validate_authority(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != AUTHORITY_KEYS:
        raise UpdateError("update_authority_invalid")
    source = _require_string(value["source"], "update_authority_source_invalid")
    _require_string(value["receipt_id"], "update_authority_receipt_invalid")
    provenance = value["provenance"]
    if provenance not in {"parent_issued", "operator_issued"}:
        raise UpdateError("update_authority_provenance_invalid")
    prefix = "parent:" if provenance == "parent_issued" else "operator:"
    if not source.startswith(prefix) or source == prefix:
        raise UpdateError("update_authority_source_mismatch")
    paths = value["allowed_patch_paths"]
    if not isinstance(paths, list) or not paths:
        raise UpdateError("update_authority_paths_invalid")
    normalized = [_pointer_segments(path) for path in paths]
    if len(normalized) != len(set(normalized)):
        raise UpdateError("update_authority_paths_duplicate")
    if value["may_accept"] is not False:
        raise UpdateError("update_authority_accept_forbidden")
    if value["may_mutate_canonical_state"] is not False:
        raise UpdateError("update_authority_mutation_forbidden")
    return value


def _validate_patch(value: object, target_task: str, authority: dict[str, Any]) -> None:
    if not isinstance(value, list) or not value:
        raise UpdateError("update_patch_invalid")
    allowed = [_pointer_segments(path) for path in authority["allowed_patch_paths"]]
    task_prefix = ("tasks", target_task)
    seen: set[tuple[str, ...]] = set()
    for operation in value:
        if not isinstance(operation, dict):
            raise UpdateError("update_patch_operation_invalid")
        op = operation.get("op")
        expected_keys = PATCH_KEYS if op in {"add", "replace"} else PATCH_KEYS - {"value"}
        if set(operation) != expected_keys or op not in {"add", "replace", "remove"}:
            raise UpdateError("update_patch_operation_invalid")
        path = _pointer_segments(operation["path"])
        if path in seen:
            raise UpdateError("update_patch_path_duplicate")
        seen.add(path)
        if not _is_under(path, task_prefix):
            raise UpdateError("update_patch_target_mismatch")
        if not any(_is_under(path, prefix) for prefix in allowed):
            raise UpdateError("update_patch_scope_broadened")


def _validate_task_creation(row: dict[str, Any]) -> None:
    if row["update_kind"] != "task_creation":
        return
    patch = row["proposed_patch"]
    expected_path = f"/tasks/{row['target_task']}"
    if len(patch) != 1 or patch[0].get("op") != "add" or patch[0].get("path") != expected_path:
        raise UpdateError("update_task_creation_patch_invalid")
    value = patch[0].get("value")
    if not isinstance(value, dict) or value.get("id") != row["target_task"]:
        raise UpdateError("update_task_creation_value_invalid")
    if value.get("status") != "queued":
        raise UpdateError("update_task_creation_status_invalid")
    if row["authority_reference"]["allowed_patch_paths"] != [expected_path]:
        raise UpdateError("update_task_creation_authority_invalid")


def _validate_reconciliation(value: object) -> None:
    if not isinstance(value, dict) or set(value) != RECONCILIATION_KEYS:
        raise UpdateError("update_reconciliation_invalid")
    if not _is_hash(value["observed_state_sha256"], prefixed=True):
        raise UpdateError("update_reconciliation_hash_invalid")
    if value["outcome"] not in {"matched", "diverged", "recovered"}:
        raise UpdateError("update_reconciliation_outcome_invalid")


def _validate_shape(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != ROW_KEYS:
        raise UpdateError("update_row_shape_invalid")
    version = raw["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise UpdateError("update_schema_version_invalid")
    if version != SCHEMA_VERSION:
        raise UpdateError("update_schema_version_unsupported")
    for field in ("row_id", "update_id", "target_task"):
        _require_string(raw[field], f"update_{field}_invalid")
    sequence = raw["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise UpdateError("update_sequence_invalid")
    _validate_timestamp(raw["timestamp"])
    if raw["update_kind"] not in UPDATE_KINDS:
        raise UpdateError("update_kind_invalid")
    if raw["transition"] not in TRANSITIONS:
        raise UpdateError("update_transition_invalid")
    proposer = _validate_identity(raw["proposer_identity"])
    if proposer["role"] == "Parent" and raw["transition"] == "proposed":
        pass
    if not _is_hash(raw["expected_board_sha256"], prefixed=True):
        raise UpdateError("update_expected_board_hash_invalid")
    authority = _validate_authority(raw["authority_reference"])
    _validate_patch(raw["proposed_patch"], raw["target_task"], authority)
    _validate_task_creation(raw)
    if raw["review_status"] not in REVIEW_STATUSES:
        raise UpdateError("update_review_status_invalid")
    reviewer = raw["reviewer_identity"]
    if reviewer is not None:
        reviewer = _validate_identity(reviewer, reviewer=True)
    if raw["parent_decision"] not in {None, "approve", "reject", "supersede"}:
        raise UpdateError("update_parent_decision_invalid")
    if raw["applied_state_sha256"] is not None and not _is_hash(raw["applied_state_sha256"], prefixed=True):
        raise UpdateError("update_applied_state_hash_invalid")
    if raw["superseded_by_update_id"] is not None:
        _require_string(raw["superseded_by_update_id"], "update_superseded_by_invalid")
    if raw["reconciliation"] is not None:
        _validate_reconciliation(raw["reconciliation"])
    for field in ("previous_update_hash", "previous_row_hash", "row_hash"):
        if not _is_hash(raw[field]):
            raise UpdateError(f"update_{field}_invalid")
    return raw


def _assert_parent_reviewer(row: dict[str, Any]) -> None:
    reviewer = row["reviewer_identity"]
    if not isinstance(reviewer, dict) or reviewer["role"] != "Parent":
        raise UpdateError("update_parent_reviewer_required")
    authority = row["authority_reference"]
    if authority["provenance"] != "parent_issued":
        raise UpdateError("update_parent_authority_required")
    proposer_id = row["proposer_identity"]["agent_id"]["value"]
    reviewer_id = reviewer["agent_id"]["value"]
    if proposer_id == "unknown" or reviewer_id == "unknown":
        raise UpdateError("update_reviewer_independence_unproved")
    if proposer_id == reviewer_id:
        raise UpdateError("update_self_review_forbidden")


def _validate_transition(row: dict[str, Any], prior: dict[str, Any] | None) -> None:
    transition = row["transition"]
    if transition == "proposed":
        if prior is not None:
            raise UpdateError("update_proposal_duplicate")
        expected = ("pending", None, None, None, None)
    else:
        if prior is None:
            raise UpdateError("update_lineage_missing_proposal")
        _assert_parent_reviewer(row)
        immutable = (
            "target_task", "update_kind", "proposed_patch", "proposer_identity",
            "expected_board_sha256", "authority_reference",
        )
        if any(row[field] != prior[field] for field in immutable):
            raise UpdateError("update_lineage_payload_mismatch")
        if transition == "reviewed":
            if prior["transition"] != "proposed":
                raise UpdateError("update_transition_invalid_lineage")
            _assert_parent_reviewer(row)
            if row["parent_decision"] == "approve":
                expected = ("approved", "approve", None, None, None)
            elif row["parent_decision"] == "reject":
                expected = ("rejected", "reject", None, None, None)
            else:
                raise UpdateError("update_parent_decision_required")
        elif transition == "rejected":
            if prior["transition"] != "reviewed" or prior["parent_decision"] != "reject":
                raise UpdateError("update_transition_invalid_lineage")
            _assert_parent_reviewer(row)
            if row["reviewer_identity"] != prior["reviewer_identity"]:
                raise UpdateError("update_reviewer_lineage_mismatch")
            expected = ("rejected", "reject", None, None, None)
        elif transition == "applied":
            if prior["transition"] != "reviewed" or prior["parent_decision"] != "approve":
                raise UpdateError("update_applied_without_parent_approval")
            _assert_parent_reviewer(row)
            if row["reviewer_identity"] != prior["reviewer_identity"]:
                raise UpdateError("update_reviewer_lineage_mismatch")
            if row["applied_state_sha256"] is None:
                raise UpdateError("update_applied_state_hash_required")
            expected = ("applied", "approve", row["applied_state_sha256"], None, None)
        elif transition == "superseded":
            if prior["transition"] not in {"proposed", "reviewed"}:
                raise UpdateError("update_transition_invalid_lineage")
            _assert_parent_reviewer(row)
            if row["superseded_by_update_id"] is None:
                raise UpdateError("update_superseded_by_required")
            expected = ("superseded", "supersede", None, row["superseded_by_update_id"], None)
        else:
            if prior["transition"] != "applied":
                raise UpdateError("update_transition_invalid_lineage")
            _assert_parent_reviewer(row)
            if row["reviewer_identity"] != prior["reviewer_identity"]:
                raise UpdateError("update_reviewer_lineage_mismatch")
            if row["applied_state_sha256"] is None or row["reconciliation"] is None:
                raise UpdateError("update_reconciliation_required")
            if row["applied_state_sha256"] != prior["applied_state_sha256"]:
                raise UpdateError("update_reconciled_applied_hash_mismatch")
            observed = row["reconciliation"]["observed_state_sha256"]
            outcome = row["reconciliation"]["outcome"]
            hashes_match = observed == prior["applied_state_sha256"]
            if (outcome in {"matched", "recovered"}) != hashes_match:
                raise UpdateError("update_reconciliation_outcome_mismatch")
            expected = ("reconciled", "approve", row["applied_state_sha256"], None, row["reconciliation"])
    actual = (
        row["review_status"], row["parent_decision"], row["applied_state_sha256"],
        row["superseded_by_update_id"], row["reconciliation"],
    )
    if actual != expected:
        raise UpdateError("update_transition_fields_invalid")
    if transition == "proposed" and row["reviewer_identity"] is not None:
        raise UpdateError("update_proposal_reviewer_forbidden")
    if transition != "proposed" and row["reviewer_identity"] is None:
        raise UpdateError("update_parent_reviewer_required")


def verify_rows(rows: list[object]) -> dict[str, Any]:
    previous_row_hash = GENESIS_HASH
    row_ids: set[str] = set()
    lineage: dict[str, dict[str, Any]] = {}
    proposals: set[str] = set()
    for sequence, raw in enumerate(rows, start=1):
        row = _validate_shape(raw)
        if row["sequence"] != sequence:
            raise UpdateError("update_sequence_non_monotonic")
        if row["row_id"] in row_ids:
            raise UpdateError("update_row_id_duplicate")
        if row["previous_row_hash"] != previous_row_hash:
            raise UpdateError("update_hash_chain_broken")
        prior = lineage.get(row["update_id"])
        expected_update_hash = prior["row_hash"] if prior is not None else GENESIS_HASH
        if row["previous_update_hash"] != expected_update_hash:
            raise UpdateError("update_lineage_hash_broken")
        if row_hash(row) != row["row_hash"]:
            raise UpdateError("update_row_hash_mismatch")
        _validate_transition(row, prior)
        if row["transition"] == "proposed":
            proposals.add(row["update_id"])
        if row["transition"] == "superseded":
            replacement = row["superseded_by_update_id"]
            if replacement == row["update_id"]:
                raise UpdateError("update_supersession_cycle")
            if replacement not in proposals:
                raise UpdateError("update_superseding_proposal_missing")
            target = replacement
            visited = {row["update_id"]}
            while True:
                if target in visited:
                    raise UpdateError("update_supersession_cycle")
                visited.add(target)
                prior_target = lineage.get(target)
                if prior_target is None or prior_target["transition"] != "superseded":
                    break
                target = prior_target["superseded_by_update_id"]
        row_ids.add(row["row_id"])
        lineage[row["update_id"]] = row
        previous_row_hash = row["row_hash"]
    return {
        "head_hash": previous_row_hash,
        "row_count": len(rows),
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
        "update_count": len(lineage),
    }


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError("update_json_duplicate_key")
        result[key] = value
    return result


def _parse_bytes(raw: bytes, *, allow_empty: bool) -> list[dict[str, Any]]:
    if not raw:
        if allow_empty:
            return []
        raise UpdateError("update_log_empty")
    if not raw.endswith(b"\n"):
        raise UpdateError("update_log_truncated")
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            raise UpdateError("update_log_blank_line")
        try:
            value = json.loads(line.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
        except UpdateError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise UpdateError("update_json_invalid") from error
        if not isinstance(value, dict):
            raise UpdateError("update_row_shape_invalid")
        rows.append(value)
    return rows


def read_rows(path: Path, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise UpdateError("update_log_missing") from error
    except OSError as error:
        raise UpdateError("update_log_unavailable") from error
    rows = _parse_bytes(raw, allow_empty=allow_empty)
    verify_rows(rows)
    return rows


def _build_row(draft: object, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(draft, dict) or set(draft) != DRAFT_KEYS:
        raise UpdateError("update_draft_shape_invalid")
    prior = next((row for row in reversed(rows) if row["update_id"] == draft["update_id"]), None)
    row = dict(draft)
    row["sequence"] = len(rows) + 1
    row["previous_update_hash"] = prior["row_hash"] if prior else GENESIS_HASH
    row["previous_row_hash"] = rows[-1]["row_hash"] if rows else GENESIS_HASH
    row["row_hash"] = GENESIS_HASH
    row["row_hash"] = row_hash(row)
    verify_rows([*rows, row])
    return row


def append_update(path: Path, draft: object, *, current_board_hash: str) -> dict[str, Any]:
    if not _is_hash(current_board_hash, prefixed=True):
        raise UpdateError("update_current_board_hash_invalid")
    if not isinstance(draft, dict) or draft.get("expected_board_sha256") != current_board_hash:
        raise UpdateError("update_expected_board_hash_mismatch")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        raise UpdateError("update_log_unavailable") from error
    try:
        with os.fdopen(descriptor, "r+b", closefd=True) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            rows = _parse_bytes(stream.read(), allow_empty=True)
            if rows:
                verify_rows(rows)
            row = _build_row(draft, rows)
            stream.seek(0, os.SEEK_END)
            payload = (canonical_json(row) + "\n").encode("utf-8")
            if stream.write(payload) != len(payload):
                raise UpdateError("update_append_incomplete")
            stream.flush()
            os.fsync(stream.fileno())
            return row
    except UpdateError:
        raise
    except OSError as error:
        raise UpdateError("update_append_failed") from error


def replay(path: Path, *, task_id: str | None = None, update_id: str | None = None) -> list[dict[str, Any]]:
    return [
        row for row in read_rows(path)
        if (task_id is None or row["target_task"] == task_id)
        and (update_id is None or row["update_id"] == update_id)
    ]


def consume(path: Path, cursor: object, *, limit: int | None = None) -> dict[str, Any]:
    rows = read_rows(path)
    if not isinstance(cursor, dict) or set(cursor) != {
        "schema_version", "consumer_id", "next_sequence", "head_hash"
    }:
        raise UpdateError("update_cursor_invalid")
    cursor_version = cursor["schema_version"]
    if not isinstance(cursor_version, int) or isinstance(cursor_version, bool):
        raise UpdateError("update_cursor_version_invalid")
    if cursor_version != CURSOR_VERSION:
        raise UpdateError("update_cursor_version_unsupported")
    _require_string(cursor["consumer_id"], "update_cursor_consumer_invalid")
    next_sequence = cursor["next_sequence"]
    if not isinstance(next_sequence, int) or isinstance(next_sequence, bool) or next_sequence < 1:
        raise UpdateError("update_cursor_sequence_invalid")
    if next_sequence > len(rows) + 1:
        raise UpdateError("update_cursor_ahead")
    expected_prior = GENESIS_HASH if next_sequence == 1 else rows[next_sequence - 2]["row_hash"]
    if cursor["head_hash"] != expected_prior:
        raise UpdateError("update_cursor_hash_mismatch")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        raise UpdateError("update_cursor_limit_invalid")
    selected = rows[next_sequence - 1:]
    if limit is not None:
        selected = selected[:limit]
    new_next = next_sequence + len(selected)
    new_head = expected_prior if not selected else selected[-1]["row_hash"]
    return {
        "cursor": {
            "schema_version": CURSOR_VERSION,
            "consumer_id": cursor["consumer_id"],
            "next_sequence": new_next,
            "head_hash": new_head,
        },
        "remaining": len(rows) - (new_next - 1),
        "rows": selected,
        "status": "ok",
    }


def _load_json(path: Path) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise UpdateError("update_input_unavailable") from error
    try:
        return json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except UpdateError:
        raise
    except json.JSONDecodeError as error:
        raise UpdateError("update_input_json_invalid") from error


def _receipt(operation: str, **values: object) -> dict[str, Any]:
    return {"operation": operation, "protocol": "workgraph_updates", "schema_version": 1, "status": "ok", **values}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("log", type=Path)
    append_parser.add_argument("draft", type=Path)
    append_parser.add_argument("--board-hash", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("log", type=Path)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("log", type=Path)
    replay_parser.add_argument("--task-id")
    replay_parser.add_argument("--update-id")
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("log", type=Path)
    consume_parser.add_argument("cursor", type=Path)
    consume_parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    try:
        if args.operation == "append":
            row = append_update(args.log, _load_json(args.draft), current_board_hash=args.board_hash)
            result = _receipt("append", row=row)
        elif args.operation == "verify":
            rows = read_rows(args.log)
            result = _receipt("verify", **verify_rows(rows))
        elif args.operation == "replay":
            rows = replay(args.log, task_id=args.task_id, update_id=args.update_id)
            result = _receipt("replay", row_count=len(rows), rows=rows)
        else:
            result = _receipt("consume", **consume(args.log, _load_json(args.cursor), limit=args.limit))
    except UpdateError as error:
        print(canonical_json({
            "error": error.code,
            "operation": getattr(args, "operation", "unknown"),
            "protocol": "workgraph_updates",
            "schema_version": 1,
            "status": "error",
        }))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
