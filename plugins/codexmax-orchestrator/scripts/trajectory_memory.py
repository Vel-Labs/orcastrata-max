#!/usr/bin/env python3
"""Maintain strict, namespace-isolated trajectory-memory JSONL ledgers."""

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
GENESIS_HASH = "0" * 64
MAX_QUERY_LIMIT = 100
MAX_FILTER_ITEMS = 32
MAX_QUERY_BYTES = 1_000_000
DESCRIPTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
LOCATOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

EVENT_TYPES = {"attempt", "observation", "correction", "handoff", "decision", "result"}
OUTCOMES = {"pending", "accepted", "rejected", "blocked", "failed", "unknown"}
RELATIONS = {"continues", "corrects", "supports", "supersedes", "derived_from"}
USAGE_FIELDS = {"input_tokens", "output_tokens", "total_tokens", "wall_time_ms"}
UNKNOWN_REASONS = {"not_exposed", "not_reported", "not_applicable"}
RAW_FIELD_NAMES = {
    "body", "completion", "content", "conversation", "freeform", "message", "messages",
    "prompt", "prompts", "raw", "response", "responses", "text", "transcript", "transcripts",
}
HEADER_FIELDS = {
    "schema_version", "record_type", "namespace", "arm", "source_corpus_sha256",
    "sequence", "previous_event_hash", "event_hash",
}
EVENT_FIELDS = {
    "schema_version", "record_type", "event_id", "namespace", "arm", "source_corpus_sha256",
    "timestamp", "event_type", "task_id", "outcome", "tags", "references", "artifacts", "usage",
    "sequence", "previous_event_hash", "event_hash",
}
DRAFT_FIELDS = EVENT_FIELDS - {"record_type", "sequence", "previous_event_hash", "event_hash"}
REFERENCE_FIELDS = {"namespace", "arm", "event_id", "relation"}
ARTIFACT_FIELDS = {"locator", "sha256"}
MEASURE_FIELDS = {"status", "value", "reason"}
QUERY_FIELDS = {
    "schema_version", "namespace", "arm", "source_corpus_sha256", "event_types", "task_ids",
    "outcomes", "tags_any", "after_sequence", "limit", "max_bytes", "order",
}


class TrajectoryMemoryError(ValueError):
    """Fail-closed protocol error with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class ProtocolArgumentParser(argparse.ArgumentParser):
    """Route CLI usage errors through the machine-readable protocol."""

    def error(self, message: str) -> None:
        raise TrajectoryMemoryError("cli_usage_invalid", message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hash_record(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _object(value: Any, field: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrajectoryMemoryError("schema_invalid", f"{field}:object_required")
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise TrajectoryMemoryError("schema_unknown_key", f"{field}:{unknown[0]}")
    if missing:
        raise TrajectoryMemoryError("schema_missing_key", f"{field}:{missing[0]}")
    return value


def _reject_raw_fields(value: Any, path: str = "event") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in RAW_FIELD_NAMES:
                raise TrajectoryMemoryError("raw_content_field_forbidden", f"{path}.{key}")
            _reject_raw_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_raw_fields(child, f"{path}[{index}]")


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TrajectoryMemoryError("schema_invalid", f"{field}:integer>={minimum}")
    return value


def _descriptor(value: Any, field: str, *, locator: bool = False) -> str:
    pattern = LOCATOR if locator else DESCRIPTOR
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TrajectoryMemoryError("descriptor_invalid", field)
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise TrajectoryMemoryError("digest_invalid", field)
    return value


def _chain_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise TrajectoryMemoryError("chain_hash_invalid", field)
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise TrajectoryMemoryError("timestamp_invalid")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TrajectoryMemoryError("timestamp_invalid") from exc
    return value


def _descriptor_list(value: Any, field: str, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_FILTER_ITEMS:
        raise TrajectoryMemoryError("bounds_invalid", field)
    result: list[str] = []
    for item in value:
        descriptor = _descriptor(item, field)
        if allowed is not None and descriptor not in allowed:
            raise TrajectoryMemoryError("descriptor_invalid", field)
        result.append(descriptor)
    if len(set(result)) != len(result):
        raise TrajectoryMemoryError("descriptor_duplicate", field)
    return result


def _measure(value: Any, field: str) -> dict[str, Any]:
    measure = _object(value, field, MEASURE_FIELDS)
    status = measure["status"]
    if status == "known":
        try:
            _integer(measure["value"], f"usage.{field}.value")
        except TrajectoryMemoryError as exc:
            raise TrajectoryMemoryError("usage_encoding_invalid", field) from exc
        if measure["reason"] is not None:
            raise TrajectoryMemoryError("usage_encoding_invalid", field)
    elif status == "unknown":
        if measure["value"] is not None or measure["reason"] not in UNKNOWN_REASONS:
            raise TrajectoryMemoryError("usage_encoding_invalid", field)
    else:
        raise TrajectoryMemoryError("usage_encoding_invalid", field)
    return measure


def validate_event(value: Any) -> dict[str, Any]:
    _reject_raw_fields(value)
    event = dict(_object(value, "event", DRAFT_FIELDS))
    if event["schema_version"] != SCHEMA_VERSION or isinstance(event["schema_version"], bool):
        raise TrajectoryMemoryError("schema_version_unsupported")
    for field in ("event_id", "namespace", "arm", "task_id"):
        _descriptor(event[field], field)
    _digest(event["source_corpus_sha256"], "source_corpus_sha256")
    _timestamp(event["timestamp"])
    if event["event_type"] not in EVENT_TYPES:
        raise TrajectoryMemoryError("event_type_invalid")
    if event["outcome"] not in OUTCOMES:
        raise TrajectoryMemoryError("outcome_invalid")
    _descriptor_list(event["tags"], "tags")
    if not isinstance(event["references"], list) or len(event["references"]) > MAX_FILTER_ITEMS:
        raise TrajectoryMemoryError("bounds_invalid", "references")
    for index, raw_reference in enumerate(event["references"]):
        reference = _object(raw_reference, f"references[{index}]", REFERENCE_FIELDS)
        for field in ("namespace", "arm", "event_id"):
            _descriptor(reference[field], f"references[{index}].{field}")
        if reference["namespace"] != event["namespace"] or reference["arm"] != event["arm"]:
            raise TrajectoryMemoryError("cross_arm_reference_forbidden", reference["event_id"])
        if reference["relation"] not in RELATIONS:
            raise TrajectoryMemoryError("reference_relation_invalid", reference["event_id"])
    if not isinstance(event["artifacts"], list) or len(event["artifacts"]) > MAX_FILTER_ITEMS:
        raise TrajectoryMemoryError("bounds_invalid", "artifacts")
    for index, raw_artifact in enumerate(event["artifacts"]):
        artifact = _object(raw_artifact, f"artifacts[{index}]", ARTIFACT_FIELDS)
        _descriptor(artifact["locator"], f"artifacts[{index}].locator", locator=True)
        _digest(artifact["sha256"], f"artifacts[{index}].sha256")
    usage = _object(event["usage"], "usage", USAGE_FIELDS)
    for field in sorted(USAGE_FIELDS):
        _measure(usage[field], field)
    return event


def validate_query(value: Any) -> dict[str, Any]:
    query = dict(_object(value, "query", QUERY_FIELDS))
    if query["schema_version"] != SCHEMA_VERSION or isinstance(query["schema_version"], bool):
        raise TrajectoryMemoryError("schema_version_unsupported")
    for field in ("namespace", "arm"):
        _descriptor(query[field], field)
    _digest(query["source_corpus_sha256"], "source_corpus_sha256")
    _descriptor_list(query["event_types"], "event_types", EVENT_TYPES)
    _descriptor_list(query["task_ids"], "task_ids")
    _descriptor_list(query["outcomes"], "outcomes", OUTCOMES)
    _descriptor_list(query["tags_any"], "tags_any")
    _integer(query["after_sequence"], "after_sequence")
    try:
        limit = _integer(query["limit"], "limit", 1)
    except TrajectoryMemoryError as exc:
        raise TrajectoryMemoryError("bounds_invalid", "limit") from exc
    if limit > MAX_QUERY_LIMIT:
        raise TrajectoryMemoryError("bounds_invalid", "limit")
    try:
        max_bytes = _integer(query["max_bytes"], "max_bytes", 1)
    except TrajectoryMemoryError as exc:
        raise TrajectoryMemoryError("bounds_invalid", "max_bytes") from exc
    if max_bytes > MAX_QUERY_BYTES:
        raise TrajectoryMemoryError("bounds_invalid", "max_bytes")
    if query["order"] not in {"asc", "desc"}:
        raise TrajectoryMemoryError("order_invalid")
    return query


def ledger_path(root: Path, namespace: str, arm: str) -> Path:
    _descriptor(namespace, "namespace")
    _descriptor(arm, "arm")
    if "/" in namespace or "/" in arm or namespace in {".", ".."} or arm in {".", ".."}:
        raise TrajectoryMemoryError("descriptor_invalid", "namespace_or_arm")
    return root / namespace / f"{arm}.jsonl"


def _parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if not raw:
        raise TrajectoryMemoryError("ledger_empty")
    if not raw.endswith(b"\n"):
        raise TrajectoryMemoryError("ledger_truncated")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TrajectoryMemoryError("ledger_invalid_utf8") from exc
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line:
            raise TrajectoryMemoryError("ledger_blank_line", str(index))
        try:
            row = json.loads(line, object_pairs_hook=_pairs_without_duplicates)
        except TrajectoryMemoryError:
            raise
        except json.JSONDecodeError as exc:
            raise TrajectoryMemoryError("ledger_json_invalid", str(index)) from exc
        if not isinstance(row, dict):
            raise TrajectoryMemoryError("ledger_record_invalid", str(index))
        rows.append(row)
    return rows


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrajectoryMemoryError("json_duplicate_key", key)
        result[key] = value
    return result


def verify_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise TrajectoryMemoryError("ledger_empty")
    header = _object(rows[0], "header", HEADER_FIELDS)
    if header["schema_version"] != SCHEMA_VERSION or header["record_type"] != "namespace_init":
        raise TrajectoryMemoryError("header_invalid")
    namespace = _descriptor(header["namespace"], "namespace")
    arm = _descriptor(header["arm"], "arm")
    corpus = _digest(header["source_corpus_sha256"], "source_corpus_sha256")
    if header["sequence"] != 0 or header["previous_event_hash"] != GENESIS_HASH:
        raise TrajectoryMemoryError("chain_sequence_invalid", "header")
    _chain_hash(header["event_hash"], "header.event_hash")
    if _hash_record(header) != header["event_hash"]:
        raise TrajectoryMemoryError("chain_hash_mismatch", "header")
    previous = header["event_hash"]
    seen: set[str] = set()
    for sequence, row in enumerate(rows[1:], start=1):
        _object(row, f"event[{sequence}]", EVENT_FIELDS)
        draft = {key: row[key] for key in DRAFT_FIELDS}
        validate_event(draft)
        if row["record_type"] != "event":
            raise TrajectoryMemoryError("record_type_invalid", str(sequence))
        if (row["namespace"], row["arm"], row["source_corpus_sha256"]) != (namespace, arm, corpus):
            raise TrajectoryMemoryError("ledger_binding_mismatch", str(sequence))
        if row["sequence"] != sequence:
            raise TrajectoryMemoryError("chain_sequence_invalid", str(sequence))
        if row["previous_event_hash"] != previous:
            raise TrajectoryMemoryError("chain_broken", str(sequence))
        _chain_hash(row["event_hash"], f"event[{sequence}].event_hash")
        if _hash_record(row) != row["event_hash"]:
            raise TrajectoryMemoryError("chain_hash_mismatch", str(sequence))
        if row["event_id"] in seen:
            raise TrajectoryMemoryError("event_id_duplicate", row["event_id"])
        for reference in row["references"]:
            if reference["event_id"] not in seen:
                raise TrajectoryMemoryError("reference_not_prior", reference["event_id"])
        seen.add(row["event_id"])
        previous = row["event_hash"]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
        "namespace": namespace,
        "arm": arm,
        "source_corpus_sha256": corpus,
        "event_count": len(rows) - 1,
        "head_hash": previous,
        "event_ids": seen,
        "events": rows[1:],
    }


def verify_ledger(root: Path, namespace: str, arm: str, source_corpus_sha256: str) -> dict[str, Any]:
    path = ledger_path(root, namespace, arm)
    try:
        rows = _parse_jsonl(path.read_bytes())
    except FileNotFoundError as exc:
        raise TrajectoryMemoryError("ledger_missing") from exc
    except OSError as exc:
        raise TrajectoryMemoryError("ledger_unreadable") from exc
    verified = verify_rows(rows)
    if verified["source_corpus_sha256"] != source_corpus_sha256:
        raise TrajectoryMemoryError("source_corpus_mismatch")
    if verified["namespace"] != namespace or verified["arm"] != arm:
        raise TrajectoryMemoryError("ledger_binding_mismatch")
    return verified


def initialize(root: Path, namespace: str, arm: str, source_corpus_sha256: str) -> dict[str, Any]:
    _digest(source_corpus_sha256, "source_corpus_sha256")
    path = ledger_path(root, namespace, arm)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if path.exists() and path.stat().st_size:
            raise TrajectoryMemoryError("ledger_already_initialized")
        header = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "namespace_init",
            "namespace": namespace,
            "arm": arm,
            "source_corpus_sha256": source_corpus_sha256,
            "sequence": 0,
            "previous_event_hash": GENESIS_HASH,
        }
        header["event_hash"] = _hash_record(header)
        _append_bytes(path, canonical_json(header) + b"\n")
    return _public_verify(verify_ledger(root, namespace, arm, source_corpus_sha256))


def _append_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise TrajectoryMemoryError("append_incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_event(root: Path, value: Any, *, expected_head: str) -> dict[str, Any]:
    event = validate_event(value)
    _chain_hash(expected_head, "expected_head")
    path = ledger_path(root, event["namespace"], event["arm"])
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            verified = verify_ledger(
                root, event["namespace"], event["arm"], event["source_corpus_sha256"]
            )
            if verified["head_hash"] != expected_head:
                raise TrajectoryMemoryError("stale_head", expected_head)
            if event["event_id"] in verified["event_ids"]:
                raise TrajectoryMemoryError("event_id_duplicate", event["event_id"])
            for reference in event["references"]:
                if reference["event_id"] not in verified["event_ids"]:
                    raise TrajectoryMemoryError("reference_not_prior", reference["event_id"])
            record = {
                **event,
                "record_type": "event",
                "sequence": verified["event_count"] + 1,
                "previous_event_hash": verified["head_hash"],
            }
            record["event_hash"] = _hash_record(record)
            _append_bytes(path, canonical_json(record) + b"\n")
            return record
    except FileNotFoundError as exc:
        raise TrajectoryMemoryError("ledger_missing") from exc


def query_events(root: Path, value: Any) -> dict[str, Any]:
    query = validate_query(value)
    verified = verify_ledger(root, query["namespace"], query["arm"], query["source_corpus_sha256"])
    matched = []
    for row in verified["events"]:
        if row["sequence"] <= query["after_sequence"]:
            continue
        if query["event_types"] and row["event_type"] not in query["event_types"]:
            continue
        if query["task_ids"] and row["task_id"] not in query["task_ids"]:
            continue
        if query["outcomes"] and row["outcome"] not in query["outcomes"]:
            continue
        if query["tags_any"] and not set(query["tags_any"]).intersection(row["tags"]):
            continue
        matched.append(row)
    matched.sort(key=lambda row: row["sequence"], reverse=query["order"] == "desc")
    candidates = matched[:query["limit"]]
    query_sha256 = hashlib.sha256(canonical_json(query)).hexdigest()
    for returned_count in range(len(candidates), -1, -1):
        selected = candidates[:returned_count]
        if returned_count < len(candidates):
            reason = "max_bytes"
        elif len(candidates) < len(matched):
            reason = "limit"
        else:
            reason = "none"
        projection = {
            "schema_version": SCHEMA_VERSION,
            "status": "ok",
            "namespace": query["namespace"],
            "arm": query["arm"],
            "source_corpus_sha256": query["source_corpus_sha256"],
            "head_hash": verified["head_hash"],
            "query_sha256": query_sha256,
            "truncation": {
                "truncated": reason != "none",
                "reason": reason,
                "matched_event_count": len(matched),
                "limit_candidate_count": len(candidates),
                "returned_event_count": returned_count,
            },
            "event_count": returned_count,
            "events": selected,
        }
        result = {
            **projection,
            "retrieval_sha256": hashlib.sha256(canonical_json(projection)).hexdigest(),
        }
        if len(canonical_json(result)) <= query["max_bytes"]:
            return result
    raise TrajectoryMemoryError("max_bytes_too_small", str(query["max_bytes"]))


def _public_verify(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in (
        "schema_version", "status", "namespace", "arm", "source_corpus_sha256", "event_count", "head_hash"
    )}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_without_duplicates)
    except TrajectoryMemoryError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrajectoryMemoryError("input_invalid") from exc


def main(argv: Sequence[str] | None = None) -> int:
    operation = "unknown"
    try:
        parser = ProtocolArgumentParser(description=__doc__)
        commands = parser.add_subparsers(dest="operation", required=True)
        init_parser = commands.add_parser("init")
        verify_parser = commands.add_parser("verify")
        append_parser = commands.add_parser("append")
        query_parser = commands.add_parser("query")
        for child in (init_parser, verify_parser):
            child.add_argument("--root", type=Path, required=True)
            child.add_argument("--namespace", required=True)
            child.add_argument("--arm", required=True)
            child.add_argument("--source-corpus-sha256", required=True)
        append_parser.add_argument("--root", type=Path, required=True)
        append_parser.add_argument("--event", type=Path, required=True)
        append_parser.add_argument("--expected-head", required=True)
        query_parser.add_argument("--root", type=Path, required=True)
        query_parser.add_argument("--query", type=Path, required=True)
        args = parser.parse_args(argv)
        operation = args.operation
        if args.operation == "init":
            result = initialize(args.root, args.namespace, args.arm, args.source_corpus_sha256)
        elif args.operation == "append":
            result = {"schema_version": 1, "status": "ok", "event": append_event(
                args.root, _load_json(args.event), expected_head=args.expected_head
            )}
        elif args.operation == "query":
            result = query_events(args.root, _load_json(args.query))
        else:
            result = _public_verify(verify_ledger(
                args.root, args.namespace, args.arm, args.source_corpus_sha256
            ))
        print(canonical_json(result).decode("utf-8"))
        return 0
    except TrajectoryMemoryError as exc:
        print(canonical_json({
            "schema_version": 1, "status": "error", "operation": operation,
            "code": exc.code, "detail": exc.detail,
        }).decode("utf-8"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
