#!/usr/bin/env python3
"""Maintain the local append-only Codexmax DispatchLedger v1."""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVENT_TYPES = {
    "task_enqueued", "classification_rejected",
    "preflight_cache_hit", "preflight_cache_miss", "preflight_cache_expired",
    "preflight_probe_in_flight", "candidate_rejected",
    "lease_granted", "lease_denied", "lease_released", "lease_expired",
    "lease_recovered", "budget_reserved", "budget_reconciled",
    "dispatch_started", "dispatch_finished", "execution_unknown",
    "quality_accepted", "quality_rejected", "retry_queued", "schedule_closed",
}
EVENT_FIELDS = {
    "schema_version", "event_id", "event_type", "timestamp", "goal_id",
    "checkpoint_id", "task_id", "assignment_id", "envelope_sha256",
    "config_sha256", "board_sha256", "route", "lease", "accounting", "evidence",
}
RECORD_FIELDS = EVENT_FIELDS | {"sequence", "previous_event_hash", "event_hash"}


class LedgerError(ValueError):
    """Fail-closed ledger error with a stable code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError("event_invalid", f"{field} must be an object")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise LedgerError("event_invalid", f"{field} must be a nonempty string")
    return value


def _digest(value: Any, field: str) -> str:
    value = _string(value, field)
    if not SHA256.fullmatch(value):
        raise LedgerError("event_invalid", f"{field} must be sha256-prefixed lowercase SHA-256")
    return value


def validate_event(value: Any) -> dict[str, Any]:
    event = copy.deepcopy(_mapping(value, "event"))
    unknown = sorted(set(event) - EVENT_FIELDS)
    missing = sorted(EVENT_FIELDS - set(event))
    if unknown:
        raise LedgerError("event_invalid", f"unknown field:{unknown[0]}")
    if missing:
        raise LedgerError("event_invalid", f"missing field:{missing[0]}")
    if event["schema_version"] != SCHEMA_VERSION:
        raise LedgerError("event_invalid", "schema_version")
    for field in ("event_id", "goal_id", "checkpoint_id", "task_id", "assignment_id"):
        _string(event[field], field)
    if event["event_type"] not in EVENT_TYPES:
        raise LedgerError("event_invalid", "event_type")
    if not isinstance(event["timestamp"], str) or not TIMESTAMP.fullmatch(event["timestamp"]):
        raise LedgerError("event_invalid", "timestamp")
    try:
        datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise LedgerError("event_invalid", "timestamp") from exc
    for field in ("envelope_sha256", "config_sha256", "board_sha256"):
        _digest(event[field], field)
    for field in ("route", "lease", "accounting", "evidence"):
        _mapping(event[field], field)
    if event["accounting"].get("observed_tokens", "unknown") is None:
        raise LedgerError("unknown_accounting_erased", "observed_tokens")
    return event


def _verify_record(record: Any, expected_sequence: int, previous_hash: str) -> dict[str, Any]:
    row = _mapping(record, f"record[{expected_sequence}]")
    unknown = sorted(set(row) - RECORD_FIELDS)
    missing = sorted(RECORD_FIELDS - set(row))
    if unknown or missing:
        detail = f"unknown:{unknown[0]}" if unknown else f"missing:{missing[0]}"
        raise LedgerError("ledger_record_invalid", f"{expected_sequence}:{detail}")
    event = validate_event({field: row[field] for field in EVENT_FIELDS})
    if row["sequence"] != expected_sequence:
        raise LedgerError("ledger_sequence_mismatch", str(expected_sequence))
    if row["previous_event_hash"] != previous_hash:
        raise LedgerError("ledger_chain_mismatch", str(expected_sequence))
    recorded_hash = row["event_hash"]
    candidate = copy.deepcopy(row)
    candidate.pop("event_hash")
    computed = hashlib.sha256(canonical_json(candidate)).hexdigest()
    if recorded_hash != computed:
        raise LedgerError("ledger_hash_mismatch", str(expected_sequence))
    return {**event, "sequence": expected_sequence, "previous_event_hash": previous_hash, "event_hash": recorded_hash}


def verify_lines(lines: list[str], *, expected_head: str | None = None) -> dict[str, Any]:
    previous = ZERO_HASH
    event_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    for sequence, line in enumerate(lines, start=1):
        if not line.strip():
            raise LedgerError("ledger_truncated", f"blank line:{sequence}")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError("ledger_truncated", f"line {sequence}:{exc.msg}") from exc
        row = _verify_record(value, sequence, previous)
        if row["event_id"] in event_ids:
            raise LedgerError("ledger_event_duplicate", row["event_id"])
        event_ids.add(row["event_id"])
        rows.append(row)
        previous = row["event_hash"]
    if expected_head is not None and previous != expected_head:
        raise LedgerError("ledger_expected_head_mismatch", expected_head)
    return {
        "schema_version": SCHEMA_VERSION,
        "event_count": len(rows),
        "head_hash": previous,
        "event_ids": event_ids,
        "rows": rows,
    }


def verify_ledger(path: Path, *, expected_head: str | None = None) -> dict[str, Any]:
    if not path.exists():
        if expected_head not in {None, ZERO_HASH}:
            raise LedgerError("ledger_expected_head_mismatch", str(expected_head))
        return verify_lines([], expected_head=expected_head)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LedgerError("ledger_unreadable", str(exc)) from exc
    if raw and not raw.endswith(b"\n"):
        raise LedgerError("ledger_truncated", "missing terminal newline")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LedgerError("ledger_invalid_utf8", str(exc)) from exc
    return verify_lines(lines, expected_head=expected_head)


def _validate_existing_target(path: Path) -> None:
    """Reject aliases and non-regular existing ledger targets before append."""
    try:
        target = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LedgerError("ledger_unreadable", str(exc)) from exc
    if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode) or target.st_nlink != 1:
        raise LedgerError("ledger_unsafe", str(path))


@contextmanager
def _ledger_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LedgerError("ledger_unsafe", str(lock_path)) from exc
    try:
        lock_stat = os.fstat(descriptor)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
            raise LedgerError("ledger_unsafe", str(lock_path))
        lock = os.fdopen(descriptor, "a+b")
    except Exception:
        os.close(descriptor)
        raise
    try:
        with lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            yield
    finally:
        # ``with lock`` closes the descriptor. Keep the explicit lifecycle here
        # so callers cannot accidentally append outside the lock boundary.
        pass


def _open_append_target(path: Path) -> int:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise LedgerError("ledger_unsafe", str(path)) from exc
    try:
        target = os.fstat(descriptor)
        if not stat.S_ISREG(target.st_mode) or target.st_nlink != 1:
            raise LedgerError("ledger_unsafe", str(path))
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _write_records(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    descriptor = _open_append_target(path)
    payload = b"".join(canonical_json(record) + b"\n" for record in records)
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise LedgerError("ledger_write_failed", str(path))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_event(
    path: Path,
    event_value: Any,
    *,
    expected_head: str | None = None,
    expected_sequence: int | None = None,
) -> dict[str, Any]:
    event = validate_event(event_value)
    with _ledger_lock(path):
        _validate_existing_target(path)
        verified = verify_ledger(path, expected_head=expected_head)
        if expected_sequence is not None and verified["event_count"] != expected_sequence:
            raise LedgerError("ledger_expected_sequence_mismatch", str(expected_sequence))
        if event["event_id"] in verified["event_ids"]:
            raise LedgerError("ledger_event_duplicate", event["event_id"])
        record = {
            **event,
            "sequence": verified["event_count"] + 1,
            "previous_event_hash": verified["head_hash"],
        }
        record["event_hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
        _write_records(path, [record])
        return record


def append_event_idempotent(path: Path, event_value: Any) -> dict[str, Any]:
    """Append an event, or return the existing identical event under the lock.

    Normal ``append_event`` remains strict and rejects every duplicate. Import
    paths use this seam because a host may replay the same bounded receipt.
    Timestamp is intentionally excluded from the comparison: a replay may be
    imported at a different wall-clock time, but accounting and source
    evidence must remain byte-for-byte equivalent. Any other change fails
    closed.
    """
    result = append_events_idempotent(path, [event_value])
    return result["records"][0]


def append_events_idempotent(path: Path, event_values: Any) -> dict[str, Any]:
    """Atomically append a batch while accepting exact identity replays.

    Every input is validated before the ledger is opened. Existing and
    within-batch identities are checked while holding one exclusive lock. A
    conflict aborts before the single write, so the ledger bytes do not change.
    Timestamp is excluded from identity comparison for host receipt replays.
    """
    if isinstance(event_values, (str, bytes, dict)):
        raise LedgerError("events_invalid", "batch must be a sequence")
    try:
        events = [validate_event(value) for value in event_values]
    except TypeError as exc:
        raise LedgerError("events_invalid", "batch must be a sequence") from exc
    with _ledger_lock(path):
        _validate_existing_target(path)
        verified = verify_ledger(path)
        existing_by_id = {row["event_id"]: row for row in verified["rows"]}
        seen: dict[str, dict[str, Any]] = {}
        planned: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        appended = 0
        idempotent = 0

        def comparable(value: dict[str, Any]) -> bytes:
            return canonical_json({field: value[field] for field in EVENT_FIELDS if field != "timestamp"})

        for event in events:
            event_id = event["event_id"]
            existing = existing_by_id.get(event_id)
            if existing is not None:
                if comparable(existing) != comparable(event):
                    raise LedgerError("ledger_event_conflict", event_id)
                records.append(existing)
                idempotent += 1
                continue
            previous = seen.get(event_id)
            if previous is not None:
                if comparable(previous) != comparable(event):
                    raise LedgerError("ledger_event_conflict", event_id)
                records.append(previous)
                idempotent += 1
                continue
            record = {
                **event,
                "sequence": verified["event_count"] + len(planned) + 1,
                "previous_event_hash": (
                    planned[-1]["event_hash"] if planned else verified["head_hash"]
                ),
            }
            record["event_hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
            seen[event_id] = record
            planned.append(record)
            records.append(record)
            appended += 1
        _write_records(path, planned)
        return {"records": records, "appended": appended, "idempotent": idempotent}


def replay(value: dict[str, Any]) -> dict[str, Any]:
    rows = value["rows"]
    active_leases: dict[str, dict[str, Any]] = {}
    accepted_by_provider: dict[str, int] = {}
    unknown_accounting_events = 0
    terminal_status: dict[str, str] = {}
    for row in rows:
        lease_id = row["lease"].get("lease_id")
        if row["event_type"] == "lease_granted" and lease_id:
            active_leases[lease_id] = row
        elif row["event_type"] in {"lease_released", "lease_expired", "lease_recovered"} and lease_id:
            active_leases.pop(lease_id, None)
        if row["event_type"] == "quality_accepted":
            provider = row["route"].get("provider", "unknown")
            accepted_by_provider[provider] = accepted_by_provider.get(provider, 0) + 1
        if row["accounting"].get("observed_tokens", "unknown") == "unknown":
            unknown_accounting_events += 1
        if row["event_type"] in {"schedule_closed", "execution_unknown"}:
            terminal_status[row["task_id"]] = row["event_type"]
    return {
        "schema_version": SCHEMA_VERSION,
        "event_count": value["event_count"],
        "head_hash": value["head_hash"],
        "active_leases": active_leases,
        "quality_accepted_by_provider": accepted_by_provider,
        "unknown_accounting_events": unknown_accounting_events,
        "terminal_status_by_task": terminal_status,
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError("input_unreadable", str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser("verify")
    append_parser = commands.add_parser("append")
    project_parser = commands.add_parser("project")
    for child in (verify_parser, append_parser, project_parser):
        child.add_argument("--ledger", type=Path, required=True)
        child.add_argument("--expected-head")
    append_parser.add_argument("--event", type=Path, required=True)
    append_parser.add_argument("--expected-sequence", type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == "append":
            result = append_event(
                args.ledger, _read_json(args.event), expected_head=args.expected_head,
                expected_sequence=args.expected_sequence,
            )
        else:
            verified = verify_ledger(args.ledger, expected_head=args.expected_head)
            result = replay(verified) if args.command == "project" else {
                key: value for key, value in verified.items() if key not in {"event_ids", "rows"}
            }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except LedgerError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "detail": exc.detail}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
