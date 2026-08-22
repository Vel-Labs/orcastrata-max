#!/usr/bin/env python3
"""Task-note facade over the accepted WorkGraph activity-v1 ledger."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence

sys.dont_write_bytecode = True


_ACTIVITY_PATH = Path(__file__).with_name("workgraph_activity.py")
_SPEC = importlib.util.spec_from_file_location("workgraph_activity_notes_dependency", _ACTIVITY_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("notes_activity_dependency_unavailable")
activity = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = activity
_SPEC.loader.exec_module(activity)

SCHEMA_VERSION = 1
CURSOR_VERSION = 1
GENESIS_HASH = "0" * 64
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FILTER_KEYS = {"task_ids", "event_ids", "kinds", "roles", "identity", "evidence_presence", "corrected_state", "relationship"}
IDENTITY_FILTER_KEYS = {"field", "value", "provenance"}
RELATIONSHIP_KEYS = {"mode", "event_id"}
RELATIONSHIP_MODES = {"roots", "direct_replies", "descendants", "correction_targets", "corrected_history"}
CURSOR_KEYS = {"schema_version", "consumer_id", "ledger_path", "ledger_identity", "task_id", "next_sequence", "head_hash"}


class NotesError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _safe_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise NotesError(code)
    return value


def _bind_activity(path: Path, *, must_exist: bool) -> Path:
    if not path.is_absolute() or ".." in path.parts or path.name != "activity.jsonl" or path.parent.name != ".goalbuddy-board":
        raise NotesError("notes_activity_path_invalid")
    if path.resolve(strict=False) != path:
        raise NotesError("notes_activity_path_alias")
    if must_exist and (not path.is_file() or path.is_symlink()):
        raise NotesError("notes_activity_unavailable")
    if path.exists() and not path.is_file():
        raise NotesError("notes_activity_unavailable")
    return path


def _open_unique(path: Path, flags: int, *, alias_code: str, unavailable_code: str, mode: int = 0o600) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | nofollow, mode)
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise NotesError(alias_code if path.is_symlink() else unavailable_code) from error
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or stat.S_ISLNK(named.st_mode) or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        os.close(descriptor)
        raise NotesError(alias_code)
    return descriptor


def _assert_name_matches(path: Path, descriptor: int, code: str) -> os.stat_result:
    opened = os.fstat(descriptor)
    try:
        named = path.lstat()
    except OSError as error:
        raise NotesError(code) from error
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or stat.S_ISLNK(named.st_mode) or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise NotesError(code)
    return opened


def _ledger_identity(path: Path, descriptor: int) -> str:
    opened = _assert_name_matches(path, descriptor, "notes_activity_path_alias")
    payload = f"{path}\0{opened.st_dev}\0{opened.st_ino}".encode()
    return hashlib.sha256(payload).hexdigest()


def _rows_from_descriptor(path: Path, descriptor: int, *, allow_empty: bool, expected_board_sha256: str | None = None) -> list[dict[str, Any]]:
    _assert_name_matches(path, descriptor, "notes_activity_path_alias")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    try:
        rows = activity._parse_bytes(b"".join(chunks), allow_empty=allow_empty)
        if rows:
            activity.verify_rows(rows, expected_board_hash=expected_board_sha256)
    except activity.ActivityError as error:
        raise _translate(error) from error
    _assert_name_matches(path, descriptor, "notes_activity_path_alias")
    return rows


def _translate(error: Exception) -> NotesError:
    code = getattr(error, "code", "notes_activity_failure")
    return NotesError(f"notes_underlying_{code}")


def create_note(path: Path, draft: object, *, current_board_sha256: str) -> dict[str, Any]:
    bound = _bind_activity(path, must_exist=False)
    if not isinstance(draft, dict):
        raise NotesError("notes_draft_invalid")
    for field, code in (("event_id", "notes_event_id_invalid"), ("task_id", "notes_task_id_invalid")):
        _safe_id(draft.get(field), code)
    if draft.get("board_sha256") != current_board_sha256:
        raise NotesError("notes_board_hash_stale")
    kind = draft.get("event_kind")
    if kind not in activity.EVENT_KINDS:
        raise NotesError("notes_kind_invalid")
    bound.parent.mkdir(parents=True, exist_ok=True)
    bound = _bind_activity(bound, must_exist=False)
    descriptor = _open_unique(bound, os.O_RDWR | os.O_CREAT, alias_code="notes_activity_path_alias", unavailable_code="notes_activity_unavailable")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        rows = _rows_from_descriptor(bound, descriptor, allow_empty=True)
        try:
            row = activity._build_event(draft, rows)
        except activity.ActivityError as error:
            raise _translate(error) from error
        _assert_name_matches(bound, descriptor, "notes_activity_path_alias")
        os.lseek(descriptor, 0, os.SEEK_END)
        payload = (activity.canonical_json(row) + "\n").encode("utf-8")
        if os.write(descriptor, payload) != len(payload):
            raise NotesError("notes_underlying_activity_append_incomplete")
        os.fsync(descriptor)
        _assert_name_matches(bound, descriptor, "notes_activity_path_alias")
    except OSError as error:
        raise NotesError("notes_underlying_activity_append_failed") from error
    finally:
        os.close(descriptor)
    return {"authority_effect": "none", "acceptance_effect": "none", "decision_status": "pending" if kind == "decision_request" else "not_applicable", "event": row, "operation": "create", "protocol": "workgraph_notes", "schema_version": 1, "status": "ok"}


def _rows(path: Path, expected_board_sha256: str | None = None) -> list[dict[str, Any]]:
    bound = _bind_activity(path, must_exist=True)
    try:
        descriptor = _open_unique(bound, os.O_RDONLY, alias_code="notes_activity_path_alias", unavailable_code="notes_activity_unavailable")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            return _rows_from_descriptor(bound, descriptor, allow_empty=False, expected_board_sha256=expected_board_sha256)
        finally:
            os.close(descriptor)
    except NotesError:
        raise


def _correction_metadata(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id = {row["event_id"]: row for row in rows}
    root: dict[str, str] = {}
    for row in rows:
        cursor = row
        while cursor["correction_of"] is not None:
            cursor = by_id[cursor["correction_of"]]
        root[row["event_id"]] = cursor["event_id"]
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        latest[root[row["event_id"]]] = row
    result = {}
    for row in rows:
        current = latest[root[row["event_id"]]]
        result[row["event_id"]] = {
            "corrected": current["event_id"] != root[row["event_id"]],
            "current": row["event_id"] == current["event_id"],
            "latest_event_id": current["event_id"],
            "original_event_id": root[row["event_id"]],
            "superseded": row["event_id"] != current["event_id"],
            "visible_marker": "corrected" if current["event_id"] != root[row["event_id"]] else "original",
        }
    return result


def _validate_filters(filters: object) -> dict[str, Any]:
    if filters is None:
        return {}
    if not isinstance(filters, dict) or not set(filters) <= FILTER_KEYS:
        raise NotesError("notes_filter_invalid")
    for key in ("task_ids", "event_ids", "kinds", "roles"):
        if key in filters and (not isinstance(filters[key], list) or not all(isinstance(v, str) for v in filters[key])):
            raise NotesError("notes_filter_invalid")
    if "evidence_presence" in filters and not isinstance(filters["evidence_presence"], bool):
        raise NotesError("notes_filter_invalid")
    if filters.get("corrected_state") not in {None, "current", "superseded", "corrected_history", "uncorrected"}:
        raise NotesError("notes_filter_invalid")
    identity = filters.get("identity")
    if identity is not None and (not isinstance(identity, dict) or set(identity) - IDENTITY_FILTER_KEYS or identity.get("field") not in activity.IDENTITY_KEYS or not isinstance(identity.get("value"), str) or ("provenance" in identity and not isinstance(identity["provenance"], str))):
        raise NotesError("notes_filter_identity_invalid")
    relationship = filters.get("relationship")
    if relationship is not None:
        if not isinstance(relationship, dict) or set(relationship) != RELATIONSHIP_KEYS or relationship.get("mode") not in RELATIONSHIP_MODES:
            raise NotesError("notes_filter_relationship_invalid")
        if relationship["mode"] != "roots":
            _safe_id(relationship.get("event_id"), "notes_filter_relationship_invalid")
    return filters


def present_notes(path: Path, *, filters: object = None, expected_board_sha256: str | None = None) -> dict[str, Any]:
    rows = _rows(path, expected_board_sha256)
    filters = _validate_filters(filters)
    metadata = _correction_metadata(rows)
    selected = list(rows)
    for key, field in (("task_ids", "task_id"), ("event_ids", "event_id"), ("kinds", "event_kind"), ("roles", "author_role")):
        if key in filters:
            values = set(filters[key])
            selected = [row for row in selected if row[field] in values]
    if "evidence_presence" in filters:
        selected = [row for row in selected if bool(row["evidence"]) is filters["evidence_presence"]]
    identity_filter = filters.get("identity")
    if identity_filter:
        selected = [row for row in selected if row["identity"][identity_filter["field"]]["value"] == identity_filter["value"] and ("provenance" not in identity_filter or row["identity"][identity_filter["field"]]["provenance"] == identity_filter["provenance"])]
    state = filters.get("corrected_state")
    if state:
        selected = [row for row in selected if (state == "current" and metadata[row["event_id"]]["current"]) or (state == "superseded" and metadata[row["event_id"]]["superseded"]) or (state == "corrected_history" and metadata[row["event_id"]]["corrected"]) or (state == "uncorrected" and not metadata[row["event_id"]]["corrected"])]
    relation = filters.get("relationship")
    if relation:
        mode, target = relation["mode"], relation.get("event_id")
        if mode == "roots":
            selected = [row for row in selected if row["reply_to"] is None]
        elif mode == "direct_replies":
            selected = [row for row in selected if row["reply_to"] == target]
        elif mode == "correction_targets":
            targets = {row["correction_of"] for row in rows if row["correction_of"] is not None}
            selected = [row for row in selected if row["event_id"] in targets and (target is None or row["event_id"] == target)]
        elif mode == "corrected_history":
            if target not in metadata:
                raise NotesError("notes_filter_event_missing")
            root = metadata[target]["original_event_id"]
            selected = [row for row in selected if metadata[row["event_id"]]["original_event_id"] == root]
        else:
            descendants: set[str] = set()
            frontier = {target}
            while frontier:
                found = {row["event_id"] for row in rows if row["reply_to"] in frontier} - descendants
                descendants |= found
                frontier = found
            selected = [row for row in selected if row["event_id"] in descendants]
    events = [{**row, "presentation": metadata[row["event_id"]], "decision": {"status": "pending", "authority_effect": "none", "acceptance_effect": "none"} if row["event_kind"] == "decision_request" else None} for row in selected]
    return {"event_count": len(events), "events": events, "operation": "present", "protocol": "workgraph_notes", "schema_version": 1, "status": "ok"}


def _cursor_path(activity_path: Path, consumer_id: str, task_id: str | None) -> Path:
    scope = "global" if task_id is None else "task-" + hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    return activity_path.parent / "cursors" / "notes" / f"{consumer_id}--{scope}.json"


def _load_cursor(path: Path, activity_path: Path, ledger_identity: str, consumer_id: str, task_id: str | None) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"schema_version": 1, "consumer_id": consumer_id, "ledger_path": str(activity_path), "ledger_identity": ledger_identity, "task_id": task_id, "next_sequence": 1, "head_hash": GENESIS_HASH}
    try:
        descriptor = _open_unique(path, os.O_RDONLY, alias_code="notes_cursor_path_alias", unavailable_code="notes_cursor_corrupt")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            value = json.load(stream, object_pairs_hook=activity._pairs_no_duplicates)
    except (json.JSONDecodeError, activity.ActivityError) as error:
        raise NotesError("notes_cursor_corrupt") from error
    if not isinstance(value, dict) or set(value) != CURSOR_KEYS or value.get("schema_version") != 1 or isinstance(value.get("schema_version"), bool):
        raise NotesError("notes_cursor_corrupt")
    if value["consumer_id"] != consumer_id or value["task_id"] != task_id or value["ledger_path"] != str(activity_path) or value["ledger_identity"] != ledger_identity:
        raise NotesError("notes_cursor_other_ledger")
    return value


def _validate_cursor_position(cursor: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    next_sequence = cursor["next_sequence"]
    if not isinstance(next_sequence, int) or isinstance(next_sequence, bool) or next_sequence < 1 or next_sequence > len(rows) + 1:
        raise NotesError("notes_cursor_stale")
    prior = GENESIS_HASH if next_sequence == 1 else rows[next_sequence - 2]["event_hash"]
    if cursor["head_hash"] != prior:
        raise NotesError("notes_cursor_stale")


def unread_notes(path: Path, consumer_id: str, *, task_id: str | None = None) -> dict[str, Any]:
    bound = _bind_activity(path, must_exist=True)
    consumer_id = _safe_id(consumer_id, "notes_consumer_id_invalid")
    if task_id is not None:
        _safe_id(task_id, "notes_task_id_invalid")
    descriptor = _open_unique(bound, os.O_RDONLY, alias_code="notes_activity_path_alias", unavailable_code="notes_activity_unavailable")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        rows = _rows_from_descriptor(bound, descriptor, allow_empty=False)
        ledger_identity = _ledger_identity(bound, descriptor)
        cursor = _load_cursor(_cursor_path(bound, consumer_id, task_id), bound, ledger_identity, consumer_id, task_id)
        _validate_cursor_position(cursor, rows)
        _assert_name_matches(bound, descriptor, "notes_activity_path_alias")
    finally:
        os.close(descriptor)
    next_sequence = cursor["next_sequence"]
    events = [row for row in rows[next_sequence - 1:] if task_id is None or row["task_id"] == task_id]
    return {"cursor": cursor, "event_count": len(events), "events": events, "operation": "unread", "protocol": "workgraph_notes", "schema_version": 1, "status": "ok"}


def mark_read(path: Path, consumer_id: str, *, task_id: str | None = None) -> dict[str, Any]:
    bound = _bind_activity(path, must_exist=True)
    consumer_id = _safe_id(consumer_id, "notes_consumer_id_invalid")
    if task_id is not None:
        _safe_id(task_id, "notes_task_id_invalid")
    cursor_path = _cursor_path(bound, consumer_id, task_id)
    cursors_root = bound.parent / "cursors"
    if cursors_root.resolve(strict=False) != cursors_root or cursor_path.parent.resolve(strict=False) != cursor_path.parent:
        raise NotesError("notes_cursor_path_alias")
    cursor_path.parent.mkdir(parents=True, exist_ok=True)
    if cursor_path.parent.resolve(strict=False) != cursor_path.parent:
        raise NotesError("notes_cursor_path_alias")
    lock_path = cursor_path.with_suffix(".lock")
    ledger_descriptor = _open_unique(bound, os.O_RDONLY, alias_code="notes_activity_path_alias", unavailable_code="notes_activity_unavailable")
    lock_descriptor = _open_unique(lock_path, os.O_RDWR | os.O_CREAT, alias_code="notes_cursor_path_alias", unavailable_code="notes_cursor_unavailable")
    with os.fdopen(ledger_descriptor, "rb", closefd=True) as ledger, os.fdopen(lock_descriptor, "a+b", closefd=True) as lock:
        fcntl.flock(ledger.fileno(), fcntl.LOCK_SH)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        rows = _rows_from_descriptor(bound, ledger.fileno(), allow_empty=False)
        ledger_identity = _ledger_identity(bound, ledger.fileno())
        existing = _load_cursor(cursor_path, bound, ledger_identity, consumer_id, task_id)
        _validate_cursor_position(existing, rows)
        cursor = {"schema_version": 1, "consumer_id": consumer_id, "ledger_path": str(bound), "ledger_identity": ledger_identity, "task_id": task_id, "next_sequence": len(rows) + 1, "head_hash": rows[-1]["event_hash"] if rows else GENESIS_HASH}
        temporary = cursor_path.with_name(f".{cursor_path.name}.{os.getpid()}.tmp")
        try:
            temporary_descriptor = _open_unique(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, alias_code="notes_cursor_path_alias", unavailable_code="notes_cursor_unavailable")
            with os.fdopen(temporary_descriptor, "w", encoding="utf-8") as stream:
                stream.write(canonical_json(cursor) + "\n")
                stream.flush(); os.fsync(stream.fileno())
            _assert_name_matches(bound, ledger.fileno(), "notes_activity_path_alias")
            os.replace(temporary, cursor_path)
            _assert_name_matches(bound, ledger.fileno(), "notes_activity_path_alias")
            directory = os.open(cursor_path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if temporary.exists(): temporary.unlink()
    return {"cursor": cursor, "operation": "mark_read", "protocol": "workgraph_notes", "schema_version": 1, "status": "ok"}


def _load_json(path: Path) -> object:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise NotesError("notes_input_duplicate_key")
            result[key] = value
        return result
    try: return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except NotesError: raise
    except (OSError, json.JSONDecodeError) as error: raise NotesError("notes_input_invalid") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); subs = parser.add_subparsers(dest="operation", required=True)
    create = subs.add_parser("create"); create.add_argument("log", type=Path); create.add_argument("draft", type=Path); create.add_argument("--board-hash", required=True)
    present = subs.add_parser("present"); present.add_argument("log", type=Path); present.add_argument("--filters", type=Path); present.add_argument("--board-hash")
    unread = subs.add_parser("unread"); unread.add_argument("log", type=Path); unread.add_argument("consumer_id"); unread.add_argument("--task-id")
    mark = subs.add_parser("mark-read"); mark.add_argument("log", type=Path); mark.add_argument("consumer_id"); mark.add_argument("--task-id")
    args = parser.parse_args(argv)
    try:
        if args.operation == "create": result = create_note(args.log, _load_json(args.draft), current_board_sha256=args.board_hash)
        elif args.operation == "present": result = present_notes(args.log, filters=_load_json(args.filters) if args.filters else None, expected_board_sha256=args.board_hash)
        elif args.operation == "unread": result = unread_notes(args.log, args.consumer_id, task_id=args.task_id)
        else: result = mark_read(args.log, args.consumer_id, task_id=args.task_id)
    except NotesError as error:
        print(canonical_json({"error": error.code, "operation": getattr(args, "operation", "unknown"), "protocol": "workgraph_notes", "schema_version": 1, "status": "error"})); return 2
    print(canonical_json(result)); return 0


if __name__ == "__main__": raise SystemExit(main())
