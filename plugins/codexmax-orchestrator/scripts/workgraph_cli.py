#!/usr/bin/env python3
"""Strict local JSON facade over accepted WorkGraph runtimes."""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Sequence

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
PROTOCOL = "workgraph_tool_api"
OPERATIONS = {
    "inspect", "ready", "explain-blocked", "note", "consume", "propose",
    "review", "apply", "snapshot", "recover",
}
class ToolError(Exception):
    """Stable tool-facade failure."""

    def __init__(self, code: str, details: object | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _load_module(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("codexmax_tool_" + name, path)
    if spec is None or spec.loader is None:
        raise ToolError("tool_dependency_unavailable", name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # pragma: no cover - import failure is environment-specific
        raise ToolError("tool_dependency_unavailable", name) from error
    return module


workgraph = _load_module("workgraph")
dependencies = _load_module("workgraph_dependencies")
activity = _load_module("workgraph_activity")
updates = _load_module("workgraph_updates")
adapter = _load_module("workgraph_goalbuddy_adapter")
notes = _load_module("workgraph_notes")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolError("tool_json_duplicate_key")
        result[key] = value
    return result


def _assert_open_name_identity(path: Path, descriptor: int) -> os.stat_result:
    """Prove an opened unique regular file still owns its canonical name."""

    try:
        opened = os.fstat(descriptor)
        resolved = path.resolve(strict=True)
        named = path.lstat()
    except OSError as error:
        raise ToolError("tool_path_identity_changed") from error
    if (
        resolved != path
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ToolError("tool_path_identity_changed")
    return opened


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _open_existing(path: object) -> tuple[Path, int]:
    bound, validated = _validated_path(path, must_exist=True)
    assert validated is not None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(bound, flags)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP}:
            raise ToolError("tool_path_identity_changed") from error
        raise ToolError("tool_path_unavailable") from error
    try:
        opened = _assert_open_name_identity(bound, descriptor)
        if not _same_file(validated, opened):
            raise ToolError("tool_path_identity_changed")
    except Exception:
        os.close(descriptor)
        raise
    return bound, descriptor


def _read_json_bound(
    path: object, *, code: str = "tool_input_invalid"
) -> tuple[object, bytes, Path]:
    bound, descriptor = _open_existing(path)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            raw = stream.read()
            _assert_open_name_identity(bound, stream.fileno())
    except ToolError:
        raise
    except OSError as error:
        raise ToolError(code) from error
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except ToolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolError(code) from error
    return value, raw, bound


def _read_json(path: object, *, code: str = "tool_input_invalid") -> tuple[object, bytes]:
    value, raw, _ = _read_json_bound(path, code=code)
    return value, raw


def _validated_path(
    value: object, *, must_exist: bool, regular: bool = True
) -> tuple[Path, os.stat_result | None]:
    if isinstance(value, Path):
        value = str(value)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ToolError("tool_path_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ToolError("tool_path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise ToolError("tool_path_unavailable") from error
    if resolved != lexical:
        raise ToolError("tool_path_alias_forbidden")
    status: os.stat_result | None = None
    if must_exist:
        try:
            status = path.lstat()
        except OSError as error:
            raise ToolError("tool_path_unavailable") from error
        if stat.S_ISLNK(status.st_mode) or (regular and not stat.S_ISREG(status.st_mode)):
            raise ToolError("tool_path_alias_forbidden")
        if regular and status.st_nlink != 1:
            raise ToolError("tool_path_alias_forbidden")
    else:
        try:
            parent = path.parent.resolve(strict=True)
        except OSError as error:
            raise ToolError("tool_path_unavailable") from error
        if parent != lexical.parent or path.is_symlink():
            raise ToolError("tool_path_alias_forbidden")
        if path.exists():
            try:
                status = path.lstat()
            except OSError as error:
                raise ToolError("tool_path_unavailable") from error
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise ToolError("tool_path_alias_forbidden")
    return lexical, status


def _path(value: object, *, must_exist: bool, regular: bool = True) -> Path:
    return _validated_path(value, must_exist=must_exist, regular=regular)[0]


def _object(value: object, keys: set[str], code: str = "tool_arguments_invalid") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ToolError(code)
    return value


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolError(code)
    return value


def _optional_limit(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ToolError("tool_limit_invalid")
    return value


def capabilities() -> dict[str, Any]:
    return {
        "acceptance_authority": False,
        "billing_or_provider_access": False,
        "canonical_board_owner": "GoalBuddy",
        "operations": sorted(OPERATIONS),
        "protocol_versions": {
            "tool_api": 1, "workgraph": 1, "activity": 1, "updates": 1,
            "dependencies": 1, "notes": 1, "goalbuddy_adapter": 1,
        },
        "support": {
            "read": True, "write_activity": True, "write_updates": True,
            "apply_goalbuddy_v2": True, "recover_goalbuddy_v2": True,
            "migration": False, "network": False, "transcript": False,
        },
    }


def _inspect(arguments: object) -> object:
    args = _object(arguments, {"graph_path"})
    document, raw = _read_json(args["graph_path"])
    receipt = workgraph.validate_document(document)
    receipt["document_sha256"] = hashlib.sha256(raw).hexdigest()
    if receipt.get("status") != "valid":
        raise ToolError("tool_workgraph_invalid", receipt.get("errors", []))
    return receipt


def _claims(args: dict[str, Any]) -> list[dict[str, Any]] | None:
    registry = args["registry_path"]
    if registry is None:
        return None
    value, _ = _read_json(registry)
    dependencies.verify_registry(value)
    assert isinstance(value, dict)
    return value["claims"]


def _ready(arguments: object, *, explain: bool) -> object:
    keys = {"graph_path", "satisfaction_path", "expected_board_sha256", "registry_path"}
    if explain:
        keys.add("work_item_id")
    args = _object(arguments, keys)
    graph, _ = _read_json(args["graph_path"])
    satisfaction, _ = _read_json(args["satisfaction_path"])
    claims = _claims(args)
    if explain:
        return dependencies.explain_blocked(
            graph, satisfaction, _text(args["work_item_id"], "tool_work_item_id_invalid"),
            expected_board_hash=args["expected_board_sha256"], active_claims=claims,
        )
    return dependencies.ready(
        graph, satisfaction, expected_board_hash=args["expected_board_sha256"],
        active_claims=claims,
    )


def _note(arguments: object) -> object:
    if not isinstance(arguments, dict):
        raise ToolError("tool_arguments_invalid")
    action = arguments.get("action")
    if action == "create":
        args = _object(arguments, {"action", "activity_path", "draft_path", "current_board_sha256"})
        draft, _ = _read_json(args["draft_path"])
        return notes.create_note(
            _path(args["activity_path"], must_exist=False), draft,
            current_board_sha256=args["current_board_sha256"],
        )
    if action == "present":
        args = _object(arguments, {"action", "activity_path", "filters_path", "expected_board_sha256"})
        filters = None
        if args["filters_path"] is not None:
            filters, _ = _read_json(args["filters_path"])
        return notes.present_notes(
            _path(args["activity_path"], must_exist=True), filters=filters,
            expected_board_sha256=args["expected_board_sha256"],
        )
    if action in {"unread", "mark-read"}:
        args = _object(arguments, {"action", "activity_path", "consumer_id", "task_id"})
        path = _path(args["activity_path"], must_exist=True)
        if action == "unread":
            return notes.unread_notes(path, args["consumer_id"], task_id=args["task_id"])
        return notes.mark_read(path, args["consumer_id"], task_id=args["task_id"])
    raise ToolError("tool_note_action_unsupported")


def _consume(arguments: object) -> object:
    args = _object(arguments, {"ledger_protocol", "ledger_path", "cursor_path", "limit"})
    cursor, _ = _read_json(args["cursor_path"])
    path = _path(args["ledger_path"], must_exist=True)
    limit = _optional_limit(args["limit"])
    if args["ledger_protocol"] == "activity-v1":
        return activity.consume(path, cursor, limit=limit)
    if args["ledger_protocol"] == "updates-v1":
        return updates.consume(path, cursor, limit=limit)
    raise ToolError("tool_ledger_protocol_unsupported")


def _open_updates_output(path: object) -> tuple[Path, int]:
    bound, validated = _validated_path(path, must_exist=False)
    existed = validated is not None
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not existed:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(bound, flags, 0o600)
    except OSError as error:
        if error.errno in {errno.EEXIST, errno.ENOENT, errno.ELOOP}:
            raise ToolError("tool_path_identity_changed") from error
        raise updates.UpdateError("update_log_unavailable") from error
    try:
        opened = _assert_open_name_identity(bound, descriptor)
        if validated is not None and not _same_file(validated, opened):
            raise ToolError("tool_path_identity_changed")
    except Exception:
        os.close(descriptor)
        raise
    return bound, descriptor


def _append_update_bound(path: object, draft: object, *, current_board_hash: str) -> dict[str, Any]:
    """Append with T003 semantics while retaining one validated descriptor."""

    if not updates._is_hash(current_board_hash, prefixed=True):
        raise updates.UpdateError("update_current_board_hash_invalid")
    if not isinstance(draft, dict) or draft.get("expected_board_sha256") != current_board_hash:
        raise updates.UpdateError("update_expected_board_hash_mismatch")
    bound, descriptor = _open_updates_output(path)
    try:
        with os.fdopen(descriptor, "r+b", closefd=True) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            _assert_open_name_identity(bound, stream.fileno())
            rows = updates._parse_bytes(stream.read(), allow_empty=True)
            if rows:
                updates.verify_rows(rows)
            row = updates._build_row(draft, rows)
            payload = (updates.canonical_json(row) + "\n").encode("utf-8")
            _assert_open_name_identity(bound, stream.fileno())
            stream.seek(0, os.SEEK_END)
            if stream.write(payload) != len(payload):
                raise updates.UpdateError("update_append_incomplete")
            stream.flush()
            os.fsync(stream.fileno())
            _assert_open_name_identity(bound, stream.fileno())
            return row
    except (ToolError, updates.UpdateError):
        raise
    except OSError as error:
        raise updates.UpdateError("update_append_failed") from error


def _append_update(arguments: object, *, transition: str) -> object:
    args = _object(arguments, {"updates_path", "draft_path", "current_board_sha256"})
    draft, _ = _read_json(args["draft_path"])
    if not isinstance(draft, dict) or draft.get("transition") != transition:
        raise ToolError("tool_update_transition_mismatch")
    if transition == "reviewed":
        reviewer = draft.get("reviewer_identity")
        if not isinstance(reviewer, dict) or reviewer.get("role") != "Parent":
            raise ToolError("tool_parent_review_required")
    return _append_update_bound(
        args["updates_path"], draft,
        current_board_hash=args["current_board_sha256"],
    )


def _apply(arguments: object) -> object:
    args = _object(arguments, {"board_path", "updates_path", "journal_path", "update_id", "timestamp"})
    journal = _path(args["journal_path"], must_exist=False)
    if journal.exists():
        _read_json(args["journal_path"])
    return adapter.apply_update(
        _path(args["board_path"], must_exist=True),
        _path(args["updates_path"], must_exist=True),
        journal,
        _text(args["update_id"], "tool_update_id_invalid"), timestamp=args["timestamp"],
    )


def _snapshot(arguments: object) -> object:
    args = _object(arguments, {"board_path"})
    return adapter.snapshot(_path(args["board_path"], must_exist=True))


def _recover(arguments: object) -> object:
    args = _object(arguments, {"board_path", "updates_path", "journal_path", "timestamp"})
    _, _, journal = _read_json_bound(args["journal_path"])
    return adapter.recover(
        _path(args["board_path"], must_exist=True),
        _path(args["updates_path"], must_exist=True),
        journal, timestamp=args["timestamp"],
    )


HANDLERS: dict[str, Callable[[object], object]] = {
    "inspect": _inspect,
    "ready": lambda value: _ready(value, explain=False),
    "explain-blocked": lambda value: _ready(value, explain=True),
    "note": _note,
    "consume": _consume,
    "propose": lambda value: _append_update(value, transition="proposed"),
    "review": lambda value: _append_update(value, transition="reviewed"),
    "apply": _apply,
    "snapshot": _snapshot,
    "recover": _recover,
}


UNDERLYING_ERRORS = (
    dependencies.DependencyError, activity.ActivityError, updates.UpdateError,
    adapter.AdapterError, notes.NotesError,
)


def execute(request: object) -> dict[str, Any]:
    envelope = _object(request, {"schema_version", "operation", "arguments"}, "tool_request_shape_invalid")
    version = envelope["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ToolError("tool_schema_version_invalid")
    if version != SCHEMA_VERSION:
        raise ToolError("tool_schema_version_unsupported")
    operation = envelope["operation"]
    if operation not in OPERATIONS:
        raise ToolError("tool_operation_unsupported")
    result = HANDLERS[operation](envelope["arguments"])
    if not isinstance(result, dict) or not result:
        raise ToolError("tool_dependency_malformed_receipt")
    return {
        "capabilities": capabilities(), "operation": operation, "protocol": PROTOCOL,
        "result": result, "schema_version": 1, "status": "ok",
    }


def error_receipt(operation: str, error: Exception) -> dict[str, Any]:
    code = getattr(error, "code", "tool_dependency_failure")
    result: dict[str, Any] = {
        "error": code, "operation": operation, "protocol": PROTOCOL,
        "schema_version": 1, "status": "error",
    }
    details = getattr(error, "details", None)
    if details is not None:
        result["details"] = details
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    args = parser.parse_args(argv)
    operation = "unknown"
    try:
        request, _ = _read_json(args.request)
        if isinstance(request, dict) and isinstance(request.get("operation"), str):
            operation = request["operation"]
        result = execute(request)
    except (ToolError, *UNDERLYING_ERRORS) as error:
        print(canonical_json(error_receipt(operation, error)))
        return 2
    except Exception as error:  # never turn an unexpected dependency failure into success
        print(canonical_json(error_receipt(operation, ToolError("tool_dependency_failure"))))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
