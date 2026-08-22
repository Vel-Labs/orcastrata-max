#!/usr/bin/env python3
"""Normalize bounded provider-neutral JSON into one LoopEvent v1 artifact."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

from loop_compile import run_loop


MAX_INPUT_BYTES = 65_536
MAX_OUTPUT_BYTES = 262_144
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 2_048
INPUT_KEYS = {
    "schema_version", "artifact_type", "event_type", "source_event_id",
    "session_id", "occurred_at", "observed_at", "paths", "origin",
}
ORIGIN_KEYS = {"run_id", "loop_id", "depth", "ancestry"}
EVENT_TYPES = {
    "manual.requested", "session.start", "prompt.submitted", "file.changed",
    "run.completed", "run.failed", "goal.state_changed", "schedule.tick",
    "git.pre_commit", "git.post_commit",
}


class HarnessError(Exception):
    """A stable fail-closed harness adapter rejection."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError("harness_duplicate_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise HarnessError("harness_json_invalid")


def _validate_structure(value: object, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise HarnessError("harness_structure_too_deep")
    nodes = 1
    if isinstance(value, dict):
        for key, child in value.items():
            nodes += _validate_structure(child, depth=depth + 1)
            if nodes > MAX_JSON_NODES:
                raise HarnessError("harness_node_limit_exceeded")
    elif isinstance(value, list):
        for child in value:
            nodes += _validate_structure(child, depth=depth + 1)
            if nodes > MAX_JSON_NODES:
                raise HarnessError("harness_node_limit_exceeded")
    return nodes


def load_json_bytes(raw: bytes) -> object:
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise HarnessError("harness_input_too_large")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text, object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except HarnessError:
        raise
    except RecursionError:
        raise HarnessError("harness_structure_too_deep") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HarnessError("harness_json_invalid") from None
    _validate_structure(value)
    return value


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HarnessError("harness_timestamp_invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HarnessError("harness_timestamp_invalid") from None


def _identifier(value: object, *, kebab: bool) -> bool:
    if not isinstance(value, str) or not value:
        return False
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-" if kebab else "abcdefghijklmnopqrstuvwxyz0123456789._:-"
    first = "abcdefghijklmnopqrstuvwxyz" if kebab else "abcdefghijklmnopqrstuvwxyz0123456789"
    limit = 64 if kebab else 128
    return len(value) <= limit and value[0] in first and all(character in allowed for character in value)


def _origin(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ORIGIN_KEYS:
        raise HarnessError("harness_origin_invalid")
    ancestry = value.get("ancestry")
    depth = value.get("depth")
    loop_id = value.get("loop_id")
    run_id = value.get("run_id")
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 8:
        raise HarnessError("harness_origin_invalid")
    if not isinstance(ancestry, list) or len(ancestry) != depth:
        raise HarnessError("harness_origin_invalid")
    if not all(isinstance(item, str) for item in ancestry):
        raise HarnessError("harness_origin_invalid")
    if len(ancestry) != len(set(ancestry)):
        raise HarnessError("harness_origin_invalid")
    if not all(_identifier(item, kebab=True) for item in ancestry):
        raise HarnessError("harness_origin_invalid")
    if depth == 0:
        if loop_id is not None or run_id is not None:
            raise HarnessError("harness_origin_invalid")
    elif not _identifier(loop_id, kebab=True) or not _identifier(run_id, kebab=False) or ancestry[-1] != loop_id:
        raise HarnessError("harness_origin_invalid")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise HarnessError("harness_path_invalid")
    if value.startswith("/") or "\\" in value or ".." in value.split("/"):
        raise HarnessError("harness_path_invalid")
    normalized = PurePosixPath(value).as_posix()
    if normalized == "." or normalized.startswith("../"):
        raise HarnessError("harness_path_invalid")
    return normalized


def normalize_input(value: object, *, trusted: bool = False) -> dict[str, Any]:
    if not isinstance(trusted, bool):
        raise HarnessError("harness_trust_invalid")
    if not isinstance(value, dict) or set(value) != INPUT_KEYS:
        raise HarnessError("harness_input_invalid")
    if value.get("schema_version") != 1 or value.get("artifact_type") != "HarnessLoopInput":
        raise HarnessError("harness_input_invalid")
    event_type = value.get("event_type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise HarnessError("harness_event_unsupported")
    for key in ("source_event_id", "session_id"):
        item = value.get(key)
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > 128:
            raise HarnessError("harness_input_invalid")
    occurred = _timestamp(value.get("occurred_at"))
    observed = _timestamp(value.get("observed_at"))
    if occurred > observed:
        raise HarnessError("harness_timestamp_invalid")
    paths = value.get("paths")
    if not isinstance(paths, list) or len(paths) > 256:
        raise HarnessError("harness_input_invalid")
    normalized_paths = sorted(set(_path(item) for item in paths))
    origin = _origin(value.get("origin"))
    core = {
        "event_type": event_type,
        "session_id": value["session_id"],
        "paths": normalized_paths,
        "origin": origin,
    }
    event_hash = _digest({**core, "source_event_id": value["source_event_id"], "occurred_at": value["occurred_at"]})
    dedupe_hash = _digest(core)
    locators = [{"root_id": "workspace", "path": path} for path in normalized_paths]
    return {
        "schema_version": 1,
        "artifact_type": "LoopEvent",
        "event_id": "harness-event-" + event_hash[:24],
        "event_type": event_type,
        "occurred_at": value["occurred_at"],
        "observed_at": value["observed_at"],
        "source": {
            "adapter_id": "harness-json",
            "source_event_id": "harness-source-" + _digest(value["source_event_id"])[:24],
            "trust": "local_adapter" if trusted else "generic_stdin",
        },
        "origin": origin,
        "workspace_root": ".",
        "subject": {"paths": locators, "goalbuddy_board": None, "workgraph": None},
        "requested_scope": {"read": locators, "write": []},
        "authority": {"board": None, "receipt": None, "mutation_mode": "advisory_report_only"},
        "dedupe_key": "harness-dedupe-" + dedupe_hash[:24],
    }


def dispatch_input(
    registry: dict[str, Any],
    value: object,
    *,
    evaluation_time: str,
    roots: dict[str, Path] | None = None,
    ledger: dict[str, Any] | None = None,
    trusted: bool = False,
    execute: bool = False,
) -> dict[str, Any]:
    if not isinstance(registry, dict) or not isinstance(execute, bool) or not isinstance(trusted, bool) or (ledger is not None and not isinstance(ledger, dict)):
        raise HarnessError("harness_dispatch_invalid")
    event = normalize_input(value, trusted=trusted)
    if execute and not trusted:
        raise HarnessError("harness_untrusted_execution")
    if not execute:
        return {
            "schema_version": 1,
            "artifact_type": "HarnessLoopResult",
            "status": "preview",
            "installed": False,
            "executed": False,
            "mutations": {"adapter": False, "source": False, "goalbuddy": False, "workgraph": False},
            "receipt_artifacts_returned": False,
            "event": event,
            "receipts": [],
        }
    receipts = run_loop(
        registry,
        event,
        evaluation_time=evaluation_time,
        roots=roots,
        ledger=ledger,
    )
    return {
        "schema_version": 1,
        "artifact_type": "HarnessLoopResult",
        "status": "completed",
        "installed": False,
        "executed": True,
        "mutations": {"adapter": False, "source": False, "goalbuddy": False, "workgraph": False},
        "receipt_artifacts_returned": bool(receipts),
        "event": event,
        "receipts": receipts,
    }


def serialize_result(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise HarnessError("harness_output_too_large")
    return text


def _read_source(fixture: str | None, stdin: bool) -> bytes:
    if (fixture is None) == (stdin is False):
        raise HarnessError("harness_source_invalid")
    try:
        path = Path("/dev/stdin") if stdin else Path(fixture)
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise HarnessError("harness_source_unavailable") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise HarnessError("harness_input_too_large")
    return raw


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview one provider-neutral loop fixture.")
    parser.add_argument("--fixture")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--dry-run", action="store_true", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args()
    try:
        raw = _read_source(args.fixture, args.stdin)
        event = normalize_input(load_json_bytes(raw), trusted=False)
        result = {
            "schema_version": 1,
            "artifact_type": "HarnessLoopResult",
            "status": "preview",
            "installed": False,
            "executed": False,
            "mutations": {"adapter": False, "source": False, "goalbuddy": False, "workgraph": False},
            "receipt_artifacts_returned": False,
            "event": event,
            "receipts": [],
        }
    except HarnessError as error:
        result = {
            "schema_version": 1, "artifact_type": "HarnessLoopResult",
            "status": "rejected", "errors": [str(error)], "installed": False,
            "executed": False, "receipts": [],
        }
        print(str(error), file=sys.stderr)
    print(serialize_result(result))


if __name__ == "__main__":
    main()
