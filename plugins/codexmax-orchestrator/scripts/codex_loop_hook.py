#!/usr/bin/env python3
"""Normalize bounded Codex hook fixtures into LoopEvent v1 artifacts."""

import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from loop_compile import run_loop


CONFIG_KEYS = {
    "schema_version", "artifact_type", "adapter_id", "mode", "installed",
    "debounce_seconds", "supported_hooks",
}
HOOK_KEYS = {
    "schema_version", "hook_event_name", "source_event_id", "session_id",
    "occurred_at", "observed_at", "tool_name", "outcome", "paths", "origin",
}
ORIGIN_KEYS = {"run_id", "loop_id", "depth", "ancestry"}
HOOK_NAMES = {"SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"}
EVENT_TYPES = {
    "SessionStart": "session.start",
    "UserPromptSubmit": "prompt.submitted",
    "PostToolUse": "file.changed",
}


class HookError(Exception):
    """A stable fail-closed adapter rejection."""


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HookError("hook_timestamp_invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HookError("hook_timestamp_invalid") from None


def _config(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CONFIG_KEYS:
        raise HookError("hook_config_invalid")
    if value.get("schema_version") != 1 or value.get("artifact_type") != "CodexLoopHookConfig":
        raise HookError("hook_config_invalid")
    if value.get("adapter_id") != "codex-local" or value.get("mode") != "advisory_report_only":
        raise HookError("hook_config_invalid")
    if value.get("installed") is not False:
        raise HookError("hook_config_invalid")
    debounce = value.get("debounce_seconds")
    hooks = value.get("supported_hooks")
    if not isinstance(debounce, int) or isinstance(debounce, bool) or not 0 <= debounce <= 30:
        raise HookError("hook_config_invalid")
    if not isinstance(hooks, list) or set(hooks) != HOOK_NAMES or len(hooks) != len(HOOK_NAMES):
        raise HookError("hook_config_invalid")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise HookError("hook_path_invalid")
    if value.startswith("/") or "\\" in value or ".." in value.split("/"):
        raise HookError("hook_path_invalid")
    normalized = PurePosixPath(value).as_posix()
    if normalized == "." or normalized.startswith("../"):
        raise HookError("hook_path_invalid")
    return normalized


def _identifier(value: object, *, kebab: bool) -> bool:
    if not isinstance(value, str) or not value:
        return False
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-" if kebab else "abcdefghijklmnopqrstuvwxyz0123456789._:-"
    first = "abcdefghijklmnopqrstuvwxyz" if kebab else "abcdefghijklmnopqrstuvwxyz0123456789"
    limit = 64 if kebab else 128
    return len(value) <= limit and value[0] in first and all(character in allowed for character in value)


def _origin(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ORIGIN_KEYS:
        raise HookError("hook_origin_invalid")
    ancestry = value.get("ancestry")
    depth = value.get("depth")
    loop_id = value.get("loop_id")
    run_id = value.get("run_id")
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 8:
        raise HookError("hook_origin_invalid")
    if not isinstance(ancestry, list) or len(ancestry) != depth:
        raise HookError("hook_origin_invalid")
    if not all(isinstance(item, str) for item in ancestry):
        raise HookError("hook_origin_invalid")
    if len(ancestry) != len(set(ancestry)):
        raise HookError("hook_origin_invalid")
    if not all(_identifier(item, kebab=True) for item in ancestry):
        raise HookError("hook_origin_invalid")
    if depth == 0:
        if loop_id is not None or run_id is not None:
            raise HookError("hook_origin_invalid")
    elif not _identifier(loop_id, kebab=True) or not _identifier(run_id, kebab=False) or ancestry[-1] != loop_id:
        raise HookError("hook_origin_invalid")
    return value


def _hook(value: object, supported: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != HOOK_KEYS or value.get("schema_version") != 1:
        raise HookError("hook_payload_invalid")
    name = value.get("hook_event_name")
    if not isinstance(name, str) or name not in supported:
        raise HookError("hook_event_unsupported")
    for key in ("source_event_id", "session_id"):
        item = value.get(key)
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > 128:
            raise HookError("hook_payload_invalid")
    occurred = _timestamp(value.get("occurred_at"))
    observed = _timestamp(value.get("observed_at"))
    if occurred > observed:
        raise HookError("hook_timestamp_invalid")
    paths = value.get("paths")
    if not isinstance(paths, list) or len(paths) > 256:
        raise HookError("hook_payload_invalid")
    normalized_paths = sorted(set(_path(item) for item in paths))
    tool_name = value.get("tool_name")
    outcome = value.get("outcome")
    if name == "PostToolUse":
        if tool_name != "apply_patch" or outcome != "completed" or not normalized_paths:
            raise HookError("hook_payload_invalid")
    elif name == "Stop":
        if tool_name is not None or outcome not in {"completed", "failed"}:
            raise HookError("hook_payload_invalid")
    elif tool_name is not None or outcome is not None or normalized_paths:
        raise HookError("hook_payload_invalid")
    origin = _origin(value.get("origin"))
    return {
        **value,
        "paths": normalized_paths,
        "_occurred": occurred,
        "_observed": observed,
    }


def normalize_hooks(config: dict[str, Any], hook_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Coalesce one bounded hook batch and construct exactly one LoopEvent v1."""
    resolved = _config(config)
    if not isinstance(hook_events, list) or not hook_events or len(hook_events) > 256:
        raise HookError("hook_batch_invalid")
    hooks = [_hook(item, resolved["supported_hooks"]) for item in hook_events]
    first = hooks[0]
    if any(item["hook_event_name"] != first["hook_event_name"] or item["session_id"] != first["session_id"] or item["origin"] != first["origin"] for item in hooks):
        raise HookError("hook_batch_mixed")
    if len(hooks) > 1 and first["hook_event_name"] != "PostToolUse":
        raise HookError("hook_batch_not_debounceable")
    source_ids = [item["source_event_id"] for item in hooks]
    if len(source_ids) != len(set(source_ids)):
        raise HookError("hook_source_event_duplicate")
    earliest = min(item["_occurred"] for item in hooks)
    latest = max(item["_observed"] for item in hooks)
    if latest - earliest > timedelta(seconds=resolved["debounce_seconds"]):
        raise HookError("hook_debounce_window_exceeded")
    paths = sorted(set(path for item in hooks for path in item["paths"]))
    name = first["hook_event_name"]
    event_type = "run.failed" if name == "Stop" and first["outcome"] == "failed" else "run.completed" if name == "Stop" else EVENT_TYPES[name]
    source_ids = sorted(source_ids)
    core = {
        "event_type": event_type,
        "session_id": first["session_id"],
        "paths": paths,
        "origin": first["origin"],
    }
    occurred_at = min(item["occurred_at"] for item in hooks)
    observed_at = max(item["observed_at"] for item in hooks)
    event_hash = _digest({**core, "source_event_ids": source_ids, "occurred_at": occurred_at})
    dedupe_hash = _digest(core)
    locators = [{"root_id": "workspace", "path": path} for path in paths]
    return {
        "schema_version": 1,
        "artifact_type": "LoopEvent",
        "event_id": "codex-event-" + event_hash[:24],
        "event_type": event_type,
        "occurred_at": occurred_at,
        "observed_at": observed_at,
        "source": {
            "adapter_id": resolved["adapter_id"],
            "source_event_id": "codex-source-" + _digest(source_ids)[:24],
            "trust": "local_adapter",
        },
        "origin": first["origin"],
        "workspace_root": ".",
        "subject": {"paths": locators, "goalbuddy_board": None, "workgraph": None},
        "requested_scope": {"read": locators, "write": []},
        "authority": {"board": None, "receipt": None, "mutation_mode": "advisory_report_only"},
        "dedupe_key": "codex-dedupe-" + dedupe_hash[:24],
    }


def dispatch_hooks(
    registry: dict[str, Any],
    config: dict[str, Any],
    hook_events: list[dict[str, Any]],
    *,
    evaluation_time: str,
    roots: dict[str, Path] | None = None,
    ledger: dict[str, Any] | None = None,
    execute: bool = False,
) -> dict[str, Any]:
    """Preview by default; an explicit trusted call may request core execution."""
    resolved = _config(config)
    event = normalize_hooks(resolved, hook_events)
    if not execute:
        return {
            "schema_version": 1,
            "artifact_type": "CodexLoopHookResult",
            "status": "preview",
            "mode": resolved["mode"],
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
        "artifact_type": "CodexLoopHookResult",
        "status": "completed",
        "mode": resolved["mode"],
        "installed": False,
        "executed": True,
        "mutations": {"adapter": False, "source": False, "goalbuddy": False, "workgraph": False},
        "receipt_artifacts_returned": bool(receipts),
        "event": event,
        "receipts": receipts,
    }


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise HookError("fixture_invalid")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview a local Codex loop hook fixture.")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--config", default=str(Path(__file__).resolve().parents[1] / "assets" / "templates" / "codex-loop-hook-config.json"))
    parser.add_argument("--dry-run", action="store_true", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args()
    fixture = _load(Path(args.fixture))
    expected = {"schema_version", "artifact_type", "registry", "hook_events", "ledger", "evaluation_time"}
    if set(fixture) != expected or fixture.get("schema_version") != 1 or fixture.get("artifact_type") != "CodexLoopHookFixture":
        raise HookError("fixture_invalid")
    result = dispatch_hooks(
        fixture["registry"], _load(Path(args.config)), fixture["hook_events"],
        evaluation_time=fixture["evaluation_time"], ledger=fixture["ledger"],
        execute=False,
    )
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
