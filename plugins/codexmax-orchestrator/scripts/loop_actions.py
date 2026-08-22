#!/usr/bin/env python3
"""Resolve and execute source-owned Loop Registry action profiles safely."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

import loop_registry


PROFILE_FILES = {profile_id: f"{profile_id}.json" for profile_id in sorted(loop_registry.FIXED_PROFILE_IDS)}
PROFILE_KEYS = {
    "schema_version", "profile_id", "command_identity", "argv", "cwd",
    "capability", "timeout_seconds", "max_output_bytes", "validation_ids", "parameters",
}
CAPABILITY_KEYS = {"mutation", "network", "credentials", "external_cash", "tokens"}
FIXED_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
}


class ActionError(Exception):
    def __init__(self, *codes: str):
        self.codes = sorted(set(codes or ("action_profile_unbound",)))
        super().__init__(",".join(self.codes))


def _profile_root() -> Path:
    return Path(__file__).resolve().parents[1] / "assets" / "action-profiles"


def _read_profile(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        raw = path.read_bytes()
    except OSError as error:
        raise ActionError("action_profile_unbound") from error
    if resolved != path.absolute() or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or len(raw) > 65_536:
        raise ActionError("action_profile_unbound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=loop_registry._duplicates)  # noqa: SLF001
    except (UnicodeDecodeError, json.JSONDecodeError, loop_registry.LoopContractError) as error:
        raise ActionError("action_profile_unbound") from error
    if not isinstance(value, dict):
        raise ActionError("action_profile_unbound")
    return value, raw


def resolve_profile(profile_id: str, *, roots: dict[str, Path] | None = None) -> dict[str, Any]:
    """Resolve a profile only through the code-owned ID mapping."""
    filename = PROFILE_FILES.get(profile_id)
    if filename is None:
        raise ActionError("action_profile_unknown")
    value, raw = _read_profile(_profile_root() / filename)
    if set(value) != PROFILE_KEYS or value.get("schema_version") != 1 or value.get("profile_id") != profile_id:
        raise ActionError("action_profile_unbound")
    argv = value.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(row, str) and row and "\x00" not in row and len(row.encode()) <= 4096 for row in argv):
        raise ActionError("action_profile_unbound")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ActionError("capability_unknown")
    cwd = value.get("cwd")
    actual_roots = roots or loop_registry.default_roots()
    if not isinstance(cwd, dict) or set(cwd) != {"root_id", "path"} or cwd.get("root_id") not in actual_roots:
        raise ActionError("action_profile_unbound")
    root = actual_roots[cwd["root_id"]].resolve()
    relative = Path(cwd.get("path", ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ActionError("action_profile_unbound")
    resolved_cwd = (root / relative).resolve()
    if resolved_cwd != root and root not in resolved_cwd.parents or not resolved_cwd.is_dir():
        raise ActionError("capability_unknown")
    capability = value.get("capability")
    if not isinstance(capability, dict) or set(capability) != CAPABILITY_KEYS or capability.get("mutation") != "read_only" or any(capability.get(key) is not False for key in CAPABILITY_KEYS - {"mutation"}):
        raise ActionError("capability_unknown")
    timeout = value.get("timeout_seconds")
    output = value.get("max_output_bytes")
    validations = value.get("validation_ids")
    parameters = value.get("parameters")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600 or not isinstance(output, int) or isinstance(output, bool) or not 1024 <= output <= 1_048_576:
        raise ActionError("action_profile_unbound")
    if not isinstance(validations, list) or not validations or len(validations) != len(set(validations)) or not all(isinstance(row, str) and loop_registry.ID_RE.fullmatch(row) for row in validations):
        raise ActionError("action_profile_unbound")
    if parameters != []:
        raise ActionError("action_profile_unbound")
    return {
        **value,
        "profile_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "resolved_cwd": resolved_cwd,
    }


def bind_profile(profile: dict[str, Any], loop: dict[str, Any]) -> dict[str, Any]:
    if profile["profile_id"] not in loop["action_profile_ids"]:
        raise ActionError("action_profile_unbound")
    if loop["scope"]["mutation_mode"] not in {"advisory_report_only", "automatic_read_only"}:
        raise ActionError("capability_unknown")
    return {
        "profile_id": profile["profile_id"],
        "profile_schema_version": profile["schema_version"],
        "profile_sha256": profile["profile_sha256"],
        "command_identity": profile["command_identity"],
        "capability_decision": "compatible",
        "effective_timeout_seconds": min(profile["timeout_seconds"], loop["budget"]["timeout_seconds"]),
        "effective_max_output_bytes": min(profile["max_output_bytes"], loop["budget"]["max_output_bytes"]),
        "validation_ids": list(profile["validation_ids"]),
        "parameters": [],
    }


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_create(roots: dict[str, Path], locator: dict[str, str], raw: bytes) -> None:
    root = roots[locator["root_id"]].resolve()
    relative = Path(locator["path"])
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ActionError("path_escape")
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.exists():
            if current.is_symlink() or not current.is_dir():
                raise ActionError("path_escape")
        else:
            current.mkdir(mode=0o700)
    target = current / relative.parts[-1]
    if target.exists() or target.is_symlink():
        raise ActionError("reference_stale")
    temporary: Path | None = None
    try:
        descriptor, temporary_text = tempfile.mkstemp(prefix=f".{target.name}.pending-", dir=current)
        temporary = Path(temporary_text)
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target, follow_symlinks=False)
        directory_descriptor = os.open(current, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except FileExistsError as error:
        raise ActionError("reference_stale") from error
    except OSError as error:
        raise ActionError("path_invalid") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _sink_locator(loop: dict[str, Any], receipt_id: str, suffix: str) -> dict[str, str]:
    root = loop["proof"]["report_root"]
    base = root["path"].rstrip("/")
    return {"root_id": root["root_id"], "path": f"{base}/loop-runs/{receipt_id}{suffix}"}


def rejected_receipt(registry: dict[str, Any], event: dict[str, Any], codes: list[str], *, recorded_at: str) -> dict[str, Any]:
    """Build a bounded non-persisted rejection receipt when source identity is safe."""
    stable = sorted(set(codes) & loop_registry.STABLE_REJECTION_CODES) or ["schema_invalid"]
    loops = registry.get("loops", []) if isinstance(registry, dict) else []
    matched_loop = loops[0] if len(loops) == 1 and isinstance(loops[0], dict) else None
    action_ids = matched_loop.get("action_profile_ids", []) if matched_loop else []
    action_id = action_ids[0] if len(action_ids) == 1 and action_ids[0] in loop_registry.FIXED_PROFILE_IDS else None
    registry_digest = "sha256:" + hashlib.sha256(
        (loop_registry.canonical_json(registry) + "\n").encode("utf-8")
    ).hexdigest()
    event_digest = "sha256:" + hashlib.sha256(
        (loop_registry.canonical_json(event) + "\n").encode("utf-8")
    ).hexdigest()
    receipt_id = "receipt-rejected-" + hashlib.sha256(
        f"{event.get('event_id')}:{','.join(stable)}".encode()
    ).hexdigest()[:15]
    return {
        "schema_version": 1, "artifact_type": "LoopRunReceipt", "receipt_id": receipt_id,
        "recorded_at": recorded_at,
        "event": {
            "event_id": event.get("event_id", "unknown-event"),
            "event_type": event.get("event_type", "manual.requested"),
            "dedupe_key": event.get("dedupe_key", "unknown-dedupe"),
            "event_sha256": event_digest,
        },
        "registry": {
            "registry_id": registry.get("registry_id", "unknown-registry"),
            "registry_sha256": registry_digest,
            "loop_id": matched_loop.get("loop_id") if matched_loop else None,
            "definition_version": matched_loop.get("definition_version") if matched_loop else None,
            "lifecycle": matched_loop.get("lifecycle", {}).get("state") if matched_loop else None,
        },
        "admission": {
            "decision": "rejected", "preflight_status": "rejected",
            "rejection_codes": stable, "authority_receipt": None,
            "authority_sha256": "unknown", "scope_decision": "unknown",
        },
        "action": {
            "action_profile_id": action_id, "profile_schema_version": None,
            "profile_sha256": "unknown", "command_identity": None,
            "capability_decision": "unknown",
        },
        "execution": {
            "status": "not_run", "result": "rejected", "attempt": 0,
            "started_at": None, "finished_at": None, "duration_ms": "unknown",
            "output": {"captured_chars": 0, "truncated": False, "sha256": "unknown", "artifact_path": None},
            "failure_code": None,
        },
        "validation": [{
            "validation_id": action_id or "preflight", "execution_status": "not_run",
            "result": "not_run", "evidence_path": None, "evidence_sha256": "unknown",
        }],
        "budget": {
            "max_attempts": matched_loop.get("budget", {}).get("max_attempts", 1) if matched_loop else 1,
            "timeout_seconds": matched_loop.get("budget", {}).get("timeout_seconds", 120) if matched_loop else 120,
            "max_output_bytes": matched_loop.get("budget", {}).get("max_output_bytes", 65536) if matched_loop else 65536,
            "explicit_token_cap": matched_loop.get("budget", {}).get("explicit_token_cap") if matched_loop else None,
            "external_cash_authorized": False, "observed_tokens": "unknown",
            "observed_external_cash_usd": "unknown", "evidence_status": "unknown",
        },
        "artifacts": [{"artifact_id": "loop-run-receipt", "path": None, "sha256": "unknown", "state": "not_written"}],
        "notification_intents": [],
        "proof_boundary": {
            "state": "rejected", "local_source": True, "installed": False,
            "live_hook": False, "scheduler_active": False,
            "external_connector": False, "published": False,
            "summary": "Rejected before execution; no action or mutation occurred.",
        },
        "acceptance": {"state": "not_requested", "authority": "none"},
    }


def _receipt(
    compilation: dict[str, Any], registry: dict[str, Any], event: dict[str, Any],
    loop: dict[str, Any], binding: dict[str, Any], captured: dict[str, Any],
    started_at: str, finished_at: str, output_locator: dict[str, str],
) -> dict[str, Any]:
    passed = captured["returncode"] == 0 and not captured["timed_out"] and not captured["truncated"]
    status = "completed" if passed else "failed"
    result = "pass" if passed else "fail"
    output_digest = "sha256:" + hashlib.sha256(captured["output"]).hexdigest()
    receipt_id = "receipt-" + hashlib.sha256(
        f"{compilation['compilation_id']}:{binding['profile_id']}:1".encode()
    ).hexdigest()[:24]
    failure = None
    if captured["timed_out"]:
        failure = "timeout"
    elif captured["truncated"]:
        failure = "output_truncated"
    elif captured["returncode"] != 0:
        failure = "validation_failed"
    validation = [{
        "validation_id": row,
        "execution_status": "completed" if passed else "failed",
        "result": result,
        "evidence_path": output_locator,
        "evidence_sha256": output_digest,
    } for row in binding["validation_ids"]]
    receipt_locator = _sink_locator(loop, receipt_id, ".json")
    proof_state = "proved" if passed else "failed"
    return {
        "schema_version": 1,
        "artifact_type": "LoopRunReceipt",
        "receipt_id": receipt_id,
        "recorded_at": finished_at,
        "event": {
            "event_id": event["event_id"], "event_type": event["event_type"],
            "dedupe_key": event["dedupe_key"], "event_sha256": compilation["event"]["sha256"],
        },
        "registry": {
            "registry_id": registry["registry_id"], "registry_sha256": compilation["registry"]["sha256"],
            "loop_id": loop["loop_id"], "definition_version": loop["definition_version"],
            "lifecycle": loop["lifecycle"]["state"],
        },
        "admission": {
            "decision": "admitted", "preflight_status": "passed", "rejection_codes": [],
            "authority_receipt": compilation["authority"],
            "authority_sha256": compilation["authority"]["sha256"], "scope_decision": "contained",
        },
        "action": {
            "action_profile_id": binding["profile_id"],
            "profile_schema_version": binding["profile_schema_version"],
            "profile_sha256": binding["profile_sha256"],
            "command_identity": binding["command_identity"],
            "capability_decision": "compatible",
        },
        "execution": {
            "status": status, "result": result, "attempt": 1,
            "started_at": started_at, "finished_at": finished_at,
            "duration_ms": captured["duration_ms"],
            "output": {
                "captured_chars": len(captured["output"].decode("utf-8", errors="replace")),
                "truncated": captured["truncated"], "sha256": output_digest,
                "artifact_path": output_locator,
            },
            "failure_code": failure,
        },
        "validation": validation,
        "budget": {
            "max_attempts": loop["budget"]["max_attempts"],
            "timeout_seconds": binding["effective_timeout_seconds"],
            "max_output_bytes": binding["effective_max_output_bytes"],
            "explicit_token_cap": loop["budget"]["explicit_token_cap"],
            "external_cash_authorized": False,
            "observed_tokens": 0, "observed_external_cash_usd": 0,
            "evidence_status": "known",
        },
        "artifacts": [
            {"artifact_id": "action-output", "path": output_locator, "sha256": output_digest, "state": "validated"},
            {"artifact_id": "loop-run-receipt", "path": receipt_locator, "sha256": "unknown", "state": "written"},
        ],
        "notification_intents": [],
        "proof_boundary": {
            "state": proof_state, "local_source": True, "installed": False,
            "live_hook": False, "scheduler_active": False,
            "external_connector": False, "published": False,
            "summary": "Local fixed-profile execution evidence only; no activation or acceptance.",
        },
        "acceptance": {"state": "not_requested", "authority": "none"},
    }
