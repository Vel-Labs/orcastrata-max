#!/usr/bin/env python3
"""Verify and apply one quality-accepted scheduled Worker result.

This is the only scheduler-v1 bridge into Supervisor runtime.  It never calls a
provider and never mutates GoalBuddy.  Non-Worker role references remain typed
but unapplied until their lifecycle-specific adapters are qualified.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1


def _load(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SCHEDULER = _load("codexmax_scheduler_for_application", "schedule_headless_dispatch.py")
SUPERVISOR = _load("codexmax_supervisor_for_application", "run_goalbuddy_supervisor.py")
RESOLVER = _load("codexmax_resolver_for_application", "resolve_worker_route.py")
LEDGER = SCHEDULER.LEDGER


class ApplicationError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def digest(value: Any, *, prefixed: bool = False) -> str:
    value_digest = hashlib.sha256(canonical_json(value)).hexdigest()
    return "sha256:" + value_digest if prefixed else value_digest


def _strict(value: Any, field: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ApplicationError("shape_invalid", field)
    return copy.deepcopy(value)


def _read_json(path: Path, field: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("input_unreadable", field) from exc
    if not isinstance(value, dict):
        raise ApplicationError("shape_invalid", field)
    return value


def _inside_regular(root: Path, relative: str, field: str) -> tuple[Path, bytes]:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts or "\\" in relative:
        raise ApplicationError("artifact_path_invalid", field)
    canonical_root = root.resolve(strict=True)
    named = canonical_root / relative
    try:
        named_stat = named.lstat()
        resolved = named.resolve(strict=True)
        resolved.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ApplicationError("artifact_unreadable", field) from exc
    if stat.S_ISLNK(named_stat.st_mode) or not stat.S_ISREG(named_stat.st_mode) or named_stat.st_nlink != 1:
        raise ApplicationError("artifact_unsafe", field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(named, flags)
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ApplicationError("artifact_unreadable", field) from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink) or before.st_nlink != 1:
        raise ApplicationError("artifact_changed", field)
    return resolved, b"".join(chunks)


def _descriptor_content(root: Path, descriptor: Any, field: str, kind: str) -> dict[str, Any]:
    try:
        verified = SCHEDULER._verified_artifact_descriptor(root, descriptor, field, kind)
    except SCHEDULER.ScheduleError as exc:
        raise ApplicationError(exc.code, exc.detail) from exc
    _, raw = _inside_regular(root, verified["path"], field)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("artifact_content_invalid", field) from exc
    return value


def _normalized_artifact_path(root: Path, value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ApplicationError("artifact_binding_mismatch", field)
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            return candidate.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
        except (OSError, RuntimeError, ValueError) as exc:
            raise ApplicationError("artifact_binding_mismatch", field) from exc
    return candidate.as_posix()


def _verify_manifest(manifest: Any, envelope: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version", "artifact_type", "schedule_plan_sha256", "envelope_sha256",
        "identity", "bindings", "lease", "selected_route", "ledger", "usage",
        "return_manifest", "quality_receipt", "supervisor_event_bundle",
        "transport_succeeded", "quality_accepted", "supervisor_applied",
        "goalbuddy_applied", "accepted", "manifest_sha256",
    }
    value = _strict(manifest, "manifest", fields)
    supplied = value.pop("manifest_sha256")
    if supplied != SCHEDULER.digest(value):
        raise ApplicationError("manifest_digest_mismatch")
    value["manifest_sha256"] = supplied
    if value["schema_version"] != 1 or value["artifact_type"] != "DispatchScheduleManifest":
        raise ApplicationError("manifest_invalid", "kind")
    if any(value[field] is not False for field in (
        "transport_succeeded", "quality_accepted", "supervisor_applied",
        "goalbuddy_applied", "accepted",
    )):
        raise ApplicationError("manifest_history_mutated")
    if value["envelope_sha256"] != SCHEDULER.digest(envelope):
        raise ApplicationError("manifest_envelope_mismatch")
    return value


def _verify_ledger(manifest: dict[str, Any], ledger_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    verified = LEDGER.verify_ledger(ledger_path)
    interval = _strict(
        manifest["ledger"], "manifest.ledger",
        {"sequence_start", "sequence_end", "head_before", "head_after"},
    )
    start, end = interval["sequence_start"], interval["sequence_end"]
    if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool) or start != end or start < 1 or end > verified["event_count"]:
        raise ApplicationError("manifest_ledger_range_invalid")
    grant = verified["rows"][end - 1]
    before = LEDGER.ZERO_HASH if start == 1 else verified["rows"][start - 2]["event_hash"]
    if before != interval["head_before"] or grant["event_hash"] != interval["head_after"]:
        raise ApplicationError("manifest_ledger_head_mismatch")
    identity = manifest["identity"]
    bindings = manifest["bindings"]
    selected = manifest["selected_route"]
    route_fields = {
        "name": "route_name",
        "provider": "provider",
        "exact_model": "exact_model",
        "route_id": "route_id",
        "runtime": "runtime",
        "runtime_host": "runtime_host",
        "reasoning": "reasoning",
        "independence_group": "independence_group",
        "preflight_key_sha256": "preflight_key_sha256",
    }
    if (
        grant["event_type"] != "lease_granted"
        or grant["envelope_sha256"] != manifest["envelope_sha256"]
        or grant["config_sha256"] != bindings.get("config_sha256")
        or grant["board_sha256"] != bindings.get("board_sha256")
        or any(grant[field] != identity.get(field) for field in ("goal_id", "checkpoint_id", "task_id", "assignment_id"))
        or grant["lease"] != manifest["lease"]
        or not isinstance(selected, dict)
        or any(selected.get(source) != grant["route"].get(target) for source, target in route_fields.items())
        or manifest.get("schedule_plan_sha256") != grant["evidence"].get("plan_sha256")
        or manifest.get("usage", {}).get("reserved") != grant["accounting"]
        or manifest.get("usage", {}).get("observed") != {"tokens": "unknown", "cost": "unknown"}
        or selected.get("evidence_path") != grant["evidence"].get("output_path")
        or grant["evidence"].get("authority_sha256") != bindings.get("authority_sha256")
        or grant["evidence"].get("workgraph_sha256") != bindings.get("workgraph_sha256")
        or grant["evidence"].get("supervisor_sha256") != bindings.get("supervisor_sha256")
    ):
        raise ApplicationError("manifest_ledger_binding_mismatch")
    lease_id = manifest["lease"].get("lease_id")
    lease_rows = [row for row in verified["rows"] if row["lease"].get("lease_id") == lease_id]
    if any(row["event_type"] == "execution_unknown" for row in lease_rows):
        raise ApplicationError("execution_unknown_requires_parent_decision", lease_id)
    terminal = [row for row in lease_rows if row["event_type"] in SCHEDULER.TERMINAL_LEASE_EVENTS]
    if terminal:
        if (
            len(terminal) != 1
            or terminal[0]["event_type"] != "lease_released"
            or terminal[0]["evidence"].get("schedule_manifest_sha256") != manifest["manifest_sha256"]
        ):
            raise ApplicationError("lease_not_active", lease_id)
    else:
        try:
            active = SCHEDULER._find_active(verified, lease_id)
        except SCHEDULER.ScheduleError as exc:
            raise ApplicationError("lease_not_active", lease_id) from exc
        if active["lease"].get("fencing_token") != manifest["lease"].get("fencing_token"):
            raise ApplicationError("stale_fencing_token", lease_id)
    return verified, grant


def _verify_result(
    root: Path,
    manifest: dict[str, Any],
    envelope: dict[str, Any],
    *,
    allow_role_reference: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    returned = _descriptor_content(root, manifest["return_manifest"], "return_manifest", "DispatchReturnManifest")
    quality = _descriptor_content(root, manifest["quality_receipt"], "quality_receipt", "ArtifactQualityReceipt")
    bundle = _descriptor_content(root, manifest["supervisor_event_bundle"], "supervisor_event_bundle", "SupervisorEventBundle")
    route_name = manifest["selected_route"].get("name")
    if (
        returned.get("status") != "selected"
        or returned.get("failure") is not None
        or returned.get("selected_route") != route_name
        or returned.get("accepted") is not False
        or returned.get("applied_to_goalbuddy") is not False
        or returned.get("applied_to_supervisor") is not False
        or not isinstance(returned.get("attempts"), list)
        or len(returned["attempts"]) != 1
        or returned["attempts"][0].get("route_name") != route_name
        or returned["attempts"][0].get("outcome") != "success"
    ):
        raise ApplicationError("return_manifest_not_successful_single_attempt")
    artifact = returned.get("artifact")
    if not isinstance(artifact, dict):
        raise ApplicationError("returned_artifact_missing")
    artifact_path = _normalized_artifact_path(root, artifact.get("path"), "return.artifact.path")
    _, artifact_raw = _inside_regular(root, artifact_path, "return.artifact")
    artifact_sha = hashlib.sha256(artifact_raw).hexdigest()
    if artifact.get("sha256") != "sha256:" + artifact_sha or artifact.get("bytes") != len(artifact_raw):
        raise ApplicationError("returned_artifact_descriptor_mismatch")
    quality_artifact = quality.get("artifact", {})
    if (
        quality.get("accepted") is not True
        or quality.get("findings") != []
        or quality.get("checks_executed") is not True
        or quality.get("arbitrary_commands_executed") is not False
        or quality.get("model_judgment_used") is not False
    ):
        raise ApplicationError("quality_rejected")
    if quality.get("policy_id") != envelope.get("quality_policy", {}).get("policy_id"):
        raise ApplicationError("quality_policy_mismatch")
    if (
        _normalized_artifact_path(root, quality_artifact.get("path"), "quality.artifact.path") != artifact_path
        or quality_artifact.get("sha256") != artifact_sha
        or quality_artifact.get("size_bytes") != len(artifact_raw)
    ):
        raise ApplicationError("quality_artifact_binding_mismatch")
    handoff = returned.get("supervisor_handoff", {})
    scheduled_bundle = manifest["supervisor_event_bundle"]
    if (
        handoff.get("path") != scheduled_bundle.get("path")
        or handoff.get("sha256") != scheduled_bundle.get("sha256")
        or handoff.get("bytes") != scheduled_bundle.get("size_bytes")
    ):
        raise ApplicationError("supervisor_handoff_binding_mismatch")
    binding = bundle.get("binding", {})
    identity = manifest["identity"]
    if (
        binding.get("supervisor_assignment_id") != identity.get("assignment_id")
        or binding.get("expected_artifact") != artifact_path
        or binding.get("expected_artifact_sha256") != "sha256:" + artifact_sha
        or bundle.get("applied_to_supervisor") is not False
        or bundle.get("applied_to_goalbuddy") is not False
    ):
        raise ApplicationError("supervisor_bundle_binding_mismatch")
    events = bundle.get("events")
    semantic_role = bundle.get("semantic_role")
    if semantic_role != envelope.get("semantic_role"):
        raise ApplicationError("supervisor_bundle_role_mismatch")
    if semantic_role != "worker":
        expected_event = {
            "tester": "independent_test",
            "documenter": "documentation_result",
            "auditor": "audit_result",
        }.get(semantic_role)
        if (
            not allow_role_reference
            or expected_event is None
            or bundle.get("handoff_kind") != "role_labeled_reference"
            or bundle.get("required_supervisor_adapter_event") != expected_event
            or events != []
            or not isinstance(binding.get("route_packet_sha256"), str)
            or not binding["route_packet_sha256"].startswith("sha256:")
            or len(binding["route_packet_sha256"]) != 71
            or any(character not in "0123456789abcdef" for character in binding["route_packet_sha256"][7:])
        ):
            raise ApplicationError("manual_role_adapter_required", str(semantic_role))
        return returned, quality, bundle
    if bundle.get("handoff_kind") != "direct_worker_lifecycle":
        raise ApplicationError("supervisor_bundle_lifecycle_invalid")
    if not isinstance(events, list) or [event.get("event_type") for event in events if isinstance(event, dict)] != ["route_resolved", "worker_result"]:
        raise ApplicationError("supervisor_bundle_lifecycle_invalid")
    route_packet = events[0].get("payload", {}).get("route_packet")
    if not isinstance(route_packet, dict) or digest(route_packet, prefixed=True) != binding.get("route_packet_sha256"):
        raise ApplicationError("supervisor_route_packet_digest_mismatch")
    try:
        resolution = RESOLVER.resolve_worker_route(copy.deepcopy(route_packet))
    except RESOLVER.ResolutionError as exc:
        raise ApplicationError("supervisor_route_resolution_failed", exc.code) from exc
    if resolution.get("status") != "selected" or resolution.get("selected_route") != route_name:
        raise ApplicationError("supervisor_route_identity_mismatch")
    result_payload = events[1].get("payload", {})
    if result_payload.get("artifact") != artifact_path or result_payload.get("status") != "ready_for_review":
        raise ApplicationError("supervisor_result_binding_mismatch")
    if any(event.get("lane_id") != binding.get("supervisor_lane_id") for event in events):
        raise ApplicationError("supervisor_lane_binding_mismatch")
    return returned, quality, bundle


def _ledger_event(
    grant: dict[str, Any], event_type: str, now: str, marker: str,
    *, return_manifest: dict[str, Any], quality_receipt: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    event = {key: copy.deepcopy(grant[key]) for key in LEDGER.EVENT_FIELDS}
    event["event_id"] = hashlib.sha256(
        canonical_json([marker, grant["event_id"], manifest["manifest_sha256"]])
    ).hexdigest()
    event["event_type"] = event_type
    event["timestamp"] = now
    usage = return_manifest.get("usage", {})
    token_value = usage.get("tokens", {}).get("value", "unknown")
    cost_value = usage.get("cost", {}).get("value", "unknown")
    event["accounting"] = {
        **event["accounting"],
        "observed_tokens": token_value if token_value is not None else "unknown",
        "observed_cost": cost_value if cost_value is not None else "unknown",
        "accounting_status": "accounted" if event_type == "dispatch_finished" else "unknown",
        "accounting_scope": "orcastrata_admitted_executions",
        "accounting_method": "managed_ledger_append" if event_type == "dispatch_finished" else "not_applicable",
    }
    event["evidence"] = {
        **event["evidence"],
        "work_status": return_manifest.get("work_status", return_manifest.get("status", "unknown")),
        "execution_owner": "orcastrata_managed",
        "dispatch_return_manifest_sha256": manifest["return_manifest"]["sha256"],
        "quality_receipt_sha256": manifest["quality_receipt"]["sha256"],
        "schedule_manifest_sha256": manifest["manifest_sha256"],
        "quality_receipt_self_sha256": quality_receipt["receipt_sha256"],
    }
    return event


def _atomic_create_json(path: Path, root: Path, value: dict[str, Any]) -> None:
    canonical_root = root.resolve(strict=True)
    try:
        parent = path.parent.resolve(strict=True)
        parent.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ApplicationError("receipt_path_invalid", str(path)) from exc
    if path.exists() or path.is_symlink():
        raise ApplicationError("receipt_exists", str(path))
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ApplicationError("receipt_exists", str(path)) from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_replace_json(path: Path, root: Path, value: dict[str, Any]) -> None:
    canonical_root = root.resolve(strict=True)
    try:
        parent = path.parent.resolve(strict=True)
        parent.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ApplicationError("recovery_path_invalid", str(path)) from exc
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _relative_path(root: Path, path: Path, field: str, *, must_exist: bool = True) -> str:
    try:
        if must_exist:
            resolved = path.resolve(strict=True)
        else:
            resolved = path.parent.resolve(strict=True) / path.name
    except (OSError, RuntimeError) as exc:
        raise ApplicationError("path_outside_repository", field) from exc
    if must_exist and resolved != Path(os.path.abspath(path)):
        raise ApplicationError("path_alias_forbidden", field)
    try:
        return resolved.relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ApplicationError("path_outside_repository", field) from exc


def _open_scheduler_lock(ledger_path: Path, root: Path):
    """Open the canonical in-repository scheduler lock without following aliases."""

    try:
        canonical_root = root.resolve(strict=True)
        lexical_ledger = Path(os.path.abspath(ledger_path))
        named_ledger = lexical_ledger.lstat()
        resolved_ledger = lexical_ledger.resolve(strict=True)
        resolved_ledger.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ApplicationError("scheduler_lock_path_invalid", str(ledger_path)) from exc
    if (
        resolved_ledger != lexical_ledger
        or stat.S_ISLNK(named_ledger.st_mode)
        or not stat.S_ISREG(named_ledger.st_mode)
        or named_ledger.st_nlink != 1
    ):
        raise ApplicationError("scheduler_lock_path_invalid", str(ledger_path))
    lock_path = resolved_ledger.with_name(resolved_ledger.name + ".scheduler.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        opened = os.fstat(descriptor)
        named_lock = lock_path.lstat()
        resolved_lock = lock_path.resolve(strict=True)
        resolved_lock.relative_to(canonical_root)
        if (
            resolved_lock != lock_path
            or stat.S_ISLNK(named_lock.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named_lock.st_mode)
            or opened.st_nlink != 1
            or named_lock.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named_lock.st_dev, named_lock.st_ino)
        ):
            raise ApplicationError("scheduler_lock_path_invalid", str(lock_path))
        return os.fdopen(descriptor, "r+b")
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _recovery_value(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("recovery_sha256", None)
    result["recovery_sha256"] = digest(result, prefixed=True)
    return result


def _write_recovery(path: Path, root: Path, value: dict[str, Any], *, create: bool) -> dict[str, Any]:
    result = _recovery_value(value)
    if create:
        _atomic_create_json(path, root, result)
    else:
        _atomic_replace_json(path, root, result)
    return result


def _read_recovery(path: Path, root: Path) -> dict[str, Any]:
    relative = _relative_path(root, path, "recovery")
    _, raw = _inside_regular(root, relative, "recovery")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("application_recovery_invalid", "json") from exc
    if not isinstance(value, dict):
        raise ApplicationError("application_recovery_invalid", "shape")
    supplied = value.get("recovery_sha256")
    payload = copy.deepcopy(value)
    payload.pop("recovery_sha256", None)
    if supplied != digest(payload, prefixed=True):
        raise ApplicationError("application_recovery_invalid", "digest")
    return value


def _supervisor_records(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("supervisor_event_log_invalid") from exc
    try:
        verified = SUPERVISOR.verify_event_log(path)
    except SUPERVISOR.LoopError as exc:
        raise ApplicationError("supervisor_event_log_invalid", f"{exc.code}:{exc.detail}") from exc
    return verified, records


def _prepare_supervisor_recovery(
    *, state: dict[str, Any], board: dict[str, Any], bundle: dict[str, Any], root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    states = [copy.deepcopy(state)]
    records: list[dict[str, Any]] = []
    current = copy.deepcopy(state)
    for event in bundle["events"]:
        try:
            updated, payload = SUPERVISOR.transition_runtime(current, board, event, root)
        except SUPERVISOR.LoopError as exc:
            raise ApplicationError("supervisor_preflight_rejected", f"{exc.code}:{exc.detail}") from exc
        record = SUPERVISOR._event_record(current, event, payload)
        SUPERVISOR._advance_event_cursor(updated, record)
        records.append(record)
        states.append(updated)
        current = updated
    return records, states


def _recovery_bindings(
    *, root: Path, manifest_relative: str, manifest_raw: bytes,
    manifest: dict[str, Any], envelope: dict[str, Any], goal_path: Path,
    board_path: Path, state_path: Path, event_log_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    return {
        "manifest_path": manifest_relative,
        "manifest_file_sha256": "sha256:" + hashlib.sha256(manifest_raw).hexdigest(),
        "manifest_sha256": manifest["manifest_sha256"],
        "envelope_sha256": SCHEDULER.digest(envelope),
        "lease_id": manifest["lease"]["lease_id"],
        "fencing_token": manifest["lease"]["fencing_token"],
        "goal_path": _relative_path(root, goal_path, "goal"),
        "board_path": _relative_path(root, board_path, "board"),
        "state_path": _relative_path(root, state_path, "state"),
        "event_log_path": _relative_path(root, event_log_path, "events"),
        "receipt_path": _relative_path(root, receipt_path, "receipt", must_exist=False),
        "board_sha256": manifest["bindings"]["board_sha256"],
        "supervisor_initial_sha256": manifest["bindings"]["supervisor_sha256"],
        "event_bundle_sha256": manifest["supervisor_event_bundle"]["sha256"],
        "quality_receipt_sha256": manifest["quality_receipt"]["sha256"],
    }


def _new_recovery(
    *, application_id: str, started_at: str, bindings: dict[str, Any],
    log: dict[str, Any], records: list[dict[str, Any]], states: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": "DispatchApplicationRecovery",
        "application_id": application_id,
        "status": "prepared",
        "started_at": started_at,
        "bindings": copy.deepcopy(bindings),
        "supervisor": {
            "sequence_before": log["event_count"],
            "head_before": log["last_event_hash"],
            "expected_records": copy.deepcopy(records),
            "state_snapshots": copy.deepcopy(states),
        },
        "stages": {
            "supervisor_event_count": 0,
            "dispatch_finished_sequence": None,
            "quality_accepted_sequence": None,
            "schedule_closed_sequence": None,
            "lease_released_sequence": None,
            "receipt_created": False,
        },
    }


def _validate_recovery(
    value: dict[str, Any], *, application_id: str, bindings: dict[str, Any],
    board: dict[str, Any], bundle: dict[str, Any], root: Path,
) -> dict[str, Any]:
    required = {
        "schema_version", "artifact_type", "application_id", "status", "started_at",
        "bindings", "supervisor", "stages", "recovery_sha256",
    }
    if set(value) != required or value.get("schema_version") != 1 or value.get("artifact_type") != "DispatchApplicationRecovery":
        raise ApplicationError("application_recovery_invalid", "shape")
    if value.get("application_id") != application_id or value.get("bindings") != bindings:
        raise ApplicationError("application_recovery_conflict", "bindings")
    supervisor = value.get("supervisor")
    stages = value.get("stages")
    if not isinstance(supervisor, dict) or set(supervisor) != {
        "sequence_before", "head_before", "expected_records", "state_snapshots",
    } or not isinstance(stages, dict) or set(stages) != {
        "supervisor_event_count", "dispatch_finished_sequence", "quality_accepted_sequence",
        "schedule_closed_sequence", "lease_released_sequence", "receipt_created",
    }:
        raise ApplicationError("application_recovery_invalid", "control shape")
    states = supervisor["state_snapshots"]
    records = supervisor["expected_records"]
    if (
        not isinstance(states, list)
        or not isinstance(records, list)
        or not records
        or len(states) != len(records) + 1
    ):
        raise ApplicationError("application_recovery_invalid", "supervisor shape")
    recomputed_records, recomputed_states = _prepare_supervisor_recovery(
        state=states[0], board=board, bundle=bundle, root=root,
    )
    if records != recomputed_records or states != recomputed_states:
        raise ApplicationError("application_recovery_invalid", "supervisor projection")
    if not isinstance(value.get("started_at"), str):
        raise ApplicationError("application_recovery_invalid", "started_at")
    return value


def _reconcile_supervisor_locked(
    *, recovery: dict[str, Any], state_path: Path, event_log_path: Path,
) -> tuple[dict[str, Any], int]:
    log, records = _supervisor_records(event_log_path)
    control = recovery["supervisor"]
    before_count = control["sequence_before"]
    expected = control["expected_records"]
    snapshots = control["state_snapshots"]
    if not isinstance(before_count, int) or isinstance(before_count, bool) or before_count < 0 or before_count > len(records):
        raise ApplicationError("application_recovery_conflict", "event sequence")
    before_head = LEDGER.ZERO_HASH if before_count == 0 else records[before_count - 1].get("event_hash")
    if before_head != control["head_before"]:
        raise ApplicationError("application_recovery_conflict", "event head")
    suffix = records[before_count:]
    if len(suffix) > len(expected) or suffix != expected[:len(suffix)]:
        raise ApplicationError("application_recovery_conflict", "event suffix")
    state = SUPERVISOR.migrate_runtime_state(SUPERVISOR._load_state(state_path))
    prefix = len(suffix)
    if state == snapshots[prefix]:
        pass
    elif prefix > 0 and state == snapshots[prefix - 1]:
        SUPERVISOR._atomic_write_json(state_path, snapshots[prefix])
        state = copy.deepcopy(snapshots[prefix])
    else:
        raise ApplicationError("application_recovery_conflict", "runtime state")
    if (
        state.get("event_sequence") != log["event_count"]
        or state.get("last_event_hash") != log["last_event_hash"]
        or state.get("last_event_id") != log["last_event_id"]
    ):
        raise ApplicationError("application_recovery_conflict", "runtime cursor")
    return state, prefix


def _update_recovery_stage(
    recovery_path: Path, root: Path, recovery: dict[str, Any],
    *, status: str | None = None, **stages: Any,
) -> dict[str, Any]:
    result = copy.deepcopy(recovery)
    if status is not None:
        result["status"] = status
    result["stages"].update(stages)
    return _write_recovery(recovery_path, root, result, create=False)


def _apply_supervisor_locked(
    *, recovery_path: Path, recovery: dict[str, Any], root: Path,
    goal_path: Path, board_path: Path, state_path: Path, event_log_path: Path,
    receipt_path: Path, bundle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _, prefix = _reconcile_supervisor_locked(
        recovery=recovery, state_path=state_path, event_log_path=event_log_path,
    )
    expected_count = len(bundle["events"])
    if recovery["stages"].get("supervisor_event_count") != prefix:
        recovery = _update_recovery_stage(
            recovery_path, root, recovery,
            status="supervisor_applying" if prefix < expected_count else "supervisor_applied",
            supervisor_event_count=prefix,
        )
    for event in bundle["events"][prefix:]:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=receipt_path.parent, delete=False)
        event_path = Path(handle.name)
        try:
            with handle:
                json.dump(event, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            SUPERVISOR._apply_event_files_unlocked(
                goal_path, board_path, state_path, event_log_path, event_path, root,
            )
        except SUPERVISOR.LoopError as exc:
            raise ApplicationError("supervisor_application_failed", f"{exc.code}:{exc.detail}") from exc
        finally:
            event_path.unlink(missing_ok=True)
        _, prefix = _reconcile_supervisor_locked(
            recovery=recovery, state_path=state_path, event_log_path=event_log_path,
        )
        recovery = _update_recovery_stage(
            recovery_path, root, recovery,
            status="supervisor_applying" if prefix < expected_count else "supervisor_applied",
            supervisor_event_count=prefix,
        )
    if prefix != expected_count:
        raise ApplicationError("supervisor_application_incomplete")
    final_record = recovery["supervisor"]["expected_records"][-1]
    summary = {
        "event_ids": [record["event_id"] for record in recovery["supervisor"]["expected_records"]],
        "sequence_before": recovery["supervisor"]["sequence_before"],
        "sequence_after": final_record["sequence"],
        "head_after": final_record["event_hash"],
    }
    return recovery, summary


def _application_row(
    verified: dict[str, Any], manifest: dict[str, Any], event_type: str,
) -> dict[str, Any] | None:
    lease_id = manifest["lease"]["lease_id"]
    rows = [
        row for row in verified["rows"]
        if row["lease"].get("lease_id") == lease_id and row["event_type"] == event_type
    ]
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["evidence"].get("schedule_manifest_sha256") != manifest["manifest_sha256"]:
        raise ApplicationError("application_stage_conflict", event_type)
    return rows[0]


def _release_event(
    grant: dict[str, Any], now: str, *, return_manifest: dict[str, Any],
    quality_receipt: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    event = _ledger_event(
        grant, "lease_released", now, "lease_released",
        return_manifest=return_manifest, quality_receipt=quality_receipt, manifest=manifest,
    )
    event["lease"]["released_at"] = now
    return event


def _append_or_reuse_stage(
    *, ledger_path: Path, verified: dict[str, Any], manifest: dict[str, Any],
    event_type: str, now: str, factory: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    existing = _application_row(verified, manifest, event_type)
    expected = factory(existing["timestamp"] if existing is not None else now)
    if existing is not None:
        if any(existing[field] != expected[field] for field in LEDGER.EVENT_FIELDS):
            raise ApplicationError("application_stage_conflict", event_type)
        return existing, verified
    try:
        row = LEDGER.append_event(ledger_path, expected, expected_head=verified["head_hash"])
        return row, LEDGER.verify_ledger(ledger_path, expected_head=row["event_hash"])
    except LEDGER.LedgerError as exc:
        raise ApplicationError("ledger_finalization_failed", f"{exc.code}:{exc.detail}") from exc


def _finalize_ledger_locked(
    *, recovery_path: Path, recovery: dict[str, Any], ledger_path: Path,
    grant: dict[str, Any], manifest: dict[str, Any], returned: dict[str, Any],
    quality: dict[str, Any], supervisor_summary: dict[str, Any], root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    verified, _ = _verify_ledger(manifest, ledger_path)
    now = recovery["started_at"]
    stages = [
        ("dispatch_finished", "dispatch_finished_sequence", lambda timestamp: _ledger_event(
            grant, "dispatch_finished", timestamp, "dispatch_finished",
            return_manifest=returned, quality_receipt=quality, manifest=manifest,
        )),
        ("quality_accepted", "quality_accepted_sequence", lambda timestamp: _ledger_event(
            grant, "quality_accepted", timestamp, "quality_accepted",
            return_manifest=returned, quality_receipt=quality, manifest=manifest,
        )),
        ("schedule_closed", "schedule_closed_sequence", lambda timestamp: {
            **_ledger_event(
                grant, "schedule_closed", timestamp, "schedule_closed",
                return_manifest=returned, quality_receipt=quality, manifest=manifest,
            ),
            "evidence": {
                **_ledger_event(
                    grant, "schedule_closed", timestamp, "schedule_closed",
                    return_manifest=returned, quality_receipt=quality, manifest=manifest,
                )["evidence"],
                "supervisor_event_ids": supervisor_summary["event_ids"],
            },
        }),
        ("lease_released", "lease_released_sequence", lambda timestamp: _release_event(
            grant, timestamp, return_manifest=returned, quality_receipt=quality, manifest=manifest,
        )),
    ]
    rows: dict[str, dict[str, Any]] = {}
    seen_missing = False
    for event_type, stage_field, factory in stages:
        existing = _application_row(verified, manifest, event_type)
        if existing is None:
            seen_missing = True
        elif seen_missing:
            raise ApplicationError("application_stage_conflict", f"out_of_order:{event_type}")
        row, verified = _append_or_reuse_stage(
            ledger_path=ledger_path, verified=verified, manifest=manifest,
            event_type=event_type, now=now, factory=factory,
        )
        rows[event_type] = row
        if recovery["stages"].get(stage_field) != row["sequence"]:
            recovery = _update_recovery_stage(
                recovery_path, root, recovery,
                status="ledger_finalizing" if event_type != "lease_released" else "lease_released",
                **{stage_field: row["sequence"]},
            )
    return recovery, {
        "dispatch_finished_sequence": rows["dispatch_finished"]["sequence"],
        "quality_accepted_sequence": rows["quality_accepted"]["sequence"],
        "schedule_closed_sequence": rows["schedule_closed"]["sequence"],
        "head_after_release": rows["lease_released"]["event_hash"],
    }


def _read_application_receipt(path: Path, root: Path) -> dict[str, Any]:
    relative = _relative_path(root, path, "receipt")
    _, raw = _inside_regular(root, relative, "receipt")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("receipt_conflict", "json") from exc
    if not isinstance(value, dict):
        raise ApplicationError("receipt_conflict", "shape")
    supplied = value.get("receipt_sha256")
    payload = copy.deepcopy(value)
    payload.pop("receipt_sha256", None)
    if supplied != digest(payload, prefixed=True):
        raise ApplicationError("receipt_conflict", "digest")
    return value


def apply_scheduled_dispatch(
    *, manifest_path: Path, envelope: dict[str, Any], repo_root: Path, ledger_path: Path,
    goal_path: Path, board_path: Path, state_path: Path, event_log_path: Path,
    receipt_path: Path, now: str,
) -> dict[str, Any]:
    """Apply one verified Worker bundle as a serialized resumable transaction."""

    root = repo_root.resolve(strict=True)
    manifest_relative = _relative_path(root, manifest_path, "manifest")
    _, manifest_raw = _inside_regular(root, manifest_relative, "manifest")
    try:
        manifest_input = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ApplicationError("manifest_unreadable") from exc
    manifest = _verify_manifest(manifest_input, envelope)
    returned, quality, bundle = _verify_result(root, manifest, envelope)
    bindings = _recovery_bindings(
        root=root, manifest_relative=manifest_relative, manifest_raw=manifest_raw,
        manifest=manifest, envelope=envelope, goal_path=goal_path,
        board_path=board_path, state_path=state_path, event_log_path=event_log_path,
        receipt_path=receipt_path,
    )
    application_id = digest([
        manifest["manifest_sha256"], manifest["lease"]["lease_id"],
        manifest["lease"]["fencing_token"],
    ], prefixed=True)
    recovery_path = receipt_path.with_name(receipt_path.name + ".recovery.json")
    _relative_path(root, recovery_path, "recovery", must_exist=False)
    for field, path in (
        ("ledger", ledger_path),
        ("goal", goal_path),
        ("board", board_path),
        ("supervisor_state", state_path),
        ("supervisor_events", event_log_path),
    ):
        relative = _relative_path(root, path, field)
        _inside_regular(root, relative, field)

    with _open_scheduler_lock(ledger_path, root) as scheduler_lock:
        fcntl.flock(scheduler_lock.fileno(), fcntl.LOCK_EX)
        with SUPERVISOR.open_supervisor_lock(state_path, root) as supervisor_lock:
            fcntl.flock(supervisor_lock.fileno(), fcntl.LOCK_EX)
            verified, grant = _verify_ledger(manifest, ledger_path)
            board_relative = _relative_path(root, board_path, "board")
            state_relative = _relative_path(root, state_path, "supervisor_state")
            _, board_raw = _inside_regular(root, board_relative, "board")
            _, state_raw = _inside_regular(root, state_relative, "supervisor_state")
            if "sha256:" + hashlib.sha256(board_raw).hexdigest() != manifest["bindings"].get("board_sha256"):
                raise ApplicationError("board_binding_drift")
            board = SUPERVISOR.inspect_goalbuddy(goal_path, board_path)
            if board["active_task"] != manifest["identity"]["checkpoint_id"]:
                raise ApplicationError("supervisor_checkpoint_mismatch")

            if recovery_path.exists() or recovery_path.is_symlink():
                recovery = _validate_recovery(
                    _read_recovery(recovery_path, root), application_id=application_id,
                    bindings=bindings, board=board, bundle=bundle, root=root,
                )
            else:
                conflicting = any(
                    _application_row(verified, manifest, event_type) is not None
                    for event_type in (
                        "dispatch_finished", "quality_accepted", "schedule_closed", "lease_released",
                    )
                )
                if conflicting or receipt_path.exists() or receipt_path.is_symlink():
                    raise ApplicationError("application_recovery_missing")
                if "sha256:" + hashlib.sha256(state_raw).hexdigest() != manifest["bindings"].get("supervisor_sha256"):
                    raise ApplicationError("supervisor_binding_drift")
                state = SUPERVISOR.migrate_runtime_state(SUPERVISOR._load_state(state_path))
                log_before = SUPERVISOR.verify_event_log(event_log_path)
                if (
                    state.get("event_sequence") != log_before["event_count"]
                    or state.get("last_event_hash") != log_before["last_event_hash"]
                    or state.get("last_event_id") != log_before["last_event_id"]
                ):
                    raise ApplicationError("runtime_state_event_log_mismatch")
                lane_id = bundle["binding"]["supervisor_lane_id"]
                lane = state.get("lanes", {}).get(lane_id)
                if (
                    not isinstance(lane, dict)
                    or lane.get("assignment_id") != manifest["identity"]["assignment_id"]
                    or lane.get("task_id") != manifest["identity"]["task_id"]
                    or lane.get("expected_artifact") != bundle["binding"]["expected_artifact"]
                ):
                    raise ApplicationError("supervisor_assignment_binding_mismatch")
                records, states = _prepare_supervisor_recovery(
                    state=state, board=board, bundle=bundle, root=root,
                )
                recovery = _write_recovery(
                    recovery_path, root,
                    _new_recovery(
                        application_id=application_id, started_at=now, bindings=bindings,
                        log=log_before, records=records, states=states,
                    ),
                    create=True,
                )

            expected_records = recovery["supervisor"]["expected_records"]
            supervisor_summary = {
                "event_ids": [record["event_id"] for record in expected_records],
                "sequence_before": recovery["supervisor"]["sequence_before"],
                "sequence_after": expected_records[-1]["sequence"],
                "head_after": expected_records[-1]["event_hash"],
            }
            if (
                (receipt_path.exists() or receipt_path.is_symlink())
                and recovery["stages"].get("supervisor_event_count") != len(bundle["events"])
            ):
                raise ApplicationError("receipt_conflict", "supervisor stage incomplete")
            if not receipt_path.exists() and not receipt_path.is_symlink():
                recovery, supervisor_summary = _apply_supervisor_locked(
                    recovery_path=recovery_path, recovery=recovery, root=root,
                    goal_path=goal_path, board_path=board_path, state_path=state_path,
                    event_log_path=event_log_path, receipt_path=receipt_path, bundle=bundle,
                )
            recovery, ledger_summary = _finalize_ledger_locked(
                recovery_path=recovery_path, recovery=recovery, ledger_path=ledger_path,
                grant=grant, manifest=manifest, returned=returned, quality=quality,
                supervisor_summary=supervisor_summary, root=root,
            )
            result = {
                "schema_version": 1,
                "artifact_type": "DispatchApplicationReceipt",
                "schedule_manifest": {
                    "path": manifest_relative,
                    "sha256": "sha256:" + hashlib.sha256(manifest_raw).hexdigest(),
                    "manifest_sha256": manifest["manifest_sha256"],
                },
                "identity": copy.deepcopy(manifest["identity"]),
                "lease": {
                    "lease_id": manifest["lease"]["lease_id"],
                    "fencing_token": manifest["lease"]["fencing_token"],
                    "released": True,
                },
                "quality_receipt_sha256": quality["receipt_sha256"],
                "dispatch_ledger": ledger_summary,
                "supervisor": supervisor_summary,
                "transport_succeeded": True,
                "quality_accepted": True,
                "supervisor_applied": True,
                "goalbuddy_applied": False,
                "accepted": False,
                "acceptance_authority": "Parent Codex",
            }
            result["receipt_sha256"] = digest(result, prefixed=True)
            if receipt_path.exists() or receipt_path.is_symlink():
                if _read_application_receipt(receipt_path, root) != result:
                    raise ApplicationError("receipt_conflict", "content")
            else:
                _atomic_create_json(receipt_path, root, result)
            recovery = _update_recovery_stage(
                recovery_path, root, recovery, status="receipted", receipt_created=True,
            )
            return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--goal", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--now", required=True)
    args = parser.parse_args(argv)
    try:
        result = apply_scheduled_dispatch(
            manifest_path=args.manifest,
            envelope=_read_json(args.envelope, "envelope"),
            repo_root=args.repo_root,
            ledger_path=args.ledger,
            goal_path=args.goal,
            board_path=args.board,
            state_path=args.state,
            event_log_path=args.events,
            receipt_path=args.receipt,
            now=args.now,
        )
    except (
        ApplicationError, LEDGER.LedgerError, SCHEDULER.ScheduleError,
        SUPERVISOR.LoopError, OSError, ValueError,
    ) as exc:
        code = getattr(exc, "code", "application_error")
        detail = getattr(exc, "detail", str(exc))
        print(json.dumps({"status": "rejected", "code": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
