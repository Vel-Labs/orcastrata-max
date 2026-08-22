#!/usr/bin/env python3
"""Finalize preserved visible-provider evidence without executing a provider."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

sys.dont_write_bytecode = True

MAX_JSON_BYTES = 64 * 1024 * 1024


def _load_sibling(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(f"codexmax_finalize_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCHEDULER = _load_sibling("schedule_headless_dispatch")
RECONCILER = _load_sibling("reconcile_visible_provider_result")
QUALITY = _load_sibling("validate_dispatch_artifact")


class FinalizationError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _repo_path(root: Path, path: Path, field: str, *, must_exist: bool) -> Path:
    root = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root / path
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_parent.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise FinalizationError("path_outside_repository", field) from exc
    resolved = resolved_parent / candidate.name
    if must_exist:
        try:
            actual = resolved.resolve(strict=True)
            actual.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise FinalizationError("input_unreadable", field) from exc
        return actual
    return resolved


def _read_bytes(root: Path, path: Path, field: str, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[Path, bytes]:
    named = _repo_path(root, path, field, must_exist=True)
    try:
        metadata = named.lstat()
    except OSError as exc:
        raise FinalizationError("input_unreadable", field) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise FinalizationError("input_unsafe", field)
    if metadata.st_size > max_bytes:
        raise FinalizationError("input_oversized", field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(named, flags)
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise FinalizationError("input_oversized", field)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FinalizationError("input_unreadable", field) from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
        raise FinalizationError("input_changed", field)
    return named, b"".join(chunks)


def _read_json(root: Path, path: Path, field: str) -> tuple[Path, bytes, dict[str, Any]]:
    named, raw = _read_bytes(root, path, field)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FinalizationError("input_json_invalid", field) from exc
    if not isinstance(value, dict):
        raise FinalizationError("input_shape_invalid", field)
    return named, raw, value


def _relative(root: Path, path: Path) -> str:
    return path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()


def _descriptor(root: Path, path: Path, raw: bytes, kind: str) -> dict[str, Any]:
    return {
        "path": _relative(root, path),
        "sha256": "sha256:" + _sha(raw),
        "size_bytes": len(raw),
        "artifact_kind": kind,
    }


def _expect_equal(actual: Any, expected: Any, code: str, detail: str) -> None:
    if canonical_json(actual) != canonical_json(expected):
        raise FinalizationError(code, detail)


def _validate_inputs(
    *, root: Path, task_state: dict[str, Any], admission: dict[str, Any],
    envelope: dict[str, Any], assignment: dict[str, Any], binding: dict[str, Any],
    ledger_path: Path, returned: dict[str, Any], bundle: dict[str, Any],
    artifact_path: Path, artifact_raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        state = RECONCILER._validate_state(task_state)
    except Exception as exc:
        raise FinalizationError("task_state_invalid", str(exc)) from exc
    if (
        admission.get("schema_version") != 1
        or admission.get("artifact_type") != "DispatchSchedulePlan"
        or admission.get("status") != "admitted"
    ):
        raise FinalizationError("admission_invalid")
    plan_fields = {
        "schema_version", "artifact_type", "created_at", "envelope_sha256", "identity",
        "bindings", "ledger_head_before", "binding_sources", "ledger_sequence_before",
        "eligible_routes", "rejected_routes", "selected_route", "provider_call_started",
    }
    if SCHEDULER.digest({key: copy.deepcopy(admission[key]) for key in plan_fields}) != admission.get("plan_sha256"):
        raise FinalizationError("admission_plan_digest_mismatch")
    if SCHEDULER.digest(envelope) != admission.get("envelope_sha256"):
        raise FinalizationError("envelope_digest_mismatch")
    core_identity = {
        "goal_id": envelope.get("goal_id"), "checkpoint_id": envelope.get("checkpoint_id"),
        "task_id": envelope.get("task_id"), "assignment_id": envelope.get("assignment_id"),
    }
    _expect_equal(admission.get("identity"), core_identity, "identity_mismatch", "admission/envelope")
    visible_identity = state["assignment_identity"]
    _expect_equal(
        {key: visible_identity[key] for key in ("goal_id", "task_id", "assignment_id", "semantic_role")},
        {
            "goal_id": envelope.get("goal_id"), "task_id": envelope.get("task_id"),
            "assignment_id": envelope.get("assignment_id"), "semantic_role": envelope.get("semantic_role"),
        },
        "identity_mismatch", "task_state/envelope",
    )
    _expect_equal(
        {
            "dispatch_id": assignment.get("dispatch_id"),
            "assignment_id": assignment.get("supervisor_assignment_id"),
            "semantic_role": assignment.get("semantic_role"),
        },
        {
            "dispatch_id": visible_identity["dispatch_id"],
            "assignment_id": visible_identity["assignment_id"],
            "semantic_role": visible_identity["semantic_role"],
        },
        "identity_mismatch", "assignment/task_state",
    )
    if assignment.get("route_packet", {}).get("task_id") != visible_identity["task_id"]:
        raise FinalizationError("identity_mismatch", "assignment.task_id")
    selected = admission.get("selected_route")
    external = state["external_execution"]
    route_map = {
        "name": "route_name", "provider": "provider", "exact_model": "exact_model",
        "route_id": "route_id", "runtime": "runtime", "reasoning": "reasoning",
    }
    if not isinstance(selected, dict) or any(selected.get(key) != external[target] for key, target in route_map.items()):
        raise FinalizationError("route_identity_mismatch")
    route_packet = assignment.get("route_packet")
    admitted_packet = selected.get("resolver_packet") if isinstance(selected, dict) else None
    admitted_assignment_projection = (
        {key: copy.deepcopy(value) for key, value in admitted_packet.items() if key not in {"registry", "profile"}}
        if isinstance(admitted_packet, dict) else None
    )
    if (
        not isinstance(route_packet, dict)
        or canonical_json(route_packet) != canonical_json(admitted_assignment_projection)
        or SCHEDULER.digest(admitted_packet) != selected.get("resolver_packet_sha256")
    ):
        raise FinalizationError("route_packet_mismatch")
    route_preflight = route_packet.get("preflights", {}).get(selected.get("name"))
    if not isinstance(route_preflight, dict):
        raise FinalizationError("preflight_binding_mismatch")
    expected_binding = {
        "task_id": envelope.get("task_id"),
        "assignment_id": envelope.get("assignment_id"),
        "route_name": selected.get("name"),
        "envelope_sha256": admission.get("envelope_sha256"),
        "lease_id": admission.get("lease", {}).get("lease_id"),
        "fencing_token": admission.get("lease", {}).get("fencing_token"),
    }
    _expect_equal(
        {
            "task_id": binding.get("task_id"), "assignment_id": binding.get("assignment_id"),
            "route_name": binding.get("route_name"), "envelope_sha256": binding.get("envelope_sha256"),
            "lease_id": binding.get("lease_id"), "fencing_token": binding.get("fencing_token"),
        },
        expected_binding,
        "execution_binding_mismatch", "identity",
    )
    for field, expected in {
        "preflight_sha256": SCHEDULER.digest(route_preflight),
        "authority_sha256": SCHEDULER.digest(assignment.get("authority")),
        "evidence_directory": assignment.get("evidence_directory"),
        "expires_at": admission.get("lease", {}).get("expires_at"),
        "execution_mode": "single_resolved_attempt",
    }.items():
        if binding.get(field) != expected:
            raise FinalizationError("execution_binding_mismatch", field)
    verified = SCHEDULER.LEDGER.verify_ledger(ledger_path)
    sequence = admission.get("ledger_sequence_after")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1 or sequence > verified["event_count"]:
        raise FinalizationError("ledger_binding_mismatch", "sequence")
    row = verified["rows"][sequence - 1]
    if (
        row.get("event_type") != "lease_granted"
        or row.get("event_hash") != admission.get("ledger_head_after")
        or row.get("envelope_sha256") != admission.get("envelope_sha256")
        or row.get("lease") != admission.get("lease")
        or any(row.get(key) != core_identity[key] for key in core_identity)
    ):
        raise FinalizationError("ledger_binding_mismatch", "lease row")
    try:
        validated_return = RECONCILER._validate_return(returned, state)
    except Exception as exc:
        raise FinalizationError("return_manifest_invalid", str(exc)) from exc
    if returned.get("semantic_role") != visible_identity["semantic_role"]:
        raise FinalizationError("return_identity_mismatch", "semantic_role")
    if returned.get("proof_mode") != "live" or assignment.get("proof_mode") != "live":
        raise FinalizationError("return_identity_mismatch", "live proof mode required")
    if returned.get("effective_config_sha256") != binding.get("effective_config_sha256"):
        raise FinalizationError("execution_binding_mismatch", "effective_config_sha256")
    resolution = returned.get("route_resolution")
    if (
        not isinstance(resolution, dict)
        or resolution.get("failover_used") is not False
        or resolution.get("selected_route") != selected.get("name")
    ):
        raise FinalizationError("retry_or_fallback_forbidden", "route_resolution")
    artifact = returned.get("artifact")
    expected_artifact = {
        "path": _relative(root, artifact_path), "bytes": len(artifact_raw),
        "sha256": "sha256:" + _sha(artifact_raw),
    }
    _expect_equal(artifact, expected_artifact, "artifact_descriptor_mismatch", "return/artifact bytes")
    if assignment.get("expected_artifact") != expected_artifact["path"]:
        raise FinalizationError("artifact_descriptor_mismatch", "assignment.expected_artifact")
    if (
        bundle.get("schema_version") != 1
        or bundle.get("bundle_type") != "SupervisorEventBundle"
        or bundle.get("dispatch_id") != visible_identity["dispatch_id"]
        or bundle.get("semantic_role") != visible_identity["semantic_role"]
        or bundle.get("applied_to_supervisor") is not False
        or bundle.get("applied_to_goalbuddy") is not False
    ):
        raise FinalizationError("supervisor_event_bundle_invalid")
    _expect_equal(
        bundle.get("binding", {}).get("supervisor_assignment_id"),
        visible_identity["assignment_id"], "supervisor_event_bundle_invalid", "assignment_id",
    )
    if bundle.get("binding", {}).get("expected_artifact_sha256") != expected_artifact["sha256"]:
        raise FinalizationError("supervisor_event_bundle_invalid", "artifact digest")
    route_events = [
        event for event in bundle.get("events", [])
        if isinstance(event, dict) and event.get("event_type") == "route_resolved"
    ]
    bundle_packet = (
        route_events[0].get("payload", {}).get("route_packet")
        if len(route_events) == 1 else None
    )
    if (
        not isinstance(bundle_packet, dict)
        or bundle.get("binding", {}).get("route_packet_sha256") != SCHEDULER.digest(bundle_packet)
    ):
        raise FinalizationError("supervisor_event_bundle_invalid", "route packet digest")
    bundle_admission_projection = copy.deepcopy(bundle_packet)
    attempt_results = bundle_admission_projection.get("attempt_results")
    bundle_admission_projection["attempt_results"] = {}
    if canonical_json(bundle_admission_projection) != canonical_json(admitted_packet):
        raise FinalizationError("supervisor_event_bundle_invalid", "route packet drift")
    if (
        not isinstance(attempt_results, dict)
        or set(attempt_results) != {selected.get("name")}
        or not isinstance(attempt_results[selected.get("name")], list)
        or len(attempt_results[selected.get("name")]) != 1
    ):
        raise FinalizationError("retry_or_fallback_forbidden", "event bundle attempt results")
    return state, validated_return


def _atomic_write_new(path: Path, raw: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FinalizationError("output_collision", str(path))
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def finalize_visible_provider_dispatch(
    *, repo_root: Path, task_state_path: Path, admission_path: Path,
    envelope_path: Path, assignment_path: Path, execution_binding_path: Path,
    ledger_path: Path, return_manifest_path: Path, supervisor_event_bundle_path: Path,
    provider_artifact_path: Path, quality_receipt_path: Path,
    schedule_manifest_path: Path, reconciliation_path: Path,
) -> dict[str, Any]:
    """Validate preserved bytes and emit three Sol-pending receipts, with no call seam."""
    root = repo_root.resolve(strict=True)
    inputs = [
        _read_json(root, task_state_path, "task_state"),
        _read_json(root, admission_path, "admission"),
        _read_json(root, envelope_path, "envelope"),
        _read_json(root, assignment_path, "assignment"),
        _read_json(root, execution_binding_path, "execution_binding"),
        _read_json(root, return_manifest_path, "return_manifest"),
        _read_json(root, supervisor_event_bundle_path, "supervisor_event_bundle"),
    ]
    (_, _, task_state), (_, _, admission), (_, _, envelope), (_, _, assignment), (_, _, binding), (return_path, return_raw, returned), (bundle_path, bundle_raw, bundle) = inputs
    artifact_path, artifact_raw = _read_bytes(root, provider_artifact_path, "provider_artifact")
    ledger = _repo_path(root, ledger_path, "ledger", must_exist=True)
    state, validated_return = _validate_inputs(
        root=root, task_state=task_state, admission=admission, envelope=envelope,
        assignment=assignment, binding=binding, ledger_path=ledger, returned=returned,
        bundle=bundle, artifact_path=artifact_path, artifact_raw=artifact_raw,
    )
    return_handoff = validated_return.get("supervisor_handoff")
    _expect_equal(
        return_handoff,
        {
            "path": _relative(root, bundle_path), "bytes": len(bundle_raw),
            "sha256": "sha256:" + _sha(bundle_raw),
        },
        "supervisor_event_descriptor_mismatch", "return/bundle bytes",
    )
    outputs = [
        _repo_path(root, quality_receipt_path, "quality_receipt", must_exist=False),
        _repo_path(root, schedule_manifest_path, "schedule_manifest", must_exist=False),
        _repo_path(root, reconciliation_path, "reconciliation", must_exist=False),
    ]
    input_paths = {item[0] for item in inputs} | {artifact_path, ledger}
    if len(set(outputs)) != 3 or any(path in input_paths for path in outputs):
        raise FinalizationError("output_path_invalid")
    existing = [path.exists() or path.is_symlink() for path in outputs]
    if any(existing) and not all(existing):
        raise FinalizationError("output_collision", "partial prior finalization")

    expected_descriptor = {
        "path": _relative(root, artifact_path), "sha256": _sha(artifact_raw),
        "size_bytes": len(artifact_raw),
    }
    quality_policy = envelope.get("quality_policy", {})
    quality = QUALITY.validate_artifact(
        artifact_path,
        policy_id=quality_policy.get("policy_id"),
        expected_descriptor={
            "path": str(artifact_path), "sha256": expected_descriptor["sha256"],
            "size_bytes": expected_descriptor["size_bytes"],
        },
        requirements={"required_headings": quality_policy.get("required_sections", [])},
        max_bytes=quality_policy.get("max_bytes", 1024 * 1024),
    )
    quality["artifact"] = copy.deepcopy(expected_descriptor)
    quality["expected_descriptor"] = copy.deepcopy(expected_descriptor)
    if expected_descriptor["size_bytes"] < quality_policy.get("min_bytes", 0):
        quality["findings"] = sorted(set([*quality.get("findings", []), "artifact_below_min_bytes"]))
        quality["accepted"] = False
    quality.pop("receipt_sha256", None)
    quality["receipt_sha256"] = _sha(canonical_json(quality))
    quality_raw = _json_bytes(quality)

    created: list[Path] = []
    try:
        if not all(existing):
            _atomic_write_new(outputs[0], quality_raw)
            created.append(outputs[0])
        else:
            _, current = _read_bytes(root, outputs[0], "quality_receipt")
            if current != quality_raw:
                raise FinalizationError("output_collision", "quality_receipt")
        schedule = SCHEDULER.schedule_manifest(
            admission=admission, repo_root=root, ledger_path=ledger,
            return_manifest=_descriptor(root, return_path, return_raw, "DispatchReturnManifest"),
            quality_receipt=_descriptor(root, outputs[0], quality_raw, "ArtifactQualityReceipt"),
            supervisor_event_bundle=_descriptor(root, bundle_path, bundle_raw, "SupervisorEventBundle"),
            visible_identity={
                "dispatch_id": state["assignment_identity"]["dispatch_id"],
                "semantic_role": state["assignment_identity"]["semantic_role"],
            },
        )
        expected_visible_identity = {
            "dispatch_id": state["assignment_identity"]["dispatch_id"],
            "semantic_role": state["assignment_identity"]["semantic_role"],
        }
        _expect_equal(schedule["identity"], admission["identity"], "schedule_identity_mismatch", "admission")
        _expect_equal(
            schedule.get("visible_identity"), expected_visible_identity,
            "schedule_identity_mismatch", "visible finalizer identity",
        )
        schedule_raw = _json_bytes(schedule)
        if not all(existing):
            _atomic_write_new(outputs[1], schedule_raw)
            created.append(outputs[1])
        else:
            _, current = _read_bytes(root, outputs[1], "schedule_manifest")
            if current != schedule_raw:
                raise FinalizationError("output_collision", "schedule_manifest")
        reconciliation = RECONCILER.reconcile_visible_provider_result(
            task_state, schedule, returned, quality
        )
        reconciliation["finalization"] = {
            "provider_call_performed_by_finalizer": False,
            "runner_imported": False,
            "runner_invoked": False,
            "input_descriptors_verified": True,
        }
        reconciliation.pop("reconciliation_sha256", None)
        reconciliation["reconciliation_sha256"] = RECONCILER.digest(reconciliation)
        reconciliation_raw = _json_bytes(reconciliation)
        if not all(existing):
            _atomic_write_new(outputs[2], reconciliation_raw)
            created.append(outputs[2])
        else:
            _, current = _read_bytes(root, outputs[2], "reconciliation")
            if current != reconciliation_raw:
                raise FinalizationError("output_collision", "reconciliation")
    except BaseException:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return {
        "schema_version": 1,
        "artifact_type": "VisibleProviderDispatchFinalization",
        "status": "already_finalized" if all(existing) else "finalized",
        "provider_call_performed": False,
        "runner_imported": False,
        "runner_invoked": False,
        "identity": copy.deepcopy(state["assignment_identity"]),
        "outputs": {
            "quality_receipt": _descriptor(root, outputs[0], quality_raw, "ArtifactQualityReceipt"),
            "schedule_manifest": _descriptor(root, outputs[1], schedule_raw, "DispatchScheduleManifest"),
            "reconciliation": _descriptor(root, outputs[2], reconciliation_raw, "VisibleProviderReconciliation"),
        },
        "accepted": False,
        "sol_decision": "pending",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-state", type=Path, required=True)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--execution-binding", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--return-manifest", type=Path, required=True)
    parser.add_argument("--supervisor-event-bundle", type=Path, required=True)
    parser.add_argument("--provider-artifact", type=Path, required=True)
    parser.add_argument("--quality-receipt", type=Path, required=True)
    parser.add_argument("--schedule-manifest", type=Path, required=True)
    parser.add_argument("--reconciliation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = finalize_visible_provider_dispatch(
            repo_root=args.repo_root, task_state_path=args.task_state,
            admission_path=args.admission, envelope_path=args.envelope,
            assignment_path=args.assignment, execution_binding_path=args.execution_binding,
            ledger_path=args.ledger, return_manifest_path=args.return_manifest,
            supervisor_event_bundle_path=args.supervisor_event_bundle,
            provider_artifact_path=args.provider_artifact,
            quality_receipt_path=args.quality_receipt,
            schedule_manifest_path=args.schedule_manifest,
            reconciliation_path=args.reconciliation,
        )
    except (FinalizationError, SCHEDULER.ScheduleError, RECONCILER.ReconciliationError, OSError) as exc:
        code = exc.code if hasattr(exc, "code") else type(exc).__name__
        detail = exc.detail if hasattr(exc, "detail") else str(exc)
        print(json.dumps({"status": "rejected", "code": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
