#!/usr/bin/env python3
"""Apply one compiled role-lifecycle packet without mutating GoalBuddy."""

from __future__ import annotations

import argparse
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True


def _load(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


APPLICATION = _load("codexmax_application_for_role_lifecycle", "apply_scheduled_dispatch.py")
LIFECYCLE = _load("codexmax_lifecycle_compile_for_application", "compile_role_lifecycle.py")
SUPERVISOR = APPLICATION.SUPERVISOR
LEDGER = APPLICATION.LEDGER


class LifecycleApplicationError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _read_packet(path: Path, root: Path) -> tuple[dict[str, Any], str, bytes]:
    relative = APPLICATION._relative_path(root, path, "lifecycle_packet")
    _, raw = APPLICATION._inside_regular(root, relative, "lifecycle_packet")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleApplicationError("lifecycle_packet_unreadable") from exc
    try:
        return LIFECYCLE.validate_packet(value), relative, raw
    except LIFECYCLE.LifecycleCompileError as exc:
        raise LifecycleApplicationError(exc.code, exc.detail) from exc


def _verify_descriptor(root: Path, descriptor: Any, field: str) -> bytes:
    if descriptor is None:
        raise LifecycleApplicationError("descriptor_missing", field)
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "path", "sha256", "size_bytes", "artifact_kind",
    }:
        raise LifecycleApplicationError("descriptor_invalid", field)
    _, raw = APPLICATION._inside_regular(root, descriptor["path"], field)
    if (
        descriptor["sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest()
        or descriptor["size_bytes"] != len(raw)
    ):
        raise LifecycleApplicationError("descriptor_mismatch", field)
    return raw


def _json_descriptor(root: Path, descriptor: Any, field: str) -> dict[str, Any]:
    raw = _verify_descriptor(root, descriptor, field)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleApplicationError("descriptor_json_invalid", field) from exc
    if not isinstance(value, dict):
        raise LifecycleApplicationError("descriptor_json_invalid", field)
    return value


def _verify_packet_files(packet: dict[str, Any], root: Path) -> None:
    inputs = packet.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "schedule_manifest", "task_envelope", "assignment",
        "trusted_command_receipt", "closeout_artifact",
    }:
        raise LifecycleApplicationError("lifecycle_packet_invalid", "inputs")
    for name, descriptor in inputs.items():
        if descriptor is not None:
            _verify_descriptor(root, descriptor, f"inputs.{name}")
    sources = packet.get("source_artifacts")
    if not isinstance(sources, list):
        raise LifecycleApplicationError("lifecycle_packet_invalid", "source_artifacts")
    for index, descriptor in enumerate(sources):
        _verify_descriptor(root, descriptor, f"source_artifacts[{index}]")


def _recompile(
    packet: dict[str, Any], *, root: Path, goal_path: Path, board_path: Path,
    state_path: Path, event_log_path: Path, workspace_config: Path | None,
) -> dict[str, Any]:
    inputs = packet["inputs"]
    common = {
        "target_lane_id": packet["target"]["lane_id"],
        "root": root,
        "goal_path": goal_path,
        "board_path": board_path,
        "state_path": state_path,
        "event_log_path": event_log_path,
        "created_at": packet["created_at"],
    }
    stage = packet["stage"]
    if stage in LIFECYCLE.STAGE_TO_ROLE:
        trusted = inputs["trusted_command_receipt"]
        return LIFECYCLE.compile_scheduled(
            stage=stage,
            manifest_path=root / inputs["schedule_manifest"]["path"],
            envelope_path=root / inputs["task_envelope"]["path"],
            assignment_path=root / inputs["assignment"]["path"],
            trusted_command_receipt_path=(root / trusted["path"] if trusted else None),
            workspace_config=workspace_config,
            **common,
        )
    if stage == "worker_self_test":
        return LIFECYCLE.compile_self_test(
            trusted_command_receipt_path=root / inputs["trusted_command_receipt"]["path"],
            **common,
        )
    if stage == "candidate_closeout":
        decision = packet["events"][0]["payload"]["requested_parent_decision"]
        return LIFECYCLE.compile_closeout(
            closeout_artifact_path=root / inputs["closeout_artifact"]["path"],
            requested_parent_decision=decision,
            **common,
        )
    raise LifecycleApplicationError("stage_invalid", str(stage))


def _scheduled_material(
    packet: dict[str, Any], root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    inputs = packet["inputs"]
    manifest_input = _json_descriptor(root, inputs["schedule_manifest"], "schedule_manifest")
    envelope = _json_descriptor(root, inputs["task_envelope"], "task_envelope")
    manifest = APPLICATION._verify_manifest(manifest_input, envelope)
    returned, quality, bundle = APPLICATION._verify_result(
        root, manifest, envelope, allow_role_reference=True,
    )
    if (
        packet.get("dispatch_identity") != manifest["identity"]
        or envelope.get("semantic_role") != packet["stage"]
        or bundle.get("semantic_role") != packet["stage"]
    ):
        raise LifecycleApplicationError("scheduled_packet_binding_mismatch")
    return manifest, envelope, returned, quality


def _recovery_bindings(
    *, root: Path, packet_relative: str, packet_raw: bytes,
    packet: dict[str, Any], goal_path: Path, board_path: Path,
    state_path: Path, event_log_path: Path, receipt_path: Path,
) -> dict[str, Any]:
    return {
        "packet_path": packet_relative,
        "packet_file_sha256": "sha256:" + hashlib.sha256(packet_raw).hexdigest(),
        "packet_sha256": packet["packet_sha256"],
        "stage": packet["stage"],
        "target_lane_id": packet["target"]["lane_id"],
        "target_assignment_id": packet["target"]["assignment_id"],
        "goal_path": APPLICATION._relative_path(root, goal_path, "goal"),
        "board_path": APPLICATION._relative_path(root, board_path, "board"),
        "state_path": APPLICATION._relative_path(root, state_path, "state"),
        "event_log_path": APPLICATION._relative_path(root, event_log_path, "events"),
        "receipt_path": APPLICATION._relative_path(root, receipt_path, "receipt", must_exist=False),
        "goal_sha256": packet["bindings"]["goal_sha256"],
        "board_sha256": packet["bindings"]["board_sha256"],
    }


def _new_recovery_or_resume(
    *, recovery_path: Path, root: Path, application_id: str,
    bindings: dict[str, Any], packet: dict[str, Any], board: dict[str, Any],
    state: dict[str, Any], log: dict[str, Any], now: str,
) -> dict[str, Any]:
    bundle = {"events": packet["events"]}
    if recovery_path.exists() or recovery_path.is_symlink():
        return APPLICATION._validate_recovery(
            APPLICATION._read_recovery(recovery_path, root),
            application_id=application_id, bindings=bindings,
            board=board, bundle=bundle, root=root,
        )
    records, states = APPLICATION._prepare_supervisor_recovery(
        state=state, board=board, bundle=bundle, root=root,
    )
    return APPLICATION._write_recovery(
        recovery_path, root,
        APPLICATION._new_recovery(
            application_id=application_id, started_at=now, bindings=bindings,
            log=log, records=records, states=states,
        ),
        create=True,
    )


def _receipt_result(
    *, packet: dict[str, Any], packet_relative: str, packet_raw: bytes,
    recovery: dict[str, Any], supervisor_summary: dict[str, Any],
    ledger_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    result = {
        "schema_version": 1,
        "artifact_type": "RoleLifecycleApplicationReceipt",
        "lifecycle_packet": {
            "path": packet_relative,
            "sha256": "sha256:" + hashlib.sha256(packet_raw).hexdigest(),
            "packet_sha256": packet["packet_sha256"],
        },
        "stage": packet["stage"],
        "target": copy.deepcopy(packet["target"]),
        "dispatch_identity": copy.deepcopy(packet["dispatch_identity"]),
        "supervisor": supervisor_summary,
        "dispatch_ledger": ledger_summary,
        "started_at": recovery["started_at"],
        "supervisor_applied": True,
        "goalbuddy_applied": False,
        "accepted": False,
        "acceptance_authority": "Parent Codex",
    }
    result["receipt_sha256"] = APPLICATION.digest(result, prefixed=True)
    return result


def apply_role_lifecycle(
    *, packet_path: Path, root: Path, goal_path: Path, board_path: Path,
    state_path: Path, event_log_path: Path, receipt_path: Path, now: str,
    ledger_path: Path | None = None, workspace_config: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    packet, packet_relative, packet_raw = _read_packet(packet_path, root)
    _verify_packet_files(packet, root)
    scheduled = packet["stage"] in LIFECYCLE.STAGE_TO_ROLE
    if scheduled != (ledger_path is not None):
        raise LifecycleApplicationError("ledger_argument_mismatch")
    recovery_path = receipt_path.with_name(receipt_path.name + ".recovery.json")
    APPLICATION._relative_path(root, recovery_path, "recovery", must_exist=False)
    recovery_preexists_at_entry = recovery_path.exists() or recovery_path.is_symlink()
    prelock_recompile_error: LifecycleApplicationError | None = None
    if not recovery_preexists_at_entry:
        try:
            rebuilt = _recompile(
                packet, root=root, goal_path=goal_path, board_path=board_path,
                state_path=state_path, event_log_path=event_log_path,
                workspace_config=workspace_config,
            )
        except LIFECYCLE.LifecycleCompileError as exc:
            prelock_recompile_error = LifecycleApplicationError(exc.code, exc.detail)
        else:
            if rebuilt != packet:
                prelock_recompile_error = LifecycleApplicationError("lifecycle_packet_stale")
    manifest = envelope = returned = quality = None
    if scheduled:
        manifest, envelope, returned, quality = _scheduled_material(packet, root)
    for field, path in (
        ("goal", goal_path), ("board", board_path),
        ("supervisor_state", state_path), ("supervisor_events", event_log_path),
    ):
        relative = APPLICATION._relative_path(root, path, field)
        APPLICATION._inside_regular(root, relative, field)
    bindings = _recovery_bindings(
        root=root, packet_relative=packet_relative, packet_raw=packet_raw,
        packet=packet, goal_path=goal_path, board_path=board_path,
        state_path=state_path, event_log_path=event_log_path,
        receipt_path=receipt_path,
    )
    application_id = APPLICATION.digest([
        packet["packet_sha256"],
        manifest["lease"]["lease_id"] if manifest is not None else "control",
        manifest["lease"]["fencing_token"] if manifest is not None else packet["target"]["assignment_id"],
    ], prefixed=True)
    with contextlib.ExitStack() as stack:
        if scheduled:
            scheduler_lock = stack.enter_context(APPLICATION._open_scheduler_lock(ledger_path, root))
            fcntl.flock(scheduler_lock.fileno(), fcntl.LOCK_EX)
        supervisor_lock = stack.enter_context(SUPERVISOR.open_supervisor_lock(state_path, root))
        fcntl.flock(supervisor_lock.fileno(), fcntl.LOCK_EX)
        recovery_preexists = recovery_path.exists() or recovery_path.is_symlink()
        if not recovery_preexists and prelock_recompile_error is not None:
            raise prelock_recompile_error
        grant = None
        if scheduled:
            _, grant = APPLICATION._verify_ledger(manifest, ledger_path)
        board = SUPERVISOR.inspect_goalbuddy(goal_path, board_path)
        if (
            board["board_sha256"] != packet["bindings"]["board_sha256"]
            or board["goal_sha256"] != packet["bindings"]["goal_sha256"]
        ):
            raise LifecycleApplicationError("board_or_goal_drift")
        state = SUPERVISOR.migrate_runtime_state(SUPERVISOR._load_state(state_path))
        log = SUPERVISOR.verify_event_log(event_log_path)
        if not recovery_preexists:
            state_relative = APPLICATION._relative_path(root, state_path, "supervisor_state")
            _, state_raw = APPLICATION._inside_regular(root, state_relative, "supervisor_state")
            if (
                "sha256:" + hashlib.sha256(state_raw).hexdigest() != packet["bindings"]["supervisor_state_sha256"]
                or state.get("event_sequence") != packet["bindings"]["supervisor_event_sequence"]
                or state.get("last_event_hash") != packet["bindings"]["supervisor_event_hash"]
            ):
                raise LifecycleApplicationError("lifecycle_packet_stale")
        recovery = _new_recovery_or_resume(
            recovery_path=recovery_path, root=root, application_id=application_id,
            bindings=bindings, packet=packet, board=board, state=state,
            log=log, now=now,
        )
        bundle = {"events": packet["events"]}
        expected_count = len(packet["events"])
        if (
            (receipt_path.exists() or receipt_path.is_symlink())
            and recovery["stages"].get("supervisor_event_count") != expected_count
        ):
            raise LifecycleApplicationError("receipt_conflict", "supervisor stage incomplete")
        expected_records = recovery["supervisor"]["expected_records"]
        supervisor_summary = {
            "event_ids": [row["event_id"] for row in expected_records],
            "sequence_before": recovery["supervisor"]["sequence_before"],
            "sequence_after": expected_records[-1]["sequence"],
            "head_after": expected_records[-1]["event_hash"],
        }
        if not receipt_path.exists() and not receipt_path.is_symlink():
            recovery, supervisor_summary = APPLICATION._apply_supervisor_locked(
                recovery_path=recovery_path, recovery=recovery, root=root,
                goal_path=goal_path, board_path=board_path, state_path=state_path,
                event_log_path=event_log_path, receipt_path=receipt_path,
                bundle=bundle,
            )
        ledger_summary = None
        if scheduled:
            recovery, ledger_summary = APPLICATION._finalize_ledger_locked(
                recovery_path=recovery_path, recovery=recovery,
                ledger_path=ledger_path, grant=grant, manifest=manifest,
                returned=returned, quality=quality,
                supervisor_summary=supervisor_summary, root=root,
            )
        result = _receipt_result(
            packet=packet, packet_relative=packet_relative, packet_raw=packet_raw,
            recovery=recovery, supervisor_summary=supervisor_summary,
            ledger_summary=ledger_summary,
        )
        if receipt_path.exists() or receipt_path.is_symlink():
            if APPLICATION._read_application_receipt(receipt_path, root) != result:
                raise LifecycleApplicationError("receipt_conflict", "content")
        else:
            APPLICATION._atomic_create_json(receipt_path, root, result)
        APPLICATION._update_recovery_stage(
            recovery_path, root, recovery, status="receipted", receipt_created=True,
        )
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--goal", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--workspace-config", type=Path)
    parser.add_argument("--now", required=True)
    args = parser.parse_args(argv)
    try:
        result = apply_role_lifecycle(
            packet_path=args.packet, root=args.repo_root,
            goal_path=args.goal, board_path=args.board,
            state_path=args.state, event_log_path=args.events,
            receipt_path=args.receipt, ledger_path=args.ledger,
            workspace_config=args.workspace_config, now=args.now,
        )
    except (
        LifecycleApplicationError, LIFECYCLE.LifecycleCompileError,
        APPLICATION.ApplicationError, SUPERVISOR.LoopError,
        LEDGER.LedgerError, OSError, ValueError,
    ) as exc:
        print(json.dumps({
            "status": "rejected",
            "code": getattr(exc, "code", "lifecycle_application_error"),
            "detail": getattr(exc, "detail", str(exc)),
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
