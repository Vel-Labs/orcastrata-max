#!/usr/bin/env python3
"""Run a Parent-owned, bounded provider fan-out plan.

The controller composes the existing scheduler, binding, run-one, and
finalization boundaries.  Tests inject a lane executor.  The default executor
is the only code path that can reach the one-attempt dispatcher.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Callable, Protocol

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
READ_CONCURRENCY_CAP = 2
RETRYABLE_PRESPAWN_CODES = {
    "lease_expired_before_spawn",
    "preflight_expired_before_spawn",
    "protected_capability_expired_before_spawn",
    "evidence_collision_before_claim",
}
TERMINAL_UNKNOWN_CODES = {
    "execution_unknown", "timeout", "disconnect", "partial_capture",
    "malformed_terminal_output", "receipt_failure",
}
ATTEMPT_STATUSES = {
    "failed_certain_pre_provider",
    "source_validated_non_promotable",
    "candidate_ready",
    "execution_unknown",
    "rejected",
}
AUTHORITY_FIELDS = {
    "capability_card_sha256", "grant_sha256", "preflight_sha256",
    "lease_id", "lease_sha256", "fencing_token", "fence_token_sha256",
    "execution_binding_sha256",
}


def _load_sibling(filename: str, alias: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FANOUT = _load_sibling("provider_fanout.py", "codexmax_run_fanout_plan")
SCHEDULER = _load_sibling("schedule_headless_dispatch.py", "codexmax_run_fanout_scheduler")
BINDER = _load_sibling("bind_scheduled_dispatch.py", "codexmax_run_fanout_binder")
RUNNER = _load_sibling("run_headless_provider_dispatch.py", "codexmax_run_fanout_runner")
FINALIZER = _load_sibling("finalize_visible_provider_dispatch.py", "codexmax_run_fanout_finalizer")


class ExecutionError(ValueError):
    """A fail-closed fan-out execution error."""

    def __init__(
        self, code: str, detail: str = "", *, provider_process_started: bool = False,
        external_call_performed: bool | str = False, mutation_started: bool = False,
        possible_mutation: bool = False, execution_unknown: bool = False,
    ):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.provider_process_started = provider_process_started
        self.external_call_performed = external_call_performed
        self.mutation_started = mutation_started
        self.possible_mutation = possible_mutation
        self.execution_unknown = execution_unknown


class LaneExecutor(Protocol):
    """One exact attempt.  Implementations must not retry or select a route."""

    def admit(self, lane: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]: ...
    def bind(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any]
    ) -> dict[str, Any]: ...
    def run_one(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any],
        binding: dict[str, Any],
    ) -> dict[str, Any]: ...
    def finalize(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any],
        binding: dict[str, Any], returned: dict[str, Any],
    ) -> dict[str, Any]: ...


class ComposedLaneExecutor:
    """Compose the accepted single-lane boundaries for runtime use.

    ``runtime_inputs`` is Parent-owned.  It contains one immutable input row per
    lane attempt.  This class never manufactures a route, grant, capability,
    preflight, lease, or fencing token.
    """

    def __init__(
        self, *, repo_root: Path, ledger_path: Path,
        runtime_inputs: dict[str, list[dict[str, Any]]],
        workspace_config: Path | None = None,
    ) -> None:
        self.repo_root = RUNNER._canonical_repo_root(repo_root)
        self.ledger_path = ledger_path
        self.runtime_inputs = runtime_inputs
        self.workspace_config = workspace_config

    def verify_worktree(self, lane: dict[str, Any], attempt_index: int) -> dict[str, Any]:
        relative = lane.get("worktree_path")
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ExecutionError("worktree_path_invalid", str(relative))
        worktree = self.repo_root / relative
        try:
            resolved = worktree.resolve(strict=True)
        except OSError as exc:
            raise ExecutionError("worktree_missing", lane["lane_id"]) from exc
        commands = (
            ["git", "-C", str(resolved), "rev-parse", "--show-toplevel"],
            ["git", "-C", str(resolved), "rev-parse", "HEAD"],
            ["git", "-C", str(resolved), "status", "--porcelain", "--untracked-files=all"],
        )
        results = []
        for command in commands:
            result = subprocess.run(command, text=True, capture_output=True, timeout=10, check=False)
            if result.returncode != 0:
                raise ExecutionError("worktree_verification_failed", lane["lane_id"])
            results.append(result.stdout.strip())
        top, head, dirty = results
        if Path(top).resolve() != resolved or dirty:
            raise ExecutionError("worktree_not_clean_or_bound", lane["lane_id"])
        identity = digest({"worktree_path": relative, "head": head})
        if identity != lane["worktree_identity_sha256"]:
            raise ExecutionError("worktree_identity_mismatch", lane["lane_id"])
        receipt = {
            "schema_version": 1,
            "artifact_type": "VerifiedFanoutWorktreeReceipt",
            "lane_id": lane["lane_id"],
            "attempt_index": attempt_index,
            "worktree_path": relative,
            "head": head,
            "worktree_identity_sha256": identity,
            "clean": True,
            "environment_clean": True,
            "verifier": "git_status_porcelain_v1",
        }
        receipt["receipt_sha256"] = digest(receipt)
        return receipt

    def _input(self, lane: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        try:
            value = self.runtime_inputs[lane["lane_id"]][attempt["attempt_index"] - 1]
        except (KeyError, IndexError, TypeError) as exc:
            raise ExecutionError("runtime_attempt_input_missing", attempt["attempt_id"]) from exc
        if not isinstance(value, dict):
            raise ExecutionError("runtime_attempt_input_invalid", attempt["attempt_id"])
        return value

    def _write_input(self, attempt: dict[str, Any], name: str, value: dict[str, Any]) -> Path:
        path = self.repo_root / attempt["evidence_directory"] / name
        _atomic_new_json(self.repo_root, path, value)
        return path

    def admit(self, lane: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        value = ComposedLaneExecutor._input(self, lane, attempt)
        authority = value.get("attempt_authority")
        if not isinstance(authority, dict) or set(authority) != {
            "capability_card_sha256", "grant_sha256"
        }:
            raise ExecutionError("attempt_authority_missing", attempt["attempt_id"])
        if authority != {
            "capability_card_sha256": lane["capability_card_sha256"],
            "grant_sha256": lane["grant_sha256"],
        }:
            raise ExecutionError("attempt_authority_mismatch", attempt["attempt_id"])
        candidates = copy.deepcopy(value.get("candidates"))
        if not isinstance(candidates, list) or len(candidates) != 1 or candidates[0].get("name") != lane["route_name"]:
            raise ExecutionError("exact_route_candidate_required", lane["lane_id"])
        kwargs = {
            key: copy.deepcopy(value[key]) for key in (
                "envelope", "bindings", "binding_sources", "policy", "lease_id",
                "workgraph_claim_token", "workgraph_fencing_token",
                "board_max_write_workers", "config_max_write_workers", "now",
            )
        }
        admission = SCHEDULER.admit(
            **kwargs, candidates=candidates, repo_root=self.repo_root,
            ledger_path=self.ledger_path,
        )
        ComposedLaneExecutor._write_input(self, attempt, "admission.json", admission)
        return admission

    def bind(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any]
    ) -> dict[str, Any]:
        value = ComposedLaneExecutor._input(self, lane, attempt)
        assignment = copy.deepcopy(value["assignment"])
        # The dispatcher evidence directory must be absent.  The controller's
        # attempt directory is its immutable authority-record root.
        assignment["evidence_directory"] = attempt["evidence_directory"] + "/run-one"
        envelope = copy.deepcopy(value["envelope"])
        binding = BINDER.bind_scheduled_dispatch(
            admission=admission, task_envelope=envelope, assignment=assignment,
            repo_root=self.repo_root, ledger_path=self.ledger_path,
            now=value["now"], workspace_config=self.workspace_config,
        )
        ComposedLaneExecutor._write_input(self, attempt, "assignment.json", assignment)
        ComposedLaneExecutor._write_input(self, attempt, "envelope.json", envelope)
        ComposedLaneExecutor._write_input(self, attempt, "execution-binding.json", binding)
        return binding

    def pre_spawn_check(
        self, lane: dict[str, Any], attempt: dict[str, Any],
        admission: dict[str, Any], binding: dict[str, Any],
    ) -> None:
        if (
            binding.get("route_name") != lane["route_name"]
            or binding.get("lease_id") != admission.get("lease", {}).get("lease_id")
            or binding.get("fencing_token") != admission.get("lease", {}).get("fencing_token")
        ):
            raise ExecutionError("execution_binding_mismatch", lane["lane_id"])

    def release_pre_spawn(
        self, lane: dict[str, Any], attempt: dict[str, Any],
        admission: dict[str, Any], binding: dict[str, Any],
    ) -> dict[str, Any]:
        lease = admission.get("lease", {})
        if not isinstance(lease.get("lease_id"), str) or type(lease.get("fencing_token")) is not int:
            raise ExecutionError("failed_attempt_lease_missing", attempt["attempt_id"])
        return SCHEDULER.release(
            ledger_path=self.ledger_path, lease_id=lease["lease_id"],
            fencing_token=lease["fencing_token"], now=RUNNER._utc_now(),
        )

    def run_one(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any],
        binding: dict[str, Any],
    ) -> dict[str, Any]:
        value = ComposedLaneExecutor._input(self, lane, attempt)
        assignment = copy.deepcopy(value["assignment"])
        assignment["evidence_directory"] = attempt["evidence_directory"] + "/run-one"
        strict_assignment = RUNNER._require_assignment(assignment, self.repo_root)
        effective = RUNNER._effective_config(self.repo_root, self.workspace_config)
        packet = RUNNER._prepare_packet(
            strict_assignment, effective, scheduler_mode=True,
            scheduler_route=binding["route_name"],
        )
        test_executables = RUNNER._test_executables(
            value.get("test_adapter_manifest"), self.repo_root, strict_assignment["proof_mode"]
        )
        return RUNNER.run_dispatch(
            strict_assignment, packet, self.repo_root, test_executables,
            effective=effective,
            allow_provider_call=value.get("allow_provider_call") is True,
            allow_simulated_process=value.get("allow_simulated_process") is True,
            timeout=float(value.get("timeout_seconds", RUNNER.DEFAULT_TIMEOUT_SECONDS)),
            stdout_limit=int(value.get("stdout_limit_bytes", RUNNER.DEFAULT_STDOUT_LIMIT)),
            stderr_limit=int(value.get("stderr_limit_bytes", RUNNER.DEFAULT_STDERR_LIMIT)),
            single_attempt_binding=binding,
            task_envelope=copy.deepcopy(value["envelope"]),
            execution_time=value["now"],
            execution_clock=RUNNER._utc_now,
        )

    def finalize(
        self, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any],
        binding: dict[str, Any], returned: dict[str, Any],
    ) -> dict[str, Any]:
        value = ComposedLaneExecutor._input(self, lane, attempt)
        run_root = self.repo_root / attempt["evidence_directory"] / "run-one"
        artifact = returned.get("artifact")
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise ExecutionError(
                "receipt_failure", "selected provider artifact is absent",
                provider_process_started=bool(returned.get("attempts")),
                external_call_performed=returned.get("external_call_performed", "unknown"),
                execution_unknown=True,
            )
        return FINALIZER.finalize_visible_provider_dispatch(
            repo_root=self.repo_root,
            task_state_path=Path(value["task_state_path"]),
            admission_path=Path(attempt["evidence_directory"]) / "admission.json",
            envelope_path=Path(attempt["evidence_directory"]) / "envelope.json",
            assignment_path=Path(attempt["evidence_directory"]) / "assignment.json",
            execution_binding_path=Path(attempt["evidence_directory"]) / "execution-binding.json",
            ledger_path=self.ledger_path,
            return_manifest_path=run_root.relative_to(self.repo_root) / "dispatch-return-manifest.json",
            supervisor_event_bundle_path=run_root.relative_to(self.repo_root) / "supervisor-event-bundle.json",
            provider_artifact_path=Path(artifact["path"]),
            quality_receipt_path=Path(attempt["evidence_directory"]) / "quality-receipt.json",
            schedule_manifest_path=Path(attempt["evidence_directory"]) / "schedule-manifest.json",
            reconciliation_path=Path(attempt["evidence_directory"]) / "reconciliation.json",
        )

    def validate_live_finalization(
        self, lane: dict[str, Any], attempt: dict[str, Any],
        returned: dict[str, Any], finalization: dict[str, Any],
    ) -> dict[str, Any]:
        if finalization.get("artifact_type") != "VisibleProviderDispatchFinalization":
            raise ExecutionError("finalization_artifact_invalid", lane["lane_id"])
        outputs = finalization.get("outputs")
        if not isinstance(outputs, dict) or set(outputs) != {
            "quality_receipt", "schedule_manifest", "reconciliation"
        }:
            raise ExecutionError("finalization_outputs_invalid", lane["lane_id"])
        value = ComposedLaneExecutor._input(self, lane, attempt)
        task_state = _read_verified_json_path(
            self.repo_root, Path(value["task_state_path"]), "task_state"
        )
        quality = _read_verified_output(self.repo_root, outputs["quality_receipt"], "quality_receipt")
        schedule = _read_verified_output(self.repo_root, outputs["schedule_manifest"], "schedule_manifest")
        stored = _read_verified_output(self.repo_root, outputs["reconciliation"], "reconciliation")
        try:
            recomputed = FANOUT.RECONCILER.reconcile_visible_provider_result(
                task_state, schedule, returned, quality
            )
        except Exception as exc:
            raise ExecutionError("reconciliation_recompute_failed", str(exc)) from exc
        stored_payload = copy.deepcopy(stored)
        supplied_digest = stored_payload.pop("reconciliation_sha256", None)
        if supplied_digest != FANOUT.RECONCILER.digest(stored_payload):
            raise ExecutionError("reconciliation_digest_mismatch", lane["lane_id"])
        stored_payload.pop("finalization", None)
        expected = copy.deepcopy(recomputed)
        expected.pop("reconciliation_sha256", None)
        if canonical_json(stored_payload) != canonical_json(expected):
            raise ExecutionError("reconciliation_mismatch", lane["lane_id"])
        if stored.get("status") != "candidate_ready_for_sol_review":
            raise ExecutionError("live_candidate_not_semantically_validated", lane["lane_id"])
        return stored


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _relative(root: Path, path: Path, field: str) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExecutionError("path_outside_artifact_root", field) from exc


def _safe_new_directory(root: Path, relative: str, field: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ExecutionError("invalid_path", field)
    root = root.resolve(strict=True)
    parts = Path(relative).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ExecutionError("artifact_unsafe", field) from exc
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise ExecutionError("artifact_unsafe", field)
            os.close(descriptor)
            descriptor = child
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=descriptor)
        except FileExistsError as exc:
            raise ExecutionError("evidence_collision_before_claim", relative) from exc
    finally:
        os.close(descriptor)
    target = root.joinpath(*parts)
    try:
        target.resolve(strict=True).relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExecutionError("path_outside_artifact_root", field) from exc
    return target


def _atomic_new_json(root: Path, path: Path, value: dict[str, Any]) -> dict[str, Any]:
    _relative(root, path, "output")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"path": _relative(root, path, "output"), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}


def _descriptor(root: Path, relative: str, expected_kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ExecutionError("invalid_descriptor", expected_kind)
    path = root.resolve() / relative
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExecutionError("artifact_missing", expected_kind) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExecutionError("artifact_unsafe", expected_kind)
    raw = resolved.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionError("artifact_invalid_json", expected_kind) from exc
    if not isinstance(value, dict) or value.get("artifact_type", value.get("manifest_type")) != expected_kind:
        raise ExecutionError("artifact_kind_mismatch", expected_kind)
    return {"path": relative, "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}, value


def _read_verified_json_path(root: Path, path: Path, field: str) -> dict[str, Any]:
    candidate = path if path.is_absolute() else root / path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
        info = candidate.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExecutionError("artifact_missing", field) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExecutionError("artifact_unsafe", field)
    try:
        value = json.loads(resolved.read_bytes())
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionError("artifact_invalid_json", field) from exc
    if not isinstance(value, dict):
        raise ExecutionError("artifact_invalid_json", field)
    return value


def _read_verified_output(root: Path, descriptor: Any, field: str) -> dict[str, Any]:
    if not isinstance(descriptor, dict) or not {"path", "sha256"}.issubset(descriptor):
        raise ExecutionError("invalid_descriptor", field)
    value = _read_verified_json_path(root, Path(descriptor["path"]), field)
    raw = (root.resolve() / descriptor["path"]).read_bytes()
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    expected = descriptor["sha256"]
    if isinstance(expected, str) and not expected.startswith("sha256:"):
        expected = "sha256:" + expected
    if actual != expected:
        raise ExecutionError("artifact_digest_mismatch", field)
    if "size_bytes" in descriptor and descriptor["size_bytes"] != len(raw):
        raise ExecutionError("artifact_size_mismatch", field)
    return value


def _execution_status(
    returned: dict[str, Any], finalized: dict[str, Any], *, source_local: bool
) -> str:
    if finalized.get("accepted") is not False or finalized.get("sol_decision") != "pending":
        raise ExecutionError("parent_boundary_violation", "finalizer")
    attempts = returned.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > 1:
        raise ExecutionError("run_one_contract_violation", "attempt count")
    if returned.get("accepted") is not False or returned.get("applied_to_goalbuddy") is not False:
        raise ExecutionError("parent_boundary_violation", "run-one")
    if source_local:
        if (
            returned.get("external_call_performed") is not False
            or returned.get("provider_network_performed", False) is not False
            or finalized.get("artifact_type") != "ProviderFanoutSourceLocalFinalization"
            or finalized.get("status") != "source_validated_non_promotable"
            or finalized.get("provider_call_performed") is not False
            or finalized.get("accepted_by_parent") is not False
            or finalized.get("board_mutation_performed") is not False
            or finalized.get("fold_performed") is not False
            or finalized.get("application_performed") is not False
        ):
            raise ExecutionError("source_local_boundary_violation")
        return "source_validated_non_promotable"
    if returned.get("status") == "selected" and len(attempts) == 1:
        return "candidate_ready"
    if attempts:
        last = attempts[-1]
        if (
            last.get("timed_out") is True
            or last.get("outcome") == "execution_unknown"
            or returned.get("external_call_performed") == "unknown"
        ):
            return "execution_unknown"
    return "rejected"


def _attempt_binding_record(
    *, lane: dict[str, Any], attempt: dict[str, Any], admission: dict[str, Any],
    binding: dict[str, Any], returned: dict[str, Any] | None,
    finalization: dict[str, Any] | None, status: str, started_at: str,
    completed_at: str, failure: dict[str, Any] | None,
) -> dict[str, Any]:
    selected = admission.get("selected_route", {})
    record = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ProviderFanoutExecutionAttemptRecord",
        "fanout_id": attempt["fanout_id"],
        "lane_id": lane["lane_id"],
        "attempt_id": attempt["attempt_id"],
        "attempt_index": attempt["attempt_index"],
        "route": {
            "name": selected.get("name"), "provider": selected.get("provider"),
            "model": selected.get("exact_model"), "fallback_allowed": False,
        },
        "authority": _authority_projection(attempt, admission, binding),
        "worktree": {
            "path": attempt["worktree_path"],
            "identity_sha256": attempt["worktree_identity_sha256"],
            "clean_before_attempt": attempt["clean_before_attempt"],
            "verification_boundary": attempt["worktree_verification_boundary"],
            "receipt_descriptor": attempt["worktree_receipt_descriptor"],
        },
        "evidence_directory": attempt["evidence_directory"],
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "run_one_started": attempt.get("run_one_started", returned is not None),
        "provider_process_started": attempt.get("provider_process_started", bool((returned or {}).get("attempts"))),
        "external_call_performed": attempt.get("external_call_performed", (returned or {}).get("external_call_performed", False)),
        "mutation_started": attempt.get("mutation_started", False),
        "possible_mutation": attempt.get("possible_mutation", False),
        "execution_unknown": status == "execution_unknown",
        "execution_boundary": attempt["execution_boundary"],
        "composed_executor_finalization_validated": attempt.get(
            "composed_executor_finalization_validated", False
        ),
        "failure": failure,
        "finalization": copy.deepcopy(finalization),
        "accepted_by_parent": False,
        "board_mutation_performed": False,
        "fold_performed": False,
        "application_performed": False,
    }
    record["record_sha256"] = digest(record)
    return record


def _authority_projection(
    attempt: dict[str, Any], admission: dict[str, Any], binding: dict[str, Any]
) -> dict[str, Any]:
    lease = admission.get("lease", {})
    return {
        "capability_card_sha256": attempt["capability_card_sha256"],
        "preflight_sha256": binding.get("preflight_sha256"),
        "lease_id": lease.get("lease_id"),
        "lease_sha256": digest(lease),
        "fencing_token": lease.get("fencing_token"),
        "fence_token_sha256": digest(lease.get("fencing_token")),
        "execution_binding_sha256": digest(binding),
        "grant_sha256": attempt["grant_sha256"],
    }


def validate_failure_receipt(
    value: dict[str, Any], lane: dict[str, Any], attempt_record: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("artifact_type") != "FanoutPreProviderFailureReceipt":
        raise ExecutionError("failure_receipt_invalid", lane["lane_id"])
    supplied = value.get("receipt_sha256")
    payload = {key: copy.deepcopy(item) for key, item in value.items() if key != "receipt_sha256"}
    if supplied != digest(payload):
        raise ExecutionError("failure_receipt_digest_mismatch", lane["lane_id"])
    if (
        value.get("fanout_id") != attempt_record["fanout_id"]
        or
        value.get("lane_id") != lane["lane_id"]
        or value.get("attempt_id") != attempt_record["attempt_id"]
        or value.get("attempt_index") != attempt_record["attempt_index"]
        or value.get("route") != attempt_record["route"]
        or value.get("authority") != attempt_record["authority"]
        or value.get("failure_class") not in RETRYABLE_PRESPAWN_CODES
        or value.get("claim_failed_before_binding", False)
        is not (value.get("failure_class") == "evidence_collision_before_claim")
        or value.get("run_one_started") is not False
        or value.get("provider_process_started") is not False
        or value.get("external_call_performed") is not False
        or value.get("mutation_started") is not False
        or value.get("possible_mutation") is not False
        or value.get("execution_unknown") is not False
        or value.get("receipt_finalized") is not True
    ):
        raise ExecutionError("failure_receipt_semantic_mismatch", lane["lane_id"])
    return value


def retry_decision(
    *, lane: dict[str, Any], prior_record: dict[str, Any],
    failure_descriptor: dict[str, Any], failure_receipt: dict[str, Any],
    successor_attempt: dict[str, Any], successor_admission: dict[str, Any],
    successor_binding: dict[str, Any],
) -> dict[str, Any]:
    validate_failure_receipt(failure_receipt, lane, prior_record)
    successor_authority = _authority_projection(
        successor_attempt, successor_admission, successor_binding
    )
    for field in (
        "preflight_sha256", "lease_id", "lease_sha256", "fencing_token", "fence_token_sha256",
        "execution_binding_sha256",
    ):
        if successor_authority.get(field) == prior_record["authority"].get(field):
            raise ExecutionError("fresh_attempt_binding_reused", field)
    if successor_attempt["evidence_directory"] == prior_record["evidence_directory"]:
        raise ExecutionError("fresh_attempt_binding_reused", "evidence_directory")
    value = {
        "schema_version": 1,
        "artifact_type": "ProviderFanoutRetryDecision",
        "lane_id": lane["lane_id"],
        "prior_attempt_id": prior_record["attempt_id"],
        "failure_receipt_descriptor": failure_descriptor,
        "retry_allowed": True,
        "successor": {
            "attempt_id": successor_attempt["attempt_id"],
            "attempt_index": successor_attempt["attempt_index"],
            "route": copy.deepcopy(prior_record["route"]),
            "authority": successor_authority,
            "evidence_directory": successor_attempt["evidence_directory"],
        },
    }
    value["decision_sha256"] = digest(value)
    return value


def _bound_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def validate_attempt_record(
    value: dict[str, Any], lane: dict[str, Any], prior: dict[str, Any] | None,
    *, fanout_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("artifact_type") != "ProviderFanoutExecutionAttemptRecord":
        raise ExecutionError("attempt_record_invalid")
    supplied = value.get("record_sha256")
    payload = {key: copy.deepcopy(item) for key, item in value.items() if key != "record_sha256"}
    if supplied != digest(payload):
        raise ExecutionError("attempt_record_digest_mismatch", str(value.get("attempt_id")))
    index = value.get("attempt_index")
    expected_index = 1 if prior is None else prior["attempt_index"] + 1
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("fanout_id") != fanout_id
        or value.get("lane_id") != lane["lane_id"]
        or type(index) is not int
        or index != expected_index
        or value.get("attempt_id") != f"{fanout_id}:{lane['lane_id']}:a{index}"
    ):
        raise ExecutionError("attempt_record_identity_mismatch", lane["lane_id"])
    if value.get("route") != {
        "name": lane["route_name"], "provider": lane["provider"],
        "model": lane["model"], "fallback_allowed": False,
    }:
        raise ExecutionError("attempt_record_route_mismatch", lane["lane_id"])
    status = value.get("status")
    if not isinstance(status, str) or status not in ATTEMPT_STATUSES:
        raise ExecutionError("attempt_record_status_invalid", lane["lane_id"])
    claim_failure = (
        status == "failed_certain_pre_provider"
        and isinstance(value.get("failure"), dict)
        and value["failure"].get("code") == "evidence_collision_before_claim"
    )
    authority = value.get("authority")
    if (
        not isinstance(authority, dict)
        or set(authority) != AUTHORITY_FIELDS
        or not all(_bound_digest(authority[field]) for field in AUTHORITY_FIELDS - {"lease_id", "fencing_token"})
        or not isinstance(authority["lease_id"], str)
        or not authority["lease_id"]
        or type(authority["fencing_token"]) is not int
    ):
        raise ExecutionError("attempt_record_authority_mismatch", lane["lane_id"])
    if (
        authority["capability_card_sha256"] != lane["capability_card_sha256"]
        or authority["grant_sha256"] != lane["grant_sha256"]
    ):
        raise ExecutionError("attempt_record_authority_mismatch", lane["lane_id"])
    if claim_failure:
        expected_binding = {
            "attempt_id": value["attempt_id"],
            "route_name": lane["route_name"],
            "preflight_sha256": digest([
                value["attempt_id"], "evidence-claim-unbound"
            ]),
        }
        expected_lease = {
            "lease_id": f"unbound:{value['attempt_id']}", "fencing_token": 0,
        }
        expected_claim_authority = {
            "capability_card_sha256": lane["capability_card_sha256"],
            "preflight_sha256": expected_binding["preflight_sha256"],
            "lease_id": expected_lease["lease_id"],
            "lease_sha256": digest(expected_lease),
            "fencing_token": 0, "fence_token_sha256": digest(0),
            "execution_binding_sha256": digest(expected_binding),
            "grant_sha256": lane["grant_sha256"],
        }
        if authority != expected_claim_authority:
            raise ExecutionError("attempt_record_authority_mismatch", lane["lane_id"])
    worktree = value.get("worktree")
    boundary = value.get("execution_boundary")
    if (
        not isinstance(worktree, dict)
        or set(worktree) != {
            "path", "identity_sha256", "clean_before_attempt",
            "verification_boundary", "receipt_descriptor",
        }
        or worktree["path"] != lane["worktree_path"]
        or worktree["identity_sha256"] != lane["worktree_identity_sha256"]
        or not isinstance(boundary, str)
        or boundary not in {"source_local_injected_executor_v1", "live_composed_executor_v1"}
        or not (
            claim_failure
            and worktree["clean_before_attempt"] is False
            and worktree["verification_boundary"] == "not_reached_evidence_claim_failed"
            and worktree["receipt_descriptor"] == "not_created"
            or not claim_failure
            and worktree["clean_before_attempt"] is True
            and (
                boundary == "source_local_injected_executor_v1"
                and worktree["verification_boundary"] == "fixture_source_local"
                and worktree["receipt_descriptor"] == "source_local_fixture"
                or boundary == "live_composed_executor_v1"
                and worktree["verification_boundary"] == "verified_live"
                and isinstance(worktree["receipt_descriptor"], dict)
            )
        )
    ):
        raise ExecutionError("attempt_record_worktree_mismatch", lane["lane_id"])
    expected_directory = f"{lane['evidence_directory']}/attempt-{index:03d}"
    if value.get("evidence_directory") != expected_directory:
        raise ExecutionError("attempt_record_evidence_mismatch", lane["lane_id"])
    booleans = (
        "run_one_started", "provider_process_started", "mutation_started",
        "possible_mutation", "execution_unknown",
        "composed_executor_finalization_validated",
    )
    if any(type(value.get(field)) is not bool for field in booleans):
        raise ExecutionError("attempt_record_status_inconsistent", lane["lane_id"])
    external = value.get("external_call_performed")
    if external is not False and external is not True and external != "unknown":
        raise ExecutionError("attempt_record_status_inconsistent", lane["lane_id"])
    failure = value.get("failure")
    finalization = value.get("finalization")
    live_validated = value["composed_executor_finalization_validated"]
    if status == "failed_certain_pre_provider":
        consistent = (
            isinstance(failure, dict) and failure.get("retry_allowed") is True
            and finalization is None and value["run_one_started"] is False
            and value["provider_process_started"] is False and external is False
            and value["mutation_started"] is False and value["possible_mutation"] is False
            and value["execution_unknown"] is False and live_validated is False
        )
    elif status == "source_validated_non_promotable":
        consistent = (
            boundary == "source_local_injected_executor_v1" and failure is None
            and isinstance(finalization, dict)
            and finalization.get("artifact_type") == "ProviderFanoutSourceLocalFinalization"
            and finalization.get("status") == "source_validated_non_promotable"
            and finalization.get("provider_call_performed") is False
            and finalization.get("accepted") is False
            and finalization.get("sol_decision") == "pending"
            and finalization.get("accepted_by_parent") is False
            and finalization.get("board_mutation_performed") is False
            and finalization.get("fold_performed") is False
            and finalization.get("application_performed") is False
            and value["run_one_started"] is True
            and value["provider_process_started"] is True
            and external is False and value["mutation_started"] is False
            and value["possible_mutation"] is False
            and value["execution_unknown"] is False and live_validated is False
        )
    elif status == "candidate_ready":
        outputs = finalization.get("outputs") if isinstance(finalization, dict) else None
        consistent = (
            boundary == "live_composed_executor_v1"
            and lane["mutation_mode"] != "scoped_write"
            and failure is None and isinstance(finalization, dict)
            and finalization.get("artifact_type") == "VisibleProviderDispatchFinalization"
            and finalization.get("accepted") is False
            and finalization.get("sol_decision") == "pending"
            and isinstance(outputs, dict)
            and set(outputs) == {"quality_receipt", "schedule_manifest", "reconciliation"}
            and value["run_one_started"] is True
            and value["provider_process_started"] is True
            and external is True and value["execution_unknown"] is False
            and live_validated is True
        )
    elif status == "execution_unknown":
        consistent = (
            isinstance(failure, dict) and failure.get("retry_allowed") is False
            and value["execution_unknown"] is True and live_validated is False
            and (
                value["run_one_started"] is True
                or value["provider_process_started"] is True
                or external is not False
                or value["mutation_started"] is True
                or value["possible_mutation"] is True
            )
        )
    else:
        consistent = (
            value["execution_unknown"] is False and live_validated is False
            and value["provider_process_started"] is False and external is False
            and value["mutation_started"] is False and value["possible_mutation"] is False
            and (
                failure is None
                or (isinstance(failure, dict) and failure.get("retry_allowed") is False)
            )
        )
    if not consistent:
        raise ExecutionError("attempt_record_status_inconsistent", lane["lane_id"])
    if (
        value.get("accepted_by_parent") is not False
        or value.get("board_mutation_performed") is not False
        or value.get("fold_performed") is not False
        or value.get("application_performed") is not False
    ):
        raise ExecutionError("parent_boundary_violation", lane["lane_id"])
    if prior is not None:
        fresh = (
            "preflight_sha256", "lease_id", "lease_sha256", "fencing_token",
            "fence_token_sha256", "execution_binding_sha256",
        )
        for field in fresh:
            if value["authority"].get(field) == prior["authority"].get(field):
                raise ExecutionError("fresh_attempt_binding_reused", field)
        if value["evidence_directory"] == prior["evidence_directory"]:
            raise ExecutionError("fresh_attempt_binding_reused", "evidence_directory")
    return value


def aggregate_attempt_records(plan: dict[str, Any], lane_records: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Derive a non-accepting aggregate only from validated attempt records."""
    summaries = []
    expected = {lane["lane_id"] for lane in plan["lanes"]}
    if set(lane_records) != expected:
        raise ExecutionError("lane_record_set_mismatch")
    seen_attempt_ids: set[str] = set()
    seen_evidence_directories: set[str] = set()
    for lane in plan["lanes"]:
        rows = lane_records[lane["lane_id"]]
        if not rows:
            raise ExecutionError("attempt_record_missing", lane["lane_id"])
        prior = None
        validated = []
        for position, row in enumerate(rows):
            validated_row = validate_attempt_record(
                row, lane, prior, fanout_id=plan["fanout_id"]
            )
            if validated_row["attempt_id"] in seen_attempt_ids:
                raise ExecutionError("attempt_record_identity_collision", validated_row["attempt_id"])
            if validated_row["evidence_directory"] in seen_evidence_directories:
                raise ExecutionError("attempt_record_evidence_collision", validated_row["evidence_directory"])
            seen_attempt_ids.add(validated_row["attempt_id"])
            seen_evidence_directories.add(validated_row["evidence_directory"])
            if position < len(rows) - 1 and validated_row["status"] != "failed_certain_pre_provider":
                raise ExecutionError("attempt_history_terminal_not_last", lane["lane_id"])
            validated.append(validated_row)
            prior = row
        terminal = validated[-1]
        if terminal["status"] == "failed_certain_pre_provider":
            raise ExecutionError("attempt_history_incomplete", lane["lane_id"])
        summaries.append({
            "lane_id": lane["lane_id"], "final_status": terminal["status"],
            "attempt_count": len(validated), "attempt_record_sha256s": [row["record_sha256"] for row in validated],
            "candidate_artifact": copy.deepcopy((terminal.get("finalization") or {}).get("outputs"))
            if terminal["status"] == "candidate_ready" else None,
        })
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ProviderFanoutExecutionAggregate",
        "fanout_id": plan["fanout_id"],
        "plan_sha256": plan["plan_sha256"],
        "lanes": sorted(summaries, key=lambda row: row["lane_id"]),
        "accepted_by_parent": False,
        "board_mutation_performed": False,
        "fold_performed": False,
        "application_performed": False,
    }
    result["aggregate_sha256"] = digest(result)
    return result


@dataclass
class FanoutController:
    executor: LaneExecutor
    artifact_root: Path
    task_cap: int
    fleet_cap: int
    clock: Callable[[], str] = _timestamp
    worktree_probe: Callable[[dict[str, Any], int], dict[str, Any]] | None = None
    execution_mode: str = "source_local"

    def __post_init__(self) -> None:
        if self.execution_mode not in {"source_local", "live_composed"}:
            raise ExecutionError("execution_mode_invalid")
        if self.execution_mode == "live_composed":
            if type(self.executor) is not ComposedLaneExecutor:
                raise ExecutionError("live_executor_not_composed")
            if self.worktree_probe is not None:
                raise ExecutionError("live_fixture_probe_forbidden")
        elif not callable(self.worktree_probe):
            raise ExecutionError("source_local_fixture_probe_required")

    @classmethod
    def source_local_controller(
        cls, *, executor: LaneExecutor, artifact_root: Path, task_cap: int,
        fleet_cap: int, worktree_probe: Callable[[dict[str, Any], int], dict[str, Any]],
        clock: Callable[[], str] = _timestamp,
    ) -> "FanoutController":
        return cls(
            executor=executor, artifact_root=artifact_root, task_cap=task_cap,
            fleet_cap=fleet_cap, clock=clock, worktree_probe=worktree_probe,
            execution_mode="source_local",
        )

    @classmethod
    def live_controller(
        cls, *, executor: ComposedLaneExecutor, artifact_root: Path,
        task_cap: int, fleet_cap: int,
        clock: Callable[[], str] = _timestamp,
    ) -> "FanoutController":
        return cls(
            executor=executor, artifact_root=artifact_root, task_cap=task_cap,
            fleet_cap=fleet_cap, clock=clock, execution_mode="live_composed",
        )

    def _persist_record(
        self, attempt: dict[str, Any], record: dict[str, Any]
    ) -> dict[str, Any]:
        path = self.artifact_root / attempt["evidence_directory"] / "attempt-record.json"
        descriptor = _atomic_new_json(self.artifact_root, path, record)
        verified_descriptor, stored = _descriptor(
            self.artifact_root, descriptor["path"],
            "ProviderFanoutExecutionAttemptRecord",
        )
        if verified_descriptor != descriptor:
            raise ExecutionError("attempt_record_persistence_mismatch", attempt["attempt_id"])
        return stored

    def _persist_document(
        self, attempt: dict[str, Any], name: str, kind: str,
        value: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        path = self.artifact_root / attempt["evidence_directory"] / name
        descriptor = _atomic_new_json(self.artifact_root, path, value)
        verified, stored = _descriptor(self.artifact_root, descriptor["path"], kind)
        if verified != descriptor or stored != value:
            raise ExecutionError("artifact_persistence_mismatch", kind)
        return verified, stored

    def _persist_claim_failure_document(
        self, lane: dict[str, Any], index: int, name: str, kind: str,
        value: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        relative = f"{lane['evidence_directory']}/claim-failure-{index:03d}"
        directory = _safe_new_directory(
            self.artifact_root, relative, "claim_failure.evidence_directory"
        )
        descriptor = _atomic_new_json(self.artifact_root, directory / name, value)
        verified, stored = _descriptor(self.artifact_root, descriptor["path"], kind)
        if verified != descriptor or stored != value:
            raise ExecutionError("artifact_persistence_mismatch", kind)
        return verified, stored

    def _persist_claim_failure_record(
        self, lane: dict[str, Any], index: int, record: dict[str, Any]
    ) -> dict[str, Any]:
        relative = f"{lane['evidence_directory']}/claim-failure-{index:03d}"
        path = self.artifact_root / relative / "attempt-record.json"
        descriptor = _atomic_new_json(self.artifact_root, path, record)
        verified, stored = _descriptor(
            self.artifact_root, descriptor["path"],
            "ProviderFanoutExecutionAttemptRecord",
        )
        if verified != descriptor:
            raise ExecutionError("attempt_record_persistence_mismatch", record["attempt_id"])
        return stored

    def _claim_failure_attempt(
        self, plan: dict[str, Any], lane: dict[str, Any], index: int
    ) -> dict[str, Any]:
        attempt_id = f"{plan['fanout_id']}:{lane['lane_id']}:a{index}"
        return {
            "fanout_id": plan["fanout_id"], "lane_id": lane["lane_id"],
            "attempt_id": attempt_id, "attempt_index": index,
            "evidence_directory": f"{lane['evidence_directory']}/attempt-{index:03d}",
            "worktree_path": lane["worktree_path"],
            "worktree_identity_sha256": lane["worktree_identity_sha256"],
            "clean_before_attempt": False,
            "capability_card_sha256": lane["capability_card_sha256"],
            "grant_sha256": lane["grant_sha256"],
            "mutation_started": False, "possible_mutation": False,
            "worktree_verification_boundary": "not_reached_evidence_claim_failed",
            "worktree_receipt_descriptor": "not_created",
            "execution_boundary": (
                "live_composed_executor_v1" if self.execution_mode == "live_composed"
                else "source_local_injected_executor_v1"
            ),
            "composed_executor_finalization_validated": False,
        }

    def _attempt(self, plan: dict[str, Any], lane: dict[str, Any], index: int) -> dict[str, Any]:
        relative = f"{lane['evidence_directory']}/attempt-{index:03d}"
        evidence = _safe_new_directory(
            self.artifact_root, relative, "attempt.evidence_directory"
        )
        if self.execution_mode == "live_composed":
            receipt = ComposedLaneExecutor.verify_worktree(self.executor, lane, index)
            supplied = receipt.get("receipt_sha256") if isinstance(receipt, dict) else None
            payload = {
                key: copy.deepcopy(value) for key, value in receipt.items()
                if key != "receipt_sha256"
            } if isinstance(receipt, dict) else {}
            if (
                supplied != digest(payload)
                or receipt.get("artifact_type") != "VerifiedFanoutWorktreeReceipt"
                or receipt.get("lane_id") != lane["lane_id"]
                or receipt.get("attempt_index") != index
                or receipt.get("worktree_path") != lane["worktree_path"]
                or receipt.get("worktree_identity_sha256") != lane["worktree_identity_sha256"]
                or receipt.get("clean") is not True
                or receipt.get("environment_clean") is not True
                or receipt.get("verifier") != "git_status_porcelain_v1"
            ):
                raise ExecutionError("worktree_receipt_invalid", lane["lane_id"])
            worktree_boundary = "verified_live"
        else:
            probe = self.worktree_probe(lane, index)
            if probe != {
                "path": lane["worktree_path"],
                "identity_sha256": lane["worktree_identity_sha256"],
                "clean": True,
            }:
                raise ExecutionError("worktree_not_clean_or_bound", lane["lane_id"])
            receipt = None
            worktree_boundary = "fixture_source_local"
        attempt = {
            "fanout_id": plan["fanout_id"], "lane_id": lane["lane_id"],
            "attempt_id": f"{plan['fanout_id']}:{lane['lane_id']}:a{index}",
            "attempt_index": index, "evidence_directory": _relative(self.artifact_root, evidence, "evidence"),
            "worktree_path": lane["worktree_path"],
            "worktree_identity_sha256": lane["worktree_identity_sha256"],
            "clean_before_attempt": True,
            "capability_card_sha256": lane["capability_card_sha256"],
            "grant_sha256": lane["grant_sha256"],
            "mutation_started": False, "possible_mutation": False,
            "worktree_verification_boundary": worktree_boundary,
            "execution_boundary": (
                "live_composed_executor_v1" if self.execution_mode == "live_composed"
                else "source_local_injected_executor_v1"
            ),
            "composed_executor_finalization_validated": False,
        }
        if receipt is not None:
            descriptor, _ = self._persist_document(
                attempt, "worktree-receipt.json", "VerifiedFanoutWorktreeReceipt", receipt
            )
            attempt["worktree_receipt_descriptor"] = descriptor
        else:
            attempt["worktree_receipt_descriptor"] = "source_local_fixture"
        return attempt

    def _run_lane(self, plan: dict[str, Any], lane: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        pending_retry: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None
        for index in range(1, lane["max_attempts"] + 1):
            try:
                attempt = self._attempt(plan, lane, index)
            except ExecutionError as claim_error:
                if (
                    claim_error.code != "evidence_collision_before_claim"
                    or index >= lane["max_attempts"]
                ):
                    raise
                attempt = self._claim_failure_attempt(plan, lane, index)
                started_at = self.clock()
                admission = {
                    "selected_route": {
                        "name": lane["route_name"], "provider": lane["provider"],
                        "exact_model": lane["model"],
                    },
                    "lease": {
                        "lease_id": f"unbound:{attempt['attempt_id']}",
                        "fencing_token": 0,
                    },
                }
                binding = {
                    "attempt_id": attempt["attempt_id"],
                    "route_name": lane["route_name"],
                    "preflight_sha256": digest([
                        attempt["attempt_id"], "evidence-claim-unbound"
                    ]),
                }
                failure = {
                    "code": claim_error.code, "detail": claim_error.detail,
                    "failure_receipt_descriptor": "pending",
                    "retry_allowed": True,
                }
                record = _attempt_binding_record(
                    lane=lane, attempt=attempt, admission=admission, binding=binding,
                    returned=None, finalization=None,
                    status="failed_certain_pre_provider",
                    started_at=started_at, completed_at=self.clock(), failure=failure,
                )
                receipt = {
                    "schema_version": 1,
                    "artifact_type": "FanoutPreProviderFailureReceipt",
                    "fanout_id": plan["fanout_id"], "lane_id": lane["lane_id"],
                    "attempt_id": record["attempt_id"],
                    "attempt_index": record["attempt_index"],
                    "route": copy.deepcopy(record["route"]),
                    "authority": copy.deepcopy(record["authority"]),
                    "failure_class": claim_error.code,
                    "claim_failed_before_binding": True,
                    "run_one_started": False, "provider_process_started": False,
                    "external_call_performed": False, "mutation_started": False,
                    "possible_mutation": False, "execution_unknown": False,
                    "receipt_finalized": True,
                }
                receipt["receipt_sha256"] = digest(receipt)
                failure_descriptor, stored_failure = self._persist_claim_failure_document(
                    lane, index, "pre-provider-failure-receipt.json",
                    "FanoutPreProviderFailureReceipt", receipt,
                )
                record["failure"]["failure_receipt_descriptor"] = failure_descriptor
                record["record_sha256"] = digest({
                    key: value for key, value in record.items()
                    if key != "record_sha256"
                })
                validate_failure_receipt(stored_failure, lane, record)
                validate_attempt_record(
                    record, lane, records[-1] if records else None,
                    fanout_id=plan["fanout_id"],
                )
                stored_record = self._persist_claim_failure_record(lane, index, record)
                records.append(stored_record)
                pending_retry = (stored_record, failure_descriptor, stored_failure)
                continue
            started_at = self.clock()
            admission: dict[str, Any] = {}
            binding: dict[str, Any] = {}
            returned: dict[str, Any] | None = None
            finalization: dict[str, Any] | None = None
            stage = "admit"
            try:
                admission = (
                    ComposedLaneExecutor.admit(self.executor, lane, attempt)
                    if self.execution_mode == "live_composed"
                    else self.executor.admit(lane, attempt)
                )
                selected = admission.get("selected_route", {})
                if [selected.get("name")] != [lane["route_name"]]:
                    raise ExecutionError("scheduler_route_mismatch", lane["lane_id"])
                stage = "bind"
                binding = (
                    ComposedLaneExecutor.bind(self.executor, lane, attempt, admission)
                    if self.execution_mode == "live_composed"
                    else self.executor.bind(lane, attempt, admission)
                )
                if binding.get("route_name") != lane["route_name"] or binding.get("attempt_id") in {
                    row["attempt_id"] for row in records
                }:
                    raise ExecutionError("execution_binding_mismatch", lane["lane_id"])
                stage = "pre_spawn"
                if self.execution_mode == "live_composed":
                    ComposedLaneExecutor.pre_spawn_check(
                        self.executor, lane, attempt, admission, binding
                    )
                else:
                    check = getattr(self.executor, "pre_spawn_check", None)
                    if callable(check):
                        check(lane, attempt, admission, binding)
                if pending_retry is not None:
                    prior_record, failure_descriptor, failure_receipt = pending_retry
                    decision = retry_decision(
                        lane=lane, prior_record=prior_record,
                        failure_descriptor=failure_descriptor,
                        failure_receipt=failure_receipt,
                        successor_attempt=attempt, successor_admission=admission,
                        successor_binding=binding,
                    )
                    decision_descriptor, stored_decision = self._persist_document(
                        attempt, "retry-decision.json", "ProviderFanoutRetryDecision",
                        decision,
                    )
                    if stored_decision.get("decision_sha256") != digest({
                        key: value for key, value in stored_decision.items()
                        if key != "decision_sha256"
                    }):
                        raise ExecutionError("retry_decision_digest_mismatch", lane["lane_id"])
                    attempt["retry_decision_descriptor"] = decision_descriptor
                    pending_retry = None
                else:
                    attempt["retry_decision_descriptor"] = "initial_attempt"
                stage = "run_one"
                attempt["run_one_started"] = True
                returned = (
                    ComposedLaneExecutor.run_one(
                        self.executor, lane, attempt, admission, binding
                    )
                    if self.execution_mode == "live_composed"
                    else self.executor.run_one(lane, attempt, admission, binding)
                )
                stage = "finalize"
                finalization = (
                    ComposedLaneExecutor.finalize(
                        self.executor, lane, attempt, admission, binding, returned
                    )
                    if self.execution_mode == "live_composed"
                    else self.executor.finalize(lane, attempt, admission, binding, returned)
                )
                if self.execution_mode == "live_composed":
                    ComposedLaneExecutor.validate_live_finalization(
                        self.executor,
                        lane, attempt, returned, finalization
                    )
                    attempt["composed_executor_finalization_validated"] = True
                status = _execution_status(
                    returned, finalization,
                    source_local=self.execution_mode == "source_local",
                )
                record = _attempt_binding_record(
                    lane=lane, attempt=attempt, admission=admission, binding=binding,
                    returned=returned, finalization=finalization, status=status,
                    started_at=started_at, completed_at=self.clock(), failure=None,
                )
                validate_attempt_record(
                    record, lane, records[-1] if records else None,
                    fanout_id=plan["fanout_id"],
                )
                records.append(self._persist_record(attempt, record))
                return records
            except BaseException as exc:
                code = getattr(exc, "code", type(exc).__name__)
                run_started = attempt.get("run_one_started") is True
                spawned = bool(getattr(exc, "provider_process_started", False)) or returned is not None
                external = getattr(exc, "external_call_performed", False)
                mutated = bool(getattr(exc, "mutation_started", False))
                possible = bool(getattr(exc, "possible_mutation", False))
                unknown = bool(getattr(exc, "execution_unknown", False)) or code in TERMINAL_UNKNOWN_CODES
                retryable = (
                    code in RETRYABLE_PRESPAWN_CODES
                    and code != "evidence_collision_before_claim"
                    and stage == "pre_spawn"
                    and bool(admission) and bool(binding)
                    and not run_started and index < lane["max_attempts"]
                )
                if retryable and self.execution_mode == "live_composed":
                    try:
                        ComposedLaneExecutor.release_pre_spawn(
                            self.executor, lane, attempt, admission, binding
                        )
                    except BaseException:
                        retryable = False
                # A retry decision uses controller-observed stage state. It does
                # not use caller or exception claims about execution effects.
                attempt.update({
                    "provider_process_started": False if retryable else spawned,
                    "external_call_performed": False if retryable else external,
                    "mutation_started": False if retryable else mutated,
                    "possible_mutation": False if retryable else possible,
                })
                status = "failed_certain_pre_provider" if retryable else (
                    "execution_unknown"
                    if run_started or spawned or external != False or mutated or possible or unknown
                    else "rejected"
                )
                synthetic_admission = admission or {"selected_route": {"name": lane["route_name"], "provider": lane["provider"], "exact_model": lane["model"]}, "lease": {}}
                synthetic_binding = binding or {
                    "attempt_id": attempt["attempt_id"], "route_name": lane["route_name"],
                    "preflight_sha256": digest([attempt["attempt_id"], "unbound"]),
                }
                failure = {
                    "code": code, "detail": getattr(exc, "detail", str(exc)),
                    "failure_receipt_descriptor": "pending" if retryable else "not_retryable",
                    "retry_allowed": retryable,
                }
                record = _attempt_binding_record(
                    lane=lane, attempt=attempt, admission=synthetic_admission, binding=synthetic_binding,
                    returned=returned, finalization=finalization, status=status,
                    started_at=started_at, completed_at=self.clock(), failure=failure,
                )
                if retryable:
                    receipt = {
                        "schema_version": 1,
                        "artifact_type": "FanoutPreProviderFailureReceipt",
                        "fanout_id": plan["fanout_id"],
                        "lane_id": lane["lane_id"],
                        "attempt_id": record["attempt_id"],
                        "attempt_index": record["attempt_index"],
                        "route": copy.deepcopy(record["route"]),
                        "authority": copy.deepcopy(record["authority"]),
                        "failure_class": code,
                        "claim_failed_before_binding": False,
                        "run_one_started": False,
                        "provider_process_started": False,
                        "external_call_performed": False,
                        "mutation_started": False,
                        "possible_mutation": False,
                        "execution_unknown": False,
                        "receipt_finalized": True,
                    }
                    receipt["receipt_sha256"] = digest(receipt)
                    failure_descriptor, stored_failure = self._persist_document(
                        attempt, "pre-provider-failure-receipt.json",
                        "FanoutPreProviderFailureReceipt", receipt,
                    )
                    record["failure"]["failure_receipt_descriptor"] = failure_descriptor
                    record["record_sha256"] = digest({
                        key: value for key, value in record.items()
                        if key != "record_sha256"
                    })
                    validate_failure_receipt(stored_failure, lane, record)
                    validate_attempt_record(
                        record, lane, records[-1] if records else None,
                        fanout_id=plan["fanout_id"],
                    )
                    stored_record = self._persist_record(attempt, record)
                    records.append(stored_record)
                    pending_retry = (stored_record, failure_descriptor, stored_failure)
                    continue
                validate_attempt_record(
                    record, lane, records[-1] if records else None,
                    fanout_id=plan["fanout_id"],
                )
                records.append(self._persist_record(attempt, record))
                return records
        return records

    def execute(self, plan: dict[str, Any], *, now: dt.datetime) -> dict[str, Any]:
        FANOUT.validate_plan(plan, now=now, artifact_root=self.artifact_root)
        if plan.get("artifact_type") != "ProviderFanoutPlan":
            raise ExecutionError("compiled_plan_required")
        cap = min(plan["concurrency_limit"], self.task_cap, self.fleet_cap, READ_CONCURRENCY_CAP)
        if cap < 1:
            raise ExecutionError("concurrency_cap_invalid")
        read_lanes = [lane for lane in plan["lanes"] if lane["mutation_mode"] != "scoped_write"]
        write_lanes = [lane for lane in plan["lanes"] if lane["mutation_mode"] == "scoped_write"]
        records: dict[str, list[dict[str, Any]]] = {}
        with ThreadPoolExecutor(max_workers=cap, thread_name_prefix="provider-read-lane") as pool:
            futures = {pool.submit(self._run_lane, plan, lane): lane for lane in read_lanes}
            for future in as_completed(futures):
                lane = futures[future]
                records[lane["lane_id"]] = future.result()
        # Writers are always serial.  They start after every read lane is terminal.
        for lane in write_lanes:
            records[lane["lane_id"]] = self._run_lane(plan, lane)
        return aggregate_attempt_records(plan, records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--task-cap", type=int, required=True)
    parser.add_argument("--fleet-cap", type=int, required=True)
    args = parser.parse_args(argv)
    print(json.dumps({
        "status": "rejected", "code": "runtime_inputs_required",
        "detail": "Use the embedded API with a composed lane executor. The CLI never invents authority inputs.",
    }, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
