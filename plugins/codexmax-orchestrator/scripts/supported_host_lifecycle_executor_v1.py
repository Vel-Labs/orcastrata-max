#!/usr/bin/env python3
"""Separate durable lifecycle executor for the supported host.

Local mode is a non-authoritative harness. Live mode accepts only public intent,
inherited descriptors, identifier-only opaque agent references, and
receiver-owned receipts. It fails closed without exact external OS evidence.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence

from supported_host_public_provisioning_v1 import validate_public_provisioning, ProvisioningError
from supported_host_protected_receiver_v1 import request_fixed_receiver
from supported_host_candidate_admission_v1 import verify_selected_candidate_fds, CandidateAdmissionError
from supported_host_protected_backend_v1 import (
    OPERATIONS as BACKEND_OPERATIONS,
    PROTOCOL_VERSION as BACKEND_PROTOCOL,
    REQUEST_TYPE as BACKEND_REQUEST_TYPE,
    FixedProtectedBackendConfiguration,
    ProtectedBackendError,
    load_fixed_protected_configuration,
    request_fixed_backend,
)

STATES = ("INSTALLED", "STARTED", "HANDSHAKE_VALIDATED", "ADMITTED", "JOURNEY_COMPLETED", "STOPPED", "INVENTORIED", "RECONCILED", "CLEANED")
_TRANSITIONS = tuple(zip(BACKEND_OPERATIONS, STATES, strict=True))
_EVENT_FIELDS = frozenset({"schema_version", "artifact_type", "revision", "prior_state", "state", "operation", "backend_state", "backend_revision", "backend_writer_record_sha256", "backend_anchor_record_sha256", "backend_pre_operation_witness_sha256", "backend_post_operation_witness_sha256", "candidate_generation", "nonce", "descriptor_inventory_sha256", "protected_writer_receipt_sha256", "independent_anchor_receipt_sha256", "receiver_observation_sha256", "mode", "production_authority", "previous_event_sha256", "event_sha256"})
_REQUEST_FIELDS = frozenset({"schema_version", "artifact_type", "expected_revision", "expected_state", "target_state", "candidate_generation", "nonce", "descriptor_inventory_sha256", "protected_writer_receipt_sha256", "independent_anchor_receipt_sha256", "receiver_observation_sha256", "opaque_credential_agent_ref", "provisioning_sha256"})
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}$")


class LifecycleExecutionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code; self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(value); row["event_sha256"] = ""; row["event_sha256"] = _digest(row); return row


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields): raise LifecycleExecutionError(code, path)
    return dict(value)


def _initial() -> dict[str, Any]:
    return {"revision": 0, "state": None, "candidate_generation": None, "nonce": None, "descriptor_inventory_sha256": None, "protected_writer_receipt_sha256": None, "independent_anchor_receipt_sha256": None, "receiver_observation_sha256": None, "last_event_sha256": None, "events": []}


def verify_journal_bytes(data: bytes) -> dict[str, Any]:
    state = _initial()
    if not data: return state
    if not data.endswith(b"\n"): raise LifecycleExecutionError("journal_crash_residue_detected")
    try: rows = [json.loads(line) for line in data.decode().splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise LifecycleExecutionError("journal_corrupt") from exc
    for index, raw in enumerate(rows, start=1):
        event = _closed(raw, _EVENT_FIELDS, "journal_event_shape_invalid", f"$.events[{index}]")
        if event["schema_version"] != 1 or event["artifact_type"] != "codexmax_supported_host_lifecycle_event_v1" or event["revision"] != index:
            raise LifecycleExecutionError("journal_event_identity_invalid", f"$.events[{index}]")
        if event["previous_event_sha256"] != state["last_event_sha256"] or _seal(event)["event_sha256"] != event["event_sha256"]:
            raise LifecycleExecutionError("journal_chain_invalid", f"$.events[{index}]")
        operation, expected_state = _TRANSITIONS[index - 1]
        if (event["prior_state"] != state["state"] or event["state"] != expected_state
                or event["operation"] != operation or event["backend_state"] != expected_state
                or event["backend_revision"] != index):
            raise LifecycleExecutionError("journal_transition_invalid", f"$.events[{index}]")
        for field in ("backend_writer_record_sha256", "backend_anchor_record_sha256", "backend_pre_operation_witness_sha256", "backend_post_operation_witness_sha256"):
            if not isinstance(event[field], str) or _SHA.fullmatch(event[field]) is None:
                raise LifecycleExecutionError("journal_backend_digest_invalid", f"$.events[{index}].{field}")
        for field in ("candidate_generation", "nonce", "descriptor_inventory_sha256", "protected_writer_receipt_sha256", "independent_anchor_receipt_sha256", "receiver_observation_sha256"):
            if state[field] is not None and event[field] != state[field]: raise LifecycleExecutionError("journal_binding_changed", f"$.events[{index}].{field}")
            state[field] = event[field]
        state.update({"revision": index, "state": event["state"], "last_event_sha256": event["event_sha256"]}); state["events"].append(event)
    return state


def _validate_request(value: Any) -> dict[str, Any]:
    row = _closed(value, _REQUEST_FIELDS, "advance_request_shape_invalid", "$.request")
    if row["schema_version"] != 1 or row["artifact_type"] != "codexmax_supported_host_lifecycle_advance_v1": raise LifecycleExecutionError("advance_request_identity_invalid")
    if type(row["expected_revision"]) is not int or row["expected_revision"] < 0 or type(row["candidate_generation"]) is not int or row["candidate_generation"] < 1: raise LifecycleExecutionError("advance_counter_invalid")
    if row["target_state"] not in STATES or row["expected_state"] not in (*STATES, None): raise LifecycleExecutionError("advance_state_invalid")
    if not isinstance(row["opaque_credential_agent_ref"], str) or _ID.fullmatch(row["opaque_credential_agent_ref"]) is None: raise LifecycleExecutionError("opaque_agent_reference_invalid")
    for field in ("descriptor_inventory_sha256", "protected_writer_receipt_sha256", "independent_anchor_receipt_sha256", "receiver_observation_sha256", "provisioning_sha256"):
        if not isinstance(row[field], str) or _SHA.fullmatch(row[field]) is None: raise LifecycleExecutionError("advance_digest_invalid", f"$.request.{field}")
    if not isinstance(row["nonce"], str) or _ID.fullmatch(row["nonce"]) is None: raise LifecycleExecutionError("advance_nonce_invalid")
    return row


def _backend_request(request: Mapping[str, Any], operation: str, run_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1, "artifact_type": BACKEND_REQUEST_TYPE,
        "protocol_version": BACKEND_PROTOCOL, "operation": operation,
        "run_id": run_id,
        "attempt_id": f"{run_id}-r{request['expected_revision']}-{operation}",
        "expected_revision": request["expected_revision"],
        "candidate_generation": request["candidate_generation"],
        "candidate_descriptor_sha256": request["descriptor_inventory_sha256"],
        "challenge_sha256": "sha256:" + hashlib.sha256(request["nonce"].encode()).hexdigest(),
        "opaque_agent_ref": request["opaque_credential_agent_ref"],
        "public_receipts": {
            "certificate_receipt_sha256": request["protected_writer_receipt_sha256"],
            "handshake_receipt_sha256": request["independent_anchor_receipt_sha256"],
        },
    }


def _event(state: Mapping[str, Any], request: Mapping[str, Any], operation: str,
           backend: Mapping[str, Any], mode: str) -> dict[str, Any]:
    return _seal({"schema_version": 1, "artifact_type": "codexmax_supported_host_lifecycle_event_v1", "revision": state["revision"] + 1, "prior_state": state["state"], "state": backend["state"], "operation": operation, "backend_state": backend["state"], "backend_revision": backend["revision"], "backend_writer_record_sha256": backend["writer_record_sha256"], "backend_anchor_record_sha256": backend["anchor_record_sha256"], "backend_pre_operation_witness_sha256": backend["pre_operation_witness_sha256"], "backend_post_operation_witness_sha256": backend["post_operation_witness_sha256"], "candidate_generation": request["candidate_generation"], "nonce": request["nonce"], "descriptor_inventory_sha256": request["descriptor_inventory_sha256"], "protected_writer_receipt_sha256": request["protected_writer_receipt_sha256"], "independent_anchor_receipt_sha256": request["independent_anchor_receipt_sha256"], "receiver_observation_sha256": request["receiver_observation_sha256"], "mode": mode, "production_authority": backend["production_authority"], "previous_event_sha256": state["last_event_sha256"], "event_sha256": ""})


def _validate_backend_result(value: Any, backend_request: Mapping[str, Any],
                             target_state: str) -> dict[str, Any]:
    required = {"schema_version", "artifact_type", "protocol_version", "run_id",
                "operation", "revision", "state", "writer_record_sha256",
                "anchor_record_sha256", "pre_operation_witness_sha256",
                "post_operation_witness_sha256", "production_authority", "production_ready"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise LifecycleExecutionError("backend_response_shape_invalid")
    row = dict(value)
    if (row["artifact_type"] != "codexmax_protected_backend_response_v1"
            or row["protocol_version"] != BACKEND_PROTOCOL
            or row["run_id"] != backend_request["run_id"]
            or row["operation"] != backend_request["operation"]):
        raise LifecycleExecutionError("backend_response_binding_mismatch")
    if row["revision"] != backend_request["expected_revision"] + 1 or row["state"] != target_state:
        raise LifecycleExecutionError("backend_state_revision_mismatch")
    for field in ("writer_record_sha256", "anchor_record_sha256", "pre_operation_witness_sha256", "post_operation_witness_sha256"):
        if not isinstance(row[field], str) or _SHA.fullmatch(row[field]) is None:
            raise LifecycleExecutionError("backend_response_digest_invalid", "$.backend." + field)
    if type(row["production_authority"]) is not bool or row["production_ready"] is not row["production_authority"]:
        raise LifecycleExecutionError("backend_authority_mismatch")
    return row


def advance_fd(journal_fd: int, request_value: Any, *, mode: str, provisioning: Any,
               live_receipt_fd: int | None = None, task_selector: str | None = None,
               candidate_fds: tuple[int, int, int] | None = None,
               fixed_configuration: FixedProtectedBackendConfiguration | None = None,
               backend: Any | None = None, backend_channel: Any | None = None,
               crash_after_backend: bool = False) -> dict[str, Any]:
    request = _validate_request(request_value)
    provision = validate_public_provisioning(provisioning)
    if request["provisioning_sha256"] != provision["provisioning_sha256"]: raise LifecycleExecutionError("provisioning_binding_mismatch")
    try:
        info = os.fstat(journal_fd)
        if not stat.S_ISREG(info.st_mode): raise LifecycleExecutionError("journal_descriptor_invalid")
        fcntl.flock(journal_fd, fcntl.LOCK_EX)
        data = os.pread(journal_fd, info.st_size + 1, 0)
        state = verify_journal_bytes(data)
        if request["expected_revision"] != state["revision"] or request["expected_state"] != state["state"]: raise LifecycleExecutionError("journal_cas_mismatch")
        next_index = state["revision"]
        if next_index >= len(_TRANSITIONS) or request["target_state"] != STATES[next_index]: raise LifecycleExecutionError("lifecycle_transition_invalid")
        operation, target_state = _TRANSITIONS[next_index]
        for field in ("candidate_generation", "nonce", "descriptor_inventory_sha256", "protected_writer_receipt_sha256", "independent_anchor_receipt_sha256", "receiver_observation_sha256"):
            if state[field] is not None and request[field] != state[field]: raise LifecycleExecutionError("lifecycle_binding_substitution", f"$.request.{field}")
        if task_selector is None:
            raise LifecycleExecutionError("backend_run_id_required")
        backend_request = _backend_request(request, operation, task_selector)
        if mode == "live":
            if candidate_fds is None or fixed_configuration is None:
                # Preserve the old pending client for diagnostic compatibility.
                backend = request_fixed_receiver(
                    task_selector,
                    expected_generation=request["candidate_generation"],
                    service_start_id="lifecycle-start:" + request["nonce"],
                    service_session_id="lifecycle-session:" + request["nonce"],
                )
                if backend.get("status") not in {"consumed_success", "consumed_failure", "revoked"}:
                    raise LifecycleExecutionError("external_backend_pending")
                raise LifecycleExecutionError("external_backend_owns_live_transition")
            selected = verify_selected_candidate_fds(*candidate_fds, now=datetime.now(timezone.utc))
            public = selected.public_selection()
            if (public["generation"] != request["candidate_generation"]
                    or public["descriptor_sha256"] != request["descriptor_inventory_sha256"]):
                raise LifecycleExecutionError("selected_candidate_binding_mismatch")
            backend_result = request_fixed_backend(
                backend_request, selected=selected,
                fixed_configuration=fixed_configuration,
            )
        elif mode == "local_harness":
            if backend is None or backend_channel is None or not hasattr(backend, "observe") or not hasattr(backend, "handle"):
                raise LifecycleExecutionError("source_local_backend_required")
            observed = dict(backend.observe(task_selector))
            if observed["state"] == "EXECUTION_UNKNOWN":
                raise LifecycleExecutionError("backend_execution_unknown")
            if observed["revision"] == state["revision"]:
                if observed["state"] != state["state"]:
                    raise LifecycleExecutionError("backend_executor_state_mismatch")
                backend_result = backend.handle(backend_channel, backend_request)
            elif observed["revision"] == state["revision"] + 1:
                if (observed.get("operation") != operation
                        or observed.get("state") != target_state
                        or observed.get("attempt_id") != backend_request["attempt_id"]
                        or observed.get("request_sha256") != _digest(backend_request)):
                    raise LifecycleExecutionError("backend_partial_terminalization_mismatch")
                backend_result = {
                    "schema_version": 1,
                    "artifact_type": "codexmax_protected_backend_response_v1",
                    "protocol_version": BACKEND_PROTOCOL,
                    "run_id": task_selector,
                    "operation": operation,
                    "revision": observed["revision"],
                    "state": observed["state"],
                    "writer_record_sha256": observed["writer_record_sha256"],
                    "anchor_record_sha256": observed["anchor_record_sha256"],
                    "pre_operation_witness_sha256": observed.get("pre_operation_witness_sha256", _digest({"source_local": True})),
                    "post_operation_witness_sha256": observed.get("post_operation_witness_sha256", _digest({"source_local": True})),
                    "production_authority": False,
                    "production_ready": False,
                }
            else:
                raise LifecycleExecutionError("backend_executor_revision_mismatch")
        else:
            raise LifecycleExecutionError("execution_mode_invalid")
        backend_row = _validate_backend_result(backend_result, backend_request, target_state)
        if mode == "local_harness" and backend_row["production_authority"]:
            raise LifecycleExecutionError("source_local_authority_forbidden")
        if crash_after_backend:
            raise LifecycleExecutionError("source_local_injected_crash_after_backend")
        event = _event(state, request, operation, backend_row, mode)
        os.lseek(journal_fd, 0, os.SEEK_END)
        raw = _canonical(event)
        if os.write(journal_fd, raw) != len(raw):
            raise LifecycleExecutionError("journal_short_write")
        os.fsync(journal_fd)
        return {"artifact_type": "codexmax_supported_host_lifecycle_advance_receipt_v1",
                "operation": operation, "state": event["state"],
                "backend_state": backend_row["state"], "revision": event["revision"],
                "backend_revision": backend_row["revision"],
                "writer_record_sha256": backend_row["writer_record_sha256"],
                "anchor_record_sha256": backend_row["anchor_record_sha256"],
                "event_sha256": event["event_sha256"],
                "production_authority": backend_row["production_authority"],
                "production_ready": backend_row["production_ready"],
                "backend_owned": True}
    finally:
        try: fcntl.flock(journal_fd, fcntl.LOCK_UN)
        except OSError: pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("local_harness", "live"), required=True)
    parser.add_argument("--journal-fd", type=int, required=True)
    parser.add_argument("--request-json", required=True)
    parser.add_argument("--provisioning-json", required=True)
    parser.add_argument("--live-receipt-fd", type=int)
    parser.add_argument("--task-selector")
    parser.add_argument("--candidate-descriptor-fd", type=int)
    parser.add_argument("--runner-archive-fd", type=int)
    parser.add_argument("--runner-sidecar-fd", type=int)
    parser.add_argument("--protected-configuration-fd", type=int)
    args = parser.parse_args(argv)
    try:
        candidate_fds = None
        supplied = (args.candidate_descriptor_fd, args.runner_archive_fd, args.runner_sidecar_fd)
        if any(value is not None for value in supplied):
            if any(value is None for value in supplied):
                raise LifecycleExecutionError("candidate_descriptor_set_incomplete")
            candidate_fds = supplied
        fixed_configuration = None
        if args.protected_configuration_fd is not None:
            fixed_configuration = load_fixed_protected_configuration(args.protected_configuration_fd)
        result = advance_fd(args.journal_fd, json.loads(args.request_json), mode=args.mode, provisioning=json.loads(args.provisioning_json), live_receipt_fd=args.live_receipt_fd, task_selector=args.task_selector, candidate_fds=candidate_fds, fixed_configuration=fixed_configuration)
    except (LifecycleExecutionError, ProvisioningError, ProtectedBackendError, CandidateAdmissionError, json.JSONDecodeError) as exc:
        print(json.dumps({"state": "rejected", "error": {"code": getattr(exc, "code", "input_invalid")}, "production_ready": False}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__": raise SystemExit(main())
