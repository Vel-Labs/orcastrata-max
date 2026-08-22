#!/usr/bin/env python3
"""Fail-closed client and source-local journal for the protected receiver.

This module cannot authenticate a production transaction. Socket responses are
validated for substitution and drift, then projected as pending only.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
from typing import Any, Mapping, Sequence

FIXED_RECEIVER_SOCKET = "/var/run/codexmax/protected-provider-receiver-v1.sock"
STATES = ("pending_host_facts", "generation_reserved", "launch_attested",
          "transaction_issued", "transaction_consuming", "consumed_success",
          "consumed_failure", "execution_unknown", "revoked")
_SELECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESPONSE_FIELDS = frozenset({"schema_version", "artifact_type", "status", "task_selector",
    "expected_generation", "challenge_sha256", "service_start_id", "service_session_id",
    "transaction_record_sha256", "writer_record", "anchor_record"})
_EVENT_FIELDS = frozenset({"schema_version", "artifact_type", "sequence", "prior_state", "state",
    "task_selector", "generation", "bindings_sha256", "writer_record", "anchor_record",
    "prior_event_sha256", "event_sha256"})
_WRITER_FIELDS = frozenset({"schema_version", "artifact_type", "role", "sequence", "state",
    "task_selector", "generation", "bindings_sha256", "transition_sha256", "record_sha256"})
_ANCHOR_FIELDS = frozenset({"schema_version", "artifact_type", "role", "sequence", "state",
    "task_selector", "generation", "bindings_sha256", "transition_sha256",
    "writer_record_sha256", "record_sha256"})
_PROVIDER_BINDING_FIELDS = frozenset({"task_id", "route_name", "provider", "exact_model",
    "runtime", "billing_basis", "capability_sha256", "grant_sha256", "lease_id",
    "fencing_token", "attempt_id", "expires_at"})


class ProtectedReceiverError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise ProtectedReceiverError("json_invalid") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = dict(value); row[field] = ""; row[field] = _digest(row); return row


def _allowed_next(state: str | None) -> frozenset[str]:
    return {None: frozenset({"pending_host_facts"}),
        "pending_host_facts": frozenset({"generation_reserved", "revoked"}),
        "generation_reserved": frozenset({"launch_attested", "revoked"}),
        "launch_attested": frozenset({"transaction_issued", "revoked"}),
        "transaction_issued": frozenset({"transaction_consuming", "revoked"}),
        "transaction_consuming": frozenset({"consumed_success", "consumed_failure", "execution_unknown"}),
        "consumed_success": frozenset({"execution_unknown"}),
        "consumed_failure": frozenset({"execution_unknown"})}.get(state, frozenset())


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _transition(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in ("sequence", "prior_state", "state", "task_selector", "generation", "bindings_sha256")}


def _validate_records(row: Mapping[str, Any]) -> None:
    writer, anchor = row["writer_record"], row["anchor_record"]
    if not isinstance(writer, Mapping) or set(writer) != _WRITER_FIELDS:
        raise ProtectedReceiverError("writer_record_shape_invalid")
    if not isinstance(anchor, Mapping) or set(anchor) != _ANCHOR_FIELDS:
        raise ProtectedReceiverError("anchor_record_shape_invalid")
    transition_sha256 = _digest(_transition(row))
    common = {"sequence": row["sequence"], "state": row["state"], "task_selector": row["task_selector"],
              "generation": row["generation"], "bindings_sha256": row["bindings_sha256"],
              "transition_sha256": transition_sha256}
    for record, fields, code in ((writer, _WRITER_FIELDS, "writer_record_field_invalid"),
                                  (anchor, _ANCHOR_FIELDS, "anchor_record_field_invalid")):
        if (type(record.get("schema_version")) is not int or type(record.get("sequence")) is not int
                or type(record.get("generation")) is not int or record.get("sequence") < 1
                or record.get("generation") < 1 or not isinstance(record.get("artifact_type"), str)
                or not isinstance(record.get("role"), str) or not isinstance(record.get("state"), str)
                or not isinstance(record.get("task_selector"), str)
                or any(not _valid_sha(record.get(field)) for field in fields if field.endswith("sha256"))):
            raise ProtectedReceiverError(code)
    if writer.get("schema_version") != 1 or writer.get("artifact_type") != "codexmax_protected_writer_record_v1" or writer.get("role") != "protected_writer":
        raise ProtectedReceiverError("writer_record_identity_invalid")
    if anchor.get("schema_version") != 1 or anchor.get("artifact_type") != "codexmax_independent_anchor_record_v1" or anchor.get("role") != "independent_anchor":
        raise ProtectedReceiverError("anchor_record_identity_invalid")
    if any(writer.get(k) != v or anchor.get(k) != v for k, v in common.items()):
        raise ProtectedReceiverError("writer_anchor_binding_divergence")
    if _seal(writer, "record_sha256") != dict(writer):
        raise ProtectedReceiverError("writer_record_continuity_invalid")
    if anchor.get("writer_record_sha256") != writer.get("record_sha256") or _seal(anchor, "record_sha256") != dict(anchor):
        raise ProtectedReceiverError("anchor_record_continuity_invalid")


def _validate_response_records(response: Mapping[str, Any]) -> None:
    writer, anchor = response["writer_record"], response["anchor_record"]
    if not isinstance(writer, Mapping) or set(writer) != _WRITER_FIELDS:
        raise ProtectedReceiverError("receiver_writer_record_shape_invalid")
    if not isinstance(anchor, Mapping) or set(anchor) != _ANCHOR_FIELDS:
        raise ProtectedReceiverError("receiver_anchor_record_shape_invalid")
    for record, code in ((writer, "receiver_writer_record_invalid"), (anchor, "receiver_anchor_record_invalid")):
        if (type(record.get("schema_version")) is not int or type(record.get("sequence")) is not int
                or type(record.get("generation")) is not int or record.get("sequence") < 1
                or record.get("generation") < 1 or not isinstance(record.get("artifact_type"), str)
                or not isinstance(record.get("role"), str) or not isinstance(record.get("state"), str)
                or not isinstance(record.get("task_selector"), str)
                or any(not _valid_sha(record.get(field)) for field in record if field.endswith("sha256"))):
            raise ProtectedReceiverError(code)
    if (writer["artifact_type"] != "codexmax_protected_writer_record_v1" or writer["role"] != "protected_writer"
            or anchor["artifact_type"] != "codexmax_independent_anchor_record_v1" or anchor["role"] != "independent_anchor"):
        raise ProtectedReceiverError("receiver_record_identity_invalid")
    for field, expected in (("task_selector", response["task_selector"]),
                            ("generation", response["expected_generation"]), ("state", response["status"])):
        if writer[field] != expected or anchor[field] != expected:
            raise ProtectedReceiverError("receiver_record_binding_drift")
    if any(writer[field] != anchor[field] for field in ("sequence", "bindings_sha256", "transition_sha256")):
        raise ProtectedReceiverError("receiver_record_divergence")
    if _seal(writer, "record_sha256") != dict(writer) or anchor["writer_record_sha256"] != writer["record_sha256"] or _seal(anchor, "record_sha256") != dict(anchor):
        raise ProtectedReceiverError("receiver_record_continuity_invalid")


def verify_journal(data: bytes) -> dict[str, Any]:
    state = {"sequence": 0, "state": None, "event_sha256": None, "task_selector": None,
             "generation": None, "bindings_sha256": None}
    if data and not data.endswith(b"\n"):
        raise ProtectedReceiverError("journal_crash_residue")
    try:
        rows = [json.loads(line) for line in data.decode().splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectedReceiverError("journal_corrupt") from exc
    for sequence, raw in enumerate(rows, 1):
        if not isinstance(raw, Mapping) or set(raw) != _EVENT_FIELDS:
            raise ProtectedReceiverError("event_shape_invalid")
        row = dict(raw)
        if (type(row["schema_version"]) is not int or row["schema_version"] != 1
                or not isinstance(row["artifact_type"], str)
                or row["artifact_type"] != "codexmax_protected_receiver_event_v1"):
            raise ProtectedReceiverError("event_identity_invalid")
        if type(row["sequence"]) is not int or row["sequence"] != sequence or row["state"] not in STATES:
            raise ProtectedReceiverError("event_sequence_or_state_invalid")
        if row["prior_state"] != state["state"] or row["prior_event_sha256"] != state["event_sha256"]:
            raise ProtectedReceiverError("event_chain_invalid")
        if (not isinstance(row["task_selector"], str) or _SELECTOR.fullmatch(row["task_selector"]) is None
                or type(row["generation"]) is not int or row["generation"] < 1 or not _valid_sha(row["bindings_sha256"])):
            raise ProtectedReceiverError("event_field_invalid")
        if not _valid_sha(row["event_sha256"]) or _seal(row, "event_sha256") != row:
            raise ProtectedReceiverError("event_continuity_invalid")
        if row["state"] not in _allowed_next(state["state"]):
            raise ProtectedReceiverError("transition_invalid")
        for field in ("task_selector", "generation", "bindings_sha256"):
            if state[field] is not None and row[field] != state[field]:
                raise ProtectedReceiverError("transaction_binding_drift")
        _validate_records(row)
        state.update({"sequence": sequence, "state": row["state"], "event_sha256": row["event_sha256"],
                      "task_selector": row["task_selector"], "generation": row["generation"],
                      "bindings_sha256": row["bindings_sha256"]})
    return state


def make_source_local_event(state: Mapping[str, Any], target: str, *, task_selector: str,
                            generation: int, bindings_sha256: str) -> dict[str, Any]:
    """Create non-authoritative test records with distinct writer and anchor roles."""
    sequence = state.get("sequence", 0) + 1
    base = {"sequence": sequence, "prior_state": state.get("state"), "state": target,
            "task_selector": task_selector, "generation": generation, "bindings_sha256": bindings_sha256}
    if target not in _allowed_next(state.get("state")):
        raise ProtectedReceiverError("transition_invalid")
    transition_sha256 = _digest(base)
    common = {"schema_version": 1, "sequence": sequence, "state": target, "task_selector": task_selector,
              "generation": generation, "bindings_sha256": bindings_sha256, "transition_sha256": transition_sha256}
    writer = _seal({**common, "artifact_type": "codexmax_protected_writer_record_v1", "role": "protected_writer", "record_sha256": ""}, "record_sha256")
    anchor = _seal({**common, "artifact_type": "codexmax_independent_anchor_record_v1", "role": "independent_anchor",
                    "writer_record_sha256": writer["record_sha256"], "record_sha256": ""}, "record_sha256")
    return _seal({"schema_version": 1, "artifact_type": "codexmax_protected_receiver_event_v1", **base,
                  "writer_record": writer, "anchor_record": anchor,
                  "prior_event_sha256": state.get("event_sha256"), "event_sha256": ""}, "event_sha256")


def recover_source_local_consuming(journal_fd: int) -> dict[str, Any]:
    """Mark an interrupted attempt unknown so it can never be retried."""
    fcntl.flock(journal_fd, fcntl.LOCK_EX)
    try:
        data = os.pread(journal_fd, os.fstat(journal_fd).st_size, 0)
        state = verify_journal(data)
        if state["state"] != "transaction_consuming":
            return {"status": "pending_host_facts", "recovered": False, "production_ready": False}
        event = make_source_local_event(state, "execution_unknown", task_selector=state["task_selector"],
                                        generation=state["generation"], bindings_sha256=state["bindings_sha256"])
        os.lseek(journal_fd, 0, os.SEEK_END); os.write(journal_fd, _canonical(event)); os.fsync(journal_fd)
        verify_journal(os.pread(journal_fd, os.fstat(journal_fd).st_size, 0))
        return {"status": "execution_unknown", "recovered": True, "production_ready": False,
                "authority_issued": False}
    finally:
        fcntl.flock(journal_fd, fcntl.LOCK_UN)


def _socket_identity(client: socket.socket) -> tuple[int, int, int, int, int]:
    info = os.fstat(client.fileno())
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _peer_identity(client: socket.socket) -> tuple[int, int]:
    if not hasattr(client, "getpeereid"):
        raise ProtectedReceiverError("kernel_peer_witness_unavailable")
    return tuple(int(v) for v in client.getpeereid())


def request_fixed_receiver(task_selector: str, *, expected_generation: int = 1,
                           service_start_id: str = "pending-service-start",
                           service_session_id: str = "pending-service-session",
                           expected_receiver_uid: int | None = None, timeout: float = 1.0,
                           provider_binding: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if (not isinstance(task_selector, str) or _SELECTOR.fullmatch(task_selector) is None
            or type(expected_generation) is not int or expected_generation < 1
            or not isinstance(service_start_id, str) or _ID.fullmatch(service_start_id) is None
            or not isinstance(service_session_id, str) or _ID.fullmatch(service_session_id) is None):
        raise ProtectedReceiverError("request_binding_invalid")
    if expected_receiver_uid is not None and (type(expected_receiver_uid) is not int or expected_receiver_uid < 0):
        raise ProtectedReceiverError("receiver_uid_invalid")
    challenge = os.urandom(32); challenge_sha256 = "sha256:" + hashlib.sha256(challenge).hexdigest()
    request = {"schema_version": 1, "operation": "consume_task", "task_selector": task_selector,
               "expected_generation": expected_generation, "challenge_sha256": challenge_sha256,
               "service_start_id": service_start_id, "service_session_id": service_session_id}
    expected_binding_sha256 = None
    if provider_binding is not None:
        if set(provider_binding) != _PROVIDER_BINDING_FIELDS:
            raise ProtectedReceiverError("provider_binding_shape_invalid")
        if (any(not isinstance(provider_binding.get(field), str) or not provider_binding[field]
                for field in _PROVIDER_BINDING_FIELDS - {"fencing_token"})
                or type(provider_binding.get("fencing_token")) is not int
                or provider_binding["fencing_token"] < 1
                or provider_binding["billing_basis"] != "subscription"
                or any(not _valid_sha(provider_binding[field]) for field in ("capability_sha256", "grant_sha256"))):
            raise ProtectedReceiverError("provider_binding_field_invalid")
        expected_binding_sha256 = _digest(dict(provider_binding))
        request["provider_binding"] = dict(provider_binding)
    client = None
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.settimeout(timeout); client.connect(FIXED_RECEIVER_SOCKET)
        before_socket = _socket_identity(client); before_peer = _peer_identity(client)
        if expected_receiver_uid is None or before_peer[0] != expected_receiver_uid or before_peer[0] == os.geteuid():
            return {"status": "pending_host_facts", "provider_call_performed": False, "production_ready": False,
                    "reason": "distinct_authenticated_receiver_unavailable"}
        wire = _canonical(request); client.sendall(struct.pack("!I", len(wire)) + wire)
        header = client.recv(4)
        if len(header) != 4: raise ProtectedReceiverError("receiver_frame_truncated")
        length = struct.unpack("!I", header)[0]
        if length < 2 or length > 262144: raise ProtectedReceiverError("receiver_frame_invalid")
        chunks = bytearray()
        while len(chunks) < length:
            chunk = client.recv(length - len(chunks))
            if not chunk: raise ProtectedReceiverError("receiver_frame_truncated")
            chunks.extend(chunk)
        after_socket = _socket_identity(client); after_peer = _peer_identity(client)
        if before_socket != after_socket: raise ProtectedReceiverError("receiver_socket_identity_drift")
        if before_peer != after_peer: raise ProtectedReceiverError("receiver_peer_identity_drift")
    except FileNotFoundError:
        return {"status": "pending_host_facts", "provider_call_performed": False, "production_ready": False, "reason": "fixed_receiver_unavailable"}
    except OSError as exc:
        return {"status": "pending_host_facts", "provider_call_performed": False, "production_ready": False, "reason": "fixed_receiver_unavailable:" + type(exc).__name__}
    finally:
        if client is not None: client.close()
    try: response = json.loads(chunks)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ProtectedReceiverError("receiver_response_invalid") from exc
    if not isinstance(response, Mapping) or set(response) != _RESPONSE_FIELDS:
        raise ProtectedReceiverError("receiver_response_shape_invalid")
    if (type(response.get("schema_version")) is not int or type(response.get("expected_generation")) is not int
            or not isinstance(response.get("artifact_type"), str) or not isinstance(response.get("status"), str)
            or not isinstance(response.get("task_selector"), str) or not isinstance(response.get("service_start_id"), str)
            or not isinstance(response.get("service_session_id"), str) or not _valid_sha(response.get("challenge_sha256"))
            or response.get("status") not in {"transaction_consuming", "consumed_success", "consumed_failure", "revoked"}
            or not _valid_sha(response.get("transaction_record_sha256"))
            or not isinstance(response.get("writer_record"), Mapping)
            or not isinstance(response.get("anchor_record"), Mapping)):
        raise ProtectedReceiverError("receiver_response_field_invalid")
    _validate_response_records(response)
    if expected_binding_sha256 is not None and response["writer_record"]["bindings_sha256"] != expected_binding_sha256:
        raise ProtectedReceiverError("receiver_provider_binding_drift")
    exact = {"schema_version": 1, "artifact_type": "codexmax_protected_receiver_response_v1",
             "task_selector": task_selector, "expected_generation": expected_generation,
             "challenge_sha256": challenge_sha256, "service_start_id": service_start_id,
             "service_session_id": service_session_id}
    if any(response.get(k) != v for k, v in exact.items()):
        raise ProtectedReceiverError("receiver_response_binding_drift")
    # Python cannot authenticate the protected transaction records. Even a
    # well-formed terminal response remains pending and can never authorize a
    # caller-side provider process.
    return {"status": "pending_host_facts", "provider_call_performed": False, "production_ready": False,
            "reason": "production_protected_transaction_authentication_unavailable"}


def request_provider_authority(*, card: Mapping[str, Any], grant: Mapping[str, Any],
                               attempt_id: str, service_start_id: str,
                               service_session_id: str, expected_generation: int = 1,
                               expected_receiver_uid: int | None = None) -> dict[str, Any]:
    """Request an exact receiver-owned authority transaction.

    A caller mapping only states requested bindings. It never mints authority.
    This Python client always returns pending until the OS-protected receiver
    can authenticate and consume the transaction for the launched process.
    """
    binding = {"task_id": grant.get("task_id"), "route_name": grant.get("route_name"),
        "provider": card.get("provider"), "exact_model": card.get("exact_model"),
        "runtime": card.get("runtime"), "billing_basis": card.get("billing_basis"),
        "capability_sha256": card.get("capability_sha256"), "grant_sha256": grant.get("grant_sha256"),
        "lease_id": grant.get("lease_id"), "fencing_token": grant.get("fencing_token"),
        "attempt_id": attempt_id, "expires_at": grant.get("expires_at")}
    return request_fixed_receiver(str(grant.get("task_id", "")), expected_generation=expected_generation,
        service_start_id=service_start_id, service_session_id=service_session_id,
        expected_receiver_uid=expected_receiver_uid, provider_binding=binding)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Request the fixed protected provider receiver.")
    parser.add_argument("--task-selector", required=True); parser.add_argument("--expected-generation", type=int, default=1)
    parser.add_argument("--service-start-id", default="pending-service-start"); parser.add_argument("--service-session-id", default="pending-service-session")
    args = parser.parse_args(argv)
    try: result = request_fixed_receiver(args.task_selector, expected_generation=args.expected_generation,
        service_start_id=args.service_start_id, service_session_id=args.service_session_id)
    except ProtectedReceiverError as exc:
        print(json.dumps({"status": "rejected", "error": {"code": exc.code}, "provider_call_performed": False}), file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 4


if __name__ == "__main__": raise SystemExit(main())
