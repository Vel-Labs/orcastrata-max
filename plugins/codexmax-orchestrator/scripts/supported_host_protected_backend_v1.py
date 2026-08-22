#!/usr/bin/env python3
"""Package-owned protected receiver and durable lifecycle backend.

Production mode owns one fixed AF_UNIX socket and accepts only inherited file
descriptors. Source-local mode uses an inherited socket and temporary roots. It
can test the full state machine, but it never creates production authority.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import weakref

from supported_host_candidate_admission_v1 import (
    CandidateAdmissionError,
    VerifiedSelectedCandidate,
    verify_selected_candidate_fds,
)
FIXED_RECEIVER_SOCKET = "/var/run/codexmax/protected-provider-receiver-v1.sock"
DEPLOYMENT_BOOTSTRAP_SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v2"
PROTOCOL_VERSION = "supported_host_protected_backend_v1"
REQUEST_TYPE = "codexmax_protected_backend_request_v1"
RESPONSE_TYPE = "codexmax_protected_backend_response_v1"
OPERATIONS = (
    "install", "start", "handshake", "admit", "journey", "stop",
    "inventory", "reconcile", "cleanup",
)
TERMINAL_STATES = frozenset({"CLEANED", "REVOKED", "EXECUTION_UNKNOWN"})
MAX_FRAME_BYTES = 262_144
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}$")
_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "operation",
    "run_id", "attempt_id", "expected_revision", "candidate_generation",
    "candidate_descriptor_sha256", "challenge_sha256", "opaque_agent_ref",
    "public_receipts",
})
_PUBLIC_RECEIPT_FIELDS = frozenset({
    "certificate_receipt_sha256", "handshake_receipt_sha256",
})
_WRITER_FIELDS = frozenset({
    "schema_version", "artifact_type", "sequence", "revision", "run_id", "attempt_id",
    "operation", "state", "candidate_generation",
    "candidate_descriptor_sha256", "challenge_sha256", "request_sha256",
    "os_facts_sha256", "previous_record_sha256", "record_sha256",
})
_ANCHOR_FIELDS = frozenset({
    "schema_version", "artifact_type", "sequence", "run_id", "attempt_id",
    "writer_sequence", "writer_record_sha256", "previous_record_sha256",
    "record_sha256",
})
_SENSITIVE = re.compile(r"(?:secret|password|private|token|keychain|credential_(?:path|value))", re.I)
_FIXED_CONFIG_FIELDS = frozenset({
    "schema_version", "artifact_type", "bootstrap_uid", "bootstrap_gid",
    "bootstrap_groups", "bootstrap_build_sha256", "bootstrap_start_id",
    "bootstrap_session_id", "runtime_uid", "runtime_gid", "receiver_uid",
    "writer_uid", "anchor_uid",
})
_FIXED_CONFIG_AUTHORITY = object()
_PRODUCTION_TRANSACTION_AUTHORITY = object()

_CHANNEL_IDENTITY_FIELDS = frozenset({
    "uid", "service_id", "service_build_sha256", "service_start_id",
    "service_session_id",
})


class ProtectedBackendError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _descriptor_call(code: str, operation: Any, /, *args: Any, **kwargs: Any) -> Any:
    """Translate filesystem and descriptor syscall failures into closed errors."""
    try:
        return operation(*args, **kwargs)
    except OSError as exc:
        raise ProtectedBackendError(code) from exc


def _close_descriptor(fd: int, code: str) -> None:
    _descriptor_call(code, os.close, fd)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest(value: Mapping[str, Any] | bytes) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = dict(value)
    row[field] = ""
    row[field] = _digest(row)
    return row


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ProtectedBackendError(code, path)
    return dict(value)


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None or _SENSITIVE.search(value):
        raise ProtectedBackendError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ProtectedBackendError("sha256_invalid", path)
    return value


def validate_request(value: Any) -> Mapping[str, Any]:
    row = _closed(value, _REQUEST_FIELDS, "request_shape_invalid", "$.request")
    if row["schema_version"] != 1 or row["artifact_type"] != REQUEST_TYPE or row["protocol_version"] != PROTOCOL_VERSION:
        raise ProtectedBackendError("request_identity_invalid", "$.request")
    if row["operation"] not in OPERATIONS:
        raise ProtectedBackendError("operation_invalid", "$.request.operation")
    for field in ("run_id", "attempt_id", "opaque_agent_ref"):
        _identifier(row[field], "$.request." + field)
    if type(row["expected_revision"]) is not int or row["expected_revision"] < 0:
        raise ProtectedBackendError("revision_invalid", "$.request.expected_revision")
    if type(row["candidate_generation"]) is not int or row["candidate_generation"] < 1:
        raise ProtectedBackendError("generation_invalid", "$.request.candidate_generation")
    for field in ("candidate_descriptor_sha256", "challenge_sha256"):
        _sha(row[field], "$.request." + field)
    receipts = _closed(row["public_receipts"], _PUBLIC_RECEIPT_FIELDS, "public_receipts_shape_invalid", "$.request.public_receipts")
    for field, digest in receipts.items():
        _sha(digest, "$.request.public_receipts." + field)
    # The closed request is also the credential boundary. It has no endpoint,
    # path, executable, callback, authority mapping, private value, or digest
    # supplied as an assertion about the service itself.
    encoded = json.dumps(row, sort_keys=True)
    if _SENSITIVE.search(encoded):
        raise ProtectedBackendError("private_material_forbidden", "$.request")
    return MappingProxyType(row)


class FixedProtectedBackendConfiguration:
    """Opaque configuration read from one root-owned inherited descriptor."""

    __slots__ = ("_row", "_authority")

    def __init__(self, row: Mapping[str, Any], authority: object = None) -> None:
        if authority is not _FIXED_CONFIG_AUTHORITY:
            raise ProtectedBackendError("fixed_protected_configuration_not_mintable")
        self._row = MappingProxyType(dict(row))
        self._authority = authority

    def _require(self) -> Mapping[str, Any]:
        if getattr(self, "_authority", None) is not _FIXED_CONFIG_AUTHORITY:
            raise ProtectedBackendError("fixed_protected_configuration_forged")
        return self._row


def load_fixed_protected_configuration(config_fd: int) -> FixedProtectedBackendConfiguration:
    """Read canonical public identity policy from one protected regular file."""
    if type(config_fd) is not int or config_fd < 0:
        raise ProtectedBackendError("fixed_protected_configuration_fd_invalid")
    duplicate = _descriptor_call("fixed_protected_configuration_unavailable", os.dup, config_fd)
    try:
        before = _descriptor_call("fixed_protected_configuration_unavailable", os.fstat, duplicate)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 1 <= before.st_size <= 65536):
            raise ProtectedBackendError("fixed_protected_configuration_not_protected")
        raw = _descriptor_call("fixed_protected_configuration_read_failed", os.pread, duplicate, before.st_size + 1, 0)
        after = _descriptor_call("fixed_protected_configuration_unavailable", os.fstat, duplicate)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
            raise ProtectedBackendError("fixed_protected_configuration_drift")
    finally:
        _close_descriptor(duplicate, "fixed_protected_configuration_close_failed")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedBackendError("fixed_protected_configuration_json_invalid") from exc
    if raw != _canonical(value):
        raise ProtectedBackendError("fixed_protected_configuration_not_canonical")
    row = _closed(value, _FIXED_CONFIG_FIELDS, "fixed_protected_configuration_shape_invalid", "$.configuration")
    if row["schema_version"] != 1 or row["artifact_type"] != "codexmax_fixed_protected_backend_configuration_v1":
        raise ProtectedBackendError("fixed_protected_configuration_identity_invalid")
    for field in ("bootstrap_uid", "bootstrap_gid", "runtime_uid", "runtime_gid", "receiver_uid", "writer_uid", "anchor_uid"):
        if type(row[field]) is not int or row[field] < 1:
            raise ProtectedBackendError("fixed_protected_configuration_account_invalid", "$.configuration." + field)
    groups = row["bootstrap_groups"]
    if (not isinstance(groups, list) or not groups or any(type(value) is not int or value < 1 for value in groups)
            or groups != sorted(set(groups)) or row["bootstrap_gid"] not in groups):
        raise ProtectedBackendError("fixed_protected_configuration_groups_invalid")
    if len({row["runtime_uid"], row["receiver_uid"], row["writer_uid"], row["anchor_uid"]}) != 4:
        raise ProtectedBackendError("fixed_protected_configuration_identity_collision")
    _sha(row["bootstrap_build_sha256"], "$.configuration.bootstrap_build_sha256")
    for field in ("bootstrap_start_id", "bootstrap_session_id"):
        _identifier(row[field], "$.configuration." + field)
    return FixedProtectedBackendConfiguration(row, _FIXED_CONFIG_AUTHORITY)


def _open_journal(root_fd: int, name: str, expected_owner_uid: int) -> int:
    if type(root_fd) is not int or root_fd < 0 or name not in {"writer.journal", "anchor.journal"}:
        raise ProtectedBackendError("journal_root_invalid")
    root = _descriptor_call("journal_root_unavailable", os.fstat, root_fd)
    if not stat.S_ISDIR(root.st_mode):
        raise ProtectedBackendError("journal_root_wrong_type")
    if root.st_uid != expected_owner_uid:
        raise ProtectedBackendError("journal_root_owner_invalid")
    if root.st_mode & 0o022:
        raise ProtectedBackendError("journal_root_mode_invalid")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=root_fd)
    except OSError as exc:
        code = {
            errno.ELOOP: "journal_path_symlink",
            errno.ENOENT: "journal_path_missing",
            errno.ENOTDIR: "journal_path_wrong_type",
            errno.EISDIR: "journal_path_wrong_type",
        }.get(exc.errno, "journal_open_failed")
        raise ProtectedBackendError(code) from exc
    try:
        info = _descriptor_call("journal_descriptor_unavailable", os.fstat, fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProtectedBackendError("journal_descriptor_wrong_type")
        if info.st_nlink != 1:
            raise ProtectedBackendError("journal_descriptor_link_count_invalid")
        if info.st_uid != expected_owner_uid:
            raise ProtectedBackendError("journal_descriptor_owner_invalid")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ProtectedBackendError("journal_descriptor_mode_invalid")
    except BaseException:
        _close_descriptor(fd, "journal_descriptor_close_failed")
        raise
    return fd


def _read_journal(fd: int, fields: frozenset[str], artifact_type: str) -> list[dict[str, Any]]:
    info = _descriptor_call("journal_descriptor_unavailable", os.fstat, fd)
    raw = _descriptor_call("journal_read_failed", os.pread, fd, info.st_size + 1, 0)
    if raw and not raw.endswith(b"\n"):
        raise ProtectedBackendError("journal_crash_residue")
    try:
        rows = [json.loads(line) for line in raw.decode().splitlines()]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedBackendError("journal_corrupt") from exc
    prior = None
    for sequence, item in enumerate(rows, 1):
        row = _closed(item, fields, "journal_record_shape_invalid", f"$.journal[{sequence}]")
        if row["schema_version"] != 1 or row["artifact_type"] != artifact_type or row["sequence"] != sequence:
            raise ProtectedBackendError("journal_record_identity_invalid", f"$.journal[{sequence}]")
        if row["previous_record_sha256"] != prior or _seal(row, "record_sha256") != row:
            raise ProtectedBackendError("journal_chain_invalid", f"$.journal[{sequence}]")
        prior = row["record_sha256"]
    return rows


def _append(fd: int, row: Mapping[str, Any]) -> None:
    _descriptor_call("journal_seek_failed", os.lseek, fd, 0, os.SEEK_END)
    raw = _canonical(row)
    if _descriptor_call("journal_write_failed", os.write, fd, raw) != len(raw):
        raise ProtectedBackendError("journal_short_write")
    _descriptor_call("journal_sync_failed", os.fsync, fd)


class DurableReceiverTransaction:
    """Source-local durability harness. It is never production authority."""

    def __init__(self, writer_root_fd: int, anchor_root_fd: int, *,
                 writer_uid: int | None = None, anchor_uid: int | None = None) -> None:
        writer_root = _descriptor_call("writer_root_unavailable", os.fstat, writer_root_fd)
        anchor_root = _descriptor_call("anchor_root_unavailable", os.fstat, anchor_root_fd)
        if (writer_root.st_dev, writer_root.st_ino) == (anchor_root.st_dev, anchor_root.st_ino):
            raise ProtectedBackendError("writer_anchor_root_collision")
        writer_uid = os.geteuid() if writer_uid is None else writer_uid
        anchor_uid = os.geteuid() if anchor_uid is None else anchor_uid
        if type(writer_uid) is not int or type(anchor_uid) is not int or writer_uid < 0 or anchor_uid < 0:
            raise ProtectedBackendError("journal_owner_invalid")
        self._writer_fd = _open_journal(writer_root_fd, "writer.journal", writer_uid)
        self._anchor_fd = -1
        self._writer_locked = False
        self._anchor_locked = False
        try:
            self._anchor_fd = _open_journal(anchor_root_fd, "anchor.journal", anchor_uid)
        except BaseException:
            _close_descriptor(self._writer_fd, "journal_descriptor_close_failed")
            self._writer_fd = -1
            raise

    def close(self) -> None:
        if self._writer_fd >= 0:
            _close_descriptor(self._writer_fd, "writer_journal_close_failed")
            self._writer_fd = -1
        if self._anchor_fd >= 0:
            _close_descriptor(self._anchor_fd, "anchor_journal_close_failed")
            self._anchor_fd = -1

    def _locked(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            _descriptor_call("writer_journal_lock_failed", fcntl.flock, self._writer_fd, fcntl.LOCK_EX)
            self._writer_locked = True
            _descriptor_call("anchor_journal_lock_failed", fcntl.flock, self._anchor_fd, fcntl.LOCK_EX)
            self._anchor_locked = True
            writers = _read_journal(self._writer_fd, _WRITER_FIELDS, "codexmax_protected_backend_writer_v1")
            anchors = _read_journal(self._anchor_fd, _ANCHOR_FIELDS, "codexmax_protected_backend_anchor_v1")
        except BaseException:
            self._unlock()
            raise
        anchored = {row["writer_sequence"]: row for row in anchors}
        if any(index < 1 or index > len(writers) or row["writer_record_sha256"] != writers[index - 1]["record_sha256"] for index, row in anchored.items()):
            raise ProtectedBackendError("writer_anchor_divergence")
        if sorted(anchored) != list(range(1, len(anchors) + 1)):
            raise ProtectedBackendError("anchor_sequence_divergence")
        if len(writers) - len(anchors) > 1:
            raise ProtectedBackendError("multiple_unanchored_writer_records")
        revisions: dict[str, int] = {}
        operations: dict[str, str] = {}
        for row in writers:
            prior_revision = revisions.get(row["run_id"], 0)
            if row["state"] in {"REVOKED", "EXECUTION_UNKNOWN"}:
                if prior_revision < 1 or row["revision"] != prior_revision or row["operation"] != operations[row["run_id"]]:
                    raise ProtectedBackendError("writer_revision_invalid")
            else:
                if row["revision"] != prior_revision + 1 or row["revision"] > len(OPERATIONS) or row["operation"] != OPERATIONS[row["revision"] - 1]:
                    raise ProtectedBackendError("writer_revision_invalid")
                revisions[row["run_id"]] = row["revision"]
                operations[row["run_id"]] = row["operation"]
        return writers, anchors

    def _unlock(self) -> None:
        first_error = None
        if self._anchor_locked:
            try:
                _descriptor_call("anchor_journal_unlock_failed", fcntl.flock, self._anchor_fd, fcntl.LOCK_UN)
            except ProtectedBackendError as exc:
                first_error = exc
            self._anchor_locked = False
        if self._writer_locked:
            try:
                _descriptor_call("writer_journal_unlock_failed", fcntl.flock, self._writer_fd, fcntl.LOCK_UN)
            except ProtectedBackendError as exc:
                first_error = first_error or exc
            self._writer_locked = False
        if first_error is not None:
            raise first_error

    def recover(self) -> Mapping[str, Any]:
        try:
            writers, anchors = self._locked()
            if len(writers) == len(anchors):
                return MappingProxyType({"recovered": False, "state": writers[-1]["state"] if writers else None})
            dangling = writers[-1]
            dangling_anchor = _seal({
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_anchor_v1",
                "sequence": len(anchors) + 1,
                "run_id": dangling["run_id"],
                "attempt_id": dangling["attempt_id"],
                "writer_sequence": dangling["sequence"],
                "writer_record_sha256": dangling["record_sha256"],
                "previous_record_sha256": anchors[-1]["record_sha256"] if anchors else None,
                "record_sha256": "",
            }, "record_sha256")
            _append(self._anchor_fd, dangling_anchor)
            if dangling["state"] != "EXECUTION_UNKNOWN":
                unknown = _seal({
                    **{key: dangling[key] for key in (
                        "run_id", "attempt_id", "candidate_generation",
                        "candidate_descriptor_sha256", "challenge_sha256",
                        "request_sha256", "os_facts_sha256",
                    )},
                    "schema_version": 1,
                    "artifact_type": "codexmax_protected_backend_writer_v1",
                    "sequence": len(writers) + 1,
                    "revision": dangling["revision"],
                    "operation": dangling["operation"],
                    "state": "EXECUTION_UNKNOWN",
                    "previous_record_sha256": dangling["record_sha256"],
                    "record_sha256": "",
                }, "record_sha256")
                _append(self._writer_fd, unknown)
                anchor = _seal({
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_anchor_v1",
                "sequence": len(anchors) + 2,
                "run_id": unknown["run_id"],
                "attempt_id": unknown["attempt_id"],
                "writer_sequence": unknown["sequence"],
                "writer_record_sha256": unknown["record_sha256"],
                "previous_record_sha256": dangling_anchor["record_sha256"],
                "record_sha256": "",
                }, "record_sha256")
                _append(self._anchor_fd, anchor)
            return MappingProxyType({"recovered": True, "state": "EXECUTION_UNKNOWN"})
        finally:
            self._unlock()

    def observe(self, run_id: str) -> Mapping[str, Any]:
        """Return the last fully anchored record for one lifecycle run."""
        _identifier(run_id, "$.run_id")
        try:
            writers, anchors = self._locked()
            if len(writers) != len(anchors):
                raise ProtectedBackendError("recovery_required")
            matching = [row for row in writers if row["run_id"] == run_id]
            if not matching:
                return MappingProxyType({"revision": 0, "state": None})
            last = matching[-1]
            anchor = anchors[last["sequence"] - 1]
            if anchor["writer_record_sha256"] != last["record_sha256"]:
                raise ProtectedBackendError("writer_anchor_divergence")
            return MappingProxyType({
                "revision": last["revision"],
                "state": last["state"],
                "operation": last["operation"],
                "attempt_id": last["attempt_id"],
                "request_sha256": last["request_sha256"],
                "pre_operation_witness_sha256": last["os_facts_sha256"],
                "post_operation_witness_sha256": last["os_facts_sha256"],
                "writer_record_sha256": last["record_sha256"],
                "anchor_record_sha256": anchor["record_sha256"],
            })
        finally:
            self._unlock()

    def apply(self, request_value: Any, os_facts: Mapping[str, Any], *, crash_after_writer: bool = False) -> Mapping[str, Any]:
        request = validate_request(request_value)
        request_sha256 = _digest(dict(request))
        os_facts_sha256 = _digest(dict(os_facts))
        try:
            writers, anchors = self._locked()
            if len(writers) != len(anchors):
                raise ProtectedBackendError("recovery_required")
            matching = [row for row in writers if row["run_id"] == request["run_id"]]
            attempts = {row["attempt_id"] for row in writers}
            if request["attempt_id"] in attempts:
                prior = next(row for row in writers if row["attempt_id"] == request["attempt_id"])
                if (prior["request_sha256"] != request_sha256 or prior["run_id"] != request["run_id"]
                        or prior["operation"] != request["operation"] or prior["revision"] != request["expected_revision"] + 1):
                    raise ProtectedBackendError("attempt_replay")
                anchor = anchors[prior["sequence"] - 1] if prior["sequence"] <= len(anchors) else None
                if anchor is None or anchor["writer_record_sha256"] != prior["record_sha256"]:
                    raise ProtectedBackendError("recovery_required")
                return MappingProxyType({
                    "revision": prior["revision"], "state": prior["state"],
                    "writer_record_sha256": prior["record_sha256"],
                    "anchor_record_sha256": anchor["record_sha256"],
                    "reconciled": True,
                })
            if matching and matching[-1]["state"] in TERMINAL_STATES:
                raise ProtectedBackendError("transaction_terminal")
            revision = matching[-1]["revision"] if matching else 0
            if request["expected_revision"] != revision or request["operation"] != OPERATIONS[revision]:
                raise ProtectedBackendError("lifecycle_cas_or_order_invalid")
            if matching and any(
                request[field] != matching[0][field]
                for field in ("candidate_generation", "candidate_descriptor_sha256")
            ):
                raise ProtectedBackendError("candidate_binding_drift")
            state = {
                "install": "INSTALLED", "start": "STARTED",
                "handshake": "HANDSHAKE_VALIDATED", "admit": "ADMITTED",
                "journey": "JOURNEY_COMPLETED", "stop": "STOPPED",
                "inventory": "INVENTORIED", "reconcile": "RECONCILED",
                "cleanup": "CLEANED",
            }[request["operation"]]
            writer = _seal({
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_writer_v1",
                "sequence": len(writers) + 1,
                "revision": revision + 1,
                "run_id": request["run_id"],
                "attempt_id": request["attempt_id"],
                "operation": request["operation"],
                "state": state,
                "candidate_generation": request["candidate_generation"],
                "candidate_descriptor_sha256": request["candidate_descriptor_sha256"],
                "challenge_sha256": request["challenge_sha256"],
                "request_sha256": request_sha256,
                "os_facts_sha256": os_facts_sha256,
                "previous_record_sha256": writers[-1]["record_sha256"] if writers else None,
                "record_sha256": "",
            }, "record_sha256")
            _append(self._writer_fd, writer)
            if crash_after_writer:
                raise ProtectedBackendError("source_local_injected_crash")
            anchor = _seal({
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_anchor_v1",
                "sequence": len(anchors) + 1,
                "run_id": request["run_id"],
                "attempt_id": request["attempt_id"],
                "writer_sequence": writer["sequence"],
                "writer_record_sha256": writer["record_sha256"],
                "previous_record_sha256": anchors[-1]["record_sha256"] if anchors else None,
                "record_sha256": "",
            }, "record_sha256")
            _append(self._anchor_fd, anchor)
            return MappingProxyType({
                "revision": revision + 1,
                "state": state,
                "writer_record_sha256": writer["record_sha256"],
                "anchor_record_sha256": anchor["record_sha256"],
                "reconciled": False,
            })
        finally:
            self._unlock()

    def revoke(self, run_id: str, attempt_id: str, reason_sha256: str) -> Mapping[str, Any]:
        """Revoke a non-consuming run through both durable records."""
        _identifier(run_id, "$.run_id")
        _identifier(attempt_id, "$.attempt_id")
        _sha(reason_sha256, "$.reason_sha256")
        try:
            writers, anchors = self._locked()
            matching = [row for row in writers if row["run_id"] == run_id]
            if not matching or len(writers) != len(anchors):
                raise ProtectedBackendError("revocation_target_unavailable")
            last = matching[-1]
            if last["state"] in TERMINAL_STATES:
                raise ProtectedBackendError("transaction_terminal")
            if any(row["attempt_id"] == attempt_id for row in writers):
                raise ProtectedBackendError("attempt_replay")
            writer = _seal({
                **{key: last[key] for key in (
                    "run_id", "candidate_generation", "candidate_descriptor_sha256",
                    "challenge_sha256", "os_facts_sha256",
                )},
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_writer_v1",
                "sequence": len(writers) + 1, "attempt_id": attempt_id,
                "revision": last["revision"],
                "operation": last["operation"], "state": "REVOKED",
                "request_sha256": reason_sha256,
                "previous_record_sha256": writers[-1]["record_sha256"],
                "record_sha256": "",
            }, "record_sha256")
            _append(self._writer_fd, writer)
            anchor = _seal({
                "schema_version": 1,
                "artifact_type": "codexmax_protected_backend_anchor_v1",
                "sequence": len(anchors) + 1, "run_id": run_id,
                "attempt_id": attempt_id, "writer_sequence": writer["sequence"],
                "writer_record_sha256": writer["record_sha256"],
                "previous_record_sha256": anchors[-1]["record_sha256"],
                "record_sha256": "",
            }, "record_sha256")
            _append(self._anchor_fd, anchor)
            return MappingProxyType({"state": "REVOKED", "writer_record_sha256": writer["record_sha256"], "anchor_record_sha256": anchor["record_sha256"]})
        finally:
            self._unlock()


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
        ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
        ("svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
        ("pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
        ("start_tvsec", ctypes.c_uint64), ("start_tvusec", ctypes.c_uint64),
    ]


def collect_live_os_facts(channel: socket.socket, *, expected_peer_uid: int, expected_peer_gid: int,
                          protected_root_fds: Sequence[int], service_uids: Sequence[int]) -> Mapping[str, Any]:
    """Collect Darwin peer, process-start, executable-vnode, and root facts."""
    if sys.platform != "darwin" or not hasattr(channel, "getpeereid"):
        raise ProtectedBackendError("darwin_os_facts_unavailable")
    if len(set(service_uids)) != len(service_uids) or os.geteuid() not in service_uids or expected_peer_uid in service_uids:
        raise ProtectedBackendError("distinct_service_identity_required")
    peer_uid, peer_gid = (int(value) for value in channel.getpeereid())
    if (peer_uid, peer_gid) != (expected_peer_uid, expected_peer_gid) or peer_uid == os.geteuid():
        raise ProtectedBackendError("peer_identity_mismatch")
    try:
        peer_pid = struct.unpack("i", channel.getsockopt(0, 2, 4))[0]  # Darwin LOCAL_PEERPID.
    except (OSError, struct.error) as exc:
        raise ProtectedBackendError("peer_pid_unavailable") from exc
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = _ProcBsdInfo()
    if libproc.proc_pidinfo(peer_pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
        raise ProtectedBackendError("peer_process_start_unavailable")
    path_buffer = ctypes.create_string_buffer(4096)
    if libproc.proc_pidpath(peer_pid, path_buffer, len(path_buffer)) <= 0:
        raise ProtectedBackendError("peer_executable_unavailable")
    executable = _descriptor_call(
        "peer_executable_open_failed", os.open, path_buffer.value,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = _descriptor_call("peer_executable_stat_failed", os.fstat, executable)
        executable_bytes = _descriptor_call("peer_executable_read_failed", os.pread, executable, before.st_size, 0)
        code_identity = hashlib.sha256(executable_bytes).hexdigest()
        after = _descriptor_call("peer_executable_stat_failed", os.fstat, executable)
    finally:
        _close_descriptor(executable, "peer_executable_close_failed")
    vnode = (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_size, before.st_mtime_ns)
    if vnode != (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_size, after.st_mtime_ns):
        raise ProtectedBackendError("peer_executable_vnode_drift")
    roots = []
    for fd in protected_root_fds:
        root = _descriptor_call("protected_root_unavailable", os.fstat, fd)
        if not stat.S_ISDIR(root.st_mode) or root.st_mode & 0o022:
            raise ProtectedBackendError("protected_root_invalid")
        roots.append((root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode))
    if len(set((item[0], item[1]) for item in roots)) != len(roots):
        raise ProtectedBackendError("protected_root_collision")
    return MappingProxyType({
        "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid,
        "peer_process_start": [info.start_tvsec, info.start_tvusec],
        "peer_executable_vnode": list(vnode),
        "peer_code_identity_sha256": "sha256:" + code_identity,
        "protected_roots": [list(item) for item in roots],
        "service_uids": list(service_uids),
    })


def source_local_os_facts(channel: socket.socket, protected_root_fds: Sequence[int]) -> Mapping[str, Any]:
    """Collect real descriptor facts but mark them permanently non-authoritative."""
    roots = [_descriptor_call("protected_root_unavailable", os.fstat, fd) for fd in protected_root_fds]
    return MappingProxyType({
        "scope": "source_local_temp_root_non_production",
        "peer_uid": os.geteuid(), "peer_gid": os.getegid(),
        "peer_process_start": None, "peer_code_identity_sha256": None,
        "protected_roots": [[row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode] for row in roots],
        "production_authority": False,
    })


def collect_current_receiver_os_identity() -> Mapping[str, Any]:
    """Collect the current Darwin receiver process and executable identity."""
    if sys.platform != "darwin":
        raise ProtectedBackendError("darwin_receiver_identity_unavailable")
    pid = os.getpid()
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = _ProcBsdInfo()
    if libproc.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
        raise ProtectedBackendError("receiver_process_start_unavailable")
    path_buffer = ctypes.create_string_buffer(4096)
    if libproc.proc_pidpath(pid, path_buffer, len(path_buffer)) <= 0:
        raise ProtectedBackendError("receiver_executable_unavailable")
    executable = _descriptor_call(
        "receiver_executable_open_failed", os.open, path_buffer.value,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = _descriptor_call("receiver_executable_stat_failed", os.fstat, executable)
        raw = _descriptor_call("receiver_executable_read_failed", os.pread, executable, before.st_size, 0)
        after = _descriptor_call("receiver_executable_stat_failed", os.fstat, executable)
    finally:
        _close_descriptor(executable, "receiver_executable_close_failed")
    vnode_before = (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_size, before.st_mtime_ns)
    vnode_after = (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_size, after.st_mtime_ns)
    if vnode_before != vnode_after:
        raise ProtectedBackendError("receiver_executable_vnode_drift")
    return MappingProxyType({
        "pid": pid, "uid": os.geteuid(),
        "process_start_id": f"darwin:{pid}:{info.start_tvsec}:{info.start_tvusec}",
        "executable_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "executable_vnode": list(vnode_before),
    })


def _validate_admitted_receiver_identity(admission: Mapping[str, Any], selection: Mapping[str, Any],
                                          configuration: FixedProtectedBackendConfiguration) -> Mapping[str, Any]:
    config = configuration._require()
    receiver = selection["protected_receiver"]
    writer = selection["protected_writer"]
    anchor = selection["independent_anchor"]
    if (admission["candidate_descriptor_sha256"] != selection["descriptor_sha256"]
            or admission["candidate_id"] != selection["candidate_id"]
            or admission["generation"] != selection["generation"]):
        raise ProtectedBackendError("admission_selected_candidate_mismatch")
    if (admission["child_uid"] != config["receiver_uid"]
            or admission["child_executable_sha256"] != receiver["service_build_sha256"]
            or admission["child_start_id"] != receiver["service_start_id"]):
        raise ProtectedBackendError("admission_receiver_identity_mismatch")
    if (admission["writer_service_start_id"] != writer["service_start_id"]
            or admission["writer_service_session_id"] != writer["service_session_id"]
            or admission["anchor_service_start_id"] != anchor["service_start_id"]
            or admission["anchor_service_session_id"] != anchor["service_session_id"]):
        raise ProtectedBackendError("admission_writer_anchor_identity_mismatch")
    return MappingProxyType({
        "receiver": {**dict(receiver), "uid": config["receiver_uid"]},
        "writer": {**dict(writer), "uid": config["writer_uid"]},
        "anchor": {**dict(anchor), "uid": config["anchor_uid"]},
        "runtime_uid": config["runtime_uid"], "runtime_gid": config["runtime_gid"],
        "deployment_commit_sha256": admission["deployment_commit_sha256"],
        "receiver_pid": admission["child_pid"],
    })


def _backend_transaction_binding_store():
    """Keep transaction ownership outside mutable backend instance state."""
    bindings: weakref.WeakKeyDictionary[Any, tuple[Any, int]] = weakref.WeakKeyDictionary()

    def bind(owner: Any, transaction: Any) -> None:
        if owner in bindings:
            raise ProtectedBackendError("backend_transaction_already_bound")
        bindings[owner] = (transaction, id(transaction))

    def require(owner: Any) -> Any:
        binding = bindings.get(owner)
        if binding is None:
            raise ProtectedBackendError("backend_transaction_binding_unavailable")
        transaction, original_identity = binding
        if id(transaction) != original_identity:
            raise ProtectedBackendError("backend_transaction_identity_mismatch")
        return transaction

    return bind, require


_bind_backend_transaction, _require_bound_backend_transaction = _backend_transaction_binding_store()


class ProtectedReceiverBackend:
    __slots__ = (
        "_selected", "_selection", "_mode", "_roots", "_service_uids",
        "_production_identity", "__weakref__",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("protected_receiver_backend_is_final")

    def __init__(self, selected: VerifiedSelectedCandidate, transaction: Any,
                 *, mode: str, protected_root_fds: Sequence[int], service_uids: Sequence[int],
                 admission_source: Any | None = None,
                 fixed_configuration: FixedProtectedBackendConfiguration | None = None,
                 now: datetime | None = None) -> None:
        if type(selected) is not VerifiedSelectedCandidate:
            raise ProtectedBackendError("selected_candidate_authority_required")
        selection = selected.public_selection()
        self._selected = selected
        self._selection = selection
        self._mode = mode
        self._roots = tuple(protected_root_fds)
        self._service_uids = tuple(service_uids)
        self._production_identity = None
        if mode not in {"production", "source_local_harness"}:
            raise ProtectedBackendError("backend_mode_invalid")
        if mode == "source_local_harness":
            if admission_source is not None or fixed_configuration is not None:
                raise ProtectedBackendError("source_local_production_authority_forbidden")
            if type(transaction) is not DurableReceiverTransaction:
                raise ProtectedBackendError("source_local_transaction_type_required")
            _bind_backend_transaction(self, transaction)
            return
        from supported_host_protected_service_v1 import OsBoundDeploymentAdmissionV2Source
        if type(transaction) is not OpaqueProductionReceiverTransaction:
            raise ProtectedBackendError("opaque_production_transaction_type_required")
        if type(admission_source) is not OsBoundDeploymentAdmissionV2Source:
            raise ProtectedBackendError("one_use_deployment_admission_required")
        if type(fixed_configuration) is not FixedProtectedBackendConfiguration:
            raise ProtectedBackendError("fixed_protected_configuration_required")
        config = fixed_configuration._require()
        expected_channels = {
            "writer": {**dict(selection["protected_writer"]), "uid": config["writer_uid"]},
            "anchor": {**dict(selection["independent_anchor"]), "uid": config["anchor_uid"]},
        }
        # Validate every static prerequisite before consuming the one-use source.
        transaction.require_static_identities(expected_channels)
        try:
            admission = admission_source._consume_authenticated_admission(
                now=now if now is not None else datetime.now(timezone.utc)
            )
        except ValueError as exc:
            raise ProtectedBackendError(exc.code, exc.path) from exc
        self._production_identity = _validate_admitted_receiver_identity(
            admission, selection, fixed_configuration,
        )
        self._service_uids = tuple(
            self._production_identity[role]["uid"]
            for role in ("receiver", "writer", "anchor")
        )
        transaction.require_static_identities(self._production_identity)
        _bind_backend_transaction(self, transaction)

    @property
    def _transaction(self) -> Any:
        """Return the construction-bound transaction without a writable slot."""
        return self._require_transaction()

    def _require_transaction(self) -> Any:
        transaction = _require_bound_backend_transaction(self)
        if self._mode == "production":
            if type(transaction) is not OpaqueProductionReceiverTransaction:
                raise ProtectedBackendError("opaque_production_transaction_type_required")
            transaction._require()
        elif type(transaction) is not DurableReceiverTransaction:
            raise ProtectedBackendError("source_local_transaction_type_required")
        return transaction

    def observe(self, run_id: str) -> Mapping[str, Any]:
        transaction = self._require_transaction()
        return transaction.observe(run_id)

    def handle(self, channel: socket.socket, request_value: Any, *, crash_after_writer: bool = False) -> Mapping[str, Any]:
        request = validate_request(request_value)
        transaction = self._require_transaction()
        if request["candidate_generation"] != self._selection["generation"] or request["candidate_descriptor_sha256"] != self._selection["descriptor_sha256"]:
            raise ProtectedBackendError("selected_candidate_binding_mismatch")
        if self._mode == "production":
            if self._production_identity is None:
                raise ProtectedBackendError("production_authority_unavailable")
            identity = self._production_identity
            receiver_before = collect_current_receiver_os_identity()
            expected_receiver = identity["receiver"]
            if (receiver_before["pid"] != identity["receiver_pid"]
                    or receiver_before["uid"] != expected_receiver["uid"]
                    or receiver_before["process_start_id"] != expected_receiver["service_start_id"]
                    or receiver_before["executable_sha256"] != expected_receiver["service_build_sha256"]):
                raise ProtectedBackendError("accepted_receiver_process_identity_mismatch")
            before = collect_live_os_facts(
                channel, expected_peer_uid=identity["runtime_uid"],
                expected_peer_gid=identity["runtime_gid"],
                protected_root_fds=self._roots, service_uids=self._service_uids,
            )
            pre_witness = MappingProxyType({
                "receiver_process": dict(receiver_before),
                "runtime_process": dict(before),
            })
            observed = transaction.observe(request["run_id"])
            request_sha256 = _digest(dict(request))
            if observed["revision"] == request["expected_revision"] + 1:
                if (observed.get("attempt_id") != request["attempt_id"]
                        or observed.get("operation") != request["operation"]
                        or observed.get("request_sha256") != request_sha256):
                    raise ProtectedBackendError("production_observation_binding_mismatch")
                if observed["state"] == "EXECUTION_UNKNOWN":
                    raise ProtectedBackendError("production_operation_terminal_unknown")
                result = observed
            elif observed["revision"] == request["expected_revision"]:
                prepared = transaction.begin(request, pre_witness)
                try:
                    after = collect_live_os_facts(
                        channel, expected_peer_uid=identity["runtime_uid"],
                        expected_peer_gid=identity["runtime_gid"],
                        protected_root_fds=self._roots, service_uids=self._service_uids,
                    )
                    receiver_after = collect_current_receiver_os_identity()
                except BaseException:
                    transaction.commit(prepared, None, terminal_unknown=True)
                    raise
                post_witness = MappingProxyType({
                    "receiver_process": dict(receiver_after),
                    "runtime_process": dict(after),
                })
                if dict(pre_witness) != dict(post_witness):
                    transaction.commit(prepared, post_witness, terminal_unknown=True)
                    raise ProtectedBackendError("authority_process_identity_drift")
                result = transaction.commit(prepared, post_witness)
            else:
                raise ProtectedBackendError("production_observation_revision_mismatch")
            production = True
        else:
            facts = source_local_os_facts(channel, self._roots)
            production = False
            result = transaction.apply(request, facts, crash_after_writer=crash_after_writer)
            witness_sha256 = _digest(dict(facts))
            result = {**dict(result),
                      "pre_operation_witness_sha256": witness_sha256,
                      "post_operation_witness_sha256": witness_sha256}
        return MappingProxyType({
            "schema_version": 1, "artifact_type": RESPONSE_TYPE,
            "protocol_version": PROTOCOL_VERSION, "run_id": request["run_id"],
            "operation": request["operation"], "revision": result["revision"],
            "state": result["state"], "writer_record_sha256": result["writer_record_sha256"],
            "anchor_record_sha256": result["anchor_record_sha256"],
            "pre_operation_witness_sha256": result["pre_operation_witness_sha256"],
            "post_operation_witness_sha256": result["post_operation_witness_sha256"],
            "production_authority": production, "production_ready": production,
        })


def _receive(channel: socket.socket) -> Mapping[str, Any]:
    try:
        header = channel.recv(4)
    except OSError as exc:
        raise ProtectedBackendError("frame_receive_failed") from exc
    if len(header) != 4:
        raise ProtectedBackendError("frame_truncated")
    size = struct.unpack("!I", header)[0]
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise ProtectedBackendError("frame_size_invalid")
    data = bytearray()
    while len(data) < size:
        try:
            chunk = channel.recv(size - len(data))
        except OSError as exc:
            raise ProtectedBackendError("frame_receive_failed") from exc
        if not chunk:
            raise ProtectedBackendError("frame_truncated")
        data.extend(chunk)
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedBackendError("frame_json_invalid") from exc
    if bytes(data) != _canonical(value)[:-1]:
        raise ProtectedBackendError("frame_not_canonical")
    return value


def _send(channel: socket.socket, value: Mapping[str, Any]) -> None:
    data = _canonical(value)[:-1]
    try:
        channel.sendall(struct.pack("!I", len(data)) + data)
    except OSError as exc:
        raise ProtectedBackendError("frame_send_failed") from exc


def _channel_kernel_witness(channel: socket.socket, expected_uid: int) -> Mapping[str, Any]:
    """Return a stable kernel witness for one inherited service channel."""
    if not hasattr(channel, "getpeereid"):
        raise ProtectedBackendError("kernel_peer_witness_unavailable")
    info = _descriptor_call("production_channel_stat_failed", os.fstat, channel.fileno())
    if not stat.S_ISSOCK(info.st_mode):
        raise ProtectedBackendError("production_channel_descriptor_invalid")
    peer_uid, peer_gid = (int(value) for value in channel.getpeereid())
    if peer_uid != expected_uid or peer_uid == os.geteuid():
        raise ProtectedBackendError("production_channel_peer_identity_mismatch")
    return MappingProxyType({
        "device": info.st_dev,
        "inode": info.st_ino,
        "peer_uid": peer_uid,
        "peer_gid": peer_gid,
    })


class OpaqueProductionReceiverTransaction:
    """Closed production transaction over distinct authenticated OS channels."""

    __slots__ = (
        "_writer", "_anchor", "_expected", "_authority", "_channel_witnesses",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("opaque_production_transaction_is_final")

    def __init__(self, writer_fd: int, anchor_fd: int, expected: Mapping[str, Any],
                 authority: object = None) -> None:
        if authority is not _PRODUCTION_TRANSACTION_AUTHORITY:
            raise ProtectedBackendError("production_transaction_not_mintable")
        if type(writer_fd) is not int or type(anchor_fd) is not int or writer_fd < 0 or anchor_fd < 0:
            raise ProtectedBackendError("production_channel_fd_invalid")
        if writer_fd == anchor_fd:
            raise ProtectedBackendError("production_channel_descriptor_collision")
        expected_row = _closed(expected, frozenset({"writer", "anchor"}),
                               "production_channel_identity_invalid", "$.expected")
        identities: dict[str, Mapping[str, Any]] = {}
        for role in ("writer", "anchor"):
            identity = _closed(expected_row[role], _CHANNEL_IDENTITY_FIELDS,
                               "production_channel_identity_invalid", "$.expected." + role)
            if type(identity["uid"]) is not int or identity["uid"] < 1:
                raise ProtectedBackendError("production_channel_identity_invalid", "$.expected." + role + ".uid")
            for field in ("service_id", "service_start_id", "service_session_id"):
                _identifier(identity[field], "$.expected." + role + "." + field)
            _sha(identity["service_build_sha256"], "$.expected." + role + ".service_build_sha256")
            identities[role] = MappingProxyType(identity)
        if identities["writer"]["uid"] == identities["anchor"]["uid"]:
            raise ProtectedBackendError("independent_writer_anchor_ownership_required")
        writer = socket.fromfd(writer_fd, socket.AF_UNIX, socket.SOCK_STREAM)
        anchor = socket.fromfd(anchor_fd, socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            writer_witness = _channel_kernel_witness(writer, identities["writer"]["uid"])
            anchor_witness = _channel_kernel_witness(anchor, identities["anchor"]["uid"])
            if ((writer_witness["device"], writer_witness["inode"])
                    == (anchor_witness["device"], anchor_witness["inode"])):
                raise ProtectedBackendError("production_channel_descriptor_collision")
        except BaseException:
            writer.close()
            anchor.close()
            raise
        self._writer = writer
        self._anchor = anchor
        self._expected = MappingProxyType(identities)
        self._authority = authority
        self._channel_witnesses = MappingProxyType({"writer": writer_witness, "anchor": anchor_witness})

    def _require(self) -> None:
        if type(self) is not OpaqueProductionReceiverTransaction:
            raise ProtectedBackendError("opaque_production_transaction_type_required")
        if getattr(self, "_authority", None) is not _PRODUCTION_TRANSACTION_AUTHORITY:
            raise ProtectedBackendError("production_transaction_forged")

    def close(self) -> None:
        self._require()
        self._writer.close()
        self._anchor.close()

    def require_static_identities(self, expected: Mapping[str, Any]) -> None:
        """Validate protected identities before consuming one-use admission."""
        self._require()
        for role in ("writer", "anchor"):
            if dict(self._expected[role]) != {
                field: expected[role][field] for field in _CHANNEL_IDENTITY_FIELDS
            }:
                raise ProtectedBackendError("production_channel_identity_mismatch", "$." + role)
            current = _channel_kernel_witness(self._channel(role), self._expected[role]["uid"])
            if dict(current) != dict(self._channel_witnesses[role]):
                raise ProtectedBackendError("production_channel_identity_drift", "$." + role)

    def _channel(self, role: str) -> socket.socket:
        return self._writer if role == "writer" else self._anchor

    def _exchange(self, role: str, operation: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._require()
        channel = self._channel(role)
        expected = self._expected[role]
        before = _channel_kernel_witness(channel, expected["uid"])
        if dict(before) != dict(self._channel_witnesses[role]):
            raise ProtectedBackendError("production_channel_identity_drift", "$." + role)
        _send(channel, {
            "schema_version": 1,
            "artifact_type": "codexmax_production_transaction_request_v1",
            "operation": operation,
            "payload": dict(payload),
        })
        response = _receive(channel)
        after = _channel_kernel_witness(channel, expected["uid"])
        if dict(before) != dict(after):
            raise ProtectedBackendError("production_channel_identity_drift", "$." + role)
        row = _closed(response, frozenset({
            "schema_version", "artifact_type", "operation", "service_identity", "payload",
        }), "production_channel_response_invalid", "$." + role)
        if (row["schema_version"] != 1
                or row["artifact_type"] != "codexmax_production_transaction_response_v1"
                or row["operation"] != operation):
            raise ProtectedBackendError("production_channel_response_invalid", "$." + role)
        identity = _closed(row["service_identity"], _CHANNEL_IDENTITY_FIELDS,
                           "production_channel_session_identity_invalid", "$." + role + ".service_identity")
        if identity != dict(expected):
            raise ProtectedBackendError("production_channel_session_identity_mismatch", "$." + role)
        if not isinstance(row["payload"], Mapping):
            raise ProtectedBackendError("production_channel_response_invalid", "$." + role + ".payload")
        return MappingProxyType(dict(row["payload"]))

    def begin(self, request_value: Any, pre_witness: Mapping[str, Any]) -> Mapping[str, Any]:
        request = validate_request(request_value)
        pre_sha = _digest(dict(pre_witness))
        row = self._exchange("writer", "begin", {
            "request": dict(request), "request_sha256": _digest(dict(request)),
            "pre_operation_witness_sha256": pre_sha,
        })
        required = frozenset({
            "run_id", "attempt_id", "operation", "revision", "state",
            "request_sha256", "pre_operation_witness_sha256",
            "writer_record_sha256", "commit_token_sha256", "reconciled",
        })
        prepared = _closed(row, required, "production_writer_response_invalid", "$.writer")
        if (prepared["run_id"] != request["run_id"]
                or prepared["attempt_id"] != request["attempt_id"]
                or prepared["operation"] != request["operation"]
                or prepared["revision"] != request["expected_revision"] + 1
                or prepared["request_sha256"] != _digest(dict(request))
                or prepared["pre_operation_witness_sha256"] != pre_sha):
            raise ProtectedBackendError("production_writer_response_binding_mismatch")
        for field in ("writer_record_sha256", "commit_token_sha256"):
            _sha(prepared[field], "$.writer." + field)
        if type(prepared["reconciled"]) is not bool:
            raise ProtectedBackendError("production_writer_response_invalid")
        return MappingProxyType(prepared)

    def commit(self, prepared: Mapping[str, Any], post_witness: Mapping[str, Any] | None,
               *, terminal_unknown: bool = False) -> Mapping[str, Any]:
        post_sha = _digest(dict(post_witness)) if post_witness is not None else _digest({"witness": "missing"})
        row = self._exchange("anchor", "commit", {
            "prepared": dict(prepared),
            "post_operation_witness_sha256": post_sha,
            "terminal_unknown": terminal_unknown,
        })
        required = frozenset({
            "run_id", "attempt_id", "operation", "revision", "state",
            "request_sha256", "pre_operation_witness_sha256",
            "post_operation_witness_sha256", "writer_record_sha256",
            "anchor_record_sha256", "reconciled",
        })
        committed = _closed(row, required, "production_anchor_response_invalid", "$.anchor")
        for field in required - {"anchor_record_sha256", "post_operation_witness_sha256"}:
            if field in prepared and committed[field] != prepared[field]:
                raise ProtectedBackendError("production_anchor_response_binding_mismatch", "$.anchor." + field)
        if committed["post_operation_witness_sha256"] != post_sha:
            raise ProtectedBackendError("production_anchor_response_binding_mismatch")
        for field in ("writer_record_sha256", "anchor_record_sha256", "pre_operation_witness_sha256", "post_operation_witness_sha256"):
            _sha(committed[field], "$.anchor." + field)
        if terminal_unknown and committed["state"] != "EXECUTION_UNKNOWN":
            raise ProtectedBackendError("production_unknown_terminalization_failed")
        if not terminal_unknown and committed["state"] == "EXECUTION_UNKNOWN":
            raise ProtectedBackendError("production_operation_terminal_unknown")
        return MappingProxyType(committed)

    def observe(self, run_id: str) -> Mapping[str, Any]:
        """Observe only exact writer and anchor state. Never repeat an operation."""
        _identifier(run_id, "$.run_id")
        writer = self._exchange("writer", "observe", {"run_id": run_id})
        anchor = self._exchange("anchor", "observe", {"run_id": run_id})
        if not writer and not anchor:
            return MappingProxyType({"revision": 0, "state": None})
        if not writer or not anchor:
            raise ProtectedBackendError("production_recovery_terminal_unknown")
        required = frozenset({
            "run_id", "attempt_id", "operation", "revision", "state",
            "request_sha256", "pre_operation_witness_sha256",
            "post_operation_witness_sha256", "writer_record_sha256",
            "anchor_record_sha256",
        })
        observed = _closed(anchor, required, "production_observation_invalid", "$.anchor")
        if observed["run_id"] != run_id:
            raise ProtectedBackendError("production_observation_binding_mismatch")
        for field in required - {"anchor_record_sha256", "post_operation_witness_sha256"}:
            if field not in writer or writer[field] != observed[field]:
                raise ProtectedBackendError("production_observation_divergence", "$." + field)
        for field in ("request_sha256", "pre_operation_witness_sha256", "post_operation_witness_sha256", "writer_record_sha256", "anchor_record_sha256"):
            _sha(observed[field], "$.observation." + field)
        return MappingProxyType(observed)


def create_opaque_production_transaction(writer_channel_fd: int, anchor_channel_fd: int,
                                         selected: VerifiedSelectedCandidate,
                                         configuration: FixedProtectedBackendConfiguration) -> OpaqueProductionReceiverTransaction:
    """Mint the sole production transaction type from protected inherited FDs."""
    if type(selected) is not VerifiedSelectedCandidate:
        raise ProtectedBackendError("selected_candidate_authority_required")
    if type(configuration) is not FixedProtectedBackendConfiguration:
        raise ProtectedBackendError("fixed_protected_configuration_required")
    selection = selected.public_selection()
    config = configuration._require()
    expected = {
        "writer": {**dict(selection["protected_writer"]), "uid": config["writer_uid"]},
        "anchor": {**dict(selection["independent_anchor"]), "uid": config["anchor_uid"]},
    }
    return OpaqueProductionReceiverTransaction(
        writer_channel_fd, anchor_channel_fd, expected, _PRODUCTION_TRANSACTION_AUTHORITY,
    )


def request_fixed_backend(request_value: Any, *, selected: VerifiedSelectedCandidate,
                          fixed_configuration: FixedProtectedBackendConfiguration,
                          timeout: float = 5.0) -> Mapping[str, Any]:
    """Call only the fixed endpoint and authenticate its distinct kernel peer."""
    request = validate_request(request_value)
    if type(selected) is not VerifiedSelectedCandidate:
        raise ProtectedBackendError("selected_candidate_authority_required")
    if type(fixed_configuration) is not FixedProtectedBackendConfiguration:
        raise ProtectedBackendError("fixed_protected_configuration_required")
    selection = selected.public_selection()
    configuration = fixed_configuration._require()
    expected_receiver_uid = configuration["receiver_uid"]
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.settimeout(timeout)
    try:
        try:
            channel.connect(FIXED_RECEIVER_SOCKET)
        except OSError as exc:
            raise ProtectedBackendError("fixed_receiver_connect_failed") from exc
        before = _descriptor_call("receiver_channel_stat_failed", os.fstat, channel.fileno())
        if not hasattr(channel, "getpeereid"):
            raise ProtectedBackendError("kernel_peer_witness_unavailable")
        peer_before = tuple(int(value) for value in channel.getpeereid())
        if peer_before[0] != expected_receiver_uid or peer_before[0] == os.geteuid():
            raise ProtectedBackendError("distinct_receiver_identity_required")
        _send(channel, request)
        response = _receive(channel)
        after = _descriptor_call("receiver_channel_stat_failed", os.fstat, channel.fileno())
        peer_after = tuple(int(value) for value in channel.getpeereid())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or peer_before != peer_after:
            raise ProtectedBackendError("receiver_channel_identity_drift")
    finally:
        channel.close()
    required = {
        "schema_version", "artifact_type", "protocol_version", "run_id",
        "operation", "revision", "state", "writer_record_sha256",
        "anchor_record_sha256", "pre_operation_witness_sha256",
        "post_operation_witness_sha256", "production_authority", "production_ready",
    }
    if not isinstance(response, Mapping) or set(response) != required:
        raise ProtectedBackendError("response_shape_invalid")
    if any(response[field] != request[field] for field in ("run_id", "operation")):
        raise ProtectedBackendError("response_binding_mismatch")
    if response["artifact_type"] != RESPONSE_TYPE or response["protocol_version"] != PROTOCOL_VERSION:
        raise ProtectedBackendError("response_identity_invalid")
    for field in ("writer_record_sha256", "anchor_record_sha256",
                  "pre_operation_witness_sha256", "post_operation_witness_sha256"):
        _sha(response[field], "$.response." + field)
    if response["production_authority"] is not True or response["production_ready"] is not True:
        raise ProtectedBackendError("production_authority_unavailable")
    if (request["candidate_generation"] != selection["generation"]
            or request["candidate_descriptor_sha256"] != selection["descriptor_sha256"]):
        raise ProtectedBackendError("selected_candidate_binding_mismatch")
    return MappingProxyType(dict(response))


def serve_one(listener: socket.socket, backend: ProtectedReceiverBackend) -> Mapping[str, Any]:
    try:
        channel, _ = listener.accept()
    except OSError as exc:
        raise ProtectedBackendError("receiver_accept_failed") from exc
    try:
        response = backend.handle(channel, _receive(channel))
        _send(channel, response)
        return response
    finally:
        channel.close()


def bind_fixed_production_socket() -> socket.socket:
    """Bind the single production endpoint. No caller can select its path."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(FIXED_RECEIVER_SOCKET)
        os.chmod(FIXED_RECEIVER_SOCKET, 0o660)
        listener.listen(16)
        return listener
    except OSError as exc:
        listener.close()
        raise ProtectedBackendError("fixed_receiver_bind_failed") from exc
    except BaseException:
        listener.close()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codexmax-protected-receiver-service-v1", allow_abbrev=False)
    parser.add_argument("--candidate-descriptor-fd", type=int, required=True)
    parser.add_argument("--runner-archive-fd", type=int, required=True)
    parser.add_argument("--runner-sidecar-fd", type=int, required=True)
    parser.add_argument("--writer-root-fd", type=int, required=True)
    parser.add_argument("--anchor-root-fd", type=int, required=True)
    parser.add_argument("--writer-channel-fd", type=int, required=True)
    parser.add_argument("--anchor-channel-fd", type=int, required=True)
    parser.add_argument("--candidate-root-fd", type=int, required=True)
    parser.add_argument("--deployment-admission-fd", type=int, required=True)
    parser.add_argument("--protected-configuration-fd", type=int, required=True)
    parser.add_argument("--serve-once", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    listener = None
    transaction = None
    try:
        args = _parser().parse_args(argv)
        now = datetime.now(timezone.utc)
        selected = verify_selected_candidate_fds(
            args.candidate_descriptor_fd, args.runner_archive_fd,
            args.runner_sidecar_fd, now=now,
        )
        fixed_configuration = load_fixed_protected_configuration(args.protected_configuration_fd)
        config = fixed_configuration._require()
        selection = selected.public_selection()
        from supported_host_protected_service_v1 import (
            OsBoundDeploymentAdmissionV2Source,
            PreconnectedDeploymentAdmissionV2,
        )
        admission_socket = socket.fromfd(args.deployment_admission_fd, socket.AF_UNIX, socket.SOCK_STREAM)
        admission_channel = PreconnectedDeploymentAdmissionV2(
            admission_socket,
            expected_uid=config["bootstrap_uid"], expected_gid=config["bootstrap_gid"],
            expected_groups=tuple(config["bootstrap_groups"]),
            bootstrap_identity={
                "bootstrap_source_id": DEPLOYMENT_BOOTSTRAP_SOURCE_ID,
                "bootstrap_build_sha256": config["bootstrap_build_sha256"],
                "bootstrap_start_id": config["bootstrap_start_id"],
                "bootstrap_session_id": config["bootstrap_session_id"],
            },
            expected_previous_commit_sha256=selection["protocol_lineage"]["previous_committed_head_sha256"],
        )
        admission_source = OsBoundDeploymentAdmissionV2Source(admission_channel, selected)
        service_uids = (config["receiver_uid"], config["writer_uid"], config["anchor_uid"])
        transaction = create_opaque_production_transaction(
            args.writer_channel_fd, args.anchor_channel_fd,
            selected, fixed_configuration,
        )
        backend = ProtectedReceiverBackend(
            selected, transaction, mode="production",
            protected_root_fds=(args.writer_root_fd, args.anchor_root_fd, args.candidate_root_fd),
            service_uids=service_uids, admission_source=admission_source,
            fixed_configuration=fixed_configuration, now=now,
        )
        listener = bind_fixed_production_socket()
        if not args.serve_once:
            raise ProtectedBackendError("bounded_serve_once_required")
        result = serve_one(listener, backend)
        print(json.dumps(dict(result), sort_keys=True, separators=(",", ":")))
        return 0
    except (ProtectedBackendError, CandidateAdmissionError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": getattr(exc, "code", type(exc).__name__)}, sort_keys=True), file=sys.stderr)
        return 2
    finally:
        if listener is not None:
            listener.close()
        if transaction is not None:
            transaction.close()


__all__ = [
    "DurableReceiverTransaction", "FIXED_RECEIVER_SOCKET", "FixedProtectedBackendConfiguration", "OPERATIONS",
    "OpaqueProductionReceiverTransaction", "PROTOCOL_VERSION", "ProtectedBackendError", "ProtectedReceiverBackend",
    "bind_fixed_production_socket", "collect_current_receiver_os_identity", "collect_live_os_facts", "serve_one",
    "create_opaque_production_transaction", "load_fixed_protected_configuration", "request_fixed_backend",
    "source_local_os_facts", "validate_request", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
