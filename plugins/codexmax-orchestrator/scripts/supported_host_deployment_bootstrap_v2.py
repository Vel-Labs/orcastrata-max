#!/usr/bin/env python3
"""Descriptor-bound deployment admission for a separately governed bootstrap.

This module is not a runner entry point. The separate bootstrap owns one fixed
descriptor-bound launch and its durable deployment transaction. Source-local
callers can test that mechanism. They cannot mint a production admission.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import select
import socket
import stat
import struct
import time
from types import MappingProxyType
from typing import Any, Mapping


PROTOCOL_VERSION = "supported_host_deployment_admission_v2"
ADMISSION_TYPE = "codexmax_deployment_admission_v2"
COMMIT_TYPE = "codexmax_deployment_commit_v2"
DESCRIPTOR_TYPE = "codexmax_deployment_candidate_descriptor_v2"
ROOT_MANIFEST_TYPE = "codexmax_extracted_generation_manifest_v2"
SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v2"
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ROOT_MEMBERS = 4096
MAX_LEDGER_RECORD_BYTES = 1024 * 1024
COMMIT_RECEIPT_FRAME_BYTES = 1024 * 1024
LEDGER_TYPE = "codexmax_deployment_ledger_event_v2"
COMMIT_RECEIPT_TYPE = "codexmax_deployment_commit_service_receipt_v2"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

DESCRIPTOR_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "candidate_id",
    "runner_artifact_type", "archive_sha256", "sidecar_sha256",
    "source_identity_sha256", "root_manifest_sha256", "entrypoint",
    "generation", "descriptor_sha256",
})
ROOT_MEMBER_FIELDS = frozenset({"path", "size", "mode", "sha256"})
ROOT_MANIFEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "candidate_id", "archive_sha256",
    "members", "manifest_sha256",
})
ADMISSION_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "bootstrap_source_id",
    "candidate_descriptor_sha256", "candidate_id", "archive_sha256",
    "sidecar_sha256", "source_identity_sha256", "root_manifest_sha256",
    "verified_root_device", "verified_root_inode", "child_pid", "child_uid",
    "child_gid", "child_start_id", "child_executable_sha256",
    "entrypoint_device", "entrypoint_inode", "generation",
    "nonce_sha256", "observed_at", "expires_at", "installer_identity",
    "writer_service_start_id", "writer_service_session_id",
    "anchor_service_start_id", "anchor_service_session_id", "revocation_state",
    "previous_committed_head_sha256", "deployment_commit_sha256",
    "writer_receipt_sha256", "anchor_receipt_sha256", "ledger_head_sha256",
    "admission_sha256",
})
INSTALLER_IDENTITY_FIELDS = frozenset({
    "installer_id", "installer_build_sha256", "installer_start_id",
    "installer_session_id",
})
COMMIT_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "bootstrap_source_id",
    "candidate_descriptor_sha256", "candidate_id", "archive_sha256",
    "sidecar_sha256", "source_identity_sha256", "root_manifest_sha256",
    "verified_root_device", "verified_root_inode", "child_pid", "child_uid",
    "child_gid", "child_start_id", "child_executable_sha256",
    "entrypoint_device", "entrypoint_inode", "generation", "nonce_sha256",
    "previous_committed_head_sha256", "installer_identity", "revocation_state",
    "commit_sha256",
})
COMMIT_RECEIPT_FIELDS = frozenset({
    "schema_version", "artifact_type", "service", "service_id",
    "service_build_sha256", "service_start_id", "service_session_id",
    "deployment_commit_sha256", "request_sha256", "observed_at",
    "receipt_sha256",
})
LEDGER_EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "sequence", "event_kind",
    "transaction_id", "candidate_descriptor_sha256", "candidate_id",
    "generation", "nonce_sha256", "previous_committed_head_sha256",
    "payload", "observed_at", "previous_event_sha256", "event_sha256",
})


class DeploymentBootstrapError(ValueError):
    """Stable, non-echoing deployment bootstrap rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return deepcopy(value)


def canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeploymentBootstrapError("deployment_json_invalid") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DeploymentBootstrapError(code, path)
    return deepcopy(dict(value))


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise DeploymentBootstrapError("deployment_sha256_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise DeploymentBootstrapError("deployment_identifier_invalid", path)
    lowered = value.lower()
    if any(part in lowered for part in ("credential", "private", "password", "secret", "token")):
        raise DeploymentBootstrapError("deployment_sensitive_identifier_forbidden", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise DeploymentBootstrapError("deployment_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _sealed(row: Mapping[str, Any], field: str, code: str) -> dict[str, Any]:
    result = deepcopy(dict(row))
    actual = result.get(field)
    result[field] = ""
    if actual != canonical_digest(result):
        raise DeploymentBootstrapError(code, "$." + field)
    result[field] = actual
    return result


def validate_candidate_descriptor(value: Any) -> Mapping[str, Any]:
    """Validate one version-neutral selected candidate descriptor."""

    row = _closed(value, DESCRIPTOR_FIELDS, "deployment_descriptor_shape_invalid", "$.descriptor")
    if row["schema_version"] != 2 or row["artifact_type"] != DESCRIPTOR_TYPE or row["protocol_version"] != PROTOCOL_VERSION:
        raise DeploymentBootstrapError("deployment_descriptor_identity_invalid", "$.descriptor")
    _identifier(row["candidate_id"], "$.descriptor.candidate_id")
    _identifier(row["runner_artifact_type"], "$.descriptor.runner_artifact_type")
    for field in ("archive_sha256", "sidecar_sha256", "source_identity_sha256", "root_manifest_sha256"):
        _sha(row[field], "$.descriptor." + field)
    entrypoint = PurePosixPath(row["entrypoint"] if isinstance(row["entrypoint"], str) else "")
    if entrypoint.is_absolute() or not entrypoint.parts or ".." in entrypoint.parts or "." in entrypoint.parts:
        raise DeploymentBootstrapError("deployment_entrypoint_invalid", "$.descriptor.entrypoint")
    if type(row["generation"]) is not int or row["generation"] < 1:
        raise DeploymentBootstrapError("deployment_generation_invalid", "$.descriptor.generation")
    return MappingProxyType(_sealed(row, "descriptor_sha256", "deployment_descriptor_digest_mismatch"))


def validate_root_manifest(value: Any, descriptor: Mapping[str, Any]) -> Mapping[str, Any]:
    descriptor = validate_candidate_descriptor(descriptor)
    row = _closed(value, ROOT_MANIFEST_FIELDS, "deployment_root_manifest_shape_invalid", "$.root_manifest")
    if row["schema_version"] != 2 or row["artifact_type"] != ROOT_MANIFEST_TYPE:
        raise DeploymentBootstrapError("deployment_root_manifest_identity_invalid", "$.root_manifest")
    if row["candidate_id"] != descriptor["candidate_id"] or row["archive_sha256"] != descriptor["archive_sha256"]:
        raise DeploymentBootstrapError("deployment_root_descriptor_mismatch", "$.root_manifest")
    if not isinstance(row["members"], list) or not 1 <= len(row["members"]) <= MAX_ROOT_MEMBERS:
        raise DeploymentBootstrapError("deployment_root_inventory_invalid", "$.root_manifest.members")
    paths: list[str] = []
    for index, value_member in enumerate(row["members"]):
        member = _closed(value_member, ROOT_MEMBER_FIELDS, "deployment_root_member_shape_invalid", f"$.root_manifest.members[{index}]")
        member_path = PurePosixPath(member["path"] if isinstance(member["path"], str) else "")
        if member_path.is_absolute() or not member_path.parts or ".." in member_path.parts or "." in member_path.parts:
            raise DeploymentBootstrapError("deployment_root_member_path_invalid", f"$.root_manifest.members[{index}].path")
        if type(member["size"]) is not int or member["size"] < 0 or type(member["mode"]) is not int or member["mode"] not in {0o444, 0o555}:
            raise DeploymentBootstrapError("deployment_root_member_metadata_invalid", f"$.root_manifest.members[{index}]")
        _sha(member["sha256"], f"$.root_manifest.members[{index}].sha256")
        paths.append(member["path"])
    if paths != sorted(set(paths)) or descriptor["entrypoint"] not in paths:
        raise DeploymentBootstrapError("deployment_root_inventory_invalid", "$.root_manifest.members")
    sealed = _sealed(row, "manifest_sha256", "deployment_root_manifest_digest_mismatch")
    if sealed["manifest_sha256"] != descriptor["root_manifest_sha256"]:
        raise DeploymentBootstrapError("deployment_root_manifest_binding_mismatch", "$.root_manifest.manifest_sha256")
    return MappingProxyType(sealed)


def _read_regular_fd(fd: int, *, maximum: int, role: str) -> tuple[bytes, tuple[int, int, int, int, int]]:
    if type(fd) is not int or fd < 0:
        raise DeploymentBootstrapError("deployment_descriptor_invalid", "$." + role)
    try:
        duplicate = os.dup(fd)
    except OSError as exc:
        raise DeploymentBootstrapError("deployment_descriptor_unavailable", "$." + role) from exc
    try:
        before = os.fstat(duplicate)
        fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
            raise DeploymentBootstrapError("deployment_descriptor_type_invalid", "$." + role)
        os.lseek(duplicate, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(duplicate, min(131072, maximum + 1 - sum(map(len, chunks))))
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > maximum:
                raise DeploymentBootstrapError("deployment_descriptor_size_invalid", "$." + role)
        after = os.fstat(duplicate)
        if fingerprint != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
            raise DeploymentBootstrapError("deployment_descriptor_drift", "$." + role)
        return b"".join(chunks), fingerprint
    finally:
        os.close(duplicate)


def verify_selected_descriptors(archive_fd: int, sidecar_fd: int, descriptor_fd: int) -> Mapping[str, Any]:
    """Verify selected immutable bytes through stable inherited descriptors."""

    archive, archive_identity = _read_regular_fd(archive_fd, maximum=MAX_ARCHIVE_BYTES, role="archive")
    sidecar, sidecar_identity = _read_regular_fd(sidecar_fd, maximum=MAX_DESCRIPTOR_BYTES, role="sidecar")
    descriptor_raw, descriptor_identity = _read_regular_fd(descriptor_fd, maximum=MAX_DESCRIPTOR_BYTES, role="descriptor")
    try:
        decoded = json.loads(descriptor_raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentBootstrapError("deployment_descriptor_json_invalid", "$.descriptor") from exc
    if canonical_bytes(decoded) != descriptor_raw:
        raise DeploymentBootstrapError("deployment_descriptor_not_canonical", "$.descriptor")
    descriptor = validate_candidate_descriptor(decoded)
    actual = {
        "archive_sha256": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "sidecar_sha256": "sha256:" + hashlib.sha256(sidecar).hexdigest(),
    }
    if any(descriptor[field] != digest for field, digest in actual.items()):
        raise DeploymentBootstrapError("deployment_selected_bytes_mismatch", "$.descriptor")
    try:
        sidecar_value = json.loads(sidecar)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentBootstrapError("deployment_sidecar_json_invalid", "$.sidecar") from exc
    if canonical_bytes(sidecar_value).removesuffix(b"\n") != sidecar:
        raise DeploymentBootstrapError("deployment_sidecar_not_canonical", "$.sidecar")
    if not isinstance(sidecar_value, Mapping):
        raise DeploymentBootstrapError("deployment_sidecar_shape_invalid", "$.sidecar")
    archive_binding = sidecar_value.get("archive")
    source_binding = sidecar_value.get("source")
    if not isinstance(archive_binding, Mapping) or archive_binding.get("sha256") != descriptor["archive_sha256"]:
        raise DeploymentBootstrapError("deployment_sidecar_archive_mismatch", "$.sidecar.archive")
    if not isinstance(source_binding, Mapping) or source_binding.get("source_identity_sha256") != descriptor["source_identity_sha256"]:
        raise DeploymentBootstrapError("deployment_sidecar_source_mismatch", "$.sidecar.source")
    return MappingProxyType({
        "descriptor": deepcopy(dict(descriptor)),
        "archive_descriptor_identity": archive_identity,
        "sidecar_descriptor_identity": sidecar_identity,
        "candidate_descriptor_identity": descriptor_identity,
        "verification_state": "selected_descriptors_verified_source_local_non_authoritative",
        "production_admission_issued": False,
    })


def verify_extracted_generation_root(root_fd: int, manifest_fd: int, descriptor: Mapping[str, Any]) -> Mapping[str, Any]:
    """Verify one exact extracted root without following links."""

    descriptor = validate_candidate_descriptor(descriptor)
    manifest_raw, manifest_identity = _read_regular_fd(manifest_fd, maximum=MAX_DESCRIPTOR_BYTES, role="root_manifest")
    try:
        decoded = json.loads(manifest_raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentBootstrapError("deployment_root_manifest_json_invalid", "$.root_manifest") from exc
    if canonical_bytes(decoded) != manifest_raw:
        raise DeploymentBootstrapError("deployment_root_manifest_not_canonical", "$.root_manifest")
    manifest = validate_root_manifest(decoded, descriptor)
    try:
        root = os.dup(root_fd)
    except OSError as exc:
        raise DeploymentBootstrapError("deployment_root_unavailable", "$.root") from exc
    try:
        before = os.fstat(root)
        if not stat.S_ISDIR(before.st_mode):
            raise DeploymentBootstrapError("deployment_root_type_invalid", "$.root")
        expected = {member["path"]: member for member in manifest["members"]}
        observed: set[str] = set()
        for current, directories, files, directory_fd in os.fwalk(".", topdown=True, follow_symlinks=False, dir_fd=root):
            for name in directories:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    raise DeploymentBootstrapError("deployment_root_link_forbidden", "$.root")
            for name in files:
                relative = str(PurePosixPath(current, name)).removeprefix("./")
                if relative not in expected:
                    raise DeploymentBootstrapError("deployment_root_extra_member", "$.root." + relative)
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                try:
                    member_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise DeploymentBootstrapError("deployment_root_link_forbidden", "$.root." + relative) from exc
                try:
                    info = os.fstat(member_fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise DeploymentBootstrapError("deployment_root_member_type_invalid", "$.root." + relative)
                    data = b""
                    while len(data) <= expected[relative]["size"]:
                        chunk = os.read(member_fd, 131072)
                        if not chunk:
                            break
                        data += chunk
                finally:
                    os.close(member_fd)
                if len(data) != expected[relative]["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != expected[relative]["sha256"]:
                    raise DeploymentBootstrapError("deployment_root_member_digest_mismatch", "$.root." + relative)
                if stat.S_IMODE(info.st_mode) != expected[relative]["mode"]:
                    raise DeploymentBootstrapError("deployment_root_member_mode_mismatch", "$.root." + relative)
                observed.add(relative)
        after = os.fstat(root)
        if observed != set(expected) or (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
            raise DeploymentBootstrapError("deployment_root_inventory_or_identity_mismatch", "$.root")
        return MappingProxyType({
            "candidate_descriptor_sha256": descriptor["descriptor_sha256"],
            "root_manifest_sha256": manifest["manifest_sha256"],
            "verified_root_device": before.st_dev,
            "verified_root_inode": before.st_ino,
            "root_manifest_descriptor_identity": manifest_identity,
            "entrypoint": descriptor["entrypoint"],
            "verification_state": "extracted_generation_root_verified_source_local_non_authoritative",
            "production_admission_issued": False,
        })
    finally:
        os.close(root)


@dataclass(frozen=True, slots=True)
class ChildLaunchObservation:
    """OS-derived result of one exact descriptor-bound launch."""

    pid: int
    uid: int
    gid: int
    start_id: str
    executable_sha256: str
    root_device: int
    root_inode: int
    entrypoint_device: int
    entrypoint_inode: int
    observed_at: str


@dataclass(frozen=True, slots=True)
class CommittedDeploymentTransaction:
    """Opaque result available only after both authenticated receipt exchanges."""

    commit: Mapping[str, Any]
    writer_receipt: Mapping[str, Any]
    anchor_receipt: Mapping[str, Any]
    ledger_head: Mapping[str, Any]


def _digest_fd(fd: int, *, maximum: int, path: str) -> tuple[str, os.stat_result]:
    try:
        before = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 131072)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise DeploymentBootstrapError("deployment_entrypoint_size_invalid", path)
            digest.update(chunk)
        after = os.fstat(fd)
    except OSError as exc:
        raise DeploymentBootstrapError("deployment_entrypoint_unavailable", path) from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
        raise DeploymentBootstrapError("deployment_entrypoint_drift", path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not before.st_mode & stat.S_IXUSR:
        raise DeploymentBootstrapError("deployment_entrypoint_type_invalid", path)
    return "sha256:" + digest.hexdigest(), before


def _open_entrypoint_fd(root_fd: int, relative: str) -> int:
    """Open an entrypoint through directory descriptors without path reopen."""

    parts = PurePosixPath(relative).parts
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        return os.open(parts[-1], flags, dir_fd=current)
    except OSError as exc:
        raise DeploymentBootstrapError("deployment_entrypoint_substitution", "$.root.entrypoint") from exc
    finally:
        os.close(current)


class VerifiedRootLaunchOperation:
    """Own one no-shell launch from the verified inherited root descriptor."""

    __slots__ = ("_used",)

    def __init__(self) -> None:
        self._used = False

    def launch(
        self, *, root_fd: int, manifest_fd: int, descriptor: Mapping[str, Any],
        now: datetime,
    ) -> ChildLaunchObservation:
        if self._used:
            raise DeploymentBootstrapError("deployment_launch_operation_reused", "$.launch")
        self._used = True
        verified = verify_extracted_generation_root(root_fd, manifest_fd, descriptor)
        descriptor = validate_candidate_descriptor(descriptor)
        try:
            root_before = os.fstat(root_fd)
        except OSError as exc:
            raise DeploymentBootstrapError("deployment_root_unavailable", "$.root") from exc
        if (root_before.st_dev, root_before.st_ino) != (
            verified["verified_root_device"], verified["verified_root_inode"],
        ):
            raise DeploymentBootstrapError("deployment_root_substitution", "$.root")
        entrypoint_fd = _open_entrypoint_fd(root_fd, descriptor["entrypoint"])
        try:
            executable_sha256, entrypoint_before = _digest_fd(
                entrypoint_fd, maximum=MAX_ARCHIVE_BYTES, path="$.root.entrypoint",
            )
            manifest_raw, _ = _read_regular_fd(
                manifest_fd, maximum=MAX_DESCRIPTOR_BYTES, role="root_manifest",
            )
            manifest = validate_root_manifest(json.loads(manifest_raw), descriptor)
            expected = next(item for item in manifest["members"] if item["path"] == descriptor["entrypoint"])
            if executable_sha256 != expected["sha256"]:
                raise DeploymentBootstrapError("deployment_entrypoint_digest_mismatch", "$.root.entrypoint")
            if os.execve not in os.supports_fd:
                raise DeploymentBootstrapError("deployment_descriptor_exec_unavailable", "$.launch")
            os.set_inheritable(entrypoint_fd, True)
            pid = os.fork()
            if pid == 0:
                try:
                    os.execve(entrypoint_fd, [descriptor["entrypoint"]], {"PATH": "/usr/bin:/bin"})
                except BaseException:
                    os._exit(127)
            try:
                os.kill(pid, 0)
            except OSError as exc:
                raise DeploymentBootstrapError("deployment_child_not_observed", "$.launch") from exc
            root_after = os.fstat(root_fd)
            entrypoint_after = os.fstat(entrypoint_fd)
            if (root_before.st_dev, root_before.st_ino, root_before.st_mtime_ns) != (
                root_after.st_dev, root_after.st_ino, root_after.st_mtime_ns,
            ):
                raise DeploymentBootstrapError("deployment_root_substitution_after_launch", "$.root")
            entrypoint_identity = (
                entrypoint_before.st_dev, entrypoint_before.st_ino,
                entrypoint_before.st_size, entrypoint_before.st_mtime_ns,
            )
            if entrypoint_identity != (
                entrypoint_after.st_dev, entrypoint_after.st_ino,
                entrypoint_after.st_size, entrypoint_after.st_mtime_ns,
            ):
                raise DeploymentBootstrapError("deployment_entrypoint_substitution_after_launch", "$.root.entrypoint")
            current = now.astimezone(timezone.utc).replace(microsecond=0)
            observed_at = current.strftime("%Y-%m-%dT%H:%M:%SZ")
            start_id = canonical_digest({
                "artifact_type": "codexmax_os_child_start_identity_v2",
                "pid": pid, "uid": os.geteuid(), "gid": os.getegid(),
                "root_device": root_before.st_dev, "root_inode": root_before.st_ino,
                "entrypoint_device": entrypoint_before.st_dev,
                "entrypoint_inode": entrypoint_before.st_ino,
                "executable_sha256": executable_sha256,
                "observed_monotonic_ns": time.monotonic_ns(),
            })
            return ChildLaunchObservation(
                pid=pid, uid=os.geteuid(), gid=os.getegid(), start_id=start_id,
                executable_sha256=executable_sha256,
                root_device=root_before.st_dev, root_inode=root_before.st_ino,
                entrypoint_device=entrypoint_before.st_dev,
                entrypoint_inode=entrypoint_before.st_ino,
                observed_at=observed_at,
            )
        finally:
            os.close(entrypoint_fd)


def validate_commit_service_receipt(
    value: Any, *, service: str, deployment_commit_sha256: str,
    request_sha256: str,
) -> Mapping[str, Any]:
    row = _closed(value, COMMIT_RECEIPT_FIELDS, "deployment_commit_receipt_shape_invalid", "$.receipt")
    if row["schema_version"] != 2 or row["artifact_type"] != COMMIT_RECEIPT_TYPE or row["service"] != service:
        raise DeploymentBootstrapError("deployment_commit_receipt_identity_invalid", "$.receipt")
    for field in ("service_id", "service_start_id", "service_session_id"):
        _identifier(row[field], "$.receipt." + field)
    for field in ("service_build_sha256", "deployment_commit_sha256", "request_sha256"):
        _sha(row[field], "$.receipt." + field)
    _time(row["observed_at"], "$.receipt.observed_at")
    if row["deployment_commit_sha256"] != deployment_commit_sha256 or row["request_sha256"] != request_sha256:
        raise DeploymentBootstrapError("deployment_commit_receipt_binding_mismatch", "$.receipt")
    return MappingProxyType(_sealed(row, "receipt_sha256", "deployment_commit_receipt_digest_mismatch"))


class PreconnectedCommitReceiptChannel:
    """One-use exact receipt exchange with one distinct external authority."""

    __slots__ = ("_socket", "_service", "_expected_uid", "_used", "_fingerprint")

    def __init__(self, channel: socket.socket, *, service: str, expected_uid: int) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise DeploymentBootstrapError("deployment_commit_channel_invalid", "$.channel")
        if service not in {"protected_writer", "independent_anchor"}:
            raise DeploymentBootstrapError("deployment_commit_service_invalid", "$.channel")
        if type(expected_uid) is not int or expected_uid < 1 or expected_uid == os.geteuid():
            raise DeploymentBootstrapError("deployment_commit_peer_account_invalid", "$.channel")
        info = os.fstat(channel.fileno())
        self._socket = channel
        self._service = service
        self._expected_uid = expected_uid
        self._used = False
        self._fingerprint = (channel.fileno(), info.st_dev, info.st_ino, info.st_mode)

    def _peer_uid(self) -> int | None:
        try:
            peer_uid, _ = self._socket.getpeereid()
            return peer_uid
        except (AttributeError, OSError):
            return None

    def exchange(self, commit: Mapping[str, Any], *, now: datetime) -> Mapping[str, Any]:
        if self._used:
            raise DeploymentBootstrapError("deployment_commit_channel_reused", "$.channel")
        self._used = True
        info = os.fstat(self._socket.fileno())
        if self._fingerprint != (self._socket.fileno(), info.st_dev, info.st_ino, info.st_mode):
            raise DeploymentBootstrapError("deployment_commit_channel_substituted", "$.channel")
        peer_uid = self._peer_uid()
        if peer_uid is None or peer_uid == os.geteuid() or peer_uid != self._expected_uid:
            raise DeploymentBootstrapError("deployment_commit_peer_not_authoritative", "$.channel")
        commit_sha256 = canonical_digest(commit)
        request = {
            "schema_version": 2,
            "artifact_type": "codexmax_deployment_commit_service_request_v2",
            "service": self._service,
            "deployment_commit": deepcopy(dict(commit)),
            "deployment_commit_sha256": commit_sha256,
            "challenge": secrets.token_urlsafe(32),
            "requested_at": now.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_sha256": "",
        }
        request["request_sha256"] = canonical_digest(request)
        raw = canonical_bytes(request)
        self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        header = self._recv_exact(4)
        size = struct.unpack("!I", header)[0]
        if size < 2 or size > COMMIT_RECEIPT_FRAME_BYTES:
            raise DeploymentBootstrapError("deployment_commit_frame_invalid", "$.channel")
        raw_receipt = self._recv_exact(size)
        readable, _, _ = select.select([self._socket], [], [], 0)
        if readable:
            raise DeploymentBootstrapError("deployment_commit_frame_trailing", "$.channel")
        try:
            receipt = json.loads(raw_receipt)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DeploymentBootstrapError("deployment_commit_receipt_json_invalid", "$.channel") from exc
        if canonical_bytes(receipt) != raw_receipt:
            raise DeploymentBootstrapError("deployment_commit_receipt_not_canonical", "$.channel")
        return validate_commit_service_receipt(
            receipt, service=self._service, deployment_commit_sha256=commit_sha256,
            request_sha256=request["request_sha256"],
        )

    def _recv_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            part = self._socket.recv(count - len(chunks))
            if not part:
                raise DeploymentBootstrapError("deployment_commit_frame_truncated", "$.channel")
            chunks.extend(part)
        return bytes(chunks)


class DurableDeploymentLedger:
    """Append-only descriptor-rooted deployment transaction ledger."""

    __slots__ = ("_root", "_root_identity", "_events", "_head")

    def __init__(self, root_fd: int) -> None:
        try:
            self._root = os.dup(root_fd)
            info = os.fstat(self._root)
        except OSError as exc:
            raise DeploymentBootstrapError("deployment_ledger_root_unavailable", "$.ledger") from exc
        if not stat.S_ISDIR(info.st_mode):
            os.close(self._root)
            raise DeploymentBootstrapError("deployment_ledger_root_invalid", "$.ledger")
        self._root_identity = (info.st_dev, info.st_ino)
        self._events: list[dict[str, Any]] = []
        self._head: dict[str, Any] | None = None
        self.recover()

    def close(self) -> None:
        if getattr(self, "_root", -1) >= 0:
            os.close(self._root)
            self._root = -1

    def _check_root(self) -> None:
        try:
            info = os.fstat(self._root)
        except OSError as exc:
            raise DeploymentBootstrapError("deployment_ledger_root_unavailable", "$.ledger") from exc
        if self._root_identity != (info.st_dev, info.st_ino):
            raise DeploymentBootstrapError("deployment_ledger_root_substituted", "$.ledger")

    def _read_name(self, name: str, *, required: bool = True) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, dir_fd=self._root)
        except FileNotFoundError:
            if not required:
                return None
            raise DeploymentBootstrapError("deployment_ledger_record_missing", "$.ledger")
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_LEDGER_RECORD_BYTES:
                raise DeploymentBootstrapError("deployment_ledger_record_invalid", "$.ledger")
            chunks = bytearray()
            while len(chunks) <= MAX_LEDGER_RECORD_BYTES:
                part = os.read(fd, 131072)
                if not part:
                    break
                chunks.extend(part)
            if len(chunks) > MAX_LEDGER_RECORD_BYTES:
                raise DeploymentBootstrapError("deployment_ledger_record_too_large", "$.ledger")
            return bytes(chunks)
        finally:
            os.close(fd)

    def _write_absent(self, name: str, value: Mapping[str, Any]) -> None:
        raw = canonical_bytes(value)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, 0o400, dir_fd=self._root)
        except FileExistsError as exc:
            raise DeploymentBootstrapError("deployment_ledger_record_collision", "$.ledger") from exc
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._root)

    def _publish_head(self, value: Mapping[str, Any]) -> None:
        raw = canonical_bytes(value)
        temporary = f".head-{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o400, dir_fd=self._root)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, "HEAD.json", src_dir_fd=self._root, dst_dir_fd=self._root)
        os.fsync(self._root)

    def _decode_event(self, raw: bytes, sequence: int) -> dict[str, Any]:
        try:
            decoded = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DeploymentBootstrapError("deployment_ledger_json_invalid", "$.ledger") from exc
        if canonical_bytes(decoded) != raw:
            raise DeploymentBootstrapError("deployment_ledger_not_canonical", "$.ledger")
        row = _closed(decoded, LEDGER_EVENT_FIELDS, "deployment_ledger_event_shape_invalid", "$.ledger")
        if row["schema_version"] != 2 or row["artifact_type"] != LEDGER_TYPE or row["sequence"] != sequence:
            raise DeploymentBootstrapError("deployment_ledger_event_identity_invalid", "$.ledger")
        if row["previous_event_sha256"] != (None if not self._events else self._events[-1]["event_sha256"]):
            raise DeploymentBootstrapError("deployment_ledger_fork_or_truncation", "$.ledger")
        return _sealed(row, "event_sha256", "deployment_ledger_event_digest_mismatch")

    def recover(self) -> Mapping[str, Any]:
        self._check_root()
        names = sorted(name for name in os.listdir(self._root) if name.startswith("event-") and name.endswith(".json"))
        expected_names = [f"event-{sequence:08d}.json" for sequence in range(1, len(names) + 1)]
        if names != expected_names:
            raise DeploymentBootstrapError("deployment_ledger_truncation_or_gap", "$.ledger")
        self._events = []
        transactions: dict[str, dict[str, Any]] = {}
        committed: list[dict[str, Any]] = []
        nonces: set[str] = set()
        last_generation = 0
        for sequence, name in enumerate(names, 1):
            event = self._decode_event(self._read_name(name) or b"", sequence)
            self._events.append(event)
            transaction = transactions.setdefault(event["transaction_id"], {"events": []})
            transaction["events"].append(event)
            kind = event["event_kind"]
            if kind == "reserved":
                if len(transaction["events"]) != 1 or event["nonce_sha256"] in nonces:
                    raise DeploymentBootstrapError("deployment_nonce_replay", "$.ledger")
                if event["generation"] <= last_generation:
                    raise DeploymentBootstrapError("deployment_generation_rollback", "$.ledger")
                nonces.add(event["nonce_sha256"])
            elif kind == "committed":
                if any(item["event_kind"] == "committed" for item in transaction["events"][:-1]):
                    raise DeploymentBootstrapError("deployment_commit_replay", "$.ledger")
                if event["generation"] <= last_generation:
                    raise DeploymentBootstrapError("deployment_generation_rollback", "$.ledger")
                committed.append(event)
                last_generation = event["generation"]
            elif kind not in {"launched", "writer_receipt", "anchor_receipt", "admission_issued", "revoked", "aborted"}:
                raise DeploymentBootstrapError("deployment_ledger_event_kind_invalid", "$.ledger")
        head_raw = self._read_name("HEAD.json", required=False)
        head = None
        if head_raw is not None:
            try:
                head = json.loads(head_raw)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise DeploymentBootstrapError("deployment_ledger_head_invalid", "$.ledger") from exc
            if canonical_bytes(head) != head_raw or not isinstance(head, Mapping) or set(head) != {
                "generation", "transaction_id", "event_sha256", "commit_sha256",
            }:
                raise DeploymentBootstrapError("deployment_ledger_head_invalid", "$.ledger")
            if not committed or any(head.get(field) != committed[-1].get(field) for field in ("generation", "transaction_id", "event_sha256")):
                raise DeploymentBootstrapError("deployment_ledger_head_substitution", "$.ledger")
            if head["commit_sha256"] != committed[-1]["payload"].get("commit_sha256"):
                raise DeploymentBootstrapError("deployment_ledger_head_substitution", "$.ledger")
        elif committed:
            latest = committed[-1]
            head = {
                "generation": latest["generation"], "transaction_id": latest["transaction_id"],
                "event_sha256": latest["event_sha256"],
                "commit_sha256": latest["payload"]["commit_sha256"],
            }
            self._publish_head(head)
        self._head = None if head is None else dict(head)
        pending = [
            transaction_id for transaction_id, value in transactions.items()
            if value["events"][-1]["event_kind"] not in {"committed", "admission_issued", "revoked", "aborted"}
        ]
        return MappingProxyType({
            "state": "deployment_ledger_reconciled_source_local_non_authoritative",
            "event_count": len(self._events), "committed_head": deepcopy(self._head),
            "pending_transactions": tuple(sorted(pending)),
            "production_admission_issued": False,
        })

    def _append(
        self, *, kind: str, transaction_id: str, descriptor: Mapping[str, Any],
        nonce_sha256: str, payload: Mapping[str, Any], now: datetime,
    ) -> CommittedDeploymentTransaction:
        descriptor = validate_candidate_descriptor(descriptor)
        sequence = len(self._events) + 1
        row = {
            "schema_version": 2, "artifact_type": LEDGER_TYPE,
            "sequence": sequence, "event_kind": kind,
            "transaction_id": transaction_id,
            "candidate_descriptor_sha256": descriptor["descriptor_sha256"],
            "candidate_id": descriptor["candidate_id"],
            "generation": descriptor["generation"], "nonce_sha256": nonce_sha256,
            "previous_committed_head_sha256": None if self._head is None else self._head["event_sha256"],
            "payload": deepcopy(dict(payload)),
            "observed_at": now.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "previous_event_sha256": None if not self._events else self._events[-1]["event_sha256"],
            "event_sha256": "",
        }
        row["event_sha256"] = canonical_digest(row)
        self._write_absent(f"event-{sequence:08d}.json", row)
        self._events.append(deepcopy(row))
        return MappingProxyType(row)

    def reserve(self, descriptor: Mapping[str, Any], *, nonce: str, now: datetime) -> Mapping[str, Any]:
        descriptor = validate_candidate_descriptor(descriptor)
        _identifier(nonce, "$.nonce")
        nonce_sha256 = canonical_digest({"nonce": nonce})
        if any(event["nonce_sha256"] == nonce_sha256 for event in self._events):
            raise DeploymentBootstrapError("deployment_nonce_replay", "$.nonce")
        current_generation = 0 if self._head is None else self._head["generation"]
        if descriptor["generation"] != current_generation + 1:
            raise DeploymentBootstrapError("deployment_generation_not_monotonic", "$.descriptor.generation")
        transaction_id = "deployment-" + nonce_sha256.removeprefix("sha256:")
        return self._append(
            kind="reserved", transaction_id=transaction_id, descriptor=descriptor,
            nonce_sha256=nonce_sha256,
            payload={"reservation_state": "pending", "nonce_consumed": True}, now=now,
        )

    def revoke(self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any], *, reason: str, now: datetime) -> Mapping[str, Any]:
        _identifier(reason, "$.reason")
        current = self._transaction(reservation["transaction_id"])
        if current[-1]["event_kind"] in {"committed", "revoked", "aborted"}:
            raise DeploymentBootstrapError("deployment_revocation_state_invalid", "$.transaction")
        return self._append(
            kind="revoked", transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload={"reason": reason}, now=now,
        )

    def _record_launch(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any],
        observation: ChildLaunchObservation, *, authority_mode: str, now: datetime,
    ) -> Mapping[str, Any]:
        if type(observation) is not ChildLaunchObservation:
            raise DeploymentBootstrapError("deployment_child_observation_required", "$.launch")
        current = self._transaction(reservation["transaction_id"])
        if current[-1]["event_kind"] != "reserved":
            raise DeploymentBootstrapError("deployment_launch_state_invalid", "$.transaction")
        return self._append(
            kind="launched", transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload={
                "child_pid": observation.pid, "child_uid": observation.uid,
                "child_gid": observation.gid, "child_start_id": observation.start_id,
                "child_executable_sha256": observation.executable_sha256,
                "verified_root_device": observation.root_device,
                "verified_root_inode": observation.root_inode,
                "entrypoint_device": observation.entrypoint_device,
                "entrypoint_inode": observation.entrypoint_inode,
                "launch_authority_mode": authority_mode,
            }, now=now,
        )

    def launch_reserved(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any], *,
        root_fd: int, manifest_fd: int, now: datetime,
    ) -> ChildLaunchObservation:
        """Launch and retain only bootstrap-owned OS observations."""

        observation = VerifiedRootLaunchOperation().launch(
            root_fd=root_fd, manifest_fd=manifest_fd, descriptor=descriptor, now=now,
        )
        self._record_launch(
            reservation, descriptor, observation,
            authority_mode="bootstrap_owned_os_observation", now=now,
        )
        return observation

    def _transaction(self, transaction_id: str) -> list[dict[str, Any]]:
        rows = [event for event in self._events if event["transaction_id"] == transaction_id]
        if not rows:
            raise DeploymentBootstrapError("deployment_transaction_unknown", "$.transaction")
        return rows

    def _commit_basis(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any],
        installer_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        descriptor = validate_candidate_descriptor(descriptor)
        launched = self._transaction(reservation["transaction_id"])[-1]
        if launched["event_kind"] != "launched":
            raise DeploymentBootstrapError("deployment_commit_state_invalid", "$.transaction")
        if launched["payload"].get("launch_authority_mode") != "bootstrap_owned_os_observation":
            raise DeploymentBootstrapError("deployment_launch_authority_invalid", "$.transaction")
        installer = _closed(installer_identity, INSTALLER_IDENTITY_FIELDS, "deployment_installer_identity_invalid", "$.installer")
        for field in ("installer_id", "installer_start_id", "installer_session_id"):
            _identifier(installer[field], "$.installer." + field)
        _sha(installer["installer_build_sha256"], "$.installer.installer_build_sha256")
        return {
            "schema_version": 2, "artifact_type": COMMIT_TYPE,
            "protocol_version": PROTOCOL_VERSION, "bootstrap_source_id": SOURCE_ID,
            "candidate_descriptor_sha256": descriptor["descriptor_sha256"],
            "candidate_id": descriptor["candidate_id"],
            "archive_sha256": descriptor["archive_sha256"],
            "sidecar_sha256": descriptor["sidecar_sha256"],
            "source_identity_sha256": descriptor["source_identity_sha256"],
            "root_manifest_sha256": descriptor["root_manifest_sha256"],
            **{
                field: launched["payload"][field] for field in (
                    "child_pid", "child_uid", "child_gid", "child_start_id",
                    "child_executable_sha256", "verified_root_device",
                    "verified_root_inode", "entrypoint_device", "entrypoint_inode",
                )
            },
            "generation": descriptor["generation"],
            "nonce_sha256": reservation["nonce_sha256"],
            "previous_committed_head_sha256": None if self._head is None else self._head["event_sha256"],
            "installer_identity": installer, "revocation_state": "not_revoked",
            "commit_sha256": "",
        }

    def commit_with_authorities(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any], *,
        installer_identity: Mapping[str, Any], writer: PreconnectedCommitReceiptChannel,
        anchor: PreconnectedCommitReceiptChannel, now: datetime,
        fault_after: str | None = None,
    ) -> Mapping[str, Any]:
        if type(writer) is not PreconnectedCommitReceiptChannel or writer._service != "protected_writer":
            raise DeploymentBootstrapError("deployment_writer_channel_required", "$.writer")
        if type(anchor) is not PreconnectedCommitReceiptChannel or anchor._service != "independent_anchor":
            raise DeploymentBootstrapError("deployment_anchor_channel_required", "$.anchor")
        if writer._expected_uid == anchor._expected_uid:
            raise DeploymentBootstrapError("deployment_authority_account_collision", "$.authorities")
        commit = self._commit_basis(reservation, descriptor, installer_identity)
        commit["commit_sha256"] = canonical_digest(commit)
        commit_wire_sha256 = canonical_digest(commit)
        writer_receipt = writer.exchange(commit, now=now)
        writer_event = self._append(
            kind="writer_receipt", transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload=dict(writer_receipt), now=now,
        )
        if fault_after == "writer_receipt":
            raise DeploymentBootstrapError("deployment_test_crash_after_writer_receipt", "$.transaction")
        if self._transaction(reservation["transaction_id"])[-1]["event_kind"] == "revoked":
            raise DeploymentBootstrapError("deployment_revoked", "$.transaction")
        anchor_receipt = anchor.exchange(commit, now=now)
        anchor_event = self._append(
            kind="anchor_receipt", transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload=dict(anchor_receipt), now=now,
        )
        if fault_after == "anchor_receipt":
            raise DeploymentBootstrapError("deployment_test_crash_after_anchor_receipt", "$.transaction")
        if writer_receipt["deployment_commit_sha256"] != anchor_receipt["deployment_commit_sha256"]:
            raise DeploymentBootstrapError("deployment_commit_receipt_divergence", "$.authorities")
        committed = self._append(
            kind="committed", transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload={
                "commit_sha256": commit_wire_sha256,
                "writer_receipt_sha256": writer_receipt["receipt_sha256"],
                "anchor_receipt_sha256": anchor_receipt["receipt_sha256"],
                "writer_event_sha256": writer_event["event_sha256"],
                "anchor_event_sha256": anchor_event["event_sha256"],
                "authority_mode": "os_authenticated_distinct_services",
            }, now=now,
        )
        if fault_after == "before_head_publication":
            raise DeploymentBootstrapError("deployment_test_crash_before_head_publication", "$.transaction")
        head = {
            "generation": committed["generation"], "transaction_id": committed["transaction_id"],
            "event_sha256": committed["event_sha256"], "commit_sha256": commit_wire_sha256,
        }
        self._publish_head(head)
        self._head = head
        return CommittedDeploymentTransaction(
            commit=MappingProxyType(deepcopy(commit)),
            writer_receipt=MappingProxyType(dict(writer_receipt)),
            anchor_receipt=MappingProxyType(dict(anchor_receipt)),
            ledger_head=MappingProxyType(deepcopy(head)),
        )

    def issue_admission(
        self, committed: CommittedDeploymentTransaction, descriptor: Mapping[str, Any], *,
        now: datetime, expires_at: datetime,
    ) -> Mapping[str, Any]:
        """Issue one admission only from the current authenticated committed head."""

        if type(committed) is not CommittedDeploymentTransaction:
            raise DeploymentBootstrapError("deployment_committed_transaction_required", "$.transaction")
        descriptor = validate_candidate_descriptor(descriptor)
        if self._head is None or dict(committed.ledger_head) != self._head:
            raise DeploymentBootstrapError("deployment_committed_head_mismatch", "$.ledger")
        events = self._transaction(self._head["transaction_id"])
        if events[-1]["event_kind"] != "committed":
            raise DeploymentBootstrapError("deployment_admission_already_issued_or_invalid", "$.transaction")
        commit = _closed(committed.commit, COMMIT_FIELDS, "deployment_commit_shape_invalid", "$.commit")
        if canonical_digest(commit) != self._head["commit_sha256"]:
            raise DeploymentBootstrapError("deployment_committed_head_mismatch", "$.commit")
        writer = validate_commit_service_receipt(
            committed.writer_receipt, service="protected_writer",
            deployment_commit_sha256=canonical_digest(commit),
            request_sha256=committed.writer_receipt["request_sha256"],
        )
        anchor = validate_commit_service_receipt(
            committed.anchor_receipt, service="independent_anchor",
            deployment_commit_sha256=canonical_digest(commit),
            request_sha256=committed.anchor_receipt["request_sha256"],
        )
        current = now.astimezone(timezone.utc).replace(microsecond=0)
        expiry = expires_at.astimezone(timezone.utc).replace(microsecond=0)
        if expiry <= current:
            raise DeploymentBootstrapError("deployment_admission_expiry_invalid", "$.expires_at")
        admission = {
            key: deepcopy(commit[key]) for key in COMMIT_FIELDS
            if key not in {"artifact_type", "commit_sha256"}
        }
        admission.update({
            "artifact_type": ADMISSION_TYPE,
            "observed_at": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "writer_service_start_id": writer["service_start_id"],
            "writer_service_session_id": writer["service_session_id"],
            "anchor_service_start_id": anchor["service_start_id"],
            "anchor_service_session_id": anchor["service_session_id"],
            "deployment_commit_sha256": canonical_digest(commit),
            "writer_receipt_sha256": writer["receipt_sha256"],
            "anchor_receipt_sha256": anchor["receipt_sha256"],
            "ledger_head_sha256": self._head["event_sha256"],
            "admission_sha256": "",
        })
        admission["admission_sha256"] = canonical_digest(admission)
        self._append(
            kind="admission_issued", transaction_id=self._head["transaction_id"],
            descriptor=descriptor, nonce_sha256=commit["nonce_sha256"],
            payload={"admission_sha256": admission["admission_sha256"]}, now=now,
        )
        return MappingProxyType(admission)

    def record_source_local_test_commit(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any], *,
        observation: ChildLaunchObservation, now: datetime,
    ) -> Mapping[str, Any]:
        """Exercise durable phases without creating receipt or admission authority."""

        launched = self._record_launch(
            reservation, descriptor, observation,
            authority_mode="source_local_fixture_non_authoritative", now=now,
        )
        return MappingProxyType({
            "state": "source_local_test_launch_retained_non_authoritative",
            "launch_event_sha256": launched["event_sha256"],
            "production_admission_eligible": False,
        })

    def advance_source_local_test_phase(
        self, reservation: Mapping[str, Any], descriptor: Mapping[str, Any], *,
        phase: str, now: datetime,
    ) -> Mapping[str, Any]:
        """Retain crash-recovery fixtures without creating authority."""

        expected = {
            "writer_receipt": "launched",
            "anchor_receipt": "writer_receipt",
            "committed": "anchor_receipt",
        }
        if phase not in expected:
            raise DeploymentBootstrapError("deployment_test_phase_invalid", "$.phase")
        current = self._transaction(reservation["transaction_id"])
        if current[-1]["event_kind"] != expected[phase]:
            raise DeploymentBootstrapError("deployment_test_phase_order_invalid", "$.phase")
        payload = {
            "classification": "source_local_fixture_non_authoritative",
            "production_admission_eligible": False,
        }
        if phase == "committed":
            payload["commit_sha256"] = canonical_digest({
                "transaction_id": reservation["transaction_id"],
                "classification": payload["classification"],
            })
        event = self._append(
            kind=phase, transaction_id=reservation["transaction_id"], descriptor=descriptor,
            nonce_sha256=reservation["nonce_sha256"], payload=payload, now=now,
        )
        if phase == "committed":
            head = {
                "generation": event["generation"], "transaction_id": event["transaction_id"],
                "event_sha256": event["event_sha256"], "commit_sha256": payload["commit_sha256"],
            }
            self._publish_head(head)
            self._head = head
        return MappingProxyType({
            "state": "source_local_test_phase_retained_non_authoritative",
            "phase": phase, "event_sha256": event["event_sha256"],
            "production_admission_eligible": False,
        })


def validate_deployment_admission(value: Any, *, now: datetime, expected_previous_commit_sha256: str | None = None) -> Mapping[str, Any]:
    """Validate closure and freshness of authenticated channel output."""

    row = _closed(value, ADMISSION_FIELDS, "deployment_admission_shape_invalid", "$.admission")
    if row["schema_version"] != 2 or row["artifact_type"] != ADMISSION_TYPE or row["protocol_version"] != PROTOCOL_VERSION or row["bootstrap_source_id"] != SOURCE_ID:
        raise DeploymentBootstrapError("deployment_admission_identity_invalid", "$.admission")
    for field in (
        "candidate_descriptor_sha256", "archive_sha256", "sidecar_sha256",
        "source_identity_sha256", "root_manifest_sha256", "child_executable_sha256",
        "nonce_sha256", "deployment_commit_sha256", "writer_receipt_sha256",
        "anchor_receipt_sha256", "ledger_head_sha256",
    ):
        _sha(row[field], "$.admission." + field)
    for field in ("candidate_id", "child_start_id", "writer_service_start_id", "writer_service_session_id", "anchor_service_start_id", "anchor_service_session_id"):
        _identifier(row[field], "$.admission." + field)
    installer = _closed(row["installer_identity"], INSTALLER_IDENTITY_FIELDS, "deployment_installer_identity_invalid", "$.admission.installer_identity")
    for field in ("installer_id", "installer_start_id", "installer_session_id"):
        _identifier(installer[field], "$.admission.installer_identity." + field)
    _sha(installer["installer_build_sha256"], "$.admission.installer_identity.installer_build_sha256")
    for field in ("verified_root_device", "verified_root_inode", "entrypoint_device", "entrypoint_inode", "child_pid", "child_uid", "child_gid", "generation"):
        if type(row[field]) is not int or row[field] < 1:
            raise DeploymentBootstrapError("deployment_numeric_identity_invalid", "$.admission." + field)
    if row["revocation_state"] != "not_revoked":
        raise DeploymentBootstrapError("deployment_revoked", "$.admission.revocation_state")
    if row["writer_receipt_sha256"] == row["anchor_receipt_sha256"]:
        raise DeploymentBootstrapError("deployment_commit_receipt_identity_collision", "$.admission")
    previous = row["previous_committed_head_sha256"]
    if previous is not None:
        _sha(previous, "$.admission.previous_committed_head_sha256")
    if previous != expected_previous_commit_sha256:
        raise DeploymentBootstrapError("deployment_commit_lineage_mismatch", "$.admission.previous_committed_head_sha256")
    observed = _time(row["observed_at"], "$.admission.observed_at")
    expires = _time(row["expires_at"], "$.admission.expires_at")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise DeploymentBootstrapError("deployment_clock_invalid", "$.now")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > current or expires <= current or observed >= expires:
        raise DeploymentBootstrapError("deployment_admission_expired", "$.admission")
    return MappingProxyType(_sealed(row, "admission_sha256", "deployment_admission_digest_mismatch"))


def validate_deployment_commit(value: Any, *, expected_admission: Mapping[str, Any], expected_previous_commit_sha256: str | None) -> Mapping[str, Any]:
    """Validate writer and anchor parity for one monotonic deployment commit."""

    row = _closed(value, COMMIT_FIELDS, "deployment_commit_shape_invalid", "$.commit")
    if row["schema_version"] != 2 or row["artifact_type"] != COMMIT_TYPE or row["protocol_version"] != PROTOCOL_VERSION or row["bootstrap_source_id"] != SOURCE_ID:
        raise DeploymentBootstrapError("deployment_commit_identity_invalid", "$.commit")
    for field in COMMIT_FIELDS - {"artifact_type", "commit_sha256"}:
        if field in expected_admission and row[field] != expected_admission[field]:
            raise DeploymentBootstrapError("deployment_commit_admission_mismatch", "$.commit." + field)
    previous = row["previous_committed_head_sha256"]
    if previous is not None:
        _sha(previous, "$.commit.previous_committed_head_sha256")
    if previous != expected_previous_commit_sha256:
        raise DeploymentBootstrapError("deployment_commit_lineage_mismatch", "$.commit.previous_committed_head_sha256")
    return MappingProxyType(_sealed(row, "commit_sha256", "deployment_commit_digest_mismatch"))


def source_local_validation_boundary() -> Mapping[str, Any]:
    """Describe the source-local proof boundary without issuing authority."""

    return MappingProxyType({
        "schema_version": 2,
        "artifact_type": "codexmax_deployment_bootstrap_source_boundary_v2",
        "protocol_version": PROTOCOL_VERSION,
        "bootstrap_source_id": SOURCE_ID,
        "production_admission_issued": False,
        "process_started": False,
        "socket_opened": False,
        "writes": False,
        "external_action_performed": False,
    })


__all__ = [
    "ADMISSION_FIELDS", "ADMISSION_TYPE", "COMMIT_FIELDS", "COMMIT_TYPE",
    "DESCRIPTOR_FIELDS", "DESCRIPTOR_TYPE", "DeploymentBootstrapError",
    "PROTOCOL_VERSION", "ROOT_MANIFEST_FIELDS", "ROOT_MANIFEST_TYPE", "SOURCE_ID",
    "canonical_bytes", "canonical_digest", "source_local_validation_boundary",
    "validate_candidate_descriptor", "validate_deployment_admission",
    "validate_deployment_commit", "validate_root_manifest",
    "verify_extracted_generation_root", "verify_selected_descriptors",
]
