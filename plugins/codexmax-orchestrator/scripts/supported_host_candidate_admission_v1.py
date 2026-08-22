#!/usr/bin/env python3
"""Version-neutral selected-candidate admission boundary.

The installer reads the descriptor, archive, and sidecar through inherited
regular-file descriptors.  The returned opaque value can bind a later
DeploymentAdmissionV2.  A caller mapping is never production authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping


DESCRIPTOR_TYPE = "codexmax_selected_candidate_descriptor_v1"
ADMISSION_PROTOCOL = "supported_host_deployment_admission_v2"
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RUNNER_ID = re.compile(r"^codexmax-package-host-runner-v([1-9][0-9]*)$")
_RUNNER_TARGET = re.compile(
    r"^orcastrata:package-host-runner:v([1-9][0-9]*):"
    r"codexmax-package-host-runner-bundle-v([1-9][0-9]*)$"
)
_FIELDS = frozenset({
    "schema_version", "artifact_type", "candidate_id", "target",
    "runner_artifact_type", "archive_sha256", "sidecar_sha256",
    "source_identity_sha256", "protocol_lineage", "generation",
    "issued_at", "expires_at", "challenge_sha256", "installer",
    "protected_receiver", "protected_writer", "independent_anchor",
})
_LINEAGE_FIELDS = frozenset({
    "deployment_admission_protocol", "bootstrap_source_id",
    "minimum_generation", "previous_committed_head_sha256",
    "legacy_migration_candidate",
})
_SERVICE_FIELDS = frozenset({
    "service_id", "service_build_sha256", "service_start_id",
    "service_session_id",
})


class CandidateAdmissionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CandidateAdmissionError(code, path)
    return deepcopy(dict(value))


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CandidateAdmissionError("candidate_identifier_invalid", path)
    if any(part in value.lower() for part in ("credential", "password", "private", "secret", "token")):
        raise CandidateAdmissionError("candidate_sensitive_identifier_forbidden", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise CandidateAdmissionError("candidate_sha256_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise CandidateAdmissionError("candidate_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _service(value: Any, role: str) -> dict[str, str]:
    row = _closed(value, _SERVICE_FIELDS, "candidate_service_shape_invalid", "$." + role)
    _identifier(row["service_id"], f"$.{role}.service_id")
    _sha(row["service_build_sha256"], f"$.{role}.service_build_sha256")
    _identifier(row["service_start_id"], f"$.{role}.service_start_id")
    _identifier(row["service_session_id"], f"$.{role}.service_session_id")
    return row


def validate_selected_candidate_descriptor(value: Any, *, now: datetime) -> Mapping[str, Any]:
    """Validate public descriptor data without creating authority."""
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise CandidateAdmissionError("candidate_clock_invalid", "$.now")
    row = _closed(value, _FIELDS, "candidate_descriptor_shape_invalid", "$.descriptor")
    if row["schema_version"] != 1 or row["artifact_type"] != DESCRIPTOR_TYPE:
        raise CandidateAdmissionError("candidate_descriptor_identity_invalid", "$.descriptor")
    candidate_match = _RUNNER_ID.fullmatch(_identifier(row["candidate_id"], "$.candidate_id"))
    if candidate_match is None:
        raise CandidateAdmissionError("candidate_identity_invalid", "$.candidate_id")
    generation = int(candidate_match.group(1))
    expected_artifact_type = f"codexmax_package_host_runner_bundle_v{generation}"
    target_match = _RUNNER_TARGET.fullmatch(row["target"]) if isinstance(row["target"], str) else None
    if row["runner_artifact_type"] != expected_artifact_type:
        raise CandidateAdmissionError("candidate_runner_artifact_identity_invalid", "$.runner_artifact_type")
    if (
        target_match is None
        or int(target_match.group(1)) != generation
        or int(target_match.group(2)) != generation
        or any(part in {".", ".."} for part in row["target"].split(":"))
    ):
        raise CandidateAdmissionError("candidate_target_invalid", "$.target")
    for field in ("archive_sha256", "sidecar_sha256", "source_identity_sha256", "challenge_sha256"):
        _sha(row[field], "$." + field)
    if type(row["generation"]) is not int or row["generation"] != generation:
        raise CandidateAdmissionError("candidate_generation_invalid", "$.generation")
    issued = _time(row["issued_at"], "$.issued_at")
    expires = _time(row["expires_at"], "$.expires_at")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    if issued > current or current >= expires or expires <= issued:
        raise CandidateAdmissionError("candidate_descriptor_expired", "$.expires_at")
    lineage = _closed(row["protocol_lineage"], _LINEAGE_FIELDS, "candidate_lineage_shape_invalid", "$.protocol_lineage")
    if lineage["deployment_admission_protocol"] != ADMISSION_PROTOCOL:
        raise CandidateAdmissionError("candidate_protocol_incompatible", "$.protocol_lineage")
    _identifier(lineage["bootstrap_source_id"], "$.protocol_lineage.bootstrap_source_id")
    _identifier(lineage["legacy_migration_candidate"], "$.protocol_lineage.legacy_migration_candidate")
    if type(lineage["minimum_generation"]) is not int or lineage["minimum_generation"] < 1 or row["generation"] < lineage["minimum_generation"]:
        raise CandidateAdmissionError("candidate_generation_invalid", "$.protocol_lineage.minimum_generation")
    previous = lineage["previous_committed_head_sha256"]
    if previous is not None:
        _sha(previous, "$.protocol_lineage.previous_committed_head_sha256")
    services = [_service(row[role], role) for role in ("installer", "protected_receiver", "protected_writer", "independent_anchor")]
    if len({service["service_id"] for service in services}) != len(services):
        raise CandidateAdmissionError("candidate_service_identity_collision", "$.descriptor")
    return MappingProxyType(row)


def _read_fd(fd: int, *, maximum: int, role: str) -> bytes:
    if type(fd) is not int or fd < 0:
        raise CandidateAdmissionError("candidate_fd_invalid", "$." + role)
    duplicate = os.dup(fd)
    try:
        before = os.fstat(duplicate)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
            raise CandidateAdmissionError("candidate_fd_type_invalid", "$." + role)
        os.lseek(duplicate, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(duplicate, min(131072, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(duplicate)
        if len(data) > maximum or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
            raise CandidateAdmissionError("candidate_fd_drift", "$." + role)
        return bytes(data)
    finally:
        os.close(duplicate)


_VERIFIED_AUTHORITY = object()


@dataclass(frozen=True, init=False)
class VerifiedSelectedCandidate:
    """Opaque result of one descriptor-bound immutable byte verification."""
    _descriptor: Mapping[str, Any]
    descriptor_sha256: str
    _authority: object

    def __init__(self, descriptor: Mapping[str, Any], descriptor_sha256: str, authority: object = None) -> None:
        if authority is not _VERIFIED_AUTHORITY:
            raise CandidateAdmissionError("candidate_verified_object_not_mintable", "$.candidate")
        object.__setattr__(self, "_descriptor", MappingProxyType(deepcopy(dict(descriptor))))
        object.__setattr__(self, "descriptor_sha256", descriptor_sha256)
        object.__setattr__(self, "_authority", authority)

    def _require_authority(self) -> None:
        if getattr(self, "_authority", None) is not _VERIFIED_AUTHORITY:
            raise CandidateAdmissionError("candidate_verified_object_forged", "$.candidate")

    def public_selection(self) -> Mapping[str, Any]:
        self._require_authority()
        return MappingProxyType({
            **deepcopy(dict(self._descriptor)),
            "artifact_type": "codexmax_authenticated_candidate_selection_v1",
            "state": "selected_descriptor_verified_non_authorizing",
            "descriptor_sha256": self.descriptor_sha256,
            "admission_authority": False,
        })

    def bind_admission(self, admission: Any) -> Mapping[str, Any]:
        self._require_authority()
        if not isinstance(admission, Mapping):
            raise CandidateAdmissionError("candidate_admission_shape_invalid", "$.admission")
        row = dict(admission)
        expected = {
            "protocol_version": self._descriptor["protocol_lineage"]["deployment_admission_protocol"],
            "bootstrap_source_id": self._descriptor["protocol_lineage"]["bootstrap_source_id"],
            "candidate_descriptor_sha256": self.descriptor_sha256,
            "candidate_id": self._descriptor["candidate_id"],
            "archive_sha256": self._descriptor["archive_sha256"],
            "sidecar_sha256": self._descriptor["sidecar_sha256"],
            "source_identity_sha256": self._descriptor["source_identity_sha256"],
            "generation": self._descriptor["generation"],
            "expires_at": self._descriptor["expires_at"],
            "previous_committed_head_sha256": self._descriptor["protocol_lineage"]["previous_committed_head_sha256"],
        }
        if any(row.get(field) != value for field, value in expected.items()):
            raise CandidateAdmissionError("candidate_admission_binding_mismatch", "$.admission")
        installer = self._descriptor["installer"]
        if row.get("installer_identity") != {
            "installer_id": installer["service_id"],
            "installer_build_sha256": installer["service_build_sha256"],
            "installer_start_id": installer["service_start_id"],
            "installer_session_id": installer["service_session_id"],
        }:
            raise CandidateAdmissionError("candidate_installer_binding_mismatch", "$.admission.installer_identity")
        for role, prefix in (("protected_writer", "writer"), ("independent_anchor", "anchor")):
            service = self._descriptor[role]
            if row.get(prefix + "_service_start_id") != service["service_start_id"] or row.get(prefix + "_service_session_id") != service["service_session_id"]:
                raise CandidateAdmissionError("candidate_service_binding_mismatch", "$.admission." + prefix)
        return MappingProxyType(row)


def verify_selected_candidate_fds(
    descriptor_fd: int, archive_fd: int, sidecar_fd: int, *, now: datetime,
) -> VerifiedSelectedCandidate:
    """Bind the selected descriptor to exact inherited archive and sidecar bytes."""
    raw_descriptor = _read_fd(descriptor_fd, maximum=MAX_DESCRIPTOR_BYTES, role="descriptor")
    archive = _read_fd(archive_fd, maximum=MAX_ARCHIVE_BYTES, role="archive")
    sidecar = _read_fd(sidecar_fd, maximum=MAX_DESCRIPTOR_BYTES, role="sidecar")
    try:
        decoded = json.loads(raw_descriptor)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateAdmissionError("candidate_descriptor_json_invalid", "$.descriptor") from exc
    if not isinstance(decoded, Mapping) or raw_descriptor != _canonical(decoded):
        raise CandidateAdmissionError("candidate_descriptor_not_canonical", "$.descriptor")
    descriptor = validate_selected_candidate_descriptor(decoded, now=now)
    if descriptor["archive_sha256"] != _digest(archive) or descriptor["sidecar_sha256"] != _digest(sidecar):
        raise CandidateAdmissionError("candidate_selected_bytes_mismatch", "$.descriptor")
    try:
        sidecar_value = json.loads(sidecar)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateAdmissionError("candidate_sidecar_json_invalid", "$.sidecar") from exc
    if not isinstance(sidecar_value, Mapping):
        raise CandidateAdmissionError("candidate_sidecar_json_invalid", "$.sidecar")
    if sidecar_value.get("artifact_type") != descriptor["runner_artifact_type"]:
        raise CandidateAdmissionError("candidate_sidecar_artifact_mismatch", "$.sidecar")
    if sidecar_value.get("archive", {}).get("sha256") != descriptor["archive_sha256"]:
        raise CandidateAdmissionError("candidate_sidecar_archive_mismatch", "$.sidecar")
    if sidecar_value.get("source", {}).get("source_identity_sha256") != descriptor["source_identity_sha256"]:
        raise CandidateAdmissionError("candidate_sidecar_source_mismatch", "$.sidecar")
    if sidecar_value.get("target") != descriptor["target"]:
        raise CandidateAdmissionError("candidate_sidecar_target_mismatch", "$.sidecar")
    return VerifiedSelectedCandidate(descriptor, _digest(raw_descriptor), _VERIFIED_AUTHORITY)


def source_local_boundary() -> Mapping[str, bool | str]:
    return MappingProxyType({
        "state": "pending_external_os_authenticated_descriptor_and_admission",
        "production_ready": False,
        "admission_authority": False,
        "process_started": False,
        "external_action_performed": False,
    })


__all__ = [
    "ADMISSION_PROTOCOL", "CandidateAdmissionError", "DESCRIPTOR_TYPE",
    "VerifiedSelectedCandidate", "source_local_boundary",
    "validate_selected_candidate_descriptor", "verify_selected_candidate_fds",
]
