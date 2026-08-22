#!/usr/bin/env python3
"""Fail-closed source-local schema for receiver-owned Darwin launch proof.

This module can reject malformed, stale, replayed, or substituted evidence. It
cannot attest to launchd, code-sign, audit-token, filesystem, or process facts.
It therefore never returns a production-positive result.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Collection, Mapping


PROTOCOL_VERSION = "supported_host_darwin_launch_proof_v3"
ARTIFACT_TYPE = "codexmax_darwin_launch_proof_v3"
SOURCE_ID = "codexmax-supported-host-darwin-launch-authority-v1"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

SOURCE_BINDING_FIELDS = (
    "candidate_id",
    "candidate_descriptor_sha256",
    "generation",
    "nonce_sha256",
    "r3_transaction_digest",
)

# Every field in this sequence is a receiver-owned observation. A missing value
# has one exact pending state. The order gives deterministic assessment output.
LIVE_OBSERVATION_FIELDS = (
    "generation_manifest_sha256",
    "generation_manifest_generation",
    "generation_root_path",
    "generation_ancestor_chain_sha256",
    "generation_root_device",
    "generation_root_inode",
    "generation_root_mode",
    "generation_root_uid",
    "generation_root_gid",
    "generation_root_acl_sha256",
    "entrypoint_device",
    "entrypoint_inode",
    "entrypoint_sha256",
    "launchd_label",
    "launchd_domain",
    "launchd_job_sha256",
    "launchd_program",
    "launchd_arguments_sha256",
    "launchd_generation",
    "service_id",
    "service_uid",
    "service_gid",
    "service_groups_sha256",
    "service_generation",
    "static_team_id",
    "static_signing_id",
    "static_cdhash_sha256",
    "static_requirement_sha256",
    "static_executable_sha256",
    "challenge_sha256",
    "challenge_response_sha256",
    "challenge_generation",
    "challenge_issued_at",
    "audit_token_sha256",
    "audit_pid",
    "audit_euid",
    "audit_egid",
    "audit_process_start_id",
    "audit_generation",
    "live_team_id",
    "live_signing_id",
    "live_cdhash_sha256",
    "live_requirement_sha256",
    "live_executable_sha256",
    "live_generation",
    "service_start_id",
    "service_session_id",
    "service_instance_generation",
    "observed_at",
    "expires_at",
)

PENDING_STATES = {
    field: "pending_" + field + "_observation"
    for field in LIVE_OBSERVATION_FIELDS
}

LAUNCH_PROOF_V3_FIELDS = frozenset({
    "schema_version",
    "artifact_type",
    "protocol_version",
    *SOURCE_BINDING_FIELDS,
    *LIVE_OBSERVATION_FIELDS,
    "proof_sha256",
})

EXPECTED_BINDING_FIELDS = frozenset({
    *SOURCE_BINDING_FIELDS,
    *LIVE_OBSERVATION_FIELDS,
})

_SHA_FIELDS = frozenset({
    field for field in EXPECTED_BINDING_FIELDS
    if field.endswith("_sha256") or field == "r3_transaction_digest"
})
_ID_FIELDS = frozenset({
    "candidate_id", "launchd_label", "launchd_domain", "service_id",
    "static_team_id", "static_signing_id", "audit_process_start_id",
    "live_team_id", "live_signing_id", "service_start_id",
    "service_session_id",
})
_INT_FIELDS = frozenset({
    "generation", "generation_manifest_generation", "generation_root_device",
    "generation_root_inode", "generation_root_mode", "generation_root_uid",
    "generation_root_gid", "entrypoint_device", "entrypoint_inode",
    "launchd_generation", "service_uid", "service_gid",
    "service_generation", "challenge_generation", "audit_pid", "audit_euid",
    "audit_egid", "audit_generation", "live_generation",
    "service_instance_generation",
})
_PATH_FIELDS = frozenset({"generation_root_path", "launchd_program"})
_TIME_FIELDS = frozenset({"challenge_issued_at", "observed_at", "expires_at"})


class DarwinLaunchProofError(ValueError):
    """Stable, non-echoing rejection for one launch-proof envelope."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class LaunchProofV3Assessment:
    """A non-authoritative pending result. This type cannot represent success."""

    state: str
    missing_observations: tuple[str, ...]
    production_authority_issued: bool = False
    r3_ledger_advance_allowed: bool = False
    process_started: bool = False
    pathname_reopened: bool = False
    external_action_performed: bool = False

    def __post_init__(self) -> None:
        if not self.state.startswith("pending_"):
            raise ValueError("launch_proof_assessment_must_be_pending")
        if any((
            self.production_authority_issued,
            self.r3_ledger_advance_allowed,
            self.process_started,
            self.pathname_reopened,
            self.external_action_performed,
        )):
            raise ValueError("launch_proof_assessment_cannot_issue_authority")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return deepcopy(value)


def canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            _plain(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise DarwinLaunchProofError("darwin_launch_proof_json_invalid") from exc
    return (encoded + "\n").encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def seal_launch_proof_v3(value: Mapping[str, Any]) -> dict[str, Any]:
    """Seal a source-local test envelope. The digest grants no authority."""

    if not isinstance(value, Mapping) or set(value) != LAUNCH_PROOF_V3_FIELDS:
        raise DarwinLaunchProofError("darwin_launch_proof_shape_invalid")
    result = deepcopy(dict(value))
    result["proof_sha256"] = ""
    result["proof_sha256"] = canonical_digest(result)
    return result


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise DarwinLaunchProofError("darwin_launch_proof_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _validate_path(value: Any, path: str) -> None:
    if not isinstance(value, str):
        raise DarwinLaunchProofError("darwin_launch_proof_path_invalid", path)
    candidate = PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise DarwinLaunchProofError("darwin_launch_proof_path_invalid", path)


def _validate_value(field: str, value: Any, *, nullable: bool) -> None:
    path = "$." + field
    if value is None and nullable:
        return
    if field in _SHA_FIELDS:
        if not isinstance(value, str) or _SHA.fullmatch(value) is None:
            raise DarwinLaunchProofError("darwin_launch_proof_sha256_invalid", path)
        return
    if field in _ID_FIELDS:
        if not isinstance(value, str) or _ID.fullmatch(value) is None:
            raise DarwinLaunchProofError("darwin_launch_proof_identifier_invalid", path)
        return
    if field in _INT_FIELDS:
        minimum = 1 if field in {
            "generation", "generation_manifest_generation", "generation_root_device",
            "generation_root_inode", "entrypoint_device", "entrypoint_inode",
            "launchd_generation", "service_uid", "service_generation",
            "challenge_generation", "audit_pid", "audit_generation",
            "live_generation", "service_instance_generation",
        } else 0
        if type(value) is not int or value < minimum:
            raise DarwinLaunchProofError("darwin_launch_proof_integer_invalid", path)
        return
    if field in _PATH_FIELDS:
        _validate_path(value, path)
        return
    if field in _TIME_FIELDS:
        _time(value, path)
        return
    raise DarwinLaunchProofError("darwin_launch_proof_field_unclassified", path)


def _validate_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != LAUNCH_PROOF_V3_FIELDS:
        raise DarwinLaunchProofError("darwin_launch_proof_shape_invalid")
    row = deepcopy(dict(value))
    if (
        row["schema_version"] != 3
        or row["artifact_type"] != ARTIFACT_TYPE
        or row["protocol_version"] != PROTOCOL_VERSION
    ):
        raise DarwinLaunchProofError("darwin_launch_proof_identity_invalid")
    for field in SOURCE_BINDING_FIELDS:
        _validate_value(field, row[field], nullable=False)
    for field in LIVE_OBSERVATION_FIELDS:
        _validate_value(field, row[field], nullable=True)
    if not isinstance(row["proof_sha256"], str) or _SHA.fullmatch(row["proof_sha256"]) is None:
        raise DarwinLaunchProofError("darwin_launch_proof_sha256_invalid", "$.proof_sha256")
    actual = row["proof_sha256"]
    row["proof_sha256"] = ""
    if actual != canonical_digest(row):
        raise DarwinLaunchProofError("darwin_launch_proof_digest_mismatch", "$.proof_sha256")
    row["proof_sha256"] = actual
    return row


def _validate_expectations(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != EXPECTED_BINDING_FIELDS:
        raise DarwinLaunchProofError("darwin_launch_expectation_shape_invalid", "$.expected")
    row = deepcopy(dict(value))
    for field in SOURCE_BINDING_FIELDS:
        _validate_value(field, row[field], nullable=False)
    for field in LIVE_OBSERVATION_FIELDS:
        _validate_value(field, row[field], nullable=False)
    return row


def _validate_clock(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise DarwinLaunchProofError("darwin_launch_clock_invalid", "$.now")
    if value.tzinfo is None or value.utcoffset() is None:
        raise DarwinLaunchProofError(
            "darwin_launch_clock_timezone_required",
            "$.now",
        )
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _reject_present_relationship_failures(
    row: Mapping[str, Any],
    *,
    current: datetime,
) -> None:
    """Reject each checkable relationship before unrelated pending output."""

    generation = row["generation"]
    for field in (
        "generation_manifest_generation", "launchd_generation",
        "service_generation", "challenge_generation", "audit_generation",
        "live_generation", "service_instance_generation",
    ):
        if row[field] is not None and row[field] != generation:
            raise DarwinLaunchProofError(
                "darwin_launch_mixed_generation_evidence",
                "$." + field,
            )

    if (
        row["static_executable_sha256"] is not None
        and row["entrypoint_sha256"] is not None
        and row["static_executable_sha256"] != row["entrypoint_sha256"]
    ):
        raise DarwinLaunchProofError("darwin_launch_static_code_identity_substitution")

    for static, live in (
        ("static_team_id", "live_team_id"),
        ("static_signing_id", "live_signing_id"),
        ("static_cdhash_sha256", "live_cdhash_sha256"),
        ("static_requirement_sha256", "live_requirement_sha256"),
        ("static_executable_sha256", "live_executable_sha256"),
    ):
        if row[static] is not None and row[live] is not None and row[static] != row[live]:
            raise DarwinLaunchProofError(
                "darwin_launch_live_code_identity_substitution",
                "$." + live,
            )

    if (
        row["audit_euid"] is not None
        and row["service_uid"] is not None
        and row["audit_euid"] != row["service_uid"]
    ) or (
        row["audit_egid"] is not None
        and row["service_gid"] is not None
        and row["audit_egid"] != row["service_gid"]
    ):
        raise DarwinLaunchProofError("darwin_launch_service_identity_substitution")
    if (
        row["generation_root_uid"] is not None
        and row["service_uid"] is not None
        and row["generation_root_uid"] == row["service_uid"]
    ):
        raise DarwinLaunchProofError("darwin_launch_same_uid_forbidden")

    challenged = (
        _time(row["challenge_issued_at"], "$.challenge_issued_at")
        if row["challenge_issued_at"] is not None else None
    )
    observed = (
        _time(row["observed_at"], "$.observed_at")
        if row["observed_at"] is not None else None
    )
    expires = (
        _time(row["expires_at"], "$.expires_at")
        if row["expires_at"] is not None else None
    )
    if (
        (challenged is not None and observed is not None and challenged > observed)
        or (observed is not None and observed > current)
        or (expires is not None and expires <= current)
        or (observed is not None and expires is not None and observed >= expires)
    ):
        raise DarwinLaunchProofError("darwin_launch_proof_stale_or_expired")


def assess_launch_proof_v3(
    value: Any,
    *,
    expected_bindings: Mapping[str, Any],
    previous_committed_generation: int,
    now: datetime,
    seen_proof_sha256s: Collection[str] = (),
    seen_nonce_sha256s: Collection[str] = (),
) -> LaunchProofV3Assessment:
    """Reject unsafe evidence and otherwise return one pending-only result.

    Expected bindings and replay sets are rejection inputs only. Caller values,
    callbacks, fixtures, certificates, self-digests, and source-local simulation
    cannot convert this assessment into production authority.
    """

    current = _validate_clock(now)
    row = _validate_envelope(value)
    expected = _validate_expectations(expected_bindings)
    if type(previous_committed_generation) is not int or previous_committed_generation < 0:
        raise DarwinLaunchProofError(
            "darwin_launch_previous_generation_invalid",
            "$.previous_committed_generation",
        )
    if row["generation"] != previous_committed_generation + 1:
        raise DarwinLaunchProofError("darwin_launch_rollback_or_generation_gap", "$.generation")
    for field in SOURCE_BINDING_FIELDS:
        if row[field] != expected[field]:
            raise DarwinLaunchProofError("darwin_launch_" + field + "_substitution", "$." + field)

    if row["proof_sha256"] in seen_proof_sha256s:
        raise DarwinLaunchProofError("darwin_launch_proof_replay", "$.proof_sha256")
    if row["nonce_sha256"] in seen_nonce_sha256s:
        raise DarwinLaunchProofError("darwin_launch_nonce_replay", "$.nonce_sha256")

    missing = tuple(field for field in LIVE_OBSERVATION_FIELDS if row[field] is None)
    for field in LIVE_OBSERVATION_FIELDS:
        if row[field] is not None and row[field] != expected[field]:
            raise DarwinLaunchProofError("darwin_launch_" + field + "_substitution", "$." + field)

    _reject_present_relationship_failures(row, current=current)

    if missing:
        return LaunchProofV3Assessment(
            state=PENDING_STATES[missing[0]],
            missing_observations=missing,
        )

    # Schema closure and parity are source-local proof only. The receiver must
    # independently own and verify every live fact before it calls the unchanged
    # R3 writer/anchor commit boundary.
    return LaunchProofV3Assessment(
        state="pending_receiver_owned_live_attestation",
        missing_observations=(),
    )


def source_local_validation_boundary() -> LaunchProofV3Assessment:
    """Return the fixed non-authoritative boundary for source-local work."""

    return LaunchProofV3Assessment(
        state=PENDING_STATES[LIVE_OBSERVATION_FIELDS[0]],
        missing_observations=LIVE_OBSERVATION_FIELDS,
    )


__all__ = [
    "ARTIFACT_TYPE",
    "DarwinLaunchProofError",
    "EXPECTED_BINDING_FIELDS",
    "LAUNCH_PROOF_V3_FIELDS",
    "LIVE_OBSERVATION_FIELDS",
    "LaunchProofV3Assessment",
    "PENDING_STATES",
    "PROTOCOL_VERSION",
    "SOURCE_BINDING_FIELDS",
    "SOURCE_ID",
    "assess_launch_proof_v3",
    "canonical_bytes",
    "canonical_digest",
    "seal_launch_proof_v3",
    "source_local_validation_boundary",
]
