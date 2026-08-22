#!/usr/bin/env python3
"""Credential-safe fixed operator supervisor and installer-evidence plan."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import re
import select
import socket
import stat
import struct
import tarfile
from typing import Any, Mapping, Sequence, TextIO
from pathlib import Path

from supported_host_public_profile_v1 import (
    PENDING_PUBLIC_CANDIDATE_SELECTION,
    HISTORICAL_RUNNER_V23_IDENTITY,
)
from supported_host_candidate_admission_v1 import (
    CandidateAdmissionError,
    VerifiedSelectedCandidate,
    verify_selected_candidate_fds,
)

DEPLOYMENT_ADMISSION_PROTOCOL = "supported_host_deployment_admission_v2"
DEPLOYMENT_BOOTSTRAP_SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v2"


DEPLOYMENT_ADMISSION_V2_COMPATIBILITY = {
    "identity_type": "bootstrap_bound_deployment_admission_v2",
    "protocol_version": DEPLOYMENT_ADMISSION_PROTOCOL,
    "bootstrap_source_id": DEPLOYMENT_BOOTSTRAP_SOURCE_ID,
    "minimum_generation": 1,
    "legacy_migration_candidate": HISTORICAL_RUNNER_V23_IDENTITY["candidate_id"],
}
ACCEPTED_INSTALLER_IDENTITY = {
    "installer_id": "codexmax-independent-installer-v1",
    "installer_build_sha256": "sha256:2e7dc78aa879b1daf2b88ae44829891657463d47cb18b0c12dc98b308f27b67a",
    "installer_start_id": "codexmax-independent-installer-start-v1",
    "installer_session_id": "codexmax-independent-installer-session-v1",
}
# Retained only so old source-local evidence has an explicit reject target.
# This mapping is never used by the selected-candidate verifier or lifecycle.
RETIRED_STATIC_CANDIDATE = {
    "candidate_id": "codexmax-package-host-runner-v26",
    "archive_sha256": "sha256:cab9506c8004038e3545a41077e0f1fad9935590e40ac21a1f2f3935caa934af",
    "sidecar_sha256": "sha256:449496e0307658564e093bfc6bd2c0e9a36bf1964cf6d3fde7a419d4fc1d70e4",
    "source_identity_sha256": "sha256:c4940e2136ffb856a437dd8b6bd3237f4884828d564e0901fe1d693d041c6fd6",
    "target": "orcastrata:retired-package-host-runner:v26:codexmax-package-host-runner-bundle-v26",
    "admission_authority": False,
}
INSTALLER_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "installer_id", "installer_build_sha256",
    "installer_start_id", "installer_session_id", "challenge", "candidate_id",
    "runner_target", "request_sha256",
})
INSTALLER_EVIDENCE_FIELDS = frozenset({
    "schema_version", "artifact_type", "candidate_id", "archive_sha256",
    "sidecar_sha256", "source_identity_sha256", "runner_target", "installer_id",
    "installer_build_sha256", "installer_start_id", "installer_session_id",
    "observed_at", "expires_at", "evidence_sha256",
})
INSTALLER_RESPONSE_FIELDS = frozenset({"challenge", "request_sha256", "evidence", "response_sha256"})
FIXED_ROLES = (
    "protected_writer", "independent_anchor", "opaque_tls_agent",
    "catalog_selection", "native_supervision", "responses_seals",
    "effect_authority", "registered_action", "recovery",
)
OPERATIONS = (
    "read_capability_admission", "open_operator_listener",
    "read_operator_preset_bundle", "read_operator_selection_head",
    "read_operator_selection_mutation", "commit_operator_selection",
    "read_operator_supervision", "issue_responses_context",
    "verify_effect_authority", "invoke_registered_action",
    "verify_responses_bridge", "commit_or_verify_record",
    "seal_or_verify_projection", "read_operator_recovery_lease_grant",
)
FD_ROLES = tuple(role + "_fd" for role in FIXED_ROLES) + (
    "deployment_admission_fd", "credential_agent_fd", "runtime_root_fd",
)
SAFETY = {"writes": False, "process_started": False, "socket_opened": False, "network_accessed": False, "external_action_performed": False}

PROTECTED_SERVICE_PROTOCOL = "supported_host_protected_service_v1"
OPERATION_SOURCE_PROTOCOL = "supported_host_operation_sources_v1"
INSTALLER_FRAME_MAX_BYTES = 65536
SERVICE_FRAME_MAX_BYTES = 4 * 1024 * 1024
JOINT_SERVICES = ("protected_writer", "independent_anchor", "opaque_tls_agent")
OPERATION_SOURCE_OWNERS = (
    "catalog_selection", "native_supervision", "responses_seals",
    "effect_authority", "registered_action", "recovery",
)
JOINT_AUTHORITY_ROLES = JOINT_SERVICES + OPERATION_SOURCE_OWNERS
JOINT_AUTHORITY_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "authority_id",
    "execution_scope", "roles", "external_peers", "channel_policies",
    "authority_sha256",
})
JOINT_ROLE_FIELDS = frozenset({
    "role_id", "service_id", "service_build_sha256", "expected_uid",
    "expected_gid", "supplemental_groups", "root_identity",
    "expected_service_start_id", "expected_service_session_id",
    "session_expires_at", "allowed_inbound_channel_ids",
    "allowed_outbound_channel_ids",
})
ROOT_IDENTITY_FIELDS = frozenset({"root_id", "device", "inode"})
EXTERNAL_PEER_FIELDS = frozenset({
    "peer_id", "expected_uid", "expected_groups", "peer_start_id",
    "peer_session_id", "session_expires_at", "allowed_channel_ids",
})
CHANNEL_POLICY_FIELDS = frozenset({
    "channel_id", "client_kind", "client_id", "server_role",
    "request_type", "response_type", "one_use",
})
OPERATION_SOURCE_SERVICE_FIELDS = frozenset({
    "schema_version", "artifact_type", "owner_id", "source_id",
    "source_build_sha256", "expected_uid", "expected_gid", "service_start_id",
    "service_session_id", "protocol_version", "max_frame_bytes",
})
_SOURCE_CHANNELS = {
    owner_id: f"protected_writer_to_{owner_id}"
    for owner_id in OPERATION_SOURCE_OWNERS
}
_ARTIFACT_EDGE_POLICIES = {
    "catalog_selection_to_responses_selection_v1": ("responses_seals", "catalog_selection"),
    "native_supervision_to_responses_context_v1": ("responses_seals", "native_supervision"),
    "responses_context_to_effect_authority_v1": ("effect_authority", "responses_seals"),
    "effect_authority_to_registered_action_v1": ("registered_action", "effect_authority"),
    "registered_action_to_responses_bridge_v1": ("responses_seals", "registered_action"),
    "responses_projection_to_recovery_v1": ("recovery", "responses_seals"),
    "native_supervision_to_recovery_v1": ("recovery", "native_supervision"),
    "effect_authority_to_recovery_v1": ("recovery", "effect_authority"),
}
FIXED_JOINT_CHANNEL_POLICIES = {
    "protected_writer_to_independent_anchor": {
        "client_kind": "role", "client_id": "protected_writer",
        "server_role": "independent_anchor",
        "request_type": "supported_host_protected_service_request_v1",
        "response_type": "supported_host_protected_service_command_response_v1",
        "one_use": True,
    },
    **{
        channel_id: {
            "client_kind": "role", "client_id": "protected_writer",
            "server_role": owner_id,
            "request_type": "supported_host_joint_operation_source_request_v1",
            "response_type": "supported_host_joint_operation_source_response_v1",
            "one_use": True,
        }
        for owner_id, channel_id in _SOURCE_CHANNELS.items()
    },
    **{
        edge_id: {
            "client_kind": "role", "client_id": consumer_role,
            "server_role": producer_role,
            "request_type": "supported_host_cross_owner_request_v1",
            "response_type": "supported_host_cross_owner_response_v1",
            "one_use": True,
        }
        for edge_id, (consumer_role, producer_role) in _ARTIFACT_EDGE_POLICIES.items()
    },
    "runtime_to_protected_writer": {
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "protected_writer",
        "request_type": "supported_host_protected_service_request_v1",
        "response_type": "supported_host_protected_service_response_v1",
        "one_use": True,
    },
    "runtime_to_independent_anchor": {
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "independent_anchor",
        "request_type": "supported_host_protected_service_request_v1",
        "response_type": "supported_host_protected_service_response_v1",
        "one_use": True,
    },
    "runtime_to_opaque_tls_agent": {
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "opaque_tls_agent",
        "request_type": "supported_host_opaque_tls_request_v1",
        "response_type": "supported_host_opaque_tls_response_v1",
        "one_use": True,
    },
    "opaque_tls_agent_to_credential_agent": {
        "client_kind": "role", "client_id": "opaque_tls_agent",
        "server_role": "external:credential_agent",
        "request_type": "supported_host_opaque_credential_agent_request_v1",
        "response_type": "supported_host_opaque_credential_agent_response_v1",
        "one_use": True,
    },
    **{
        f"{peer_id}_to_{owner_id}": {
            "client_kind": "external_peer", "client_id": peer_id,
            "server_role": owner_id,
            "request_type": f"supported_host_{owner_id}_raw_observation_v1",
            "response_type": "supported_host_raw_observation_ack_v1",
            "one_use": True,
        }
        for peer_id, owner_id in (
            ("catalog_receiver", "catalog_selection"),
            ("native_observer", "native_supervision"),
            ("responses_receiver", "responses_seals"),
            ("authority_issuer", "effect_authority"),
            ("action_executor", "registered_action"),
            ("reconciliation_receiver", "recovery"),
        )
    },
}
_AUTHORITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_AUTHORITY_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTHORITY_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SENSITIVE_IDENTIFIER_PARTS = (
    "password", "private", "secret", "token", "apikey",
)


class SupervisorError(ValueError):
    def __init__(self, code: str, residue: Sequence[str] = ()) -> None:
        self.code = code
        self.residue = tuple(residue)
        super().__init__(code)


class PublicAuthorityError(ValueError):
    """Stable non-echoing rejection from the import-closed pure validators."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _authority_closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise PublicAuthorityError(code, path)
    return {key: _authority_plain(item) for key, item in value.items()}


def _authority_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _authority_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_authority_plain(item) for item in value]
    return deepcopy(value)


def _authority_identifier(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or _AUTHORITY_ID.fullmatch(value) is None:
        raise PublicAuthorityError(code, path)
    lowered = value.lower()
    if any(part in lowered for part in _SENSITIVE_IDENTIFIER_PARTS):
        raise PublicAuthorityError(code, path)
    if any(part in value for part in ("/", "\\", "..", "~")):
        raise PublicAuthorityError(code, path)
    return value


def _authority_digest(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or _AUTHORITY_SHA256.fullmatch(value) is None:
        raise PublicAuthorityError(code, path)
    return value


def _authority_time(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or _AUTHORITY_TIME.fullmatch(value) is None:
        raise PublicAuthorityError(code, path)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PublicAuthorityError(code, path) from exc
    return value


def _authority_seal(value: Mapping[str, Any], field: str) -> str:
    row = deepcopy(dict(value))
    row[field] = ""
    try:
        raw = (json.dumps(
            row, allow_nan=False, ensure_ascii=False, separators=(",", ":"),
            sort_keys=True,
        ) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublicAuthorityError("public_authority_json_invalid") from exc
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def expected_joint_role_channels(role: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if role not in JOINT_AUTHORITY_ROLES:
        raise PublicAuthorityError("joint_authority_role_id_invalid", "$.authority.roles")
    inbound = tuple(sorted(
        channel_id for channel_id, policy in FIXED_JOINT_CHANNEL_POLICIES.items()
        if policy["server_role"] == role
    ))
    outbound = tuple(sorted(
        channel_id for channel_id, policy in FIXED_JOINT_CHANNEL_POLICIES.items()
        if policy["client_kind"] == "role" and policy["client_id"] == role
    ))
    return inbound, outbound


def validate_complete_joint_authority(value: Any) -> dict[str, Any]:
    """Validate the complete fixed joint authority without runtime imports."""

    row = _authority_closed(value, JOINT_AUTHORITY_FIELDS, "joint_authority_shape_invalid", "$.authority")
    if (
        row["schema_version"] != 1
        or row["artifact_type"] != "supported_host_joint_service_authority_v1"
    ):
        raise PublicAuthorityError("joint_authority_identity_invalid", "$.authority")
    if row["protocol_version"] != PROTECTED_SERVICE_PROTOCOL:
        raise PublicAuthorityError("joint_authority_protocol_invalid", "$.authority.protocol_version")
    _authority_identifier(row["authority_id"], "joint_authority_id_invalid", "$.authority.authority_id")
    if row["execution_scope"] not in {"source_local_test", "live_external_candidate"}:
        raise PublicAuthorityError("joint_authority_execution_scope_invalid", "$.authority.execution_scope")
    if not isinstance(row["roles"], Mapping) or set(row["roles"]) != set(JOINT_AUTHORITY_ROLES):
        raise PublicAuthorityError("joint_authority_roles_invalid", "$.authority.roles")
    if (
        not isinstance(row["channel_policies"], Mapping)
        or set(row["channel_policies"]) != set(FIXED_JOINT_CHANNEL_POLICIES)
    ):
        raise PublicAuthorityError("joint_authority_channels_invalid", "$.authority.channel_policies")

    roles: dict[str, dict[str, Any]] = {}
    for role in JOINT_AUTHORITY_ROLES:
        path = f"$.authority.roles.{role}"
        item = _authority_closed(row["roles"][role], JOINT_ROLE_FIELDS, "joint_authority_role_shape_invalid", path)
        if item["role_id"] != role:
            raise PublicAuthorityError("joint_authority_role_id_invalid", path + ".role_id")
        _authority_identifier(item["service_id"], "joint_authority_service_id_invalid", path + ".service_id")
        _authority_digest(item["service_build_sha256"], "joint_authority_build_digest_invalid", path + ".service_build_sha256")
        _authority_identifier(item["expected_service_start_id"], "joint_authority_start_id_invalid", path + ".expected_service_start_id")
        _authority_identifier(item["expected_service_session_id"], "joint_authority_session_id_invalid", path + ".expected_service_session_id")
        _authority_time(item["session_expires_at"], "joint_authority_expiry_invalid", path + ".session_expires_at")
        if type(item["expected_uid"]) is not int or item["expected_uid"] < 1:
            raise PublicAuthorityError("joint_authority_uid_invalid", path + ".expected_uid")
        if type(item["expected_gid"]) is not int or item["expected_gid"] < 1:
            raise PublicAuthorityError("joint_authority_gid_invalid", path + ".expected_gid")
        groups = item["supplemental_groups"]
        if (
            not isinstance(groups, list)
            or any(type(group) is not int or group < 1 for group in groups)
            or groups != sorted(set(groups))
        ):
            raise PublicAuthorityError("joint_authority_groups_invalid", path + ".supplemental_groups")
        root = _authority_closed(item["root_identity"], ROOT_IDENTITY_FIELDS, "joint_authority_root_shape_invalid", path + ".root_identity")
        _authority_identifier(root["root_id"], "joint_authority_root_id_invalid", path + ".root_identity.root_id")
        if any(type(root[field]) is not int or root[field] < 1 for field in ("device", "inode")):
            raise PublicAuthorityError("joint_authority_root_identity_invalid", path + ".root_identity")
        inbound, outbound = expected_joint_role_channels(role)
        if item["allowed_inbound_channel_ids"] != list(inbound):
            raise PublicAuthorityError("joint_authority_inbound_channels_invalid", path + ".allowed_inbound_channel_ids")
        if item["allowed_outbound_channel_ids"] != list(outbound):
            raise PublicAuthorityError("joint_authority_outbound_channels_invalid", path + ".allowed_outbound_channel_ids")
        roles[role] = item

    for field, code in (
        ("service_id", "joint_authority_service_id_collision"),
        ("expected_uid", "joint_authority_uid_collision"),
        ("expected_gid", "joint_authority_gid_collision"),
        ("expected_service_start_id", "joint_authority_start_collision"),
        ("expected_service_session_id", "joint_authority_session_collision"),
    ):
        if len({item[field] for item in roles.values()}) != len(roles):
            raise PublicAuthorityError(code, "$.authority.roles")
    roots = {
        (item["root_identity"]["root_id"], item["root_identity"]["device"], item["root_identity"]["inode"])
        for item in roles.values()
    }
    if len(roots) != len(roles):
        raise PublicAuthorityError("joint_authority_root_collision", "$.authority.roles")
    primary_groups = {item["expected_gid"] for item in roles.values()}
    supplemental = [group for item in roles.values() for group in item["supplemental_groups"]]
    if primary_groups.intersection(supplemental) or len(supplemental) != len(set(supplemental)):
        raise PublicAuthorityError("joint_authority_group_collision", "$.authority.roles")

    channels: dict[str, dict[str, Any]] = {}
    for channel_id, fixed in FIXED_JOINT_CHANNEL_POLICIES.items():
        path = f"$.authority.channel_policies.{channel_id}"
        item = _authority_closed(row["channel_policies"][channel_id], CHANNEL_POLICY_FIELDS, "joint_authority_channel_shape_invalid", path)
        if item != {"channel_id": channel_id, **fixed}:
            raise PublicAuthorityError("joint_authority_channel_policy_invalid", path)
        channels[channel_id] = item

    external_ids = {
        policy["client_id"] for policy in FIXED_JOINT_CHANNEL_POLICIES.values()
        if policy["client_kind"] == "external_peer"
    } | {"credential_agent"}
    if not isinstance(row["external_peers"], Mapping) or set(row["external_peers"]) != external_ids:
        raise PublicAuthorityError("joint_authority_external_peers_invalid", "$.authority.external_peers")
    peers: dict[str, dict[str, Any]] = {}
    for peer_id in sorted(external_ids):
        path = f"$.authority.external_peers.{peer_id}"
        item = _authority_closed(row["external_peers"][peer_id], EXTERNAL_PEER_FIELDS, "joint_authority_external_peer_shape_invalid", path)
        if item["peer_id"] != peer_id:
            raise PublicAuthorityError("joint_authority_external_peer_id_invalid", path + ".peer_id")
        if type(item["expected_uid"]) is not int or item["expected_uid"] < 1:
            raise PublicAuthorityError("joint_authority_external_uid_invalid", path + ".expected_uid")
        groups = item["expected_groups"]
        if (
            not isinstance(groups, list)
            or any(type(group) is not int or group < 1 for group in groups)
            or groups != sorted(set(groups))
        ):
            raise PublicAuthorityError("joint_authority_external_groups_invalid", path + ".expected_groups")
        _authority_identifier(item["peer_start_id"], "joint_authority_external_start_invalid", path + ".peer_start_id")
        _authority_identifier(item["peer_session_id"], "joint_authority_external_session_invalid", path + ".peer_session_id")
        _authority_time(item["session_expires_at"], "joint_authority_external_expiry_invalid", path + ".session_expires_at")
        expected_channels = sorted(
            channel_id for channel_id, policy in FIXED_JOINT_CHANNEL_POLICIES.items()
            if (policy["client_kind"] == "external_peer" and policy["client_id"] == peer_id)
            or (peer_id == "credential_agent" and policy["server_role"] == "external:credential_agent")
        )
        if item["allowed_channel_ids"] != expected_channels:
            raise PublicAuthorityError("joint_authority_external_channels_invalid", path + ".allowed_channel_ids")
        peers[peer_id] = item

    peer_uids = [item["expected_uid"] for item in peers.values()]
    peer_groups = [group for item in peers.values() for group in item["expected_groups"]]
    peer_starts = [item["peer_start_id"] for item in peers.values()]
    peer_sessions = [item["peer_session_id"] for item in peers.values()]
    if len(peer_uids) != len(set(peer_uids)) or set(peer_uids).intersection(item["expected_uid"] for item in roles.values()):
        raise PublicAuthorityError("joint_authority_external_uid_collision", "$.authority.external_peers")
    if len(peer_groups) != len(set(peer_groups)) or set(peer_groups).intersection(primary_groups) or set(peer_groups).intersection(supplemental):
        raise PublicAuthorityError("joint_authority_external_group_collision", "$.authority.external_peers")
    if len(peer_starts) != len(set(peer_starts)) or set(peer_starts).intersection(item["expected_service_start_id"] for item in roles.values()):
        raise PublicAuthorityError("joint_authority_external_start_collision", "$.authority.external_peers")
    if len(peer_sessions) != len(set(peer_sessions)) or set(peer_sessions).intersection(item["expected_service_session_id"] for item in roles.values()):
        raise PublicAuthorityError("joint_authority_external_session_collision", "$.authority.external_peers")
    if row["authority_sha256"] != _authority_seal(row, "authority_sha256"):
        raise PublicAuthorityError("joint_authority_digest_invalid", "$.authority.authority_sha256")
    return {**row, "roles": roles, "external_peers": peers, "channel_policies": channels}


def validate_operation_source_service_configuration(
    value: Any, *, expected_owner: str | None = None,
) -> dict[str, Any]:
    """Validate one fixed operation-source service configuration."""

    path = "$.operation_source_service" if expected_owner is None else f"$.operation_source_services.{expected_owner}"
    row = _authority_closed(value, OPERATION_SOURCE_SERVICE_FIELDS, "operation_source_service_shape_invalid", path)
    owner = row.get("owner_id")
    if expected_owner is not None and owner != expected_owner:
        raise PublicAuthorityError("operation_source_service_identity_invalid", path)
    if (
        row["schema_version"] != 1
        or row["artifact_type"] != "supported_host_operation_source_config_v1"
        or row["protocol_version"] != OPERATION_SOURCE_PROTOCOL
        or owner not in OPERATION_SOURCE_OWNERS
        or row["source_id"] != owner.replace("_", "-") + "-owner-v1"
    ):
        raise PublicAuthorityError("operation_source_service_identity_invalid", path)
    _authority_identifier(row["source_id"], "operation_source_service_identity_invalid", path + ".source_id")
    _authority_digest(row["source_build_sha256"], "operation_source_service_build_digest_invalid", path + ".source_build_sha256")
    _authority_identifier(row["service_start_id"], "operation_source_service_start_id_invalid", path + ".service_start_id")
    _authority_identifier(row["service_session_id"], "operation_source_service_session_id_invalid", path + ".service_session_id")
    if type(row["expected_uid"]) is not int or row["expected_uid"] < 1:
        raise PublicAuthorityError("operation_source_service_uid_invalid", path + ".expected_uid")
    if type(row["expected_gid"]) is not int or row["expected_gid"] < 1:
        raise PublicAuthorityError("operation_source_service_gid_invalid", path + ".expected_gid")
    if type(row["max_frame_bytes"]) is not int or not 1024 <= row["max_frame_bytes"] <= SERVICE_FRAME_MAX_BYTES:
        raise PublicAuthorityError("operation_source_service_frame_limit_invalid", path + ".max_frame_bytes")
    return row


def validate_operation_source_service_set(value: Any) -> dict[str, dict[str, Any]]:
    """Validate the complete fixed operation-source service set."""

    if not isinstance(value, Mapping) or set(value) != set(OPERATION_SOURCE_OWNERS):
        raise PublicAuthorityError("operation_source_service_set_invalid", "$.operation_source_services")
    rows = {
        owner: validate_operation_source_service_configuration(value[owner], expected_owner=owner)
        for owner in OPERATION_SOURCE_OWNERS
    }
    for field, code in (
        ("source_id", "operation_source_service_identity_collision"),
        ("expected_uid", "operation_source_service_uid_collision"),
        ("expected_gid", "operation_source_service_gid_collision"),
        ("service_start_id", "operation_source_service_start_collision"),
        ("service_session_id", "operation_source_service_session_collision"),
    ):
        if len({row[field] for row in rows.values()}) != len(rows):
            raise PublicAuthorityError(code, "$.operation_source_services")
    return rows


def validate_complete_start_authority(
    authority: Any, source_services: Any,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Validate both closed objects and their fixed cross-role bindings."""

    joint = validate_complete_joint_authority(authority)
    sources = validate_operation_source_service_set(source_services)
    for owner, source in sources.items():
        role = joint["roles"][owner]
        expected = (
            ("source_id", "service_id"),
            ("source_build_sha256", "service_build_sha256"),
            ("expected_uid", "expected_uid"),
            ("expected_gid", "expected_gid"),
            ("service_start_id", "expected_service_start_id"),
            ("service_session_id", "expected_service_session_id"),
        )
        if any(source[source_field] != role[role_field] for source_field, role_field in expected):
            raise PublicAuthorityError(
                "operation_source_joint_role_mismatch",
                f"$.operation_source_services.{owner}",
            )
    return joint, sources


def _canonical(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = dict(value)
    row[field] = ""
    row[field] = _sha(_canonical(row))
    return row


def _wire_canonical(value: Any) -> bytes:
    return _canonical(value) + b"\n"


def _wire_seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = dict(value)
    row[field] = ""
    row[field] = _sha(_wire_canonical(row))
    return row


def _recv_exact(channel: socket.socket, count: int, code: str) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        try:
            part = channel.recv(count - len(chunks))
        except (OSError, TimeoutError) as exc:
            raise SupervisorError(code) from exc
        if not part:
            raise SupervisorError(code)
        chunks.extend(part)
    return bytes(chunks)


def _reject_trailing_frame_data(channel: socket.socket) -> None:
    try:
        readable, _, _ = select.select([channel], [], [], 0)
    except (OSError, ValueError) as exc:
        raise SupervisorError("installer_channel_failed") from exc
    if not readable:
        return
    flags = getattr(socket, "MSG_PEEK", 0) | getattr(socket, "MSG_DONTWAIT", 0)
    if not flags:
        return
    try:
        trailing = channel.recv(1, flags)
    except (BlockingIOError, TimeoutError):
        return
    except OSError as exc:
        if exc.errno in {getattr(os, "EAGAIN", 11), getattr(os, "EWOULDBLOCK", 11)}:
            return
        raise SupervisorError("installer_channel_failed") from exc
    if trailing:
        raise SupervisorError("installer_request_trailing_data")


def _installer_request(value: Any, selected_candidate: VerifiedSelectedCandidate) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != INSTALLER_REQUEST_FIELDS:
        raise SupervisorError("installer_request_shape_invalid")
    row = dict(value)
    if row["schema_version"] != 1 or row["artifact_type"] != "codexmax_selected_candidate_installer_evidence_request_v1":
        raise SupervisorError("installer_request_identity_invalid")
    descriptor = selected_candidate._descriptor
    installer = descriptor["installer"]
    expected = {
        "installer_id": installer["service_id"],
        "installer_build_sha256": installer["service_build_sha256"],
        "installer_start_id": installer["service_start_id"],
        "installer_session_id": installer["service_session_id"],
        "candidate_id": descriptor["candidate_id"],
        "runner_target": descriptor["target"],
    }
    if any(row.get(field) != item for field, item in expected.items()):
        raise SupervisorError("installer_request_binding_mismatch")
    challenge = row.get("challenge")
    if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128 or not all(character.isalnum() or character in "_-" for character in challenge):
        raise SupervisorError("installer_request_challenge_invalid")
    if _sha(challenge.encode("utf-8")) != descriptor["challenge_sha256"]:
        raise SupervisorError("installer_request_challenge_binding_mismatch")
    if row.get("request_sha256") != _wire_seal(row, "request_sha256")["request_sha256"]:
        raise SupervisorError("installer_request_digest_mismatch")
    return row


def _read_inherited(fd: int) -> bytes:
    if type(fd) is not int or fd < 0:
        raise SupervisorError("inherited_artifact_fd_invalid")
    duplicate = os.dup(fd)
    try:
        before = os.fstat(duplicate)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > 16 * 1024 * 1024:
            raise SupervisorError("inherited_artifact_invalid")
        os.lseek(duplicate, 0, os.SEEK_SET); chunks = []
        while True:
            chunk = os.read(duplicate, 131072)
            if not chunk: break
            chunks.append(chunk)
        after = os.fstat(duplicate)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SupervisorError("inherited_artifact_drift")
        return b"".join(chunks)
    finally:
        os.close(duplicate)


def verify_accepted_runner_fds(descriptor_fd: int, archive_fd: int, sidecar_fd: int, *, now: datetime) -> Mapping[str, Any]:
    """Verify exact descriptor-selected bytes without compile-time candidate pins."""
    try:
        selected = verify_selected_candidate_fds(descriptor_fd, archive_fd, sidecar_fd, now=now)
    except CandidateAdmissionError as exc:
        raise SupervisorError(exc.code) from exc
    archive = _read_inherited(archive_fd); sidecar_raw = _read_inherited(sidecar_fd)
    descriptor = selected._descriptor
    try:
        sidecar = json.loads(sidecar_raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("installer_sidecar_invalid") from exc
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            members = [item for item in bundle.getmembers() if item.isfile()]
    except tarfile.TarError as exc:
        raise SupervisorError("installer_archive_invalid") from exc
    if len(members) != sidecar.get("member_count") or len(members) != len(sidecar.get("members", [])):
        raise SupervisorError("installer_archive_inventory_mismatch")
    return {"state": "selected_candidate_verified", "selected_candidate": selected, "candidate": dict(selected.public_selection()), "member_count": len(members), **SAFETY}


def validate_public_request_fd(fd: int, request_type: str) -> Mapping[str, Any]:
    """Read one canonical public request from an inherited regular-file FD."""
    try:
        raw = _read_inherited(fd)
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("supervisor_public_request_invalid") from exc
    if not isinstance(value, Mapping) or raw != _canonical(value):
        raise SupervisorError("supervisor_public_request_invalid")
    shapes = {
        "handshake": {"artifact_type", "candidate_id", "peer_identity", "service_start_id", "session_id"},
        "admission": {"artifact_type", "challenge", "handshake_seal_sha256"},
        "journey": {"artifact_type", "operations"},
        "stop": {"artifact_type", "reason"},
    }
    if request_type not in shapes or set(value) != shapes[request_type] or value["artifact_type"] != f"codexmax_supported_host_{request_type}_request_v1":
        raise SupervisorError("supervisor_public_request_shape_invalid")
    if request_type == "handshake":
        if not _public_identifier(value["candidate_id"]) or any(not _public_identifier(value[key]) for key in ("peer_identity", "service_start_id", "session_id")):
            raise SupervisorError("supervisor_public_request_binding_invalid")
    elif request_type == "admission":
        if not _public_identifier(value["challenge"]) or not _digest_syntax(value["handshake_seal_sha256"]):
            raise SupervisorError("supervisor_public_request_binding_invalid")
    elif request_type == "journey":
        if tuple(value["operations"]) != OPERATIONS:
            raise SupervisorError("supervisor_public_request_binding_invalid")
    elif value["reason"] != "operator_stop":
        raise SupervisorError("supervisor_public_request_binding_invalid")
    return {"state": "public_request_validated_non_authoritative", "request_type": request_type, "request_sha256": _sha(raw), **SAFETY}


def _digest_syntax(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(character in "0123456789abcdef" for character in value[7:])


def _public_identifier(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 256 or not value[0].isalnum():
        return False
    if not all(character.isalnum() or character in "_.:-" for character in value):
        return False
    lowered = value.lower()
    return not any(part in lowered for part in ("password", "private", "secret", "credential", "token", "key"))


class InstallerEvidenceServer:
    """Serve one verified evidence response over one inherited AF_UNIX channel."""
    def __init__(self, channel: socket.socket, descriptor_fd: int, archive_fd: int, sidecar_fd: int, *, now: datetime) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise SupervisorError("installer_evidence_server_invalid")
        self._channel = channel; self._verified = dict(verify_accepted_runner_fds(descriptor_fd, archive_fd, sidecar_fd, now=now)); self._used = False
        info=os.fstat(channel.fileno());self._fingerprint=(info.st_dev,info.st_ino,info.st_mode)

    def serve_one(self) -> Mapping[str, Any]:
        if self._used: raise SupervisorError("installer_evidence_server_reused")
        self._used = True
        current=os.fstat(self._channel.fileno())
        if (current.st_dev,current.st_ino,current.st_mode)!=self._fingerprint:raise SupervisorError("installer_channel_substituted")
        try: peer_uid,_=self._channel.getpeereid()
        except (AttributeError,OSError): raise SupervisorError("installer_external_peer_identity_required")
        if peer_uid==os.geteuid(): raise SupervisorError("installer_external_peer_identity_required")
        header = _recv_exact(self._channel, 4, "installer_request_truncated")
        size = struct.unpack("!I", header)[0]
        if size < 2 or size > INSTALLER_FRAME_MAX_BYTES: raise SupervisorError("installer_request_size_invalid")
        raw_request = _recv_exact(self._channel, size, "installer_request_truncated")
        _reject_trailing_frame_data(self._channel)
        try:
            decoded = json.loads(raw_request)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SupervisorError("installer_request_json_invalid") from exc
        if _wire_canonical(decoded) != raw_request:
            raise SupervisorError("installer_request_not_canonical")
        selected = self._verified["selected_candidate"]
        request = _installer_request(decoded, selected)
        observed = datetime.now(timezone.utc).replace(microsecond=0)
        expires = observed + timedelta(minutes=1)
        evidence = _wire_seal({
            "schema_version": 1,
            "artifact_type": "codexmax_selected_candidate_installer_evidence_v1",
            "candidate_id": selected._descriptor["candidate_id"],
            "archive_sha256": selected._descriptor["archive_sha256"],
            "sidecar_sha256": selected._descriptor["sidecar_sha256"],
            "source_identity_sha256": selected._descriptor["source_identity_sha256"],
            "runner_target": selected._descriptor["target"],
            "installer_id": selected._descriptor["installer"]["service_id"],
            "installer_build_sha256": selected._descriptor["installer"]["service_build_sha256"],
            "installer_start_id": selected._descriptor["installer"]["service_start_id"],
            "installer_session_id": selected._descriptor["installer"]["service_session_id"],
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "evidence_sha256": "",
        }, "evidence_sha256")
        if set(evidence) != INSTALLER_EVIDENCE_FIELDS:
            raise SupervisorError("installer_evidence_internal_shape_invalid")
        result = _wire_seal({"challenge": request["challenge"], "request_sha256": request["request_sha256"], "evidence": evidence, "response_sha256": ""}, "response_sha256")
        if set(result) != INSTALLER_RESPONSE_FIELDS:
            raise SupervisorError("installer_response_internal_shape_invalid")
        raw = _wire_canonical(result); self._channel.sendall(struct.pack("!I", len(raw)) + raw)
        return {"state": "installer_evidence_served_once", "request_count": 1, **SAFETY}


def prepare_lifecycle(descriptor_fd: int, archive_fd: int, sidecar_fd: int, role_fds: Mapping[str, int], *, opaque_agent_available: bool, now: datetime) -> Mapping[str, Any]:
    verified = verify_accepted_runner_fds(descriptor_fd, archive_fd, sidecar_fd, now=now)
    if not isinstance(role_fds, Mapping) or set(role_fds) != set(FD_ROLES) or any(type(value) is not int or value < 0 for value in role_fds.values()):
        raise SupervisorError("supervisor_descriptor_inventory_invalid")
    fingerprints=[]
    for name,fd in role_fds.items():
        try: info=os.fstat(fd)
        except OSError as exc: raise SupervisorError("supervisor_descriptor_unavailable") from exc
        expected=stat.S_ISDIR(info.st_mode) if name=="runtime_root_fd" else stat.S_ISSOCK(info.st_mode)
        if not expected: raise SupervisorError("supervisor_descriptor_type_invalid")
        fingerprints.append((info.st_dev,info.st_ino,info.st_mode))
    if len(set(fingerprints))!=len(fingerprints): raise SupervisorError("supervisor_descriptor_duplicate")
    if [(os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_mode) for fd in role_fds.values()]!=fingerprints: raise SupervisorError("supervisor_descriptor_substituted")
    if not opaque_agent_available:
        return {"state": "external_opaque_credential_agent_required", "verified": verified, "roles_prepared": list(FIXED_ROLES), "operation_count": 14, **SAFETY}
    return {"state": "external_service_account_identity_required", "verified": verified, "roles_prepared": list(FIXED_ROLES), "operation_count": 14, **SAFETY}


class SourceLocalLifecycleState:
    """Restart-safe sealed temp-root lifecycle state with no production authority."""
    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise SupervisorError("test_state_root_invalid")
        if root.exists() and (root.is_symlink() or not root.is_dir()):
            raise SupervisorError("test_state_root_invalid")
        if not root.exists():
            root.mkdir(mode=0o700)
        self.root = root
        self._recover_or_initialize()

    @staticmethod
    def _record_seal(value: Mapping[str, Any]) -> str:
        unsigned = {key: item for key, item in value.items() if key != "seal_sha256"}
        return _sha(_canonical(unsigned))

    def _atomic(self, name: str, raw: bytes, *, no_replace: bool = False) -> None:
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        temporary = "." + name + ".tmp"
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                output = os.open(temporary, flags, 0o600, dir_fd=directory)
            except FileExistsError as exc:
                raise SupervisorError("test_state_residue_collision") from exc
            try:
                os.write(output, raw)
                os.fsync(output)
            finally:
                os.close(output)
            if no_replace:
                try:
                    os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                except FileExistsError:
                    existing = (self.root / name).read_bytes()
                    if existing != raw:
                        raise SupervisorError("test_state_record_collision")
                finally:
                    os.unlink(temporary, dir_fd=directory)
            else:
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)

    def _decode(self, path: Path, code: str) -> Mapping[str, Any]:
        try:
            raw = path.read_bytes()
            value = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SupervisorError(code) from exc
        if not isinstance(value, Mapping) or raw != _canonical(value):
            raise SupervisorError(code)
        return value

    def _records(self) -> list[Mapping[str, Any]]:
        records = []
        for path in sorted(self.root.glob("record-*.json")):
            value = self._decode(path, "test_state_record_invalid")
            if set(value) != {"schema_version", "sequence", "previous_seal_sha256", "event", "state", "payload", "seal_sha256"}:
                raise SupervisorError("test_state_record_invalid")
            if type(value["sequence"]) is not int or value["sequence"] < 0 or value["sequence"] != len(records) or path.name != f"record-{len(records):08d}.json":
                raise SupervisorError("test_state_sequence_invalid")
            previous = "sha256:" + "0" * 64 if not records else records[-1]["seal_sha256"]
            if value["previous_seal_sha256"] != previous or value["seal_sha256"] != self._record_seal(value):
                raise SupervisorError("test_state_seal_invalid")
            records.append(value)
        return records

    def _pointer(self, name: str) -> Mapping[str, Any] | None:
        path = self.root / name
        if not path.exists():
            return None
        pointer = self._decode(path, "test_state_pointer_invalid")
        if set(pointer) != {"sequence", "seal_sha256"} or type(pointer["sequence"]) is not int or pointer["sequence"] < 0 or not isinstance(pointer["seal_sha256"], str):
            raise SupervisorError("test_state_pointer_invalid")
        return pointer

    def _publish_pointer(self, name: str, record: Mapping[str, Any]) -> None:
        self._atomic(name, _canonical({"sequence": record["sequence"], "seal_sha256": record["seal_sha256"]}))

    def _recover_or_initialize(self) -> None:
        records = self._records()
        head = self._pointer("head.json")
        anchor = self._pointer("anchor.json")
        committed = self._pointer("committed.json")
        if not records:
            if head is not None or anchor is not None or committed is not None:
                raise SupervisorError("test_state_truncation_detected")
            self._append("initialize", "stopped", {}, expected_head=None)
            return
        if committed is None:
            genesis = records[0]
            if len(records) != 1 or genesis["event"] != "initialize" or genesis["state"] != "stopped":
                raise SupervisorError("test_state_rollback_or_truncation")
            self._publish_pointer("head.json", genesis)
            self._publish_pointer("anchor.json", genesis)
            self._publish_pointer("committed.json", genesis)
            return
        if committed["sequence"] >= len(records) or committed["seal_sha256"] != records[committed["sequence"]]["seal_sha256"]:
            raise SupervisorError("test_state_rollback_or_truncation")
        record = records[committed["sequence"]]
        expected = {"sequence": record["sequence"], "seal_sha256": record["seal_sha256"]}
        for pointer in (head, anchor):
            if pointer is not None and (pointer["sequence"] >= len(records) or pointer["seal_sha256"] != records[pointer["sequence"]]["seal_sha256"]):
                raise SupervisorError("test_state_rollback_or_truncation")
        if head != expected:
            self._publish_pointer("head.json", record)
        if anchor != expected:
            self._publish_pointer("anchor.json", record)

    def _append(self, event: str, state: str, payload: Mapping[str, Any], *, expected_head: str | None) -> Mapping[str, Any]:
        records = self._records()
        committed = self._pointer("committed.json")
        previous = None if committed is None else records[committed["sequence"]]
        actual_head = None if previous is None else previous["seal_sha256"]
        if expected_head is not None and expected_head != actual_head:
            raise SupervisorError("test_state_expected_head_mismatch")
        record = {
            "schema_version": 1,
            "sequence": 0 if previous is None else previous["sequence"] + 1,
            "previous_seal_sha256": "sha256:" + "0" * 64 if previous is None else previous["seal_sha256"],
            "event": event,
            "state": state,
            "payload": dict(payload),
        }
        record["seal_sha256"] = self._record_seal(record)
        sequence = record["sequence"]
        if len(records) > sequence + 1:
            raise SupervisorError("test_state_publication_residue", tuple(path.name for path in sorted(self.root.glob("record-*.json"))[sequence:]))
        if len(records) == sequence:
            self._atomic(f"record-{sequence:08d}.json", _canonical(record), no_replace=True)
        elif records[sequence] != record:
            raise SupervisorError("test_state_publication_residue", (f"record-{sequence:08d}.json",))
        try:
            self._publish_pointer("head.json", record)
            self._publish_pointer("anchor.json", record)
            self._publish_pointer("committed.json", record)
        except BaseException as exc:
            residue = (f"record-{sequence:08d}.json", "head.json", "anchor.json")
            raise SupervisorError("test_state_publication_incomplete", residue) from exc
        return self.inventory()

    def _transition(self, expected_state: str, event: str, state: str, payload: Mapping[str, Any], *, expected_head: str | None = None):
        current = self.inventory()
        if current["state"] != expected_state:
            raise SupervisorError("test_state_transition_invalid")
        return self._append(event, state, payload, expected_head=expected_head)

    def start(self, *, expected_head: str | None = None):
        return self._transition("stopped", "start", "started", {}, expected_head=expected_head)

    def validate_handshake(self, receipt: Mapping[str, Any], *, expected_head: str | None = None):
        if not isinstance(receipt, Mapping) or set(receipt) != {"candidate_id", "peer_identity", "service_start_id", "session_id"}:
            raise SupervisorError("test_handshake_receipt_invalid")
        if not _public_identifier(receipt["candidate_id"]) or any(not isinstance(receipt[key], str) or not receipt[key] for key in ("peer_identity", "service_start_id", "session_id")):
            raise SupervisorError("test_handshake_receipt_invalid")
        return self._transition("started", "validate_handshake", "handshake_validated", receipt, expected_head=expected_head)

    def admit(self, admission: Mapping[str, Any], *, expected_head: str | None = None):
        if not isinstance(admission, Mapping) or set(admission) != {"challenge", "handshake_seal_sha256"} or not all(isinstance(item, str) and item for item in admission.values()):
            raise SupervisorError("test_admission_invalid")
        return self._transition("handshake_validated", "admit", "admitted", admission, expected_head=expected_head)

    def run_journey(self, operations: Sequence[str], *, expected_head: str | None = None):
        if tuple(operations) != OPERATIONS:
            raise SupervisorError("test_journey_operations_invalid")
        return self._transition("admitted", "run_journey", "journey_completed", {"operations": list(OPERATIONS)}, expected_head=expected_head)

    def stop(self, *, expected_head: str | None = None):
        return self._transition("journey_completed", "stop", "stopped", {}, expected_head=expected_head)

    def inventory(self):
        records = self._records()
        committed = self._pointer("committed.json")
        if not records or committed is None or committed["sequence"] >= len(records):
            raise SupervisorError("test_state_truncation_detected")
        latest = records[committed["sequence"]]
        if committed["seal_sha256"] != latest["seal_sha256"]:
            raise SupervisorError("test_state_rollback_or_truncation")
        return {"state": latest["state"], "sequence": latest["sequence"], "head_sha256": latest["seal_sha256"], "anchor_sha256": latest["seal_sha256"], "classification":"source_local_test_non_authoritative","roles":list(FIXED_ROLES),"operation_count":14}

    def reconcile(self):
        self._recover_or_initialize()
        inventory = self.inventory()
        residues = sorted(path.name for path in self.root.glob(".*.tmp"))
        residues.extend(f"record-{sequence:08d}.json" for sequence in range(inventory["sequence"] + 1, len(self._records())))
        return {**inventory,"residue":sorted(set(residues)),"writes_may_have_occurred":True,"production_authority":False}


def check_only_plan() -> Mapping[str, Any]:
    return {
        "artifact_type": "codexmax_supported_host_operator_supervisor_plan_v1",
        "state": "external_action_required",
        "deployment_compatibility": dict(DEPLOYMENT_ADMISSION_V2_COMPATIBILITY),
        "current_public_candidate": dict(PENDING_PUBLIC_CANDIDATE_SELECTION),
        "legacy_migration_runner": dict(HISTORICAL_RUNNER_V23_IDENTITY),
        "deployment_identity_authority": "separately_governed_bootstrap_verified_launch_and_commit_v2",
        "deployment_admission_channel": "inherited_os_authenticated_af_unix_descriptor_one_request",
        "roles": list(FIXED_ROLES), "inherited_descriptors": list(FD_ROLES),
        "operations": list(OPERATIONS), "operation_count": 14,
        "opaque_credential_agent_only": True, "accepts_credential_paths": False,
        **SAFETY,
    }


def validate_installer_public_identity(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or dict(value) != DEPLOYMENT_ADMISSION_V2_COMPATIBILITY:
        raise SupervisorError("deployment_admission_compatibility_mismatch")
    return {"state": "deployment_compatibility_qualified_check_only", "deployment_compatibility": dict(value), **SAFETY}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise SupervisorError("supervisor_arguments_invalid")


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    import sys
    stdout = sys.stdout if stdout is None else stdout
    parser = _Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--help", action="store_true")
    try:
        args = parser.parse_args(argv)
        if not args.check_only and not args.help:
            raise SupervisorError("external_action_required")
        value = check_only_plan()
        if args.help:
            value = {**value, "state": "help", "usage": ["codexmax-supported-host-operator-supervisor-v1", "--check-only"]}
        stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except SupervisorError as exc:
        stdout.write(json.dumps({"error": {"code": exc.code}, "state": "rejected", **SAFETY}, sort_keys=True, separators=(",", ":")) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
