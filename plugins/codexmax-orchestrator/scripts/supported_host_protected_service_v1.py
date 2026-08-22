#!/usr/bin/env python3
"""OS-bound clients for the protected writer, anchor, and opaque TLS agent.

The module accepts only preconnected AF_UNIX sockets. It does not discover or
open endpoints. A channel is live-authoritative only after Darwin kernel peer
credentials prove the configured, distinct service UID and GID. Source-local
socket pairs therefore remain pending.
"""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import argparse
import fcntl
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import socket
import stat
import struct
import sys
import tempfile
from types import MappingProxyType
from typing import Any, Callable, Mapping

from supported_host_candidate_admission_v1 import (
    CandidateAdmissionError,
    VerifiedSelectedCandidate,
)

DEPLOYMENT_ADMISSION_PROTOCOL = "supported_host_deployment_admission_v2"
DEPLOYMENT_ADMISSION_TYPE = "codexmax_deployment_admission_v2"
DEPLOYMENT_BOOTSTRAP_SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v2"
DEPLOYMENT_INSTALLER_IDENTITY_FIELDS = frozenset({
    "installer_id", "installer_build_sha256", "installer_start_id",
    "installer_session_id",
})
DEPLOYMENT_ADMISSION_FIELDS = frozenset({
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

from supported_host_operator_supervisor_v1 import (
    ACCEPTED_INSTALLER_IDENTITY,
    RETIRED_STATIC_CANDIDATE,
    FIXED_JOINT_CHANNEL_POLICIES,
    INSTALLER_FRAME_MAX_BYTES,
    INSTALLER_EVIDENCE_FIELDS,
    INSTALLER_REQUEST_FIELDS,
    INSTALLER_RESPONSE_FIELDS,
    PublicAuthorityError,
    SERVICE_FRAME_MAX_BYTES,
    expected_joint_role_channels,
    validate_complete_joint_authority,
    validate_operation_source_service_configuration as validate_canonical_source_service_configuration,
    validate_operation_source_service_set as validate_canonical_source_service_set,
)

# An extracted runner is a flat `scripts/` directory next to its private
# `src/` package tree. Add only that sibling when it contains the fixed package.
# This never searches the workspace, environment, installation, or network.
_RUNNER_SRC = Path(__file__).resolve().parent.parent / "src"
if (_RUNNER_SRC / "codexmax_package_host" / "__init__.py").is_file():
    sys.path.insert(0, str(_RUNNER_SRC))


def _packaged_check_only_entrypoint() -> int | None:
    """Run the no-I/O service preflight before the live dependency graph loads."""

    if __name__ != "__main__" or "--check-only" not in sys.argv[1:]:
        return None
    try:
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        parser.add_argument("--role", choices=("protected_writer", "independent_anchor", "opaque_tls_agent"), required=True)
        parser.add_argument("--service-public-json", required=True)
        parser.add_argument("--check-only", action="store_true", required=True)
        args = parser.parse_args()
        from supported_host_lifecycle_tool_v1 import _validate_public_service_set
        services = _validate_public_service_set(json.loads(args.service_public_json))
        required = {
            "protected_writer": ("client_descriptor", "anchor_descriptor", "service_store_root", "operation_source_descriptors"),
            "independent_anchor": ("client_descriptor", "service_store_root"),
            "opaque_tls_agent": ("client_descriptor", "agent_descriptor"),
        }[args.role]
        result = {
            "schema_version": 1,
            "artifact_type": "supported_host_service_runner_check_v1",
            "role": args.role,
            "service_id": services[args.role]["service_id"],
            "state": "check_only_non_production",
            "missing_live_inputs": list(required),
            "descriptors_opened": False,
            "store_opened": False,
            "service_executed": False,
            "production_ready": False,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except BaseException as exc:
        print(json.dumps({"status": "failed", "error": getattr(exc, "code", "service_runner_invalid")}, sort_keys=True, separators=(",", ":")))
        return 2


_PACKAGED_CHECK_ONLY_RESULT = _packaged_check_only_entrypoint()
if _PACKAGED_CHECK_ONLY_RESULT is not None:
    raise SystemExit(_PACKAGED_CHECK_ONLY_RESULT)

import supported_host_durable_store_v1 as t082
from supported_host_durable_store_v1 import (
    DurableStoreError, EMPTY_SHA256, TestOnlyUntrustedLocalBackend,
    prepare_append_request, validate_protected_record,
)
from supported_host_service_store_v1 import (
    ServiceOwnedAnchorStore, ServiceOwnedWriterStore, ServiceStoreError,
)
from supported_host_operation_sources_v1 import (
    OWNER_IDS as OPERATION_OWNER_IDS, OPERATION_ROWS as SOURCE_OPERATION_ROWS,
    OWNER_TYPES as OPERATION_OWNER_TYPES, OperationSourceError,
    OperationSourceStore, PreconnectedOperationSourceClient,
    SourceUnavailable, QuarantinedDerivedResult,
    validate_query as validate_operation_query,
    validate_raw_observation,
    validate_source_service_configuration as _runtime_validate_source_service_configuration,
    validate_source_service_set as _runtime_validate_source_service_set,
    create_catalog_selection_accepted_runtime,
    create_effect_authority_accepted_runtime,
    create_native_supervision_accepted_runtime,
    create_recovery_accepted_runtime,
    create_registered_action_accepted_runtime,
    create_responses_seals_accepted_runtime,
)
from package_host_supported_host_fact_sources_v1 import UnavailableFact, t063_source_ids
from supported_host_cross_owner_artifacts_v1 import (
    CatalogSelectionCrossOwnerStore, EffectAuthorityCrossOwnerStore,
    NativeSupervisionCrossOwnerStore, RecoveryCrossOwnerStore,
    RegisteredActionCrossOwnerStore, ResponsesSealsCrossOwnerStore,
    ServiceIdentity as CrossOwnerServiceIdentity,
)


PROTOCOL_VERSION = "supported_host_protected_service_v1"
REQUEST_TYPE = "supported_host_protected_service_request_v1"
RESPONSE_TYPE = "supported_host_protected_service_response_v1"
PENDING_TYPE = "supported_host_protected_service_pending_v1"
MAX_FRAME_BYTES = SERVICE_FRAME_MAX_BYTES
SERVICES = ("protected_writer", "independent_anchor", "opaque_tls_agent")
JOINT_ROLES = SERVICES + tuple(OPERATION_OWNER_IDS)
JOINT_AUTHORITY_TYPE = "supported_host_joint_service_authority_v1"
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


def validate_source_service_configuration(value: Any) -> Mapping[str, Any]:
    """Use the import-closed canonical validator on the runtime surface."""
    try:
        return MappingProxyType(validate_canonical_source_service_configuration(value))
    except PublicAuthorityError as exc:
        raise ProtectedServiceError(exc.code, exc.path) from exc


def validate_source_service_set(value: Any) -> Mapping[str, Mapping[str, Any]]:
    """Use the import-closed canonical closed-set validator."""
    try:
        rows = validate_canonical_source_service_set(value)
    except PublicAuthorityError as exc:
        raise ProtectedServiceError(exc.code, exc.path) from exc
    return MappingProxyType({key: MappingProxyType(row) for key, row in rows.items()})

_SOURCE_CHANNELS = {
    owner_id: f"protected_writer_to_{owner_id}" for owner_id in OPERATION_OWNER_IDS
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
_ROLE_ARTIFACT_EDGES = MappingProxyType({
    owner_id: tuple(sorted(
        edge_id for edge_id, roles in _ARTIFACT_EDGE_POLICIES.items()
        if owner_id in roles
    ))
    for owner_id in OPERATION_OWNER_IDS
})
_OPERATION_REQUIRED_ARTIFACT_EDGES = MappingProxyType({
    "read_operator_preset_bundle": (),
    "read_operator_selection_head": (),
    "read_operator_selection_mutation": (),
    "commit_operator_selection": ("catalog_selection_to_responses_selection_v1",),
    "read_operator_supervision": (
        "native_supervision_to_recovery_v1",
        "native_supervision_to_responses_context_v1",
    ),
    "issue_responses_context": (
        "catalog_selection_to_responses_selection_v1",
        "native_supervision_to_responses_context_v1",
        "responses_context_to_effect_authority_v1",
    ),
    "verify_effect_authority": (
        "effect_authority_to_recovery_v1",
        "effect_authority_to_registered_action_v1",
        "responses_context_to_effect_authority_v1",
    ),
    "invoke_registered_action": (
        "effect_authority_to_registered_action_v1",
        "registered_action_to_responses_bridge_v1",
    ),
    "verify_responses_bridge": ("registered_action_to_responses_bridge_v1",),
    "commit_or_verify_record": (),
    "seal_or_verify_projection": ("responses_projection_to_recovery_v1",),
    "read_operator_recovery_lease_grant": (
        "effect_authority_to_recovery_v1",
        "native_supervision_to_recovery_v1",
        "responses_projection_to_recovery_v1",
    ),
})
FIXED_CHANNEL_POLICIES = MappingProxyType({
    "protected_writer_to_independent_anchor": MappingProxyType({
        "client_kind": "role", "client_id": "protected_writer",
        "server_role": "independent_anchor", "request_type": REQUEST_TYPE,
        "response_type": "supported_host_protected_service_command_response_v1", "one_use": True,
    }),
    **{
        channel_id: MappingProxyType({
            "client_kind": "role", "client_id": "protected_writer",
            "server_role": owner_id,
            "request_type": "supported_host_joint_operation_source_request_v1",
            "response_type": "supported_host_joint_operation_source_response_v1",
            "one_use": True,
        })
        for owner_id, channel_id in _SOURCE_CHANNELS.items()
    },
    **{
        edge_id: MappingProxyType({
            "client_kind": "role", "client_id": consumer_role,
            "server_role": producer_role,
            "request_type": "supported_host_cross_owner_request_v1",
            "response_type": "supported_host_cross_owner_response_v1",
            "one_use": True,
        })
        for edge_id, (consumer_role, producer_role) in _ARTIFACT_EDGE_POLICIES.items()
    },
    "runtime_to_protected_writer": MappingProxyType({
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "protected_writer", "request_type": REQUEST_TYPE,
        "response_type": RESPONSE_TYPE, "one_use": True,
    }),
    "runtime_to_independent_anchor": MappingProxyType({
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "independent_anchor", "request_type": REQUEST_TYPE,
        "response_type": RESPONSE_TYPE, "one_use": True,
    }),
    "runtime_to_opaque_tls_agent": MappingProxyType({
        "client_kind": "external_peer", "client_id": "runtime_client",
        "server_role": "opaque_tls_agent",
        "request_type": "supported_host_opaque_tls_request_v1",
        "response_type": "supported_host_opaque_tls_response_v1", "one_use": True,
    }),
    "opaque_tls_agent_to_credential_agent": MappingProxyType({
        "client_kind": "role", "client_id": "opaque_tls_agent",
        "server_role": "external:credential_agent",
        "request_type": "supported_host_opaque_credential_agent_request_v1",
        "response_type": "supported_host_opaque_credential_agent_response_v1", "one_use": True,
    }),
    **{
        f"{peer_id}_to_{owner_id}": MappingProxyType({
            "client_kind": "external_peer", "client_id": peer_id,
            "server_role": owner_id,
            "request_type": f"supported_host_{owner_id}_raw_observation_v1",
            "response_type": "supported_host_raw_observation_ack_v1", "one_use": True,
        })
        for peer_id, owner_id in (
            ("catalog_receiver", "catalog_selection"),
            ("native_observer", "native_supervision"),
            ("responses_receiver", "responses_seals"),
            ("authority_issuer", "effect_authority"),
            ("action_executor", "registered_action"),
            ("reconciliation_receiver", "recovery"),
        )
    },
})
JOINT_SOURCE_REQUEST_TYPE = "supported_host_joint_operation_source_request_v1"
JOINT_SOURCE_RESPONSE_TYPE = "supported_host_joint_operation_source_response_v1"
JOINT_SOURCE_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "authority_sha256",
    "channel_id", "owner_id", "service_id", "service_build_sha256",
    "client_service_start_id", "client_service_session_id",
    "expected_source_start_id", "expected_source_session_id", "challenge", "operation", "query",
    "candidate_sha256", "profile_sha256", "requested_at", "request_sha256",
})
JOINT_SOURCE_RESPONSE_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "authority_sha256",
    "channel_id", "owner_id", "service_id", "service_build_sha256",
    "service_start_id", "service_session_id", "challenge", "operation",
    "request_sha256", "state", "reason", "fact_key", "fact_value",
    "observed_at", "expires_at", "source_digest", "observation_id",
    "journal_event_sha256", "response_sha256",
})
RAW_OBSERVATION_ACK_TYPE = "supported_host_raw_observation_ack_v1"
RAW_OBSERVATION_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "authority_sha256",
    "channel_id", "owner_id", "peer_id", "peer_start_id", "peer_session_id",
    "expected_source_start_id", "expected_source_session_id", "challenge",
    "operation", "raw_observation", "request_sha256",
})
RAW_OBSERVATION_ACK_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "authority_sha256",
    "channel_id", "owner_id", "service_id", "service_start_id",
    "service_session_id", "challenge", "operation", "request_sha256",
    "state", "reason", "observation_id", "journal_event_sha256",
    "ack_sha256",
})
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,255}$")
_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

CONFIG_FIELDS = frozenset({
    "schema_version", "artifact_type", "service", "service_id", "service_build_sha256",
    "expected_uid", "expected_gid", "expected_service_start_id", "expected_service_session_id",
    "protocol_version", "max_frame_bytes",
})
HISTORICAL_RUNNER_V26_CANDIDATE_ID = RETIRED_STATIC_CANDIDATE["candidate_id"]
HISTORICAL_RUNNER_V26_TARGET = RETIRED_STATIC_CANDIDATE["target"]
RETIRED_RUNNER_V26_BIND_COMMAND = "bind_current_runner_v26_admission"
REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "service", "service_id",
    "service_build_sha256", "challenge", "client_session_id", "client_service_start_id",
    "expected_service_start_id", "expected_service_session_id",
    "principal_id", "operation", "candidate_sha256", "profile_sha256",
    "operation_body_sha256", "dependency_receipts_sha256", "requested_at",
    "request_body", "request_body_sha256", "request_sha256",
})
RESPONSE_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "service", "service_id",
    "service_build_sha256", "challenge", "client_session_id", "service_session_id",
    "service_start_id", "principal_id", "operation", "request_sha256", "state",
    "reason", "record", "retained_anchor", "responded_at", "response_sha256",
})
RECORD_FIELDS = frozenset({
    "request", "writer_receipt", "anchor_receipt", "fact_key", "fact_value",
    "operation_body_sha256", "dependency_receipts_sha256", "observed_at", "expires_at",
    "source_digest", "record_sha256",
})
ANCHOR_VIEW_FIELDS = frozenset({
    "store_id", "namespace", "sequence", "generation", "head_sha256", "anchor_sha256",
    "writer_receipt_sha256", "anchor_receipt_sha256",
})
TLS_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "service", "service_id",
    "service_build_sha256", "challenge", "client_session_id", "expected_service_start_id",
    "expected_service_session_id", "expected_server_leaf_sha256",
    "principal_id", "operation",
    "receiver_request_b64", "receiver_request_sha256", "request_sha256",
})
TLS_RESPONSE_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "service", "service_id",
    "service_build_sha256", "challenge", "client_session_id", "service_session_id",
    "service_start_id", "principal_id", "operation", "request_sha256", "server_leaf_sha256", "receiver_response_b64",
    "receiver_response_sha256", "response_sha256",
})
COMMAND_RESPONSE_TYPE = "supported_host_protected_service_command_response_v1"
COMMAND_RESPONSE_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "service", "service_id",
    "service_build_sha256", "challenge", "client_session_id", "service_session_id",
    "service_start_id", "principal_id", "operation", "request_sha256", "command",
    "state", "reason", "result", "responded_at", "response_sha256",
})
OPAQUE_AGENT_REQUEST_TYPE = "supported_host_opaque_credential_agent_request_v1"
OPAQUE_AGENT_RESPONSE_TYPE = "supported_host_opaque_credential_agent_response_v1"
OPAQUE_AGENT_PROTOCOL_VERSION = "supported_host_opaque_credential_agent_v1"
OPAQUE_AGENT_RESPONSE_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "agent_id", "agent_build_sha256",
    "agent_start_id", "agent_session_id", "challenge", "request_sha256", "principal_id",
    "operation", "server_leaf_sha256", "receiver_response_b64", "receiver_response_sha256",
    "response_sha256",
})


class ProtectedServiceError(ValueError):
    """Stable fail-closed protocol error."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtectedServiceError("protected_service_json_invalid") from exc


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return deepcopy(value)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def decode_framed_bytes(value: bytes, *, maximum: int = MAX_FRAME_BYTES) -> Mapping[str, Any]:
    """Parse one complete frame without opening or reading a socket."""
    if not isinstance(value, bytes) or len(value) < 4:
        raise ProtectedServiceError("protected_service_frame_truncated", "$.frame")
    length = struct.unpack("!I", value[:4])[0]
    if length < 2 or length > maximum:
        raise ProtectedServiceError("protected_service_frame_length_invalid", "$.frame")
    if len(value) != 4 + length:
        raise ProtectedServiceError("protected_service_frame_truncated", "$.frame")
    try:
        decoded = json.loads(value[4:])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectedServiceError("protected_service_response_json_invalid", "$.frame") from exc
    if not isinstance(decoded, Mapping) or _canonical(decoded) != value[4:]:
        raise ProtectedServiceError("protected_service_response_not_canonical", "$.frame")
    return MappingProxyType(deepcopy(dict(decoded)))


def _recv_exact_socket(channel: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        try:
            part = channel.recv(count - len(chunks))
        except (OSError, TimeoutError) as exc:
            raise ProtectedServiceError("protected_service_channel_failed", "$.channel") from exc
        if not part:
            raise ProtectedServiceError("protected_service_frame_truncated", "$.frame")
        chunks.extend(part)
    return bytes(chunks)


def _reject_socket_trailing(channel: socket.socket, path: str) -> None:
    try:
        readable, _, _ = select.select([channel], [], [], 0)
    except (OSError, ValueError) as exc:
        raise ProtectedServiceError("protected_service_channel_failed", path) from exc
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
        if exc.errno in {11, 35}:
            return
        raise ProtectedServiceError("protected_service_channel_failed", path) from exc
    if trailing:
        raise ProtectedServiceError("protected_service_frame_trailing_data", path)


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = deepcopy(dict(value))
    row[field] = ""
    row[field] = _digest(row)
    return row


def _authority_record_from_triple(triple: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        validated = validate_protected_record(
            triple["request"], triple["writer_receipt"], triple["anchor_receipt"],
        )
    except (KeyError, DurableStoreError) as exc:
        raise ProtectedServiceError(getattr(exc, "code", "protected_service_record_invalid"), "$.store") from exc
    request = validated["request"]
    if request["event_kind"] != "fact" or set(request["payload"]) != {
        "fact_key", "fact_value", "operation_body_sha256", "dependency_receipts_sha256",
        "observed_at", "expires_at", "source_digest",
    }:
        raise ProtectedServiceError("protected_service_fact_payload_invalid", "$.store.request.payload")
    return MappingProxyType(_seal({
        "request": validated["request"], "writer_receipt": validated["writer_receipt"],
        "anchor_receipt": validated["anchor_receipt"], **deepcopy(dict(request["payload"])),
        "record_sha256": "",
    }, "record_sha256"))


def _anchor_view_from_triple(triple: Mapping[str, Any]) -> Mapping[str, Any]:
    validated = validate_protected_record(
        triple["request"], triple["writer_receipt"], triple["anchor_receipt"],
    )
    writer = validated["writer_receipt"]; anchor = validated["anchor_receipt"]
    return MappingProxyType({
        "store_id": validated["request"]["store_id"], "namespace": validated["request"]["namespace"],
        "sequence": writer["successor_sequence"], "generation": writer["successor_generation"],
        "head_sha256": writer["successor_head_sha256"], "anchor_sha256": writer["anchor_sha256"],
        "writer_receipt_sha256": writer["receipt_sha256"],
        "anchor_receipt_sha256": anchor["receipt_sha256"],
    })


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ProtectedServiceError(code, path)
    return _plain(value)


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ProtectedServiceError("protected_service_identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ProtectedServiceError("protected_service_digest_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise ProtectedServiceError("protected_service_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_deployment_admission_v2(
    value: Any, *, now: datetime, expected_previous_commit_sha256: str | None,
) -> Mapping[str, Any]:
    """Independently validate bootstrap output without importing bootstrap code."""

    row = _closed(value, DEPLOYMENT_ADMISSION_FIELDS, "deployment_admission_shape_invalid", "$.admission")
    if (
        row["schema_version"] != 2
        or row["artifact_type"] != DEPLOYMENT_ADMISSION_TYPE
        or row["protocol_version"] != DEPLOYMENT_ADMISSION_PROTOCOL
        or row["bootstrap_source_id"] != DEPLOYMENT_BOOTSTRAP_SOURCE_ID
    ):
        raise ProtectedServiceError("deployment_admission_identity_invalid", "$.admission")
    for field in (
        "candidate_descriptor_sha256", "archive_sha256", "sidecar_sha256",
        "source_identity_sha256", "root_manifest_sha256",
        "child_executable_sha256", "nonce_sha256", "deployment_commit_sha256",
        "writer_receipt_sha256", "anchor_receipt_sha256", "ledger_head_sha256",
    ):
        _sha(row[field], "$.admission." + field)
    if row["writer_receipt_sha256"] == row["anchor_receipt_sha256"]:
        raise ProtectedServiceError("deployment_commit_receipt_identity_collision", "$.admission")
    for field in (
        "candidate_id", "child_start_id", "writer_service_start_id",
        "writer_service_session_id", "anchor_service_start_id",
        "anchor_service_session_id",
    ):
        _identifier(row[field], "$.admission." + field)
    installer = _closed(
        row["installer_identity"], DEPLOYMENT_INSTALLER_IDENTITY_FIELDS,
        "deployment_installer_identity_invalid", "$.admission.installer_identity",
    )
    for field in ("installer_id", "installer_start_id", "installer_session_id"):
        _identifier(installer[field], "$.admission.installer_identity." + field)
    _sha(installer["installer_build_sha256"], "$.admission.installer_identity.installer_build_sha256")
    for field in ("verified_root_device", "verified_root_inode", "entrypoint_device", "entrypoint_inode", "child_pid", "child_uid", "child_gid", "generation"):
        if type(row[field]) is not int or row[field] < 1:
            raise ProtectedServiceError("deployment_numeric_identity_invalid", "$.admission." + field)
    if row["revocation_state"] != "not_revoked":
        raise ProtectedServiceError("deployment_revoked", "$.admission.revocation_state")
    previous = row["previous_committed_head_sha256"]
    if previous is not None:
        _sha(previous, "$.admission.previous_committed_head_sha256")
    if previous != expected_previous_commit_sha256:
        raise ProtectedServiceError("deployment_commit_lineage_mismatch", "$.admission.previous_committed_head_sha256")
    observed = _time(row["observed_at"], "$.admission.observed_at")
    expires = _time(row["expires_at"], "$.admission.expires_at")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ProtectedServiceError("deployment_clock_invalid", "$.now")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > current or expires <= current or observed >= expires:
        raise ProtectedServiceError("deployment_admission_expired", "$.admission")
    sealed = dict(row); actual = sealed["admission_sha256"]; sealed["admission_sha256"] = ""
    if actual != _digest(sealed):
        raise ProtectedServiceError("deployment_admission_digest_mismatch", "$.admission.admission_sha256")
    sealed["admission_sha256"] = actual
    return MappingProxyType(sealed)


def validate_current_runner_v26_installer_evidence(value: Any, *, now: datetime) -> Mapping[str, Any]:
    """Reject predecessor evidence retained only as an explicit lineage seam."""

    del value, now
    raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.installer_evidence")


@dataclass(frozen=True, slots=True)
class ProtectedServicePending:
    service: str
    reason: str

    def as_mapping(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema_version": 1, "artifact_type": PENDING_TYPE,
            "service": self.service, "state": "pending", "reason": self.reason,
            "production_ready": False,
        })


class SourceLocalProtectedWriterStateOwner:
    """Test-root implementation of the writer state machine.

    This owner creates exact T082 requests. Its backend receipts remain
    test-only and can never promote a production fact.
    """

    __slots__ = ("_backend",)

    def __init__(self, backend: TestOnlyUntrustedLocalBackend) -> None:
        if type(backend) is not TestOnlyUntrustedLocalBackend:
            raise ProtectedServiceError("protected_writer_backend_invalid", "$.backend")
        self._backend = backend

    def restart(self) -> Mapping[str, Mapping[str, Any]]:
        return self._backend.recover_all()

    def append(
        self, *, namespace: str, canonical_source_id: str, producer_principal_id: str,
        operation: str, candidate_sha256: str, profile_sha256: str, record_id: str,
        occurred_at: str, nonce: str, payload: Mapping[str, Any],
    ) -> Mapping[str, Mapping[str, Any]]:
        head = self._backend.head(namespace)
        request = prepare_append_request(
            store_id=self._backend.store_id, namespace=namespace,
            canonical_source_id=canonical_source_id,
            producer_principal_id=producer_principal_id, operation=operation,
            candidate_sha256=candidate_sha256, profile_sha256=profile_sha256,
            expected_sequence=head["sequence"], expected_head_sha256=head["head_sha256"],
            expected_generation=head["generation"], event_kind="fact", record_id=record_id,
            occurred_at=occurred_at, nonce=nonce, payload=payload,
        )
        evidence = self._backend.append(request)
        return MappingProxyType({"request": request, **evidence})

    def transition(
        self, *, kind: str, namespace: str, canonical_source_id: str,
        producer_principal_id: str, operation: str, candidate_sha256: str,
        profile_sha256: str, record_id: str, occurred_at: str, nonce: str,
        target_event_sha256: str, consumer_sha256: str | None = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        head = self._backend.head(namespace)
        request = prepare_append_request(
            store_id=self._backend.store_id, namespace=namespace,
            canonical_source_id=canonical_source_id,
            producer_principal_id=producer_principal_id, operation=operation,
            candidate_sha256=candidate_sha256, profile_sha256=profile_sha256,
            expected_sequence=head["sequence"], expected_head_sha256=head["head_sha256"],
            expected_generation=head["generation"], event_kind=kind, record_id=record_id,
            occurred_at=occurred_at, nonce=nonce, payload={"transition": kind},
            target_event_sha256=target_event_sha256, consumer_sha256=consumer_sha256,
        )
        evidence = self._backend.append(request)
        return MappingProxyType({"request": request, **evidence})

    def records(self, namespace: str) -> tuple[Mapping[str, Any], ...]:
        _head, records = self._backend._recover(namespace)
        return tuple(MappingProxyType(deepcopy(item)) for item in records)


class SourceLocalIndependentAnchorStateOwner:
    """Independently retain exact T082 anchor receipts in one test root."""

    __slots__ = ("_root", "_path")

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute() or root.exists():
            raise ProtectedServiceError("anchor_test_root_invalid", "$.root")
        root.mkdir(mode=0o700)
        self._root = root
        self._path = root / "anchors.json"
        self._write([])

    @classmethod
    def restart(cls, root: Path) -> "SourceLocalIndependentAnchorStateOwner":
        subject = object.__new__(cls)
        subject._root = root
        subject._path = root / "anchors.json"
        subject.recover()
        return subject

    def _write(self, rows: list[Mapping[str, Any]]) -> None:
        temporary = self._root / ".anchors.pending"
        encoded = _canonical({"anchors": rows})
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, encoded); os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self._path)

    def recover(self) -> tuple[Mapping[str, Any], ...]:
        if (self._root / ".anchors.pending").exists():
            raise ProtectedServiceError("anchor_pending_publication_detected", "$.anchor")
        try:
            value = json.loads(self._path.read_bytes())
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProtectedServiceError("anchor_journal_invalid", "$.anchor") from exc
        if not isinstance(value, Mapping) or set(value) != {"anchors"} or _canonical(value) != self._path.read_bytes():
            raise ProtectedServiceError("anchor_journal_invalid", "$.anchor")
        rows = value["anchors"]
        if not isinstance(rows, list):
            raise ProtectedServiceError("anchor_journal_invalid", "$.anchor")
        prior = EMPTY_SHA256
        for item in rows:
            if not isinstance(item, Mapping) or item.get("previous_anchor_receipt_sha256") != prior:
                raise ProtectedServiceError("anchor_journal_fork", "$.anchor")
            validate_protected_record(item["request"], item["writer_receipt"], item["anchor_receipt"])
            prior = item["anchor_receipt"]["receipt_sha256"]
        return tuple(MappingProxyType(deepcopy(item)) for item in rows)

    def retain(self, triple: Mapping[str, Any]) -> Mapping[str, Any]:
        validated = validate_protected_record(triple["request"], triple["writer_receipt"], triple["anchor_receipt"])
        rows = [deepcopy(dict(item)) for item in self.recover()]
        expected = EMPTY_SHA256 if not rows else rows[-1]["anchor_receipt"]["receipt_sha256"]
        if validated["anchor_receipt"]["previous_anchor_receipt_sha256"] != expected:
            raise ProtectedServiceError("anchor_journal_fork", "$.anchor")
        row = {**validated, "previous_anchor_receipt_sha256": expected}
        rows.append(row); self._write(rows)
        return MappingProxyType(deepcopy(row))


class SourceLocalOpaqueTlsAgentStateOwner:
    """Credential-safe service owner. Source-local execution stays pending."""

    __slots__ = ()

    def process(self, receiver_request: bytes) -> ProtectedServicePending:
        if not isinstance(receiver_request, bytes):
            raise ProtectedServiceError("opaque_tls_agent_request_invalid", "$.request")
        return ProtectedServicePending("opaque_tls_agent", "live_credential_agent_unavailable")


class ServiceOwnedProtectedWriterStateOwner:
    """Executable writer owner backed by fixed process-owned stores.

    The service process constructs this owner from its configured roots.  Wire
    callers can submit exact T082 requests.  They cannot select a backend,
    supply a receipt, or turn a source-local root into production authority.
    """

    __slots__ = ("_writer", "_anchor_client", "_operation_sources")

    def __init__(
        self, writer: ServiceOwnedWriterStore, anchor_client: "AnchorServiceClient",
        operation_sources: Mapping[str, PreconnectedOperationSourceClient] | None = None,
    ) -> None:
        if type(writer) is not ServiceOwnedWriterStore or type(anchor_client) is not AnchorServiceClient:
            raise ProtectedServiceError("protected_writer_store_invalid", "$.owner")
        try:
            writer._recover_committed_all()
        except (AttributeError, ServiceStoreError) as exc:
            raise ProtectedServiceError("protected_writer_store_invalid", "$.owner") from exc
        self._writer = writer
        self._anchor_client = anchor_client
        sources = {} if operation_sources is None else operation_sources
        if not isinstance(sources, Mapping) or (sources and set(sources) != set(OPERATION_OWNER_IDS)):
            raise ProtectedServiceError("operation_source_inventory_invalid", "$.owner.operation_sources")
        if any(type(source) is not PreconnectedOperationSourceClient or source._config["owner_id"] != owner for owner, source in sources.items()):
            raise ProtectedServiceError("operation_source_inventory_invalid", "$.owner.operation_sources")
        self._operation_sources = MappingProxyType(dict(sources))

    @property
    def source_local(self) -> bool:
        return self._writer.source_local

    def dispatch(self, body: Mapping[str, Any], service_request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Reject the retired caller-command surface.

        Writer append, revoke, and consume transitions are internal results of
        source-owned state. They are not production wire commands.
        """
        del body, service_request
        raise ProtectedServiceError("protected_writer_public_command_forbidden", "$.request.request_body")

    def read_fact(self, service_request: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        """Read one current fact from service-owned state; never from caller data."""
        matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        requested = _time(service_request["requested_at"], "$.request.requested_at")
        for namespace in t082.NAMESPACES:
            records = self._writer.records(namespace)
            transitioned = {
                row["request"]["target_event_sha256"]
                for row in records if row["request"]["event_kind"] in {"revoke", "consume"}
            }
            for triple in records:
                request = triple["request"]; writer = triple["writer_receipt"]
                if request["event_kind"] != "fact" or writer["event_sha256"] in transitioned:
                    continue
                payload = request["payload"]
                if (
                    request["operation"] != service_request["operation"]
                    or request["producer_principal_id"] != service_request["principal_id"]
                    or request["candidate_sha256"] != service_request["candidate_sha256"]
                    or request["profile_sha256"] != service_request["profile_sha256"]
                    or payload.get("operation_body_sha256") != service_request["operation_body_sha256"]
                    or payload.get("dependency_receipts_sha256") != service_request["dependency_receipts_sha256"]
                ):
                    continue
                observed = _time(payload.get("observed_at"), "$.record.observed_at")
                expires = _time(payload.get("expires_at"), "$.record.expires_at")
                if observed <= requested < expires:
                    record = _authority_record_from_triple(triple)
                    matches.append((record, _anchor_view_from_triple(triple)))
        if len(matches) != 1:
            if matches:
                raise ProtectedServiceError("protected_writer_current_fact_collision", "$.store")
        if matches:
            return matches[0]
        operation = service_request["operation"]
        source_row = SOURCE_OPERATION_ROWS[operation]
        source = self._operation_sources.get(source_row["owner_id"])
        if source is None:
            return None
        try:
            query = validate_operation_query(operation, service_request["request_body"])
            acquired = source.read(
                operation=operation, query=query,
                candidate_sha256=service_request["candidate_sha256"],
                profile_sha256=service_request["profile_sha256"],
                request_challenge=service_request["challenge"],
                requested_at=service_request["requested_at"],
            )
        except OperationSourceError as exc:
            raise ProtectedServiceError(exc.code, exc.path) from exc
        if isinstance(acquired, SourceUnavailable):
            return None
        if not isinstance(acquired, Mapping) or acquired.get("state") != "available":
            raise ProtectedServiceError("operation_source_result_invalid", "$.operation_source")
        namespace = source_row["namespace"]
        with self._writer.namespace_lock(namespace):
            head = self._writer.head(namespace)
            request = prepare_append_request(
                store_id=self._writer.store_id, namespace=namespace,
                canonical_source_id=source_row["canonical_source_id"],
                producer_principal_id=source_row["producer_principal_id"], operation=operation,
                candidate_sha256=service_request["candidate_sha256"], profile_sha256=service_request["profile_sha256"],
                expected_sequence=head["sequence"], expected_head_sha256=head["head_sha256"],
                expected_generation=head["generation"], event_kind="fact",
                record_id="observation-" + acquired["journal_event_sha256"].split(":", 1)[1],
                occurred_at=acquired["observed_at"],
                nonce=hashlib.sha256((acquired["observation_id"] + service_request["request_sha256"]).encode("utf-8")).hexdigest(),
                payload={
                    "fact_key": acquired["fact_key"], "fact_value": _plain(acquired["fact_value"]),
                    "operation_body_sha256": service_request["operation_body_sha256"],
                    "dependency_receipts_sha256": service_request["dependency_receipts_sha256"],
                    "observed_at": acquired["observed_at"], "expires_at": acquired["expires_at"],
                    "source_digest": acquired["source_digest"],
                },
            )
            prepared = self._writer.begin_append(request)
            anchor = self._anchor_client.retain(prepared["request"], prepared["writer_statement"], service_request)
            evidence = self._writer.commit_append(namespace, anchor)
        triple = {"request": request, **evidence}
        return _authority_record_from_triple(triple), _anchor_view_from_triple(triple)


class SourceLocalProtectedWriterJourney:
    """Non-authoritative full writer/anchor call graph for temp-root tests."""

    __slots__ = ("_writer", "_anchor")

    def __init__(
        self, writer: ServiceOwnedWriterStore, anchor: ServiceOwnedAnchorStore,
    ) -> None:
        if (type(writer) is not ServiceOwnedWriterStore
                or type(anchor) is not ServiceOwnedAnchorStore
                or not writer.source_local or not anchor.source_local):
            raise ProtectedServiceError("source_local_writer_journey_store_invalid", "$.store")
        if writer.store_id != anchor.store_id:
            raise ProtectedServiceError("source_local_writer_journey_store_mismatch", "$.store")
        self._writer = writer
        self._anchor = anchor

    @property
    def production_ready(self) -> bool:
        return False

    def ingest(
        self, source: PreconnectedOperationSourceClient,
        service_request: Mapping[str, Any],
    ) -> Mapping[str, Any] | SourceUnavailable:
        """Acquire on the authenticated channel and run exact T082 stores."""
        if type(source) is not PreconnectedOperationSourceClient:
            raise ProtectedServiceError("source_local_writer_journey_source_invalid", "$.source")
        if not isinstance(service_request, Mapping) or service_request.get("operation") not in SOURCE_OPERATION_ROWS:
            raise ProtectedServiceError("source_local_writer_journey_request_invalid", "$.request")
        operation = service_request["operation"]
        row = SOURCE_OPERATION_ROWS[operation]
        if source._config["owner_id"] != row["owner_id"]:
            raise ProtectedServiceError("source_local_writer_journey_source_invalid", "$.source")
        query = validate_operation_query(operation, service_request["request_body"])
        acquired = source.read(
            operation=operation, query=query,
            candidate_sha256=service_request["candidate_sha256"],
            profile_sha256=service_request["profile_sha256"],
            request_challenge=service_request["challenge"],
            requested_at=service_request["requested_at"],
        )
        if isinstance(acquired, SourceUnavailable):
            return acquired
        if not isinstance(acquired, Mapping) or acquired.get("state") != "available":
            raise ProtectedServiceError("operation_source_result_invalid", "$.operation_source")
        namespace = row["namespace"]
        with self._writer.namespace_lock(namespace):
            head = self._writer.head(namespace)
            request = prepare_append_request(
                store_id=self._writer.store_id, namespace=namespace,
                canonical_source_id=row["canonical_source_id"],
                producer_principal_id=row["producer_principal_id"], operation=operation,
                candidate_sha256=service_request["candidate_sha256"],
                profile_sha256=service_request["profile_sha256"],
                expected_sequence=head["sequence"], expected_head_sha256=head["head_sha256"],
                expected_generation=head["generation"], event_kind="fact",
                record_id="observation-" + acquired["journal_event_sha256"].split(":", 1)[1],
                occurred_at=acquired["observed_at"],
                nonce=hashlib.sha256((acquired["observation_id"] + service_request["request_sha256"]).encode()).hexdigest(),
                payload={
                    "fact_key": acquired["fact_key"], "fact_value": _plain(acquired["fact_value"]),
                    "operation_body_sha256": service_request["operation_body_sha256"],
                    "dependency_receipts_sha256": service_request["dependency_receipts_sha256"],
                    "observed_at": acquired["observed_at"], "expires_at": acquired["expires_at"],
                    "source_digest": acquired["source_digest"],
                },
            )
            prepared = self._writer.begin_append(request)
            anchor_receipt = self._anchor.retain(prepared["request"], prepared["writer_statement"])
            evidence = self._writer.commit_append(namespace, anchor_receipt)
        triple = MappingProxyType({"request": request, **evidence})
        validate_protected_record(
            triple["request"], triple["writer_receipt"], triple["anchor_receipt"],
        )
        return MappingProxyType({
            "execution_scope": "source_local_multi_role_simulation_non_production",
            "production_ready": False, "triple": triple,
        })


class ServiceOwnedIndependentAnchorStateOwner:
    """Executable independent-anchor owner with no writer-root access."""

    __slots__ = ("_anchor",)

    def __init__(self, anchor: ServiceOwnedAnchorStore) -> None:
        if type(anchor) is not ServiceOwnedAnchorStore:
            raise ProtectedServiceError("independent_anchor_store_invalid", "$.owner")
        try:
            anchor.recover_all()
        except (AttributeError, ServiceStoreError) as exc:
            raise ProtectedServiceError("independent_anchor_store_invalid", "$.owner") from exc
        self._anchor = anchor

    @property
    def source_local(self) -> bool:
        return self._anchor.source_local

    def dispatch(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(body, Mapping) or "command" not in body:
            raise ProtectedServiceError("independent_anchor_command_invalid", "$.request.request_body")
        command = body["command"]
        try:
            if command == "retain":
                if set(body) != {"command", "request", "writer_statement"}:
                    raise ProtectedServiceError("independent_anchor_command_shape_invalid", "$.request.request_body")
                result: Mapping[str, Any] = {"anchor_receipt": self._anchor.retain(body["request"], body["writer_statement"])}
            elif command == "read":
                if set(body) != {"command", "namespace", "anchor_receipt_sha256"}:
                    raise ProtectedServiceError("independent_anchor_command_shape_invalid", "$.request.request_body")
                result = {"records": list(self._anchor.read(body["namespace"], body["anchor_receipt_sha256"]))}
            elif command == "recover":
                if set(body) != {"command"}:
                    raise ProtectedServiceError("independent_anchor_command_shape_invalid", "$.request.request_body")
                result = {"heads": dict(self._anchor.recover_all())}
            else:
                raise ProtectedServiceError("independent_anchor_command_unknown", "$.request.request_body.command")
        except (ServiceStoreError, DurableStoreError) as exc:
            raise ProtectedServiceError(getattr(exc, "code", "independent_anchor_store_failed"), "$.service_store") from exc
        return MappingProxyType({
            "execution_scope": "source_local_temp_root_non_production" if self.source_local else "service_account_owned_candidate",
            "value": _plain(result),
        })

    def read_fact(self, body: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        required = {"record_sha256", "writer_receipt_sha256", "anchor_receipt_sha256"}
        if not isinstance(body, Mapping) or set(body) != required:
            raise ProtectedServiceError("independent_anchor_query_invalid", "$.request.request_body")
        for namespace in t082.NAMESPACES:
            for triple in self._anchor.read(namespace, body["anchor_receipt_sha256"]):
                record = _authority_record_from_triple(triple)
                if (
                    record["record_sha256"] == body["record_sha256"]
                    and triple["writer_receipt"]["receipt_sha256"] == body["writer_receipt_sha256"]
                ):
                    return record, _anchor_view_from_triple(triple)
        return None


class PreconnectedOpaqueCredentialAgent:
    """Narrow opaque frame port to an externally provisioned credential agent.

    The port accepts only an inherited AF_UNIX socket.  It never receives a
    private value or a private-value location.  It rechecks the current kernel
    peer and descriptor before and after every exchange.
    """

    __slots__ = ("_socket", "_fingerprint", "_expected_uid", "_expected_groups", "_identity", "_used", "_admitted_witness")

    def __init__(self, channel: socket.socket, *, expected_uid: int, expected_gid: int,
                 expected_groups: tuple[int, ...] | None = None,
                 identity: Mapping[str, str]) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("opaque_credential_agent_channel_invalid", "$.channel")
        required = {"agent_id", "agent_build_sha256", "agent_start_id", "agent_session_id"}
        if not isinstance(identity, Mapping) or set(identity) != required:
            raise ProtectedServiceError("opaque_credential_agent_identity_invalid", "$.identity")
        row = dict(identity)
        _identifier(row["agent_id"], "$.identity.agent_id"); _sha(row["agent_build_sha256"], "$.identity.agent_build_sha256")
        _identifier(row["agent_start_id"], "$.identity.agent_start_id"); _identifier(row["agent_session_id"], "$.identity.agent_session_id")
        if type(expected_uid) is not int or expected_uid < 1 or type(expected_gid) is not int or expected_gid < 1:
            raise ProtectedServiceError("opaque_credential_agent_account_invalid", "$.identity")
        groups = (expected_gid,) if expected_groups is None else expected_groups
        if not isinstance(groups, tuple) or any(type(group) is not int or group < 1 for group in groups) or groups != tuple(sorted(set(groups))):
            raise ProtectedServiceError("opaque_credential_agent_groups_invalid", "$.identity")
        if expected_gid not in groups:
            raise ProtectedServiceError("opaque_credential_agent_gid_invalid", "$.identity")
        self._socket = channel; self._fingerprint = _socket_fingerprint(channel)
        self._expected_uid = expected_uid; self._expected_groups = groups
        self._admitted_witness = _channel_witness(channel)
        self._identity = MappingProxyType(row); self._used = False

    def _pending(self) -> ProtectedServicePending | None:
        try:
            if _socket_fingerprint(self._socket) != self._fingerprint:
                return ProtectedServicePending("opaque_tls_agent", "opaque_credential_agent_socket_replaced")
            witness = _channel_witness(self._socket)
        except (AttributeError, ProtectedServiceError):
            return ProtectedServicePending("opaque_tls_agent", "opaque_credential_agent_peer_invalid")
        if witness is None:
            return ProtectedServicePending("opaque_tls_agent", "kernel_peer_credentials_not_supported")
        uid, groups = witness.peer_uid, witness.peer_groups
        if witness != self._admitted_witness:
            return ProtectedServicePending("opaque_tls_agent", "opaque_credential_agent_witness_changed")
        if uid == os.geteuid():
            return ProtectedServicePending("opaque_tls_agent", "same_uid_credential_agent_not_authoritative")
        if uid != self._expected_uid or groups != self._expected_groups:
            return ProtectedServicePending("opaque_tls_agent", "opaque_credential_agent_peer_mismatch")
        return None

    def exchange(self, request: Mapping[str, Any]) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self._pending()
        if pending is not None:
            return pending
        if self._used:
            raise ProtectedServiceError("opaque_credential_agent_channel_reused", "$.channel")
        self._used = True
        if not isinstance(request, Mapping):
            raise ProtectedServiceError("opaque_credential_agent_request_invalid", "$.request")
        row = _seal({
            "schema_version": 1, "artifact_type": OPAQUE_AGENT_REQUEST_TYPE,
            "protocol_version": OPAQUE_AGENT_PROTOCOL_VERSION,
            **dict(self._identity), "challenge": request["challenge"],
            "principal_id": request["principal_id"], "operation": request["operation"],
            "expected_server_leaf_sha256": request["expected_server_leaf_sha256"],
            "receiver_request_b64": request["receiver_request_b64"],
            "receiver_request_sha256": request["receiver_request_sha256"],
            "request_sha256": "",
        }, "request_sha256")
        raw = _canonical(row)
        if len(raw) > MAX_FRAME_BYTES:
            raise ProtectedServiceError("opaque_credential_agent_frame_oversized", "$.request")
        self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        header = _recv_exact_socket(self._socket, 4); length = struct.unpack("!I", header)[0]
        if length < 2 or length > MAX_FRAME_BYTES:
            raise ProtectedServiceError("opaque_credential_agent_frame_length_invalid", "$.response")
        response = decode_framed_bytes(header + _recv_exact_socket(self._socket, length))
        response = MappingProxyType(_closed(response, OPAQUE_AGENT_RESPONSE_FIELDS, "opaque_credential_agent_response_shape_invalid", "$.response"))
        pending = self._pending()
        if pending is not None:
            return pending
        expected = {
            "artifact_type": OPAQUE_AGENT_RESPONSE_TYPE, "agent_id": row["agent_id"],
            "protocol_version": OPAQUE_AGENT_PROTOCOL_VERSION,
            "agent_build_sha256": row["agent_build_sha256"], "agent_start_id": row["agent_start_id"],
            "agent_session_id": row["agent_session_id"], "challenge": row["challenge"],
            "request_sha256": row["request_sha256"], "principal_id": row["principal_id"],
            "operation": row["operation"], "server_leaf_sha256": row["expected_server_leaf_sha256"],
        }
        if response.get("schema_version") != 1 or any(response.get(key) != value for key, value in expected.items()):
            raise ProtectedServiceError("opaque_credential_agent_response_binding_mismatch", "$.response")
        try:
            receiver = base64.b64decode(response["receiver_response_b64"], validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtectedServiceError("opaque_credential_agent_response_encoding_invalid", "$.response") from exc
        if response.get("receiver_response_sha256") != "sha256:" + hashlib.sha256(receiver).hexdigest() or response.get("response_sha256") != _seal(response, "response_sha256")["response_sha256"]:
            raise ProtectedServiceError("opaque_credential_agent_response_digest_mismatch", "$.response")
        return MappingProxyType(deepcopy(dict(response)))


class ServiceOwnedOpaqueTlsAgentStateOwner:
    """Executable opaque TLS service owner with an optional external agent port."""

    __slots__ = ("_agent",)

    def __init__(self, agent: PreconnectedOpaqueCredentialAgent | None = None) -> None:
        if agent is not None and type(agent) is not PreconnectedOpaqueCredentialAgent:
            raise ProtectedServiceError("opaque_credential_agent_invalid", "$.agent")
        self._agent = agent

    def process(self, request: Mapping[str, Any]) -> Mapping[str, Any] | ProtectedServicePending:
        if self._agent is None:
            return ProtectedServicePending("opaque_tls_agent", "live_credential_agent_unavailable")
        return self._agent.exchange(request)


class PreconnectedProtectedServiceHandler:
    """Service-side peer and continuity gate for one preconnected client."""

    __slots__ = (
        "_socket", "_config", "_socket_fingerprint", "_client_uid", "_client_gid",
        "_client_groups", "_principal_map", "_joint_policy", "_admitted_witness",
        "_client_start_id", "_client_session_id", "_client_session_expires_at", "_joint_scope",
    )

    def __init__(self, channel: socket.socket, configuration: Mapping[str, Any], *,
                 expected_client_uid: int, expected_client_gid: int,
                 principal_map: Mapping[str, str],
                 joint_authority: Mapping[str, Any] | None = None,
                 channel_id: str | None = None) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("protected_service_channel_invalid", "$.channel")
        self._socket = channel
        self._socket_fingerprint = _socket_fingerprint(channel)
        self._config = validate_service_configuration(configuration)
        if type(expected_client_uid) is not int or expected_client_uid < 1:
            raise ProtectedServiceError("protected_service_client_uid_invalid", "$.client")
        if type(expected_client_gid) is not int or expected_client_gid < 1:
            raise ProtectedServiceError("protected_service_client_gid_invalid", "$.client")
        if not isinstance(principal_map, Mapping):
            raise ProtectedServiceError("protected_service_principal_map_invalid", "$.principal_map")
        self._client_uid = expected_client_uid
        self._client_gid = expected_client_gid
        self._client_groups = (expected_client_gid,)
        self._principal_map = MappingProxyType(dict(principal_map))
        self._joint_policy = None
        self._admitted_witness = None
        self._client_start_id = None
        self._client_session_id = None
        self._client_session_expires_at = None
        self._joint_scope = None
        if (joint_authority is None) != (channel_id is None):
            raise ProtectedServiceError("joint_authority_channel_binding_incomplete", "$.channel")
        if joint_authority is not None and channel_id is not None:
            policy, uid, groups = _joint_server_binding(
                joint_authority, channel_id, server_role=self._config["service"],
            )
            expected_config = service_configuration_from_authority(joint_authority, self._config["service"])
            if any(self._config[field] != expected_config[field] for field in CONFIG_FIELDS - {"max_frame_bytes"}):
                raise ProtectedServiceError("joint_authority_service_config_mismatch", "$.config")
            if expected_client_uid != uid or expected_client_gid not in groups:
                raise ProtectedServiceError("joint_authority_client_identity_mismatch", "$.client")
            self._client_uid = uid
            self._client_groups = groups
            self._joint_policy = policy
            self._admitted_witness = _channel_witness(channel)
            joint = validate_joint_service_authority(joint_authority)
            self._joint_scope = joint["execution_scope"]
            peer = (
                joint["roles"][policy["client_id"]] if policy["client_kind"] == "role"
                else joint["external_peers"][policy["client_id"]]
            )
            self._client_start_id = peer.get("expected_service_start_id", peer.get("peer_start_id"))
            self._client_session_id = peer.get("expected_service_session_id", peer.get("peer_session_id"))
            self._client_session_expires_at = peer["session_expires_at"]

    def current_pending(self) -> ProtectedServicePending | None:
        try:
            service_name = self._config["service"]
        except (AttributeError, KeyError, TypeError):
            return ProtectedServicePending("unknown", "protected_service_handler_uninitialized")
        try:
            if _socket_fingerprint(self._socket) != self._socket_fingerprint:
                return ProtectedServicePending(service_name, "protected_service_socket_replaced")
            witness = _channel_witness(self._socket)
        except (AttributeError, ProtectedServiceError):
            return ProtectedServicePending(service_name, "protected_service_client_peer_invalid")
        if self._joint_scope == "source_local_test":
            return ProtectedServicePending(service_name, "source_local_authority_not_live")
        if witness is None:
            return ProtectedServicePending(service_name, "kernel_peer_credentials_not_supported")
        uid, groups = witness.peer_uid, witness.peer_groups
        if self._joint_policy is not None and witness != self._admitted_witness:
            return ProtectedServicePending(service_name, "protected_service_client_witness_changed")
        if uid != self._client_uid or (
            groups != self._client_groups if self._joint_policy is not None else self._client_gid not in groups
        ):
            return ProtectedServicePending(service_name, "protected_service_client_peer_mismatch")
        return None

    def validate_query(self, value: Mapping[str, Any]) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self.current_pending()
        if pending is not None:
            return pending
        row = validate_request(value, self._config)
        if self._joint_policy is not None:
            if (
                row["client_service_start_id"] != self._client_start_id
                or row["client_session_id"] != self._client_session_id
                or _time(row["requested_at"], "$.request.requested_at") >= _time(self._client_session_expires_at, "$.peer.session_expires_at")
            ):
                raise ProtectedServiceError("joint_authority_client_continuity_mismatch", "$.request")
            if row["artifact_type"] != self._joint_policy["request_type"]:
                raise ProtectedServiceError("joint_authority_request_type_mismatch", "$.request")
        if self._principal_map.get(row["operation"]) != row["principal_id"]:
            raise ProtectedServiceError("protected_service_principal_operation_mismatch", "$.request")
        return row


class ProtectedWriterServiceHandler(PreconnectedProtectedServiceHandler):
    """Service-side read handler. Fact acquisition and append stay owner-side."""

    __slots__ = ()

    def handle_query(self, value: Mapping[str, Any], owner: SourceLocalProtectedWriterStateOwner) -> Mapping[str, Any] | ProtectedServicePending:
        if type(owner) is not SourceLocalProtectedWriterStateOwner:
            raise ProtectedServiceError("protected_writer_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        body = row["request_body"]
        if not isinstance(body, Mapping) or set(body) != {"command", "namespace"} or body["command"] != "read":
            raise ProtectedServiceError("protected_writer_query_invalid", "$.request.request_body")
        records = owner.records(body["namespace"])
        return MappingProxyType({"state": "test_only_records", "records": records, "production_ready": False})

    def dispatch_command(
        self, value: Mapping[str, Any], owner: ServiceOwnedProtectedWriterStateOwner,
    ) -> Mapping[str, Any] | ProtectedServicePending:
        if type(owner) is not ServiceOwnedProtectedWriterStateOwner:
            raise ProtectedServiceError("protected_writer_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        body = row["request_body"]
        if isinstance(body, Mapping) and body.get("command") == RETIRED_RUNNER_V26_BIND_COMMAND:
            raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.request.request_body")
        del owner
        raise ProtectedServiceError("protected_writer_public_command_forbidden", "$.request.request_body")

    def read_service_fact(
        self, value: Mapping[str, Any], owner: ServiceOwnedProtectedWriterStateOwner,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None | ProtectedServicePending:
        if type(owner) is not ServiceOwnedProtectedWriterStateOwner:
            raise ProtectedServiceError("protected_writer_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        body = row["request_body"]
        if not isinstance(body, Mapping) or set(body) != {"identity", "operation_body", "dependency_receipts"}:
            raise ProtectedServiceError("protected_writer_query_invalid", "$.request.request_body")
        return owner.read_fact(row)


class IndependentAnchorServiceHandler(PreconnectedProtectedServiceHandler):
    """Service-side exact anchor lookup handler."""

    __slots__ = ()

    def handle_query(self, value: Mapping[str, Any], owner: SourceLocalIndependentAnchorStateOwner) -> Mapping[str, Any] | ProtectedServicePending:
        if type(owner) is not SourceLocalIndependentAnchorStateOwner:
            raise ProtectedServiceError("independent_anchor_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        body = row["request_body"]
        if not isinstance(body, Mapping) or set(body) != {"anchor_receipt_sha256"}:
            raise ProtectedServiceError("independent_anchor_query_invalid", "$.request.request_body")
        matches = [item for item in owner.recover() if item["anchor_receipt"]["receipt_sha256"] == body["anchor_receipt_sha256"]]
        if len(matches) != 1:
            return MappingProxyType({"state": "unavailable", "reason": "anchor_not_retained"})
        return MappingProxyType({"state": "test_only_anchor", "record": matches[0], "production_ready": False})

    def dispatch_command(
        self, value: Mapping[str, Any], owner: ServiceOwnedIndependentAnchorStateOwner,
    ) -> Mapping[str, Any] | ProtectedServicePending:
        if type(owner) is not ServiceOwnedIndependentAnchorStateOwner:
            raise ProtectedServiceError("independent_anchor_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        body = row["request_body"]
        if isinstance(body, Mapping) and body.get("command") == RETIRED_RUNNER_V26_BIND_COMMAND:
            raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.request.request_body")
        if isinstance(body, Mapping) and body.get("command") == "retain":
            inner = body.get("request")
            if not isinstance(inner, Mapping):
                raise ProtectedServiceError("independent_anchor_retain_request_invalid", "$.request.request_body")
            exact = {
                "operation": row["operation"], "producer_principal_id": row["principal_id"],
                "candidate_sha256": row["candidate_sha256"], "profile_sha256": row["profile_sha256"],
            }
            if any(inner.get(field) != expected for field, expected in exact.items()):
                raise ProtectedServiceError("independent_anchor_outer_binding_mismatch", "$.request.request_body.request")
            if inner.get("event_kind") == "fact":
                payload = inner.get("payload")
                if not isinstance(payload, Mapping) or payload.get("operation_body_sha256") != row["operation_body_sha256"] or payload.get("dependency_receipts_sha256") != row["dependency_receipts_sha256"]:
                    raise ProtectedServiceError("independent_anchor_query_binding_mismatch", "$.request.request_body.request.payload")
        return owner.dispatch(body)

    def read_service_fact(
        self, value: Mapping[str, Any], owner: ServiceOwnedIndependentAnchorStateOwner,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None | ProtectedServicePending:
        if type(owner) is not ServiceOwnedIndependentAnchorStateOwner:
            raise ProtectedServiceError("independent_anchor_owner_invalid", "$.owner")
        row = self.validate_query(value)
        if isinstance(row, ProtectedServicePending):
            return row
        return owner.read_fact(row["request_body"])


class OpaqueTlsAgentServiceHandler(PreconnectedProtectedServiceHandler):
    """Service-side opaque receiver-frame handler."""

    __slots__ = ()

    def handle_receiver_frame(self, receiver_request: bytes, owner: SourceLocalOpaqueTlsAgentStateOwner) -> ProtectedServicePending:
        pending = self.current_pending()
        if pending is not None:
            return pending
        if type(owner) is not SourceLocalOpaqueTlsAgentStateOwner:
            raise ProtectedServiceError("opaque_tls_agent_owner_invalid", "$.owner")
        return owner.process(receiver_request)

    def dispatch_opaque_request(
        self, value: Mapping[str, Any], owner: ServiceOwnedOpaqueTlsAgentStateOwner,
    ) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self.current_pending()
        if pending is not None:
            return pending
        if type(owner) is not ServiceOwnedOpaqueTlsAgentStateOwner:
            raise ProtectedServiceError("opaque_tls_agent_owner_invalid", "$.owner")
        return owner.process(value)


def prepare_command_response(
    configuration: Mapping[str, Any], request: Mapping[str, Any], *, command: str,
    result: Mapping[str, Any] | None, reason: str | None, responded_at: str,
) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration)
    request_row = validate_request(request, config)
    _identifier(command, "$.response.command"); _time(responded_at, "$.response.responded_at")
    if (result is None) == (reason is None):
        raise ProtectedServiceError("protected_service_command_result_invalid", "$.response")
    if result is not None and not isinstance(result, Mapping):
        raise ProtectedServiceError("protected_service_command_result_invalid", "$.response.result")
    if reason is not None:
        _identifier(reason, "$.response.reason")
    row = _seal({
        "schema_version": 1, "artifact_type": COMMAND_RESPONSE_TYPE,
        "protocol_version": PROTOCOL_VERSION, "service": config["service"],
        "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
        "challenge": request_row["challenge"], "client_session_id": request_row["client_session_id"],
        "service_session_id": config["expected_service_session_id"],
        "service_start_id": config["expected_service_start_id"],
        "principal_id": request_row["principal_id"], "operation": request_row["operation"],
        "request_sha256": request_row["request_sha256"], "command": command,
        "state": "completed" if result is not None else "pending", "reason": reason,
        "result": deepcopy(dict(result)) if result is not None else None,
        "responded_at": responded_at, "response_sha256": "",
    }, "response_sha256")
    return MappingProxyType(row)


def prepare_fact_response(
    configuration: Mapping[str, Any], request: Mapping[str, Any], *,
    fact: tuple[Mapping[str, Any], Mapping[str, Any]] | None,
    unavailable_reason: str = "fact_not_observed", responded_at: str,
) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration); request_row = validate_request(request, config)
    _time(responded_at, "$.response.responded_at")
    if fact is None:
        record = retained = None; state = "unavailable"; reason: str | None = unavailable_reason
        _identifier(reason, "$.response.reason")
    else:
        if not isinstance(fact, tuple) or len(fact) != 2:
            raise ProtectedServiceError("protected_service_fact_result_invalid", "$.fact")
        record, retained = _plain(fact[0]), _plain(fact[1]); state = "available"; reason = None
    response = _seal({
        "schema_version": 1, "artifact_type": RESPONSE_TYPE, "protocol_version": PROTOCOL_VERSION,
        "service": config["service"], "service_id": config["service_id"],
        "service_build_sha256": config["service_build_sha256"], "challenge": request_row["challenge"],
        "client_session_id": request_row["client_session_id"],
        "service_session_id": config["expected_service_session_id"],
        "service_start_id": config["expected_service_start_id"],
        "principal_id": request_row["principal_id"], "operation": request_row["operation"],
        "request_sha256": request_row["request_sha256"], "state": state, "reason": reason,
        "record": record, "retained_anchor": retained, "responded_at": responded_at,
        "response_sha256": "",
    }, "response_sha256")
    validate_response(response, request_row, config)
    return MappingProxyType(response)


def validate_command_response(
    value: Mapping[str, Any], request: Mapping[str, Any], configuration: Mapping[str, Any],
) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration); request_row = validate_request(request, config)
    row = _closed(value, COMMAND_RESPONSE_FIELDS, "protected_service_command_response_shape_invalid", "$.response")
    exact = {
        "schema_version": 1, "artifact_type": COMMAND_RESPONSE_TYPE,
        "protocol_version": PROTOCOL_VERSION, "service": config["service"],
        "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
        "challenge": request_row["challenge"], "client_session_id": request_row["client_session_id"],
        "service_session_id": config["expected_service_session_id"],
        "service_start_id": config["expected_service_start_id"], "principal_id": request_row["principal_id"],
        "operation": request_row["operation"], "request_sha256": request_row["request_sha256"],
        "command": request_row["request_body"].get("command"),
    }
    if any(row.get(key) != expected for key, expected in exact.items()):
        raise ProtectedServiceError("protected_service_command_response_binding_mismatch", "$.response")
    _time(row["responded_at"], "$.response.responded_at")
    if row["state"] == "completed":
        if not isinstance(row["result"], Mapping) or row["reason"] is not None:
            raise ProtectedServiceError("protected_service_command_response_result_invalid", "$.response")
    elif row["state"] == "pending":
        if row["result"] is not None:
            raise ProtectedServiceError("protected_service_command_response_pending_invalid", "$.response")
        _identifier(row["reason"], "$.response.reason")
    else:
        raise ProtectedServiceError("protected_service_command_response_state_invalid", "$.response.state")
    if row["response_sha256"] != _seal(row, "response_sha256")["response_sha256"]:
        raise ProtectedServiceError("protected_service_command_response_digest_mismatch", "$.response.response_sha256")
    return MappingProxyType(row)


class FramedProtectedServiceDispatcher:
    """Serve one bound command on an already admitted AF_UNIX descriptor."""

    __slots__ = ("_handler", "_owner")

    def __init__(
        self, handler: ProtectedWriterServiceHandler | IndependentAnchorServiceHandler,
        owner: ServiceOwnedProtectedWriterStateOwner | ServiceOwnedIndependentAnchorStateOwner,
    ) -> None:
        valid = (
            type(handler) is ProtectedWriterServiceHandler and type(owner) is ServiceOwnedProtectedWriterStateOwner
        ) or (
            type(handler) is IndependentAnchorServiceHandler and type(owner) is ServiceOwnedIndependentAnchorStateOwner
        )
        if not valid:
            raise ProtectedServiceError("protected_service_dispatcher_owner_invalid", "$.dispatcher")
        self._handler = handler; self._owner = owner

    def serve_one(self, *, responded_at: str) -> Mapping[str, Any] | ProtectedServicePending:
        before = self._handler.current_pending()
        if before is not None:
            return before
        channel = self._handler._socket; maximum = self._handler._config["max_frame_bytes"]
        header = _recv_exact_socket(channel, 4); length = struct.unpack("!I", header)[0]
        if length < 2 or length > maximum:
            raise ProtectedServiceError("protected_service_frame_length_invalid", "$.request")
        request = decode_framed_bytes(header + _recv_exact_socket(channel, length), maximum=maximum)
        after_read = self._handler.current_pending()
        if after_read is not None:
            return after_read
        command = request["request_body"].get("command") if isinstance(request.get("request_body"), Mapping) else None
        if command is None:
            result = self._handler.read_service_fact(request, self._owner)
        else:
            result = self._handler.dispatch_command(request, self._owner)
        before_write = self._handler.current_pending()
        if before_write is not None:
            return before_write
        if command is None and not isinstance(result, ProtectedServicePending):
            response = prepare_fact_response(
                self._handler._config, request, fact=result, responded_at=responded_at,
            )
        elif isinstance(result, ProtectedServicePending):
            response = prepare_command_response(
                self._handler._config, request, command=command or "read_fact",
                result=None, reason=result.reason, responded_at=responded_at,
            )
        else:
            response = prepare_command_response(
                self._handler._config, request, command=command,
                result=result, reason=None, responded_at=responded_at,
            )
        encoded = _canonical(response)
        channel.sendall(struct.pack("!I", len(encoded)) + encoded)
        after_write = self._handler.current_pending()
        if after_write is not None:
            return after_write
        return response


class FramedOpaqueTlsServiceDispatcher:
    """Serve one opaque receiver exchange through the external agent port."""

    __slots__ = ("_handler", "_owner")

    def __init__(self, handler: OpaqueTlsAgentServiceHandler,
                 owner: ServiceOwnedOpaqueTlsAgentStateOwner) -> None:
        if type(handler) is not OpaqueTlsAgentServiceHandler or type(owner) is not ServiceOwnedOpaqueTlsAgentStateOwner:
            raise ProtectedServiceError("opaque_tls_agent_dispatcher_owner_invalid", "$.dispatcher")
        self._handler = handler; self._owner = owner

    def serve_one(self) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self._handler.current_pending()
        if pending is not None:
            return pending
        channel = self._handler._socket; maximum = self._handler._config["max_frame_bytes"]
        header = _recv_exact_socket(channel, 4); length = struct.unpack("!I", header)[0]
        if length < 2 or length > maximum:
            raise ProtectedServiceError("protected_service_frame_length_invalid", "$.request")
        request = decode_framed_bytes(header + _recv_exact_socket(channel, length), maximum=maximum)
        request = validate_tls_request(request, self._handler._config)
        pending = self._handler.current_pending()
        if pending is not None:
            return pending
        result = self._handler.dispatch_opaque_request(request, self._owner)
        if isinstance(result, ProtectedServicePending):
            return result
        pending = self._handler.current_pending()
        if pending is not None:
            return pending
        response = prepare_tls_response(self._handler._config, request, result)
        encoded = _canonical(response); channel.sendall(struct.pack("!I", len(encoded)) + encoded)
        pending = self._handler.current_pending()
        if pending is not None:
            return pending
        return response


@dataclass(frozen=True, slots=True)
class ValidatedProtectedFact:
    """A detached result of one OS-authenticated channel exchange.

    The object is data, not authority. The validating channel remains the
    authority boundary, and production callers must perform the exchange.
    """

    operation: str
    key: str
    value: Mapping[str, Any]
    observed_at: datetime
    expires_at: datetime
    canonical_source_id: str
    source_digest: str
    authority_record: Mapping[str, Any]


class OsBoundProtectedFactSource:
    """Read facts only through distinct writer and anchor service channels."""

    __slots__ = ("_writer_channels", "_anchor_channels", "_principal_ids", "_profile_sha256", "_client_session_id", "_service_set")

    def __init__(
        self, *, writer_channels: Mapping[str, PreconnectedProtectedServiceChannel],
        anchor_channels: Mapping[str, PreconnectedProtectedServiceChannel],
        service_configurations: Mapping[str, Mapping[str, Any]],
        principal_ids: Mapping[str, str], profile_sha256: str, client_session_id: str,
    ) -> None:
        source_ids = t063_source_ids()
        services = validate_service_set(service_configurations)
        if not isinstance(writer_channels, Mapping) or set(writer_channels) != set(source_ids):
            raise ProtectedServiceError("protected_service_writer_channels_invalid", "$.writer_channels")
        if not isinstance(anchor_channels, Mapping) or set(anchor_channels) != set(source_ids):
            raise ProtectedServiceError("protected_service_anchor_channels_invalid", "$.anchor_channels")
        if any(type(item) is not PreconnectedProtectedServiceChannel for item in writer_channels.values()):
            raise ProtectedServiceError("protected_service_writer_channel_invalid", "$.writer_channels")
        if any(type(item) is not PreconnectedProtectedServiceChannel for item in anchor_channels.values()):
            raise ProtectedServiceError("protected_service_anchor_channel_invalid", "$.anchor_channels")
        if any(item._config["service"] != "protected_writer" for item in writer_channels.values()):
            raise ProtectedServiceError("protected_service_writer_role_invalid", "$.writer_channels")
        if any(item._config["service"] != "independent_anchor" for item in anchor_channels.values()):
            raise ProtectedServiceError("protected_service_anchor_role_invalid", "$.anchor_channels")
        if any(dict(item._config) != dict(services["protected_writer"]) for item in writer_channels.values()):
            raise ProtectedServiceError("protected_service_writer_set_mismatch", "$.writer_channels")
        if any(dict(item._config) != dict(services["independent_anchor"]) for item in anchor_channels.values()):
            raise ProtectedServiceError("protected_service_anchor_set_mismatch", "$.anchor_channels")
        if not isinstance(principal_ids, Mapping) or set(principal_ids) != set(source_ids):
            raise ProtectedServiceError("protected_service_principal_map_invalid", "$.principal_ids")
        self._writer_channels = dict(writer_channels)
        self._anchor_channels = dict(anchor_channels)
        self._principal_ids = {operation: _identifier(principal_ids[operation], "$.principal_ids") for operation in source_ids}
        self._profile_sha256 = _sha(profile_sha256, "$.profile_sha256")
        self._client_session_id = _identifier(client_session_id, "$.client_session_id")
        self._service_set = services

    def read_fact(
        self, operation: str, exact_identity: Mapping[str, Any],
        dependency_receipts: Mapping[str, str], now: datetime,
        operation_body: Mapping[str, Any] | None = None,
    ) -> UnavailableFact | ValidatedProtectedFact:
        source_ids = t063_source_ids()
        if operation not in source_ids:
            raise ProtectedServiceError("protected_service_operation_invalid", "$.operation")
        if not isinstance(exact_identity, Mapping) or operation_body is None or not isinstance(operation_body, Mapping):
            return UnavailableFact(operation, "protected_service_query_incomplete", source_ids[operation])
        writer = self._writer_channels[operation]
        anchor = self._anchor_channels[operation]
        if writer.pending is not None:
            return UnavailableFact(operation, writer.pending.reason, source_ids[operation])
        if anchor.pending is not None:
            return UnavailableFact(operation, anchor.pending.reason, source_ids[operation])
        dependency_digest = _digest(dict(sorted(dependency_receipts.items())))
        operation_body_digest = _digest(operation_body)
        requested_at = now.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        common = {
            "challenge": secrets.token_urlsafe(32), "client_session_id": self._client_session_id,
            "client_service_start_id": exact_identity.get("service_start_id"),
            "principal_id": self._principal_ids[operation], "operation": operation,
            "candidate_sha256": exact_identity.get("candidate_sha256"),
            "profile_sha256": self._profile_sha256,
            "operation_body_sha256": operation_body_digest,
            "dependency_receipts_sha256": dependency_digest, "requested_at": requested_at,
            "request_body": {
                "identity": deepcopy(dict(exact_identity)), "operation_body": deepcopy(dict(operation_body)),
                "dependency_receipts": deepcopy(dict(dependency_receipts)),
            },
        }
        writer_request = prepare_request(writer._config, **common)
        writer_response = writer.exchange(writer_request)
        if isinstance(writer_response, ProtectedServicePending):
            return UnavailableFact(operation, writer_response.reason, source_ids[operation])
        if writer_response["state"] != "available":
            return UnavailableFact(operation, writer_response["reason"], source_ids[operation])
        record = writer_response["record"]
        anchor_common = dict(common)
        anchor_common["challenge"] = secrets.token_urlsafe(32)
        anchor_common["request_body"] = {
            "record_sha256": record["record_sha256"],
            "writer_receipt_sha256": record["writer_receipt"]["receipt_sha256"],
            "anchor_receipt_sha256": record["anchor_receipt"]["receipt_sha256"],
        }
        anchor_request = prepare_request(anchor._config, **anchor_common)
        anchor_response = anchor.exchange(anchor_request)
        if isinstance(anchor_response, ProtectedServicePending):
            return UnavailableFact(operation, anchor_response.reason, source_ids[operation])
        if anchor_response["state"] != "available":
            return UnavailableFact(operation, anchor_response["reason"], source_ids[operation])
        if anchor_response["record"]["record_sha256"] != record["record_sha256"] or anchor_response["retained_anchor"] != writer_response["retained_anchor"]:
            raise ProtectedServiceError("protected_service_anchor_reconciliation_mismatch", "$.response")
        return ValidatedProtectedFact(
            operation=operation, key=record["fact_key"],
            value=MappingProxyType(deepcopy(dict(record["fact_value"]))),
            observed_at=_time(record["observed_at"], "$.record.observed_at"),
            expires_at=_time(record["expires_at"], "$.record.expires_at"),
            canonical_source_id=source_ids[operation], source_digest=record["source_digest"],
            authority_record=MappingProxyType(deepcopy(dict(record))),
        )

def _expected_role_channels(role: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        return expected_joint_role_channels(role)
    except PublicAuthorityError as exc:
        raise ProtectedServiceError(exc.code, exc.path) from exc


def validate_joint_service_authority(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Project the one canonical import-closed authority validation."""
    try:
        row = validate_complete_joint_authority(value)
    except PublicAuthorityError as exc:
        raise ProtectedServiceError(exc.code, exc.path) from exc
    roles = {
        role: MappingProxyType(item)
        for role, item in row["roles"].items()
    }
    peers = {
        peer_id: MappingProxyType(item)
        for peer_id, item in row["external_peers"].items()
    }
    channels = {
        channel_id: MappingProxyType(item)
        for channel_id, item in row["channel_policies"].items()
    }
    return MappingProxyType({
        **row,
        "roles": MappingProxyType(roles),
        "external_peers": MappingProxyType(peers),
        "channel_policies": MappingProxyType(channels),
    })

def service_configuration_from_authority(authority: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    validated = validate_joint_service_authority(authority)
    if role not in SERVICES:
        raise ProtectedServiceError("protected_service_name_invalid", "$.role")
    item = validated["roles"][role]
    return validate_service_configuration({
        "schema_version": 1, "artifact_type": "supported_host_protected_service_config_v1",
        "service": role, "service_id": item["service_id"],
        "service_build_sha256": item["service_build_sha256"],
        "expected_uid": item["expected_uid"], "expected_gid": item["expected_gid"],
        "expected_service_start_id": item["expected_service_start_id"],
        "expected_service_session_id": item["expected_service_session_id"],
        "protocol_version": PROTOCOL_VERSION, "max_frame_bytes": MAX_FRAME_BYTES,
    })


def check_joint_service_authority(authority: Mapping[str, Any]) -> Mapping[str, Any]:
    """Check public authority bytes without opening a root or channel."""
    validated = validate_joint_service_authority(authority)
    return MappingProxyType({
        "schema_version": 1,
        "artifact_type": "supported_host_joint_service_authority_check_v1",
        "authority_id": validated["authority_id"],
        "authority_sha256": validated["authority_sha256"],
        "state": "check_only_non_production",
        "roles_validated": list(JOINT_ROLES),
        "channels_validated": sorted(FIXED_CHANNEL_POLICIES),
        "descriptors_opened": False,
        "roots_opened": False,
        "production_ready": False,
    })


def validate_service_configuration(value: Mapping[str, Any]) -> Mapping[str, Any]:
    row = _closed(value, CONFIG_FIELDS, "protected_service_config_shape_invalid", "$.config")
    if row["schema_version"] != 1 or row["artifact_type"] != "supported_host_protected_service_config_v1":
        raise ProtectedServiceError("protected_service_config_identity_invalid", "$.config")
    if row["service"] not in SERVICES:
        raise ProtectedServiceError("protected_service_name_invalid", "$.config.service")
    _identifier(row["service_id"], "$.config.service_id")
    _sha(row["service_build_sha256"], "$.config.service_build_sha256")
    _identifier(row["expected_service_start_id"], "$.config.expected_service_start_id")
    _identifier(row["expected_service_session_id"], "$.config.expected_service_session_id")
    if type(row["expected_uid"]) is not int or row["expected_uid"] < 1:
        raise ProtectedServiceError("protected_service_uid_invalid", "$.config.expected_uid")
    if type(row["expected_gid"]) is not int or row["expected_gid"] < 1:
        raise ProtectedServiceError("protected_service_gid_invalid", "$.config.expected_gid")
    if row["protocol_version"] != PROTOCOL_VERSION:
        raise ProtectedServiceError("protected_service_protocol_invalid", "$.config.protocol_version")
    if type(row["max_frame_bytes"]) is not int or not 1024 <= row["max_frame_bytes"] <= MAX_FRAME_BYTES:
        raise ProtectedServiceError("protected_service_frame_limit_invalid", "$.config.max_frame_bytes")
    return MappingProxyType(row)


def validate_service_set(configurations: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(configurations, Mapping) or set(configurations) != set(SERVICES):
        raise ProtectedServiceError("protected_service_set_invalid", "$.services")
    rows = {name: validate_service_configuration(configurations[name]) for name in SERVICES}
    if any(rows[name]["service"] != name for name in SERVICES):
        raise ProtectedServiceError("protected_service_set_name_mismatch", "$.services")
    if len({row["service_id"] for row in rows.values()}) != 3:
        raise ProtectedServiceError("protected_service_identity_collision", "$.services")
    if len({row["expected_uid"] for row in rows.values()}) != 3 or len({row["expected_gid"] for row in rows.values()}) != 3:
        raise ProtectedServiceError("protected_service_account_collision", "$.services")
    return MappingProxyType(rows)


def validate_current_role_identity(
    role: str, configurations: Mapping[str, Mapping[str, Any]], *, root: Path | None = None,
) -> Mapping[str, Any]:
    """Validate only the selected live service role against the current process."""
    services = validate_service_set(configurations)
    if role not in SERVICES:
        raise ProtectedServiceError("service_runner_role_invalid", "$.role")
    selected = services[role]
    if os.geteuid() != selected["expected_uid"] or os.getegid() != selected["expected_gid"]:
        raise ProtectedServiceError("service_runner_role_identity_mismatch", "$.role")
    groups = set(os.getgroups())
    other_groups = {services[name]["expected_gid"] for name in SERVICES if name != role}
    if groups.intersection(other_groups):
        raise ProtectedServiceError("service_runner_cross_role_group", "$.role")
    if root is not None:
        try:
            info = root.lstat()
        except OSError as exc:
            raise ProtectedServiceError("service_runner_store_root_invalid", "$.store_root") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != selected["expected_uid"]:
            raise ProtectedServiceError("service_runner_store_root_invalid", "$.store_root")
    return selected


def validate_selected_joint_role(
    role: str, authority: Mapping[str, Any], *, inherited_root_fd: int,
    now: str,
) -> Mapping[str, Any]:
    """Validate only one selected live role and its inherited root descriptor."""
    joint = validate_joint_service_authority(authority)
    if role not in JOINT_ROLES:
        raise ProtectedServiceError("service_runner_role_invalid", "$.role")
    selected = joint["roles"][role]
    if os.geteuid() != selected["expected_uid"] or os.getegid() != selected["expected_gid"]:
        raise ProtectedServiceError("service_runner_role_identity_mismatch", "$.role")
    if sorted(os.getgroups()) != selected["supplemental_groups"]:
        raise ProtectedServiceError("service_runner_supplemental_groups_mismatch", "$.role")
    if _time(now, "$.now") >= _time(selected["session_expires_at"], f"$.authority.roles.{role}.session_expires_at"):
        raise ProtectedServiceError("service_runner_role_session_expired", "$.role")
    if type(inherited_root_fd) is not int or inherited_root_fd < 0:
        raise ProtectedServiceError("service_runner_root_fd_invalid", "$.root_fd")
    try:
        info = os.fstat(inherited_root_fd)
    except OSError as exc:
        raise ProtectedServiceError("service_runner_store_root_invalid", "$.root_fd") from exc
    root = selected["root_identity"]
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != selected["expected_uid"]
        or info.st_gid != selected["expected_gid"] or info.st_dev != root["device"]
        or info.st_ino != root["inode"]
    ):
        raise ProtectedServiceError("service_runner_store_root_invalid", "$.root_fd")
    return selected


def _darwin_peer_credentials(channel: socket.socket) -> tuple[int, tuple[int, ...]] | None:
    """Return kernel xucred data, or None when this platform cannot prove it."""
    if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
        raise ProtectedServiceError("protected_service_channel_invalid", "$.channel")
    local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
    sol_local = getattr(socket, "SOL_LOCAL", None)
    if local_peercred is None or sol_local is None:
        return None
    try:
        raw = channel.getsockopt(sol_local, local_peercred, 256)
    except OSError as exc:
        raise ProtectedServiceError("protected_service_peer_credentials_unavailable", "$.channel") from exc
    # Darwin xucred: version, uid, ngroups, groups[16]. Native alignment is used.
    if len(raw) < 12:
        raise ProtectedServiceError("protected_service_peer_credentials_malformed", "$.channel")
    version, uid, group_count = struct.unpack_from("=IIh2x", raw, 0)
    if version == 0 or group_count > 16 or len(raw) < 12 + 4 * group_count:
        raise ProtectedServiceError("protected_service_peer_credentials_malformed", "$.channel")
    groups = struct.unpack_from("=" + "I" * group_count, raw, 12) if group_count else ()
    return uid, tuple(groups)


def _socket_fingerprint(channel: socket.socket) -> tuple[int, int, int]:
    if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
        raise ProtectedServiceError("protected_service_channel_invalid", "$.channel")
    try:
        info = os.fstat(channel.fileno())
    except (OSError, ValueError) as exc:
        raise ProtectedServiceError("protected_service_channel_stale", "$.channel") from exc
    return channel.fileno(), info.st_dev, info.st_ino


@dataclass(frozen=True, slots=True)
class ChannelWitness:
    """One exact descriptor and kernel peer observation."""

    descriptor_fingerprint: tuple[int, int, int, int, int, int, int]
    peer_uid: int
    peer_groups: tuple[int, ...]


def _channel_witness(channel: socket.socket) -> ChannelWitness | None:
    if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
        raise ProtectedServiceError("protected_service_channel_invalid", "$.channel")
    try:
        info = os.fstat(channel.fileno())
    except (OSError, ValueError) as exc:
        raise ProtectedServiceError("protected_service_channel_stale", "$.channel") from exc
    peer = _darwin_peer_credentials(channel)
    if peer is None:
        return None
    uid, groups = peer
    fingerprint = (
        channel.fileno(), info.st_dev, info.st_ino, info.st_mode,
        info.st_rdev, int(channel.type), int(channel.proto),
    )
    return ChannelWitness(fingerprint, uid, tuple(sorted(set(groups))))


def _joint_channel_binding(
    authority: Mapping[str, Any], channel_id: str, *, server_role: str,
) -> tuple[Mapping[str, Any], int, tuple[int, ...]]:
    joint = validate_joint_service_authority(authority)
    if channel_id not in joint["channel_policies"]:
        raise ProtectedServiceError("joint_authority_channel_unknown", "$.channel_id")
    policy = joint["channel_policies"][channel_id]
    if policy["server_role"] != server_role:
        raise ProtectedServiceError("joint_authority_channel_server_mismatch", "$.channel_id")
    role = joint["roles"].get(server_role)
    if role is None:
        raise ProtectedServiceError("joint_authority_channel_server_invalid", "$.channel_id")
    groups = tuple(sorted({role["expected_gid"], *role["supplemental_groups"]}))
    return policy, role["expected_uid"], groups


def _joint_server_binding(
    authority: Mapping[str, Any], channel_id: str, *, server_role: str,
) -> tuple[Mapping[str, Any], int, tuple[int, ...]]:
    joint = validate_joint_service_authority(authority)
    policy = joint["channel_policies"].get(channel_id)
    if policy is None or policy["server_role"] != server_role:
        raise ProtectedServiceError("joint_authority_channel_server_mismatch", "$.channel_id")
    if policy["client_kind"] == "role":
        peer = joint["roles"][policy["client_id"]]
        groups = tuple(sorted({peer["expected_gid"], *peer["supplemental_groups"]}))
    else:
        peer = joint["external_peers"][policy["client_id"]]
        groups = tuple(peer["expected_groups"])
    return policy, peer["expected_uid"], groups


def _cross_owner_identity(
    joint: Mapping[str, Any], role: str,
) -> CrossOwnerServiceIdentity:
    """Derive one W1 identity only from the validated joint authority."""
    selected = joint["roles"][role]
    root = selected["root_identity"]
    return CrossOwnerServiceIdentity(
        role=role.replace("_", "-"),
        service_id=selected["service_id"],
        build_sha256=selected["service_build_sha256"],
        root_identity_sha256=_digest({
            "root_id": root["root_id"], "device": root["device"],
            "inode": root["inode"],
        }),
        start_id=selected["expected_service_start_id"],
        session_id=selected["expected_service_session_id"],
        session_expires_at=selected["session_expires_at"],
        expected_uid=selected["expected_uid"],
        expected_gid=selected["expected_gid"],
        supplemental_groups=tuple(selected["supplemental_groups"]),
    )


def cross_owner_service_identity(
    authority: Mapping[str, Any], role: str,
) -> CrossOwnerServiceIdentity:
    """Return one fixed public service identity without opening a channel."""
    joint = validate_joint_service_authority(authority)
    if role not in OPERATION_OWNER_IDS:
        raise ProtectedServiceError("cross_owner_role_invalid", "$.role")
    return _cross_owner_identity(joint, role)


def _artifact_channel_witness(
    channel: socket.socket, joint: Mapping[str, Any], edge_id: str, *, server: bool,
) -> ChannelWitness | None:
    consumer_role, producer_role = _ARTIFACT_EDGE_POLICIES[edge_id]
    if server:
        _policy, uid, groups = _joint_server_binding(
            joint, edge_id, server_role=producer_role,
        )
    else:
        _policy, uid, groups = _joint_channel_binding(
            joint, edge_id, server_role=producer_role,
        )
        if _policy["client_id"] != consumer_role:
            raise ProtectedServiceError("cross_owner_channel_consumer_mismatch", "$.channel")
    witness = _channel_witness(channel)
    if joint["execution_scope"] == "live_external_candidate" and (
        witness is None or witness.peer_uid != uid or witness.peer_groups != groups
    ):
        raise ProtectedServiceError("cross_owner_channel_peer_mismatch", "$.channel")
    return witness


def _serve_cross_owner_artifact_once(
    *, channel: socket.socket, authority: Mapping[str, Any], edge_id: str,
    store: Any, expected_store_type: type, family_store: Any,
    export_method: str, serve_method: str, observed_at: datetime,
    expires_at: datetime,
) -> Mapping[str, Any]:
    if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
        raise ProtectedServiceError("cross_owner_channel_invalid", "$.channel")
    if type(store) is not expected_store_type:
        raise ProtectedServiceError("cross_owner_store_role_invalid", "$.store")
    joint = validate_joint_service_authority(authority)
    before = _artifact_channel_witness(channel, joint, edge_id, server=True)
    consumer_role, _producer_role = _ARTIFACT_EDGE_POLICIES[edge_id]
    artifact = getattr(store, export_method)(
        family_store=family_store,
        consumer_identity=_cross_owner_identity(joint, consumer_role),
        observed_at=observed_at, expires_at=expires_at,
    )
    getattr(store, serve_method)(descriptor=channel.fileno())
    if _channel_witness(channel) != before:
        raise ProtectedServiceError("cross_owner_channel_witness_changed", "$.channel")
    return MappingProxyType(deepcopy(dict(artifact)))


def _import_cross_owner_artifact_once(
    *, channel: socket.socket, authority: Mapping[str, Any], edge_id: str,
    store: Any, expected_store_type: type, import_method: str,
    expected_import_head_sha256: str | None, challenge: str, now: datetime,
) -> Any:
    if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
        raise ProtectedServiceError("cross_owner_channel_invalid", "$.channel")
    if type(store) is not expected_store_type:
        raise ProtectedServiceError("cross_owner_store_role_invalid", "$.store")
    joint = validate_joint_service_authority(authority)
    before = _artifact_channel_witness(channel, joint, edge_id, server=False)
    projection = getattr(store, import_method)(
        descriptor=channel.fileno(),
        expected_import_head_sha256=expected_import_head_sha256,
        challenge=challenge, now=now,
        expected_producer_identity=_cross_owner_identity(
            joint, _ARTIFACT_EDGE_POLICIES[edge_id][1],
        ),
        expected_consumer_identity=_cross_owner_identity(
            joint, _ARTIFACT_EDGE_POLICIES[edge_id][0],
        ),
    )
    if _channel_witness(channel) != before:
        raise ProtectedServiceError("cross_owner_channel_witness_changed", "$.channel")
    return projection


def serve_catalog_selection_to_responses_selection_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="catalog_selection_to_responses_selection_v1", expected_store_type=CatalogSelectionCrossOwnerStore, export_method="export_catalog_selection_to_responses_selection", serve_method="serve_catalog_selection_to_responses_selection", **values)


def import_catalog_selection_from_catalog_selection_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="catalog_selection_to_responses_selection_v1", expected_store_type=ResponsesSealsCrossOwnerStore, import_method="import_catalog_selection_from_catalog_selection", **values)


def serve_native_supervision_to_responses_context_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="native_supervision_to_responses_context_v1", expected_store_type=NativeSupervisionCrossOwnerStore, export_method="export_native_supervision_to_responses_context", serve_method="serve_native_supervision_to_responses_context", **values)


def import_native_supervision_for_responses_context_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="native_supervision_to_responses_context_v1", expected_store_type=ResponsesSealsCrossOwnerStore, import_method="import_native_supervision_from_native_supervision", **values)


def serve_responses_context_to_effect_authority_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="responses_context_to_effect_authority_v1", expected_store_type=ResponsesSealsCrossOwnerStore, export_method="export_responses_context_to_effect_authority", serve_method="serve_responses_context_to_effect_authority", **values)


def import_responses_context_for_effect_authority_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="responses_context_to_effect_authority_v1", expected_store_type=EffectAuthorityCrossOwnerStore, import_method="import_responses_context_from_responses_seals", **values)


def serve_effect_authority_to_registered_action_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="effect_authority_to_registered_action_v1", expected_store_type=EffectAuthorityCrossOwnerStore, export_method="export_effect_authority_to_registered_action", serve_method="serve_effect_authority_to_registered_action", **values)


def import_effect_authority_for_registered_action_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="effect_authority_to_registered_action_v1", expected_store_type=RegisteredActionCrossOwnerStore, import_method="import_effect_authority_from_effect_authority", **values)


def serve_registered_action_to_responses_bridge_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="registered_action_to_responses_bridge_v1", expected_store_type=RegisteredActionCrossOwnerStore, export_method="export_registered_action_to_responses_bridge", serve_method="serve_registered_action_to_responses_bridge", **values)


def import_registered_action_for_responses_bridge_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="registered_action_to_responses_bridge_v1", expected_store_type=ResponsesSealsCrossOwnerStore, import_method="import_registered_action_from_registered_action", **values)


def serve_responses_projection_to_recovery_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="responses_projection_to_recovery_v1", expected_store_type=ResponsesSealsCrossOwnerStore, export_method="export_responses_projection_to_recovery", serve_method="serve_responses_projection_to_recovery", **values)


def import_responses_projection_for_recovery_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="responses_projection_to_recovery_v1", expected_store_type=RecoveryCrossOwnerStore, import_method="import_responses_projection_from_responses_seals", **values)


def serve_native_supervision_to_recovery_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="native_supervision_to_recovery_v1", expected_store_type=NativeSupervisionCrossOwnerStore, export_method="export_native_supervision_to_recovery", serve_method="serve_native_supervision_to_recovery", **values)


def import_native_supervision_for_recovery_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="native_supervision_to_recovery_v1", expected_store_type=RecoveryCrossOwnerStore, import_method="import_native_supervision_from_native_supervision", **values)


def serve_effect_authority_to_recovery_artifact_once(**values: Any) -> Mapping[str, Any]:
    return _serve_cross_owner_artifact_once(edge_id="effect_authority_to_recovery_v1", expected_store_type=EffectAuthorityCrossOwnerStore, export_method="export_effect_authority_to_recovery", serve_method="serve_effect_authority_to_recovery", **values)


def import_effect_authority_for_recovery_artifact_once(**values: Any) -> Any:
    return _import_cross_owner_artifact_once(edge_id="effect_authority_to_recovery_v1", expected_store_type=RecoveryCrossOwnerStore, import_method="import_effect_authority_from_effect_authority", **values)


_ARTIFACT_IMPORT_ENTRYPOINTS = MappingProxyType({
    "catalog_selection_to_responses_selection_v1": (
        import_catalog_selection_from_catalog_selection_artifact_once,
        "current_catalog_selection_from_catalog_selection",
    ),
    "native_supervision_to_responses_context_v1": (
        import_native_supervision_for_responses_context_artifact_once,
        "current_native_supervision_from_native_supervision",
    ),
    "responses_context_to_effect_authority_v1": (
        import_responses_context_for_effect_authority_artifact_once,
        "current_responses_context_from_responses_seals",
    ),
    "effect_authority_to_registered_action_v1": (
        import_effect_authority_for_registered_action_artifact_once,
        "current_effect_authority_from_effect_authority",
    ),
    "registered_action_to_responses_bridge_v1": (
        import_registered_action_for_responses_bridge_artifact_once,
        "current_registered_action_from_registered_action",
    ),
    "responses_projection_to_recovery_v1": (
        import_responses_projection_for_recovery_artifact_once,
        "current_responses_projection_from_responses_seals",
    ),
    "native_supervision_to_recovery_v1": (
        import_native_supervision_for_recovery_artifact_once,
        "current_native_supervision_from_native_supervision",
    ),
    "effect_authority_to_recovery_v1": (
        import_effect_authority_for_recovery_artifact_once,
        "current_effect_authority_from_effect_authority",
    ),
})

_ARTIFACT_SERVE_ENTRYPOINTS = MappingProxyType({
    "catalog_selection_to_responses_selection_v1": serve_catalog_selection_to_responses_selection_artifact_once,
    "native_supervision_to_responses_context_v1": serve_native_supervision_to_responses_context_artifact_once,
    "responses_context_to_effect_authority_v1": serve_responses_context_to_effect_authority_artifact_once,
    "effect_authority_to_registered_action_v1": serve_effect_authority_to_registered_action_artifact_once,
    "registered_action_to_responses_bridge_v1": serve_registered_action_to_responses_bridge_artifact_once,
    "responses_projection_to_recovery_v1": serve_responses_projection_to_recovery_artifact_once,
    "native_supervision_to_recovery_v1": serve_native_supervision_to_recovery_artifact_once,
    "effect_authority_to_recovery_v1": serve_effect_authority_to_recovery_artifact_once,
})

_ARTIFACT_EXPORT_METHODS = MappingProxyType({
    "catalog_selection_to_responses_selection_v1": "export_catalog_selection_to_responses_selection",
    "native_supervision_to_responses_context_v1": "export_native_supervision_to_responses_context",
    "responses_context_to_effect_authority_v1": "export_responses_context_to_effect_authority",
    "effect_authority_to_registered_action_v1": "export_effect_authority_to_registered_action",
    "registered_action_to_responses_bridge_v1": "export_registered_action_to_responses_bridge",
    "responses_projection_to_recovery_v1": "export_responses_projection_to_recovery",
    "native_supervision_to_recovery_v1": "export_native_supervision_to_recovery",
    "effect_authority_to_recovery_v1": "export_effect_authority_to_recovery",
})
_ARTIFACT_RETAINED_SERVE_METHODS = MappingProxyType({
    edge: method.replace("export_", "serve_")
    for edge, method in _ARTIFACT_EXPORT_METHODS.items()
})


def _import_selected_artifact_once(
    *, edge_id: str, channel: socket.socket, authority: Mapping[str, Any],
    store: Any, now: datetime,
) -> Any:
    entrypoint, current_name = _ARTIFACT_IMPORT_ENTRYPOINTS[edge_id]
    current = getattr(store, current_name)()
    expected_head = None if current is None else current.import_head_sha256
    challenge = hashlib.sha256(
        (authority["authority_sha256"] + ":" + edge_id + ":" + now.strftime("%Y-%m-%dT%H:%M:%SZ")).encode()
    ).hexdigest()
    return entrypoint(
        channel=channel, authority=authority, store=store,
        expected_import_head_sha256=expected_head, challenge=challenge, now=now,
    )


def _serve_selected_artifact_once(
    *, edge_id: str, channel: socket.socket, authority: Mapping[str, Any],
    store: Any, family_store: Any, observed_at: datetime, expires_at: datetime,
) -> Mapping[str, Any]:
    return _ARTIFACT_SERVE_ENTRYPOINTS[edge_id](
        channel=channel, authority=authority, store=store,
        family_store=family_store, observed_at=observed_at, expires_at=expires_at,
    )


def _retain_selected_artifact(
    *, edge_id: str, authority: Mapping[str, Any], store: Any,
    family_store: Any, observed_at: datetime, expires_at: datetime,
) -> Mapping[str, Any]:
    """Retain one producer export without waiting for a future consumer."""
    consumer, _producer = _ARTIFACT_EDGE_POLICIES[edge_id]
    method = _ARTIFACT_EXPORT_METHODS[edge_id]
    return MappingProxyType(getattr(store, method)(
        family_store=family_store,
        consumer_identity=_cross_owner_identity(authority, consumer),
        observed_at=observed_at, expires_at=expires_at,
    ))


def _serve_retained_selected_artifact_once(
    *, edge_id: str, channel: socket.socket, authority: Mapping[str, Any],
    store: Any,
) -> None:
    """Serve the latest durable export without creating another export."""
    joint = validate_joint_service_authority(authority)
    before = _artifact_channel_witness(channel, joint, edge_id, server=True)
    getattr(store, _ARTIFACT_RETAINED_SERVE_METHODS[edge_id])(
        descriptor=channel.fileno(),
    )
    if _channel_witness(channel) != before:
        raise ProtectedServiceError("cross_owner_channel_witness_changed", "$.channel")


class JointOperationSourceExchange:
    """Authenticated callback for ``PreconnectedOperationSourceClient``."""

    __slots__ = ("_socket", "_joint", "_role", "_channel_id", "_witness", "_used")

    def __init__(self, channel: socket.socket, authority: Mapping[str, Any], owner_id: str) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("operation_source_channel_invalid", "$.channel")
        joint = validate_joint_service_authority(authority)
        if owner_id not in OPERATION_OWNER_IDS:
            raise ProtectedServiceError("operation_source_owner_invalid", "$.owner_id")
        channel_id = _SOURCE_CHANNELS[owner_id]
        _policy, uid, groups = _joint_channel_binding(joint, channel_id, server_role=owner_id)
        witness = _channel_witness(channel)
        if joint["execution_scope"] == "live_external_candidate":
            if witness is None or witness.peer_uid != uid or witness.peer_groups != groups:
                raise ProtectedServiceError("operation_source_peer_mismatch", "$.channel")
        self._socket = channel
        self._joint = joint
        self._role = joint["roles"][owner_id]
        self._channel_id = channel_id
        self._witness = witness
        self._used = False

    def __call__(
        self, *, operation: str, query: Mapping[str, Any], candidate_sha256: str,
        profile_sha256: str, request_challenge: str, requested_at: str,
    ) -> SourceUnavailable | Mapping[str, Any]:
        if self._used:
            raise ProtectedServiceError("operation_source_channel_reused", "$.channel")
        self._used = True
        if self._joint["execution_scope"] != "live_external_candidate":
            return SourceUnavailable(operation, "source_local_authority_not_live")
        current = _channel_witness(self._socket)
        if current != self._witness:
            return SourceUnavailable(operation, "operation_source_channel_witness_changed")
        if _time(requested_at, "$.requested_at") >= _time(self._role["session_expires_at"], "$.role.session_expires_at"):
            return SourceUnavailable(operation, "operation_source_session_expired")
        row = _seal({
            "schema_version": 1, "artifact_type": JOINT_SOURCE_REQUEST_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"],
            "channel_id": self._channel_id, "owner_id": self._role["role_id"],
            "service_id": self._role["service_id"],
            "service_build_sha256": self._role["service_build_sha256"],
            "client_service_start_id": self._joint["roles"]["protected_writer"]["expected_service_start_id"],
            "client_service_session_id": self._joint["roles"]["protected_writer"]["expected_service_session_id"],
            "expected_source_start_id": self._role["expected_service_start_id"],
            "expected_source_session_id": self._role["expected_service_session_id"],
            "challenge": request_challenge, "operation": operation, "query": _plain(query),
            "candidate_sha256": candidate_sha256, "profile_sha256": profile_sha256,
            "requested_at": requested_at, "request_sha256": "",
        }, "request_sha256")
        raw = _canonical(row)
        if len(raw) > MAX_FRAME_BYTES:
            raise ProtectedServiceError("operation_source_frame_oversized", "$.request")
        self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        header = _recv_exact_socket(self._socket, 4)
        length = struct.unpack("!I", header)[0]
        if length < 2 or length > MAX_FRAME_BYTES:
            raise ProtectedServiceError("operation_source_frame_length_invalid", "$.response")
        response = _closed(
            decode_framed_bytes(header + _recv_exact_socket(self._socket, length)),
            JOINT_SOURCE_RESPONSE_FIELDS, "operation_source_response_shape_invalid", "$.response",
        )
        if _channel_witness(self._socket) != self._witness:
            return SourceUnavailable(operation, "operation_source_channel_witness_changed")
        exact = {
            "schema_version": 1, "artifact_type": JOINT_SOURCE_RESPONSE_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"], "channel_id": self._channel_id,
            "owner_id": self._role["role_id"], "service_id": self._role["service_id"],
            "service_build_sha256": self._role["service_build_sha256"],
            "service_start_id": self._role["expected_service_start_id"],
            "service_session_id": self._role["expected_service_session_id"],
            "challenge": request_challenge, "operation": operation,
            "request_sha256": row["request_sha256"],
        }
        if any(response.get(field) != value for field, value in exact.items()):
            raise ProtectedServiceError("operation_source_response_binding_mismatch", "$.response")
        if response["response_sha256"] != _seal(response, "response_sha256")["response_sha256"]:
            raise ProtectedServiceError("operation_source_response_digest_invalid", "$.response")
        if response["state"] == "unavailable":
            if not isinstance(response["reason"], str) or any(response[field] is not None for field in (
                "fact_key", "fact_value", "observed_at", "expires_at", "source_digest",
                "observation_id", "journal_event_sha256",
            )):
                raise ProtectedServiceError("operation_source_unavailable_response_invalid", "$.response")
            return SourceUnavailable(operation, response["reason"])
        if response["state"] != "available" or response["reason"] is not None or not isinstance(response["fact_value"], Mapping):
            raise ProtectedServiceError("operation_source_available_response_invalid", "$.response")
        _identifier(response["fact_key"], "$.response.fact_key")
        _identifier(response["observation_id"], "$.response.observation_id")
        observed = _time(response["observed_at"], "$.response.observed_at")
        expires = _time(response["expires_at"], "$.response.expires_at")
        if not observed <= _time(requested_at, "$.requested_at") < expires:
            raise ProtectedServiceError("operation_source_response_not_fresh", "$.response")
        _sha(response["source_digest"], "$.response.source_digest")
        _sha(response["journal_event_sha256"], "$.response.journal_event_sha256")
        current_witness = _channel_witness(self._socket)
        if current_witness is None:
            raise ProtectedServiceError("operation_source_channel_witness_unavailable", "$.channel")
        return MappingProxyType(response)


class JointOperationSourceServiceHandler:
    """Serve one writer-to-source exchange on an inherited descriptor."""

    __slots__ = ("_socket", "_joint", "_role", "_channel_id", "_witness")

    def __init__(self, channel: socket.socket, authority: Mapping[str, Any], owner_id: str) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("operation_source_channel_invalid", "$.channel")
        joint = validate_joint_service_authority(authority)
        if owner_id not in OPERATION_OWNER_IDS:
            raise ProtectedServiceError("operation_source_owner_invalid", "$.owner_id")
        channel_id = _SOURCE_CHANNELS[owner_id]
        policy, uid, groups = _joint_server_binding(joint, channel_id, server_role=owner_id)
        if policy["client_id"] != "protected_writer":
            raise ProtectedServiceError("operation_source_client_role_invalid", "$.channel")
        witness = _channel_witness(channel)
        if joint["execution_scope"] == "live_external_candidate" and (
            witness is None or witness.peer_uid != uid or witness.peer_groups != groups
        ):
            raise ProtectedServiceError("operation_source_client_peer_mismatch", "$.channel")
        self._socket = channel; self._joint = joint; self._role = joint["roles"][owner_id]
        self._channel_id = channel_id; self._witness = witness

    def _pending(self) -> ProtectedServicePending | None:
        if self._joint["execution_scope"] != "live_external_candidate":
            return ProtectedServicePending(self._role["role_id"], "source_local_authority_not_live")
        if _channel_witness(self._socket) != self._witness:
            return ProtectedServicePending(self._role["role_id"], "operation_source_channel_witness_changed")
        return None

    def serve_one(
        self, dispatch: Callable[..., SourceUnavailable | QuarantinedDerivedResult],
    ) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self._pending()
        if pending is not None:
            return pending
        header = _recv_exact_socket(self._socket, 4); length = struct.unpack("!I", header)[0]
        if length < 2 or length > MAX_FRAME_BYTES:
            raise ProtectedServiceError("operation_source_frame_length_invalid", "$.request")
        request = _closed(
            decode_framed_bytes(header + _recv_exact_socket(self._socket, length)),
            JOINT_SOURCE_REQUEST_FIELDS, "operation_source_request_shape_invalid", "$.request",
        )
        expected = {
            "schema_version": 1, "artifact_type": JOINT_SOURCE_REQUEST_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"], "channel_id": self._channel_id,
            "owner_id": self._role["role_id"], "service_id": self._role["service_id"],
            "service_build_sha256": self._role["service_build_sha256"],
            "client_service_start_id": self._joint["roles"]["protected_writer"]["expected_service_start_id"],
            "client_service_session_id": self._joint["roles"]["protected_writer"]["expected_service_session_id"],
            "expected_source_start_id": self._role["expected_service_start_id"],
            "expected_source_session_id": self._role["expected_service_session_id"],
        }
        if any(request.get(field) != value for field, value in expected.items()):
            raise ProtectedServiceError("operation_source_request_binding_mismatch", "$.request")
        if request["request_sha256"] != _seal(request, "request_sha256")["request_sha256"]:
            raise ProtectedServiceError("operation_source_request_digest_invalid", "$.request")
        operation = request["operation"]
        if operation not in SOURCE_OPERATION_ROWS or SOURCE_OPERATION_ROWS[operation]["owner_id"] != self._role["role_id"]:
            raise ProtectedServiceError("operation_source_owner_mismatch", "$.request.operation")
        try:
            query = validate_operation_query(operation, request["query"])
        except OperationSourceError as exc:
            raise ProtectedServiceError(exc.code, exc.path) from exc
        _sha(request["candidate_sha256"], "$.request.candidate_sha256")
        _sha(request["profile_sha256"], "$.request.profile_sha256")
        _identifier(request["challenge"], "$.request.challenge")
        requested = _time(request["requested_at"], "$.request.requested_at")
        if requested >= _time(self._role["session_expires_at"], "$.role.session_expires_at"):
            raise ProtectedServiceError("operation_source_session_expired", "$.request")
        pending = self._pending()
        if pending is not None:
            return pending
        result = dispatch(
            operation=operation, query=query, candidate_sha256=request["candidate_sha256"],
            profile_sha256=request["profile_sha256"], request_challenge=request["challenge"],
            requested_at=request["requested_at"],
        )
        if not isinstance(result, (SourceUnavailable, QuarantinedDerivedResult)) or result.operation != operation:
            raise ProtectedServiceError("operation_source_result_invalid", "$.result")
        if isinstance(result, SourceUnavailable):
            values = {
                "state": "unavailable", "reason": result.reason, "fact_key": None,
                "fact_value": None, "observed_at": None, "expires_at": None,
                "source_digest": None, "observation_id": None, "journal_event_sha256": None,
            }
        else:
            if result._accepted_source_digest is None:
                raise ProtectedServiceError("operation_source_live_digest_missing", "$.result")
            values = {
                "state": "available", "reason": None, "fact_key": result.fact_key,
                "fact_value": _plain(result.fact_value), "observed_at": result.observed_at,
                "expires_at": result.expires_at, "source_digest": result._accepted_source_digest,
                "observation_id": result.observation_id,
                "journal_event_sha256": result.journal_event_sha256,
            }
        response = _seal({
            "schema_version": 1, "artifact_type": JOINT_SOURCE_RESPONSE_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"], "channel_id": self._channel_id,
            "owner_id": self._role["role_id"], "service_id": self._role["service_id"],
            "service_build_sha256": self._role["service_build_sha256"],
            "service_start_id": self._role["expected_service_start_id"],
            "service_session_id": self._role["expected_service_session_id"],
            "challenge": request["challenge"], "operation": operation,
            "request_sha256": request["request_sha256"], **values, "response_sha256": "",
        }, "response_sha256")
        pending = self._pending()
        if pending is not None:
            return pending
        raw = _canonical(response); self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        pending = self._pending()
        return pending if pending is not None else MappingProxyType(response)


class JointRawObservationServiceHandler:
    """Receive one operation-specific observation from the fixed family peer.

    The peer is an authenticated observer. It is not fact authority. This
    handler returns raw evidence only after it revalidates the descriptor and
    the peer witness. The owner adapter must persist and validate that evidence
    before this handler can acknowledge it.
    """

    __slots__ = (
        "_socket", "_joint", "_role", "_peer", "_channel_id", "_witness",
        "_request_type", "_request", "_used",
    )

    def __init__(self, channel: socket.socket, authority: Mapping[str, Any], owner_id: str) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("raw_observation_channel_invalid", "$.channel")
        joint = validate_joint_service_authority(authority)
        if owner_id not in OPERATION_OWNER_IDS:
            raise ProtectedServiceError("operation_source_owner_invalid", "$.owner_id")
        matches = [
            (channel_id, policy) for channel_id, policy in joint["channel_policies"].items()
            if policy["server_role"] == owner_id and policy["client_kind"] == "external_peer"
        ]
        if len(matches) != 1:
            raise ProtectedServiceError("raw_observation_channel_policy_invalid", "$.authority")
        channel_id, policy = matches[0]
        peer = joint["external_peers"][policy["client_id"]]
        witness = _channel_witness(channel)
        if joint["execution_scope"] == "live_external_candidate" and (
            witness is None
            or witness.peer_uid != peer["expected_uid"]
            or witness.peer_groups != tuple(peer["expected_groups"])
        ):
            raise ProtectedServiceError("raw_observation_peer_mismatch", "$.channel")
        self._socket = channel
        self._joint = joint
        self._role = joint["roles"][owner_id]
        self._peer = peer
        self._channel_id = channel_id
        self._request_type = policy["request_type"]
        self._witness = witness
        self._request = None
        self._used = False

    def _pending(self) -> ProtectedServicePending | None:
        if self._joint["execution_scope"] != "live_external_candidate":
            return ProtectedServicePending(self._role["role_id"], "source_local_authority_not_live")
        if _channel_witness(self._socket) != self._witness:
            return ProtectedServicePending(self._role["role_id"], "raw_observation_channel_witness_changed")
        return None

    def receive_one(self, operation: str) -> Mapping[str, Any] | ProtectedServicePending:
        if self._used:
            raise ProtectedServiceError("raw_observation_channel_reused", "$.channel")
        self._used = True
        pending = self._pending()
        if pending is not None:
            return pending
        if operation not in SOURCE_OPERATION_ROWS or SOURCE_OPERATION_ROWS[operation]["owner_id"] != self._role["role_id"]:
            raise ProtectedServiceError("operation_source_owner_mismatch", "$.operation")
        header = _recv_exact_socket(self._socket, 4)
        length = struct.unpack("!I", header)[0]
        if length < 2 or length > MAX_FRAME_BYTES:
            raise ProtectedServiceError("raw_observation_frame_length_invalid", "$.request")
        request = _closed(
            decode_framed_bytes(header + _recv_exact_socket(self._socket, length)),
            RAW_OBSERVATION_REQUEST_FIELDS, "raw_observation_request_shape_invalid", "$.request",
        )
        expected = {
            "schema_version": 1,
            "artifact_type": self._request_type,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"],
            "channel_id": self._channel_id,
            "owner_id": self._role["role_id"],
            "peer_id": self._peer["peer_id"],
            "peer_start_id": self._peer["peer_start_id"],
            "peer_session_id": self._peer["peer_session_id"],
            "expected_source_start_id": self._role["expected_service_start_id"],
            "expected_source_session_id": self._role["expected_service_session_id"],
            "operation": operation,
        }
        if any(request.get(field) != value for field, value in expected.items()):
            raise ProtectedServiceError("raw_observation_request_binding_mismatch", "$.request")
        _identifier(request["challenge"], "$.request.challenge")
        if request["request_sha256"] != _seal(request, "request_sha256")["request_sha256"]:
            raise ProtectedServiceError("raw_observation_request_digest_invalid", "$.request")
        try:
            raw = validate_raw_observation(operation, request["raw_observation"])
        except OperationSourceError as exc:
            raise ProtectedServiceError(exc.code, exc.path) from exc
        observed_field = (
            "receiver_time"
            if SOURCE_OPERATION_ROWS[operation]["raw_schema"] == "reconciliation"
            else "observed_at"
        )
        observed = _time(raw[observed_field], "$.request.raw_observation." + observed_field)
        if observed >= _time(self._peer["session_expires_at"], "$.peer.session_expires_at"):
            raise ProtectedServiceError("raw_observation_peer_session_expired", "$.request.raw_observation")
        if observed >= _time(self._role["session_expires_at"], "$.role.session_expires_at"):
            raise ProtectedServiceError("operation_source_session_expired", "$.request.raw_observation")
        pending = self._pending()
        if pending is not None:
            return pending
        self._request = MappingProxyType(request)
        return raw

    def acknowledge(
        self, result: SourceUnavailable | QuarantinedDerivedResult, *,
        retained_raw_event_sha256: str | None = None,
    ) -> Mapping[str, Any] | ProtectedServicePending:
        if self._request is None:
            raise ProtectedServiceError("raw_observation_request_missing", "$.request")
        if not isinstance(result, (SourceUnavailable, QuarantinedDerivedResult)) or result.operation != self._request["operation"]:
            raise ProtectedServiceError("operation_source_result_invalid", "$.result")
        pending = self._pending()
        if pending is not None:
            return pending
        available = isinstance(result, QuarantinedDerivedResult) and result._accepted_source_digest is not None
        if available:
            journal_event_sha256 = result.journal_event_sha256
        else:
            journal_event_sha256 = _sha(
                retained_raw_event_sha256,
                "$.retained_raw_event_sha256",
            )
        response = _seal({
            "schema_version": 1,
            "artifact_type": RAW_OBSERVATION_ACK_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "authority_sha256": self._joint["authority_sha256"],
            "channel_id": self._channel_id,
            "owner_id": self._role["role_id"],
            "service_id": self._role["service_id"],
            "service_start_id": self._role["expected_service_start_id"],
            "service_session_id": self._role["expected_service_session_id"],
            "challenge": self._request["challenge"],
            "operation": result.operation,
            "request_sha256": self._request["request_sha256"],
            "state": "derived_and_retained" if available else "retained_unavailable",
            "reason": None if available else result.reason,
            "observation_id": (
                result.observation_id if available
                else self._request["raw_observation"]["observation_id"]
            ),
            "journal_event_sha256": journal_event_sha256,
            "ack_sha256": "",
        }, "ack_sha256")
        raw = _canonical(response)
        self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        pending = self._pending()
        return pending if pending is not None else MappingProxyType(response)


def _serve_operation_source_owner_from_selected_root(
    *, owner_id: str, writer_channel: socket.socket,
    raw_observation_channel: socket.socket, authority: Mapping[str, Any],
    source_configuration: Mapping[str, Any],
    inherited_root_fd: int, store_root: Path, now: str | None = None,
    artifact_channels: Mapping[str, socket.socket] | None = None,
) -> Mapping[str, Any] | ProtectedServicePending:
    """Execute one fixed owner adapter without opening any other role root."""
    joint = validate_joint_service_authority(authority)
    if joint["execution_scope"] != "live_external_candidate":
        return ProtectedServicePending(owner_id, "source_local_authority_not_live")
    if owner_id not in OPERATION_OWNER_IDS:
        raise ProtectedServiceError("operation_source_owner_invalid", "$.owner_id")
    role = joint["roles"][owner_id]
    source = validate_source_service_configuration(source_configuration)
    if source["owner_id"] != owner_id:
        raise ProtectedServiceError("operation_source_joint_identity_mismatch", "$.source_configuration")
    expected = {
        "source_id": role["service_id"],
        "source_build_sha256": role["service_build_sha256"],
        "expected_uid": role["expected_uid"],
        "expected_gid": role["expected_gid"],
        "service_start_id": role["expected_service_start_id"],
        "service_session_id": role["expected_service_session_id"],
    }
    if any(source[field] != value for field, value in expected.items()):
        raise ProtectedServiceError("operation_source_joint_identity_mismatch", "$.source_configuration")
    validate_selected_joint_role(
        owner_id, joint, inherited_root_fd=inherited_root_fd,
        now=now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    descriptor_info = os.fstat(inherited_root_fd)
    root_witness = (descriptor_info.st_dev, descriptor_info.st_ino)
    store = OperationSourceStore(store_root)
    if store.source_local:
        raise ProtectedServiceError("operation_source_store_not_service_owned", "$.store_root")
    manifest_bindings = {
        "owner_id": owner_id,
        "source_id": source["source_id"],
        "source_build_sha256": source["source_build_sha256"],
        "service_uid": source["expected_uid"],
        "service_gid": source["expected_gid"],
        "service_start_id": source["service_start_id"],
        "service_session_id": source["service_session_id"],
    }
    if any(store.manifest[field] != value for field, value in manifest_bindings.items()):
        raise ProtectedServiceError("operation_source_store_identity_mismatch", "$.store_root")
    runtime_factory = {
        "catalog_selection": create_catalog_selection_accepted_runtime,
        "native_supervision": create_native_supervision_accepted_runtime,
        "responses_seals": create_responses_seals_accepted_runtime,
        "effect_authority": create_effect_authority_accepted_runtime,
        "registered_action": create_registered_action_accepted_runtime,
        "recovery": create_recovery_accepted_runtime,
    }[owner_id]
    runtime = (
        runtime_factory(store_root, joint, operation_state_store=store)
        if owner_id == "effect_authority"
        else runtime_factory(store_root, joint)
    )
    channels = {} if artifact_channels is None else dict(artifact_channels)
    allowed_edges = set(_ROLE_ARTIFACT_EDGES[owner_id])
    if set(channels) - allowed_edges or any(type(channel) is not socket.socket for channel in channels.values()):
        raise ProtectedServiceError("cross_owner_channel_invalid", "$.artifact_channels")
    complete_artifact_map = set(channels) == allowed_edges
    descriptor_values = [
        writer_channel.fileno(), raw_observation_channel.fileno(), inherited_root_fd,
        *(channel.fileno() for channel in channels.values()),
    ]
    if len(descriptor_values) != len(set(descriptor_values)):
        raise ProtectedServiceError("operation_source_descriptor_reused", "$.descriptors")
    role_name = owner_id
    before_witnesses = {
        "writer": _channel_witness(writer_channel),
        "raw": _channel_witness(raw_observation_channel),
    }
    for edge_id, channel in channels.items():
        before_witnesses[edge_id] = _artifact_channel_witness(
            channel, joint, edge_id,
            server=_ARTIFACT_EDGE_POLICIES[edge_id][1] == role_name,
        )
    if any(witness is None for witness in before_witnesses.values()):
        raise ProtectedServiceError("operation_source_channel_witness_unavailable", "$.channels")
    writer_handler = JointOperationSourceServiceHandler(writer_channel, joint, owner_id)
    raw_handler = JointRawObservationServiceHandler(raw_observation_channel, joint, owner_id)

    def dispatch(*, operation: str, query: Mapping[str, Any], **_bindings: Any) -> SourceUnavailable | QuarantinedDerivedResult:
        raw = raw_handler.receive_one(operation)
        if isinstance(raw, ProtectedServicePending):
            return SourceUnavailable(operation, raw.reason)
        owner_time = _time(
            now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "$.owner_now",
        )
        required_edges = set(_OPERATION_REQUIRED_ARTIFACT_EDGES[operation])
        if complete_artifact_map and not required_edges.issubset(channels):
            raise ProtectedServiceError("operation_source_artifact_channel_missing", "$.artifact_channels")
        active_edges = required_edges if complete_artifact_map else required_edges.intersection(channels)
        imported_edges: list[str] = []
        served_edges: list[str] = []
        for edge_id in sorted(active_edges):
            channel = channels[edge_id]
            consumer, _producer = _ARTIFACT_EDGE_POLICIES[edge_id]
            if consumer == role_name:
                _import_selected_artifact_once(
                    edge_id=edge_id, channel=channel, authority=joint,
                    store=runtime.artifact_store, now=owner_time,
                )
                imported_edges.append(edge_id)
        result = store.acquire_accepted(
            operation, raw, query, accepted_runtime=runtime,
            owner_now=owner_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        for edge_id in sorted(active_edges):
            channel = channels[edge_id]
            _consumer, producer = _ARTIFACT_EDGE_POLICIES[edge_id]
            if producer == role_name:
                _retain_selected_artifact(
                    edge_id=edge_id, authority=joint,
                    store=runtime.artifact_store, family_store=runtime.family_store,
                    observed_at=owner_time, expires_at=owner_time + timedelta(seconds=30),
                )
                served_edges.append(edge_id)
        raw_event = next(
            row for row in reversed(store.recover())
            if row["event_kind"] == "raw_observation"
            and row["observation_id"] == raw["observation_id"]
            and row["operation"] == operation
        )
        if isinstance(result, SourceUnavailable):
            raw_handler.acknowledge(
                result, retained_raw_event_sha256=raw_event["event_sha256"],
            )
            return result
        if not isinstance(result, QuarantinedDerivedResult):
            raise ProtectedServiceError("operation_source_result_invalid", "$.result")
        if not complete_artifact_map:
            unavailable = SourceUnavailable(
                operation, "accepted_family_quarantine_non_promotable",
            )
            raw_handler.acknowledge(
                unavailable, retained_raw_event_sha256=raw_event["event_sha256"],
            )
            return unavailable
        after_witnesses = {
            "writer": _channel_witness(writer_channel),
            "raw": _channel_witness(raw_observation_channel),
        }
        for edge_id, channel in channels.items():
            after_witnesses[edge_id] = _artifact_channel_witness(
                channel, joint, edge_id,
                server=_ARTIFACT_EDGE_POLICIES[edge_id][1] == role_name,
            )
        if after_witnesses != before_witnesses:
            raise ProtectedServiceError("operation_source_channel_witness_changed", "$.channels")
        if result._accepted_source_digest is None:
            raise ProtectedServiceError("operation_source_live_digest_missing", "$.result")
        raw_handler.acknowledge(result)
        return result

    result = writer_handler.serve_one(dispatch)
    descriptor_after = os.fstat(inherited_root_fd)
    if root_witness != (descriptor_after.st_dev, descriptor_after.st_ino):
        raise ProtectedServiceError("operation_source_root_descriptor_changed", "$.store_root")
    return result


def _copy_dirfd_tree_to_scratch(source_fd: int, target: Path) -> None:
    """Copy a closed descriptor tree into non-authoritative process scratch."""
    for name in os.listdir(source_fd):
        if name == ".runner.lock":
            continue
        if not isinstance(name, str) or name in {".", ".."} or "/" in name:
            raise ProtectedServiceError("operation_source_root_entry_invalid", "$.inherited_root_fd")
        info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        destination = target / name
        if stat.S_ISDIR(info.st_mode):
            destination.mkdir(mode=0o700)
            child_fd = os.open(
                name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            try:
                _copy_dirfd_tree_to_scratch(child_fd, destination)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
            try:
                chunks = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                os.close(descriptor)
            destination.write_bytes(b"".join(chunks))
            destination.chmod(0o600)
        else:
            raise ProtectedServiceError("operation_source_root_entry_type_invalid", "$.inherited_root_fd")


def _publish_scratch_tree_to_dirfd(source: Path, target_fd: int) -> None:
    """Publish scratch changes through openat-style operations only."""
    source_names = {item.name for item in source.iterdir()}
    target_names = set(os.listdir(target_fd)) - {".runner.lock"}
    for name in sorted(source_names):
        item = source / name
        prior = None
        try:
            prior = os.stat(name, dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        if item.is_dir() and not item.is_symlink():
            if prior is None:
                os.mkdir(name, 0o700, dir_fd=target_fd)
            elif not stat.S_ISDIR(prior.st_mode):
                raise ProtectedServiceError("operation_source_root_entry_collision", "$.inherited_root_fd")
            child_fd = os.open(
                name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=target_fd,
            )
            try:
                _publish_scratch_tree_to_dirfd(item, child_fd)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
        elif item.is_file() and not item.is_symlink():
            temporary = ".runner-publication-" + secrets.token_hex(16)
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=target_fd,
            )
            try:
                view = memoryview(item.read_bytes())
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ProtectedServiceError("operation_source_root_write_incomplete", "$.inherited_root_fd")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(temporary, name, src_dir_fd=target_fd, dst_dir_fd=target_fd)
        else:
            raise ProtectedServiceError("operation_source_scratch_entry_invalid", "$.scratch")
    for name in sorted(target_names - source_names):
        if name == ".runner.lock":
            continue
        info = os.stat(name, dir_fd=target_fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            os.unlink(name, dir_fd=target_fd)
        else:
            raise ProtectedServiceError("operation_source_root_delete_invalid", "$.inherited_root_fd")
    os.fsync(target_fd)


@contextmanager
def _descriptor_root_workspace(inherited_root_fd: int):
    """Lock one inherited root and expose only a non-authoritative scratch view."""
    try:
        root_info = os.fstat(inherited_root_fd)
        if not stat.S_ISDIR(root_info.st_mode):
            raise OSError("root descriptor is not a directory")
        lock_fd = os.open(
            ".runner.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600, dir_fd=inherited_root_fd,
        )
    except OSError as exc:
        raise ProtectedServiceError("operation_source_root_descriptor_invalid", "$.inherited_root_fd") from exc
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix="codexmax-owner-runner-") as scratch_name:
            scratch = Path(scratch_name)
            _copy_dirfd_tree_to_scratch(inherited_root_fd, scratch)
            yield scratch
            current_root = os.fstat(inherited_root_fd)
            if (current_root.st_dev, current_root.st_ino) != (root_info.st_dev, root_info.st_ino):
                raise ProtectedServiceError("operation_source_root_descriptor_changed", "$.inherited_root_fd")
            _publish_scratch_tree_to_dirfd(scratch, inherited_root_fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def serve_operation_source_owner_once(
    *, owner_id: str, writer_channel: socket.socket,
    raw_observation_channel: socket.socket, authority: Mapping[str, Any],
    source_configuration: Mapping[str, Any], inherited_root_fd: int,
    now: str | None = None,
    artifact_channels: Mapping[str, socket.socket] | None = None,
) -> Mapping[str, Any] | ProtectedServicePending:
    """Serve one owner from an inherited descriptor without cwd authority."""
    with _descriptor_root_workspace(inherited_root_fd) as store_root:
        return _serve_operation_source_owner_from_selected_root(
            owner_id=owner_id, writer_channel=writer_channel,
            raw_observation_channel=raw_observation_channel, authority=authority,
            source_configuration=source_configuration,
            inherited_root_fd=inherited_root_fd, store_root=store_root, now=now,
            artifact_channels=artifact_channels,
        )


def _fixed_operation_owner_runner(owner_id: str) -> Callable[..., Mapping[str, Any] | ProtectedServicePending]:
    def runner(**values: Any) -> Mapping[str, Any] | ProtectedServicePending:
        return serve_operation_source_owner_once(owner_id=owner_id, **values)
    runner.__name__ = "serve_" + owner_id + "_owner_once"
    runner.__doc__ = "Serve one fixed " + owner_id + " operation-owner exchange."
    return runner


OPERATION_SOURCE_OWNER_RUNNERS = MappingProxyType({
    owner_id: _fixed_operation_owner_runner(owner_id)
    for owner_id in OPERATION_OWNER_IDS
})
for _owner_id, _owner_runner in OPERATION_SOURCE_OWNER_RUNNERS.items():
    globals()[_owner_runner.__name__] = _owner_runner


class PreconnectedProtectedServiceChannel:
    """One-use framed channel. It never opens or discovers a socket."""

    __slots__ = (
        "_socket", "_config", "_socket_fingerprint", "_used", "_joint_policy",
        "_expected_peer_uid", "_expected_peer_groups", "_admitted_witness", "_joint_scope",
    )

    def __init__(
        self, channel: socket.socket, configuration: Mapping[str, Any], *,
        joint_authority: Mapping[str, Any] | None = None, channel_id: str | None = None,
    ) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("protected_service_channel_invalid", "$.channel")
        self._config = validate_service_configuration(configuration)
        self._socket = channel
        self._socket_fingerprint = _socket_fingerprint(channel)
        self._used = False
        if (joint_authority is None) != (channel_id is None):
            raise ProtectedServiceError("joint_authority_channel_binding_incomplete", "$.channel")
        self._joint_policy = None
        self._expected_peer_uid = self._config["expected_uid"]
        self._expected_peer_groups = (self._config["expected_gid"],)
        self._admitted_witness = None
        self._joint_scope = None
        if joint_authority is not None and channel_id is not None:
            policy, uid, groups = _joint_channel_binding(
                joint_authority, channel_id, server_role=self._config["service"],
            )
            expected_config = service_configuration_from_authority(joint_authority, self._config["service"])
            if any(self._config[field] != expected_config[field] for field in CONFIG_FIELDS - {"max_frame_bytes"}):
                raise ProtectedServiceError("joint_authority_service_config_mismatch", "$.config")
            self._joint_policy = policy
            self._joint_scope = validate_joint_service_authority(joint_authority)["execution_scope"]
            self._expected_peer_uid = uid
            self._expected_peer_groups = groups
            self._admitted_witness = _channel_witness(channel)

    def _current_pending(self) -> ProtectedServicePending | None:
        try:
            channel = self._socket
            config = self._config
            expected_fingerprint = self._socket_fingerprint
        except AttributeError:
            return ProtectedServicePending("unknown", "protected_service_channel_uninitialized")
        try:
            if _socket_fingerprint(channel) != expected_fingerprint:
                return ProtectedServicePending(config["service"], "protected_service_socket_replaced")
        except ProtectedServiceError as exc:
            return ProtectedServicePending(config["service"], exc.code)
        if self._joint_scope == "source_local_test":
            return ProtectedServicePending(config["service"], "source_local_authority_not_live")
        witness = _channel_witness(channel)
        if witness is None:
            reason = "kernel_peer_credentials_not_supported"
        else:
            uid, groups = witness.peer_uid, witness.peer_groups
            if self._joint_policy is not None and witness != self._admitted_witness:
                return ProtectedServicePending(config["service"], "protected_service_channel_witness_changed")
            if uid == os.geteuid():
                reason = "same_uid_peer_not_authoritative"
            elif uid != self._expected_peer_uid:
                reason = "protected_service_uid_mismatch"
            elif self._joint_policy is not None and groups != self._expected_peer_groups:
                reason = "protected_service_groups_mismatch"
            elif self._joint_policy is None and config["expected_gid"] not in groups:
                reason = "protected_service_gid_mismatch"
            else:
                return None
        return ProtectedServicePending(config["service"], reason)

    @property
    def pending(self) -> ProtectedServicePending | None:
        return self._current_pending()

    def exchange(self, request: Mapping[str, Any]) -> Mapping[str, Any] | ProtectedServicePending:
        if self._used:
            raise ProtectedServiceError("protected_service_channel_reused", "$.channel")
        self._used = True
        if self.pending is not None:
            return self.pending
        request_row = validate_request(request, self._config)
        decoded = self._exchange_mapping(request_row)
        current = self._current_pending()
        if current is not None:
            return current
        return validate_response(decoded, request_row, self._config)

    def exchange_command(self, request: Mapping[str, Any]) -> Mapping[str, Any] | ProtectedServicePending:
        """Exchange one service command and validate all response bindings."""
        if self._used:
            raise ProtectedServiceError("protected_service_channel_reused", "$.channel")
        self._used = True
        pending = self._current_pending()
        if pending is not None:
            return pending
        request_row = validate_request(request, self._config)
        decoded = self._exchange_mapping(request_row)
        pending = self._current_pending()
        if pending is not None:
            return pending
        return validate_command_response(decoded, request_row, self._config)

    def _exchange_mapping(self, request_row: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = _canonical(request_row)
        if len(payload) > self._config["max_frame_bytes"]:
            raise ProtectedServiceError("protected_service_frame_oversized", "$.request")
        try:
            self._socket.sendall(struct.pack("!I", len(payload)) + payload)
            header = self._recv_exact(4)
            length = struct.unpack("!I", header)[0]
            if length < 2 or length > self._config["max_frame_bytes"]:
                raise ProtectedServiceError("protected_service_frame_length_invalid", "$.response")
            raw = self._recv_exact(length)
        except ProtectedServiceError:
            raise
        except (OSError, TimeoutError) as exc:
            raise ProtectedServiceError("protected_service_channel_failed", "$.channel") from exc
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtectedServiceError("protected_service_response_json_invalid", "$.response") from exc
        if _canonical(decoded) != raw:
            raise ProtectedServiceError("protected_service_response_not_canonical", "$.response")
        if not isinstance(decoded, Mapping):
            raise ProtectedServiceError("protected_service_response_shape_invalid", "$.response")
        return decoded

    def _recv_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            part = self._socket.recv(count - len(chunks))
            if not part:
                raise ProtectedServiceError("protected_service_frame_truncated", "$.response")
            chunks.extend(part)
        return bytes(chunks)


class PreconnectedRunnerInstallerEvidence:
    """Retired predecessor port retained only to reject stale constructors."""

    __slots__ = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.installer")

    def exchange(self, *, now: datetime) -> Mapping[str, Any] | ProtectedServicePending:
        del now
        raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.installer")


class PreconnectedDeploymentAdmissionV2:
    """Read one DeploymentAdmissionV2 from the distinct bootstrap account."""

    __slots__ = (
        "_socket", "_fingerprint", "_witness", "_uid", "_groups",
        "_bootstrap_identity", "_previous_commit", "_used",
    )

    def __init__(
        self, channel: socket.socket, *, expected_uid: int, expected_gid: int,
        expected_groups: tuple[int, ...], bootstrap_identity: Mapping[str, str],
        expected_previous_commit_sha256: str | None,
    ) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise ProtectedServiceError("deployment_admission_channel_invalid", "$.bootstrap")
        required = {"bootstrap_source_id", "bootstrap_build_sha256", "bootstrap_start_id", "bootstrap_session_id"}
        if not isinstance(bootstrap_identity, Mapping) or set(bootstrap_identity) != required:
            raise ProtectedServiceError("deployment_bootstrap_identity_invalid", "$.bootstrap")
        identity = dict(bootstrap_identity)
        if identity["bootstrap_source_id"] != DEPLOYMENT_BOOTSTRAP_SOURCE_ID:
            raise ProtectedServiceError("deployment_bootstrap_source_mismatch", "$.bootstrap")
        for field in ("bootstrap_source_id", "bootstrap_start_id", "bootstrap_session_id"):
            _identifier(identity[field], "$.bootstrap." + field)
        _sha(identity["bootstrap_build_sha256"], "$.bootstrap.bootstrap_build_sha256")
        if type(expected_uid) is not int or expected_uid < 1 or type(expected_gid) is not int or expected_gid < 1:
            raise ProtectedServiceError("deployment_bootstrap_account_invalid", "$.bootstrap")
        if not isinstance(expected_groups, tuple) or expected_groups != tuple(sorted(set(expected_groups))) or expected_gid not in expected_groups:
            raise ProtectedServiceError("deployment_bootstrap_groups_invalid", "$.bootstrap")
        if expected_previous_commit_sha256 is not None:
            _sha(expected_previous_commit_sha256, "$.previous_commit_sha256")
        self._socket = channel
        self._fingerprint = _socket_fingerprint(channel)
        self._witness = _channel_witness(channel)
        self._uid = expected_uid
        self._groups = expected_groups
        self._bootstrap_identity = MappingProxyType(identity)
        self._previous_commit = expected_previous_commit_sha256
        self._used = False

    def _pending(self) -> ProtectedServicePending | None:
        try:
            if _socket_fingerprint(self._socket) != self._fingerprint:
                return ProtectedServicePending("deployment_bootstrap", "deployment_bootstrap_socket_replaced")
            witness = _channel_witness(self._socket)
        except (AttributeError, ProtectedServiceError):
            return ProtectedServicePending("deployment_bootstrap", "deployment_bootstrap_peer_invalid")
        if witness is None:
            return ProtectedServicePending("deployment_bootstrap", "kernel_peer_credentials_not_supported")
        if witness != self._witness:
            return ProtectedServicePending("deployment_bootstrap", "deployment_bootstrap_witness_changed")
        if witness.peer_uid == os.geteuid():
            return ProtectedServicePending("deployment_bootstrap", "same_uid_bootstrap_not_authoritative")
        if witness.peer_uid != self._uid or witness.peer_groups != self._groups:
            return ProtectedServicePending("deployment_bootstrap", "deployment_bootstrap_peer_mismatch")
        return None

    def exchange(self, *, now: datetime) -> Mapping[str, Any] | ProtectedServicePending:
        pending = self._pending()
        if pending is not None:
            return pending
        if self._used:
            raise ProtectedServiceError("deployment_admission_channel_reused", "$.bootstrap")
        self._used = True
        challenge = secrets.token_urlsafe(32)
        request = _seal({
            "schema_version": 2,
            "artifact_type": "codexmax_deployment_admission_request_v2",
            **dict(self._bootstrap_identity),
            "challenge": challenge,
            "previous_commit_sha256": self._previous_commit,
            "request_sha256": "",
        }, "request_sha256")
        raw = _canonical(request)
        self._socket.sendall(struct.pack("!I", len(raw)) + raw)
        header = _recv_exact_socket(self._socket, 4)
        size = struct.unpack("!I", header)[0]
        if size < 2 or size > INSTALLER_FRAME_MAX_BYTES:
            raise ProtectedServiceError("deployment_admission_frame_length_invalid", "$.bootstrap")
        response = decode_framed_bytes(header + _recv_exact_socket(self._socket, size), maximum=INSTALLER_FRAME_MAX_BYTES)
        _reject_socket_trailing(self._socket, "$.bootstrap")
        if set(response) != {"challenge", "request_sha256", "admission", "response_sha256"}:
            raise ProtectedServiceError("deployment_admission_response_shape_invalid", "$.bootstrap")
        if response["challenge"] != challenge or response["request_sha256"] != request["request_sha256"]:
            raise ProtectedServiceError("deployment_admission_response_binding_mismatch", "$.bootstrap")
        if response["response_sha256"] != _seal(response, "response_sha256")["response_sha256"]:
            raise ProtectedServiceError("deployment_admission_response_digest_mismatch", "$.bootstrap")
        return validate_deployment_admission_v2(
            response["admission"], now=now,
            expected_previous_commit_sha256=self._previous_commit,
        )


class OsBoundDeploymentAdmissionV2Source:
    """Expose one candidate-bound authenticated admission to the runtime."""

    __slots__ = ("_channel", "_selected_candidate", "_used")

    def __init__(
        self, channel: PreconnectedDeploymentAdmissionV2,
        selected_candidate: VerifiedSelectedCandidate,
    ) -> None:
        if type(channel) is not PreconnectedDeploymentAdmissionV2 or type(selected_candidate) is not VerifiedSelectedCandidate:
            raise ProtectedServiceError("deployment_admission_source_invalid", "$.source")
        self._channel = channel
        self._selected_candidate = selected_candidate
        self._used = False

    def _consume_authenticated_admission(self, *, now: datetime) -> Mapping[str, Any]:
        if (
            getattr(self, "_used", None) is not False
            or type(getattr(self, "_channel", None)) is not PreconnectedDeploymentAdmissionV2
            or type(getattr(self, "_selected_candidate", None)) is not VerifiedSelectedCandidate
        ):
            raise ProtectedServiceError("deployment_admission_source_reused_or_uninitialized", "$.source")
        self._used = True
        result = self._channel.exchange(now=now)
        if isinstance(result, ProtectedServicePending):
            raise ProtectedServiceError(result.reason, "$.bootstrap")
        try:
            return self._selected_candidate.bind_admission(result)
        except CandidateAdmissionError as exc:
            raise ProtectedServiceError(exc.code, exc.path) from exc


class OsBoundCurrentRunnerV26AdmissionSource:
    """Retired predecessor seam retained only to reject stale callers."""

    __slots__ = ()

    def __init__(
        self, *, installer: PreconnectedRunnerInstallerEvidence,
        writer_channel: PreconnectedProtectedServiceChannel,
        anchor_channel: PreconnectedProtectedServiceChannel,
        profile_sha256: str, client_service_start_id: str, client_session_id: str,
    ) -> None:
        del installer, writer_channel, anchor_channel, profile_sha256
        del client_service_start_id, client_session_id
        raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.source")

    def _consume_authenticated_admission(self, *, now: datetime) -> Mapping[str, Any]:
        del now
        raise ProtectedServiceError("retired_static_candidate_admission_forbidden", "$.source")


class AnchorServiceClient:
    """Writer-side client for one exact independent-anchor command."""

    __slots__ = ("_channel", "_services")

    def __init__(
        self, channel: PreconnectedProtectedServiceChannel,
        service_configurations: Mapping[str, Mapping[str, Any]],
    ) -> None:
        services = validate_service_set(service_configurations)
        if type(channel) is not PreconnectedProtectedServiceChannel:
            raise ProtectedServiceError("anchor_service_client_channel_invalid", "$.channel")
        if dict(channel._config) != dict(services["independent_anchor"]):
            raise ProtectedServiceError("anchor_service_client_configuration_mismatch", "$.channel")
        self._channel = channel; self._services = services

    def _command(self, body: Mapping[str, Any], outer_request: Mapping[str, Any]) -> Mapping[str, Any]:
        writer = self._services["protected_writer"]
        anchor = self._services["independent_anchor"]
        command = prepare_request(
            anchor, challenge=secrets.token_urlsafe(32),
            client_session_id=writer["expected_service_session_id"],
            client_service_start_id=writer["expected_service_start_id"],
            principal_id=outer_request["principal_id"], operation=outer_request["operation"],
            candidate_sha256=outer_request["candidate_sha256"],
            profile_sha256=outer_request["profile_sha256"],
            operation_body_sha256=outer_request["operation_body_sha256"],
            dependency_receipts_sha256=outer_request["dependency_receipts_sha256"],
            requested_at=outer_request["requested_at"],
            request_body=_plain(body),
        )
        response = self._channel.exchange_command(command)
        if isinstance(response, ProtectedServicePending):
            raise ProtectedServiceError(response.reason, "$.anchor_service")
        if response["state"] != "completed":
            raise ProtectedServiceError(response["reason"], "$.anchor_service")
        result = response["result"]
        if not isinstance(result, Mapping) or result.get("execution_scope") != "service_account_owned_candidate":
            raise ProtectedServiceError("anchor_service_result_not_live_candidate", "$.anchor_service")
        value = result.get("value")
        if not isinstance(value, Mapping):
            raise ProtectedServiceError("anchor_service_result_invalid", "$.anchor_service")
        return MappingProxyType(_plain(value))

    def retain(
        self, request: Mapping[str, Any], writer_statement: Mapping[str, Any],
        outer_request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._command({
            "command": "retain", "request": _plain(request),
            "writer_statement": _plain(writer_statement),
        }, outer_request)
        if set(value) != {"anchor_receipt"} or not isinstance(value["anchor_receipt"], Mapping):
            raise ProtectedServiceError("anchor_service_result_invalid", "$.anchor_service")
        return MappingProxyType(_plain(value["anchor_receipt"]))

    def read(
        self, namespace: str, anchor_receipt_sha256: str, outer_request: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], ...]:
        value = self._command({
            "command": "read", "namespace": namespace,
            "anchor_receipt_sha256": anchor_receipt_sha256,
        }, outer_request)
        if set(value) != {"records"} or not isinstance(value["records"], list):
            raise ProtectedServiceError("anchor_service_result_invalid", "$.anchor_service")
        return tuple(MappingProxyType(_plain(row)) for row in value["records"])

    def recover(self, outer_request: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
        value = self._command({"command": "recover"}, outer_request)
        if set(value) != {"heads"} or not isinstance(value["heads"], Mapping):
            raise ProtectedServiceError("anchor_service_result_invalid", "$.anchor_service")
        return MappingProxyType({key: MappingProxyType(_plain(row)) for key, row in value["heads"].items()})


class OsBoundOpaqueTlsTransport:
    """Submit receiver frames through a kernel-authenticated TLS agent."""

    __slots__ = ("_channel", "_client_session_id", "_server_leaf_sha256", "_principal_id", "_operation", "_used")

    def __init__(
        self, channel: PreconnectedProtectedServiceChannel, *,
        client_session_id: str, server_leaf_sha256: str,
        principal_id: str = "first-party-responses-bridge-producer-v1",
        operation: str = "verify_responses_bridge",
    ) -> None:
        if type(channel) is not PreconnectedProtectedServiceChannel or channel._config["service"] != "opaque_tls_agent":
            raise ProtectedServiceError("opaque_tls_agent_channel_invalid", "$.channel")
        self._channel = channel
        self._client_session_id = _identifier(client_session_id, "$.client_session_id")
        self._server_leaf_sha256 = _sha(server_leaf_sha256, "$.server_leaf_sha256")
        self._principal_id = _identifier(principal_id, "$.principal_id")
        self._operation = _identifier(operation, "$.operation")
        self._used = False

    def _consume(self, expected_server_leaf_sha256: str):
        try:
            used = self._used
            server_leaf = self._server_leaf_sha256
            channel = self._channel
        except AttributeError as exc:
            raise ProtectedServiceError("opaque_tls_agent_transport_uninitialized", "$.transport") from exc
        if used:
            raise ProtectedServiceError("opaque_tls_agent_transport_reused", "$.transport")
        self._used = True
        if expected_server_leaf_sha256 != server_leaf:
            raise ProtectedServiceError("opaque_tls_agent_leaf_mismatch", "$.transport")
        if channel.pending is not None:
            raise ProtectedServiceError(channel.pending.reason, "$.transport")
        if channel._used:
            raise ProtectedServiceError("protected_service_channel_reused", "$.channel")
        channel._used = True
        return self.exchange_receiver

    def exchange_receiver(self, receiver_request: bytes) -> bytes:
        if not isinstance(receiver_request, bytes):
            raise ProtectedServiceError("opaque_tls_agent_request_invalid", "$.request")
        config = self._channel._config
        encoded = base64.b64encode(receiver_request).decode("ascii")
        request = _seal({
            "schema_version": 1, "artifact_type": "supported_host_opaque_tls_request_v1",
            "protocol_version": PROTOCOL_VERSION, "service": config["service"],
            "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
            "challenge": secrets.token_urlsafe(32), "client_session_id": self._client_session_id,
            "expected_service_start_id": config["expected_service_start_id"],
            "expected_service_session_id": config["expected_service_session_id"],
            "expected_server_leaf_sha256": self._server_leaf_sha256,
            "principal_id": self._principal_id, "operation": self._operation,
            "receiver_request_b64": encoded,
            "receiver_request_sha256": "sha256:" + hashlib.sha256(receiver_request).hexdigest(),
            "request_sha256": "",
        }, "request_sha256")
        decoded = self._channel._exchange_mapping(request)
        current = self._channel._current_pending()
        if current is not None:
            raise ProtectedServiceError(current.reason, "$.transport")
        row = _closed(decoded, TLS_RESPONSE_FIELDS, "opaque_tls_agent_response_shape_invalid", "$.response")
        exact = {
            "schema_version": 1, "artifact_type": "supported_host_opaque_tls_response_v1",
            "protocol_version": PROTOCOL_VERSION, "service": config["service"],
            "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
            "challenge": request["challenge"], "client_session_id": self._client_session_id,
            "principal_id": self._principal_id, "operation": self._operation,
            "request_sha256": request["request_sha256"], "server_leaf_sha256": self._server_leaf_sha256,
            "service_start_id": config["expected_service_start_id"],
            "service_session_id": config["expected_service_session_id"],
        }
        if any(row[name] != expected for name, expected in exact.items()):
            raise ProtectedServiceError("opaque_tls_agent_response_binding_mismatch", "$.response")
        _identifier(row["service_session_id"], "$.response.service_session_id")
        _identifier(row["service_start_id"], "$.response.service_start_id")
        try:
            raw = base64.b64decode(row["receiver_response_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ProtectedServiceError("opaque_tls_agent_response_encoding_invalid", "$.response") from exc
        if row["receiver_response_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise ProtectedServiceError("opaque_tls_agent_receiver_digest_mismatch", "$.response")
        if row["response_sha256"] != _seal(row, "response_sha256")["response_sha256"]:
            raise ProtectedServiceError("opaque_tls_agent_response_digest_mismatch", "$.response")
        return raw


def validate_tls_request(value: Mapping[str, Any], configuration: Mapping[str, Any]) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration)
    row = _closed(value, TLS_REQUEST_FIELDS, "opaque_tls_agent_request_shape_invalid", "$.request")
    exact = {
        "schema_version": 1, "artifact_type": "supported_host_opaque_tls_request_v1",
        "protocol_version": PROTOCOL_VERSION, "service": "opaque_tls_agent",
        "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
        "expected_service_start_id": config["expected_service_start_id"],
        "expected_service_session_id": config["expected_service_session_id"],
    }
    if config["service"] != "opaque_tls_agent" or any(row.get(key) != expected for key, expected in exact.items()):
        raise ProtectedServiceError("opaque_tls_agent_request_binding_mismatch", "$.request")
    _identifier(row["client_session_id"], "$.request.client_session_id")
    _identifier(row["principal_id"], "$.request.principal_id"); _identifier(row["operation"], "$.request.operation")
    if not isinstance(row["challenge"], str) or _CHALLENGE.fullmatch(row["challenge"]) is None:
        raise ProtectedServiceError("protected_service_challenge_invalid", "$.request.challenge")
    _sha(row["expected_server_leaf_sha256"], "$.request.expected_server_leaf_sha256")
    try:
        raw = base64.b64decode(row["receiver_request_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ProtectedServiceError("opaque_tls_agent_request_encoding_invalid", "$.request") from exc
    if row["receiver_request_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest() or row["request_sha256"] != _seal(row, "request_sha256")["request_sha256"]:
        raise ProtectedServiceError("opaque_tls_agent_request_digest_mismatch", "$.request")
    return MappingProxyType(row)


def prepare_tls_response(
    configuration: Mapping[str, Any], request: Mapping[str, Any], agent_response: Mapping[str, Any],
) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration); request_row = validate_tls_request(request, config)
    agent_response = _closed(agent_response, OPAQUE_AGENT_RESPONSE_FIELDS, "opaque_credential_agent_response_shape_invalid", "$.agent_response")
    if agent_response.get("server_leaf_sha256") != request_row["expected_server_leaf_sha256"]:
        raise ProtectedServiceError("opaque_credential_agent_leaf_mismatch", "$.agent_response")
    try:
        raw = base64.b64decode(agent_response["receiver_response_b64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtectedServiceError("opaque_credential_agent_response_encoding_invalid", "$.agent_response") from exc
    if agent_response.get("receiver_response_sha256") != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise ProtectedServiceError("opaque_credential_agent_response_digest_mismatch", "$.agent_response")
    return MappingProxyType(_seal({
        "schema_version": 1, "artifact_type": "supported_host_opaque_tls_response_v1",
        "protocol_version": PROTOCOL_VERSION, "service": "opaque_tls_agent",
        "service_id": config["service_id"], "service_build_sha256": config["service_build_sha256"],
        "challenge": request_row["challenge"], "client_session_id": request_row["client_session_id"],
        "service_session_id": config["expected_service_session_id"],
        "service_start_id": config["expected_service_start_id"],
        "principal_id": request_row["principal_id"], "operation": request_row["operation"],
        "request_sha256": request_row["request_sha256"],
        "server_leaf_sha256": request_row["expected_server_leaf_sha256"],
        "receiver_response_b64": agent_response["receiver_response_b64"],
        "receiver_response_sha256": agent_response["receiver_response_sha256"],
        "response_sha256": "",
    }, "response_sha256"))


def prepare_request(
    configuration: Mapping[str, Any], *, challenge: str, client_session_id: str,
    client_service_start_id: str, principal_id: str, operation: str,
    candidate_sha256: str, profile_sha256: str, operation_body_sha256: str,
    dependency_receipts_sha256: str, requested_at: str, request_body: Mapping[str, Any],
) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration)
    if not isinstance(challenge, str) or _CHALLENGE.fullmatch(challenge) is None:
        raise ProtectedServiceError("protected_service_challenge_invalid", "$.challenge")
    for value, path in ((client_session_id, "$.client_session_id"), (client_service_start_id, "$.client_service_start_id"), (principal_id, "$.principal_id"), (operation, "$.operation")):
        _identifier(value, path)
    for value, path in ((candidate_sha256, "$.candidate_sha256"), (profile_sha256, "$.profile_sha256"), (operation_body_sha256, "$.operation_body_sha256"), (dependency_receipts_sha256, "$.dependency_receipts_sha256")):
        _sha(value, path)
    _time(requested_at, "$.requested_at")
    if not isinstance(request_body, Mapping):
        raise ProtectedServiceError("protected_service_request_body_invalid", "$.request_body")
    return MappingProxyType(_seal({
        "schema_version": 1, "artifact_type": REQUEST_TYPE, "protocol_version": PROTOCOL_VERSION,
        "service": config["service"], "service_id": config["service_id"],
        "service_build_sha256": config["service_build_sha256"], "challenge": challenge,
        "client_session_id": client_session_id, "client_service_start_id": client_service_start_id,
        "expected_service_start_id": config["expected_service_start_id"],
        "expected_service_session_id": config["expected_service_session_id"],
        "principal_id": principal_id, "operation": operation, "candidate_sha256": candidate_sha256,
        "profile_sha256": profile_sha256, "operation_body_sha256": operation_body_sha256,
        "dependency_receipts_sha256": dependency_receipts_sha256, "requested_at": requested_at,
        "request_body": deepcopy(dict(request_body)), "request_body_sha256": _digest(request_body),
        "request_sha256": "",
    }, "request_sha256"))


def validate_request(value: Mapping[str, Any], configuration: Mapping[str, Any]) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration)
    row = _closed(value, REQUEST_FIELDS, "protected_service_request_shape_invalid", "$.request")
    if row["schema_version"] != 1 or row["artifact_type"] != REQUEST_TYPE or row["protocol_version"] != PROTOCOL_VERSION:
        raise ProtectedServiceError("protected_service_request_identity_invalid", "$.request")
    if row["service"] != config["service"] or row["service_id"] != config["service_id"] or row["service_build_sha256"] != config["service_build_sha256"]:
        raise ProtectedServiceError("protected_service_request_service_mismatch", "$.request")
    if row["expected_service_start_id"] != config["expected_service_start_id"] or row["expected_service_session_id"] != config["expected_service_session_id"]:
        raise ProtectedServiceError("protected_service_request_continuity_mismatch", "$.request")
    if row["request_body_sha256"] != _digest(row["request_body"]) or row["request_sha256"] != _seal(row, "request_sha256")["request_sha256"]:
        raise ProtectedServiceError("protected_service_request_digest_mismatch", "$.request")
    return MappingProxyType(row)


def validate_response(value: Mapping[str, Any], request: Mapping[str, Any], configuration: Mapping[str, Any]) -> Mapping[str, Any]:
    config = validate_service_configuration(configuration)
    request_row = validate_request(request, config)
    row = _closed(value, RESPONSE_FIELDS, "protected_service_response_shape_invalid", "$.response")
    if row["schema_version"] != 1 or row["artifact_type"] != RESPONSE_TYPE or row["protocol_version"] != PROTOCOL_VERSION:
        raise ProtectedServiceError("protected_service_response_identity_invalid", "$.response")
    exact = {
        "service": config["service"], "service_id": config["service_id"],
        "service_build_sha256": config["service_build_sha256"], "challenge": request_row["challenge"],
        "client_session_id": request_row["client_session_id"], "principal_id": request_row["principal_id"],
        "operation": request_row["operation"], "request_sha256": request_row["request_sha256"],
        "service_start_id": config["expected_service_start_id"],
        "service_session_id": config["expected_service_session_id"],
    }
    if any(row[name] != expected for name, expected in exact.items()):
        raise ProtectedServiceError("protected_service_response_binding_mismatch", "$.response")
    _identifier(row["service_session_id"], "$.response.service_session_id")
    _identifier(row["service_start_id"], "$.response.service_start_id")
    _time(row["responded_at"], "$.response.responded_at")
    if row["state"] == "unavailable":
        _identifier(row["reason"], "$.response.reason")
        if row["record"] is not None or row["retained_anchor"] is not None:
            raise ProtectedServiceError("protected_service_unavailable_payload_invalid", "$.response")
    elif row["state"] == "available":
        if row["reason"] is not None:
            raise ProtectedServiceError("protected_service_available_reason_invalid", "$.response")
        validate_authority_record(row["record"], request_row)
        validate_retained_anchor(row["retained_anchor"], row["record"])
    else:
        raise ProtectedServiceError("protected_service_response_state_invalid", "$.response.state")
    if row["response_sha256"] != _seal(row, "response_sha256")["response_sha256"]:
        raise ProtectedServiceError("protected_service_response_digest_mismatch", "$.response.response_sha256")
    return MappingProxyType(row)


def validate_authority_record(value: Mapping[str, Any], service_request: Mapping[str, Any]) -> Mapping[str, Any]:
    row = _closed(value, RECORD_FIELDS, "protected_service_record_shape_invalid", "$.record")
    try:
        triple = validate_protected_record(row["request"], row["writer_receipt"], row["anchor_receipt"])
    except DurableStoreError as exc:
        raise ProtectedServiceError(exc.code, "$.record" + exc.location.lstrip("$")) from exc
    request = triple["request"]
    if request["operation"] != service_request["operation"] or request["producer_principal_id"] != service_request["principal_id"]:
        raise ProtectedServiceError("protected_service_record_authority_mismatch", "$.record.request")
    exact = {
        "candidate_sha256": service_request["candidate_sha256"],
        "profile_sha256": service_request["profile_sha256"],
    }
    if any(request[name] != expected for name, expected in exact.items()):
        raise ProtectedServiceError("protected_service_record_identity_mismatch", "$.record.request")
    for field in ("operation_body_sha256", "dependency_receipts_sha256", "source_digest"):
        _sha(row[field], "$.record." + field)
    if row["operation_body_sha256"] != service_request["operation_body_sha256"] or row["dependency_receipts_sha256"] != service_request["dependency_receipts_sha256"]:
        raise ProtectedServiceError("protected_service_record_query_mismatch", "$.record")
    if not isinstance(row["fact_value"], Mapping):
        raise ProtectedServiceError("protected_service_record_fact_invalid", "$.record.fact_value")
    _identifier(row["fact_key"], "$.record.fact_key")
    observed = _time(row["observed_at"], "$.record.observed_at")
    expires = _time(row["expires_at"], "$.record.expires_at")
    if expires <= observed:
        raise ProtectedServiceError("protected_service_record_expiry_invalid", "$.record")
    payload_view = {
        "fact_key": row["fact_key"], "fact_value": row["fact_value"],
        "operation_body_sha256": row["operation_body_sha256"],
        "dependency_receipts_sha256": row["dependency_receipts_sha256"],
        "observed_at": row["observed_at"], "expires_at": row["expires_at"],
        "source_digest": row["source_digest"],
    }
    if request["payload"] != payload_view:
        raise ProtectedServiceError("protected_service_record_payload_mismatch", "$.record")
    if row["record_sha256"] != _seal(row, "record_sha256")["record_sha256"]:
        raise ProtectedServiceError("protected_service_record_digest_mismatch", "$.record.record_sha256")
    return MappingProxyType(row)


def validate_retained_anchor(value: Mapping[str, Any], record: Mapping[str, Any]) -> Mapping[str, Any]:
    row = _closed(value, ANCHOR_VIEW_FIELDS, "protected_service_anchor_view_shape_invalid", "$.retained_anchor")
    triple = validate_protected_record(record["request"], record["writer_receipt"], record["anchor_receipt"])
    receipt = triple["writer_receipt"]
    anchor = triple["anchor_receipt"]
    expected = {
        "store_id": triple["request"]["store_id"], "namespace": triple["request"]["namespace"],
        "sequence": receipt["successor_sequence"], "generation": receipt["successor_generation"],
        "head_sha256": receipt["successor_head_sha256"], "anchor_sha256": receipt["anchor_sha256"],
        "writer_receipt_sha256": receipt["receipt_sha256"],
        "anchor_receipt_sha256": anchor["receipt_sha256"],
    }
    if row != expected:
        raise ProtectedServiceError("protected_service_anchor_view_mismatch", "$.retained_anchor")
    return MappingProxyType(row)


def check_service_runner(
    *, role: str, service_configurations: Mapping[str, Mapping[str, Any]],
    inherited_client_fd: int | None, inherited_anchor_fd: int | None,
    inherited_agent_fd: int | None, store_root: str | None,
    operation_source_fds: Mapping[str, int] | None = None,
) -> Mapping[str, Any]:
    """Validate public runner wiring without touching a descriptor or root."""
    services = validate_service_set(service_configurations)
    if role not in SERVICES:
        raise ProtectedServiceError("service_runner_role_invalid", "$.role")
    if inherited_client_fd is not None and (type(inherited_client_fd) is not int or inherited_client_fd < 0):
        raise ProtectedServiceError("service_runner_client_fd_invalid", "$.client_fd")
    if inherited_anchor_fd is not None and (type(inherited_anchor_fd) is not int or inherited_anchor_fd < 0):
        raise ProtectedServiceError("service_runner_anchor_fd_invalid", "$.anchor_fd")
    if inherited_agent_fd is not None and (type(inherited_agent_fd) is not int or inherited_agent_fd < 0):
        raise ProtectedServiceError("service_runner_agent_fd_invalid", "$.agent_fd")
    required_anchor = role == "protected_writer"
    required_agent = role == "opaque_tls_agent"
    required_store = role in {"protected_writer", "independent_anchor"}
    missing = []
    if inherited_client_fd is None: missing.append("client_descriptor")
    if required_anchor and inherited_anchor_fd is None: missing.append("anchor_descriptor")
    if required_agent and inherited_agent_fd is None: missing.append("agent_descriptor")
    if required_store and store_root is None: missing.append("service_store_root")
    if role == "protected_writer" and operation_source_fds is None: missing.append("operation_source_descriptors")
    if operation_source_fds is not None and (
        not isinstance(operation_source_fds, Mapping)
        or set(operation_source_fds) != set(OPERATION_OWNER_IDS)
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in operation_source_fds.values())
    ):
        raise ProtectedServiceError("service_runner_operation_source_descriptors_invalid", "$.operation_source_fds")
    return MappingProxyType({
        "schema_version": 1, "artifact_type": "supported_host_service_runner_check_v1",
        "role": role, "service_id": services[role]["service_id"],
        "state": "check_only_non_production", "missing_live_inputs": tuple(missing),
        "descriptors_opened": False, "store_opened": False, "service_executed": False,
        "production_ready": False,
    })


def _runner_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="supported_host_protected_service_v1")
    parser.add_argument("--role", choices=SERVICES, required=True)
    parser.add_argument("--service-public-json", required=True)
    parser.add_argument("--principal-map-json", default="{}")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--client-fd", type=int)
    parser.add_argument("--anchor-fd", type=int)
    parser.add_argument("--agent-fd", type=int)
    parser.add_argument("--store-root")
    parser.add_argument("--root-fd", type=int)
    parser.add_argument("--operation-source-fds-json")
    parser.add_argument("--operation-source-service-json")
    parser.add_argument("--joint-authority-json")
    parser.add_argument("--expected-client-uid", type=int)
    parser.add_argument("--expected-client-gid", type=int)
    parser.add_argument("--responded-at")
    parser.add_argument("--session-expires-at")
    parser.add_argument("--agent-public-json")
    return parser


def service_runner_main(argv: list[str] | None = None) -> int:
    """Run one inherited-descriptor service exchange or a no-I/O preflight."""
    try:
        args = _runner_parser().parse_args(argv)
        if args.check_only and args.execute_live:
            raise ProtectedServiceError("service_runner_mode_conflict", "$.runner")
        services = json.loads(args.service_public_json)
        operation_source_fds = (
            None if args.operation_source_fds_json is None
            else json.loads(args.operation_source_fds_json)
        )
        checked = check_service_runner(
            role=args.role, service_configurations=services,
            inherited_client_fd=args.client_fd, inherited_anchor_fd=args.anchor_fd,
            inherited_agent_fd=args.agent_fd, store_root=args.store_root,
            operation_source_fds=operation_source_fds,
        )
        if args.check_only:
            print(json.dumps(_plain(checked), sort_keys=True, separators=(",", ":")))
            return 0
        if not args.execute_live:
            raise ProtectedServiceError("service_runner_external_action_required", "$.execute_live")
        if checked["missing_live_inputs"] or args.expected_client_uid is None or args.expected_client_gid is None:
            raise ProtectedServiceError("service_runner_live_inputs_missing", "$.runner")
        configurations = validate_service_set(services)
        if args.joint_authority_json is None or args.root_fd is None:
            raise ProtectedServiceError("service_runner_joint_authority_missing", "$.runner")
        joint_authority = validate_joint_service_authority(json.loads(args.joint_authority_json))
        if joint_authority["execution_scope"] != "live_external_candidate":
            raise ProtectedServiceError("service_runner_joint_authority_not_live", "$.runner")
        expected_selected = service_configuration_from_authority(joint_authority, args.role)
        if any(configurations[args.role][field] != expected_selected[field] for field in CONFIG_FIELDS - {"max_frame_bytes"}):
            raise ProtectedServiceError("service_runner_joint_authority_mismatch", "$.runner")
        validate_current_role_identity(
            args.role, configurations,
            root=Path(args.store_root) if args.store_root is not None else None,
        )
        validate_selected_joint_role(
            args.role, joint_authority, inherited_root_fd=args.root_fd,
            now=args.responded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        client_socket = socket.socket(fileno=args.client_fd)
        handler_type = {
            "protected_writer": ProtectedWriterServiceHandler,
            "independent_anchor": IndependentAnchorServiceHandler,
            "opaque_tls_agent": OpaqueTlsAgentServiceHandler,
        }[args.role]
        principal_map = json.loads(args.principal_map_json)
        handler = handler_type(
            client_socket, configurations[args.role], expected_client_uid=args.expected_client_uid,
            expected_client_gid=args.expected_client_gid, principal_map=principal_map,
        )
        if args.role == "protected_writer":
            if args.session_expires_at is None:
                raise ProtectedServiceError("service_runner_session_expiry_missing", "$.runner")
            writer_config = configurations["protected_writer"]
            identity = {
                "service_id": writer_config["service_id"], "service_build_sha256": writer_config["service_build_sha256"],
                "service_uid": writer_config["expected_uid"], "service_gid": writer_config["expected_gid"],
                "service_start_id": writer_config["expected_service_start_id"],
                "service_session_id": writer_config["expected_service_session_id"],
                "session_expires_at": args.session_expires_at,
            }
            writer = ServiceOwnedWriterStore(Path(args.store_root), identity)
            if args.operation_source_service_json is None:
                raise ProtectedServiceError("service_runner_operation_source_services_missing", "$.runner")
            source_services = validate_source_service_set(json.loads(args.operation_source_service_json))
            protected_uids = {row["expected_uid"] for row in configurations.values()}; protected_gids = {row["expected_gid"] for row in configurations.values()}
            if any(row["expected_uid"] in protected_uids or row["expected_gid"] in protected_gids for row in source_services.values()):
                raise ProtectedServiceError("service_runner_operation_source_account_collision", "$.runner")
            anchor_socket = socket.socket(fileno=args.anchor_fd)
            anchor_client = AnchorServiceClient(
                PreconnectedProtectedServiceChannel(anchor_socket, configurations["independent_anchor"]), configurations,
            )
            sources = {}
            for owner_id in OPERATION_OWNER_IDS:
                source_config = source_services[owner_id]
                joint_role = joint_authority["roles"][owner_id]
                if any((
                    source_config["source_id"] != joint_role["service_id"],
                    source_config["source_build_sha256"] != joint_role["service_build_sha256"],
                    source_config["expected_uid"] != joint_role["expected_uid"],
                    source_config["expected_gid"] != joint_role["expected_gid"],
                    source_config["service_start_id"] != joint_role["expected_service_start_id"],
                    source_config["service_session_id"] != joint_role["expected_service_session_id"],
                )):
                    raise ProtectedServiceError("service_runner_operation_source_joint_mismatch", "$.runner")
                source_socket = socket.socket(fileno=operation_source_fds[owner_id])
                sources[owner_id] = PreconnectedOperationSourceClient(
                    source_socket, source_config, joint_authority=joint_authority,
                )
            owner = ServiceOwnedProtectedWriterStateOwner(writer, anchor_client, sources)
            result = FramedProtectedServiceDispatcher(handler, owner).serve_one(responded_at=args.responded_at)
        elif args.role == "independent_anchor":
            owner = ServiceOwnedIndependentAnchorStateOwner(ServiceOwnedAnchorStore(Path(args.store_root)))
            result = FramedProtectedServiceDispatcher(handler, owner).serve_one(responded_at=args.responded_at)
        else:
            if args.agent_public_json is None:
                raise ProtectedServiceError("service_runner_agent_identity_missing", "$.runner")
            agent_public = json.loads(args.agent_public_json)
            agent_socket = socket.socket(fileno=args.agent_fd)
            agent = PreconnectedOpaqueCredentialAgent(
                agent_socket, expected_uid=agent_public["expected_uid"], expected_gid=agent_public["expected_gid"],
                identity=agent_public["identity"],
            )
            result = FramedOpaqueTlsServiceDispatcher(
                handler, ServiceOwnedOpaqueTlsAgentStateOwner(agent),
            ).serve_one()
        print(json.dumps(_plain(result.as_mapping() if isinstance(result, ProtectedServicePending) else result), sort_keys=True, separators=(",", ":")))
        return 0 if not isinstance(result, ProtectedServicePending) else 3
    except BaseException as exc:
        code = getattr(exc, "code", "service_runner_invalid")
        print(json.dumps({"status": "failed", "error": code}, sort_keys=True, separators=(",", ":")))
        return 2


__all__ = [
    "AnchorServiceClient", "ChannelWitness", "COMMAND_RESPONSE_FIELDS", "COMMAND_RESPONSE_TYPE", "CONFIG_FIELDS", "FIXED_CHANNEL_POLICIES", "JOINT_AUTHORITY_FIELDS", "JOINT_AUTHORITY_TYPE", "JOINT_ROLES", "JOINT_SOURCE_REQUEST_TYPE", "JOINT_SOURCE_RESPONSE_TYPE", "JointOperationSourceExchange", "JointOperationSourceServiceHandler", "JointRawObservationServiceHandler", "MAX_FRAME_BYTES", "OPERATION_SOURCE_OWNER_RUNNERS", "PENDING_TYPE", "PROTOCOL_VERSION", "ProtectedServiceError", "RAW_OBSERVATION_ACK_FIELDS", "RAW_OBSERVATION_ACK_TYPE", "RAW_OBSERVATION_REQUEST_FIELDS",
    "ProtectedServicePending", "PreconnectedProtectedServiceChannel", "PreconnectedProtectedServiceHandler",
    "PreconnectedRunnerInstallerEvidence", "OsBoundCurrentRunnerV26AdmissionSource",
    "PreconnectedDeploymentAdmissionV2", "OsBoundDeploymentAdmissionV2Source",
    "ProtectedWriterServiceHandler", "IndependentAnchorServiceHandler", "OpaqueTlsAgentServiceHandler",
    "SourceLocalIndependentAnchorStateOwner", "SourceLocalOpaqueTlsAgentStateOwner",
    "SourceLocalProtectedWriterStateOwner", "REQUEST_FIELDS", "REQUEST_TYPE",
    "RESPONSE_FIELDS", "RESPONSE_TYPE", "SERVICES", "FramedOpaqueTlsServiceDispatcher", "FramedProtectedServiceDispatcher",
    "OsBoundOpaqueTlsTransport", "OsBoundProtectedFactSource", "ValidatedProtectedFact",
    "PreconnectedOpaqueCredentialAgent", "ServiceOwnedIndependentAnchorStateOwner",
    "ServiceOwnedOpaqueTlsAgentStateOwner", "ServiceOwnedProtectedWriterStateOwner",
    "check_joint_service_authority", "check_service_runner", "cross_owner_service_identity", "prepare_command_response", "prepare_request", "prepare_tls_response", "serve_operation_source_owner_once", "service_configuration_from_authority", "service_runner_main", "validate_command_response", "validate_tls_request",
    "serve_catalog_selection_to_responses_selection_artifact_once", "import_catalog_selection_from_catalog_selection_artifact_once",
    "serve_native_supervision_to_responses_context_artifact_once", "import_native_supervision_for_responses_context_artifact_once",
    "serve_responses_context_to_effect_authority_artifact_once", "import_responses_context_for_effect_authority_artifact_once",
    "serve_effect_authority_to_registered_action_artifact_once", "import_effect_authority_for_registered_action_artifact_once",
    "serve_registered_action_to_responses_bridge_artifact_once", "import_registered_action_for_responses_bridge_artifact_once",
    "serve_responses_projection_to_recovery_artifact_once", "import_responses_projection_for_recovery_artifact_once",
    "serve_native_supervision_to_recovery_artifact_once", "import_native_supervision_for_recovery_artifact_once",
    "serve_effect_authority_to_recovery_artifact_once", "import_effect_authority_for_recovery_artifact_once",
    "decode_framed_bytes",
    "validate_current_runner_v26_installer_evidence", "validate_authority_record", "validate_request", "validate_response", "validate_retained_anchor",
    "validate_current_role_identity", "validate_joint_service_authority", "validate_selected_joint_role", "validate_service_configuration", "validate_service_set",
] + [runner.__name__ for runner in OPERATION_SOURCE_OWNER_RUNNERS.values()]


if __name__ == "__main__":
    sys.exit(service_runner_main())
