#!/usr/bin/env python3
"""Pinned TLS-over-AF_UNIX package host capability adapter.

The public production singleton has no configurable endpoint or trust input.
Only ``_for_test`` accepts an alternate package root, and only roots whose
closed trust document is explicitly marked test-only.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any, Mapping


REQUEST_TYPE = "package_host_capability_request_v1"
RESPONSE_TYPE = "package_host_capability_response_v1"
TRUST_TYPE = "package_host_trust_v1"
CAPABILITIES_TYPE = "package_host_capabilities_v1"
PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_CLOCK_SKEW_SECONDS = 5
MAX_RESPONSE_LIFETIME_SECONDS = 60
SEMANTIC_OPERATIONS = frozenset({
    "verify_effect_authority",
    "invoke_registered_action",
    "issue_responses_context",
    "verify_responses_bridge",
    "read_capability_admission",
    "commit_or_verify_record",
    "seal_or_verify_projection",
    "open_operator_listener",
    "read_operator_supervision",
    "read_operator_preset_bundle",
    "read_operator_selection_head",
    "read_operator_selection_mutation",
    "commit_operator_selection",
    "read_operator_recovery_lease_grant",
})
TRUST_FIELDS = {
    "schema_version", "artifact_type", "configured", "test_only", "host_id",
    "socket_path", "expected_dns_san", "ca_pem_sha256", "tls_minimum",
    "protocol_version", "config_sha256",
}
CAPABILITY_FIELDS = {
    "schema_version", "artifact_type", "configured", "action_registrations",
    "capability_ids", "operation_mapping", "config_sha256",
}
IDENTITY_FIELDS = {"workspace_id", "source_sha256", "candidate_sha256"}
REQUEST_FIELDS = {
    "schema_version", "artifact_type", "protocol_version", "session_nonce",
    "request_nonce", "operation", "identity", "body", "issued_at",
    "expires_at", "request_sha256",
}
RESPONSE_FIELDS = {
    "schema_version", "artifact_type", "protocol_version", "session_nonce",
    "request_nonce", "operation", "identity", "body", "issued_at",
    "expires_at", "request_sha256", "response_sha256",
}
LISTENER_ADMISSION_TYPE = "standalone_operator_listener_admission_receipt_v1"
LISTENER_ADMISSION_FIELDS = {
    "schema_version", "artifact_type", "admission_id", "workspace_id",
    "source_sha256", "candidate_sha256", "service_instance_id",
    "route_table_sha256", "local_only", "host_binds_http", "issued_at",
    "expires_at", "seal",
}
SUPERVISION_TYPE = "standalone_operator_supervision_receipt_v1"
SUPERVISION_FIELDS = {
    "schema_version", "artifact_type", "receipt_id", "workspace_id", "source_sha256",
    "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version",
    "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation",
    "selection_sha256", "native", "topology", "continuity", "recovery",
    "snapshot_sequence", "previous_snapshot_sha256", "issued_at", "expires_at",
    "snapshot_sha256", "receipt_sha256", "seal",
}
SELECTION_HEAD_TYPE = "standalone_operator_selection_head_receipt_v1"
CATALOG_TYPE = "standalone_operator_configured_preset_bundle_receipt_v1"
CATALOG_FIELDS = {"schema_version", "artifact_type", "catalog_receipt_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "preset_policy_sha256", "adapter_registry_sha256", "capability_profile_sha256", "catalog_generation", "previous_catalog_sha256", "bundle", "bundle_sha256", "configured_bindings", "issued_at", "expires_at", "receipt_sha256", "seal"}
CATALOG_BINDING_FIELDS = {"preset_id", "adapter_type", "route_name", "adapter_binding_sha256", "route_identity_sha256", "qualification_certificate_sha256", "action_id", "tool_id", "transport"}
SELECTION_HEAD_FIELDS = {"schema_version", "artifact_type", "head_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "selection_state_version", "selection", "selection_sha256", "catalog_receipt_sha256", "bundle_sha256", "bundle_generation", "issued_at", "expires_at", "receipt_sha256", "seal"}
SELECTION_MUTATION_TYPE = "standalone_operator_selection_mutation_receipt_v1"
SELECTION_MUTATION_FIELDS = {"schema_version", "artifact_type", "mutation_id", "submission_sha256", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation", "selection_state_version_before", "selection_state_version_after", "previous_selection_sha256", "selection", "selection_sha256", "catalog_receipt_sha256", "bundle_sha256", "bundle_generation", "issued_at", "expires_at", "receipt_sha256", "seal"}
RECOVERY_GRANT_TYPE = "effect_kernel_recovery_lease_grant_v1"
RECOVERY_GRANT_FIELDS = {"schema_version", "artifact_type", "grant_id", "issuer_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "selection_sha256", "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "no_successor", "fresh_lease", "expected_cas", "reserved_authority_id", "issued_at", "expires_at", "grant_sha256", "seal"}
BODY_FIELDS = MappingProxyType({
    "verify_effect_authority": frozenset({"authority", "context"}),
    "invoke_registered_action": frozenset({"action_id", "operation", "effect_request"}),
    "issue_responses_context": frozenset({"mode", "responses_request", "control_action", "control_payload", "record_sha256", "service_instance_id", "recovery_grant_id", "recovery_grant_sha256"}),
    "verify_responses_bridge": frozenset({"mode", "responses_request", "effect_request", "effect_receipt", "bridge_receipt", "context"}),
    "read_capability_admission": frozenset({"service_instance_id", "now"}),
    "commit_or_verify_record": frozenset({"mode", "record", "context", "seal"}),
    "seal_or_verify_projection": frozenset({"mode", "context", "seal"}),
    "open_operator_listener": frozenset({"service_instance_id", "routes"}),
    "read_operator_supervision": frozenset({"admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation", "selection_sha256", "now"}),
    "read_operator_preset_bundle": frozenset({"admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "selector", "bundle_sha256", "now"}),
    "read_operator_selection_head": frozenset({"admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "now"}),
    "read_operator_selection_mutation": frozenset({"admission_id", "service_instance_id", "submission_id", "submission_sha256", "now"}),
    "commit_operator_selection": frozenset({"admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation", "selection_state_version", "current_selection_sha256", "preset_id", "expected_generation", "submission_id", "submission_sha256", "now"}),
    "read_operator_recovery_lease_grant": frozenset({"admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "selection_sha256", "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "expected_cas", "now"}),
})
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class HostCapabilityError(RuntimeError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HostCapabilityError("package_host_protocol_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _closed(value: Any, fields: set[str] | frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise HostCapabilityError(code, path)
    return copy.deepcopy(dict(value))


def _identifier(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise HostCapabilityError(code, path)
    return value


def _sha(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise HostCapabilityError(code, path)
    return value


def _timestamp(value: Any, code: str, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HostCapabilityError(code, path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HostCapabilityError(code, path) from exc
    return parsed.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostCapabilityError("production_capability_unavailable", str(path.name)) from exc


_CONSTRUCTION_TOKEN = object()


class _PackageHostCapabilityAdapter:
    """One immutable package-root adapter with operation-specific methods."""

    def __init__(self, token: object, *, test_package_root: Path | None = None) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise HostCapabilityError("production_capability_unavailable", "$.package_root")
        self._package_root = _PACKAGE_ROOT if test_package_root is None else test_package_root.resolve()
        self._test_only = test_package_root is not None
        self._session_nonce = secrets.token_hex(32)
        self._seen_response_digests: set[str] = set()
        self._trust: dict[str, Any] | None = None
        self._capabilities: dict[str, Any] | None = None
        self._last_supervision: dict[tuple[str, str], tuple[int, str]] = {}
        self._last_catalog: dict[tuple[str, str], tuple[int, str]] = {}

    def _verify_release_pin(self, relative: str, raw: bytes) -> None:
        manifest = _load_json(self._package_root / ".codex-plugin" / "release-manifest.json")
        files = manifest.get("files") if isinstance(manifest, Mapping) else None
        if not isinstance(files, list):
            raise HostCapabilityError("package_data_not_pinned", relative)
        row = next((item for item in files if isinstance(item, Mapping) and item.get("path") == relative), None)
        if row is None or row.get("sha256") != hashlib.sha256(raw).hexdigest() or row.get("size") != len(raw):
            raise HostCapabilityError("package_data_not_pinned", relative)

    def _load(self) -> tuple[dict[str, Any], dict[str, Any], Path]:
        if self._trust is not None and self._capabilities is not None:
            return self._trust, self._capabilities, self._package_root / "assets/runtime/package-host-ca.pem"
        trust_path = self._package_root / "assets/runtime/package-host-trust-v1.json"
        caps_path = self._package_root / "assets/runtime/package-host-capabilities-v1.json"
        ca_path = self._package_root / "assets/runtime/package-host-ca.pem"
        try:
            trust_raw, caps_raw, ca_raw = trust_path.read_bytes(), caps_path.read_bytes(), ca_path.read_bytes()
        except OSError as exc:
            raise HostCapabilityError("production_capability_unavailable", "$.package_data") from exc
        if not self._test_only:
            self._verify_release_pin("assets/runtime/package-host-trust-v1.json", trust_raw)
            self._verify_release_pin("assets/runtime/package-host-ca.pem", ca_raw)
            self._verify_release_pin("assets/runtime/package-host-capabilities-v1.json", caps_raw)
        trust = _closed(_load_json(trust_path), TRUST_FIELDS, "package_host_trust_invalid", "$.trust")
        caps = _closed(_load_json(caps_path), CAPABILITY_FIELDS, "package_host_capabilities_invalid", "$.capabilities")
        if trust["schema_version"] != 1 or trust["artifact_type"] != TRUST_TYPE or caps["schema_version"] != 1 or caps["artifact_type"] != CAPABILITIES_TYPE:
            raise HostCapabilityError("production_capability_unavailable", "$.package_data")
        if trust["test_only"] is not self._test_only:
            raise HostCapabilityError("test_package_root_required" if self._test_only else "production_capability_unavailable")
        if trust["config_sha256"] != digest({key: item for key, item in trust.items() if key != "config_sha256"}):
            raise HostCapabilityError("package_host_trust_invalid", "$.trust.config_sha256")
        if caps["config_sha256"] != digest({key: item for key, item in caps.items() if key != "config_sha256"}):
            raise HostCapabilityError("package_host_capabilities_invalid", "$.capabilities.config_sha256")
        if trust["configured"] is not True or caps["configured"] is not True:
            raise HostCapabilityError("production_capability_unavailable", "$.package_data.configured")
        _identifier(trust["host_id"], "package_host_trust_invalid", "$.trust.host_id")
        if not isinstance(trust["socket_path"], str) or not trust["socket_path"].startswith("/") or not isinstance(trust["expected_dns_san"], str) or not trust["expected_dns_san"]:
            raise HostCapabilityError("package_host_trust_invalid", "$.trust")
        if trust["tls_minimum"] != "TLSv1.3" or trust["protocol_version"] != PROTOCOL_VERSION or trust["ca_pem_sha256"] != bytes_digest(ca_raw):
            raise HostCapabilityError("package_host_trust_invalid", "$.trust")
        if not isinstance(caps["operation_mapping"], Mapping) or set(caps["operation_mapping"]) != SEMANTIC_OPERATIONS or any(key != value for key, value in caps["operation_mapping"].items()):
            raise HostCapabilityError("package_host_capabilities_invalid", "$.capabilities.operation_mapping")
        if not isinstance(caps["capability_ids"], list) or len(caps["capability_ids"]) != len(set(caps["capability_ids"])) or any(not isinstance(item, str) for item in caps["capability_ids"]):
            raise HostCapabilityError("package_host_capabilities_invalid", "$.capabilities.capability_ids")
        if not isinstance(caps["action_registrations"], list):
            raise HostCapabilityError("package_host_capabilities_invalid", "$.capabilities.action_registrations")
        for index, value in enumerate(caps["action_registrations"]):
            row = _closed(value, {"action_id", "tool_id", "transport", "parameter_fields"}, "package_host_capabilities_invalid", f"$.capabilities.action_registrations[{index}]")
            for field in ("action_id", "tool_id", "transport"):
                _identifier(row[field], "package_host_capabilities_invalid", f"$.capabilities.action_registrations[{index}].{field}")
            if not isinstance(row["parameter_fields"], list) or len(row["parameter_fields"]) != len(set(row["parameter_fields"])) or any(not isinstance(item, str) for item in row["parameter_fields"]):
                raise HostCapabilityError("package_host_capabilities_invalid", f"$.capabilities.action_registrations[{index}].parameter_fields")
        self._trust, self._capabilities = trust, caps
        return trust, caps, ca_path

    def require_configured(self) -> None:
        self._load()

    def capability_ids(self) -> frozenset[str]:
        _, caps, _ = self._load()
        return frozenset(caps["capability_ids"])

    def action_registrations(self) -> tuple[dict[str, Any], ...]:
        _, caps, _ = self._load()
        return tuple(copy.deepcopy(caps["action_registrations"]))

    def _read_exact(self, connection: ssl.SSLSocket, size: int) -> bytes:
        chunks: list[bytes] = []
        while size:
            chunk = connection.recv(size)
            if not chunk:
                raise HostCapabilityError("production_capability_unavailable", "$.transport")
            chunks.append(chunk)
            size -= len(chunk)
        return b"".join(chunks)

    def _request(self, operation: str, identity_value: Mapping[str, Any], body_value: Mapping[str, Any]) -> Any:
        if operation not in SEMANTIC_OPERATIONS:
            raise HostCapabilityError("package_host_operation_denied", "$.operation")
        identity = _closed(identity_value, IDENTITY_FIELDS, "package_host_identity_invalid", "$.identity")
        _identifier(identity["workspace_id"], "package_host_identity_invalid", "$.identity.workspace_id")
        for field in ("source_sha256", "candidate_sha256"):
            _sha(identity[field], "package_host_identity_invalid", f"$.identity.{field}")
        body = _closed(body_value, BODY_FIELDS[operation], "package_host_body_invalid", "$.body")
        trust, _, ca_path = self._load()
        now = _utc_now()
        request = {
            "schema_version": 1, "artifact_type": REQUEST_TYPE,
            "protocol_version": PROTOCOL_VERSION, "session_nonce": self._session_nonce,
            "request_nonce": secrets.token_hex(32), "operation": operation,
            "identity": identity, "body": body, "issued_at": _format_time(now),
            "expires_at": _format_time(now + timedelta(seconds=MAX_RESPONSE_LIFETIME_SECONDS)),
            "request_sha256": "",
        }
        request["request_sha256"] = digest({key: item for key, item in request.items() if key != "request_sha256"})
        raw = canonical_json(request)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(ca_path))
        plain = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        plain.settimeout(2.0)
        try:
            plain.connect(trust["socket_path"])
            connection = context.wrap_socket(plain, server_hostname=trust["expected_dns_san"])
            try:
                connection.sendall(struct.pack("!I", len(raw)) + raw)
                size = struct.unpack("!I", self._read_exact(connection, 4))[0]
                if size < 2 or size > MAX_FRAME_BYTES:
                    raise HostCapabilityError("package_host_protocol_invalid", "$.response")
                response = json.loads(self._read_exact(connection, size).decode("utf-8"))
            finally:
                connection.close()
        except (OSError, ssl.SSLError, UnicodeError, json.JSONDecodeError, struct.error) as exc:
            plain.close()
            raise HostCapabilityError("production_capability_unavailable", "$.transport") from exc
        row = _closed(response, RESPONSE_FIELDS, "package_host_protocol_invalid", "$.response")
        response_sha = row["response_sha256"]
        if response_sha != digest({key: item for key, item in row.items() if key != "response_sha256"}) or response_sha in self._seen_response_digests:
            raise HostCapabilityError("package_host_response_replay", "$.response")
        if any(row[field] != request[field] for field in ("protocol_version", "session_nonce", "request_nonce", "operation", "identity", "request_sha256")) or row["schema_version"] != 1 or row["artifact_type"] != RESPONSE_TYPE:
            raise HostCapabilityError("package_host_response_mismatch", "$.response")
        issued = _timestamp(row["issued_at"], "package_host_response_stale", "$.response.issued_at")
        expires = _timestamp(row["expires_at"], "package_host_response_stale", "$.response.expires_at")
        observed = _utc_now()
        if issued > observed or (observed - issued).total_seconds() > MAX_CLOCK_SKEW_SECONDS or expires <= observed or (expires - issued).total_seconds() > MAX_RESPONSE_LIFETIME_SECONDS:
            raise HostCapabilityError("package_host_response_stale", "$.response")
        self._seen_response_digests.add(response_sha)
        return copy.deepcopy(row["body"])

    def verify_effect_authority(self, authority: dict[str, Any], context: dict[str, Any]) -> bool:
        identity = {"workspace_id": context["workspace_id"], "source_sha256": context["source_sha256"], "candidate_sha256": context["candidate_sha256"]}
        return self._request("verify_effect_authority", identity, {"authority": authority, "context": context}) == {"authorized": True}

    def invoke_registered_action(self, action_id: str, operation: str, effect_request: dict[str, Any]) -> dict[str, Any]:
        identity = {"workspace_id": effect_request["workspace_id"], "source_sha256": effect_request["source_bundle"]["source_sha256"], "candidate_sha256": effect_request["source_bundle"]["candidate_sha256"]}
        return self._request("invoke_registered_action", identity, {"action_id": action_id, "operation": operation, "effect_request": effect_request})

    def issue_responses_context(self, responses_request: dict[str, Any] | None, identity: dict[str, Any], *, control_action: str | None = None, control_payload: dict[str, Any] | None = None, record_sha256: str | None = None, service_instance_id: str | None = None, recovery_grant_id: str | None = None, recovery_grant_sha256: str | None = None) -> dict[str, Any]:
        mode = "request" if responses_request is not None else "control"
        if control_action != "recover" and (recovery_grant_id is not None or recovery_grant_sha256 is not None):
            raise HostCapabilityError("recovery_authority_unavailable", "$.context")
        if control_action == "recover":
            _identifier(recovery_grant_id, "recovery_authority_unavailable", "$.context.recovery_grant_id")
            _sha(recovery_grant_sha256, "recovery_authority_unavailable", "$.context.recovery_grant_sha256")
        return self._request("issue_responses_context", identity, {"mode": mode, "responses_request": responses_request, "control_action": control_action, "control_payload": control_payload, "record_sha256": record_sha256, "service_instance_id": service_instance_id, "recovery_grant_id": recovery_grant_id, "recovery_grant_sha256": recovery_grant_sha256})

    def issue_responses_bridge(self, responses_request: dict[str, Any], effect_request: dict[str, Any], effect_receipt: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
        return self._request("verify_responses_bridge", identity, {"mode": "issue", "responses_request": responses_request, "effect_request": effect_request, "effect_receipt": effect_receipt, "bridge_receipt": None, "context": None})

    def verify_responses_bridge(self, bridge_receipt: dict[str, Any], context: dict[str, Any], identity: dict[str, Any]) -> bool:
        return self._request("verify_responses_bridge", identity, {"mode": "verify", "responses_request": None, "effect_request": None, "effect_receipt": None, "bridge_receipt": bridge_receipt, "context": context}) == {"authorized": True}

    def read_capability_admission(self, identity: dict[str, Any], service_instance_id: str, now: str) -> dict[str, Any]:
        return self._request("read_capability_admission", identity, {"service_instance_id": service_instance_id, "now": now})

    def commit_or_verify_record(self, identity: dict[str, Any], *, mode: str, record: dict[str, Any] | None, context: dict[str, Any], seal: str | None) -> Any:
        return self._request("commit_or_verify_record", identity, {"mode": mode, "record": record, "context": context, "seal": seal})

    def seal_or_verify_projection(self, identity: dict[str, Any], *, mode: str, context: dict[str, Any], seal: str | None) -> Any:
        return self._request("seal_or_verify_projection", identity, {"mode": mode, "context": context, "seal": seal})

    def read_projection_baseline(self, identity: dict[str, Any], admission_id: str, now: str) -> dict[str, Any]:
        return self.seal_or_verify_projection(
            identity, mode="baseline",
            context={"admission_id": admission_id, "now": now}, seal=None,
        )

    def open_operator_listener(self, identity: dict[str, Any], service_instance_id: str, routes: list[dict[str, str]]) -> dict[str, Any]:
        value = self._request("open_operator_listener", identity, {"service_instance_id": service_instance_id, "routes": routes})
        row = _closed(value, LISTENER_ADMISSION_FIELDS, "listener_admission_invalid", "$.listener_admission")
        if row["schema_version"] != 1 or row["artifact_type"] != LISTENER_ADMISSION_TYPE:
            raise HostCapabilityError("listener_admission_invalid", "$.listener_admission")
        _identifier(row["admission_id"], "listener_admission_invalid", "$.listener_admission.admission_id")
        _identifier(row["service_instance_id"], "listener_admission_invalid", "$.listener_admission.service_instance_id")
        for field in ("source_sha256", "candidate_sha256", "route_table_sha256", "seal"):
            _sha(row[field], "listener_admission_invalid", f"$.listener_admission.{field}")
        if (
            any(row[field] != identity[field] for field in IDENTITY_FIELDS)
            or row["service_instance_id"] != service_instance_id
            or row["route_table_sha256"] != digest(routes)
            or row["local_only"] is not True
            or row["host_binds_http"] is not False
        ):
            raise HostCapabilityError("listener_admission_mismatch", "$.listener_admission")
        issued = _timestamp(row["issued_at"], "listener_admission_stale", "$.listener_admission.issued_at")
        expires = _timestamp(row["expires_at"], "listener_admission_stale", "$.listener_admission.expires_at")
        now = _utc_now()
        if issued > now or expires <= now or (expires - issued).total_seconds() > MAX_RESPONSE_LIFETIME_SECONDS:
            raise HostCapabilityError("listener_admission_stale", "$.listener_admission")
        return row

    def read_operator_supervision(self, identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
        result = _closed(self._request("read_operator_supervision", identity, request_body), {"state", "reason", "receipt"}, "supervision_response_invalid", "$.supervision")
        chain_key = (identity["workspace_id"], request_body["service_instance_id"])
        if result["state"] == "unavailable":
            if not isinstance(result["reason"], str) or not result["reason"] or len(result["reason"]) > 256 or result["receipt"] is not None:
                raise HostCapabilityError("supervision_response_invalid", "$.supervision")
            self._last_supervision.pop(chain_key, None)
            return result
        if result["state"] != "verified" or result["reason"] is not None:
            raise HostCapabilityError("supervision_response_invalid", "$.supervision")
        row = _closed(result["receipt"], SUPERVISION_FIELDS, "supervision_receipt_invalid", "$.supervision.receipt")
        if row["schema_version"] != 1 or row["artifact_type"] != SUPERVISION_TYPE:
            raise HostCapabilityError("supervision_receipt_invalid", "$.supervision.receipt")
        expected = {"workspace_id": identity["workspace_id"], "source_sha256": identity["source_sha256"], "candidate_sha256": identity["candidate_sha256"], **{key: request_body[key] for key in ("service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation", "selection_sha256")}}
        if any(row[key] != value for key, value in expected.items()):
            raise HostCapabilityError("supervision_receipt_mismatch", "$.supervision.receipt")
        for field in ("receipt_id", "service_instance_id", "admission_id", "runtime_thread_id"):
            _identifier(row[field], "supervision_receipt_invalid", f"$.supervision.receipt.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "selection_sha256", "snapshot_sha256", "receipt_sha256", "seal"):
            _sha(row[field], "supervision_receipt_invalid", f"$.supervision.receipt.{field}")
        for field, minimum in (("binding_state_version", 0), ("runtime_thread_generation", 1), ("snapshot_sequence", 1)):
            if type(row[field]) is not int or row[field] < minimum:
                raise HostCapabilityError("supervision_receipt_invalid", f"$.supervision.receipt.{field}")
        native = _closed(row["native"], {"live_host", "native_available", "corroborated", "native_proved", "identity_receipt_sha256", "chain_tip_sha256", "event_sequence", "locator_kind", "parent_locator", "supervisor_locator", "model", "reasoning_effort", "route"}, "supervision_native_invalid", "$.supervision.receipt.native")
        if any(native[key] is not True for key in ("live_host", "native_available", "corroborated", "native_proved")) or native["locator_kind"] != "desktop_thread_id" or any(native[key] != "unknown" for key in ("model", "reasoning_effort", "route")):
            raise HostCapabilityError("supervision_native_unproved", "$.supervision.receipt.native")
        for field in ("identity_receipt_sha256", "chain_tip_sha256"):
            _sha(native[field], "supervision_native_invalid", f"$.supervision.receipt.native.{field}")
        for field in ("parent_locator", "supervisor_locator"):
            _identifier(native[field], "supervision_native_invalid", f"$.supervision.receipt.native.{field}")
        if type(native["event_sequence"]) is not int or native["event_sequence"] < 1:
            raise HostCapabilityError("supervision_native_invalid", "$.supervision.receipt.native.event_sequence")
        topology = _closed(row["topology"], {"inventory_event_sha256", "inventory_cursor", "presentation", "parent_count", "active_supervisor_count", "supervisor_checkpoint_sha256", "supervisor_checkpoint_count", "top_level_worker_count", "internal_worker_count", "activity_cursor"}, "supervision_topology_invalid", "$.supervision.receipt.topology")
        if topology["presentation"] != "approved_containment" or topology["parent_count"] != 1 or topology["active_supervisor_count"] != 1 or topology["top_level_worker_count"] != 0:
            raise HostCapabilityError("supervision_topology_invalid", "$.supervision.receipt.topology")
        for field in ("inventory_event_sha256", "supervisor_checkpoint_sha256"):
            _sha(topology[field], "supervision_topology_invalid", f"$.supervision.receipt.topology.{field}")
        for field in ("inventory_cursor", "activity_cursor"):
            _identifier(topology[field], "supervision_topology_invalid", f"$.supervision.receipt.topology.{field}")
        for field in ("supervisor_checkpoint_count", "internal_worker_count"):
            if type(topology[field]) is not int or not 0 <= topology[field] <= 10000:
                raise HostCapabilityError("supervision_topology_invalid", f"$.supervision.receipt.topology.{field}")
        continuity = _closed(row["continuity"], {"host_read_event_sha256", "read_cursor", "subscription_state", "current_cursor_sequence"}, "supervision_continuity_invalid", "$.supervision.receipt.continuity")
        _sha(continuity["host_read_event_sha256"], "supervision_continuity_invalid", "$.supervision.receipt.continuity.host_read_event_sha256")
        _identifier(continuity["read_cursor"], "supervision_continuity_invalid", "$.supervision.receipt.continuity.read_cursor")
        if continuity["subscription_state"] != "current" or type(continuity["current_cursor_sequence"]) is not int or continuity["current_cursor_sequence"] < 1:
            raise HostCapabilityError("supervision_continuity_invalid", "$.supervision.receipt.continuity")
        recovery = _closed(row["recovery"], {"recovery_epoch", "reconciliation_receipt_sha256", "status"}, "supervision_recovery_invalid", "$.supervision.receipt.recovery")
        _sha(recovery["reconciliation_receipt_sha256"], "supervision_recovery_invalid", "$.supervision.receipt.recovery.reconciliation_receipt_sha256")
        if type(recovery["recovery_epoch"]) is not int or recovery["recovery_epoch"] < 0 or recovery["status"] not in {"current", "reconciled"}:
            raise HostCapabilityError("supervision_recovery_invalid", "$.supervision.receipt.recovery")
        issued, expires, now = (_timestamp(row["issued_at"], "supervision_receipt_stale", "$.issued_at"), _timestamp(row["expires_at"], "supervision_receipt_stale", "$.expires_at"), _timestamp(request_body["now"], "supervision_receipt_stale", "$.now"))
        if issued > now or expires <= now:
            raise HostCapabilityError("supervision_receipt_stale", "$.supervision.receipt")
        semantic = {key: value for key, value in row.items() if key not in {"issued_at", "expires_at", "snapshot_sha256", "receipt_sha256", "seal"}}
        if row["snapshot_sha256"] != digest(semantic) or row["receipt_sha256"] != digest({key: value for key, value in row.items() if key not in {"receipt_sha256", "seal"}}):
            raise HostCapabilityError("supervision_receipt_digest_mismatch", "$.supervision.receipt")
        previous = self._last_supervision.get(chain_key)
        if previous is None:
            invalid_chain = row["snapshot_sequence"] != 1 or row["previous_snapshot_sha256"] is not None
        else:
            exact_replay = row["snapshot_sequence"] == previous[0] and row["snapshot_sha256"] == previous[1]
            successor = row["snapshot_sequence"] == previous[0] + 1 and row["previous_snapshot_sha256"] == previous[1]
            invalid_chain = not (exact_replay or successor)
        if invalid_chain:
            raise HostCapabilityError("supervision_chain_invalid", "$.supervision.receipt")
        self._last_supervision[chain_key] = (row["snapshot_sequence"], row["snapshot_sha256"])
        return {"state": "verified", "reason": None, "receipt": row}

    def _selection_receipt(self, value: Any, fields: set[str], artifact_type: str, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        row = _closed(value, fields, "selection_receipt_invalid", "$.selection_receipt")
        if row["schema_version"] != 1 or row["artifact_type"] != artifact_type:
            raise HostCapabilityError("selection_receipt_invalid", "$.selection_receipt")
        for field in ("workspace_id", "source_sha256", "candidate_sha256"):
            if row[field] != identity[field]:
                raise HostCapabilityError("selection_receipt_mismatch", f"$.selection_receipt.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "selection_sha256", "catalog_receipt_sha256", "bundle_sha256", "receipt_sha256", "seal"):
            _sha(row[field], "selection_receipt_invalid", f"$.selection_receipt.{field}")
        for field in ("service_instance_id", "admission_id"):
            _identifier(row[field], "selection_receipt_invalid", f"$.selection_receipt.{field}")
            if row[field] != body[field]:
                raise HostCapabilityError("selection_receipt_mismatch", f"$.selection_receipt.{field}")
        if ((artifact_type == SELECTION_HEAD_TYPE and (row["binding_state_version"] != body["binding_state_version"] or row["binding_state_sha256"] != body["binding_state_sha256"])) or type(row["selection_state_version" if artifact_type == SELECTION_HEAD_TYPE else "selection_state_version_after"]) is not int or type(row["bundle_generation"]) is not int or row["bundle_generation"] < 1):
            raise HostCapabilityError("selection_receipt_mismatch", "$.selection_receipt.binding")
        if not isinstance(row["selection"], Mapping) or row["selection_sha256"] != digest(row["selection"]):
            raise HostCapabilityError("selection_receipt_digest_mismatch", "$.selection_receipt.selection")
        issued, expires, now = (_timestamp(row["issued_at"], "selection_receipt_stale", "$.issued_at"), _timestamp(row["expires_at"], "selection_receipt_stale", "$.expires_at"), _timestamp(body["now"], "selection_receipt_stale", "$.now"))
        if issued > now or expires <= now or row["receipt_sha256"] != digest({key: item for key, item in row.items() if key not in {"receipt_sha256", "seal"}}):
            raise HostCapabilityError("selection_receipt_stale", "$.selection_receipt")
        return row

    def read_operator_preset_bundle(self, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        if body["selector"] not in {"current", "historical"} or (body["selector"] == "current" and body["bundle_sha256"] is not None) or (body["selector"] == "historical" and (not isinstance(body["bundle_sha256"], str) or SHA_RE.fullmatch(body["bundle_sha256"]) is None)):
            raise HostCapabilityError("preset_catalog_request_invalid", "$.body")
        row = _closed(self._request("read_operator_preset_bundle", identity, body), CATALOG_FIELDS, "preset_catalog_invalid", "$.preset_catalog")
        if row["schema_version"] != 1 or row["artifact_type"] != CATALOG_TYPE:
            raise HostCapabilityError("preset_catalog_invalid", "$.preset_catalog")
        expected = {"workspace_id": identity["workspace_id"], "source_sha256": identity["source_sha256"], "candidate_sha256": identity["candidate_sha256"], **{key: body[key] for key in ("service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256")}}
        if any(row[key] != value for key, value in expected.items()):
            raise HostCapabilityError("preset_catalog_mismatch", "$.preset_catalog")
        for field in ("catalog_receipt_id", "service_instance_id", "admission_id"):
            _identifier(row[field], "preset_catalog_invalid", f"$.preset_catalog.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "preset_policy_sha256", "adapter_registry_sha256", "capability_profile_sha256", "bundle_sha256", "receipt_sha256", "seal"):
            _sha(row[field], "preset_catalog_invalid", f"$.preset_catalog.{field}")
        if row["previous_catalog_sha256"] is not None:
            _sha(row["previous_catalog_sha256"], "preset_catalog_invalid", "$.preset_catalog.previous_catalog_sha256")
        if type(row["binding_state_version"]) is not int or row["binding_state_version"] < 0 or type(row["catalog_generation"]) is not int or row["catalog_generation"] < 1:
            raise HostCapabilityError("preset_catalog_invalid", "$.preset_catalog.catalog_generation")
        bundle = _closed(row["bundle"], {"schema_version", "artifact_type", "bundle_id", "generation", "presets", "bundle_sha256"}, "preset_catalog_invalid", "$.preset_catalog.bundle")
        if bundle["bundle_sha256"] != row["bundle_sha256"] or row["bundle_sha256"] != digest({key: item for key, item in bundle.items() if key != "bundle_sha256"}) or type(bundle["generation"]) is not int or bundle["generation"] != row["catalog_generation"] or not isinstance(bundle["presets"], list) or not 1 <= len(bundle["presets"]) <= 32:
            raise HostCapabilityError("preset_catalog_digest_mismatch", "$.preset_catalog.bundle")
        if body["selector"] == "historical" and row["bundle_sha256"] != body["bundle_sha256"]:
            raise HostCapabilityError("historical_unavailable", "$.preset_catalog.bundle_sha256")
        if not isinstance(row["configured_bindings"], list) or len(row["configured_bindings"]) != len(bundle["presets"]):
            raise HostCapabilityError("preset_catalog_qualification_invalid", "$.preset_catalog.configured_bindings")
        _, caps, _ = self._load()
        if not {"preset.catalog", "preset.select"} <= set(caps["capability_ids"]):
            raise HostCapabilityError("preset_catalog_unavailable", "$.capabilities.capability_ids")
        registrations = {item["action_id"]: item for item in caps["action_registrations"]}
        preset_by_id = {item.get("preset_id"): item for item in bundle["presets"] if isinstance(item, Mapping)}
        seen: set[str] = set()
        for index, value in enumerate(row["configured_bindings"]):
            binding = _closed(value, CATALOG_BINDING_FIELDS, "preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}]")
            preset_id = _identifier(binding["preset_id"], "preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}].preset_id")
            if preset_id in seen or preset_id not in preset_by_id:
                raise HostCapabilityError("preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}]")
            seen.add(preset_id)
            for field in ("adapter_type", "route_name", "action_id", "tool_id", "transport"):
                _identifier(binding[field], "preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}].{field}")
            for field in ("adapter_binding_sha256", "route_identity_sha256", "qualification_certificate_sha256"):
                _sha(binding[field], "preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}].{field}")
            preset = preset_by_id[preset_id]
            adapter, route = preset.get("adapter", {}), preset.get("route", {})
            registration = registrations.get(binding["action_id"])
            if binding["adapter_type"] != adapter.get("adapter_id") or binding["route_name"] != route.get("route_id") or binding["action_id"] != adapter.get("action_id") or binding["tool_id"] != adapter.get("tool_id") or binding["transport"] != adapter.get("transport") or registration is None or registration.get("tool_id") != binding["tool_id"] or registration.get("transport") != binding["transport"]:
                raise HostCapabilityError("preset_catalog_qualification_invalid", f"$.preset_catalog.configured_bindings[{index}]")
        issued, expires, now = (_timestamp(row["issued_at"], "preset_catalog_stale", "$.preset_catalog.issued_at"), _timestamp(row["expires_at"], "preset_catalog_stale", "$.preset_catalog.expires_at"), _timestamp(body["now"], "preset_catalog_stale", "$.body.now"))
        if issued > now or expires <= now or row["receipt_sha256"] != digest({key: item for key, item in row.items() if key not in {"receipt_sha256", "seal"}}):
            raise HostCapabilityError("preset_catalog_stale", "$.preset_catalog")
        if body["selector"] == "current":
            chain_key = (identity["workspace_id"], body["service_instance_id"])
            previous = self._last_catalog.get(chain_key)
            if previous is None:
                invalid = row["catalog_generation"] != 1 or row["previous_catalog_sha256"] is not None
            else:
                replay = row["catalog_generation"] == previous[0] and row["receipt_sha256"] == previous[1]
                successor = row["catalog_generation"] == previous[0] + 1 and row["previous_catalog_sha256"] == previous[1]
                invalid = not (replay or successor)
            if invalid:
                raise HostCapabilityError("preset_catalog_chain_invalid", "$.preset_catalog")
            self._last_catalog[chain_key] = (row["catalog_generation"], row["receipt_sha256"])
        return row

    def read_operator_selection_head(self, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        return self._selection_receipt(self._request("read_operator_selection_head", identity, body), SELECTION_HEAD_FIELDS, SELECTION_HEAD_TYPE, identity, body)

    def read_operator_recovery_lease_grant(self, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        row = _closed(self._request("read_operator_recovery_lease_grant", identity, body), RECOVERY_GRANT_FIELDS, "recovery_authority_unavailable", "$.recovery_grant")
        if row["schema_version"] != 1 or row["artifact_type"] != RECOVERY_GRANT_TYPE:
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant")
        expected = {"workspace_id": identity["workspace_id"], "source_sha256": identity["source_sha256"], "candidate_sha256": identity["candidate_sha256"], **{key: body[key] for key in ("service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "selection_sha256", "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "expected_cas")}}
        if any(row[key] != value for key, value in expected.items()) or row["no_successor"] is not True:
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant")
        if type(row["binding_state_version"]) is not int or row["binding_state_version"] < 1:
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant.binding_state_version")
        for field in ("grant_id", "issuer_id", "service_instance_id", "admission_id", "predecessor_run_id", "reserved_authority_id"):
            _identifier(row[field], "recovery_authority_unavailable", f"$.recovery_grant.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "selection_sha256", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "grant_sha256", "seal"):
            _sha(row[field], "recovery_authority_unavailable", f"$.recovery_grant.{field}")
        lease = _closed(row["fresh_lease"], {"lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256"}, "recovery_authority_unavailable", "$.recovery_grant.fresh_lease")
        _identifier(lease["lease_id"], "recovery_authority_unavailable", "$.recovery_grant.fresh_lease.lease_id")
        if type(lease["fencing_token"]) is not int or lease["fencing_token"] < 1 or lease["lease_sha256"] != digest({key: value for key, value in lease.items() if key != "lease_sha256"}):
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant.fresh_lease")
        cas = _closed(row["expected_cas"], {"expected_state_version", "expected_thread_generation"}, "recovery_authority_unavailable", "$.recovery_grant.expected_cas")
        if any(type(cas[field]) is not int or cas[field] < 0 for field in cas):
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant.expected_cas")
        issued, expires, lease_issued, lease_expires, now = (_timestamp(row["issued_at"], "recovery_authority_unavailable", "$.issued_at"), _timestamp(row["expires_at"], "recovery_authority_unavailable", "$.expires_at"), _timestamp(lease["issued_at"], "recovery_authority_unavailable", "$.fresh_lease.issued_at"), _timestamp(lease["expires_at"], "recovery_authority_unavailable", "$.fresh_lease.expires_at"), _timestamp(body["now"], "recovery_authority_unavailable", "$.now"))
        if issued > now or lease_issued > now or expires <= now or lease_expires <= now or expires > lease_expires or expires <= issued or lease_expires <= lease_issued or (expires - issued).total_seconds() > MAX_RESPONSE_LIFETIME_SECONDS or row["grant_sha256"] != digest({key: value for key, value in row.items() if key not in {"grant_sha256", "seal"}}):
            raise HostCapabilityError("recovery_authority_unavailable", "$.recovery_grant")
        return row

    def _validate_selection_mutation(self, value: Any, identity: dict[str, Any], body: dict[str, Any], *, commit: bool) -> dict[str, Any]:
        row = self._selection_receipt(value, SELECTION_MUTATION_FIELDS, SELECTION_MUTATION_TYPE, identity, body)
        if row["mutation_id"] != body["submission_id"] or row["submission_sha256"] != body["submission_sha256"] or type(row["selection_state_version_before"]) is not int or row["selection_state_version_before"] < 1 or row["selection_state_version_after"] != row["selection_state_version_before"] + 1 or type(row["runtime_thread_generation"]) is not int or row["runtime_thread_generation"] < 1:
            raise HostCapabilityError("selection_receipt_mismatch", "$.selection_receipt")
        for field in ("runtime_thread_id", "mutation_id"):
            _identifier(row[field], "selection_receipt_invalid", f"$.selection_receipt.{field}")
        _sha(row["submission_sha256"], "selection_receipt_invalid", "$.selection_receipt.submission_sha256")
        _sha(row["previous_selection_sha256"], "selection_receipt_invalid", "$.selection_receipt.previous_selection_sha256")
        if commit and (
            row["binding_state_version"] != body["binding_state_version"]
            or row["binding_state_sha256"] != body["binding_state_sha256"]
            or row["runtime_thread_id"] != body["runtime_thread_id"]
            or row["runtime_thread_generation"] != body["runtime_thread_generation"]
            or row["selection_state_version_before"] != body["selection_state_version"]
            or row["previous_selection_sha256"] != body["current_selection_sha256"]
            or row["bundle_generation"] != body["expected_generation"]
        ):
            raise HostCapabilityError("selection_receipt_mismatch", "$.selection_receipt")
        return row

    def read_operator_selection_mutation(self, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        result = _closed(self._request("read_operator_selection_mutation", identity, body), {"status", "receipt"}, "selection_lookup_invalid", "$.selection_lookup")
        if result["status"] == "absent":
            if result["receipt"] is not None:
                raise HostCapabilityError("selection_lookup_invalid", "$.selection_lookup")
            return result
        if result["status"] == "collision":
            if result["receipt"] is not None:
                raise HostCapabilityError("selection_lookup_invalid", "$.selection_lookup")
            raise HostCapabilityError("selection_submission_collision", "$.selection_lookup")
        if result["status"] != "exact":
            raise HostCapabilityError("selection_lookup_invalid", "$.selection_lookup")
        return {"status": "exact", "receipt": self._validate_selection_mutation(result["receipt"], identity, body, commit=False)}

    def commit_operator_selection(self, identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        return self._validate_selection_mutation(self._request("commit_operator_selection", identity, body), identity, body, commit=True)


_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_PRODUCTION_ADAPTER = _PackageHostCapabilityAdapter(_CONSTRUCTION_TOKEN)
_TEST_ADAPTER: _PackageHostCapabilityAdapter | None = None


def _active_adapter() -> _PackageHostCapabilityAdapter:
    return _PRODUCTION_ADAPTER if _TEST_ADAPTER is None else _TEST_ADAPTER


@contextmanager
def _for_test(package_root: str | Path):
    """TEST ONLY: temporarily select one closed test-only package root."""
    global _TEST_ADAPTER
    if _TEST_ADAPTER is not None:
        raise HostCapabilityError("test_package_root_required", "$.package_root")
    adapter = _PackageHostCapabilityAdapter(
        _CONSTRUCTION_TOKEN, test_package_root=Path(package_root),
    )
    adapter.require_configured()
    _TEST_ADAPTER = adapter
    try:
        yield adapter
    finally:
        _TEST_ADAPTER = None


def require_configured() -> None:
    _active_adapter().require_configured()


def verify_effect_authority(authority: dict[str, Any], context: dict[str, Any]) -> bool:
    return _active_adapter().verify_effect_authority(authority, context)


def invoke_registered_action(action_id: str, operation: str, effect_request: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().invoke_registered_action(action_id, operation, effect_request)


def action_registrations() -> tuple[dict[str, Any], ...]:
    return _active_adapter().action_registrations()


def capability_ids() -> frozenset[str]:
    return _active_adapter().capability_ids()


def issue_responses_context(responses_request: dict[str, Any] | None, identity: dict[str, Any], *, control_action: str | None = None, control_payload: dict[str, Any] | None = None, record_sha256: str | None = None, service_instance_id: str | None = None) -> dict[str, Any]:
    return _active_adapter().issue_responses_context(
        responses_request, identity, control_action=control_action,
        control_payload=control_payload, record_sha256=record_sha256,
        service_instance_id=service_instance_id, recovery_grant_id=None,
        recovery_grant_sha256=None,
    )


def _issue_responses_context_with_recovery_grant(responses_request: dict[str, Any] | None, identity: dict[str, Any], *, control_action: str, control_payload: dict[str, Any], record_sha256: str, service_instance_id: str, recovery_grant_id: str, recovery_grant_sha256: str) -> dict[str, Any]:
    """PACKAGE INTERNAL: bind Recover context to an already TLS-validated grant."""
    return _active_adapter().issue_responses_context(responses_request, identity, control_action=control_action, control_payload=control_payload, record_sha256=record_sha256, service_instance_id=service_instance_id, recovery_grant_id=recovery_grant_id, recovery_grant_sha256=recovery_grant_sha256)


def issue_responses_bridge(responses_request: dict[str, Any], effect_request: dict[str, Any], effect_receipt: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().issue_responses_bridge(
        responses_request, effect_request, effect_receipt, identity,
    )


def verify_responses_bridge(bridge_receipt: dict[str, Any], context: dict[str, Any], identity: dict[str, Any]) -> bool:
    return _active_adapter().verify_responses_bridge(bridge_receipt, context, identity)


def read_capability_admission(identity: dict[str, Any], service_instance_id: str, now: str) -> dict[str, Any]:
    return _active_adapter().read_capability_admission(identity, service_instance_id, now)


def read_operator_recovery_lease_grant(identity: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """PACKAGE INTERNAL: resolve one TLS-authenticated current recovery grant."""
    return _active_adapter().read_operator_recovery_lease_grant(identity, body)


def commit_or_verify_record(identity: dict[str, Any], *, mode: str, record: dict[str, Any] | None, context: dict[str, Any], seal: str | None) -> Any:
    return _active_adapter().commit_or_verify_record(
        identity, mode=mode, record=record, context=context, seal=seal,
    )


def seal_or_verify_projection(identity: dict[str, Any], *, mode: str, context: dict[str, Any], seal: str | None) -> Any:
    return _active_adapter().seal_or_verify_projection(
        identity, mode=mode, context=context, seal=seal,
    )


def read_projection_baseline(identity: dict[str, Any], admission_id: str, now: str) -> dict[str, Any]:
    return _active_adapter().read_projection_baseline(identity, admission_id, now)


def open_operator_listener(identity: dict[str, Any], service_instance_id: str, routes: list[dict[str, str]]) -> dict[str, Any]:
    return _active_adapter().open_operator_listener(identity, service_instance_id, routes)


def read_operator_supervision(identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().read_operator_supervision(identity, request_body)


def read_operator_preset_bundle(identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().read_operator_preset_bundle(identity, request_body)


def read_operator_selection_head(identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().read_operator_selection_head(identity, request_body)


def read_operator_selection_mutation(identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().read_operator_selection_mutation(identity, request_body)


def commit_operator_selection(identity: dict[str, Any], request_body: dict[str, Any]) -> dict[str, Any]:
    return _active_adapter().commit_operator_selection(identity, request_body)


def production_configured() -> bool:
    try:
        require_configured()
    except HostCapabilityError:
        return False
    return True
