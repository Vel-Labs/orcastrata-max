#!/usr/bin/env python3
"""Workspace-scoped foreground runtime service and effect-state owner.

The service reads exactly ``<workspace>/runtime.json`` and exposes strict v1
inspection, reconnect, and in-process shutdown views.  It does not bind an
endpoint, start a daemon, write runtime state, select routes, allocate leases,
grant authority, accept work, install anything, or call a provider. Explicit
``run``, ``cancel``, and ``recover`` requests are persisted with CAS and are
delegated to the single effect authority in ``runtime_execution_gateway``.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence

import package_host_capability_adapter as package_host
import runtime_execution_gateway as effect_gateway
import served_agent_presets as response_bridge
import standalone_operator_local_binding as operator_binding


SERVICE_VERSION = 1
SUPPORTED_RUNTIME_VERSION = "1"
SUPPORTED_API_VERSION = "1"
ARTIFACT_TYPE = "standalone_runtime_service_manifest_v1"
RESULT_ARTIFACT_TYPE = "standalone_runtime_service_result_v1"
ERROR_ARTIFACT_TYPE = "standalone_runtime_service_error_v1"
RUNTIME_FILENAME = "runtime.json"
EFFECT_STATE_FILENAME = ".codexmax-effect-kernel-state.json"
EFFECT_LOCK_FILENAME = ".codexmax-effect-kernel.lock"
OPERATOR_BINDING_FILENAME = ".codexmax-operator-binding-record.json"
OPERATOR_BINDING_MAX_BYTES = 8 * 1024 * 1024
# Production capabilities are owned immutably by the gateway package.  The
# service never accepts or substitutes them from request-facing code.
_PACKAGE_ACTION_REGISTRY = effect_gateway._PACKAGE_ACTION_REGISTRY
_PACKAGE_AUTHORITY_VERIFIER = effect_gateway._PACKAGE_AUTHORITY_VERIFIER
def _package_responses_context_provider(request: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    return package_host.issue_responses_context(request, identity)


def _package_responses_bridge_provider(request: dict[str, Any], effect_request: dict[str, Any], effect_receipt: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    return package_host.issue_responses_bridge(request, effect_request, effect_receipt, identity)


def _package_operator_capability_preflight() -> None:
    package_host.require_configured()


_PACKAGE_RESPONSES_CONTEXT_PROVIDER = _package_responses_context_provider
_PACKAGE_RESPONSES_BRIDGE_RECEIPT_PROVIDER = _package_responses_bridge_provider
_PACKAGE_OPERATOR_CAPABILITY_PREFLIGHT = _package_operator_capability_preflight
_PACKAGE_OPERATOR_LISTENER_FACTORY = operator_binding.start_package_listener
LIFECYCLE_STATES = ("created", "ready", "stopping", "stopped")
LIFECYCLE_TRANSITIONS = (
    ("created", "ready"),
    ("ready", "stopping"),
    ("stopping", "stopped"),
)
LOCAL_TRANSPORTS = {"local_cli", "in_process", "unix_socket", "loopback_http"}
ENDPOINT_KINDS = {"unix_socket", "loopback_http"}
HEALTH_STATUSES = {"healthy", "degraded", "unknown", "unavailable"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LOOPBACK_RE = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})$")

ROOT_FIELDS = {
    "schema_version",
    "artifact_type",
    "workspace_id",
    "evaluated_at",
    "runtime_manifest",
    "lifecycle",
    "endpoint",
    "health",
    "reconnect",
    "shutdown",
    "effect_guarantees",
}
RUNTIME_MANIFEST_FIELDS = {
    "runtime_id",
    "runtime_version",
    "api_version",
    "source_sha256",
    "candidate_sha256",
    "workspace_root_sha256",
    "isolation_id",
    "process_mode",
    "endpoint_kind",
    "supported_transports",
    "health",
    "degraded_reasons",
    "recovery_instructions",
    "mandatory_model_hop",
    "model_can_admit",
}
LIFECYCLE_FIELDS = {"version", "states", "transitions"}
ENDPOINT_FIELDS = {"kind", "address", "local_only", "bound"}
HEALTH_FIELDS = {
    "status",
    "provenance",
    "observed_at",
    "expires_at",
    "degraded_reasons",
}
RECONNECT_FIELDS = {"supported", "requires_original_client", "instruction"}
SHUTDOWN_FIELDS = {"supported", "mode", "instruction"}
EFFECT_FIELDS = {
    "provider_called",
    "lease_created",
    "dispatch_started",
    "policy_activated",
    "ledger_written",
    "authority_granted",
    "acceptance_granted",
    "installed",
    "daemon_started",
    "network_bound",
}


class RuntimeServiceError(ValueError):
    """Stable typed failure for malformed or unsafe service input."""

    def __init__(self, code: str, path: str):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise RuntimeServiceError("nonfinite_number", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nonfinite(child, f"{path}[{index}]")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes, rejecting non-finite numbers."""
    _reject_nonfinite(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RuntimeServiceError("canonical_json_invalid", "$") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeServiceError("duplicate_json_key", key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RuntimeServiceError("nonfinite_number", value)


def load_json_bytes(raw: bytes) -> Any:
    """Strictly decode one UTF-8 JSON value with duplicate-key rejection."""
    if not isinstance(raw, bytes):
        raise RuntimeServiceError("bytes_required", "$")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeServiceError("utf8_invalid", f"byte:{exc.start}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except RuntimeServiceError:
        raise
    except json.JSONDecodeError as exc:
        raise RuntimeServiceError(
            "json_invalid", f"line:{exc.lineno}:column:{exc.colno}"
        ) from exc
    _reject_nonfinite(value)
    return value


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeServiceError("object_required", path)
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise RuntimeServiceError("unknown_field", f"{path}.{unknown[0]}")
    if missing:
        raise RuntimeServiceError("missing_field", f"{path}.{missing[0]}")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RuntimeServiceError("integer_invalid", path)
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise RuntimeServiceError("boolean_required", path)
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeServiceError("string_required", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise RuntimeServiceError("identifier_invalid", path)
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RuntimeServiceError("digest_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise RuntimeServiceError("timestamp_invalid", path)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeServiceError("timestamp_invalid", path) from exc


def _string_list(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    identifiers: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise RuntimeServiceError("array_required", path)
    result: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        result.append(_identifier(item, item_path) if identifiers else _text(item, item_path))
    if len(result) != len(set(result)):
        raise RuntimeServiceError("array_duplicate", path)
    return result


def _portable_relative_path(value: Any, path: str) -> str:
    text = _text(value, path)
    if "\\" in text or "%" in text or text.startswith("/"):
        raise RuntimeServiceError("path_not_contained", path)
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeServiceError("path_not_contained", path)
    if re.match(r"^[A-Za-z]:", text):
        raise RuntimeServiceError("path_not_contained", path)
    return text


def _absolute_workspace_path(workspace: str | Path) -> Path:
    if not isinstance(workspace, (str, Path)):
        raise RuntimeServiceError("workspace_path_invalid", "--workspace")
    raw = str(workspace)
    if not raw or "\x00" in raw or "%" in raw or "\\" in raw:
        raise RuntimeServiceError("workspace_path_invalid", "--workspace")
    lexical = Path(raw).expanduser()
    if ".." in lexical.parts:
        raise RuntimeServiceError("workspace_path_traversal", "--workspace")
    absolute = lexical if lexical.is_absolute() else Path.cwd() / lexical
    absolute = Path(os.path.normpath(str(absolute)))
    if not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise RuntimeServiceError("workspace_path_invalid", "--workspace")
    return absolute


def _stat_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stat_snapshot(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _safe_open_flags(*, directory: bool = False) -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    if directory:
        required += ("O_DIRECTORY",)
    if any(not hasattr(os, name) for name in required):
        raise RuntimeServiceError("path_safety_unsupported", "--workspace")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _open_workspace_directory(workspace_path: Path) -> int:
    """Open every selected component without following symlinks."""
    try:
        current_fd = os.open(workspace_path.anchor, _safe_open_flags(directory=True))
    except OSError as exc:
        raise RuntimeServiceError("workspace_unavailable", "--workspace") from exc
    try:
        for component in workspace_path.parts[1:]:
            try:
                selected = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                raise RuntimeServiceError("workspace_unavailable", "--workspace") from exc
            if stat.S_ISLNK(selected.st_mode):
                raise RuntimeServiceError("workspace_symlink_ambiguous", "--workspace")
            if not stat.S_ISDIR(selected.st_mode):
                raise RuntimeServiceError("workspace_not_directory", "--workspace")
            try:
                next_fd = os.open(
                    component,
                    _safe_open_flags(directory=True),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                code = (
                    "workspace_symlink_ambiguous"
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}
                    else "workspace_unavailable"
                )
                raise RuntimeServiceError(code, "--workspace") from exc
            opened = os.fstat(next_fd)
            if _stat_identity(opened) != _stat_identity(selected):
                os.close(next_fd)
                raise RuntimeServiceError("workspace_path_changed", "--workspace")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _read_runtime_bytes(workspace_fd: int) -> bytes:
    """Read the direct immutable child from one already-open workspace."""
    try:
        selected = os.stat(RUNTIME_FILENAME, dir_fd=workspace_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeServiceError("runtime_manifest_unavailable", RUNTIME_FILENAME) from exc
    if stat.S_ISLNK(selected.st_mode):
        raise RuntimeServiceError("runtime_path_symlink_ambiguous", RUNTIME_FILENAME)
    if not stat.S_ISREG(selected.st_mode):
        raise RuntimeServiceError("runtime_manifest_not_file", RUNTIME_FILENAME)
    try:
        runtime_fd = os.open(
            RUNTIME_FILENAME,
            _safe_open_flags(),
            dir_fd=workspace_fd,
        )
    except OSError as exc:
        code = (
            "runtime_path_symlink_ambiguous"
            if exc.errno == errno.ELOOP
            else "runtime_manifest_unreadable"
        )
        raise RuntimeServiceError(code, RUNTIME_FILENAME) from exc
    try:
        before = os.fstat(runtime_fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeServiceError("runtime_manifest_not_file", RUNTIME_FILENAME)
        if _stat_identity(before) != _stat_identity(selected):
            raise RuntimeServiceError("runtime_path_changed", RUNTIME_FILENAME)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(runtime_fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(runtime_fd)
        try:
            current = os.stat(
                RUNTIME_FILENAME,
                dir_fd=workspace_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise RuntimeServiceError("runtime_path_changed", RUNTIME_FILENAME) from exc
        if (
            _stat_snapshot(before) != _stat_snapshot(after)
            or _stat_identity(after) != _stat_identity(current)
            or stat.S_ISLNK(current.st_mode)
        ):
            raise RuntimeServiceError("runtime_manifest_changed_during_read", RUNTIME_FILENAME)
        return b"".join(chunks)
    except OSError as exc:
        raise RuntimeServiceError("runtime_manifest_unreadable", RUNTIME_FILENAME) from exc
    finally:
        os.close(runtime_fd)


def _validate_lifecycle(value: Any) -> dict[str, Any]:
    row = _closed(value, LIFECYCLE_FIELDS, "$.lifecycle")
    if _integer(row["version"], "$.lifecycle.version", minimum=1) != SERVICE_VERSION:
        raise RuntimeServiceError("lifecycle_version_unsupported", "$.lifecycle.version")
    states = _string_list(row["states"], "$.lifecycle.states", nonempty=True)
    if states != list(LIFECYCLE_STATES):
        raise RuntimeServiceError("lifecycle_states_invalid", "$.lifecycle.states")
    transitions = row["transitions"]
    if not isinstance(transitions, list):
        raise RuntimeServiceError("array_required", "$.lifecycle.transitions")
    normalized: list[tuple[str, str]] = []
    for index, transition in enumerate(transitions):
        item = _closed(transition, {"from", "to"}, f"$.lifecycle.transitions[{index}]")
        normalized.append(
            (
                _text(item["from"], f"$.lifecycle.transitions[{index}].from"),
                _text(item["to"], f"$.lifecycle.transitions[{index}].to"),
            )
        )
    if normalized != list(LIFECYCLE_TRANSITIONS):
        raise RuntimeServiceError("lifecycle_transitions_invalid", "$.lifecycle.transitions")
    return row


def _validate_endpoint(value: Any, manifest: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = _closed(value, ENDPOINT_FIELDS, "$.endpoint")
    kind = _text(endpoint["kind"], "$.endpoint.kind")
    address = _text(endpoint["address"], "$.endpoint.address")
    if kind not in ENDPOINT_KINDS or kind != manifest["endpoint_kind"]:
        raise RuntimeServiceError("endpoint_kind_invalid", "$.endpoint.kind")
    if not _boolean(endpoint["local_only"], "$.endpoint.local_only"):
        raise RuntimeServiceError("endpoint_not_local", "$.endpoint.local_only")
    if _boolean(endpoint["bound"], "$.endpoint.bound"):
        raise RuntimeServiceError("network_effect_claimed", "$.endpoint.bound")
    if kind == "unix_socket":
        _portable_relative_path(address, "$.endpoint.address")
    else:
        match = LOOPBACK_RE.fullmatch(address)
        if match is None or int(match.group(1)) > 65535:
            raise RuntimeServiceError("endpoint_not_loopback", "$.endpoint.address")
    return endpoint


def _validate_health(
    value: Any,
    manifest: Mapping[str, Any],
    evaluated_at: datetime,
) -> dict[str, Any]:
    health = _closed(value, HEALTH_FIELDS, "$.health")
    status = _text(health["status"], "$.health.status")
    provenance = _text(health["provenance"], "$.health.provenance")
    if status not in HEALTH_STATUSES:
        raise RuntimeServiceError("health_status_invalid", "$.health.status")
    if provenance not in {"observed", "unknown"}:
        raise RuntimeServiceError("health_provenance_invalid", "$.health.provenance")
    observed_at = _timestamp(health["observed_at"], "$.health.observed_at")
    expires_at = _timestamp(health["expires_at"], "$.health.expires_at")
    reasons = _string_list(health["degraded_reasons"], "$.health.degraded_reasons")
    if expires_at <= observed_at or evaluated_at < observed_at:
        raise RuntimeServiceError("health_window_invalid", "$.health")
    if evaluated_at >= expires_at:
        if status != "unknown" or "health_evidence_expired" not in reasons:
            raise RuntimeServiceError("health_freshness_mismatch", "$.health.status")
    elif provenance == "unknown":
        if status != "unknown" or not reasons:
            raise RuntimeServiceError("health_unknown_mismatch", "$.health")
    elif status == "healthy":
        if reasons:
            raise RuntimeServiceError("healthy_degraded_mismatch", "$.health.degraded_reasons")
    elif status in {"degraded", "unavailable"}:
        if not reasons:
            raise RuntimeServiceError("degraded_reason_required", "$.health.degraded_reasons")
    else:
        raise RuntimeServiceError("health_status_mismatch", "$.health.status")
    if manifest["health"] != status or manifest["degraded_reasons"] != reasons:
        raise RuntimeServiceError("runtime_health_mismatch", "$.runtime_manifest.health")
    return health


def validate_manifest(document: Any) -> dict[str, Any]:
    """Validate and return a deep-copied strict v1 runtime service manifest."""
    _reject_nonfinite(document)
    root = _closed(copy.deepcopy(document), ROOT_FIELDS, "$")
    if _integer(root["schema_version"], "$.schema_version", minimum=1) != SERVICE_VERSION:
        raise RuntimeServiceError("schema_version_unsupported", "$.schema_version")
    if root["artifact_type"] != ARTIFACT_TYPE:
        raise RuntimeServiceError("artifact_type_unsupported", "$.artifact_type")
    workspace_id = _identifier(root["workspace_id"], "$.workspace_id")
    evaluated_at = _timestamp(root["evaluated_at"], "$.evaluated_at")

    manifest = _closed(
        root["runtime_manifest"], RUNTIME_MANIFEST_FIELDS, "$.runtime_manifest"
    )
    for field in ("runtime_id", "runtime_version", "api_version", "isolation_id"):
        _identifier(manifest[field], f"$.runtime_manifest.{field}")
    if manifest["runtime_version"] != SUPPORTED_RUNTIME_VERSION:
        raise RuntimeServiceError(
            "runtime_version_unsupported", "$.runtime_manifest.runtime_version"
        )
    if manifest["api_version"] != SUPPORTED_API_VERSION:
        raise RuntimeServiceError(
            "api_version_unsupported", "$.runtime_manifest.api_version"
        )
    for field in ("source_sha256", "candidate_sha256", "workspace_root_sha256"):
        _digest(manifest[field], f"$.runtime_manifest.{field}")
    if manifest["isolation_id"] != workspace_id:
        raise RuntimeServiceError("workspace_isolation_mismatch", "$.runtime_manifest.isolation_id")
    if manifest["process_mode"] != "foreground":
        raise RuntimeServiceError("runtime_process_mode_invalid", "$.runtime_manifest.process_mode")
    endpoint_kind = _text(manifest["endpoint_kind"], "$.runtime_manifest.endpoint_kind")
    transports = _string_list(
        manifest["supported_transports"],
        "$.runtime_manifest.supported_transports",
        nonempty=True,
        identifiers=True,
    )
    if endpoint_kind not in ENDPOINT_KINDS:
        raise RuntimeServiceError("runtime_endpoint_kind_invalid", "$.runtime_manifest.endpoint_kind")
    if not set(transports) <= LOCAL_TRANSPORTS or endpoint_kind not in transports:
        raise RuntimeServiceError("runtime_transport_invalid", "$.runtime_manifest.supported_transports")
    if (ENDPOINT_KINDS - {endpoint_kind}) & set(transports):
        raise RuntimeServiceError("runtime_transport_invalid", "$.runtime_manifest.supported_transports")
    _text(manifest["health"], "$.runtime_manifest.health")
    _string_list(manifest["degraded_reasons"], "$.runtime_manifest.degraded_reasons")
    _text(manifest["recovery_instructions"], "$.runtime_manifest.recovery_instructions")
    if _boolean(manifest["mandatory_model_hop"], "$.runtime_manifest.mandatory_model_hop"):
        raise RuntimeServiceError("model_authority_boundary_invalid", "$.runtime_manifest.mandatory_model_hop")
    if _boolean(manifest["model_can_admit"], "$.runtime_manifest.model_can_admit"):
        raise RuntimeServiceError("model_authority_boundary_invalid", "$.runtime_manifest.model_can_admit")

    _validate_lifecycle(root["lifecycle"])
    _validate_endpoint(root["endpoint"], manifest)
    _validate_health(root["health"], manifest, evaluated_at)

    reconnect = _closed(root["reconnect"], RECONNECT_FIELDS, "$.reconnect")
    if not _boolean(reconnect["supported"], "$.reconnect.supported"):
        raise RuntimeServiceError("reconnect_truth_missing", "$.reconnect.supported")
    if _boolean(reconnect["requires_original_client"], "$.reconnect.requires_original_client"):
        raise RuntimeServiceError("client_absence_not_supported", "$.reconnect.requires_original_client")
    _text(reconnect["instruction"], "$.reconnect.instruction")

    shutdown = _closed(root["shutdown"], SHUTDOWN_FIELDS, "$.shutdown")
    if not _boolean(shutdown["supported"], "$.shutdown.supported"):
        raise RuntimeServiceError("shutdown_truth_missing", "$.shutdown.supported")
    if shutdown["mode"] != "foreground_signal":
        raise RuntimeServiceError("shutdown_mode_invalid", "$.shutdown.mode")
    _text(shutdown["instruction"], "$.shutdown.instruction")

    effects = _closed(root["effect_guarantees"], EFFECT_FIELDS, "$.effect_guarantees")
    for field in sorted(EFFECT_FIELDS):
        if _boolean(effects[field], f"$.effect_guarantees.{field}"):
            raise RuntimeServiceError("effect_guarantee_invalid", f"$.effect_guarantees.{field}")
    return root


def load_manifest(workspace: str | Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Load only the selected workspace's direct ``runtime.json`` child."""
    workspace_path = _absolute_workspace_path(workspace)
    workspace_fd = _open_workspace_directory(workspace_path)
    try:
        opened_workspace = os.fstat(workspace_fd)
        raw = _read_runtime_bytes(workspace_fd)
    finally:
        os.close(workspace_fd)
    confirmation_fd = _open_workspace_directory(workspace_path)
    try:
        if _stat_identity(os.fstat(confirmation_fd)) != _stat_identity(opened_workspace):
            raise RuntimeServiceError("workspace_path_changed", "--workspace")
    finally:
        os.close(confirmation_fd)
    document = validate_manifest(load_json_bytes(raw))
    expected_workspace_id = workspace_path.name
    if document["workspace_id"] != expected_workspace_id:
        raise RuntimeServiceError("workspace_identity_mismatch", "$.workspace_id")
    manifest = document["runtime_manifest"]
    if manifest["isolation_id"] != expected_workspace_id:
        raise RuntimeServiceError(
            "workspace_isolation_mismatch", "$.runtime_manifest.isolation_id"
        )
    workspace_path_sha256 = "sha256:" + hashlib.sha256(
        str(workspace_path).encode("utf-8")
    ).hexdigest()
    if manifest["workspace_root_sha256"] != workspace_path_sha256:
        raise RuntimeServiceError(
            "workspace_root_identity_mismatch",
            "$.runtime_manifest.workspace_root_sha256",
        )
    identity = {
        "workspace_path_sha256": workspace_path_sha256,
        "runtime_json_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "manifest_sha256": canonical_digest(document),
    }
    return document, identity


class RuntimeReadService:
    """One foreground, workspace-scoped, side-effect-free service view."""

    def __init__(self, workspace: str | Path):
        self._manifest, self._identity = load_manifest(workspace)
        self._state = "created"
        self._history = ["created"]

    @property
    def state(self) -> str:
        return self._state

    def _transition(self, target: str) -> None:
        if (self._state, target) not in LIFECYCLE_TRANSITIONS:
            raise RuntimeServiceError(
                "lifecycle_transition_invalid", f"{self._state}->{target}"
            )
        self._state = target
        self._history.append(target)

    def start(self) -> dict[str, Any]:
        if self._state == "created":
            self._transition("ready")
        elif self._state != "ready":
            raise RuntimeServiceError("service_not_startable", self._state)
        return self.inspect(operation="start")

    def inspect(self, *, operation: str = "inspect") -> dict[str, Any]:
        result = {
            "service_version": SERVICE_VERSION,
            "artifact_type": RESULT_ARTIFACT_TYPE,
            "operation": operation,
            "workspace_id": self._manifest["workspace_id"],
            **copy.deepcopy(self._identity),
            "runtime_manifest": copy.deepcopy(self._manifest["runtime_manifest"]),
            "lifecycle": {
                "state": self._state,
                "history": list(self._history),
                "foreground": True,
            },
            "endpoint": copy.deepcopy(self._manifest["endpoint"]),
            "health": copy.deepcopy(self._manifest["health"]),
            "reconnect": copy.deepcopy(self._manifest["reconnect"]),
            "shutdown": copy.deepcopy(self._manifest["shutdown"]),
            "recovery_instructions": self._manifest["runtime_manifest"]["recovery_instructions"],
            "effect_guarantees": copy.deepcopy(self._manifest["effect_guarantees"]),
            "runtime_json_written": False,
            "side_effect_free": True,
        }
        return result

    def reconnect(self) -> dict[str, Any]:
        result = self.inspect(operation="reconnect")
        result["reconnect_requested"] = True
        result["reconnected"] = False
        result["reconnect_observed"] = False
        result["original_client_required"] = False
        return result

    def shutdown(self) -> dict[str, Any]:
        result = self.inspect(operation="shutdown")
        result["shutdown_requested"] = True
        result["shutdown_observed"] = False
        result["persistent_state_changed"] = False
        return result


def inspect_workspace(workspace: str | Path) -> dict[str, Any]:
    service = RuntimeReadService(workspace)
    service.start()
    return service.inspect()


def reconnect_workspace(workspace: str | Path) -> dict[str, Any]:
    return RuntimeReadService(workspace).reconnect()


def shutdown_workspace(workspace: str | Path) -> dict[str, Any]:
    return RuntimeReadService(workspace).shutdown()


def _read_effect_state(workspace_fd: int, workspace_id: str) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(EFFECT_STATE_FILENAME, flags, dir_fd=workspace_fd)
    except FileNotFoundError:
        return effect_gateway.new_effect_state(workspace_id)
    except OSError as exc:
        raise RuntimeServiceError("effect_state_unavailable", EFFECT_STATE_FILENAME) from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeServiceError("effect_state_unsafe", EFFECT_STATE_FILENAME)
        raw = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 8 * 1024 * 1024:
                raise RuntimeServiceError("effect_state_too_large", EFFECT_STATE_FILENAME)
    finally:
        os.close(fd)
    try:
        state = effect_gateway.verify_effect_state(load_json_bytes(raw))
    except effect_gateway.GatewayError as exc:
        raise RuntimeServiceError(exc.code, EFFECT_STATE_FILENAME) from exc
    if state["workspace_id"] != workspace_id:
        raise RuntimeServiceError("workspace_identity_mismatch", EFFECT_STATE_FILENAME)
    return copy.deepcopy(state)


def _write_effect_state(workspace_fd: int, state: Mapping[str, Any]) -> None:
    raw = canonical_json(state)
    temp_name = f"{EFFECT_STATE_FILENAME}.tmp.{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temp_name, flags, 0o600, dir_fd=workspace_fd)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written < 1:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp_name, EFFECT_STATE_FILENAME, src_dir_fd=workspace_fd, dst_dir_fd=workspace_fd)
        os.fsync(workspace_fd)
    except OSError as exc:
        try:
            os.unlink(temp_name, dir_fd=workspace_fd)
        except OSError:
            pass
        raise RuntimeServiceError("effect_state_write_failed", EFFECT_STATE_FILENAME) from exc


def _read_operator_binding_record_raw(workspace_fd: int) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(OPERATOR_BINDING_FILENAME, flags, dir_fd=workspace_fd)
    except FileNotFoundError as exc:
        raise RuntimeServiceError("operator_binding_unavailable", OPERATOR_BINDING_FILENAME) from exc
    except OSError as exc:
        raise RuntimeServiceError("operator_binding_unsafe", OPERATOR_BINDING_FILENAME) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeServiceError("operator_binding_unsafe", OPERATOR_BINDING_FILENAME)
        raw = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw += chunk
            if len(raw) > OPERATOR_BINDING_MAX_BYTES:
                raise RuntimeServiceError("operator_binding_too_large", OPERATOR_BINDING_FILENAME)
    finally:
        os.close(fd)
    return load_json_bytes(raw)


def _read_operator_binding_record(workspace_fd: int, admission: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    try:
        raw = _read_operator_binding_record_raw(workspace_fd)
        bundle_sha = raw.get("responses_request", {}).get("selection", {}).get("bundle_sha256")
        if bundle_sha == response_bridge.DEFAULT_PRESET_BUNDLE["bundle_sha256"]:
            return operator_binding.validate_binding_record(raw, admission, now=now)
        identity = {key: admission[key] for key in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id")}
        resolved = _resolve_operator_catalog(
            identity, admission, binding_state_version=raw.get("binding_state_version"),
            binding_state_sha256=raw.get("record_sha256"), now=now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            selector="historical", bundle_sha256=bundle_sha,
        )
        return operator_binding._validate_binding_record_with_resolved_bundle(raw, admission, resolved["bundle"], now=now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _read_operator_binding_record_for_test(
    workspace_fd: int, admission: dict[str, Any], validation_verifier: Any,
    authority_verifier: Any, *, now: str, trusted_bridge_receipt_sha256: str | None,
) -> dict[str, Any]:
    try:
        return operator_binding._validate_binding_record_for_test(
            _read_operator_binding_record_raw(workspace_fd), admission,
            validation_verifier, now=now, authority_verifier=authority_verifier,
            trusted_bridge_receipt_sha256=trusted_bridge_receipt_sha256,
        )
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _write_operator_binding_record(workspace_fd: int, record: Mapping[str, Any]) -> None:
    raw = canonical_json(record)
    temp_name = OPERATOR_BINDING_FILENAME + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temp_name, flags, 0o600, dir_fd=workspace_fd)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp_name, OPERATOR_BINDING_FILENAME, src_dir_fd=workspace_fd, dst_dir_fd=workspace_fd)
        os.fsync(workspace_fd)
    except OSError as exc:
        try:
            os.unlink(temp_name, dir_fd=workspace_fd)
        except OSError:
            pass
        raise RuntimeServiceError("operator_binding_write_failed", OPERATOR_BINDING_FILENAME) from exc


def _execute_effect_workspace(
    workspace: str | Path,
    request: Mapping[str, Any],
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Persist one production result using package-owned capabilities only."""

    execution_now = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        if isinstance(request, Mapping) and request.get("operation") == "recover":
            effect_gateway._preflight_recovery_request_shape(copy.deepcopy(request))
        else:
            effect_gateway.preflight_effect_authority(
                copy.deepcopy(request), now=execution_now,
            )
    except effect_gateway.GatewayError as exc:
        raise RuntimeServiceError(exc.code, "$.effect_request") from exc
    manifest, _ = load_manifest(workspace)
    workspace_path = _absolute_workspace_path(workspace)
    workspace_fd = _open_workspace_directory(workspace_path)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        except OSError as exc:
            raise RuntimeServiceError("effect_state_lock_failed", EFFECT_LOCK_FILENAME) from exc
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise RuntimeServiceError("effect_state_lock_unsafe", EFFECT_LOCK_FILENAME)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            state = _read_effect_state(workspace_fd, manifest["workspace_id"])
            try:
                request_copy = copy.deepcopy(request)
                if request_copy.get("operation") == "recover":
                    replay = state["idempotency_index"].get(request_copy.get("idempotency_key"))
                    if replay is not None:
                        if replay["request_sha256"] != request_copy.get("request_sha256"):
                            raise RuntimeServiceError("idempotency_collision", "$.effect_request")
                        result = effect_gateway._replay_recovery_from_canonical_state(
                            state, request_copy,
                            token=effect_gateway._RECOVERY_REPLAY_TOKEN,
                        )
                        return copy.deepcopy(result["receipt"])
                    else:
                        identity = _operator_identity(manifest)
                        try:
                            admission = operator_binding.resolve_package_admission(
                                **identity, now=execution_now,
                            )
                            record = _read_operator_binding_record(
                                workspace_fd, admission, now=execution_now,
                            )
                            grant = _read_operator_recovery_grant(
                                identity, admission, record, now=execution_now,
                            )
                        except operator_binding.BindingError as exc:
                            raise RuntimeServiceError(
                                "recovery_authority_unavailable", "$.recovery_grant",
                            ) from exc
                        if (
                            request_copy["run"]["predecessor_run_id"] != grant["predecessor_run_id"]
                            or request_copy["lease"] != grant["fresh_lease"]
                            or request_copy["cas"] != grant["expected_cas"]
                            or request_copy["authority_receipt"]["authority_id"] != grant["reserved_authority_id"]
                        ):
                            raise RuntimeServiceError(
                                "recovery_authority_unavailable", "$.effect_request",
                            )
                        provenance = {
                            key: copy.deepcopy(grant[key])
                            for key in effect_gateway.RECOVERY_PROVENANCE_FIELDS
                        }
                        result = effect_gateway._execute_recovery_with_package_grant(
                            state, request_copy, provenance, now=execution_now,
                            token=effect_gateway._RECOVERY_PACKAGE_TOKEN,
                        )
                else:
                    result = effect_gateway.execute_effect(
                        state, request_copy, now=execution_now,
                    )
            except effect_gateway.GatewayError as exc:
                raise RuntimeServiceError(exc.code, "$.effect_request") from exc
            _write_effect_state(workspace_fd, result["state"])
            return copy.deepcopy(result["receipt"])
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)


def execute_effect_workspace(workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Public closed effect entry; production actions must be package-registered."""

    return _execute_effect_workspace(workspace, request)


def _execute_effect_workspace_for_test(
    workspace: str | Path,
    request: Mapping[str, Any],
    action_registry: Mapping[str, Any],
    authority_verifier: Any,
) -> dict[str, Any]:
    """TEST ONLY: persist using an explicitly test-only action registry."""

    registration_fields = {
        "action_id", "tool_id", "transport", "parameter_fields", "handler", "test_only",
    }
    if not isinstance(action_registry, Mapping):
        raise RuntimeServiceError("direct_effect_bypass", "$.effect_request")
    for action_id, registration in action_registry.items():
        if (
            not isinstance(action_id, str)
            or not isinstance(registration, Mapping)
            or set(registration) != registration_fields
            or registration.get("test_only") is not True
            or registration.get("action_id") != action_id
            or not isinstance(registration.get("tool_id"), str)
            or not isinstance(registration.get("transport"), str)
            or not isinstance(registration.get("parameter_fields"), (list, tuple))
            or any(not isinstance(field, str) for field in registration.get("parameter_fields", ()))
            or not callable(registration.get("handler"))
        ):
            raise RuntimeServiceError("direct_effect_bypass", "$.effect_request")
    execution_now = request.get("created_at", "") if isinstance(request, Mapping) else ""
    try:
        effect_gateway._preflight_effect_authority_for_test(
            copy.deepcopy(request),
            now=execution_now,
            authority_verifier=authority_verifier,
        )
    except effect_gateway.GatewayError as exc:
        raise RuntimeServiceError(exc.code, "$.effect_request") from exc
    manifest, _ = load_manifest(workspace)
    workspace_path = _absolute_workspace_path(workspace)
    workspace_fd = _open_workspace_directory(workspace_path)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        except OSError as exc:
            raise RuntimeServiceError("effect_state_lock_failed", EFFECT_LOCK_FILENAME) from exc
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise RuntimeServiceError("effect_state_lock_unsafe", EFFECT_LOCK_FILENAME)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            state = _read_effect_state(workspace_fd, manifest["workspace_id"])
            try:
                result = effect_gateway._execute_effect_for_test(
                    state,
                    copy.deepcopy(request),
                    action_registry,
                    authority_verifier,
                    now=execution_now,
                )
            except effect_gateway.GatewayError as exc:
                raise RuntimeServiceError(exc.code, "$.effect_request") from exc
            _write_effect_state(workspace_fd, result["state"])
            return copy.deepcopy(result["receipt"])
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)


def execute_responses_workspace(
    workspace: str | Path, request: Mapping[str, Any],
) -> dict[str, Any]:
    """Translate through package-owned context and the single effect entry."""

    return _execute_responses_workspace_artifacts(workspace, request)["bridge_receipt"]


def _execute_responses_workspace_artifacts(
    workspace: str | Path, request: Mapping[str, Any],
    _resolved_bundle: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Package-only composition returning exact originals for operator retention."""

    bundle = response_bridge.DEFAULT_PRESET_BUNDLE if _resolved_bundle is None else response_bridge.validate_bundle(_resolved_bundle)
    try:
        response_bridge.validate_responses_request(request, bundle)
    except response_bridge.PresetError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    try:
        package_host.require_configured()
    except package_host.HostCapabilityError as exc:
        raise RuntimeServiceError("authority_missing", "$.responses_request") from exc
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    host_identity = {key: identity[key] for key in ("workspace_id", "source_sha256", "candidate_sha256")}
    try:
        context = _PACKAGE_RESPONSES_CONTEXT_PROVIDER(copy.deepcopy(request), host_identity)
        effect_request = response_bridge.translate_responses_request(request, context, bundle)
    except package_host.HostCapabilityError as exc:
        raise RuntimeServiceError("authority_missing", "$.responses_request") from exc
    except response_bridge.PresetError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    effect_receipt = execute_effect_workspace(workspace, effect_request)
    if effect_receipt.get("post_state") == "execution_unknown":
        raise RuntimeServiceError("execution_unknown", "$.effect_receipt")
    try:
        trusted_receipt = _PACKAGE_RESPONSES_BRIDGE_RECEIPT_PROVIDER(
            copy.deepcopy(request), copy.deepcopy(effect_request), copy.deepcopy(effect_receipt), host_identity,
        )
        validated, _ = response_bridge._validate_bridge_receipt(
            trusted_receipt, request, bundle,
        )
        if (
            validated["effect_request_sha256"] != effect_request["request_sha256"]
            or validated["effect_receipt_sha256"] != effect_receipt["receipt_sha256"]
        ):
            raise RuntimeServiceError("bridge_request_binding_mismatch", "$.bridge_receipt")
        return {
            "responses_request": copy.deepcopy(dict(request)),
            "effect_request": copy.deepcopy(effect_request),
            "effect_receipt": copy.deepcopy(effect_receipt),
            "bridge_receipt": copy.deepcopy(validated),
        }
    except package_host.HostCapabilityError as exc:
        raise RuntimeServiceError("bridge_receipt_not_authorized", "$.bridge_receipt") from exc
    except response_bridge.PresetError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _resolve_operator_catalog(
    identity: Mapping[str, str], admission: Mapping[str, Any], *,
    binding_state_version: int, binding_state_sha256: str, now: str,
    selector: str, bundle_sha256: str | None,
) -> dict[str, Any]:
    """PACKAGE INTERNAL: resolve only host-sealed current or artifact-derived history."""
    body = {
        "admission_id": admission["admission_id"],
        "service_instance_id": identity["service_instance_id"],
        "binding_state_version": binding_state_version,
        "binding_state_sha256": binding_state_sha256,
        "selector": selector, "bundle_sha256": bundle_sha256, "now": now,
    }
    try:
        return package_host.read_operator_preset_bundle(
            {key: identity[key] for key in ("workspace_id", "source_sha256", "candidate_sha256")}, body,
        )
    except package_host.HostCapabilityError as exc:
        code = "historical_unavailable" if selector == "historical" else "preset_catalog_unavailable"
        raise RuntimeServiceError(code if exc.code == "production_capability_unavailable" else exc.code, "$.preset_catalog") from exc


def _execute_responses_workspace_for_test(
    workspace: str | Path,
    request: Mapping[str, Any],
    effect_context: Mapping[str, Any],
    action_registry: Mapping[str, Any],
    authority_verifier: Any,
    observation: Mapping[str, Any],
    bundle: Mapping[str, Any] = response_bridge.DEFAULT_PRESET_BUNDLE,
) -> dict[str, Any]:
    """TEST ONLY: translate, execute once, and project observed bytes."""

    try:
        effect_request = response_bridge.translate_responses_request(request, effect_context, bundle)
    except response_bridge.PresetError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    effect_receipt = _execute_effect_workspace_for_test(
        workspace, effect_request, action_registry, authority_verifier,
    )
    if effect_receipt.get("post_state") == "execution_unknown":
        raise RuntimeServiceError("execution_unknown", "$.effect_receipt")
    try:
        return response_bridge._project_observed_response_for_test(
            request, bundle, request["selection"], effect_request,
            effect_receipt, observation,
            test_capability={"capability_id": "service-test-projection", "test_only": True},
        )
    except response_bridge.PresetError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _read_operator_recovery_grant(identity: Mapping[str, str], admission: Mapping[str, Any], record: Mapping[str, Any], *, now: str) -> dict[str, Any]:
    """PACKAGE INTERNAL: read a current TLS-sealed grant from canonical record facts."""
    receipt, request, recovery = record["effect_receipt"], record["effect_request"], record["recovery"]
    if (
        receipt["post_state"] != "execution_unknown"
        or receipt["action_receipt"] is not None
        or recovery["reconciliation_observed"] is not True
        or recovery["no_successor"] is not True
        or recovery["successor_run_id"] is not None
        or recovery["reconciliation_receipt_sha256"] is None
    ):
        raise RuntimeServiceError("recovery_authority_unavailable", "$.record.recovery")
    expected_cas = {"expected_state_version": receipt["state_version_after"], "expected_thread_generation": record["selection"]["thread_generation"]}
    body = {
        "admission_id": admission["admission_id"], "service_instance_id": identity["service_instance_id"],
        "binding_state_version": record["binding_state_version"], "binding_state_sha256": record["record_sha256"],
        "selection_sha256": operator_binding.digest(record["selection"]), "predecessor_run_id": receipt["run_id"],
        "predecessor_effect_request_sha256": request["request_sha256"], "predecessor_effect_receipt_sha256": receipt["receipt_sha256"],
        "reconciliation_receipt_sha256": recovery["reconciliation_receipt_sha256"], "expected_cas": expected_cas, "now": now,
    }
    try:
        grant = package_host.read_operator_recovery_lease_grant({key: identity[key] for key in ("workspace_id", "source_sha256", "candidate_sha256")}, body)
    except package_host.HostCapabilityError as exc:
        raise RuntimeServiceError("recovery_authority_unavailable", "$.recovery_grant") from exc
    predecessor_lease = request["lease"]
    if grant["fresh_lease"]["lease_id"] == predecessor_lease["lease_id"] or grant["fresh_lease"]["fencing_token"] <= predecessor_lease["fencing_token"]:
        raise RuntimeServiceError("recovery_authority_unavailable", "$.recovery_grant.fresh_lease")
    return grant


def _operator_identity(manifest: Mapping[str, Any]) -> dict[str, str]:
    runtime = manifest["runtime_manifest"]
    candidate = runtime["candidate_sha256"]
    return {
        "workspace_id": manifest["workspace_id"],
        "source_sha256": runtime["source_sha256"],
        "candidate_sha256": candidate,
        "service_instance_id": "operator-" + candidate[7:23],
    }


def _projection_times(now: str | None) -> tuple[str, str]:
    if now is None:
        instant = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    else:
        try:
            instant = datetime.fromisoformat(now[:-1] + "+00:00").astimezone(timezone.utc)
        except (AttributeError, ValueError) as exc:
            raise RuntimeServiceError("projection_time_invalid", "$.now") from exc
    return (
        instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
        (instant + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _projection_ids(identity: Mapping[str, str], record: Mapping[str, Any] | None, issued_at: str) -> tuple[str, str]:
    version = 0 if record is None else record["binding_state_version"]
    state_sha = effect_gateway.ZERO_SHA256 if record is None else record["record_sha256"]
    seed = operator_binding.digest({
        "workspace_id": identity["workspace_id"], "candidate_sha256": identity["candidate_sha256"],
        "binding_state_version": version, "binding_state_sha256": state_sha,
        "issued_at": issued_at,
        "used_view_count": 0 if record is None else len(record["used_view_nonces"]),
    })
    return "projection-" + seed[7:23], "view-" + seed[23:39]


def operator_status_workspace(workspace: str | Path) -> dict[str, Any]:
    """Return a truthful disabled view until package capabilities are admitted."""
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    issued_at, expires_at = _projection_times(None)
    try:
        admission = operator_binding.resolve_package_admission(**identity, now=issued_at)
    except operator_binding.BindingError:
        admission = None
    record = None
    effect_state = None
    recovery_grant = None
    if admission is not None:
        workspace_fd = _open_workspace_directory(_absolute_workspace_path(workspace))
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                effect_state = _read_effect_state(workspace_fd, manifest["workspace_id"])
                try:
                    record = _read_operator_binding_record(workspace_fd, admission, now=issued_at)
                except RuntimeServiceError as exc:
                    if exc.code != "operator_binding_unavailable":
                        raise
                if record is not None and record["effect_receipt"]["post_state"] == "execution_unknown":
                    try:
                        recovery_grant = _read_operator_recovery_grant(identity, admission, record, now=issued_at)
                    except RuntimeServiceError:
                        recovery_grant = None
            finally:
                os.close(lock_fd)
        finally:
            os.close(workspace_fd)
    projection_id, view_nonce = _projection_ids(identity, record, issued_at)
    try:
        return operator_binding.build_projection_v3(
            **identity, projection_id=projection_id, view_nonce=view_nonce,
            issued_at=issued_at, expires_at=expires_at, record=record,
            admission=admission, _effect_state=effect_state,
            _recovery_grant=recovery_grant,
        )
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _operator_status_workspace_for_test(
    workspace: str | Path, admission_value: Mapping[str, Any], admission_verifier: Any,
    record_verifier: Any, projection_sealer: Any, *, now: str,
) -> dict[str, Any]:
    """TEST ONLY: prove the immutable binding with separately trusted admission."""
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    issued_at, expires_at = _projection_times(now)
    try:
        admission = operator_binding._resolve_package_admission_for_test(
            admission_value, **identity, now=issued_at, verifier=admission_verifier,
        )
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    workspace_fd = _open_workspace_directory(_absolute_workspace_path(workspace))
    try:
        record = operator_binding._validate_binding_record_structure(
            _read_operator_binding_record_raw(workspace_fd), admission, record_verifier,
        )
    finally:
        os.close(workspace_fd)
    projection_id, view_nonce = _projection_ids(identity, record, issued_at)
    try:
        return operator_binding._build_projection_for_test(
            **identity, projection_id=projection_id, view_nonce=view_nonce,
            issued_at=issued_at, expires_at=expires_at, record=record,
            admission=admission, sealer=projection_sealer,
        )
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc


def _persist_operator_binding_record_for_test(
    workspace: str | Path, record: Mapping[str, Any], admission_value: Mapping[str, Any],
    admission_verifier: Any, record_verifier: Any, *, now: str,
) -> None:
    """TEST ONLY: persist a validated record under the existing effect lock."""
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    try:
        admission = operator_binding._resolve_package_admission_for_test(
            admission_value, **identity, now=now, verifier=admission_verifier,
        )
        validated = operator_binding._validate_binding_record_structure(record, admission, record_verifier)
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    workspace_fd = _open_workspace_directory(_absolute_workspace_path(workspace))
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise RuntimeServiceError("effect_state_lock_unsafe", EFFECT_LOCK_FILENAME)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            _write_operator_binding_record(workspace_fd, validated)
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)


def _commit_operator_selection(
    workspace_path: Path, submission: dict[str, Any], identity: dict[str, str],
    admission: dict[str, Any], issued_at: str, expires_at: str,
) -> dict[str, Any]:
    """Package-only Select path sharing the effect lock but never effect state."""
    host_identity = {key: identity[key] for key in ("workspace_id", "source_sha256", "candidate_sha256")}
    submission_sha = operator_binding.digest(submission)
    lookup_body = {
        "admission_id": admission["admission_id"],
        "service_instance_id": identity["service_instance_id"],
        "submission_id": submission["submission_id"],
        "submission_sha256": submission_sha,
        "now": issued_at,
    }
    try:
        lookup = package_host.read_operator_selection_mutation(host_identity, lookup_body)
    except package_host.HostCapabilityError as exc:
        raise RuntimeServiceError(exc.code, "$.selection_lookup") from exc
    if lookup["status"] == "exact":
        mutation = lookup["receipt"]
        try:
            historic = _resolve_operator_catalog(
                identity, admission,
                binding_state_version=mutation["binding_state_version"],
                binding_state_sha256=mutation["binding_state_sha256"], now=issued_at,
                selector="historical", bundle_sha256=mutation["bundle_sha256"],
            )
            selected, _ = response_bridge.validate_selection(mutation["selection"], historic["bundle"])
        except response_bridge.PresetError as exc:
            raise RuntimeServiceError(exc.code, exc.path) from exc
        if (
            historic["receipt_sha256"] != mutation["catalog_receipt_sha256"]
            or historic["bundle_sha256"] != mutation["bundle_sha256"]
            or historic["bundle"]["generation"] != mutation["bundle_generation"]
            or selected["preset_id"] != submission["payload"]["preset_id"]
            or selected["expected_generation"] != submission["payload"]["expected_generation"]
            or mutation["bundle_generation"] != submission["payload"]["expected_generation"]
            or selected["thread_id"] == mutation["runtime_thread_id"]
            or selected["thread_generation"] <= mutation["runtime_thread_generation"]
        ):
            raise RuntimeServiceError("selection_receipt_mismatch", "$.selection_lookup")
        return operator_binding.validate_selection_transport_receipt({
            "schema_version": 1, "artifact_type": operator_binding.SELECTION_TRANSPORT_RECEIPT_TYPE,
            "submission_id": submission["submission_id"], "transport_accepted": True,
            "selection_mutation_receipt_sha256": mutation["receipt_sha256"],
            "selection_outcome": "unknown_until_status_refresh", "optimistic_state_change": False,
        })
    workspace_fd = _open_workspace_directory(workspace_path)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise RuntimeServiceError("effect_state_lock_unsafe", EFFECT_LOCK_FILENAME)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                record = _read_operator_binding_record(workspace_fd, admission, now=issued_at)
            except RuntimeServiceError as exc:
                if exc.code != "operator_binding_unavailable":
                    raise
                record = None
            projection_id, view_nonce = _projection_ids(identity, record, issued_at)
            try:
                effect_state = _read_effect_state(workspace_fd, identity["workspace_id"])
                projection = operator_binding.build_projection_v3(
                    **identity, projection_id=projection_id, view_nonce=view_nonce,
                    issued_at=issued_at, expires_at=expires_at, record=record,
                    admission=admission, _effect_state=effect_state,
                )
                accepted = operator_binding.validate_submission(submission, projection, record, now=issued_at)
            except operator_binding.BindingError as exc:
                raise RuntimeServiceError(exc.code, exc.path) from exc
            head = projection.get("active_selection", {}).get("head")
            catalog_view = projection.get("preset_catalog", {})
            if not isinstance(head, Mapping) or catalog_view.get("state") != "verified":
                raise RuntimeServiceError("preset_catalog_unavailable", "$.preset_catalog")
            current = head["selection"]
            body = {
                "admission_id": admission["admission_id"],
                "service_instance_id": identity["service_instance_id"],
                "binding_state_version": projection["binding_state_version"],
                "binding_state_sha256": projection["binding_state_sha256"],
                "runtime_thread_id": current["thread_id"],
                "runtime_thread_generation": current["thread_generation"],
                "selection_state_version": head["selection_state_version"],
                "current_selection_sha256": head["selection_sha256"],
                "preset_id": accepted["payload"]["preset_id"],
                "expected_generation": accepted["payload"]["expected_generation"],
                "submission_id": accepted["submission_id"],
                "submission_sha256": operator_binding.digest(accepted),
                "now": issued_at,
            }
            try:
                mutation = package_host.commit_operator_selection(host_identity, body)
                catalog_receipt = _resolve_operator_catalog(
                    identity, admission, binding_state_version=projection["binding_state_version"],
                    binding_state_sha256=projection["binding_state_sha256"], now=issued_at,
                    selector="current", bundle_sha256=None,
                )
                selection, _ = response_bridge.validate_selection(mutation["selection"], catalog_receipt["bundle"])
            except package_host.HostCapabilityError as exc:
                raise RuntimeServiceError(exc.code, "$.selection") from exc
            except response_bridge.PresetError as exc:
                raise RuntimeServiceError(exc.code, exc.path) from exc
            if (
                mutation["binding_state_version"] != projection["binding_state_version"]
                or mutation["binding_state_sha256"] != projection["binding_state_sha256"]
                or mutation["runtime_thread_id"] != current["thread_id"]
                or mutation["runtime_thread_generation"] != current["thread_generation"]
                or mutation["selection_state_version_before"] != head["selection_state_version"]
                or mutation["previous_selection_sha256"] != head["selection_sha256"]
                or mutation["catalog_receipt_sha256"] != catalog_receipt["receipt_sha256"]
                or mutation["bundle_sha256"] != catalog_receipt["bundle_sha256"]
                or mutation["bundle_generation"] != catalog_receipt["bundle"]["generation"]
                or selection["preset_id"] != accepted["payload"]["preset_id"]
                or selection["expected_generation"] != accepted["payload"]["expected_generation"]
                or selection["thread_id"] == current["thread_id"]
                or selection["thread_generation"] <= current["thread_generation"]
            ):
                raise RuntimeServiceError("selection_receipt_mismatch", "$.selection")
            return operator_binding.validate_selection_transport_receipt({
                "schema_version": 1,
                "artifact_type": operator_binding.SELECTION_TRANSPORT_RECEIPT_TYPE,
                "submission_id": accepted["submission_id"],
                "transport_accepted": True,
                "selection_mutation_receipt_sha256": mutation["receipt_sha256"],
                "selection_outcome": "unknown_until_status_refresh",
                "optimistic_state_change": False,
            })
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)


def operator_submit_workspace(workspace: str | Path, submission: Mapping[str, Any]) -> dict[str, Any]:
    """Submit through immutable package slots; absence fails before workspace I/O."""
    try:
        submission_row = operator_binding.validate_submission_shape(submission)
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    try:
        _PACKAGE_OPERATOR_CAPABILITY_PREFLIGHT()
    except Exception as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.admission") from exc
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    try:
        admission = operator_binding.resolve_package_admission(**identity, now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.admission") from exc
    issued_at, expires_at = _projection_times(None)
    workspace_path = _absolute_workspace_path(workspace)
    if submission_row["action"] == "select":
        return _commit_operator_selection(
            workspace_path, submission_row, identity, admission, issued_at, expires_at,
        )
    dispatcher = operator_binding._PACKAGE_CONTROL_DISPATCHER
    if dispatcher is None or not callable(dispatcher):
        raise RuntimeServiceError("production_capability_unavailable", "$.admission")
    workspace_fd = _open_workspace_directory(workspace_path)
    try:
        try:
            record = _read_operator_binding_record(workspace_fd, admission, now=issued_at)
        except RuntimeServiceError as exc:
            if exc.code != "operator_binding_unavailable":
                raise
            record = None
    finally:
        os.close(workspace_fd)
    if record is not None:
        replay = next((item for item in record["submission_replays"] if item["submission_id"] == submission_row["submission_id"]), None)
        if replay is not None:
            if replay["submission_sha256"] != operator_binding.digest(submission_row):
                raise RuntimeServiceError("control_submission_collision", "$.submission.submission_id")
            try:
                return operator_binding.validate_transport_receipt(replay["transport_receipt"])
            except operator_binding.BindingError as exc:
                raise RuntimeServiceError(exc.code, exc.path) from exc
    projection_id, view_nonce = _projection_ids(identity, record, issued_at)
    authority_workspace_fd = _open_workspace_directory(workspace_path)
    authority_lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        authority_lock_fd = os.open(EFFECT_LOCK_FILENAME, authority_lock_flags, 0o600, dir_fd=authority_workspace_fd)
        try:
            fcntl.flock(authority_lock_fd, fcntl.LOCK_EX)
            current_record = None
            try:
                current_record = _read_operator_binding_record(authority_workspace_fd, admission, now=issued_at)
            except RuntimeServiceError as exc:
                if exc.code != "operator_binding_unavailable":
                    raise
            if (record is None) != (current_record is None) or (record is not None and current_record["record_sha256"] != record["record_sha256"]):
                raise RuntimeServiceError("binding_cas_mismatch", OPERATOR_BINDING_FILENAME)
            record = current_record
            effect_state = _read_effect_state(authority_workspace_fd, identity["workspace_id"])
            recovery_grant = None
            if record is not None and record["effect_receipt"]["post_state"] == "execution_unknown":
                recovery_grant = _read_operator_recovery_grant(identity, admission, record, now=issued_at)
            projection = operator_binding.build_projection_v3(
                **identity, projection_id=projection_id, view_nonce=view_nonce,
                issued_at=issued_at, expires_at=expires_at, record=record,
                admission=admission, _effect_state=effect_state,
                _recovery_grant=recovery_grant,
            )
            accepted = operator_binding.validate_submission(submission_row, projection, record, now=issued_at)
        finally:
            os.close(authority_lock_fd)
        responses_request = dispatcher(accepted["action"], copy.deepcopy(accepted["payload"]), copy.deepcopy(record), copy.deepcopy(identity), copy.deepcopy(recovery_grant))
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    except RuntimeServiceError:
        raise
    except Exception as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.dispatcher") from exc
    finally:
        os.close(authority_workspace_fd)
    reserved = None if record is None else operator_binding.apply_transport_acceptance(record, accepted)
    if record is not None:
        workspace_fd = _open_workspace_directory(workspace_path)
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                current = _read_operator_binding_record(workspace_fd, admission, now=issued_at)
                if current["record_sha256"] != record["record_sha256"]:
                    raise RuntimeServiceError("binding_cas_mismatch", OPERATOR_BINDING_FILENAME)
                _write_operator_binding_record(workspace_fd, reserved)
            finally:
                os.close(lock_fd)
        finally:
            os.close(workspace_fd)
    if accepted["action"] == "run":
        catalog_receipt = _resolve_operator_catalog(
            identity, admission, binding_state_version=projection["binding_state_version"],
            binding_state_sha256=projection["binding_state_sha256"], now=issued_at,
            selector="current", bundle_sha256=None,
        )
        active_selection = projection["active_selection"]["head"]["selection"]
        if responses_request.get("selection") != active_selection:
            raise RuntimeServiceError("preset_selection_stale", "$.responses_request.selection")
        resolved_bundle = catalog_receipt["bundle"]
    else:
        historic_sha = record["responses_request"]["selection"]["bundle_sha256"]
        if historic_sha == response_bridge.DEFAULT_PRESET_BUNDLE["bundle_sha256"]:
            resolved_bundle = response_bridge.DEFAULT_PRESET_BUNDLE
        else:
            resolved_bundle = _resolve_operator_catalog(
                identity, admission, binding_state_version=projection["binding_state_version"],
                binding_state_sha256=projection["binding_state_sha256"], now=issued_at,
                selector="historical", bundle_sha256=historic_sha,
            )["bundle"]
        if responses_request.get("selection") != record["selection"]:
            raise RuntimeServiceError("preset_selection_stale", "$.responses_request.selection")
    artifacts = _execute_responses_workspace_artifacts(workspace, responses_request, resolved_bundle)
    recovery = {
        "reconciliation_observed": artifacts["effect_receipt"]["operation"] == "recover",
        "reconciliation_receipt_sha256": artifacts["effect_receipt"]["receipt_sha256"] if artifacts["effect_receipt"]["operation"] == "recover" else None,
        "no_successor": artifacts["effect_receipt"]["operation"] != "recover",
        "fresh_lease_id": artifacts["effect_receipt"]["lease"]["lease_id"],
        "fresh_fencing_token": artifacts["effect_receipt"]["lease"]["fencing_token"],
        "successor_run_id": artifacts["effect_receipt"]["run_id"] if artifacts["effect_receipt"]["operation"] == "recover" else None,
    }
    try:
        updated = operator_binding._create_binding_record_with_resolved_bundle(
            record_id="record-" + artifacts["effect_receipt"]["receipt_sha256"][7:23],
            service_instance_id=identity["service_instance_id"], admission=admission,
            **artifacts, now=issued_at,
            cursor={"sequence": (0 if record is None else len(record["submission_replays"])) + 1, "stable": True, "receipt_sha256": artifacts["bridge_receipt"]["receipt_sha256"]},
            recovery=recovery,
            binding_state_version=artifacts["effect_receipt"]["state_version_after"],
            bundle=resolved_bundle,
        )
        transport_receipt = {
            "schema_version": 1, "artifact_type": operator_binding.TRANSPORT_RECEIPT_TYPE,
            "submission_id": accepted["submission_id"], "transport_accepted": True,
            "effect_outcome": "unknown_until_status_refresh", "optimistic_state_change": False,
        }
        updated["submission_replays"] = [
            *( [] if record is None else record["submission_replays"]),
            {
                "submission_id": accepted["submission_id"],
                "submission_sha256": operator_binding.digest(accepted),
                "transport_receipt": copy.deepcopy(transport_receipt),
            },
        ]
        updated["used_view_nonces"] = [*([] if record is None else record["used_view_nonces"]), accepted["view_nonce"]]
        updated["pending_submission"] = None
        updated["record_sha256"] = operator_binding.digest({key: item for key, item in updated.items() if key != "record_sha256"})
        operator_binding._validate_binding_record_with_resolved_bundle(updated, admission, resolved_bundle, now=issued_at)
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    workspace_fd = _open_workspace_directory(workspace_path)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if reserved is not None:
                current = _read_operator_binding_record(workspace_fd, admission, now=issued_at)
                if current["record_sha256"] != reserved["record_sha256"]:
                    raise RuntimeServiceError("binding_cas_mismatch", OPERATOR_BINDING_FILENAME)
            _write_operator_binding_record(workspace_fd, updated)
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)
    return transport_receipt


def _operator_submit_workspace_for_test(
    workspace: str | Path, submission: Mapping[str, Any], admission_value: Mapping[str, Any],
    admission_verifier: Any, record_verifier: Any, projection_sealer: Any, *, now: str,
) -> dict[str, Any]:
    """TEST ONLY: accept transport and replay state without claiming an effect."""
    projection = _operator_status_workspace_for_test(
        workspace, admission_value, admission_verifier, record_verifier, projection_sealer, now=now,
    )
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    try:
        admission = operator_binding._resolve_package_admission_for_test(
            admission_value, **identity, now=now, verifier=admission_verifier,
        )
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError(exc.code, exc.path) from exc
    workspace_fd = _open_workspace_directory(_absolute_workspace_path(workspace))
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(EFFECT_LOCK_FILENAME, lock_flags, 0o600, dir_fd=workspace_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            record = operator_binding._validate_binding_record_structure(
                _read_operator_binding_record_raw(workspace_fd), admission, record_verifier,
            )
            try:
                accepted = operator_binding.validate_submission(submission, projection, record, now=now)
                updated = operator_binding.apply_transport_acceptance(record, accepted)
                operator_binding._validate_binding_record_structure(updated, admission, record_verifier)
            except operator_binding.BindingError as exc:
                raise RuntimeServiceError(exc.code, exc.path) from exc
            _write_operator_binding_record(workspace_fd, updated)
        finally:
            os.close(lock_fd)
    finally:
        os.close(workspace_fd)
    return {
        "schema_version": 1, "artifact_type": "standalone_operator_control_transport_receipt_v1",
        "submission_id": accepted["submission_id"], "transport_accepted": True,
        "effect_outcome": "unknown_until_status_refresh", "optimistic_state_change": False,
    }


def handle_operator_request(
    workspace: str | Path, method: str, path: str, body: Mapping[str, Any] | None = None,
) -> dict[str, Any] | bytes:
    """Closed fixed-route handler; no caller origin, URL, or transport exists."""
    route = operator_binding.FIXED_ROUTES.get((method, path))
    if route is None or "?" in path or "#" in path:
        raise RuntimeServiceError("operator_route_not_found", "$.path")
    if route in {"assets", "app_js", "styles_css"}:
        if body is not None:
            raise RuntimeServiceError("operator_request_invalid", "$.body")
        filename = {"assets": "index.html", "app_js": "app.js", "styles_css": "styles.css"}[route]
        asset = Path(__file__).resolve().parents[1] / "assets/operator/standalone-runtime" / filename
        return asset.read_bytes()
    if route == "status":
        if body is not None:
            raise RuntimeServiceError("operator_request_invalid", "$.body")
        return operator_status_workspace(workspace)
    if body is None:
        raise RuntimeServiceError("operator_request_invalid", "$.body")
    return operator_submit_workspace(workspace, body)


def start_operator_listener(workspace: str | Path) -> dict[str, Any]:
    """Return package-host admission only; this service never binds HTTP."""
    starter = _PACKAGE_OPERATOR_LISTENER_FACTORY
    if starter is None or not callable(starter):
        raise RuntimeServiceError("production_capability_unavailable", "$.listener")
    try:
        _PACKAGE_OPERATOR_CAPABILITY_PREFLIGHT()
    except Exception as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.listener") from exc
    manifest, _ = load_manifest(workspace)
    identity = _operator_identity(manifest)
    try:
        operator_binding.resolve_package_admission(**identity, now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    except operator_binding.BindingError as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.listener") from exc
    try:
        return starter(copy.deepcopy(identity))
    except Exception as exc:
        raise RuntimeServiceError("production_capability_unavailable", "$.listener") from exc


# Small public aliases keep the in-process surface aligned with CLI verbs.
inspect = inspect_workspace
reconnect = reconnect_workspace
shutdown = shutdown_workspace


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("operation", choices=("inspect", "reconnect", "shutdown", "operator-listen"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        operation = {
            "inspect": inspect_workspace,
            "reconnect": reconnect_workspace,
            "shutdown": shutdown_workspace,
            "operator-listen": start_operator_listener,
        }[args.operation]
        result = operation(args.workspace)
    except RuntimeServiceError as exc:
        error = {
            "service_version": SERVICE_VERSION,
            "artifact_type": ERROR_ARTIFACT_TYPE,
            "code": exc.code,
            "path": exc.path,
            "side_effect_free": True,
        }
        print(json.dumps(error, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
