#!/usr/bin/env python3
"""Candidate-resident fourteen-operation package-host journey control."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from datetime import datetime, timezone
from types import ModuleType
from typing import Any, Callable, Mapping

from supported_host_candidate_admission_v1 import (
    CandidateAdmissionError,
    VerifiedSelectedCandidate,
)

DEPLOYMENT_ADMISSION_PROTOCOL = "supported_host_deployment_admission_v2"


SCRIPT_PATH = Path(__file__).resolve()
SOURCE_REPOSITORY_ROOT = (
    SCRIPT_PATH.parents[3]
    if SCRIPT_PATH.parent.name == "scripts"
    and SCRIPT_PATH.parents[1].name == "codexmax-orchestrator"
    and SCRIPT_PATH.parents[2].name == "plugins"
    else None
)
DEPENDENCY_GRAPH = {
    "read_capability_admission": (),
    "open_operator_listener": ("read_capability_admission",),
    "read_operator_preset_bundle": ("open_operator_listener",),
    "read_operator_selection_head": ("read_operator_preset_bundle",),
    "read_operator_selection_mutation": ("read_operator_selection_head",),
    "commit_operator_selection": ("read_operator_selection_mutation",),
    "read_operator_supervision": ("commit_operator_selection",),
    "issue_responses_context": ("read_operator_supervision",),
    "verify_effect_authority": ("issue_responses_context",),
    "invoke_registered_action": ("verify_effect_authority",),
    "verify_responses_bridge": ("invoke_registered_action", "issue_responses_context"),
    "commit_or_verify_record": ("verify_responses_bridge",),
    "seal_or_verify_projection": ("commit_or_verify_record",),
    "read_operator_recovery_lease_grant": ("seal_or_verify_projection",),
}
SEMANTIC_OPERATIONS = tuple(DEPENDENCY_GRAPH)
SERVICE_OWNED_OPERATIONS = frozenset({"read_capability_admission", "open_operator_listener"})
EXTERNAL_OPERATIONS = tuple(
    operation for operation in SEMANTIC_OPERATIONS
    if operation not in SERVICE_OWNED_OPERATIONS
)
PHASED_BINDING_OPERATIONS = frozenset(EXTERNAL_OPERATIONS)
ADAPTER_PATH = "scripts/package_host_capability_adapter.py"
JOURNEY_PATH = "tools/package_host_production_journey_v1.py"
TRUST_PATH = "assets/runtime/package-host-trust-v1.json"
CA_PATH = "assets/runtime/package-host-ca.pem"
CAPABILITIES_PATH = "assets/runtime/package-host-capabilities-v1.json"
ACTION_PATH = "assets/runtime/action-profile-v1.json"
PRODUCER_PATH = "assets/runtime/producer-policy-v1.json"
PRODUCER_VALIDATOR_PATH = "src/codexmax_package_host/producer_policy_v1.py"
PRODUCER_VALIDATOR_SHA256 = "sha256:4c1368e2be3f83eb2ae6589e97581f3add4c4bb0d558a9633b585db22ad50cb2"
MANIFEST_PATH = "manifest.json"
PROFILE_PATH = "profile.json"
MAX_FILE_BYTES = 8 * 1024 * 1024
WORKSPACE_ID = "codexmax-external-workspace-v1"
SERVICE_INSTANCE_ID = "codexmax-external-service-v1"
EXTERNAL_HOST_ID = "codexmax-package-host-external"
EXTERNAL_HOST_BUILD_PREFIX = "codexmax-package-host-external-deployment-"
VERIFIED_ROOT_TARGET = re.compile(r"^verified-root:[1-9][0-9]*:[1-9][0-9]*$")
EXTERNAL_HOST_BUILD = EXTERNAL_HOST_BUILD_PREFIX + "generation"
EXTERNAL_RUNNER_TARGET = "verified-root:1:1"
CANONICAL_ROUTES = [
    {"method": "GET", "path": "/operator/v1/", "handler": "assets"},
    {"method": "GET", "path": "/operator/v1/app.js", "handler": "app_js"},
    {"method": "GET", "path": "/operator/v1/styles.css", "handler": "styles_css"},
    {"method": "GET", "path": "/operator/v1/status", "handler": "status"},
    {"method": "POST", "path": "/operator/v1/submit", "handler": "submit"},
]


class JourneyError(RuntimeError):
    def __init__(self, code: str, operation: str | None = None) -> None:
        self.code = code
        self.operation = operation
        super().__init__(code)


def validate_selected_candidate_for_journey(
    selected_candidate: VerifiedSelectedCandidate,
    deployment_admission: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Require the same opaque candidate binding before a live journey."""
    if type(selected_candidate) is not VerifiedSelectedCandidate:
        raise JourneyError("journey_selected_candidate_source_required")
    try:
        return selected_candidate.bind_admission(deployment_admission)
    except CandidateAdmissionError as exc:
        raise JourneyError(exc.code) from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(_canonical(value))


def _read_candidate_file(root_fd: int, relative: str) -> bytes:
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts) or relative.startswith("/") or "\\" in relative:
        raise JourneyError("candidate_path_invalid")
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
            os.close(current)
            current = child
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size < 0 or before.st_size > MAX_FILE_BYTES or before.st_mode & 0o022:
                raise JourneyError("candidate_file_invalid")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise JourneyError("candidate_file_truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_nlink, value.st_mode, value.st_size, value.st_mtime_ns)
            if identity(before) != identity(after):
                raise JourneyError("candidate_file_drift")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(current)


def _json(raw: bytes, code: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise JourneyError(code)
            result[key] = item
        return result
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(JourneyError(code)))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JourneyError(code) from exc
    if not isinstance(value, dict):
        raise JourneyError(code)
    if raw not in {_canonical(value), _canonical(value) + b"\n"}:
        raise JourneyError(code)
    return value


def _sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(character in "0123456789abcdef" for character in value[7:])


def _load_policy_validator(candidate_root: Path, validator_bytes: bytes) -> tuple[Any, type[BaseException]]:
    path = (candidate_root / PRODUCER_VALIDATOR_PATH).resolve()
    source_validator = (
        SOURCE_REPOSITORY_ROOT
        / "companion/package-host/src/codexmax_package_host/producer_policy_v1.py"
        if SOURCE_REPOSITORY_ROOT is not None
        else None
    )
    if (SOURCE_REPOSITORY_ROOT is not None and candidate_root.resolve() == SOURCE_REPOSITORY_ROOT) or candidate_root.resolve() not in path.parents or (source_validator is not None and path == source_validator) or "fixtures" in path.parts or "tests" in path.parts:
        raise JourneyError("producer_policy_validator_resolution_rejected")
    if _digest_bytes(validator_bytes) != PRODUCER_VALIDATOR_SHA256:
        raise JourneyError("producer_policy_validator_identity_mismatch")
    module = ModuleType("codexmax_candidate_producer_policy_v1")
    module.__file__ = str(path)
    module.__package__ = None
    try:
        code = compile(validator_bytes, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        raise JourneyError("producer_policy_validator_load_failed") from exc
    validator = getattr(module, "validate_producer_policy", None)
    error_type = getattr(module, "ProducerPolicyValidationError", None)
    if not callable(validator) or not isinstance(error_type, type) or not issubclass(error_type, BaseException):
        raise JourneyError("producer_policy_validator_interface_invalid")
    return validator, error_type


def _validate_candidate(candidate_root: Path, journey_file: Path) -> dict[str, Any]:
    resolved = candidate_root.resolve()
    resolved_journey = journey_file.resolve()
    if (SOURCE_REPOSITORY_ROOT is not None and resolved == SOURCE_REPOSITORY_ROOT) or "fixtures" in resolved.parts or "tests" in resolved.parts:
        raise JourneyError("candidate_resolution_rejected")
    if resolved_journey != resolved / JOURNEY_PATH:
        raise JourneyError("candidate_journey_path_invalid")
    root_fd = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        manifest = _json(_read_candidate_file(root_fd, MANIFEST_PATH), "candidate_manifest_invalid")
        profile = _json(_read_candidate_file(root_fd, PROFILE_PATH), "candidate_profile_invalid")
        entries = manifest.get("files")
        if set(manifest) != {"schema_version", "artifact_type", "profile_id", "base_candidate_sha256", "candidate_sha256", "files", "manifest_sha256"} or manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "codexmax_external_candidate_manifest_v1" or not isinstance(entries, list) or not entries:
            raise JourneyError("candidate_manifest_invalid")
        pins: dict[str, dict[str, Any]] = {}
        verified: dict[str, bytes] = {}
        for row in entries:
            if not isinstance(row, Mapping) or set(row) != {"path", "sha256", "size"} or row["path"] in pins:
                raise JourneyError("candidate_manifest_invalid")
            data = _read_candidate_file(root_fd, row["path"])
            if row["size"] != len(data) or row["sha256"] != _digest_bytes(data):
                raise JourneyError("candidate_manifest_drift")
            pins[row["path"]] = dict(row)
            verified[row["path"]] = data
        if [row["path"] for row in entries] != sorted(pins):
            raise JourneyError("candidate_manifest_invalid")
        required = {ADAPTER_PATH, JOURNEY_PATH, TRUST_PATH, CA_PATH, CAPABILITIES_PATH, ACTION_PATH, PRODUCER_PATH, PRODUCER_VALIDATOR_PATH, ".codex-plugin/release-manifest.json"}
        if set(pins) != required:
            raise JourneyError("candidate_manifest_inventory_invalid")
        if manifest.get("candidate_sha256") != _digest({"artifact_type": "codexmax_external_materialized_file_set_v1", "files": entries}):
            raise JourneyError("candidate_identity_invalid")
        if manifest.get("manifest_sha256") != _digest({key: item for key, item in manifest.items() if key != "manifest_sha256"}):
            raise JourneyError("candidate_manifest_digest_invalid")
        profile_fields = {
            "schema_version", "artifact_type", "profile_id", "host_id",
            "host_build", "runner_target", "service_instance_id", "expected_dns_san",
            "tls_minimum", "protocol_version", "source_sha256",
            "candidate_sha256", "manifest_sha256", "active_generation",
            "supported_host_profile_id", "supported_host_profile_sha256",
            "profile_sha256",
        }
        if set(profile) != profile_fields or profile.get("schema_version") != 2 or profile.get("artifact_type") != "codexmax_external_materialized_profile_v2":
            raise JourneyError("candidate_profile_invalid")
        if not isinstance(profile.get("runner_target"), str) or VERIFIED_ROOT_TARGET.fullmatch(profile["runner_target"]) is None:
            raise JourneyError("candidate_runner_target_invalid")
        if profile.get("host_id") != EXTERNAL_HOST_ID or not isinstance(profile.get("host_build"), str) or not profile["host_build"].startswith(EXTERNAL_HOST_BUILD_PREFIX):
            raise JourneyError("candidate_host_identity_invalid")
        if profile.get("profile_id") != manifest.get("profile_id") or profile.get("service_instance_id") != SERVICE_INSTANCE_ID or profile.get("expected_dns_san") != "codexmax-package-host.local" or profile.get("tls_minimum") != "TLSv1.3" or profile.get("protocol_version") != DEPLOYMENT_ADMISSION_PROTOCOL or type(profile.get("active_generation")) is not int or profile["active_generation"] < 1:
            raise JourneyError("candidate_profile_invalid")
        if not _sha(profile.get("source_sha256")) or profile.get("candidate_sha256") != manifest["candidate_sha256"] or profile.get("manifest_sha256") != manifest.get("manifest_sha256") or profile.get("profile_sha256") != _digest({key: item for key, item in profile.items() if key != "profile_sha256"}):
            raise JourneyError("candidate_profile_binding_invalid")
        trust = _json(verified[TRUST_PATH], "candidate_trust_invalid")
        capabilities = _json(verified[CAPABILITIES_PATH], "candidate_capabilities_invalid")
        action = _json(verified[ACTION_PATH], "candidate_action_profile_invalid")
        ca = verified[CA_PATH]
        validate_policy, policy_error = _load_policy_validator(resolved, verified[PRODUCER_VALIDATOR_PATH])
        producer_input = _json(verified[PRODUCER_PATH], "candidate_producer_policy_invalid")
        principal_map_present = producer_input.get("supported_host_principal_map") is not None
        trusted_profile_id = profile.get("supported_host_profile_id")
        trusted_profile_sha256 = profile.get("supported_host_profile_sha256")
        if principal_map_present:
            if trusted_profile_id is None or trusted_profile_sha256 is None:
                raise JourneyError("candidate_supported_host_profile_missing")
        elif trusted_profile_id is not None or trusted_profile_sha256 is not None:
            raise JourneyError("candidate_supported_host_profile_unbound")
        try:
            producer = validate_policy(
                producer_input,
                expected_ca_sha256=_digest_bytes(ca),
                expected_host_profile_id=trusted_profile_id,
                expected_host_profile_sha256=trusted_profile_sha256,
            )
        except policy_error as exc:
            dependency_codes = {"producer_policy_dependencies_invalid", "producer_policy_dependency_cycle"}
            code = "candidate_producer_policy_dependency_invalid" if getattr(exc, "code", None) in dependency_codes else "candidate_producer_policy_invalid"
            raise JourneyError(code) from exc
        if not isinstance(producer, dict):
            raise JourneyError("candidate_producer_policy_invalid")
        observed_dependencies = {
            row["operation"]: tuple(row["dependency_operations"])
            for row in producer["evidence_policy"]
        }
        if observed_dependencies != DEPENDENCY_GRAPH:
            raise JourneyError("candidate_producer_policy_dependency_invalid")
        release_pins = _json(verified[".codex-plugin/release-manifest.json"], "candidate_release_pins_invalid")
        expected_release_pins = [
            {"path": path, "sha256": pins[path]["sha256"].removeprefix("sha256:"), "size": pins[path]["size"]}
            for path in (TRUST_PATH, CA_PATH, CAPABILITIES_PATH)
        ]
        trust_fields = {"schema_version", "artifact_type", "configured", "test_only", "host_id", "socket_path", "expected_dns_san", "ca_pem_sha256", "tls_minimum", "protocol_version", "config_sha256"}
        if (
            set(trust) != trust_fields
            or trust.get("schema_version") != 1
            or trust.get("artifact_type") != "package_host_trust_v1"
            or trust.get("configured") is not True
            or trust.get("test_only") is not False
            or trust.get("tls_minimum") != "TLSv1.3"
            or trust.get("protocol_version") != 1
            or trust.get("ca_pem_sha256") != _digest_bytes(ca)
            or trust.get("config_sha256") != _digest({key: item for key, item in trust.items() if key != "config_sha256"})
            or trust.get("expected_dns_san") != "codexmax-package-host.local"
            or not isinstance(trust.get("socket_path"), str)
            or not trust["socket_path"].endswith("/Library/Application Support/Codexmax/package-host/v1/package-host.sock")
        ):
            raise JourneyError("candidate_trust_invalid")
        mapping = capabilities.get("operation_mapping")
        capability_fields = {"schema_version", "artifact_type", "configured", "action_registrations", "capability_ids", "operation_mapping", "config_sha256"}
        if set(capabilities) != capability_fields or capabilities.get("schema_version") != 1 or capabilities.get("artifact_type") != "package_host_capabilities_v1" or capabilities.get("configured") is not True or not isinstance(mapping, Mapping) or set(mapping) != set(SEMANTIC_OPERATIONS) or any(key != value for key, value in mapping.items()) or capabilities.get("config_sha256") != _digest({key: item for key, item in capabilities.items() if key != "config_sha256"}):
            raise JourneyError("candidate_capabilities_invalid")
        if release_pins.get("release") is not False or release_pins.get("files") != expected_release_pins:
            raise JourneyError("candidate_release_pins_invalid")
        if set(action) != {"schema_version", "artifact_type", "configured", "operations"} or action.get("schema_version") != 1 or action.get("artifact_type") != "package_host_action_profile_v1" or action.get("configured") is not True or action.get("operations") != sorted(SEMANTIC_OPERATIONS):
            raise JourneyError("candidate_action_profile_invalid")
        return {
            "root": resolved,
            "manifest": manifest,
            "profile": profile,
            "trust": trust,
            "capabilities": capabilities,
            "producer_policy": producer,
            "supported_host_profile": {
                "profile_id": trusted_profile_id,
                "profile_sha256": trusted_profile_sha256,
                "state": "qualified" if principal_map_present else "missing",
            },
            "adapter_bytes": verified[ADAPTER_PATH],
            "paths": {path: {"relative_path": path, "sha256": pins[path]["sha256"]} for path in sorted(required)},
        }
    finally:
        os.close(root_fd)


def _load_adapter(candidate_root: Path, adapter_bytes: bytes) -> ModuleType:
    path = (candidate_root / ADAPTER_PATH).resolve()
    source_adapter = (
        SOURCE_REPOSITORY_ROOT
        / "plugins/codexmax-orchestrator/scripts/package_host_capability_adapter.py"
        if SOURCE_REPOSITORY_ROOT is not None
        else None
    )
    if candidate_root.resolve() not in path.parents or (source_adapter is not None and path == source_adapter) or "fixtures" in path.parts or "tests" in path.parts:
        raise JourneyError("adapter_resolution_rejected")
    module = ModuleType("codexmax_candidate_package_host_adapter")
    module.__file__ = str(path)
    module.__package__ = None
    try:
        code = compile(adapter_bytes, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        raise JourneyError("adapter_load_failed") from exc
    if Path(module.__file__).resolve() != path or Path(module._PACKAGE_ROOT).resolve() != candidate_root.resolve() or hasattr(module, "PRODUCTION_ADAPTER") or not hasattr(module, "require_configured"):
        raise JourneyError("adapter_resolution_rejected")
    return module


def run_candidate(
    candidate_root: Path,
    journey_file: Path,
    *,
    execute_calls: bool = True,
    phased_binding_coordinator: Callable[[str, Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    checked = _validate_candidate(candidate_root, journey_file)
    if not execute_calls:
        return {
            "artifact_type": "codexmax_package_host_production_journey_check_v1",
            "state": "candidate_ready",
            "operation_count": len(SEMANTIC_OPERATIONS),
            "operations": list(SEMANTIC_OPERATIONS),
            "candidate_sha256": checked["manifest"]["candidate_sha256"],
            "candidate_paths": checked["paths"],
            "phase_boundary": _phase_boundary(checked),
            "writes": False,
        }
    adapter = _load_adapter(checked["root"], checked["adapter_bytes"])
    adapter.require_configured()
    return _run_adapter_journey(adapter, checked, phased_binding_coordinator)


def _now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _phase_boundary(checked: Mapping[str, Any] | None = None) -> dict[str, Any]:
    profile_state = (
        checked["supported_host_profile"]["state"]
        if checked is not None else "candidate_not_loaded"
    )
    return {
        "service_owned_current_start": list(operation for operation in SEMANTIC_OPERATIONS if operation in SERVICE_OWNED_OPERATIONS),
        "external_supported_host_live": list(EXTERNAL_OPERATIONS),
        "supported_host_profile_state": profile_state,
        "fixtures_establish_live_readiness": False,
    }


def _admission(value: Any, identity: Mapping[str, Any], checked: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version", "artifact_type", "admission_id", "issuer_id",
        "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id",
        "capability_ids", "binding_state_version", "binding_state_sha256",
        "durable_index_sha256", "admission_sha256",
        "producer_policy_sha256", "missing_producer_operations", "issued_at",
        "expires_at", "revoked", "seal",
    }
    if not isinstance(value, Mapping) or set(value) != fields or value.get("schema_version") != 1 or value.get("artifact_type") != "standalone_operator_capability_admission_v1":
        raise JourneyError("capability_admission_invalid", "read_capability_admission")
    row = dict(value)
    if any(row.get(field) != identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")) or row.get("service_instance_id") != SERVICE_INSTANCE_ID:
        raise JourneyError("capability_admission_identity_mismatch", "read_capability_admission")
    if (
        type(row.get("binding_state_version")) is not int
        or row["binding_state_version"] < 0
        or not _sha(row.get("binding_state_sha256"))
        or not _sha(row.get("durable_index_sha256"))
        or not _sha(row.get("admission_sha256"))
        or row["admission_sha256"] != _digest({
            key: item for key, item in row.items()
            if key not in {"seal", "admission_sha256"}
        })
    ):
        raise JourneyError("capability_admission_binding_invalid", "read_capability_admission")
    if row.get("producer_policy_sha256") != checked["producer_policy"]["policy_sha256"]:
        raise JourneyError("capability_admission_policy_mismatch", "read_capability_admission")
    expected = sorted(SEMANTIC_OPERATIONS)
    missing = row.get("missing_producer_operations")
    if not isinstance(missing, list) or missing != sorted(missing) or len(missing) != len(set(missing)) or any(item not in expected for item in missing):
        raise JourneyError("capability_admission_missing_invalid", "read_capability_admission")
    if not _sha(row.get("seal")) or row["revoked"] is not False:
        raise JourneyError("capability_admission_invalid", "read_capability_admission")
    return row


def _observe(observations: dict[str, dict[str, Any]], operation: str, result: Any) -> Any:
    dependencies = DEPENDENCY_GRAPH[operation]
    observations[operation] = {
        "operation": operation,
        "dependency_response_sha256": [observations[item]["response_sha256"] for item in dependencies],
        "response_sha256": _digest(result),
        "status": "authenticated_service_result",
    }
    return result


def _bind_phased_operation(
    adapter: ModuleType,
    coordinator: Callable[[str, Mapping[str, Any]], Any],
    operation: str,
    operation_body: Mapping[str, Any],
    identity: Mapping[str, Any],
    admission: Mapping[str, Any],
    observations: dict[str, dict[str, Any]],
    checked: Mapping[str, Any],
    now: str,
) -> dict[str, Any]:
    """Bind one request-dependent fact, then trust only refreshed admission."""
    if operation not in PHASED_BINDING_OPERATIONS:
        raise JourneyError("phased_binding_operation_invalid", operation)
    if operation not in admission["missing_producer_operations"]:
        return dict(admission)
    coordinator(operation, {
        "schema_version": 1,
        "artifact_type": "codexmax_package_host_phased_binding_input_v1",
        "operation": operation,
        "identity": deepcopy(dict(identity)),
        "service_instance_id": SERVICE_INSTANCE_ID,
        "producer_policy_sha256": admission["producer_policy_sha256"],
        "binding_state_version": admission["binding_state_version"],
        "previous_durable_index_sha256": admission["durable_index_sha256"],
        "previous_readiness_sha256": admission["binding_state_sha256"],
        "predecessor_admission_sha256": admission["admission_sha256"],
        "dependency_response_sha256": [
            observations[item]["response_sha256"]
            for item in DEPENDENCY_GRAPH[operation]
        ],
        "operation_body": deepcopy(dict(operation_body)),
        "operation_body_sha256": _digest(operation_body),
    })
    refreshed = _admission(
        adapter.read_capability_admission(identity, SERVICE_INSTANCE_ID, now),
        identity,
        checked,
    )
    previous_missing = set(admission["missing_producer_operations"])
    refreshed_missing = set(refreshed["missing_producer_operations"])
    if (
        refreshed["binding_state_version"] != admission["binding_state_version"] + 1
        or refreshed["binding_state_sha256"] == admission["binding_state_sha256"]
        or refreshed["durable_index_sha256"] == admission["durable_index_sha256"]
        or refreshed["admission_sha256"] == admission["admission_sha256"]
        or refreshed_missing != previous_missing - {operation}
    ):
        raise JourneyError("phased_binding_admission_mismatch", operation)
    _observe(observations, "read_capability_admission", refreshed)
    return refreshed


def _binding_common(admission: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "admission_id": admission["admission_id"],
        "service_instance_id": SERVICE_INSTANCE_ID,
        "binding_state_version": admission["binding_state_version"],
        "binding_state_sha256": admission["binding_state_sha256"],
    }


def _translate_effect(request: Mapping[str, Any], context: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
    selection = request["selection"]
    preset = next((row for row in bundle["presets"] if row.get("preset_id") == selection.get("preset_id") and row.get("family_id") == selection.get("family_id")), None)
    if not isinstance(preset, Mapping):
        raise JourneyError("responses_selection_unavailable", "issue_responses_context")
    effect = {
        "schema_version": 1, "artifact_type": "effect_kernel_request_v1",
        "request_id": request["request_id"], "idempotency_key": request["idempotency_key"],
        "operation": request["operation"], "workspace_id": request["workspace_id"],
        "goal_id": request["goal_id"], "task_id": request["task_id"], "actor": request["actor"],
        "authority_receipt": dict(context["authority_receipt"]), "source_bundle": dict(context["source_bundle"]),
        "thread_snapshot": dict(context["thread_snapshot"]),
        "preset_snapshot": {"preset_id": preset["preset_id"], "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "route_snapshot": {"route_id": preset["route"]["route_id"], "requested_model": preset["route"]["model_id"], "requested_host": preset["route"]["host_id"], "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "adapter_snapshot": {**dict(preset["adapter"]), "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "policy_snapshot": {**dict(preset["policy"]), "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "lease": dict(context["lease"]), "run": dict(context["run"]), "cas": dict(context["cas"]),
        "input": {"tool_id": preset["adapter"]["tool_id"], "parameters": {"message": "\n".join(item["content"] for item in request["input"])}},
        "created_at": request["created_at"], "request_sha256": "",
    }
    for field in ("preset_snapshot", "route_snapshot", "adapter_snapshot", "policy_snapshot"):
        effect[field]["snapshot_sha256"] = _digest({key: item for key, item in effect[field].items() if key != "snapshot_sha256"})
    effect["request_sha256"] = _digest({key: item for key, item in effect.items() if key != "request_sha256"})
    return effect


def _effect_receipt(effect: Mapping[str, Any], action: Mapping[str, Any]) -> dict[str, Any]:
    before = effect["cas"]["expected_state_version"]
    value = {
        "schema_version": 1, "artifact_type": "effect_kernel_receipt_v1",
        "request_id": effect["request_id"], "request_sha256": effect["request_sha256"],
        "operation": effect["operation"], "disposition": "observed",
        "run_id": effect["run"]["run_id"], "pre_state": "absent", "post_state": "running",
        "state_version_before": before, "state_version_after": before + 1,
        "action_receipt": dict(action),
        "route_requested": {"route_id": effect["route_snapshot"]["route_id"], "model": effect["route_snapshot"]["requested_model"], "host": effect["route_snapshot"]["requested_host"]},
        "route_observed": dict(action["observed_identity"]), "preset_snapshot": dict(effect["preset_snapshot"]),
        "lease": dict(effect["lease"]), "event_ids": [effect["request_id"] + ":requested", effect["request_id"] + ":observed"],
        "proof_boundary": "source_local_registered_action",
        "unknowns": [field for field, item in action["observed_identity"].items() if item == "unknown"],
        "receipt_sha256": "",
    }
    value["receipt_sha256"] = _digest({key: item for key, item in value.items() if key != "receipt_sha256"})
    return value


def _run_adapter_journey(
    adapter: ModuleType,
    checked: Mapping[str, Any],
    phased_binding_coordinator: Callable[[str, Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    identity = {"workspace_id": WORKSPACE_ID, "source_sha256": checked["profile"]["source_sha256"], "candidate_sha256": checked["manifest"]["candidate_sha256"]}
    now = _now_text()
    observations: dict[str, dict[str, Any]] = {}
    try:
        initial_admission = _admission(adapter.read_capability_admission(identity, SERVICE_INSTANCE_ID, now), identity, checked)
        _observe(observations, "read_capability_admission", initial_admission)
        listener = adapter.open_operator_listener(identity, SERVICE_INSTANCE_ID, list(CANONICAL_ROUTES))
        _observe(observations, "open_operator_listener", listener)
        admission = _admission(adapter.read_capability_admission(identity, SERVICE_INSTANCE_ID, now), identity, checked)
        initial_version = initial_admission["binding_state_version"]
        refreshed_version = admission["binding_state_version"]
        initial_digest = initial_admission["binding_state_sha256"]
        refreshed_digest = admission["binding_state_sha256"]
        if refreshed_version < initial_version or (refreshed_version == initial_version) != (refreshed_digest == initial_digest):
            raise JourneyError("capability_admission_binding_regressed", "read_capability_admission")
        if SERVICE_OWNED_OPERATIONS.intersection(admission["missing_producer_operations"]):
            raise JourneyError("service_owned_registration_incomplete", "read_capability_admission")
        if checked["producer_policy"]["supported_host_principal_map"] is None:
            return _live_blocked_receipt(
                admission, observations, checked,
                reason="missing_supported_host_profile",
                pending_operations=EXTERNAL_OPERATIONS,
            )
        missing = set(admission["missing_producer_operations"])
        if missing and phased_binding_coordinator is None:
            return _live_blocked_receipt(
                admission, observations, checked,
                reason="missing_authenticated_external_bindings",
                pending_operations=admission["missing_producer_operations"],
            )
        catalog_body = {**_binding_common(admission), "selector": "current", "bundle_sha256": None, "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "read_operator_preset_bundle",
                catalog_body, identity, admission, observations, checked, now,
            )
        catalog = adapter.read_operator_preset_bundle(identity, catalog_body)
        _observe(observations, "read_operator_preset_bundle", catalog)
        head_body = {**_binding_common(admission), "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "read_operator_selection_head",
                head_body, identity, admission, observations, checked, now,
            )
        head = adapter.read_operator_selection_head(identity, head_body)
        _observe(observations, "read_operator_selection_head", head)
        preset = next((item for item in catalog["bundle"]["presets"] if item.get("preset_id") != head["selection"].get("preset_id")), None)
        if not isinstance(preset, Mapping):
            raise JourneyError("selection_target_unavailable", "commit_operator_selection")
        submission_id = "t058-" + _digest({"candidate": identity["candidate_sha256"], "head": head["receipt_sha256"]})[7:39]
        expected_absence = {"status": "absent", "receipt": None}
        expected_absence_sha = _digest(expected_absence)
        submission_sha = _digest({"artifact_type": "codexmax_t058_causal_selection_v1", "submission_id": submission_id, "preset_id": preset["preset_id"], "expected_generation": catalog["catalog_generation"], "head_sha256": head["receipt_sha256"], "expected_mutation_absence_sha256": expected_absence_sha})
        mutation_lookup_body = {"admission_id": admission["admission_id"], "service_instance_id": SERVICE_INSTANCE_ID, "submission_id": submission_id, "submission_sha256": submission_sha, "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "read_operator_selection_mutation",
                mutation_lookup_body, identity, admission, observations, checked, now,
            )
        mutation_lookup = adapter.read_operator_selection_mutation(identity, mutation_lookup_body)
        if mutation_lookup != expected_absence or _digest(mutation_lookup) != expected_absence_sha:
            raise JourneyError("selection_mutation_absence_required", "read_operator_selection_mutation")
        _observe(observations, "read_operator_selection_mutation", mutation_lookup)
        commit_body = {**_binding_common(admission), "runtime_thread_id": head["selection"]["thread_id"], "runtime_thread_generation": head["selection"]["thread_generation"], "selection_state_version": head["selection_state_version"], "current_selection_sha256": head["selection_sha256"], "preset_id": preset["preset_id"], "expected_generation": catalog["catalog_generation"], "submission_id": submission_id, "submission_sha256": submission_sha, "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "commit_operator_selection",
                commit_body, identity, admission, observations, checked, now,
            )
        mutation = adapter.commit_operator_selection(identity, commit_body)
        _observe(observations, "commit_operator_selection", mutation)
        supervision_body = {**_binding_common(admission), "runtime_thread_id": mutation["selection"]["thread_id"], "runtime_thread_generation": mutation["selection"]["thread_generation"], "selection_sha256": mutation["selection_sha256"], "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "read_operator_supervision",
                supervision_body, identity, admission, observations, checked, now,
            )
        supervision = adapter.read_operator_supervision(identity, supervision_body)
        _observe(observations, "read_operator_supervision", supervision)
        responses_body = {
            "mode": "control", "responses_request": None,
            "control_action": "run",
            "control_payload": {"message": identity["candidate_sha256"]},
            "record_sha256": None, "service_instance_id": SERVICE_INSTANCE_ID,
            "recovery_grant_id": None, "recovery_grant_sha256": None,
        }
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "issue_responses_context",
                responses_body, identity, admission, observations, checked, now,
            )
        response_request = adapter.issue_responses_context(None, identity, control_action="run", control_payload={"message": identity["candidate_sha256"]}, record_sha256=None, service_instance_id=SERVICE_INSTANCE_ID)
        effect_context = adapter.issue_responses_context(response_request, identity)
        if response_request.get("selection") != mutation["selection"] or effect_context.get("thread_snapshot", {}).get("thread_id") != mutation["selection"]["thread_id"] or effect_context.get("thread_snapshot", {}).get("generation") != mutation["selection"]["thread_generation"]:
            raise JourneyError("causal_selection_chain_mismatch", "issue_responses_context")
        _observe(observations, "issue_responses_context", {"responses_request": response_request, "effect_context": effect_context})
        authority_body = {"authority": effect_context["authority_receipt"], "context": effect_context}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "verify_effect_authority",
                authority_body, identity, admission, observations, checked, now,
            )
        authorized = adapter.verify_effect_authority(effect_context["authority_receipt"], effect_context)
        if authorized is not True:
            raise JourneyError("effect_authority_denied", "verify_effect_authority")
        _observe(observations, "verify_effect_authority", {"authorized": True})
        effect_request = _translate_effect(response_request, effect_context, catalog["bundle"])
        action_body = {"action_id": effect_request["adapter_snapshot"]["action_id"], "operation": effect_request["operation"], "effect_request": effect_request}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "invoke_registered_action",
                action_body, identity, admission, observations, checked, now,
            )
        action = adapter.invoke_registered_action(effect_request["adapter_snapshot"]["action_id"], effect_request["operation"], effect_request)
        _observe(observations, "invoke_registered_action", action)
        effect_receipt = _effect_receipt(effect_request, action)
        bridge_body = {"mode": "issue", "responses_request": response_request, "effect_request": effect_request, "effect_receipt": effect_receipt, "bridge_receipt": None, "context": None}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "verify_responses_bridge",
                bridge_body, identity, admission, observations, checked, now,
            )
        bridge = adapter.issue_responses_bridge(response_request, effect_request, effect_receipt, identity)
        _observe(observations, "verify_responses_bridge", bridge)
        artifact_set_sha = _digest({"responses_request": response_request, "effect_request": effect_request, "effect_receipt": effect_receipt, "bridge_receipt": bridge})
        record_context = {
            **identity, "service_instance_id": SERVICE_INSTANCE_ID,
            "artifact_set_sha256": artifact_set_sha, "admission_seal": admission["seal"],
        }
        record_body = {"mode": "commit", "record": None, "context": record_context, "seal": None}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "commit_or_verify_record",
                record_body, identity, admission, observations, checked, now,
            )
        record_seal = adapter.commit_or_verify_record(identity, **record_body)
        _observe(observations, "commit_or_verify_record", record_seal)
        projection_context = {"admission_id": admission["admission_id"], "artifact_set_sha256": artifact_set_sha, "record_seal": record_seal["seal"]}
        projection_body = {"mode": "seal", "context": projection_context, "seal": None}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "seal_or_verify_projection",
                projection_body, identity, admission, observations, checked, now,
            )
        projection = adapter.seal_or_verify_projection(identity, **projection_body)
        _observe(observations, "seal_or_verify_projection", projection)
        supervision_receipt = supervision.get("receipt") if isinstance(supervision, Mapping) else None
        recovery_sha = supervision_receipt.get("recovery", {}).get("reconciliation_receipt_sha256") if isinstance(supervision_receipt, Mapping) else None
        common = {
            "admission_id": admission["admission_id"],
            "service_instance_id": SERVICE_INSTANCE_ID,
            "binding_state_version": admission["binding_state_version"],
            "binding_state_sha256": admission["binding_state_sha256"],
        }
        recovery_body = {**common, "selection_sha256": mutation["selection_sha256"], "predecessor_run_id": effect_request["run"]["run_id"], "predecessor_effect_request_sha256": effect_request["request_sha256"], "predecessor_effect_receipt_sha256": effect_receipt["receipt_sha256"], "reconciliation_receipt_sha256": recovery_sha, "expected_cas": dict(effect_context["cas"]), "now": now}
        if phased_binding_coordinator is not None:
            admission = _bind_phased_operation(
                adapter, phased_binding_coordinator, "read_operator_recovery_lease_grant",
                recovery_body, identity, admission, observations, checked, now,
            )
        recovery = adapter.read_operator_recovery_lease_grant(identity, recovery_body)
        if recovery["predecessor_run_id"] != effect_request["run"]["run_id"] or recovery["fresh_lease"]["fencing_token"] <= effect_request["lease"]["fencing_token"]:
            raise JourneyError("recovery_fence_invalid", "read_operator_recovery_lease_grant")
        _observe(observations, "read_operator_recovery_lease_grant", recovery)
    except JourneyError:
        raise
    except Exception as exc:
        operation = next((name for name in SEMANTIC_OPERATIONS if name not in observations), None)
        return _blocked_receipt(operation or "journey", getattr(exc, "code", "causal_operation_failed"), checked)
    ordered = [observations[name] for name in SEMANTIC_OPERATIONS]
    receipt = {
        "schema_version": 2,
        "artifact_type": "codexmax_package_host_production_journey_receipt_v2",
        "state": "complete",
        "candidate_sha256": checked["manifest"]["candidate_sha256"],
        "manifest_sha256": checked["manifest"]["manifest_sha256"],
        "host_id": checked["profile"]["host_id"],
        "host_build": checked["profile"]["host_build"],
        "runner_target": checked["profile"]["runner_target"],
        "operation_count": len(ordered),
        "operations": ordered,
        "transport": "AF_UNIX",
        "tls_minimum": "TLSv1.3",
        "expected_dns_san": checked["trust"]["expected_dns_san"],
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = _digest({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    return receipt


def _live_blocked_receipt(
    admission: Mapping[str, Any],
    observations: Mapping[str, Mapping[str, Any]],
    checked: Mapping[str, Any],
    *,
    reason: str,
    pending_operations: Any,
) -> dict[str, Any]:
    missing = sorted(pending_operations)
    if not missing or any(operation not in EXTERNAL_OPERATIONS for operation in missing):
        raise JourneyError("pending_external_operations_invalid", "read_capability_admission")
    value = {
        "schema_version": 2,
        "artifact_type": "codexmax_package_host_production_journey_receipt_v2",
        "state": "blocked_live_product_fact",
        "reason": reason,
        "candidate_sha256": checked["manifest"]["candidate_sha256"],
        "manifest_sha256": checked["manifest"]["manifest_sha256"],
        "host_id": checked["profile"]["host_id"],
        "host_build": checked["profile"]["host_build"],
        "runner_target": checked["profile"]["runner_target"],
        "producer_policy_sha256": admission["producer_policy_sha256"],
        "binding_state_version": admission["binding_state_version"],
        "binding_state_sha256": admission["binding_state_sha256"],
        "pending_operations": missing,
        "supported_host_profile": dict(checked["supported_host_profile"]),
        "phase_boundary": _phase_boundary(checked),
        "dependency_response_sha256": {
            operation: [observations[item]["response_sha256"] for item in DEPENDENCY_GRAPH[operation] if item in observations]
            for operation in missing
        },
        "receipt_sha256": "",
    }
    value["receipt_sha256"] = _digest({key: item for key, item in value.items() if key != "receipt_sha256"})
    return value


def _blocked_receipt(operation: str, reason: str, checked: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": 2,
        "artifact_type": "codexmax_package_host_production_journey_receipt_v2",
        "state": "blocked_live_product_fact",
        "blocked_operation": operation,
        "reason": reason,
        "candidate_sha256": checked["manifest"]["candidate_sha256"],
        "manifest_sha256": checked["manifest"]["manifest_sha256"],
        "host_id": checked["profile"]["host_id"],
        "host_build": checked["profile"]["host_build"],
        "runner_target": checked["profile"]["runner_target"],
        "receipt_sha256": "",
    }
    value["receipt_sha256"] = _digest({key: item for key, item in value.items() if key != "receipt_sha256"})
    return value


def check_only() -> dict[str, Any]:
    source = Path(__file__).read_bytes()
    return {
        "artifact_type": "codexmax_package_host_production_journey_source_check_v1",
        "state": "source_ready_candidate_not_loaded",
        "operation_count": len(SEMANTIC_OPERATIONS),
        "operations": list(SEMANTIC_OPERATIONS),
        "phase_boundary": _phase_boundary(),
        "source_sha256": _digest_bytes(source),
        "external_candidate_imported": False,
        "external_io": False,
        "writes": False,
    }


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        if values == ["--check-only"]:
            result = check_only()
        elif len(values) == 4 and values[:3:2] == ["--operations", "--tls-agent-ref"]:
            if values[1] != "all-14" or not values[3]:
                raise JourneyError("arguments_invalid")
            result = {
                "artifact_type": "codexmax_package_host_production_journey_external_gate_v1",
                "state": "external_action_required", "operation_count": 14,
                "operations": list(SEMANTIC_OPERATIONS), "opaque_tls_agent_required": True,
                "writes": False, "process_started": False, "socket_opened": False,
                "network_accessed": False, "external_action_performed": False,
            }
        elif not values:
            candidate_root = Path(__file__).resolve().parents[1]
            result = run_candidate(candidate_root, Path(__file__).resolve())
        else:
            raise JourneyError("arguments_invalid")
    except JourneyError as exc:
        print(json.dumps({"error": {"code": exc.code}}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if result.get("state") == "external_action_required":
        return 4
    return 3 if result.get("state") == "blocked_live_product_fact" else 0


if __name__ == "__main__":
    raise SystemExit(main())
