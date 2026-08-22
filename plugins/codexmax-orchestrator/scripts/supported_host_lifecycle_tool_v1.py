#!/usr/bin/env python3
"""Pure check-only lifecycle planning for the first-party supported host."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Sequence, TextIO

from supported_host_public_profile_v1 import (
    EXTERNAL_OPERATIONS,
    PENDING_STATE,
    PRINCIPAL_IDS,
    PublicProfileError,
    pending_public_profile,
    validate_candidate_selection,
    validate_public_profile,
)
from supported_host_operator_supervisor_v1 import (
    FD_ROLES,
    JOINT_AUTHORITY_ROLES,
    OPERATION_SOURCE_OWNERS,
    PROTECTED_SERVICE_PROTOCOL,
    PublicAuthorityError,
    SupervisorError,
    check_only_plan as supervisor_check_only_plan,
    prepare_lifecycle,
    validate_complete_start_authority,
    validate_public_request_fd,
)


_SERVICE_PROTOCOL = PROTECTED_SERVICE_PROTOCOL
_SERVICES = ("protected_writer", "independent_anchor", "opaque_tls_agent")
OPERATION_OWNER_IDS = OPERATION_SOURCE_OWNERS
JOINT_ROLES = JOINT_AUTHORITY_ROLES
_SERVICE_FIELDS = frozenset({
    "schema_version", "artifact_type", "service", "service_id", "service_build_sha256",
    "expected_uid", "expected_gid", "expected_service_start_id", "expected_service_session_id",
    "protocol_version", "max_frame_bytes",
})
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,255}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


LAYOUT = {
    "layout_id": "codexmax-first-party-supported-host-layout-v1",
    "runtime_root": "operator-controlled-runtime-root",
    "namespaces": [
        "action-observation", "catalog", "effect-authority", "native-inventory",
        "recovery", "responses-seals", "selection",
    ],
    "anchor_witness": "operator-controlled-independent-anchor-witness",
    "production_persistence_performed": False,
}

SOURCE_LOCAL_COMMAND = [
    "python3",
    "-B",
    "plugins/codexmax-orchestrator/scripts/supported_host_lifecycle_tool_v1.py",
]
CHECK_COMMANDS = frozenset({
    "check-candidate",
    "check-public-profile",
    "check-layout",
    "check-service-config",
    "render-runtime-plan",
    "render-procedure-commands",
})
EXTERNAL_ACTION_COMMANDS = frozenset({
    "install",
    "start",
    "validate-handshake",
    "admit",
    "run-journey",
    "stop",
    "inventory",
    "reconcile",
})
EXTERNAL_OPTION_SPEC = {
    "install": ("--candidate-descriptor-fd", "--runner-archive-fd", "--runner-sidecar-fd"),
    "start": (
        "--candidate-descriptor-fd", "--root-manifest-fd", "--runner-archive-fd", "--runner-sidecar-fd", "--supervisor-fds-json",
        "--tls-agent-ref", "--service-public-json", "--joint-authority-json",
        "--operation-source-service-json", "--operation-source-fds-json",
        "--raw-observation-fds-json", "--service-root-fds-json",
        "--deployment-admission-fd", "--runtime-root-fd",
    ),
    "validate-handshake": ("--candidate-descriptor-fd", "--runner-archive-fd", "--runner-sidecar-fd", "--supervisor-fds-json", "--public-request-fd", "--tls-agent-ref"),
    "admit": ("--candidate-descriptor-fd", "--runner-archive-fd", "--runner-sidecar-fd", "--supervisor-fds-json", "--public-request-fd"),
    "run-journey": ("--candidate-descriptor-fd", "--runner-archive-fd", "--runner-sidecar-fd", "--supervisor-fds-json", "--public-request-fd", "--operations", "--tls-agent-ref"),
    "stop": ("--candidate-descriptor-fd", "--runner-archive-fd", "--runner-sidecar-fd", "--supervisor-fds-json", "--public-request-fd"),
    "inventory": ("--check-only",),
    "reconcile": ("--check-only",),
}
HUMAN_COMMAND_ARGUMENTS = {
    "install": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>"),
    "start": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--root-manifest-fd", "<INHERITED_ROOT_MANIFEST_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>", "--supervisor-fds-json", "<INHERITED_SUPERVISOR_FDS_JSON>", "--tls-agent-ref", "<OPAQUE_TLS_AGENT_REF>", "--service-public-json", "<PUBLIC_SERVICE_CONFIG_JSON>", "--joint-authority-json", "<PUBLIC_JOINT_SERVICE_AUTHORITY_JSON>", "--operation-source-service-json", "<PUBLIC_OPERATION_SOURCE_SERVICE_JSON>", "--operation-source-fds-json", "<INHERITED_OPERATION_SOURCE_FDS_JSON>", "--raw-observation-fds-json", "<INHERITED_RAW_OBSERVATION_FDS_JSON>", "--service-root-fds-json", "<INHERITED_SERVICE_ROOT_FDS_JSON>", "--deployment-admission-fd", "<INHERITED_DEPLOYMENT_ADMISSION_FD>", "--runtime-root-fd", "<INHERITED_RUNTIME_ROOT_FD>"),
    "validate-handshake": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>", "--supervisor-fds-json", "<INHERITED_SUPERVISOR_FDS_JSON>", "--public-request-fd", "<INHERITED_PUBLIC_HANDSHAKE_REQUEST_FD>", "--tls-agent-ref", "<OPAQUE_TLS_AGENT_REF>"),
    "admit": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>", "--supervisor-fds-json", "<INHERITED_SUPERVISOR_FDS_JSON>", "--public-request-fd", "<INHERITED_PUBLIC_ADMISSION_REQUEST_FD>"),
    "run-journey": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>", "--supervisor-fds-json", "<INHERITED_SUPERVISOR_FDS_JSON>", "--public-request-fd", "<INHERITED_PUBLIC_JOURNEY_REQUEST_FD>", "--operations", "all-14", "--tls-agent-ref", "<OPAQUE_TLS_AGENT_REF>"),
    "stop": ("--candidate-descriptor-fd", "<INHERITED_CANDIDATE_DESCRIPTOR_FD>", "--runner-archive-fd", "<INHERITED_RUNNER_ARCHIVE_FD>", "--runner-sidecar-fd", "<INHERITED_RUNNER_SIDECAR_FD>", "--supervisor-fds-json", "<INHERITED_SUPERVISOR_FDS_JSON>", "--public-request-fd", "<INHERITED_PUBLIC_STOP_REQUEST_FD>"),
    "inventory": ("--check-only",),
    "reconcile": ("--check-only",),
}
_SAFETY_FACTS = {
    "writes": False,
    "process_started": False,
    "socket_opened": False,
    "external_action_performed": False,
}


class LifecycleCheckError(ValueError):
    """Stable lifecycle check rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


class LifecycleCliError(ValueError):
    """Stable non-echoing command-line rejection."""

    def __init__(self, code: str, path: str = "$.argv") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise LifecycleCliError("command_arguments_invalid")


def check_candidate(value: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        candidate = validate_candidate_selection(value, now=now)
    except PublicProfileError as exc:
        raise LifecycleCheckError(exc.code, exc.path) from exc
    return {
        "artifact_type": "codexmax_supported_host_candidate_check_v1",
        "state": "candidate_selection_validated_non_authoritative",
        "candidate": candidate,
        "writes": False,
        "process_started": False,
        "socket_opened": False,
        "external_action_performed": False,
    }


def check_public_profile(value: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    try:
        profile = validate_public_profile(value, now=now)
    except PublicProfileError as exc:
        raise LifecycleCheckError(exc.code, exc.path) from exc
    pending = profile["state"] == PENDING_STATE
    return {
        "artifact_type": "codexmax_supported_host_public_profile_check_v1",
        "state": (
            "pending_external_identity" if pending
            else "pending_real_tls_handshake_evidence"
        ),
        "profile_id": profile["profile_id"],
        "profile_sha256": profile["profile_sha256"],
        "credential_state": "pending_opaque_tls_agent",
        "socket_state": "not_observed_check_only",
        "certificate_fact_authority": False,
        "writes": False,
        "process_started": False,
        "socket_opened": False,
        "external_action_performed": False,
    }


def check_layout(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or dict(value) != LAYOUT:
        raise LifecycleCheckError("supported_host_layout_invalid", "$.layout")
    return {
        "artifact_type": "codexmax_supported_host_layout_check_v1",
        "state": "layout_contract_qualified",
        "layout": deepcopy(LAYOUT),
        "writes": False,
        "process_started": False,
        "socket_opened": False,
        "external_action_performed": False,
        "production_persistence_performed": False,
    }


def check_service_config(value: Mapping[str, Any]) -> dict[str, Any]:
    services = _validate_public_service_set(value)
    return {
        "artifact_type": "codexmax_supported_host_service_config_check_v1",
        "state": "pending_live_kernel_peer_identity",
        "services": {name: dict(row) for name, row in services.items()},
        "kernel_peer_identity_observed": False,
        **_SAFETY_FACTS,
    }


def _validate_public_service_set(value: Any) -> dict[str, dict[str, Any]]:
    """Validate the public three-service map without importing live runtime code."""

    if not isinstance(value, Mapping) or set(value) != set(_SERVICES):
        raise LifecycleCheckError("protected_service_set_invalid", "$.services")
    rows: dict[str, dict[str, Any]] = {}
    for name in _SERVICES:
        raw = value[name]
        if not isinstance(raw, Mapping) or set(raw) != set(_SERVICE_FIELDS):
            raise LifecycleCheckError("protected_service_config_shape_invalid", "$.services." + name)
        row = deepcopy(dict(raw))
        if row["schema_version"] != 1 or row["artifact_type"] != "supported_host_protected_service_config_v1":
            raise LifecycleCheckError("protected_service_config_identity_invalid", "$.services." + name)
        if row["service"] != name:
            raise LifecycleCheckError("protected_service_set_name_mismatch", "$.services." + name)
        if any(not isinstance(row[field], str) or _IDENTIFIER.fullmatch(row[field]) is None for field in (
            "service_id", "expected_service_start_id", "expected_service_session_id",
        )):
            raise LifecycleCheckError("protected_service_identifier_invalid", "$.services." + name)
        if not isinstance(row["service_build_sha256"], str) or _SHA256.fullmatch(row["service_build_sha256"]) is None:
            raise LifecycleCheckError("protected_service_digest_invalid", "$.services." + name)
        if row["protocol_version"] != _SERVICE_PROTOCOL:
            raise LifecycleCheckError("protected_service_protocol_invalid", "$.services." + name)
        if type(row["expected_uid"]) is not int or row["expected_uid"] < 1:
            raise LifecycleCheckError("protected_service_uid_invalid", "$.services." + name)
        if type(row["expected_gid"]) is not int or row["expected_gid"] < 1:
            raise LifecycleCheckError("protected_service_gid_invalid", "$.services." + name)
        if type(row["max_frame_bytes"]) is not int or not 1024 <= row["max_frame_bytes"] <= 4 * 1024 * 1024:
            raise LifecycleCheckError("protected_service_frame_limit_invalid", "$.services." + name)
        rows[name] = row
    if len({row["service_id"] for row in rows.values()}) != 3:
        raise LifecycleCheckError("protected_service_identity_collision", "$.services")
    if len({row["expected_uid"] for row in rows.values()}) != 3 or len({row["expected_gid"] for row in rows.values()}) != 3:
        raise LifecycleCheckError("protected_service_account_collision", "$.services")
    return rows


def render_runtime_plan(profile: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    candidate_check = check_candidate(profile.get("candidate", {}), now=now)
    profile_check = check_public_profile(profile, now=now)
    return {
        "artifact_type": "codexmax_supported_host_runtime_plan_v1",
        "state": (
            profile_check["state"]
        ),
        "candidate": candidate_check["candidate"],
        "profile_id": profile_check["profile_id"],
        "profile_sha256": profile_check["profile_sha256"],
        "principal_ids": list(PRINCIPAL_IDS),
        "operation_order": list(EXTERNAL_OPERATIONS),
        "layout": deepcopy(LAYOUT),
        "credential_state": "pending_opaque_tls_agent",
        "socket_state": "not_observed_check_only",
        "source_local_actions": ["check-candidate", "check-public-profile", "check-layout", "check-service-config", "render-runtime-plan"],
        "human_only_actions": [
            "install", "start", "validate-handshake", "admit", "run-journey",
            "stop", "inventory", "reconcile",
        ],
        "writes": False,
        "process_started": False,
        "socket_opened": False,
        "external_action_performed": False,
    }


def render_procedure_commands() -> dict[str, Any]:
    """Return non-executing templates with opaque references and public inputs."""

    return {
        "artifact_type": "codexmax_supported_host_human_command_templates_v1",
        "state": "template_only",
        "source_local_check_commands": [
            SOURCE_LOCAL_COMMAND + ["check-candidate", "--candidate-public-json", "<PUBLIC_CANDIDATE_JSON>"],
            SOURCE_LOCAL_COMMAND + ["check-public-profile", "--profile-public-json", "<PUBLIC_PROFILE_JSON>", "--now", "<UTC_NOW>"],
            SOURCE_LOCAL_COMMAND + ["check-layout", "--layout-public-json", "<PUBLIC_LAYOUT_JSON>"],
            SOURCE_LOCAL_COMMAND + ["check-service-config", "--service-public-json", "<PUBLIC_SERVICE_CONFIG_JSON>"],
            SOURCE_LOCAL_COMMAND + ["render-runtime-plan", "--profile-public-json", "<PUBLIC_PROFILE_JSON>", "--now", "<UTC_NOW>"],
            SOURCE_LOCAL_COMMAND + ["render-procedure-commands"],
        ],
        "human_only_command_templates": [
            ["codexmax-supported-host-lifecycle-v1", name, *HUMAN_COMMAND_ARGUMENTS[name]]
            for name in ("install", "start", "validate-handshake", "admit", "run-journey", "stop", "inventory", "reconcile")
        ],
        "expected_pending_states": [
            "pending_external_identity", "pending_real_tls_handshake_evidence",
            "pending_receiver_owned_live_validation", "pending_opaque_tls_agent",
            "socket_not_observed",
        ],
        "contains_private_material": False,
        "executes_commands": False,
        **_SAFETY_FACTS,
    }


def default_check_only_plan(*, now: datetime) -> dict[str, Any]:
    return render_runtime_plan(pending_public_profile(), now=now)


def _parser() -> _ClosedArgumentParser:
    parser = _ClosedArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--help", action="store_true", dest="root_help")
    commands = parser.add_subparsers(dest="command")

    def add_json_command(name: str, option: str, destination: str, *, timed: bool = False) -> None:
        command = commands.add_parser(name, add_help=False, allow_abbrev=False)
        command.add_argument("--help", action="store_true", dest="command_help")
        command.add_argument(option, required=False, dest=destination)
        if timed:
            command.add_argument("--now", required=False)

    add_json_command("check-candidate", "--candidate-public-json", "public_json")
    add_json_command("check-public-profile", "--profile-public-json", "public_json", timed=True)
    add_json_command("check-layout", "--layout-public-json", "public_json")
    add_json_command("check-service-config", "--service-public-json", "public_json")
    add_json_command("render-runtime-plan", "--profile-public-json", "public_json", timed=True)
    procedure = commands.add_parser("render-procedure-commands", add_help=False, allow_abbrev=False)
    procedure.add_argument("--help", action="store_true", dest="command_help")
    for name in sorted(EXTERNAL_ACTION_COMMANDS):
        external = commands.add_parser(name, add_help=False, allow_abbrev=False)
        external.add_argument("--help", action="store_true", dest="command_help")
        for option in EXTERNAL_OPTION_SPEC[name]:
            if option == "--check-only":
                external.add_argument(option, action="store_true", required=True)
            else:
                external.add_argument(option, required=True)
    return parser


def _help(command: str | None = None) -> dict[str, Any]:
    if command in EXTERNAL_ACTION_COMMANDS:
        usage = [*SOURCE_LOCAL_COMMAND, command]
        state = "external_action_required"
    elif command == "check-candidate":
        usage = [*SOURCE_LOCAL_COMMAND, command, "--candidate-public-json", "<PUBLIC_JSON_OR_DASH>"]
        state = "check_only"
    elif command in {"check-public-profile", "render-runtime-plan"}:
        usage = [*SOURCE_LOCAL_COMMAND, command, "--profile-public-json", "<PUBLIC_JSON_OR_DASH>", "--now", "<UTC_TIME>"]
        state = "check_only"
    elif command in {"check-layout", "check-service-config"}:
        option = "--layout-public-json" if command == "check-layout" else "--service-public-json"
        usage = [*SOURCE_LOCAL_COMMAND, command, option, "<PUBLIC_JSON_OR_DASH>"]
        state = "check_only"
    elif command == "render-procedure-commands":
        usage = [*SOURCE_LOCAL_COMMAND, command]
        state = "template_only"
    else:
        usage = [*SOURCE_LOCAL_COMMAND, "<command>"]
        state = "help"
    return {
        "artifact_type": "codexmax_supported_host_lifecycle_help_v1",
        "state": state,
        "command": command,
        "usage": usage,
        "check_commands": sorted(CHECK_COMMANDS),
        "external_action_commands": sorted(EXTERNAL_ACTION_COMMANDS),
        "public_json_input": "direct_or_stdin_dash_only",
        **_SAFETY_FACTS,
    }


def _parse_public_json(encoded: str | None, stdin: TextIO) -> Mapping[str, Any]:
    if encoded is None:
        raise LifecycleCliError("public_json_required", "$.argv")
    payload = stdin.read() if encoded == "-" else encoded
    return _parse_json_mapping(payload, "$.input")


def _parse_now(value: str | None) -> datetime:
    if value is None:
        raise LifecycleCliError("now_required", "$.now")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise LifecycleCliError("now_invalid", "$.now") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LifecycleCliError("now_timezone_required", "$.now")
    return parsed.astimezone(timezone.utc)


def _parse_fd(value: str, path: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise LifecycleCliError("inherited_descriptor_invalid", path)
    parsed = int(value)
    if parsed < 0:
        raise LifecycleCliError("inherited_descriptor_invalid", path)
    return parsed


def _parse_supervisor_fds(encoded: str) -> dict[str, int]:
    try:
        value = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleCliError("supervisor_descriptor_inventory_invalid", "$.supervisor_fds") from exc
    if not isinstance(value, Mapping) or set(value) != set(FD_ROLES):
        raise LifecycleCliError("supervisor_descriptor_inventory_invalid", "$.supervisor_fds")
    if any(type(item) is not int or item < 0 for item in value.values()):
        raise LifecycleCliError("supervisor_descriptor_inventory_invalid", "$.supervisor_fds")
    return dict(value)


def _parse_json_mapping(encoded: str, path: str) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise LifecycleCliError("public_json_duplicate_key", path)
            result[key] = item
        return result
    try:
        value = json.loads(encoded, object_pairs_hook=reject_duplicates)
    except LifecycleCliError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleCliError("public_json_invalid", path) from exc
    if not isinstance(value, Mapping):
        raise LifecycleCliError("public_json_object_required", path)
    return value


def _parse_descriptor_map(encoded: str, keys: Sequence[str], path: str) -> dict[str, int]:
    value = _parse_json_mapping(encoded, path)
    if set(value) != set(keys) or any(type(item) is not int or item < 0 for item in value.values()) or len(set(value.values())) != len(value):
        raise LifecycleCliError("inherited_descriptor_map_invalid", path)
    return dict(value)


def _parse_opaque_agent_ref(value: str | None) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise LifecycleCliError("opaque_agent_ref_invalid", "$.tls_agent_ref")
    lowered = value.lower()
    if any(part in lowered for part in ("secret", "password", "private", "credential", "token", "key")) or any(part in value for part in ("/", "\\", "..", "~")):
        raise LifecycleCliError("opaque_agent_ref_sensitive_or_path_like", "$.tls_agent_ref")
    return value


def _validate_start_arguments(args: argparse.Namespace) -> None:
    services = _parse_json_mapping(args.service_public_json, "$.service_public_json")
    _validate_public_service_set(services)
    authority = _parse_json_mapping(args.joint_authority_json, "$.joint_authority_json")
    source_services = _parse_json_mapping(args.operation_source_service_json, "$.operation_source_service_json")
    try:
        validate_complete_start_authority(authority, source_services)
    except PublicAuthorityError as exc:
        raise LifecycleCliError(exc.code, exc.path) from exc
    _parse_descriptor_map(args.operation_source_fds_json, OPERATION_OWNER_IDS, "$.operation_source_fds_json")
    _parse_descriptor_map(args.raw_observation_fds_json, OPERATION_OWNER_IDS, "$.raw_observation_fds_json")
    _parse_descriptor_map(args.service_root_fds_json, JOINT_ROLES, "$.service_root_fds_json")
    supervisor_fds = _parse_supervisor_fds(args.supervisor_fds_json)
    deployment_fd = _parse_fd(args.deployment_admission_fd, "$.deployment_admission_fd")
    runtime_fd = _parse_fd(args.runtime_root_fd, "$.runtime_root_fd")
    if deployment_fd != supervisor_fds["deployment_admission_fd"] or runtime_fd != supervisor_fds["runtime_root_fd"]:
        raise LifecycleCliError("supervisor_descriptor_binding_mismatch", "$.supervisor_fds")
    _parse_opaque_agent_ref(args.tls_agent_ref)


def _error(code: str, path: str, *, state: str = "rejected") -> dict[str, Any]:
    return {
        "artifact_type": "codexmax_supported_host_lifecycle_error_v1",
        "state": state,
        "error": {"code": code, "path": path},
        **_SAFETY_FACTS,
    }


def _write_json(stream: TextIO, value: Mapping[str, Any]) -> None:
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the closed check-only command surface without external actions."""

    if stdin is None or stdout is None or stderr is None:
        import sys
        stdin = sys.stdin if stdin is None else stdin
        stdout = sys.stdout if stdout is None else stdout
        stderr = sys.stderr if stderr is None else stderr
    try:
        args = _parser().parse_args(argv)
        command = args.command
        if args.root_help or command is None or getattr(args, "command_help", False):
            _write_json(stdout, _help(command))
            return 0
        if command in EXTERNAL_ACTION_COMMANDS:
            live_gate = None
            descriptor_fd = None
            if "--candidate-descriptor-fd" in EXTERNAL_OPTION_SPEC[command]:
                descriptor_fd = _parse_fd(args.candidate_descriptor_fd, "$.candidate_descriptor_fd")
            if command == "install":
                _parse_fd(args.runner_archive_fd, "$.runner_archive_fd")
                _parse_fd(args.runner_sidecar_fd, "$.runner_sidecar_fd")
            if command == "start":
                _validate_start_arguments(args)
                live_gate = prepare_lifecycle(
                    descriptor_fd,
                    _parse_fd(args.runner_archive_fd, "$.runner_archive_fd"),
                    _parse_fd(args.runner_sidecar_fd, "$.runner_sidecar_fd"),
                    _parse_supervisor_fds(args.supervisor_fds_json),
                    opaque_agent_available=False,
                    now=datetime.now(timezone.utc),
                )
            if command in {"validate-handshake", "admit", "run-journey", "stop"}:
                if command in {"validate-handshake", "run-journey"}:
                    _parse_opaque_agent_ref(args.tls_agent_ref)
                if command == "run-journey" and args.operations != "all-14":
                    raise LifecycleCliError("journey_operation_set_invalid")
                request_type = {"validate-handshake": "handshake", "admit": "admission", "run-journey": "journey", "stop": "stop"}[command]
                validate_public_request_fd(_parse_fd(args.public_request_fd, "$.public_request_fd"), request_type)
                live_gate = prepare_lifecycle(
                    descriptor_fd,
                    _parse_fd(args.runner_archive_fd, "$.runner_archive_fd"),
                    _parse_fd(args.runner_sidecar_fd, "$.runner_sidecar_fd"),
                    _parse_supervisor_fds(args.supervisor_fds_json),
                    opaque_agent_available=False,
                    now=datetime.now(timezone.utc),
                )
            if command in {"inventory", "reconcile"}:
                _write_json(stdout, {**supervisor_check_only_plan(), "state": command + "_check_only"})
                return 0
            gate_state = "external_action_required" if live_gate is None else str(live_gate["state"])
            _write_json(stderr, _error(gate_state, f"$.command.{command}", state=gate_state))
            return 4
        if command == "render-procedure-commands":
            result = render_procedure_commands()
        else:
            value = _parse_public_json(args.public_json, stdin)
            if command == "check-candidate":
                result = check_candidate(value)
            elif command == "check-public-profile":
                result = check_public_profile(value, now=_parse_now(args.now))
            elif command == "check-layout":
                result = check_layout(value)
            elif command == "check-service-config":
                result = check_service_config(value)
            elif command == "render-runtime-plan":
                result = render_runtime_plan(value, now=_parse_now(args.now))
            else:
                raise LifecycleCliError("command_invalid")
        _write_json(stdout, result)
        return 0
    except LifecycleCliError as exc:
        _write_json(stderr, _error(exc.code, exc.path))
        return 2
    except LifecycleCheckError as exc:
        _write_json(stderr, _error(exc.code, exc.path))
        return 3
    except SupervisorError as exc:
        _write_json(stderr, _error(exc.code, "$.inherited_descriptors"))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
