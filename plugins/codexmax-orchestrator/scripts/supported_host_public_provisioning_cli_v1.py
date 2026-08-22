#!/usr/bin/env python3
"""Prepare and validate public-only supported-host provisioning metadata.

This CLI does not install, provision, start, or authorize a service. It does
not read files, network resources, credentials, or private host configuration.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
import platform
import re
import sys
from typing import Any, Mapping, Sequence

from supported_host_public_provisioning_v1 import (
    CERTIFICATE_ROLES,
    DESCRIPTOR_ROLES,
    SERVICE_ROLES,
    ProvisioningError,
    seal,
    validate_public_provisioning,
)


RUNNER_V33_PUBLIC_IDENTITY = {
    "runner_version": "v33",
    "archive_sha256": "92ad4aa45d144ee6a60dd58f292727357509df1275f2b211da2517e58f262908",
    "sidecar_sha256": "539cc38d1a37d744591215dda0b9825c74b2113c0d8d621ace4d77461d3f09c8",
    "source_identity_sha256": "2cfa0344fdc645d6f90c45de8269cceed7477e73632a61b93e789f2baf16fdf9",
    "standalone_version": "0.5.0+codex.20260813.standalone.37",
    "standalone_manifest_sha256": "a04264aca7981208dda70e2fc903219ccc24a78b7fc3f00ef5213e2cde0bcc21",
    "descriptor_sha256": "cdc9ab2953066e21862e72809b9fcc30b2df04884089a7c021a60c8ee8cc79d8",
}

_ALLOWED_POLICY_PATH_KEYS = frozenset({"path_authority", "paths_allowed"})
_SENSITIVE_KEY = re.compile(
    r"(?i)(private|secret|token|password|credential|keychain|browser|system_config|pathname|filesystem)"
)
_PATH_LIKE_VALUE = re.compile(r"(?:^/|^~(?:/|$)|^[A-Za-z]:[\\/]|(?:^|/)\.\.(?:/|$)|://|\\)")


def _unresolved(required_type: str) -> dict[str, str]:
    return {"state": "unresolved_external", "required_type": required_type}


def scaffold_v33() -> dict[str, Any]:
    """Return an incomplete public-data template pinned to runner v33."""
    certificates = []
    for role in CERTIFICATE_ROLES:
        certificates.append(
            {
                "role": role,
                "certificate_sha256": _unresolved("sha256"),
                "subject": _unresolved("public_identifier"),
                "issuer": _unresolved("public_identifier"),
                "serial": _unresolved("public_identifier"),
                "not_before": _unresolved("utc_timestamp"),
                "not_after": _unresolved("utc_timestamp"),
                "dns_sans": ["codexmax-package-host.local"] if role == "server" else [],
                "extended_key_usages": (
                    [] if role == "ca" else ["serverAuth" if role == "server" else "clientAuth"]
                ),
            }
        )

    services = [
        {
            "role": role,
            "service_id": _unresolved("public_identifier"),
            "build_sha256": _unresolved("sha256"),
            "uid": _unresolved("positive_integer"),
            "gid": _unresolved("positive_integer"),
            "supplemental_groups": _unresolved("unique_positive_integer_list"),
            "start_id": _unresolved("public_identifier"),
            "session_id": _unresolved("public_identifier"),
        }
        for role in SERVICE_ROLES
    ]

    return {
        "schema_version": 1,
        "artifact_type": "codexmax_supported_host_public_provisioning_scaffold_v1",
        "state": "incomplete_external_public_facts_required",
        "selected_candidate": deepcopy(RUNNER_V33_PUBLIC_IDENTITY),
        "provisioning_template": {
            "schema_version": 1,
            "artifact_type": "codexmax_supported_host_public_provisioning_v1",
            "profile_id": _unresolved("public_identifier"),
            "certificates": certificates,
            "services": services,
            "root_launch_policy": {
                "root_policy_id": _unresolved("public_identifier"),
                "launch_policy_id": _unresolved("public_identifier"),
                "required_platform": "darwin",
                "path_authority": False,
                "public_mapping_authority": False,
                "production_ready": False,
            },
            "descriptor_roles": {
                "roles": list(DESCRIPTOR_ROLES),
                "passing_mode": "inherited_numeric_descriptors_only",
                "paths_allowed": False,
                "descriptor_substitution_allowed": False,
            },
            "joint_authority": {
                "authority_id": _unresolved("public_identifier"),
                "service_roles": list(SERVICE_ROLES),
                "descriptor_roles": list(DESCRIPTOR_ROLES),
                "distinct_account_roles": list(SERVICE_ROLES),
                "joint_approval_roles": ["protected_writer", "independent_anchor"],
                "public_intent_only": True,
                "authority_minted": False,
            },
            "provisioning_sha256": _unresolved("canonical_provisioning_sha256"),
        },
        "valid_provisioning_packet": False,
        "authority_minted": False,
        "production_ready": False,
    }


def observe_current_process() -> dict[str, Any]:
    """Return public facts about this process without binding any role."""
    version = sys.version_info
    return {
        "schema_version": 1,
        "artifact_type": "codexmax_supported_host_current_process_observation_v1",
        "state": "parent_process_public_facts_observed_non_binding",
        "observations": {
            "platform_system": platform.system(),
            "pid": os.getpid(),
            "uid": os.getuid(),
            "gid": os.getgid(),
            "supplemental_groups": sorted(set(os.getgroups())),
            "executable_implementation": sys.implementation.name,
            "executable_version": f"{version.major}.{version.minor}.{version.micro}",
        },
        "observations_are_parent_process_facts_only": True,
        "service_role_bindings": False,
        "authority_minted": False,
        "production_ready": False,
    }


def _assert_public_only(value: Any, location: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"public_input_key_invalid: {location}")
            lowered = key.lower()
            if _SENSITIVE_KEY.search(key) or ("path" in lowered and lowered not in _ALLOWED_POLICY_PATH_KEYS):
                raise ValueError(f"private_or_path_field_forbidden: {location}.{key}")
            _assert_public_only(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_public_only(item, f"{location}[{index}]")
    elif isinstance(value, str) and _PATH_LIKE_VALUE.search(value):
        raise ValueError(f"path_like_value_forbidden: {location}")


def validate_from_public_json(value: Any) -> dict[str, Any]:
    """Validate one complete public packet without creating authority."""
    _assert_public_only(value)
    validated = validate_public_provisioning(value)
    recomputed = seal(validated)["provisioning_sha256"]
    return {
        "schema_version": 1,
        "artifact_type": "codexmax_supported_host_public_provisioning_cli_validation_v1",
        "state": "public_intent_validated_non_authoritative",
        "profile_id": validated["profile_id"],
        "provisioning_sha256": validated["provisioning_sha256"],
        "canonical_seal_matches": recomputed == validated["provisioning_sha256"],
        "authority_minted": False,
        "production_ready": False,
    }


def _write_json(value: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def _reject(exc: Exception) -> int:
    if isinstance(exc, ProvisioningError):
        code = exc.code
        location = exc.path
    elif isinstance(exc, json.JSONDecodeError):
        code = "public_json_invalid"
        location = "$"
    else:
        text = str(exc)
        code, _, location = text.partition(": ")
        location = location or "$"
    _write_json(
        {
            "schema_version": 1,
            "artifact_type": "codexmax_supported_host_public_provisioning_cli_validation_v1",
            "state": "rejected",
            "error": {"code": code, "location": location},
            "authority_minted": False,
            "production_ready": False,
        }
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("scaffold-v33", help="emit the incomplete runner v33 public scaffold")
    subparsers.add_parser(
        "observe-current-process",
        help="observe non-binding public facts about the current Parent process",
    )
    subparsers.add_parser("validate", help="validate one complete public packet from stdin")
    args = parser.parse_args(argv)

    if args.mode == "scaffold-v33":
        _write_json(scaffold_v33())
        return 0
    if args.mode == "observe-current-process":
        _write_json(observe_current_process())
        return 0

    try:
        value = json.load(sys.stdin)
        _write_json(validate_from_public_json(value))
        return 0
    except (ProvisioningError, ValueError, json.JSONDecodeError) as exc:
        return _reject(exc)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RUNNER_V33_PUBLIC_IDENTITY",
    "main",
    "observe_current_process",
    "scaffold_v33",
    "validate_from_public_json",
]
