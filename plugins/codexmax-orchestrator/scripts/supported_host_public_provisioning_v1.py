#!/usr/bin/env python3
"""Closed public provisioning intent for the supported host.

This module validates public metadata only. It never accepts private material,
locations, endpoints, or executable authority and never mints live authority.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping

CERTIFICATE_ROLES = ("ca", "server", "client_runner", "client_writer", "client_anchor", "client_tls_agent", "client_runtime", "client_observer")
SERVICE_ROLES = ("runner", "protected_writer", "independent_anchor", "opaque_tls_agent", "catalog_selection", "native_supervision", "responses_seals", "effect_authority", "registered_action", "recovery", "external_observer")
DESCRIPTOR_ROLES = ("candidate", "archive", "sidecar", "root_manifest", "deployment_admission", "runtime_root", "protected_writer", "independent_anchor", "opaque_tls_agent", "catalog_selection", "native_supervision", "responses_seals", "effect_authority", "registered_action", "recovery", "external_observer")
_TOP = frozenset({"schema_version", "artifact_type", "profile_id", "certificates", "services", "root_launch_policy", "descriptor_roles", "joint_authority", "provisioning_sha256"})
_CERT = frozenset({"role", "certificate_sha256", "subject", "issuer", "serial", "not_before", "not_after", "dns_sans", "extended_key_usages"})
_SERVICE = frozenset({"role", "service_id", "build_sha256", "uid", "gid", "supplemental_groups", "start_id", "session_id"})
_POLICY = frozenset({"root_policy_id", "launch_policy_id", "required_platform", "path_authority", "public_mapping_authority", "production_ready"})
_DESCRIPTORS = frozenset({"roles", "passing_mode", "paths_allowed", "descriptor_substitution_allowed"})
_AUTHORITY = frozenset({"authority_id", "service_roles", "descriptor_roles", "distinct_account_roles", "joint_approval_roles", "public_intent_only", "authority_minted"})
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FORBIDDEN_KEY = re.compile(r"(?i)(private|secret|token|password|credential|path|endpoint|socket|url|command|argv|environment|env)")
_FORBIDDEN_VALUE = re.compile(r"(?i)(-----BEGIN|bearer\s|api[_-]?key|password|secret|token|credential|://|^/|^~|\\|\.\./|\$\{)")


class ProvisioningError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def seal(value: Mapping[str, Any]) -> dict[str, Any]:
    row = deepcopy(dict(value)); row["provisioning_sha256"] = ""
    row["provisioning_sha256"] = _digest(row)
    return row


def _closed(value: Any, fields: frozenset[str], path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProvisioningError("mapping_required", path)
    unknown = sorted(set(value) - set(fields))
    if unknown:
        code = "private_or_location_field_forbidden" if _FORBIDDEN_KEY.search(unknown[0]) else "extra_field_forbidden"
        raise ProvisioningError(code, f"{path}.{unknown[0]}")
    if set(value) != set(fields):
        raise ProvisioningError("required_field_missing", path)
    return deepcopy(dict(value))


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None or _FORBIDDEN_VALUE.search(value):
        raise ProvisioningError("public_identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ProvisioningError("public_digest_invalid", path)
    return value


def validate_public_provisioning(value: Any) -> dict[str, Any]:
    row = _closed(value, _TOP, "$")
    if row["schema_version"] != 1 or row["artifact_type"] != "codexmax_supported_host_public_provisioning_v1":
        raise ProvisioningError("provisioning_identity_invalid")
    _text(row["profile_id"], "$.profile_id")
    if not isinstance(row["certificates"], list) or len(row["certificates"]) != len(CERTIFICATE_ROLES):
        raise ProvisioningError("certificate_set_invalid", "$.certificates")
    certificates = {}
    for index, raw in enumerate(row["certificates"]):
        cert = _closed(raw, _CERT, f"$.certificates[{index}]")
        role = cert["role"]
        if role not in CERTIFICATE_ROLES or role in certificates:
            raise ProvisioningError("certificate_role_invalid", f"$.certificates[{index}].role")
        _sha(cert["certificate_sha256"], f"$.certificates[{index}].certificate_sha256")
        for field in ("subject", "issuer", "serial"):
            _text(cert[field], f"$.certificates[{index}].{field}")
        for field in ("not_before", "not_after"):
            if not isinstance(cert[field], str) or _TIME.fullmatch(cert[field]) is None:
                raise ProvisioningError("certificate_time_invalid", f"$.certificates[{index}].{field}")
        if not isinstance(cert["dns_sans"], list) or not isinstance(cert["extended_key_usages"], list):
            raise ProvisioningError("certificate_metadata_invalid", f"$.certificates[{index}]")
        for field in ("dns_sans", "extended_key_usages"):
            if len(cert[field]) != len(set(cert[field])):
                raise ProvisioningError("certificate_metadata_duplicate", f"$.certificates[{index}].{field}")
            for item in cert[field]: _text(item, f"$.certificates[{index}].{field}")
        if role == "server" and (cert["dns_sans"] != ["codexmax-package-host.local"] or cert["extended_key_usages"] != ["serverAuth"]):
            raise ProvisioningError("server_certificate_policy_invalid", f"$.certificates[{index}]")
        if role.startswith("client_") and (cert["dns_sans"] or cert["extended_key_usages"] != ["clientAuth"]):
            raise ProvisioningError("client_certificate_policy_invalid", f"$.certificates[{index}]")
        if role == "ca" and (cert["dns_sans"] or cert["extended_key_usages"]):
            raise ProvisioningError("ca_certificate_policy_invalid", f"$.certificates[{index}]")
        certificates[role] = cert
    if set(certificates) != set(CERTIFICATE_ROLES) or len({c["certificate_sha256"] for c in certificates.values()}) != len(certificates):
        raise ProvisioningError("certificate_set_invalid", "$.certificates")
    if not isinstance(row["services"], list) or len(row["services"]) != len(SERVICE_ROLES):
        raise ProvisioningError("service_set_invalid", "$.services")
    services = {}
    for index, raw in enumerate(row["services"]):
        service = _closed(raw, _SERVICE, f"$.services[{index}]")
        role = service["role"]
        if role not in SERVICE_ROLES or role in services:
            raise ProvisioningError("service_role_invalid", f"$.services[{index}].role")
        for field in ("service_id", "start_id", "session_id"): _text(service[field], f"$.services[{index}].{field}")
        _sha(service["build_sha256"], f"$.services[{index}].build_sha256")
        for field in ("uid", "gid"):
            if type(service[field]) is not int or service[field] < 1: raise ProvisioningError("service_account_invalid", f"$.services[{index}].{field}")
        if not isinstance(service["supplemental_groups"], list) or any(type(group) is not int or group < 1 for group in service["supplemental_groups"]) or len(service["supplemental_groups"]) != len(set(service["supplemental_groups"])):
            raise ProvisioningError("service_groups_invalid", f"$.services[{index}].supplemental_groups")
        services[role] = service
    if set(services) != set(SERVICE_ROLES) or len({s["service_id"] for s in services.values()}) != 11 or len({s["uid"] for s in services.values()}) != 11 or len({s["gid"] for s in services.values()}) != 11:
        raise ProvisioningError("service_identity_collision", "$.services")
    policy = _closed(row["root_launch_policy"], _POLICY, "$.root_launch_policy")
    _text(policy["root_policy_id"], "$.root_launch_policy.root_policy_id"); _text(policy["launch_policy_id"], "$.root_launch_policy.launch_policy_id")
    if policy != {**policy, "required_platform": "darwin", "path_authority": False, "public_mapping_authority": False, "production_ready": False}:
        raise ProvisioningError("root_launch_policy_invalid", "$.root_launch_policy")
    descriptors = _closed(row["descriptor_roles"], _DESCRIPTORS, "$.descriptor_roles")
    if descriptors != {"roles": list(DESCRIPTOR_ROLES), "passing_mode": "inherited_numeric_descriptors_only", "paths_allowed": False, "descriptor_substitution_allowed": False}:
        raise ProvisioningError("descriptor_policy_invalid", "$.descriptor_roles")
    authority = _closed(row["joint_authority"], _AUTHORITY, "$.joint_authority")
    _text(authority["authority_id"], "$.joint_authority.authority_id")
    if authority["service_roles"] != list(SERVICE_ROLES) or authority["descriptor_roles"] != list(DESCRIPTOR_ROLES) or authority["distinct_account_roles"] != list(SERVICE_ROLES) or authority["joint_approval_roles"] != ["protected_writer", "independent_anchor"] or authority["public_intent_only"] is not True or authority["authority_minted"] is not False:
        raise ProvisioningError("joint_authority_policy_invalid", "$.joint_authority")
    supplied = _sha(row["provisioning_sha256"], "$.provisioning_sha256")
    if seal(row)["provisioning_sha256"] != supplied:
        raise ProvisioningError("provisioning_digest_mismatch", "$.provisioning_sha256")
    return row


def check_public_provisioning(value: Any) -> dict[str, Any]:
    row = validate_public_provisioning(value)
    return {"artifact_type": "codexmax_supported_host_public_provisioning_check_v1", "state": "public_intent_validated_non_authoritative", "profile_id": row["profile_id"], "provisioning_sha256": row["provisioning_sha256"], "authority_minted": False, "production_ready": False}


__all__ = ["CERTIFICATE_ROLES", "SERVICE_ROLES", "DESCRIPTOR_ROLES", "ProvisioningError", "seal", "validate_public_provisioning", "check_public_provisioning"]
