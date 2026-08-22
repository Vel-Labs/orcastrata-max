#!/usr/bin/env python3
"""Closed public identity profile for the first-party supported-host runtime.

The module validates public certificate bytes and metadata. It never reads a
certificate, key, credential, endpoint, environment variable, or filesystem
location. A validated certificate authenticates a principal. It never creates
fact authority.
"""

from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

from supported_host_candidate_admission_v1 import (
    CandidateAdmissionError,
    VerifiedSelectedCandidate,
    validate_selected_candidate_descriptor,
)

DEPLOYMENT_ADMISSION_PROTOCOL = "supported_host_deployment_admission_v2"
DEPLOYMENT_BOOTSTRAP_SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v2"


PROFILE_TYPE = "codexmax_first_party_supported_host_public_profile_v1"
PROFILE_ID = "codexmax-first-party-supported-host-profile-v1"
RUNTIME_ID = "codexmax-first-party-authoritative-supported-host-runtime-v1"
HOST_ID = "codexmax-package-host-external"
EXPECTED_DNS_SAN = "codexmax-package-host.local"
PENDING_STATE = "pending_external_identity"
HANDSHAKE_PENDING_STATE = "pending_real_tls_handshake_evidence"

T071_V10_IDENTITY = MappingProxyType({
    "candidate_id": "codexmax-package-host-runner-v10",
    "host_id": "codexmax-package-host-external",
    "host_build": "codexmax-package-host-external-t071-v10",
    "runner_artifact_type": "codexmax_package_host_runner_bundle_v10",
    "runner_archive_name": "codexmax-package-host-runner-bundle-v10.tar",
    "runner_manifest_name": "codexmax-package-host-runner-bundle-v10.manifest.json",
    "runner_target": "orcastrata:historical-package-host-runner:v10:codexmax-package-host-runner-bundle-v10",
    "archive_sha256": "sha256:7f0e9e365d057013a4b8daf69a82ebed00337c2b5a4d8de2b1e9b86671a5bcdd",
    "manifest_sha256": "sha256:2daf37f7e3b4d3af575bea67e37ad604d4247c2b812116092fe69ba43fb40c8b",
    "source_identity_sha256": "sha256:6a5fa64ddecfc523b61cbc5fe6189c1b086648f859014c93b9604ca9137f0fcf",
})

T098_V12_PREDECESSOR_IDENTITY = MappingProxyType({
    "candidate_id": "codexmax-package-host-runner-v12",
    "archive_sha256": "sha256:8569160e9d742dee166bb1bbe80cef665a09f789590da4980918643867ce5d2f",
    "sidecar_sha256": "sha256:c782f53a11fac3cbc2b7d43296600596f6fd23f030bfc687c129fdfdec2681ea",
    "source_identity_sha256": "sha256:84f3b8786daf0b79aff9deebfca2b05f12a2574be136833a46e90a24fcd11660",
    "runner_target": "orcastrata:historical-package-host-runner:v12:codexmax-package-host-runner-bundle-v12",
})

# The runner cannot authenticate its own archive digest. The installer verifies
# the accepted T099 v23 archive and sidecar. The protected-service exchange then
# carries those public digests in the admitted runtime identity.
HISTORICAL_RUNNER_V23_IDENTITY = MappingProxyType({
    "candidate_id": "codexmax-package-host-runner-v23",
    "host_id": "codexmax-package-host-external",
    "host_build": "codexmax-package-host-external-t099-v23",
    "runner_artifact_type": "codexmax_package_host_runner_bundle_v23",
    "runner_archive_name": "codexmax-package-host-runner-bundle-v23.tar",
    "runner_manifest_name": "codexmax-package-host-runner-bundle-v23.manifest.json",
    "runner_target": "orcastrata:historical-package-host-runner:v23:codexmax-package-host-runner-bundle-v23",
    "archive_identity_authority": "installer_verified_sidecar_and_protected_service_admission_v1",
    "archive_sha256": "sha256:607eb7c32c7907f6f1b3c289c6dfd0970cf878d5cfa55ecf74b8c2c6dac75925",
    "sidecar_sha256": "sha256:e4d109a2c469663cd86dd74418981a959f3ac1fd916493243a1537a3bdbd1e0e",
    "source_identity_sha256": "sha256:4c8bda775cc1757ab9e8c3e6fc380fd85a86ea4557bba22a46e2a4ec179133ab",
    "predecessor": dict(T098_V12_PREDECESSOR_IDENTITY),
    "embedded_lineage": "t098_v12_and_t071_v10",
})

# Runtime compatibility is version-neutral. Runner v23 remains migration
# history. It cannot authorize or identify a later deployment.
CURRENT_DEPLOYMENT_ADMISSION_IDENTITY = MappingProxyType({
    "identity_type": "bootstrap_bound_deployment_admission_v2",
    "protocol_version": DEPLOYMENT_ADMISSION_PROTOCOL,
    "bootstrap_source_id": DEPLOYMENT_BOOTSTRAP_SOURCE_ID,
    "minimum_generation": 1,
    "host_id": HOST_ID,
    "legacy_migration_candidate": HISTORICAL_RUNNER_V23_IDENTITY["candidate_id"],
})

# This descriptor selects the accepted T100 bytes for public procedure and
# operator display only. It is not admission evidence. Production admission
# still requires the OS-bound DeploymentAdmissionV2 transaction.
PENDING_PUBLIC_CANDIDATE_SELECTION = MappingProxyType({
    "artifact_type": "codexmax_pending_candidate_selection_v1",
    "state": "pending_authenticated_candidate_descriptor",
    "deployment_admission": dict(CURRENT_DEPLOYMENT_ADMISSION_IDENTITY),
    "admission_authority": False,
})

EXTERNAL_OPERATIONS = (
    "commit_operator_selection",
    "commit_or_verify_record",
    "invoke_registered_action",
    "issue_responses_context",
    "read_operator_preset_bundle",
    "read_operator_recovery_lease_grant",
    "read_operator_selection_head",
    "read_operator_selection_mutation",
    "read_operator_supervision",
    "seal_or_verify_projection",
    "verify_effect_authority",
    "verify_responses_bridge",
)

_PRINCIPAL_BINDINGS = {
    "first-party-effect-authority-producer-v1": (
        ("verify_effect_authority", "effect-authority-ledger", "effect-authority"),
    ),
    "first-party-registered-action-producer-v1": (
        ("invoke_registered_action", "registered-action-observation-store", "action-observation"),
    ),
    "first-party-responses-seals-producer-v1": (
        ("commit_or_verify_record", "record-lineage-authority", "responses-seals"),
        ("issue_responses_context", "responses-context-issuer", "responses-seals"),
        ("seal_or_verify_projection", "projection-seal-authority", "responses-seals"),
        ("verify_responses_bridge", "responses-bridge-observation-store", "responses-seals"),
    ),
    "first-party-catalog-selection-producer-v1": (
        ("commit_operator_selection", "operator-selection-commit-authority", "selection"),
        ("read_operator_preset_bundle", "operator-catalog-publisher", "catalog"),
        ("read_operator_selection_head", "operator-selection-ledger", "selection"),
        ("read_operator_selection_mutation", "operator-selection-mutation-history", "selection"),
    ),
    "first-party-native-supervision-producer-v1": (
        ("read_operator_supervision", "native-desktop-inventory-authority", "native-inventory"),
    ),
    "first-party-recovery-producer-v1": (
        ("read_operator_recovery_lease_grant", "recovery-lease-authority", "recovery"),
    ),
}
PRINCIPAL_IDS = tuple(sorted(_PRINCIPAL_BINDINGS))

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FORBIDDEN_KEY_PARTS = frozenset({
    "private", "credential", "secret", "password", "token", "path",
    "endpoint", "environment", "env",
})
_PROFILE_FIELDS = frozenset({
    "schema_version", "artifact_type", "state", "profile_id", "runtime_id",
    "candidate", "deployment_identity", "trust_profile", "principals",
    "capability_configuration", "action_registration_configuration",
    "tls_boundary", "profile_sha256",
})
_CERTIFICATE_FIELDS = frozenset({
    "role", "encoding", "certificate_bytes_b64", "certificate_sha256", "serial_hex",
    "subject", "issuer", "dns_sans", "extended_key_usage", "is_ca",
    "not_before", "not_after",
})
_PRINCIPAL_FIELDS = frozenset({"principal_id", "client_certificate", "operation_bindings"})
_BINDING_FIELDS = frozenset({"operation", "canonical_source_id", "durable_namespace", "capability_id"})


class PublicProfileError(ValueError):
    """Stable non-echoing public-profile rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


class _DerReader:
    """Small strict DER reader for the X.509 fields used by this contract."""

    __slots__ = ("data", "offset")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, expected_tag: int | None = None) -> tuple[int, bytes]:
        if self.offset >= len(self.data):
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        tag = self.data[self.offset]
        self.offset += 1
        if self.offset >= len(self.data):
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        first = self.data[self.offset]
        self.offset += 1
        if first < 128:
            length = first
        else:
            count = first & 0x7F
            if count == 0 or count > 4 or self.offset + count > len(self.data):
                raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
            raw_length = self.data[self.offset:self.offset + count]
            self.offset += count
            if raw_length[0] == 0:
                raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
            length = int.from_bytes(raw_length, "big")
            if length < 128:
                raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        end = self.offset + length
        if end > len(self.data) or (expected_tag is not None and tag != expected_tag):
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        value = self.data[self.offset:end]
        self.offset = end
        return tag, value

    def done(self) -> bool:
        return self.offset == len(self.data)


def _one(data: bytes, tag: int) -> bytes:
    reader = _DerReader(data)
    _, value = reader.read(tag)
    if not reader.done():
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    return value


def _oid(data: bytes) -> str:
    if not data:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    first = data[0]
    values = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    for byte in data[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(current)
            current = 0
    if data[-1] & 0x80:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    return ".".join(str(item) for item in values)


_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU"}


def _name(data: bytes) -> str:
    sequence = _DerReader(_one(data, 0x30))
    rows: list[str] = []
    while not sequence.done():
        _, set_value = sequence.read(0x31)
        set_reader = _DerReader(set_value)
        _, pair_value = set_reader.read(0x30)
        if not set_reader.done():
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        pair = _DerReader(pair_value)
        _, oid_raw = pair.read(0x06)
        value_tag, value_raw = pair.read()
        if not pair.done() or value_tag not in {0x0C, 0x13, 0x14, 0x16, 0x1E}:
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        try:
            text = value_raw.decode("utf-16-be" if value_tag == 0x1E else "utf-8")
        except UnicodeDecodeError as exc:
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate") from exc
        rows.append(f"{_NAME_OIDS.get(_oid(oid_raw), _oid(oid_raw))}={text}")
    if not rows:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    return ",".join(rows)


def _x509_time(tag: int, raw: bytes) -> datetime:
    try:
        text = raw.decode("ascii")
        if tag == 0x17:
            parsed = datetime.strptime(text, "%y%m%d%H%M%SZ")
        elif tag == 0x18:
            parsed = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            raise ValueError
    except (UnicodeDecodeError, ValueError) as exc:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _extensions(data: bytes) -> tuple[list[str], list[str], bool]:
    dns_sans: list[str] = []
    eku: list[str] = []
    is_ca = False
    outer = _DerReader(_one(data, 0x30))
    while not outer.done():
        _, extension_value = outer.read(0x30)
        extension = _DerReader(extension_value)
        _, oid_raw = extension.read(0x06)
        oid = _oid(oid_raw)
        if extension.offset < len(extension.data) and extension.data[extension.offset] == 0x01:
            extension.read(0x01)
        _, octets = extension.read(0x04)
        if not extension.done():
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
        if oid == "2.5.29.17":
            names = _DerReader(_one(octets, 0x30))
            while not names.done():
                tag, raw = names.read()
                if tag == 0x82:
                    try:
                        dns_sans.append(raw.decode("ascii"))
                    except UnicodeDecodeError as exc:
                        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate") from exc
        elif oid == "2.5.29.37":
            usages = _DerReader(_one(octets, 0x30))
            while not usages.done():
                _, raw = usages.read(0x06)
                usage_oid = _oid(raw)
                eku.append({"1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth"}.get(usage_oid, usage_oid))
        elif oid == "2.5.29.19":
            constraints = _DerReader(_one(octets, 0x30))
            if not constraints.done() and constraints.data[constraints.offset] == 0x01:
                _, raw = constraints.read(0x01)
                is_ca = raw == b"\xff"
    return sorted(set(dns_sans)), sorted(set(eku)), is_ca


def _decode_public_certificate(encoded: Any, encoding: Any) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(encoded, str) or encoding not in {"der", "pem"}:
        raise PublicProfileError("public_certificate_bytes_invalid", "$.certificate")
    try:
        wire = base64.b64decode(encoded, validate=True)
        if encoding == "pem":
            text = wire.decode("ascii")
            begin = "-----BEGIN CERTIFICATE-----\n"
            end = "\n-----END CERTIFICATE-----"
            if not text.startswith(begin) or not text.rstrip().endswith(end):
                raise ValueError
            body = text[len(begin):text.rfind(end)].replace("\n", "")
            der = base64.b64decode(body, validate=True)
        else:
            der = wire
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise PublicProfileError("public_certificate_bytes_invalid", "$.certificate") from exc
    if not der or len(der) > 65536:
        raise PublicProfileError("public_certificate_bytes_invalid", "$.certificate")
    certificate = _DerReader(_one(der, 0x30))
    _, tbs_raw = certificate.read(0x30)
    certificate.read(0x30)
    signature_tag, signature = certificate.read()
    if signature_tag != 0x03 or len(signature) < 2 or not certificate.done():
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    tbs = _DerReader(tbs_raw)
    if tbs.offset < len(tbs.data) and tbs.data[tbs.offset] == 0xA0:
        tbs.read(0xA0)
    _, serial_raw = tbs.read(0x02)
    if not serial_raw or serial_raw[0] & 0x80:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    tbs.read(0x30)
    issuer_tag, issuer_raw = tbs.read(0x30)
    _, validity_raw = tbs.read(0x30)
    subject_tag, subject_raw = tbs.read(0x30)
    if issuer_tag != 0x30 or subject_tag != 0x30:
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    tbs.read(0x30)
    dns_sans: list[str] = []
    eku: list[str] = []
    is_ca = False
    while not tbs.done():
        tag, raw = tbs.read()
        if tag == 0xA3:
            dns_sans, eku, is_ca = _extensions(raw)
        elif tag not in {0x81, 0x82}:
            raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    validity = _DerReader(validity_raw)
    before_tag, before_raw = validity.read()
    after_tag, after_raw = validity.read()
    if not validity.done():
        raise PublicProfileError("public_certificate_x509_invalid", "$.certificate")
    return der, {
        "serial_hex": serial_raw.hex().lstrip("0") or "0",
        "subject": _name(bytes([0x30]) + _der_length(len(subject_raw)) + subject_raw),
        "issuer": _name(bytes([0x30]) + _der_length(len(issuer_raw)) + issuer_raw),
        "dns_sans": dns_sans,
        "extended_key_usage": eku,
        "is_ca": is_ca,
        "not_before": _x509_time(before_tag, before_raw).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": _x509_time(after_tag, after_raw).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def canonical_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise PublicProfileError(code, path)
    return deepcopy(dict(value))


def _scan_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PublicProfileError("public_profile_key_invalid", path)
            parts = frozenset(filter(None, re.split(r"[^a-z0-9]+", key.lower())))
            if parts & _FORBIDDEN_KEY_PARTS or key.lower() in {"key", "public_key"}:
                raise PublicProfileError("private_or_location_field_forbidden", f"{path}.{key}")
            _scan_forbidden_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_forbidden_keys(item, f"{path}[{index}]")


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise PublicProfileError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise PublicProfileError("digest_invalid", path)
    return value


def _parse_time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise PublicProfileError("certificate_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _capability_id(operation: str) -> str:
    return "codexmax.supported-host." + operation + ".v1"


def _expected_principals(client_certificates: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    rows = []
    for principal_id in PRINCIPAL_IDS:
        cert = None if client_certificates is None else deepcopy(client_certificates[principal_id])
        rows.append({
            "principal_id": principal_id,
            "client_certificate": cert,
            "operation_bindings": [
                {
                    "operation": operation,
                    "canonical_source_id": source_id,
                    "durable_namespace": namespace,
                    "capability_id": _capability_id(operation),
                }
                for operation, source_id, namespace in _PRINCIPAL_BINDINGS[principal_id]
            ],
        })
    return rows


def _capability_configuration() -> dict[str, Any]:
    rows = []
    for principal_id in PRINCIPAL_IDS:
        for operation, source_id, namespace in _PRINCIPAL_BINDINGS[principal_id]:
            rows.append({
                "operation": operation,
                "capability_id": _capability_id(operation),
                "principal_id": principal_id,
                "canonical_source_id": source_id,
                "durable_namespace": namespace,
            })
    return {
        "artifact_type": "codexmax_supported_host_capability_configuration_v1",
        "operation_rows": sorted(rows, key=lambda row: row["operation"]),
    }


def _action_configuration() -> dict[str, Any]:
    return {
        "artifact_type": "codexmax_supported_host_action_registration_configuration_v1",
        "registrations": [{
            "action_id": "codexmax-supported-host-registered-action-v1",
            "operation": "invoke_registered_action",
            "capability_id": _capability_id("invoke_registered_action"),
            "principal_id": "first-party-registered-action-producer-v1",
        }],
    }


def _validate_certificate(value: Any, role: str, now: datetime, path: str) -> dict[str, Any]:
    cert = _closed(value, _CERTIFICATE_FIELDS, "public_certificate_shape_invalid", path)
    if cert["role"] != role:
        raise PublicProfileError("public_certificate_role_invalid", path + ".role")
    der, derived = _decode_public_certificate(cert["certificate_bytes_b64"], cert["encoding"])
    actual_digest = "sha256:" + hashlib.sha256(der).hexdigest()
    if _sha(cert["certificate_sha256"], path + ".certificate_sha256") != actual_digest:
        raise PublicProfileError("public_certificate_digest_mismatch", path + ".certificate_sha256")
    for field, actual in derived.items():
        if cert[field] != actual:
            raise PublicProfileError("public_certificate_metadata_mismatch", path + "." + field)
    before = _parse_time(cert["not_before"], path + ".not_before")
    after = _parse_time(cert["not_after"], path + ".not_after")
    if before >= after or not (before <= now < after):
        raise PublicProfileError("public_certificate_validity_invalid", path)
    expected = {
        "ca": (True, [], []),
        "server": (False, [EXPECTED_DNS_SAN], ["serverAuth"]),
        "client": (False, [], ["clientAuth"]),
    }[role]
    if (cert["is_ca"], cert["dns_sans"], cert["extended_key_usage"]) != expected:
        raise PublicProfileError("public_certificate_usage_invalid", path)
    return cert


def _validate_candidate(value: Any, *, now: datetime) -> dict[str, Any]:
    if isinstance(value, Mapping) and dict(value) == dict(PENDING_PUBLIC_CANDIDATE_SELECTION):
        return deepcopy(dict(value))
    if not isinstance(value, Mapping):
        raise PublicProfileError("selected_candidate_descriptor_required", "$.candidate")
    row = dict(value)
    expected_extra = {"descriptor_sha256", "admission_authority", "state"}
    descriptor = {key: item for key, item in row.items() if key not in expected_extra}
    descriptor.pop("artifact_type", None)
    descriptor["artifact_type"] = "codexmax_selected_candidate_descriptor_v1"
    try:
        validate_selected_candidate_descriptor(descriptor, now=now)
    except CandidateAdmissionError as exc:
        raise PublicProfileError(exc.code, "$.candidate") from exc
    if row.get("artifact_type") != "codexmax_authenticated_candidate_selection_v1" or row.get("state") != "selected_descriptor_verified_non_authorizing" or row.get("admission_authority") is not False:
        raise PublicProfileError("selected_candidate_state_invalid", "$.candidate")
    _sha(row.get("descriptor_sha256"), "$.candidate.descriptor_sha256")
    return deepcopy(row)


def validate_candidate_selection(value: Any, *, now: datetime) -> dict[str, Any]:
    """Validate one non-authorizing public projection of a selected descriptor."""
    return _validate_candidate(value, now=now)


def _certificate_set_digest(profile: Mapping[str, Any]) -> str:
    return canonical_digest({
        "artifact_type": "codexmax_supported_host_public_certificate_set_v1",
        "deployment_identity": profile["deployment_identity"],
        "trust_profile": profile["trust_profile"],
        "principal_certificates": [
            {"principal_id": row["principal_id"], "client_certificate": row["client_certificate"]}
            for row in profile["principals"]
        ],
    })


def public_certificate_set_sha256(profile: Mapping[str, Any], *, now: datetime) -> str:
    """Return the parsed public set identity for opaque cryptographic validation."""

    validated = validate_public_profile(profile, now=now)
    if validated["state"] != HANDSHAKE_PENDING_STATE:
        raise PublicProfileError("certificate_metadata_state_invalid", "$.state")
    return _certificate_set_digest(validated)


def validate_public_profile(value: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Validate one pending public profile without external I/O or promotion."""

    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise PublicProfileError("utc_clock_invalid", "$.now")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    _scan_forbidden_keys(value)
    profile = _closed(value, _PROFILE_FIELDS, "public_profile_shape_invalid", "$")
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1 or profile["artifact_type"] != PROFILE_TYPE:
        raise PublicProfileError("public_profile_version_invalid", "$")
    if profile["state"] not in {PENDING_STATE, HANDSHAKE_PENDING_STATE}:
        raise PublicProfileError("public_profile_state_invalid", "$.state")
    if profile["profile_id"] != PROFILE_ID or profile["runtime_id"] != RUNTIME_ID:
        raise PublicProfileError("public_profile_identity_invalid", "$.profile_id")
    _validate_candidate(profile["candidate"], now=now)
    expected_principals = _expected_principals(None)
    if not isinstance(profile["principals"], list) or len(profile["principals"]) != len(PRINCIPAL_IDS):
        raise PublicProfileError("principal_map_invalid", "$.principals")
    trust = _closed(profile["trust_profile"], frozenset({"ca_certificate", "server_certificate"}), "trust_profile_invalid", "$.trust_profile")

    if profile["state"] == PENDING_STATE:
        if profile["deployment_identity"] is not None or trust != {"ca_certificate": None, "server_certificate": None}:
            raise PublicProfileError("pending_external_identity_invalid", "$.trust_profile")
        if profile["principals"] != expected_principals:
            raise PublicProfileError("pending_external_identity_invalid", "$.principals")
    else:
        _identifier(profile["deployment_identity"], "$.deployment_identity")
        ca = _validate_certificate(trust["ca_certificate"], "ca", now, "$.trust_profile.ca_certificate")
        server = _validate_certificate(trust["server_certificate"], "server", now, "$.trust_profile.server_certificate")
        if ca["subject"] != ca["issuer"] or server["issuer"] != ca["subject"]:
            raise PublicProfileError("public_certificate_chain_invalid", "$.trust_profile")
        seen = {ca["certificate_sha256"], server["certificate_sha256"]}
        normalized_clients: dict[str, Any] = {}
        operations: set[str] = set()
        for index, principal in enumerate(profile["principals"]):
            path = f"$.principals[{index}]"
            row = _closed(principal, _PRINCIPAL_FIELDS, "principal_shape_invalid", path)
            expected_id = PRINCIPAL_IDS[index]
            if row["principal_id"] != expected_id:
                raise PublicProfileError("principal_map_invalid", path + ".principal_id")
            if row["operation_bindings"] != expected_principals[index]["operation_bindings"]:
                raise PublicProfileError("principal_map_invalid", path + ".operation_bindings")
            cert = _validate_certificate(row["client_certificate"], "client", now, path + ".client_certificate")
            if cert["issuer"] != ca["subject"] or cert["certificate_sha256"] in seen:
                raise PublicProfileError("principal_certificate_invalid", path + ".client_certificate")
            seen.add(cert["certificate_sha256"])
            normalized_clients[expected_id] = cert
            operations.update(item["operation"] for item in row["operation_bindings"])
        if operations != set(EXTERNAL_OPERATIONS):
            raise PublicProfileError("principal_operation_coverage_invalid", "$.principals")
        if profile["principals"] != _expected_principals(normalized_clients):
            raise PublicProfileError("principal_map_invalid", "$.principals")

    if profile["capability_configuration"] != _capability_configuration():
        raise PublicProfileError("capability_configuration_invalid", "$.capability_configuration")
    if profile["action_registration_configuration"] != _action_configuration():
        raise PublicProfileError("action_registration_configuration_invalid", "$.action_registration_configuration")
    if profile["tls_boundary"] != {
        "artifact_type": "codexmax_opaque_tls_agent_boundary_v1",
        "authentication": "mutual_tls_public_identity",
        "minimum_version": "TLSv1.3",
        "fact_authority": False,
        "opaque_agent_required": True,
    }:
        raise PublicProfileError("tls_boundary_invalid", "$.tls_boundary")
    expected_digest = canonical_digest({key: item for key, item in profile.items() if key != "profile_sha256"})
    if profile["profile_sha256"] != expected_digest:
        raise PublicProfileError("public_profile_digest_mismatch", "$.profile_sha256")
    return deepcopy(profile)


def pending_public_profile(selected_candidate: VerifiedSelectedCandidate | None = None) -> dict[str, Any]:
    """Return the complete product-owned profile with external identity pending."""

    profile = {
        "schema_version": 1,
        "artifact_type": PROFILE_TYPE,
        "state": PENDING_STATE,
        "profile_id": PROFILE_ID,
        "runtime_id": RUNTIME_ID,
        "candidate": deepcopy(dict(PENDING_PUBLIC_CANDIDATE_SELECTION if selected_candidate is None else selected_candidate.public_selection())),
        "deployment_identity": None,
        "trust_profile": {"ca_certificate": None, "server_certificate": None},
        "principals": _expected_principals(None),
        "capability_configuration": _capability_configuration(),
        "action_registration_configuration": _action_configuration(),
        "tls_boundary": {
            "artifact_type": "codexmax_opaque_tls_agent_boundary_v1",
            "authentication": "mutual_tls_public_identity",
            "minimum_version": "TLSv1.3",
            "fact_authority": False,
            "opaque_agent_required": True,
        },
        "profile_sha256": "",
    }
    profile["profile_sha256"] = canonical_digest({key: item for key, item in profile.items() if key != "profile_sha256"})
    return profile


def parse_public_profile(
    *, deployment_identity: str, ca_certificate: Mapping[str, Any],
    server_certificate: Mapping[str, Any], client_certificates: Mapping[str, Mapping[str, Any]],
    now: datetime, selected_candidate: VerifiedSelectedCandidate | None = None,
) -> dict[str, Any]:
    """Parse public values into a state that still requires a real handshake."""

    if not isinstance(client_certificates, Mapping) or set(client_certificates) != set(PRINCIPAL_IDS):
        raise PublicProfileError("principal_certificate_inventory_invalid", "$.client_certificates")
    profile = pending_public_profile(selected_candidate)
    profile["state"] = HANDSHAKE_PENDING_STATE
    profile["deployment_identity"] = deployment_identity
    profile["trust_profile"] = {
        "ca_certificate": deepcopy(dict(ca_certificate)),
        "server_certificate": deepcopy(dict(server_certificate)),
    }
    profile["principals"] = _expected_principals(client_certificates)
    profile["profile_sha256"] = canonical_digest({key: item for key, item in profile.items() if key != "profile_sha256"})
    return validate_public_profile(profile, now=now)


HANDSHAKE_EVIDENCE_TYPE = "codexmax_receiver_owned_tls_handshake_evidence_v1"
HANDSHAKE_EVIDENCE_FIELDS = frozenset({
    "schema_version", "artifact_type", "state", "profile_id", "profile_sha256",
    "certificate_set_sha256", "host_id", "service_instance_id", "service_start_id",
    "tls_version", "server_dns_san", "server_eku", "client_auth", "principal_id",
    "server_leaf_sha256", "peer_leaf_sha256", "observed_at", "expires_at", "request_sha256",
    "response_sha256", "nonce_sha256", "receiver_receipt_sha256", "fact_authority",
})


def validate_receiver_handshake_evidence(
    value: Mapping[str, Any], profile: Mapping[str, Any], *, now: datetime,
) -> dict[str, Any]:
    """Validate closure and binding only; never establish receiver provenance."""

    profile = validate_public_profile(profile, now=now)
    if profile["state"] != HANDSHAKE_PENDING_STATE:
        raise PublicProfileError("handshake_profile_state_invalid", "$.profile.state")
    _scan_forbidden_keys(value)
    evidence = _closed(
        value, HANDSHAKE_EVIDENCE_FIELDS,
        "handshake_evidence_shape_invalid", "$.handshake_evidence",
    )
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1:
        raise PublicProfileError("handshake_evidence_version_invalid", "$.handshake_evidence.schema_version")
    if (evidence["artifact_type"] != HANDSHAKE_EVIDENCE_TYPE
            or evidence["state"] != "observed_pending_receiver_provenance"):
        raise PublicProfileError("handshake_evidence_state_invalid", "$.handshake_evidence.state")
    if (evidence["profile_id"] != profile["profile_id"]
            or evidence["profile_sha256"] != profile["profile_sha256"]
            or evidence["certificate_set_sha256"] != _certificate_set_digest(profile)):
        raise PublicProfileError("handshake_profile_binding_invalid", "$.handshake_evidence.profile_sha256")
    if evidence["host_id"] != T071_V10_IDENTITY["host_id"]:
        raise PublicProfileError("handshake_host_identity_invalid", "$.handshake_evidence.host_id")
    for field in ("service_instance_id", "service_start_id", "principal_id"):
        _identifier(evidence[field], "$.handshake_evidence." + field)
    if evidence["service_instance_id"] != "codexmax-external-service-v1":
        raise PublicProfileError("handshake_service_identity_invalid", "$.handshake_evidence.service_instance_id")
    if evidence["tls_version"] != "TLSv1.3":
        raise PublicProfileError("handshake_tls_version_invalid", "$.handshake_evidence.tls_version")
    if (evidence["server_dns_san"] != EXPECTED_DNS_SAN
            or evidence["server_eku"] != "serverAuth"
            or evidence["client_auth"] is not True):
        raise PublicProfileError("handshake_authentication_invalid", "$.handshake_evidence")
    owners = {row["principal_id"]: row for row in profile["principals"]}
    owner = owners.get(evidence["principal_id"])
    if evidence["server_leaf_sha256"] != profile["trust_profile"]["server_certificate"]["certificate_sha256"]:
        raise PublicProfileError("handshake_server_identity_invalid", "$.handshake_evidence.server_leaf_sha256")
    if owner is None or evidence["peer_leaf_sha256"] != owner["client_certificate"]["certificate_sha256"]:
        raise PublicProfileError("handshake_peer_identity_invalid", "$.handshake_evidence.peer_leaf_sha256")
    for field in ("request_sha256", "response_sha256", "nonce_sha256", "receiver_receipt_sha256"):
        _sha(evidence[field], "$.handshake_evidence." + field)
    observed = _parse_time(evidence["observed_at"], "$.handshake_evidence.observed_at")
    expires = _parse_time(evidence["expires_at"], "$.handshake_evidence.expires_at")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > now or expires <= now or observed >= expires:
        raise PublicProfileError("handshake_freshness_invalid", "$.handshake_evidence")
    if evidence["fact_authority"] is not False:
        raise PublicProfileError("certificate_fact_authority_forbidden", "$.handshake_evidence.fact_authority")
    result = deepcopy(evidence)
    result["state"] = "pending_receiver_owned_live_validation"
    return result
