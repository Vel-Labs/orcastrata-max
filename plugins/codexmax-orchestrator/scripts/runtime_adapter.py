#!/usr/bin/env python3
"""Deterministic, evidence-only runtime-adapter snapshot validation.

This module validates synthetic/local snapshot documents.  It does not probe an
adapter, select a route, grant eligibility or authority, execute a provider, or
accept work.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping


_ADAPTER_REGISTRY_PATH = Path(__file__).with_name("adapter_registry.py")
_ADAPTER_REGISTRY_SPEC = importlib.util.spec_from_file_location(
    "runtime_adapter_registry", _ADAPTER_REGISTRY_PATH
)
if _ADAPTER_REGISTRY_SPEC is None or _ADAPTER_REGISTRY_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("adapter registry validator is unavailable")
ADAPTER_REGISTRY = importlib.util.module_from_spec(_ADAPTER_REGISTRY_SPEC)
_ADAPTER_REGISTRY_SPEC.loader.exec_module(ADAPTER_REGISTRY)


SCHEMA_VERSION = 1
SNAPSHOT_VERSION = 1
ARTIFACT_TYPE = "runtime_adapter_snapshot_v1"
IDENTITY_DOMAIN = "codexmax-runtime-adapter-identity-v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECRET_HINT_RE = re.compile(
    r"(?i)(?:bearer|password|passwd|secret|token|api[_-]?key|credential|authorization|://|@)"
)

IDENTITY_FIELDS = (
    "adapter_id",
    "adapter_version",
    "adapter_sha256",
    "route_id",
    "provider_id",
    "exact_model",
    "runtime_id",
    "runtime_version",
    "host_id",
    "transport_id",
    "service_reference_class",
    "billing_basis",
    "billing_provenance",
    "independence_group",
    "input_delivery_profile",
)
ROOT_FIELDS = {
    "schema_version",
    "artifact_type",
    "evaluated_at",
    "adapter_snapshots",
    "route_snapshots",
    "capability_snapshots",
    "health_snapshots",
    "billing_snapshots",
    "usage_snapshots",
    "conformance_snapshots",
    "execution_started",
    "provider_called",
    "acceptance_granted",
}
CHECK_FIELDS = {
    "schema_closed",
    "identity_bound",
    "capability_bound",
    "health_bound",
    "billing_bound",
    "usage_bound",
}


class AdapterSnapshotError(ValueError):
    """Stable typed failure for an invalid adapter snapshot."""

    def __init__(self, code: str, path: str):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise AdapterSnapshotError("nonfinite_number", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nonfinite(child, f"{path}[{index}]")


def canonical_json(value: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes, rejecting non-finite numbers."""
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
        raise AdapterSnapshotError("canonical_json_invalid", "$") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterSnapshotError("duplicate_json_key", key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdapterSnapshotError("nonfinite_number", value)


def load_json_bytes(raw: bytes) -> Any:
    """Strictly decode one UTF-8 JSON value with duplicate-key rejection."""
    if not isinstance(raw, bytes):
        raise AdapterSnapshotError("bytes_required", "$")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AdapterSnapshotError("utf8_invalid", f"byte:{exc.start}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except AdapterSnapshotError:
        raise
    except json.JSONDecodeError as exc:
        raise AdapterSnapshotError("json_invalid", f"line:{exc.lineno}:column:{exc.colno}") from exc
    _reject_nonfinite(value)
    return value


def load_snapshot(path: str | Path) -> Any:
    """Read and strictly parse a local snapshot without modifying it."""
    return load_json_bytes(Path(path).read_bytes())


def _closed_object(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterSnapshotError("object_required", path)
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise AdapterSnapshotError("unknown_field", f"{path}.{unknown[0]}")
    if missing:
        raise AdapterSnapshotError("missing_field", f"{path}.{missing[0]}")
    return value


def _array(value: Any, path: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        raise AdapterSnapshotError("array_required", path)
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AdapterSnapshotError("string_required", path)
    return value


def _identifier(value: Any, path: str) -> str:
    text = _text(value, path)
    if not IDENTIFIER_RE.fullmatch(text):
        raise AdapterSnapshotError("identifier_invalid", path)
    return text


def _digest(value: Any, path: str) -> str:
    text = _text(value, path)
    if not SHA256_RE.fullmatch(text):
        raise AdapterSnapshotError("digest_invalid", path)
    return text


def _optional_digest(value: Any, path: str) -> str:
    if value == "none":
        return value
    return _digest(value, path)


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise AdapterSnapshotError("boolean_required", path)
    return value


def _false(value: Any, path: str) -> None:
    if _boolean(value, path) is not False:
        raise AdapterSnapshotError("effect_flag_must_be_false", path)


def _version(value: Any, path: str) -> None:
    if type(value) is not int or value != SNAPSHOT_VERSION:
        raise AdapterSnapshotError("version_unsupported", path)


def _timestamp(value: Any, path: str) -> datetime:
    text = _text(value, path)
    if not TIMESTAMP_RE.fullmatch(text):
        raise AdapterSnapshotError("timestamp_invalid", path)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdapterSnapshotError("timestamp_invalid", path) from exc


def _enum(value: Any, allowed: set[str], path: str) -> str:
    text = _text(value, path)
    if text not in allowed:
        raise AdapterSnapshotError("enum_invalid", path)
    return text


def _identity(value: Any, path: str) -> dict[str, str]:
    row = _closed_object(value, set(IDENTITY_FIELDS), path)
    result: dict[str, str] = {}
    for field in IDENTITY_FIELDS:
        field_path = f"{path}.{field}"
        result[field] = _digest(row[field], field_path) if field == "adapter_sha256" else _identifier(row[field], field_path)
    if SECRET_HINT_RE.search(result["service_reference_class"]):
        raise AdapterSnapshotError("service_reference_class_secret", f"{path}.service_reference_class")
    return result


def adapter_identity_digest(identity: Mapping[str, Any]) -> str:
    """Digest the complete, canonical adapter/route execution identity."""
    validated = _identity(identity, "identity")
    return canonical_digest({"domain": IDENTITY_DOMAIN, "identity": validated})


def _bound_identity(row: dict[str, Any], path: str) -> tuple[dict[str, str], str]:
    identity = _identity(row["identity"], f"{path}.identity")
    digest = _digest(row["adapter_identity_sha256"], f"{path}.adapter_identity_sha256")
    if digest != adapter_identity_digest(identity):
        raise AdapterSnapshotError("identity_digest_mismatch", f"{path}.adapter_identity_sha256")
    return identity, digest


def _validate_snapshot_version(row: dict[str, Any], path: str) -> None:
    _version(row["snapshot_version"], f"{path}.snapshot_version")


def validate_adapter_snapshot(document: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a closed snapshot and return a non-authoritative receipt."""
    original = copy.deepcopy(document)
    root = _closed_object(document, ROOT_FIELDS, "$")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise AdapterSnapshotError("version_unsupported", "$.schema_version")
    if root["artifact_type"] != ARTIFACT_TYPE:
        raise AdapterSnapshotError("artifact_type_invalid", "$.artifact_type")
    evaluated_at = _timestamp(root["evaluated_at"], "$.evaluated_at")
    for flag in ("execution_started", "provider_called", "acceptance_granted"):
        _false(root[flag], f"$.{flag}")

    identities: dict[str, dict[str, str]] = {}
    adapters = _array(root["adapter_snapshots"], "$.adapter_snapshots")
    for index, item in enumerate(adapters):
        path = f"$.adapter_snapshots[{index}]"
        row = _closed_object(item, {"snapshot_version", "identity", "adapter_identity_sha256", "declared_visible"}, path)
        _validate_snapshot_version(row, path)
        identity, digest = _bound_identity(row, path)
        _boolean(row["declared_visible"], f"{path}.declared_visible")
        if digest in identities:
            raise AdapterSnapshotError("adapter_identity_duplicate", f"{path}.adapter_identity_sha256")
        identities[digest] = identity

    routes = _array(root["route_snapshots"], "$.route_snapshots")
    route_digests: set[str] = set()
    route_ids: set[str] = set()
    for index, item in enumerate(routes):
        path = f"$.route_snapshots[{index}]"
        row = _closed_object(item, {"snapshot_version", "identity", "adapter_identity_sha256", "visible"}, path)
        _validate_snapshot_version(row, path)
        identity, digest = _bound_identity(row, path)
        _boolean(row["visible"], f"{path}.visible")
        if digest not in identities or identities[digest] != identity:
            raise AdapterSnapshotError("route_identity_mismatch", path)
        if digest in route_digests or identity["route_id"] in route_ids:
            raise AdapterSnapshotError("route_identity_duplicate", path)
        route_digests.add(digest)
        route_ids.add(identity["route_id"])
    if route_digests != set(identities):
        raise AdapterSnapshotError("adapter_route_set_mismatch", "$.route_snapshots")

    capability_keys: set[tuple[str, str]] = set()
    usable_capabilities: list[dict[str, str]] = []
    capability_digests: set[str] = set()
    capabilities = _array(root["capability_snapshots"], "$.capability_snapshots")
    for index, item in enumerate(capabilities):
        path = f"$.capability_snapshots[{index}]"
        row = _closed_object(item, {
            "snapshot_version", "identity", "adapter_identity_sha256", "capability_id",
            "provenance", "derived_state", "polarity", "evidence_sha256",
            "task_profile_sha256", "evaluation_manifest_sha256",
            "contradiction_evidence_sha256", "invalidation_evidence_sha256",
            "recall_evidence_sha256", "collected_at", "expires_at", "proof_usable",
        }, path)
        _validate_snapshot_version(row, path)
        identity, digest = _bound_identity(row, path)
        if digest not in identities or identities[digest] != identity:
            raise AdapterSnapshotError("capability_identity_mismatch", path)
        capability_id = _identifier(row["capability_id"], f"{path}.capability_id")
        key = (digest, capability_id)
        if key in capability_keys:
            raise AdapterSnapshotError("capability_duplicate", path)
        capability_keys.add(key)
        provenance = _enum(row["provenance"], {"observed", "declared", "unknown"}, f"{path}.provenance")
        derived_state = _enum(
            row["derived_state"],
            {"active", "stale", "contradictory", "invalidated", "recalled", "unknown"},
            f"{path}.derived_state",
        )
        polarity = _enum(row["polarity"], {"positive", "negative", "unknown"}, f"{path}.polarity")
        _digest(row["evidence_sha256"], f"{path}.evidence_sha256")
        _digest(row["task_profile_sha256"], f"{path}.task_profile_sha256")
        _digest(row["evaluation_manifest_sha256"], f"{path}.evaluation_manifest_sha256")
        contradiction = _optional_digest(row["contradiction_evidence_sha256"], f"{path}.contradiction_evidence_sha256")
        invalidation = _optional_digest(row["invalidation_evidence_sha256"], f"{path}.invalidation_evidence_sha256")
        recall = _optional_digest(row["recall_evidence_sha256"], f"{path}.recall_evidence_sha256")
        collected_at = _timestamp(row["collected_at"], f"{path}.collected_at")
        expires_at = _timestamp(row["expires_at"], f"{path}.expires_at")
        if expires_at <= collected_at:
            raise AdapterSnapshotError("evidence_window_invalid", path)
        if collected_at > evaluated_at:
            raise AdapterSnapshotError("evidence_from_future", path)
        fresh = evaluated_at < expires_at
        if derived_state == "active" and not fresh:
            raise AdapterSnapshotError("capability_derived_state_mismatch", f"{path}.derived_state")
        if derived_state == "stale" and fresh:
            raise AdapterSnapshotError("capability_derived_state_mismatch", f"{path}.derived_state")
        state_evidence = {
            "contradictory": contradiction,
            "invalidated": invalidation,
            "recalled": recall,
        }
        for state, evidence in state_evidence.items():
            if (derived_state == state) != (evidence != "none"):
                raise AdapterSnapshotError("capability_state_evidence_mismatch", f"{path}.{state}_evidence_sha256")
        derived_usable = (
            provenance == "observed"
            and polarity == "positive"
            and fresh
            and derived_state == "active"
            and contradiction == "none"
            and invalidation == "none"
            and recall == "none"
        )
        if _boolean(row["proof_usable"], f"{path}.proof_usable") != derived_usable:
            raise AdapterSnapshotError("capability_proof_state_mismatch", f"{path}.proof_usable")
        if derived_usable:
            usable_capabilities.append({"adapter_identity_sha256": digest, "capability_id": capability_id})
            capability_digests.add(digest)
    if set(identities) - capability_digests and not all(
        any(key[0] == digest for key in capability_keys) for digest in identities
    ):
        raise AdapterSnapshotError("capability_snapshot_missing", "$.capability_snapshots")

    def validate_singleton_family(
        name: str,
        fields: set[str],
        validator: Any,
    ) -> None:
        seen: set[str] = set()
        for index, item in enumerate(_array(root[name], f"$.{name}")):
            path = f"$.{name}[{index}]"
            row = _closed_object(item, fields, path)
            _validate_snapshot_version(row, path)
            identity, digest = _bound_identity(row, path)
            if digest not in identities or identities[digest] != identity:
                raise AdapterSnapshotError("snapshot_identity_mismatch", path)
            if digest in seen:
                raise AdapterSnapshotError("snapshot_identity_duplicate", path)
            seen.add(digest)
            validator(row, path, evaluated_at)
        if seen != set(identities):
            raise AdapterSnapshotError("snapshot_identity_set_mismatch", f"$.{name}")

    def validate_health(row: dict[str, Any], path: str, now: datetime) -> None:
        status = _enum(row["status"], {"healthy", "degraded", "unhealthy", "unknown"}, f"{path}.status")
        provenance = _enum(row["provenance"], {"observed", "declared", "unknown"}, f"{path}.provenance")
        _text(row["evidence_ref"], f"{path}.evidence_ref")
        _digest(row["evidence_sha256"], f"{path}.evidence_sha256")
        recorded_at = _timestamp(row["recorded_at"], f"{path}.recorded_at")
        expires_at = _timestamp(row["expires_at"], f"{path}.expires_at")
        if expires_at <= recorded_at:
            raise AdapterSnapshotError("evidence_window_invalid", path)
        if recorded_at > now:
            raise AdapterSnapshotError("evidence_from_future", f"{path}.recorded_at")
        fresh = now < expires_at
        if _boolean(row["fresh"], f"{path}.fresh") != fresh:
            raise AdapterSnapshotError("health_freshness_mismatch", f"{path}.fresh")
        if (status == "unknown") != (provenance == "unknown"):
            raise AdapterSnapshotError("health_provenance_mismatch", path)
        if status == "healthy" and provenance != "observed":
            raise AdapterSnapshotError("healthy_not_observed", path)
        if status == "healthy" and not fresh:
            raise AdapterSnapshotError("healthy_evidence_stale", path)

    validate_singleton_family(
        "health_snapshots",
        {"snapshot_version", "identity", "adapter_identity_sha256", "status", "provenance", "evidence_ref", "evidence_sha256", "recorded_at", "expires_at", "fresh"},
        validate_health,
    )

    def validate_billing(row: dict[str, Any], path: str, now: datetime) -> None:
        basis = _enum(row["basis"], {"free", "subscription", "metered", "unknown"}, f"{path}.basis")
        provenance = _enum(row["provenance"], {"observed", "declared", "unknown"}, f"{path}.provenance")
        _text(row["evidence_ref"], f"{path}.evidence_ref")
        _digest(row["evidence_sha256"], f"{path}.evidence_sha256")
        if _timestamp(row["recorded_at"], f"{path}.recorded_at") > now:
            raise AdapterSnapshotError("evidence_from_future", f"{path}.recorded_at")
        if (basis == "unknown") != (provenance == "unknown"):
            raise AdapterSnapshotError("billing_provenance_mismatch", path)
        identity = row["identity"]
        if basis != identity["billing_basis"] or provenance != identity["billing_provenance"]:
            raise AdapterSnapshotError("billing_identity_mismatch", path)

    validate_singleton_family(
        "billing_snapshots",
        {"snapshot_version", "identity", "adapter_identity_sha256", "basis", "provenance", "evidence_ref", "evidence_sha256", "recorded_at"},
        validate_billing,
    )

    usage_ids: set[str] = set()
    usage_evidence_ids: set[str] = set()
    usage_evidence_digests: set[str] = set()
    usage_digests: set[str] = set()
    usages = _array(root["usage_snapshots"], "$.usage_snapshots")
    for index, item in enumerate(usages):
        path = f"$.usage_snapshots[{index}]"
        row = _closed_object(item, {
            "snapshot_version", "identity", "adapter_identity_sha256", "tokens",
            "external_cost_microunits", "provenance", "usage_evidence_id",
            "usage_evidence_sha256", "recorded_at", "anti_double_counting_id",
        }, path)
        _validate_snapshot_version(row, path)
        identity, digest = _bound_identity(row, path)
        if digest not in identities or identities[digest] != identity:
            raise AdapterSnapshotError("usage_identity_mismatch", path)
        if digest in usage_digests:
            raise AdapterSnapshotError("usage_identity_duplicate", f"{path}.adapter_identity_sha256")
        usage_digests.add(digest)
        evidence_id = _identifier(row["usage_evidence_id"], f"{path}.usage_evidence_id")
        evidence_digest = _digest(row["usage_evidence_sha256"], f"{path}.usage_evidence_sha256")
        if evidence_id in usage_evidence_ids:
            raise AdapterSnapshotError("usage_evidence_id_duplicate", f"{path}.usage_evidence_id")
        usage_evidence_ids.add(evidence_id)
        if evidence_digest in usage_evidence_digests:
            raise AdapterSnapshotError("usage_evidence_sha256_duplicate", f"{path}.usage_evidence_sha256")
        usage_evidence_digests.add(evidence_digest)
        if _timestamp(row["recorded_at"], f"{path}.recorded_at") > evaluated_at:
            raise AdapterSnapshotError("evidence_from_future", f"{path}.recorded_at")
        unknowns: list[bool] = []
        for field in ("tokens", "external_cost_microunits"):
            value = row[field]
            if value == "unknown":
                unknowns.append(True)
            elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise AdapterSnapshotError("usage_value_invalid", f"{path}.{field}")
            else:
                unknowns.append(False)
        provenance = _enum(row["provenance"], {"observed", "estimated", "unknown"}, f"{path}.provenance")
        if any(unknowns) and not all(unknowns):
            raise AdapterSnapshotError("usage_unknown_mixed", path)
        if all(unknowns) and provenance != "unknown":
            raise AdapterSnapshotError("usage_unknown_coerced", path)
        if not any(unknowns) and provenance not in {"observed", "estimated"}:
            raise AdapterSnapshotError("usage_numeric_provenance_invalid", path)
        usage_id = _identifier(row["anti_double_counting_id"], f"{path}.anti_double_counting_id")
        if usage_id in usage_ids:
            raise AdapterSnapshotError("usage_anti_double_counting_id_duplicate", f"{path}.anti_double_counting_id")
        usage_ids.add(usage_id)
    if usage_digests != set(identities):
        raise AdapterSnapshotError("usage_identity_set_mismatch", "$.usage_snapshots")

    def validate_conformance(row: dict[str, Any], path: str, _now: datetime) -> None:
        checks = _closed_object(row["checks"], CHECK_FIELDS, f"{path}.checks")
        for field in CHECK_FIELDS:
            _boolean(checks[field], f"{path}.checks.{field}")
        if _boolean(row["conformant"], f"{path}.conformant") != all(checks.values()):
            raise AdapterSnapshotError("conformance_state_mismatch", f"{path}.conformant")
        for flag in ("execution_started", "provider_called", "acceptance_granted"):
            _false(row[flag], f"{path}.{flag}")

    validate_singleton_family(
        "conformance_snapshots",
        {"snapshot_version", "identity", "adapter_identity_sha256", "checks", "conformant", "execution_started", "provider_called", "acceptance_granted"},
        validate_conformance,
    )

    if document != original:
        raise AdapterSnapshotError("input_mutated", "$")
    return {
        "artifact_type": "runtime_adapter_validation_receipt_v1",
        "valid": True,
        "snapshot_sha256": canonical_digest(document),
        "adapter_count": len(adapters),
        "route_count": len(routes),
        "proof_usable_capabilities": usable_capabilities,
        "execution_started": False,
        "provider_called": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "acceptance_granted": False,
        "side_effect_free": True,
    }


validate_snapshot = validate_adapter_snapshot


def validate_adapter_qualification(
    registry: Mapping[str, Any], *, evaluated_at: str
) -> dict[str, Any]:
    """Validate qualification state without granting dispatch eligibility.

    A qualified certificate remains evidence-only here.  In particular,
    ``execution_unknown`` is terminal for automatic retry and fallback.
    """
    receipt = ADAPTER_REGISTRY.validate_registry(
        registry, evaluated_at=evaluated_at, configuration_only=False
    )
    return {
        "artifact_type": "runtime_adapter_qualification_receipt_v1",
        "registry_sha256": receipt["registry_sha256"],
        "binding_states": receipt["binding_states"],
        "proof_qualified_bindings": sorted(
            name for name, state in receipt["binding_states"].items()
            if state == "qualified"
        ),
        "execution_unknown_blocks_retry": True,
        "retry_started": False,
        "fallback_started": False,
        "provider_called": False,
        "execution_started": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "acceptance_granted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = validate_adapter_snapshot(load_snapshot(args.snapshot))
    except (AdapterSnapshotError, OSError) as exc:
        if isinstance(exc, AdapterSnapshotError):
            failure = {"status": "fail", "code": exc.code, "path": exc.path}
        else:
            failure = {"status": "fail", "code": "snapshot_read_failed", "path": str(args.snapshot)}
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
