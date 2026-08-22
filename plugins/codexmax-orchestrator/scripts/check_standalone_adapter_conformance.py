#!/usr/bin/env python3
"""Closed, static adapter-author conformance validation.

The runner reads JSON evidence only.  It imports four fixed package-local
runtime primitives and never imports adapter/provider code, resolves a caller
module path, calls a provider, reads configuration, or performs an effect.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping

import runtime_adapter
import runtime_evidence
import runtime_planner
import standalone_runtime_cli


SCHEMA_VERSION = 1
BUNDLE_TYPE = "standalone_adapter_conformance_bundle_v1"
CASES_TYPE = "standalone_adapter_conformance_cases_v1"
RECEIPT_TYPE = "standalone_adapter_conformance_receipt_v1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UNSAFE_TEXT = re.compile(
    r"(?i)(?:https?://|wss?://|bearer\s|api[_-]?key|password|passwd|secret|"
    r"credential\s*[:=]|authorization\s*[:=]|-----begin|\$\{|sk-[a-z0-9])"
)

PRIMITIVES = [
    "runtime_adapter",
    "runtime_planner",
    "runtime_evidence",
    "standalone_runtime_cli",
]
CAPABILITY_STATES = [
    "declared", "unknown", "stale", "contradictory", "recalled", "foreign",
]
AUTHORITY_SOURCES = ["role", "route", "model", "conformance", "provider_identity"]
BILLING_STATES = ["unknown", "foreign"]
USAGE_STATES = ["unknown", "foreign"]
EFFECT_FIELDS = [
    "execution_started", "provider_called", "network_used", "filesystem_mutated",
    "child_dispatched", "lease_created", "run_mutated", "journal_written",
    "policy_persisted", "capability_granted", "authority_granted",
    "eligibility_granted", "acceptance_granted", "persistence_granted",
]
SIDE_CHANNEL_FIELDS = [
    "provider_headers", "provider_urls", "provider_endpoints", "environment",
    "credentials", "raw_io", "hidden_options", "unknown_extensions",
]
ROOT_FIELDS = {
    "schema_version", "artifact_type", "bundle_id", "adapter_identity_sha256",
    "runtime_primitives", "provider_code", "delegation", "journal",
    "capability_claims", "authority_claims", "billing_claims", "usage_claims",
    "effects", "side_channels", "acceptance_claimed",
}


class ConformanceError(ValueError):
    """Stable fail-closed error with a machine-readable code and path."""

    def __init__(self, code: str, path: str = "$"):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError("duplicate_json_key", key)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ConformanceError("nonfinite_number", value)


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ConformanceError("nonfinite_number", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nonfinite(child, f"{path}[{index}]")


def load_json(path: str | Path) -> Any:
    """Strictly load one local JSON input with no duplicate keys."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ConformanceError("input_read_failed", str(path)) from exc
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConformanceError("utf8_invalid", f"byte:{exc.start}") from exc
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except ConformanceError:
        raise
    except json.JSONDecodeError as exc:
        raise ConformanceError("json_invalid", f"line:{exc.lineno}:column:{exc.colno}") from exc
    _reject_nonfinite(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _reject_nonfinite(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ConformanceError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConformanceError("object_required", path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise ConformanceError("unknown_field", f"{path}.{extra[0]}")
    if missing:
        raise ConformanceError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ConformanceError("identifier_invalid", path)
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ConformanceError("digest_invalid", path)
    return value


def _false(value: Any, code: str, path: str) -> None:
    if value is not False:
        raise ConformanceError(code, path)


def _scan_unsafe(value: Any, path: str = "$") -> None:
    if isinstance(value, str) and UNSAFE_TEXT.search(value):
        raise ConformanceError("unsafe_provider_value", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _scan_unsafe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_unsafe(child, f"{path}[{index}]")


def _exact_named_rows(
    value: Any,
    expected: list[str],
    name_field: str,
    fields: set[str],
    path: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(expected):
        raise ConformanceError("coverage_incomplete", path)
    rows: list[dict[str, Any]] = []
    names: list[str] = []
    for index, raw in enumerate(value):
        row_path = f"{path}[{index}]"
        row = _closed(raw, fields, row_path)
        names.append(_identifier(row[name_field], f"{row_path}.{name_field}"))
        rows.append(row)
    if names != expected:
        raise ConformanceError("coverage_incomplete", path)
    return rows


def _known_usage_row(identity: str) -> dict[str, Any]:
    measure = {
        "status": "observed", "value": 0, "provenance": "runtime_measurement",
        "evidence_sha256": "sha256:" + "0" * 64, "unknown_reason": None,
    }
    return {
        "usage_id": f"usage-{identity}",
        "anti_double_counting_id": identity,
        "run_id": "conformance-run",
        "lineage_run_id": "conformance-run",
        "input_tokens": copy.deepcopy(measure),
        "output_tokens": copy.deepcopy(measure),
        "total_tokens": copy.deepcopy(measure),
        "external_cost_microunits": copy.deepcopy(measure),
    }


def _probe_fixed_primitives() -> None:
    probe = {"artifact_type": BUNDLE_TYPE, "schema_version": SCHEMA_VERSION}
    if runtime_adapter.canonical_digest(probe) != digest(probe):
        raise ConformanceError("primitive_adapter_mismatch")
    if runtime_planner.V1_MAXIMA != {
        "depth": 1, "total_children": 1, "active_children": 1,
        "active_descendants": 1,
    }:
        raise ConformanceError("primitive_planner_mismatch")
    guarantees = standalone_runtime_cli.EFFECT_GUARANTEES
    if not isinstance(guarantees, dict) or not guarantees or any(value is not False for value in guarantees.values()):
        raise ConformanceError("primitive_cli_effect_mismatch")
    usage = [_known_usage_row("conformance-usage-a")]
    normalized = runtime_evidence.normalize_usage(usage)
    if normalized["anti_double_counting_ids"] != ["conformance-usage-a"]:
        raise ConformanceError("primitive_evidence_mismatch")
    duplicate = usage + [_known_usage_row("conformance-usage-a")]
    try:
        runtime_evidence.normalize_usage(duplicate)
    except runtime_evidence.EvidenceError as exc:
        if exc.code != "usage_double_count":
            raise ConformanceError("primitive_evidence_mismatch") from exc
    else:
        raise ConformanceError("primitive_evidence_mismatch")


def validate_bundle(document: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one declarative bundle and return a non-authoritative receipt."""
    original = copy.deepcopy(document)
    root = _closed(document, ROOT_FIELDS, "$")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise ConformanceError("version_unsupported", "$.schema_version")
    if root["artifact_type"] != BUNDLE_TYPE:
        raise ConformanceError("artifact_type_invalid", "$.artifact_type")
    _identifier(root["bundle_id"], "$.bundle_id")
    _digest(root["adapter_identity_sha256"], "$.adapter_identity_sha256")
    if root["runtime_primitives"] != PRIMITIVES:
        raise ConformanceError("runtime_primitive_set_invalid", "$.runtime_primitives")
    _false(root["provider_code"], "provider_code_forbidden", "$.provider_code")

    delegation = _closed(root["delegation"], {
        "status", "child_materialized", "child_usage_included",
        "child_artifacts_included", "child_journal_included",
        "child_lifecycle_included",
    }, "$.delegation")
    if delegation["status"] not in {"unsupported", "denied"}:
        raise ConformanceError("delegation_status_invalid", "$.delegation.status")
    for field in (
        "child_materialized", "child_usage_included", "child_artifacts_included",
        "child_journal_included", "child_lifecycle_included",
    ):
        _false(delegation[field], f"delegation_{field}", f"$.delegation.{field}")

    journal = _closed(root["journal"], {
        "scope", "ttl_seconds", "redacted", "executable", "authoritative",
        "global", "mutable", "persistence_claimed",
    }, "$.journal")
    if journal["scope"] != "current_workgraph_subtree":
        raise ConformanceError("journal_scope_invalid", "$.journal.scope")
    if type(journal["ttl_seconds"]) is not int or not 1 <= journal["ttl_seconds"] <= 1800:
        raise ConformanceError("journal_ttl_invalid", "$.journal.ttl_seconds")
    if journal["redacted"] is not True:
        raise ConformanceError("journal_redaction_required", "$.journal.redacted")
    _false(journal["executable"], "journal_executable", "$.journal.executable")
    _false(journal["authoritative"], "journal_authoritative", "$.journal.authoritative")
    _false(journal["global"], "journal_global", "$.journal.global")
    _false(journal["mutable"], "journal_mutable", "$.journal.mutable")
    _false(journal["persistence_claimed"], "journal_persistence_forbidden", "$.journal.persistence_claimed")

    capabilities = _exact_named_rows(
        root["capability_claims"], CAPABILITY_STATES, "state",
        {"state", "usable"}, "$.capability_claims",
    )
    for index, row in enumerate(capabilities):
        _false(row["usable"], "capability_unusable_state", f"$.capability_claims[{index}].usable")

    authorities = _exact_named_rows(
        root["authority_claims"], AUTHORITY_SOURCES, "source",
        {"source", "grants_authority"}, "$.authority_claims",
    )
    for index, row in enumerate(authorities):
        _false(row["grants_authority"], "authority_source_forbidden", f"$.authority_claims[{index}].grants_authority")

    billing = _exact_named_rows(
        root["billing_claims"], BILLING_STATES, "state",
        {"state", "usable"}, "$.billing_claims",
    )
    for index, row in enumerate(billing):
        _false(row["usable"], "billing_unusable_state", f"$.billing_claims[{index}].usable")

    usage = _exact_named_rows(
        root["usage_claims"], USAGE_STATES, "state",
        {"state", "anti_double_counting_id", "counted"}, "$.usage_claims",
    )
    usage_ids: set[str] = set()
    for index, row in enumerate(usage):
        row_path = f"$.usage_claims[{index}]"
        identity = _identifier(row["anti_double_counting_id"], f"{row_path}.anti_double_counting_id")
        if identity in usage_ids:
            raise ConformanceError("usage_double_count", f"{row_path}.anti_double_counting_id")
        usage_ids.add(identity)
        _false(row["counted"], "usage_unusable_state", f"{row_path}.counted")

    effects = _closed(root["effects"], set(EFFECT_FIELDS), "$.effects")
    for field in EFFECT_FIELDS:
        _false(effects[field], "positive_effect_forbidden", f"$.effects.{field}")
    side_channels = _closed(root["side_channels"], set(SIDE_CHANNEL_FIELDS), "$.side_channels")
    for field in SIDE_CHANNEL_FIELDS:
        _false(side_channels[field], "provider_side_channel_forbidden", f"$.side_channels.{field}")
    _false(root["acceptance_claimed"], "acceptance_claim_forbidden", "$.acceptance_claimed")
    _scan_unsafe(root)
    _probe_fixed_primitives()
    if document != original:
        raise ConformanceError("input_mutated")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "bundle_id": root["bundle_id"],
        "bundle_sha256": digest(root),
        "runtime_primitives": list(PRIMITIVES),
        "proof_boundary": "static_local_non_authoritative",
        "capability_granted": False,
        "authority_granted": False,
        "eligibility_granted": False,
        "execution_started": False,
        "provider_called": False,
        "network_used": False,
        "filesystem_mutated": False,
        "effects_performed": False,
        "acceptance_granted": False,
        "persistence_granted": False,
    }


def _validate_cases(document: Any) -> list[dict[str, Any]]:
    root = _closed(document, {"schema_version", "artifact_type", "cases"}, "$.cases_document")
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != SCHEMA_VERSION
        or root["artifact_type"] != CASES_TYPE
    ):
        raise ConformanceError("cases_version_invalid", "$.cases_document")
    if not isinstance(root["cases"], list) or not root["cases"]:
        raise ConformanceError("cases_required", "$.cases_document.cases")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(root["cases"]):
        path = f"$.cases_document.cases[{index}]"
        row = _closed(raw, {"case_id", "path", "value", "expected_code"}, path)
        case_id = _identifier(row["case_id"], f"{path}.case_id")
        if case_id in seen:
            raise ConformanceError("case_duplicate", f"{path}.case_id")
        seen.add(case_id)
        if not isinstance(row["path"], list) or not row["path"]:
            raise ConformanceError("case_path_invalid", f"{path}.path")
        for part_index, part in enumerate(row["path"]):
            if not isinstance(part, (str, int)) or type(part) is bool:
                raise ConformanceError("case_path_invalid", f"{path}.path[{part_index}]")
        _identifier(row["expected_code"], f"{path}.expected_code")
        result.append(row)
    return result


def _mutate(document: dict[str, Any], path: list[Any], value: Any) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = copy.deepcopy(value)


def run_suite(bundle: Mapping[str, Any], cases_document: Any) -> dict[str, Any]:
    receipt = validate_bundle(bundle)
    cases = _validate_cases(cases_document)
    for case in cases:
        candidate = copy.deepcopy(bundle)
        try:
            _mutate(candidate, case["path"], case["value"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ConformanceError("case_path_invalid", case["case_id"]) from exc
        try:
            validate_bundle(candidate)
        except ConformanceError as exc:
            if exc.code != case["expected_code"]:
                raise ConformanceError("case_expected_code_mismatch", case["case_id"]) from exc
        else:
            raise ConformanceError("adversarial_case_accepted", case["case_id"])
    result = copy.deepcopy(receipt)
    result["cases_sha256"] = digest(cases_document)
    result["adversarial_case_count"] = len(cases)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, help="Static adapter-author bundle JSON")
    parser.add_argument("--cases", required=True, help="Static adversarial case JSON")
    args = parser.parse_args(argv)
    try:
        result = run_suite(load_json(args.bundle), load_json(args.cases))
    except ConformanceError as exc:
        error = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "standalone_adapter_conformance_error_v1",
            "code": exc.code,
            "path": exc.path,
            "capability_granted": False,
            "authority_granted": False,
            "execution_started": False,
            "provider_called": False,
            "acceptance_granted": False,
        }
        print(json.dumps(error, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
