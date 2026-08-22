#!/usr/bin/env python3
"""Compile and validate inert, hash-bound provider telemetry projections."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Mapping


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "ProviderCompactTelemetryV1"
SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+~-]{0,255}$")
UNKNOWN_REASONS = {
    "not_emitted",
    "not_reported",
    "no_provider_attempt",
    "not_applicable",
}
MEASUREMENTS = ("tokens", "cost_usd", "latency_ms", "turns", "quality_score")
ROOT_FIELDS = {
    "schema_version", "artifact_type", "dispatch_id", "recorded_at", "expires_at",
    "task_family", "requested_identity", "observed_identity", "terminal",
    "measurements", "evidence", "advisory", "unknowns", "telemetry_sha256",
}
REQUESTED_IDENTITY_FIELDS = {
    "route_name", "provider", "model", "route_id", "runtime", "billing_basis",
}
OBSERVED_IDENTITY_FIELDS = {"provider", "model", "route_id", "runtime"}
TERMINAL_FIELDS = {
    "status", "outcome", "process_started", "external_call_performed",
    "provider_network_performed", "timed_out", "output_limit_stream",
    "retry_count", "fallback_used", "hedge_used", "model_substitution_used",
}
MEASUREMENT_FIELDS = {"state", "value", "reason"}
EVIDENCE_FIELDS = {"return_manifest", "stdout", "stderr", "artifact"}
DESCRIPTOR_FIELDS = {"path", "bytes", "sha256"}
ADVISORY_FIELDS = {
    "disposition", "affects_ranking", "execution_authority", "route_selection",
    "retry_allowed", "fallback_allowed", "compiler_started_provider_call",
    "board_mutated", "accepted_by_parent",
}
MANIFEST_FIELDS = {
    "schema_version", "manifest_type", "dispatch_id", "proof_mode", "semantic_role",
    "resolver_role", "role_priority", "effective_config_sha256", "status", "failure",
    "external_call_performed", "provider_network_performed", "selected_route",
    "artifact", "attempts", "route_resolution", "usage", "provider_change_receipt",
    "acceptance_authority", "accepted", "applied_to_goalbuddy", "applied_to_supervisor",
    "supervisor_handoff",
}
CURRENT_MANIFEST_FIELDS = MANIFEST_FIELDS | {"execution_owner", "project_usage"}


class TelemetryError(ValueError):
    def __init__(self, code: str, path: str = "") -> None:
        super().__init__(f"{code}: {path}" if path else code)
        self.code = code
        self.path = path


class _DuplicateKey(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TelemetryError("closed_object_invalid", path)
    return copy.deepcopy(dict(value))


def _text(value: Any, path: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TelemetryError("text_invalid", path)
    if identifier and not IDENTIFIER.fullmatch(value):
        raise TelemetryError("identifier_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    text = _text(value, path)
    if not text.endswith("Z"):
        raise TelemetryError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise TelemetryError("timestamp_invalid", path) from exc
    if parsed.tzinfo != timezone.utc:
        raise TelemetryError("timestamp_invalid", path)
    return parsed


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise TelemetryError("digest_invalid", path)
    return value.removeprefix("sha256:")


def _strict_json(data: bytes, path: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey(key)
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=hook)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey) as exc:
        raise TelemetryError("json_invalid", path) from exc
    if not isinstance(value, dict):
        raise TelemetryError("object_required", path)
    return value


def _canonical_root(value: Path) -> Path:
    lexical = Path(os.path.abspath(value))
    try:
        info = os.lstat(lexical)
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise TelemetryError("root_invalid", "repo_root") from exc
    if lexical != resolved or not stat.S_ISDIR(info.st_mode):
        raise TelemetryError("root_invalid", "repo_root")
    return resolved


def _regular_file(path: Path, root: Path, field: str, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    lexical = Path(os.path.abspath(path))
    try:
        lexical.relative_to(root)
        before = os.lstat(lexical)
        resolved = lexical.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise TelemetryError("evidence_path_invalid", field) from exc
    if lexical != resolved or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise TelemetryError("evidence_file_unsafe", field)
    if before.st_size > max_bytes:
        raise TelemetryError("evidence_file_too_large", field)
    data = lexical.read_bytes()
    after = os.lstat(lexical)
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise TelemetryError("evidence_file_drift", field)
    return data


def _descriptor(value: Any, root: Path, field: str) -> dict[str, Any]:
    row = _closed(value, DESCRIPTOR_FIELDS, field)
    relative = Path(_text(row["path"], f"{field}.path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise TelemetryError("evidence_path_invalid", f"{field}.path")
    if isinstance(row["bytes"], bool) or not isinstance(row["bytes"], int) or row["bytes"] < 0:
        raise TelemetryError("bytes_invalid", f"{field}.bytes")
    expected = _sha(row["sha256"], f"{field}.sha256")
    data = _regular_file(root / relative, root, field)
    if len(data) != row["bytes"]:
        raise TelemetryError("evidence_size_mismatch", field)
    if hashlib.sha256(data).hexdigest() != expected:
        raise TelemetryError("evidence_digest_mismatch", field)
    return {"path": relative.as_posix(), "bytes": len(data), "sha256": "sha256:" + expected}


def known(value: int | float) -> dict[str, Any]:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise TelemetryError("measurement_value_invalid", "measurement")
    return {"state": "observed", "value": value, "reason": None}


def unknown(reason: str) -> dict[str, Any]:
    if reason not in UNKNOWN_REASONS:
        raise TelemetryError("unknown_reason_invalid", "measurement")
    return {"state": "unknown", "value": None, "reason": reason}


def _measurement(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, MEASUREMENT_FIELDS, path)
    if row["state"] == "observed":
        if row["reason"] is not None:
            raise TelemetryError("measurement_reason_invalid", path)
        return known(row["value"])
    if row["state"] == "unknown" and row["value"] is None:
        return unknown(row["reason"])
    raise TelemetryError("measurement_state_invalid", path)


def _observation(value: Any, path: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        if set(value) != {"value", "reason"}:
            return unknown("not_reported")
        candidate = value["value"]
        if candidate == "unknown":
            return unknown("not_reported")
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool) and candidate >= 0:
            return known(candidate)
        return unknown("not_reported")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return known(value)
    return unknown("not_reported")


def _requested_identity(attempt: Mapping[str, Any]) -> dict[str, str]:
    identity = attempt.get("identity")
    if not isinstance(identity, Mapping):
        raise TelemetryError("attempt_identity_invalid", "manifest.attempts[0].identity")
    result = {
        "route_name": attempt.get("route_name"),
        "provider": identity.get("provider"),
        "model": identity.get("model"),
        "route_id": identity.get("route"),
        "runtime": identity.get("runtime"),
        "billing_basis": identity.get("billing", "unknown"),
    }
    return {key: _text(value, f"requested_identity.{key}") for key, value in result.items()}


def _manifest(path: Path, root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    data = _regular_file(path, root, "return_manifest")
    value = _strict_json(data, "return_manifest")
    fields = CURRENT_MANIFEST_FIELDS if set(value) == CURRENT_MANIFEST_FIELDS else MANIFEST_FIELDS
    manifest = _closed(value, fields, "return_manifest")
    if manifest["schema_version"] != 1 or manifest["manifest_type"] != "DispatchReturnManifest":
        raise TelemetryError("manifest_type_invalid", "return_manifest")
    if fields == CURRENT_MANIFEST_FIELDS:
        if manifest["execution_owner"] != "orcastrata_managed":
            raise TelemetryError("execution_owner_invalid", "return_manifest.execution_owner")
        usage = manifest["project_usage"]
        if not isinstance(usage, Mapping) or set(usage) not in ({"status", "ledger"}, {"status", "code"}):
            raise TelemetryError("project_usage_invalid", "return_manifest.project_usage")
        if usage["status"] not in {"appended", "not_recorded", "not_initialized", "failed"}:
            raise TelemetryError("project_usage_invalid", "return_manifest.project_usage.status")
        if set(usage) == {"status", "ledger"} and usage["ledger"] is not None and not isinstance(usage["ledger"], str):
            raise TelemetryError("project_usage_invalid", "return_manifest.project_usage.ledger")
        if set(usage) == {"status", "code"} and not isinstance(usage["code"], str):
            raise TelemetryError("project_usage_invalid", "return_manifest.project_usage.code")
    if manifest["accepted"] is not False or manifest["applied_to_goalbuddy"] is not False or manifest["applied_to_supervisor"] is not False:
        raise TelemetryError("manifest_effect_invalid", "return_manifest")
    relative = path.resolve(strict=True).relative_to(root).as_posix()
    descriptor = {
        "path": relative,
        "bytes": len(data),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
    }
    return manifest, descriptor


def compile_telemetry(
    manifest_path: Path, repo_root: Path, *, recorded_at: str, expires_at: str,
) -> dict[str, Any]:
    root = _canonical_root(repo_root)
    recorded = _timestamp(recorded_at, "recorded_at")
    expires = _timestamp(expires_at, "expires_at")
    if not recorded < expires or (expires - recorded).total_seconds() > 14 * 24 * 60 * 60:
        raise TelemetryError("evidence_window_invalid", "expires_at")
    manifest, manifest_descriptor = _manifest(manifest_path, root)
    attempts = manifest["attempts"]
    if not isinstance(attempts, list) or len(attempts) > 1:
        raise TelemetryError("single_attempt_required", "return_manifest.attempts")
    task_family = _text(manifest["semantic_role"], "return_manifest.semantic_role", identifier=True)
    if attempts:
        attempt = attempts[0]
        if not isinstance(attempt, Mapping):
            raise TelemetryError("attempt_invalid", "return_manifest.attempts[0]")
        requested_identity = _requested_identity(attempt)
        stdout = _descriptor(attempt.get("stdout"), root, "stdout")
        stderr = _descriptor(attempt.get("stderr"), root, "stderr")
        timed_out = attempt.get("timed_out")
        if type(timed_out) is not bool:
            raise TelemetryError("boolean_required", "terminal.timed_out")
        output_limit = attempt.get("output_limit_stream")
        if output_limit not in {None, "stdout", "stderr"}:
            raise TelemetryError("output_limit_invalid", "terminal.output_limit_stream")
        process_started = attempt.get("returncode") is not None
        outcome = _text(attempt.get("outcome"), "terminal.outcome", identifier=True)
        measurements = {
            "tokens": _observation(attempt.get("tokens"), "measurements.tokens"),
            "cost_usd": _observation(attempt.get("cost"), "measurements.cost_usd"),
            "latency_ms": _observation(attempt.get("elapsed_time_ms"), "measurements.latency_ms"),
            "turns": unknown("not_emitted"),
            "quality_score": unknown("not_applicable"),
        }
    else:
        route = manifest.get("route_resolution")
        requested = route.get("next_attempt") if isinstance(route, Mapping) else None
        if isinstance(requested, Mapping) and isinstance(requested.get("identity"), Mapping):
            requested_identity = _requested_identity({
                "route_name": requested.get("route_name"), "identity": requested["identity"],
            })
        else:
            requested_identity = {field: "unknown" for field in REQUESTED_IDENTITY_FIELDS}
        stdout = None
        stderr = None
        timed_out = False
        output_limit = None
        process_started = False
        outcome = "no_provider_attempt"
        measurements = {field: unknown("no_provider_attempt") for field in MEASUREMENTS}
    artifact = manifest.get("artifact")
    artifact_descriptor = None if artifact is None else _descriptor(artifact, root, "artifact")
    network = manifest["provider_network_performed"]
    if network not in {True, False, "unknown"}:
        raise TelemetryError("network_observation_invalid", "terminal.provider_network_performed")
    external = manifest["external_call_performed"]
    if type(external) is not bool:
        raise TelemetryError("boolean_required", "terminal.external_call_performed")
    if external and network is False:
        raise TelemetryError(
            "external_network_observation_contradiction",
            "terminal.provider_network_performed",
        )
    if network is True and not external:
        raise TelemetryError(
            "network_without_external_call",
            "terminal.provider_network_performed",
        )
    terminal = {
        "status": _text(manifest["status"], "terminal.status", identifier=True),
        "outcome": outcome,
        "process_started": process_started,
        "external_call_performed": external,
        "provider_network_performed": network,
        "timed_out": timed_out,
        "output_limit_stream": output_limit,
        "retry_count": 0,
        "fallback_used": False,
        "hedge_used": False,
        "model_substitution_used": False,
    }
    observed_identity = {
        field: {"state": "unknown", "value": None, "reason": "not_emitted"}
        for field in OBSERVED_IDENTITY_FIELDS
    }
    evidence = {
        "return_manifest": manifest_descriptor,
        "stdout": stdout,
        "stderr": stderr,
        "artifact": artifact_descriptor,
    }
    advisory = {
        "disposition": "observe_only",
        "affects_ranking": False,
        "execution_authority": False,
        "route_selection": False,
        "retry_allowed": False,
        "fallback_allowed": False,
        "compiler_started_provider_call": False,
        "board_mutated": False,
        "accepted_by_parent": False,
    }
    unknowns = sorted(
        [f"observed_identity.{field}" for field in OBSERVED_IDENTITY_FIELDS]
        + [f"measurements.{field}" for field, value in measurements.items() if value["state"] == "unknown"]
    )
    row = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "dispatch_id": _text(manifest["dispatch_id"], "dispatch_id", identifier=True),
        "recorded_at": recorded_at,
        "expires_at": expires_at,
        "task_family": task_family,
        "requested_identity": requested_identity,
        "observed_identity": observed_identity,
        "terminal": terminal,
        "measurements": measurements,
        "evidence": evidence,
        "advisory": advisory,
        "unknowns": unknowns,
    }
    row["telemetry_sha256"] = digest(row)
    return validate_telemetry(row, repo_root=root)


def validate_telemetry(value: Any, *, repo_root: Path | None = None) -> dict[str, Any]:
    row = _closed(value, ROOT_FIELDS, "telemetry")
    if row["schema_version"] != SCHEMA_VERSION or row["artifact_type"] != ARTIFACT_TYPE:
        raise TelemetryError("telemetry_type_invalid", "telemetry")
    _text(row["dispatch_id"], "telemetry.dispatch_id", identifier=True)
    recorded = _timestamp(row["recorded_at"], "telemetry.recorded_at")
    expires = _timestamp(row["expires_at"], "telemetry.expires_at")
    if not recorded < expires or (expires - recorded).total_seconds() > 14 * 24 * 60 * 60:
        raise TelemetryError("evidence_window_invalid", "telemetry.expires_at")
    _text(row["task_family"], "telemetry.task_family", identifier=True)
    requested = _closed(row["requested_identity"], REQUESTED_IDENTITY_FIELDS, "telemetry.requested_identity")
    for field, item in requested.items():
        _text(item, f"telemetry.requested_identity.{field}")
    observed = _closed(row["observed_identity"], OBSERVED_IDENTITY_FIELDS, "telemetry.observed_identity")
    for field, item in observed.items():
        measurement = _closed(item, MEASUREMENT_FIELDS, f"telemetry.observed_identity.{field}")
        if measurement != {"state": "unknown", "value": None, "reason": "not_emitted"}:
            raise TelemetryError("runtime_identity_not_observed", f"telemetry.observed_identity.{field}")
    terminal = _closed(row["terminal"], TERMINAL_FIELDS, "telemetry.terminal")
    for field in (
        "process_started", "external_call_performed", "timed_out", "fallback_used",
        "hedge_used", "model_substitution_used",
    ):
        if type(terminal[field]) is not bool:
            raise TelemetryError("boolean_required", f"telemetry.terminal.{field}")
    if terminal["provider_network_performed"] not in {True, False, "unknown"}:
        raise TelemetryError("network_observation_invalid", "telemetry.terminal.provider_network_performed")
    if terminal["external_call_performed"] and terminal["provider_network_performed"] is False:
        raise TelemetryError(
            "external_network_observation_contradiction",
            "telemetry.terminal.provider_network_performed",
        )
    if terminal["provider_network_performed"] is True and not terminal["external_call_performed"]:
        raise TelemetryError(
            "network_without_external_call",
            "telemetry.terminal.provider_network_performed",
        )
    if terminal["output_limit_stream"] not in {None, "stdout", "stderr"}:
        raise TelemetryError("output_limit_invalid", "telemetry.terminal.output_limit_stream")
    if terminal["retry_count"] != 0 or terminal["fallback_used"] or terminal["hedge_used"] or terminal["model_substitution_used"]:
        raise TelemetryError("forbidden_execution_behavior", "telemetry.terminal")
    measurements = _closed(row["measurements"], set(MEASUREMENTS), "telemetry.measurements")
    for field, item in measurements.items():
        _measurement(item, f"telemetry.measurements.{field}")
    evidence = _closed(row["evidence"], EVIDENCE_FIELDS, "telemetry.evidence")
    root = _canonical_root(repo_root) if repo_root is not None else None
    for field in ("return_manifest", "stdout", "stderr", "artifact"):
        item = evidence[field]
        if item is None:
            if field == "return_manifest":
                raise TelemetryError("manifest_descriptor_required", "telemetry.evidence")
            continue
        descriptor = _closed(item, DESCRIPTOR_FIELDS, f"telemetry.evidence.{field}")
        _text(descriptor["path"], f"telemetry.evidence.{field}.path")
        _sha(descriptor["sha256"], f"telemetry.evidence.{field}.sha256")
        if isinstance(descriptor["bytes"], bool) or not isinstance(descriptor["bytes"], int) or descriptor["bytes"] < 0:
            raise TelemetryError("bytes_invalid", f"telemetry.evidence.{field}.bytes")
        if root is not None:
            _descriptor(descriptor, root, f"telemetry.evidence.{field}")
    advisory = _closed(row["advisory"], ADVISORY_FIELDS, "telemetry.advisory")
    expected_advisory = {
        "disposition": "observe_only", "affects_ranking": False,
        "execution_authority": False, "route_selection": False,
        "retry_allowed": False, "fallback_allowed": False,
        "compiler_started_provider_call": False, "board_mutated": False,
        "accepted_by_parent": False,
    }
    if advisory != expected_advisory:
        raise TelemetryError("advisory_effect_invalid", "telemetry.advisory")
    if not isinstance(row["unknowns"], list) or row["unknowns"] != sorted(set(row["unknowns"])):
        raise TelemetryError("unknowns_invalid", "telemetry.unknowns")
    supplied = _sha(row["telemetry_sha256"], "telemetry.telemetry_sha256")
    core = {key: item for key, item in row.items() if key != "telemetry_sha256"}
    if supplied != digest(core).removeprefix("sha256:"):
        raise TelemetryError("telemetry_digest_mismatch", "telemetry.telemetry_sha256")
    return row


def _atomic_create(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise TelemetryError("output_exists", "output")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path, follow_symlinks=False)
        os.chmod(path, 0o600)
    finally:
        if temp.exists():
            temp.unlink()


def _read_json(path: Path, root: Path, field: str) -> dict[str, Any]:
    return _strict_json(_regular_file(path, root, field), field)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    compile_parser = sub.add_parser("compile")
    compile_parser.add_argument("--repo-root", required=True)
    compile_parser.add_argument("--manifest", required=True)
    compile_parser.add_argument("--recorded-at", required=True)
    compile_parser.add_argument("--expires-at", required=True)
    compile_parser.add_argument("--output", required=True)
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--repo-root", required=True)
    validate_parser.add_argument("--telemetry", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        root = _canonical_root(Path(args.repo_root))
        if args.command == "compile":
            result = compile_telemetry(
                Path(args.manifest), root,
                recorded_at=args.recorded_at, expires_at=args.expires_at,
            )
            data = json.dumps(result, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            _atomic_create(Path(args.output), data)
        else:
            result = validate_telemetry(
                _read_json(Path(args.telemetry), root, "telemetry"), repo_root=root,
            )
        print(json.dumps({
            "status": "pass", "artifact_type": result["artifact_type"],
            "dispatch_id": result["dispatch_id"], "telemetry_sha256": result["telemetry_sha256"],
        }, sort_keys=True))
        return 0
    except TelemetryError as exc:
        print(json.dumps({"status": "failed", "error": exc.code, "path": exc.path}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
