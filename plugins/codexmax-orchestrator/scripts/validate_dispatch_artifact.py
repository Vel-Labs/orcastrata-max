#!/usr/bin/env python3
"""Create deterministic ArtifactQualityReceipt v1 records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
POLICIES = {
    "provider_neutral_result_v1", "markdown_sections_v1",
    "json_object_v1", "opaque_nonempty_v1",
}
DEFAULT_PROVIDER_HEADINGS = [
    "# Result", "## Identity", "## Input Access Receipt", "## Validation",
    "## Status", "## Artifacts",
]
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class QualityError(ValueError):
    pass


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _descriptor(path: Path, raw: bytes) -> dict[str, Any]:
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _read_regular_file(path: Path, *, max_bytes: int) -> tuple[bytes | None, list[str]]:
    findings: list[str] = []
    try:
        named = path.lstat()
    except OSError:
        return None, ["artifact_unreadable"]
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        return None, ["artifact_not_regular"]
    if named.st_size > max_bytes:
        return None, ["artifact_oversized"]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            raw = os.read(descriptor, max_bytes + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return None, ["artifact_unreadable"]
    if len(raw) > max_bytes:
        findings.append("artifact_oversized")
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        findings.append("artifact_identity_changed")
    return (None if findings else raw), findings


def _ordered_headings(text: str, headings: list[str]) -> list[str]:
    findings: list[str] = []
    cursor = -1
    lines = text.splitlines()
    for heading in headings:
        matches = [index for index, line in enumerate(lines) if line.strip() == heading]
        if len(matches) != 1:
            findings.append(f"heading_count:{heading}")
            continue
        if matches[0] <= cursor:
            findings.append(f"heading_order:{heading}")
        cursor = matches[0]
    return findings


def validate_artifact(
    path: Path,
    *,
    policy_id: str,
    expected_descriptor: dict[str, Any] | None = None,
    requirements: dict[str, Any] | None = None,
    max_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    requirements = requirements or {}
    findings: list[str] = []
    if policy_id not in POLICIES:
        findings.append("unknown_policy")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise QualityError("max_bytes must be a positive integer")
    raw, read_findings = _read_regular_file(path, max_bytes=max_bytes)
    findings.extend(read_findings)
    observed = None
    text = None
    parsed: Any = None
    if raw is not None:
        observed = _descriptor(path, raw)
        if expected_descriptor is not None:
            allowed = {"path", "sha256", "size_bytes"}
            if not isinstance(expected_descriptor, dict) or set(expected_descriptor) != allowed:
                findings.append("descriptor_invalid")
            else:
                for field in allowed:
                    if expected_descriptor[field] != observed[field]:
                        findings.append(f"descriptor_mismatch:{field}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            findings.append("artifact_invalid_utf8")
        if text is not None and not text.strip():
            findings.append("artifact_empty")
    if text is not None and policy_id in {"markdown_sections_v1", "provider_neutral_result_v1"}:
        headings = requirements.get("required_headings")
        if headings is None:
            headings = DEFAULT_PROVIDER_HEADINGS if policy_id == "provider_neutral_result_v1" else []
        if not isinstance(headings, list) or not all(isinstance(item, str) and item for item in headings):
            findings.append("required_headings_invalid")
        else:
            findings.extend(_ordered_headings(text, headings))
        for required_text in requirements.get("required_text", []):
            if not isinstance(required_text, str) or required_text not in text:
                findings.append(f"required_text_missing:{required_text}")
        if policy_id == "provider_neutral_result_v1":
            expected_identity = requirements.get("expected_identity")
            if expected_identity and f"identity: {expected_identity}" not in text:
                findings.append("identity_mismatch")
            input_receipt = requirements.get("input_receipt_sha256")
            if input_receipt and f"input_receipt_sha256: {input_receipt}" not in text:
                findings.append("input_receipt_mismatch")
            allowed_statuses = requirements.get("allowed_statuses", ["ready_for_review", "candidate_complete"])
            if not any(f"status: {status}" in text for status in allowed_statuses):
                findings.append("status_invalid")
            source_binding = requirements.get("source_binding_sha256")
            if source_binding and f"source_binding_sha256: {source_binding}" not in text:
                findings.append("source_binding_mismatch")
    if text is not None and policy_id == "json_object_v1":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            findings.append("json_invalid")
        if parsed is not None and not isinstance(parsed, dict):
            findings.append("json_root_not_object")
        if isinstance(parsed, dict):
            for field in requirements.get("required_fields", []):
                if field not in parsed:
                    findings.append(f"json_field_missing:{field}")
            schema_version = requirements.get("schema_version")
            if schema_version is not None and parsed.get("schema_version") != schema_version:
                findings.append("json_schema_version_mismatch")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": policy_id,
        "artifact": observed or {"path": str(path), "sha256": "unknown", "size_bytes": "unknown"},
        "expected_descriptor": expected_descriptor,
        "max_bytes": max_bytes,
        "checks_executed": True,
        "arbitrary_commands_executed": False,
        "model_judgment_used": False,
        "accepted": not findings,
        "findings": findings,
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical_json(receipt)).hexdigest()
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--policy", choices=sorted(POLICIES), required=True)
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024)
    args = parser.parse_args(argv)
    try:
        descriptor = json.loads(args.descriptor.read_text(encoding="utf-8")) if args.descriptor else None
        requirements = json.loads(args.requirements.read_text(encoding="utf-8")) if args.requirements else None
        receipt = validate_artifact(
            args.artifact, policy_id=args.policy, expected_descriptor=descriptor,
            requirements=requirements, max_bytes=args.max_bytes,
        )
    except (OSError, json.JSONDecodeError, QualityError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

