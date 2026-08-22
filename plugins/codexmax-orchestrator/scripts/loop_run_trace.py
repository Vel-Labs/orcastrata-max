#!/usr/bin/env python3
"""Build and verify inert, adjacent LoopRunTraceV1 evidence.

The trace is a metadata-only companion to one ``LoopRunReceipt``.  It does
not contain action output, prompts, responses, commands, or credentials.  A
trace is useful because a receipt proves one action while the trace preserves
the run ancestry and the exact receipt/output binding needed to inspect a
root or nested loop later.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

import loop_registry


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "LoopRunTraceV1"
SHA256 = "sha256:"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_BYTES = 262_144
TRACE_FIELDS = {
    "schema_version", "artifact_type", "trace_id", "run_id", "parent_run_id",
    "loop", "ancestry", "relation", "receipt", "event", "execution", "output", "privacy",
    "binding_sha256",
}
LOOP_FIELDS = {"loop_id", "definition_version"}
ANCESTRY_FIELDS = {"run_id", "loop_id", "depth", "ancestry"}
RELATION_FIELDS = {"kind", "root_run_id", "parent_run_id"}
RECEIPT_FIELDS = {"receipt_id"}
EVENT_FIELDS = {"event_id", "event_type", "dedupe_key", "source", "origin", "sha256"}
EXECUTION_FIELDS = {
    "status", "result", "attempt", "started_at", "finished_at", "duration_ms",
}
OUTPUT_FIELDS = {"sha256", "captured_chars", "truncated"}
SOURCE_FIELDS = {"adapter_id", "source_event_id", "trust"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
KEBAB_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class TraceError(ValueError):
    """Stable fail-closed trace error."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return SHA256 + hashlib.sha256(value).hexdigest()


def digest(value: Any) -> str:
    return digest_bytes(canonical_json(value) + b"\n")


def receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return canonical_json(receipt) + b"\n"


def trace_bytes(trace: dict[str, Any]) -> bytes:
    return canonical_json(trace) + b"\n"


def binding_sha256(receipt_id: str, event: dict[str, Any], loop: dict[str, Any]) -> str:
    """Hash only stable identity fields, avoiding receipt/trace digest cycles."""
    return _binding_sha256(
        receipt_id, event["event_id"], event["event_type"], event["dedupe_key"],
        event["source"], event["origin"], digest(event), loop,
    )


def binding_sha256_projection(receipt_id: str, event: dict[str, Any], loop: dict[str, Any]) -> str:
    """Recompute a binding from the closed trace projection."""
    return _binding_sha256(
        receipt_id, event["event_id"], event["event_type"], event["dedupe_key"],
        event["source"], event["origin"], event["sha256"], loop,
    )


def _binding_sha256(
    receipt_id: str, event_id: str, event_type: str, dedupe_key: str,
    source: dict[str, Any], origin: dict[str, Any], event_sha256: str,
    loop: dict[str, Any],
) -> str:
    return digest({
        "receipt_id": receipt_id,
        "event": {
            "event_id": event_id,
            "event_type": event_type,
            "dedupe_key": dedupe_key,
            "event_sha256": event_sha256,
        },
        "loop": loop,
        "source": source,
        "origin": origin,
    })


def adjacent_trace_path(receipt_path: str | Path) -> Path:
    path = Path(receipt_path)
    if path.name.endswith(".json"):
        return path.with_name(path.name[:-5] + ".trace.json")
    raise TraceError("receipt_path_invalid")


def adjacent_trace_locator(receipt_locator: dict[str, str]) -> dict[str, str]:
    """Return the logical sibling locator for a receipt locator."""
    locator = _logical_path(receipt_locator)
    path = locator["path"]
    if not path.endswith(".json"):
        raise TraceError("receipt_path_invalid")
    return {"root_id": locator["root_id"], "path": path[:-5] + ".trace.json"}


def _locator(path: Path, root: Path, *, root_id: str = "workspace") -> dict[str, str]:
    try:
        relative = path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as exc:
        raise TraceError("path_invalid") from exc
    if not relative or relative.startswith("../") or relative == ".":
        raise TraceError("path_invalid")
    return {"root_id": root_id, "path": relative}


def _safe_id(value: Any, code: str = "id_invalid") -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 128:
        raise TraceError(code)
    return value


def _digest(value: Any, code: str = "digest_invalid") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise TraceError(code)
    return value


def _closed(value: Any, fields: set[str], code: str = "schema_invalid") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TraceError(code)
    return value


def _parse_json(raw: bytes, *, path: str) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise TraceError("input_too_large", path)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise TraceError("duplicate_key", path)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except TraceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise TraceError("json_invalid", path) from exc
    if not isinstance(value, dict):
        raise TraceError("object_required", path)
    return value


def _regular_bytes(path: Path, *, max_bytes: int = MAX_BYTES) -> bytes:
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise TraceError("path_unavailable") from exc
    if resolved != path or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise TraceError("path_unsafe")
    if named.st_size > max_bytes:
        raise TraceError("input_too_large")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise TraceError("path_unavailable") from exc


def _absolute_input(value: str | Path) -> Path:
    supplied = Path(value)
    if "\x00" in str(supplied) or ".." in supplied.parts:
        raise TraceError("path_invalid")
    return Path(os.path.abspath(supplied))


def _logical_path(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"root_id", "path"}:
        raise TraceError("path_invalid")
    root_id, path = value["root_id"], value["path"]
    if not isinstance(root_id, str) or not root_id or not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or ".." in Path(path).parts:
        raise TraceError("path_invalid")
    return {"root_id": root_id, "path": path}


def _validated_origin(origin: Any) -> dict[str, Any]:
    origin = _closed(origin, ANCESTRY_FIELDS, "origin_invalid")
    run_id = origin.get("run_id")
    loop_id = origin.get("loop_id")
    depth = origin.get("depth")
    ancestry = origin.get("ancestry")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0 or depth > 8 or not isinstance(ancestry, list) or any(not isinstance(item, str) or not KEBAB_RE.fullmatch(item) for item in ancestry) or len(ancestry) != depth or len(set(ancestry)) != len(ancestry):
        raise TraceError("origin_invalid")
    if (run_id is None) != (depth == 0) or (loop_id is None) != (depth == 0):
        raise TraceError("origin_invalid")
    if run_id is not None:
        _safe_id(run_id, "origin_invalid")
    if loop_id is not None and (not KEBAB_RE.fullmatch(loop_id) or not ancestry or ancestry[-1] != loop_id):
        raise TraceError("origin_invalid")
    return origin


def _validated_source(source: Any) -> dict[str, Any]:
    source = _closed(source, SOURCE_FIELDS, "event_invalid")
    if source["trust"] not in {"local_adapter", "fixture", "generic_stdin"}:
        raise TraceError("event_invalid")
    if not isinstance(source["adapter_id"], str) or not KEBAB_RE.fullmatch(source["adapter_id"]):
        raise TraceError("event_invalid")
    if not isinstance(source["source_event_id"], str) or not ID_RE.fullmatch(source["source_event_id"]):
        raise TraceError("event_invalid")
    return source


def build_trace(
    receipt: dict[str, Any],
    event: dict[str, Any] | None = None,
    *,
    receipt_locator: dict[str, str] | None = None,
    output_locator: dict[str, str] | None = None,
    roots: dict[str, Path] | None = None,
) -> dict[str, Any]:
    """Build one closed trace from a validated receipt and current event."""
    if loop_registry.verify_receipt(receipt, roots=roots) != []:
        raise TraceError("receipt_invalid")
    receipt_id = _safe_id(receipt.get("receipt_id"), "receipt_invalid")
    event_row = receipt.get("event")
    if not isinstance(event_row, dict):
        raise TraceError("receipt_invalid")
    if event is None or not isinstance(event, dict):
        raise TraceError("event_required")
    if loop_registry.validate_event(event, evaluation_time=event.get("observed_at", ""), roots=roots, check_identity=False):
        raise TraceError("event_invalid")
    if digest(event) != event_row.get("event_sha256"):
        raise TraceError("event_digest_mismatch")
    if any(event.get(key) != event_row.get(key) for key in ("event_id", "event_type", "dedupe_key")):
        raise TraceError("event_receipt_mismatch")
    event_id = _safe_id(event_row.get("event_id"), "receipt_invalid")
    event_type = _safe_id(event_row.get("event_type"), "receipt_invalid")
    event_sha = _digest(event_row.get("event_sha256"))
    registry_row = receipt.get("registry")
    if not isinstance(registry_row, dict):
        raise TraceError("receipt_invalid")
    current_loop_id = registry_row.get("loop_id")
    definition_version = registry_row.get("definition_version")
    if not isinstance(current_loop_id, str) or not KEBAB_RE.fullmatch(current_loop_id):
        raise TraceError("receipt_invalid")
    if type(definition_version) is not int or definition_version < 1:
        raise TraceError("receipt_invalid")
    loop = {"loop_id": current_loop_id, "definition_version": definition_version}
    binding = binding_sha256(receipt_id, event, loop)
    origin = _validated_origin(event["origin"])
    _validated_source(event["source"])
    parent_run_id = origin["run_id"]
    execution = receipt["execution"]
    if not isinstance(execution, dict) or not EXECUTION_FIELDS.issubset(execution):
        raise TraceError("receipt_invalid")
    execution_projection = {key: execution[key] for key in EXECUTION_FIELDS}
    output = _closed(execution["output"], {"captured_chars", "truncated", "sha256", "artifact_path"})
    output_projection = {
        "sha256": output["sha256"],
        "captured_chars": output["captured_chars"],
        "truncated": output["truncated"],
    }
    trace = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "trace_id": "trace-" + binding[len(SHA256):][:24],
        "run_id": receipt_id,
        "parent_run_id": parent_run_id,
        "loop": loop,
        "ancestry": origin,
        "relation": {"kind": "nested" if parent_run_id is not None else "root", "root_run_id": receipt_id if parent_run_id is None else None, "parent_run_id": parent_run_id},
        "receipt": {"receipt_id": receipt_id},
        "event": {
            "event_id": event_id,
            "event_type": event_type,
            "dedupe_key": event["dedupe_key"],
            "source": event["source"],
            "origin": event["origin"],
            "sha256": event_sha,
        },
        "execution": execution_projection,
        "output": output_projection,
        "privacy": "metadata_only",
        "binding_sha256": binding,
    }
    return trace


def validate_trace(value: dict[str, Any]) -> list[str]:
    """Validate closed trace shape and its self-digest."""
    errors: list[str] = []
    try:
        _closed(value, TRACE_FIELDS)
        if set(value) != TRACE_FIELDS:
            raise TraceError("unknown_field")
        if value.get("schema_version") != 1 or value.get("artifact_type") != ARTIFACT_TYPE:
            raise TraceError("schema_invalid")
        _safe_id(value.get("trace_id"))
        _safe_id(value.get("run_id"))
        if value.get("parent_run_id") is not None:
            _safe_id(value["parent_run_id"])
        loop = _closed(value.get("loop"), LOOP_FIELDS)
        if not isinstance(loop["loop_id"], str) or not KEBAB_RE.fullmatch(loop["loop_id"]):
            raise TraceError("schema_invalid")
        if type(loop["definition_version"]) is not int or loop["definition_version"] < 1:
            raise TraceError("schema_invalid")
        ancestry = _validated_origin(value.get("ancestry"))
        relation = _closed(value.get("relation"), RELATION_FIELDS)
        if relation["kind"] not in {"root", "nested"}:
            raise TraceError("origin_invalid")
        if relation["parent_run_id"] != value["parent_run_id"] or relation["parent_run_id"] != ancestry["run_id"]:
            raise TraceError("origin_invalid")
        if relation["kind"] == "root":
            if relation["parent_run_id"] is not None or relation["root_run_id"] != value["run_id"] or ancestry["depth"] != 0:
                raise TraceError("origin_invalid")
        elif relation["parent_run_id"] is None or relation["root_run_id"] is not None or ancestry["depth"] == 0:
            raise TraceError("origin_invalid")
        receipt = _closed(value.get("receipt"), RECEIPT_FIELDS)
        _safe_id(receipt["receipt_id"], "receipt_invalid")
        event = _closed(value.get("event"), EVENT_FIELDS)
        _safe_id(event["event_id"])
        _safe_id(event["event_type"])
        _safe_id(event["dedupe_key"])
        _validated_source(event["source"])
        event_origin = _validated_origin(event["origin"])
        if event_origin != ancestry:
            raise TraceError("origin_invalid")
        if event_origin["run_id"] != value["parent_run_id"]:
            raise TraceError("origin_invalid")
        _digest(event["sha256"])
        execution = _closed(value.get("execution"), EXECUTION_FIELDS)
        output = _closed(value.get("output"), OUTPUT_FIELDS)
        if output["sha256"] != "unknown":
            _digest(output["sha256"])
        if not isinstance(output["captured_chars"], int) or output["captured_chars"] < 0 or not isinstance(output["truncated"], bool):
            raise TraceError("schema_invalid")
        if value.get("privacy") != "metadata_only":
            raise TraceError("privacy_invalid")
        _digest(value["binding_sha256"])
    except TraceError as exc:
        errors.append(exc.code)
    return sorted(set(errors))


def validate_pair(receipt_path: str | Path, trace_path: str | Path | None = None, *, roots: dict[str, Path] | None = None, event: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read and verify one explicit receipt plus its adjacent trace."""
    try:
        receipt_path = _absolute_input(receipt_path)
        trace_path = _absolute_input(trace_path) if trace_path is not None else adjacent_trace_path(receipt_path)
    except (OSError, TraceError) as exc:
        if isinstance(exc, TraceError):
            raise
        raise TraceError("path_unavailable") from exc
    receipt_raw = _regular_bytes(receipt_path)
    trace_raw = _regular_bytes(trace_path)
    receipt = _parse_json(receipt_raw, path="receipt")
    trace = _parse_json(trace_raw, path="trace")
    errors = loop_registry.verify_receipt(receipt, roots=roots)
    errors.extend(validate_trace(trace))
    receipt_id = receipt.get("receipt_id")
    receipt_event = receipt.get("event") if isinstance(receipt.get("event"), dict) else {}
    receipt_registry = receipt.get("registry") if isinstance(receipt.get("registry"), dict) else {}
    trace_event = trace.get("event") if isinstance(trace.get("event"), dict) else {}
    trace_loop = trace.get("loop") if isinstance(trace.get("loop"), dict) else {}
    trace_artifacts = [row for row in receipt.get("artifacts", []) if isinstance(row, dict) and row.get("artifact_id") == "loop-run-trace"] if isinstance(receipt.get("artifacts"), list) else []
    if len(trace_artifacts) != 1:
        errors.append("trace_binding_missing")
    elif not errors:
        try:
            artifact_locator = _logical_path(trace_artifacts[0].get("path"))
            if roots is None or artifact_locator["root_id"] not in roots:
                raise TraceError("path_invalid")
            artifact_path = Path(os.path.abspath(
                roots[artifact_locator["root_id"]] / artifact_locator["path"]
            ))
            if artifact_path != trace_path:
                errors.append("trace_artifact_path_mismatch")
        except TraceError:
            errors.append("trace_artifact_path_mismatch")
        if any(
            trace_event.get(trace_key) != receipt_event.get(receipt_key)
            for trace_key, receipt_key in (
                ("event_id", "event_id"),
                ("event_type", "event_type"),
                ("dedupe_key", "dedupe_key"),
                ("sha256", "event_sha256"),
            )
        ):
            errors.append("event_receipt_mismatch")
        if trace_loop != {"loop_id": receipt_registry.get("loop_id"), "definition_version": receipt_registry.get("definition_version")}:
            errors.append("loop_receipt_mismatch")
        expected_binding = binding_sha256_projection(receipt_id, trace_event, trace_loop)
        if trace.get("binding_sha256") != expected_binding:
            errors.append("trace_binding_mismatch")
        if trace_artifacts[0].get("sha256") != digest_bytes(trace_raw):
            errors.append("trace_artifact_digest_mismatch")
    if event is not None:
        event_errors = loop_registry.validate_event(
            event, evaluation_time=event.get("observed_at", ""), roots=roots,
            check_identity=False,
        )
        errors.extend("event_invalid" if code == "schema_invalid" else code for code in event_errors)
        if not event_errors:
            if digest(event) != trace.get("event", {}).get("sha256"):
                errors.append("event_digest_mismatch")
            for key in ("event_id", "event_type", "dedupe_key", "source", "origin"):
                if event.get(key) != trace.get("event", {}).get(key):
                    errors.append("event_trace_mismatch")
    if trace.get("receipt", {}).get("receipt_id") != receipt.get("receipt_id"):
        errors.append("receipt_id_mismatch")
    if trace.get("trace_id") != "trace-" + str(trace.get("binding_sha256", ""))[len(SHA256):][:24]:
        errors.append("trace_id_mismatch")
    if trace_path != adjacent_trace_path(receipt_path):
        errors.append("trace_not_adjacent")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "receipt_sha256": digest_bytes(receipt_raw),
        "trace": trace,
        "trace_sha256": digest_bytes(trace_raw),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--trace", type=Path)
    args = parser.parse_args(argv)
    try:
        workspace_root = _absolute_input(args.workspace_root)
        if not workspace_root.is_dir():
            raise TraceError("path_invalid")
        roots = loop_registry.default_roots(workspace_root=workspace_root)
        result = validate_pair(args.receipt, args.trace, roots=roots)
        result = {
            "valid": result["valid"],
            "errors": result["errors"],
            "receipt_sha256": result["receipt_sha256"],
            "trace_sha256": result["trace_sha256"],
        }
    except TraceError as exc:
        result = {"valid": False, "errors": [exc.code]}
    print(json.dumps({"schema_version": 1, "artifact_type": "LoopRunTraceValidation", **result}, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
