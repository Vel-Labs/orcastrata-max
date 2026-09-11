#!/usr/bin/env python3
"""Compile an explicit set of saved umbrella projection receipts."""
from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

SCHEMA_VERSION = 1
MANIFEST_TYPE = "orcastrata_umbrella_catalog_manifest_v1"
RECEIPT_TYPE = "orcastrata_github_umbrella_projection_receipt_v1"
CATALOG_TYPE = "orcastrata_umbrella_catalog_v1"
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG_CLASSES = {"topic", "status", "owner", "audience", "source"}
SENSITIVITY = {"public", "internal", "restricted"}
HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")


class CatalogError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        super().__init__(f"{code}: {path}")
        self.code, self.path = code, path


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CatalogError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _marker(kind: str, target: dict[str, str], graph_id: str, item_id: str = "umbrella") -> str:
    identity = digest({"graph_id": graph_id, "host": target["host"], "item_id": item_id,
                       "kind": kind, "repository": target["repository"].lower()})[7:27]
    return f"<!-- orcastrata:{kind}:v1:{identity} -->"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("json_duplicate_key")
        result[key] = value
    return result


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CatalogError("shape_invalid", path)
    return value


def _text(value: Any, path: str, maximum: int = 4096) -> str:
    if (not isinstance(value, str) or not value.strip() or
            len(value.encode("utf-8")) > maximum or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise CatalogError("text_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise CatalogError("digest_invalid", path)
    return value


def _tag(value: Any, path: str) -> dict[str, str]:
    row = _closed(value, {"class", "value", "owner", "source"}, path)
    tag = {key: _text(row[key], f"{path}.{key}", 256) for key in row}
    if tag["class"] not in TAG_CLASSES:
        raise CatalogError("tag_class_invalid", f"{path}.class")
    return tag


def _strings(value: Any, path: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > 100:
        raise CatalogError("list_invalid", path)
    result = [_text(item, f"{path}[{i}]") for i, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise CatalogError("list_duplicate", path)
    return result


def _body(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 65536 or any(ord(c) < 9 or (13 < ord(c) < 32) or ord(c) == 127 for c in value):
        raise CatalogError("text_invalid", path)
    return value


def _validate_preview(preview: Any, target: dict[str, str], graph_id: str, path: str) -> str:
    preview = _closed(preview, {"issues", "umbrella"}, path)
    umbrella = _closed(preview["umbrella"], {"body", "labels", "stable_id", "title"}, f"{path}.umbrella")
    umbrella_body = _body(umbrella["body"], f"{path}.umbrella.body")
    _strings(umbrella["labels"], f"{path}.umbrella.labels", True)
    title = _text(umbrella["title"], f"{path}.umbrella.title", 256)
    expected = _marker("umbrella", target, graph_id)[4:-4].strip()
    if umbrella["stable_id"] != expected or not umbrella_body.startswith(f"<!-- {expected} -->"):
        raise CatalogError("marker_invalid", f"{path}.umbrella.stable_id")
    issues = preview["issues"]
    if not isinstance(issues, list) or not 1 <= len(issues) <= 15:
        raise CatalogError("issue_count_invalid", f"{path}.issues")
    work_ids, stable_ids = set(), set()
    for i, raw in enumerate(issues):
        item_path = f"{path}.issues[{i}]"
        issue = _closed(raw, {"body", "dependencies", "labels", "ready", "stable_id", "title", "work_item_id"}, item_path)
        _body(issue["body"], f"{item_path}.body"); _strings(issue["dependencies"], f"{item_path}.dependencies", True)
        _strings(issue["labels"], f"{item_path}.labels", True); _text(issue["title"], f"{item_path}.title", 256)
        _text(issue["work_item_id"], f"{item_path}.work_item_id", 256)
        if not isinstance(issue["ready"], bool) or issue["work_item_id"] in work_ids:
            raise CatalogError("issue_identity_invalid", item_path)
        expected = _marker("issue", target, graph_id, issue["work_item_id"])[4:-4].strip()
        if issue["stable_id"] != expected or issue["stable_id"] in stable_ids or not issue["body"].startswith(f"<!-- {expected} -->"):
            raise CatalogError("marker_invalid", f"{item_path}.stable_id")
        work_ids.add(issue["work_item_id"]); stable_ids.add(issue["stable_id"])
    ordered = sorted(work_ids)
    if [issue["work_item_id"] for issue in issues] != ordered:
        raise CatalogError("issue_order_invalid", f"{path}.issues")
    for issue in issues:
        deps = issue["dependencies"]
        if any(dep not in work_ids or dep == issue["work_item_id"] for dep in deps):
            raise CatalogError("dependency_invalid", f"{path}.issues")
    def visit(item: str, trail: set[str]) -> None:
        if item in trail:
            raise CatalogError("dependency_cycle", f"{path}.issues")
        trail.add(item)
        row = next(issue for issue in issues if issue["work_item_id"] == item)
        for dep in row["dependencies"]:
            visit(dep, trail)
        trail.remove(item)
    for item in work_ids:
        visit(item, set())
    return title


def _path(root: Path, raw: Any, path: str) -> Path:
    relative = _text(raw, path, 1024)
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CatalogError("source_path_uncontained", path)
    unresolved = root / candidate
    current = root
    for component in candidate.parts:
        current = current / component
        if current.is_symlink():
            raise CatalogError("source_not_regular", path)
    resolved = unresolved.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise CatalogError("source_path_uncontained", path) from exc
    if resolved.is_symlink() or not resolved.is_file():
        raise CatalogError("source_not_regular", path)
    return resolved


def _receipt(raw: bytes, value: Any, entry: dict[str, Any], path: str) -> dict[str, Any]:
    receipt = _closed(value, {
        "artifact_type", "canonical_state", "effect_boundary", "graph_id",
        "graph_sha256", "preview", "projection_sha256", "schema_version",
        "status", "target",
    }, path)
    if receipt["schema_version"] != 1 or receipt["artifact_type"] != RECEIPT_TYPE or receipt["status"] != "ok":
        raise CatalogError("receipt_identity_invalid", path)
    target = _closed(receipt["target"], {"host", "repository"}, f"{path}.target")
    host_raw = _text(target["host"], f"{path}.target.host", 256)
    if not HOST_RE.fullmatch(host_raw):
        raise CatalogError("host_invalid", f"{path}.target.host")
    repository_raw = _text(target["repository"], f"{path}.target.repository", 256)
    if not REPOSITORY_RE.fullmatch(repository_raw):
        raise CatalogError("repository_invalid", f"{path}.target.repository")
    host, repository = host_raw, repository_raw.lower()
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise CatalogError("repository_invalid", f"{path}.target.repository")
    _text(receipt["graph_id"], f"{path}.graph_id", 256)
    _sha(receipt["graph_sha256"], f"{path}.graph_sha256")
    semantic = _sha(receipt["projection_sha256"], f"{path}.projection_sha256")
    if semantic != digest(receipt["preview"]):
        raise CatalogError("semantic_digest_mismatch", f"{path}.projection_sha256")
    boundary = receipt["effect_boundary"]
    if not isinstance(boundary, dict) or set(boundary) != {
        "acceptance_granted", "authority_granted", "goalbuddy_mutated", "github_called",
        "github_mutated", "network_used", "provider_called",
    } or any(boundary.values()):
        raise CatalogError("effect_boundary_invalid", f"{path}.effect_boundary")
    state = _closed(receipt["canonical_state"], {"active_task", "board_sha256", "owner"}, f"{path}.canonical_state")
    if state["owner"] != "GoalBuddy":
        raise CatalogError("canonical_owner_invalid", f"{path}.canonical_state.owner")
    _sha(state["board_sha256"], f"{path}.canonical_state.board_sha256")
    active = state["active_task"]
    if active is not None:
        _text(active, f"{path}.canonical_state.active_task", 256)
    expected = _sha(entry["raw_sha256"], f"{path}.raw_sha256")
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected != actual:
        raise CatalogError("raw_digest_mismatch", f"{path}.raw_sha256")
    if entry["projection_sha256"] != semantic:
        raise CatalogError("semantic_digest_mismatch", f"{path}.projection_sha256")
    preview_title = _validate_preview(receipt["preview"], target, receipt["graph_id"], f"{path}.preview")
    tags = sorted((_tag(tag, f"{path}.tags[{i}]") for i, tag in enumerate(entry["tags"])),
                  key=lambda tag: (tag["class"], tag["value"], tag["owner"], tag["source"]))
    if len({canonical_bytes(tag) for tag in tags}) != len(tags):
        raise CatalogError("tag_duplicate", f"{path}.tags")
    return {"host": host, "repository": repository, "graph_id": receipt["graph_id"],
            "title": preview_title,
            "summary": _text(entry["summary"], f"{path}.summary"),
            "tags": tags,
            "lifecycle": {"active_task": active, "owner": "GoalBuddy", "state": "snapshot"},
            "references": {"github_repository": f"https://{host}/{target['repository']}",
                           "projection": entry["path"], "workgraph_id": receipt["graph_id"],
                           "goalbuddy_owner": "GoalBuddy"},
            "digests": {"raw_receipt_sha256": actual, "projection_sha256": semantic, "graph_sha256": receipt["graph_sha256"],
                        "board_sha256": state["board_sha256"]},
            "evidence_state": "observed", "sensitivity": entry["sensitivity"],
            "exportable": entry["exportable"]}


def _record(data: dict[str, Any]) -> dict[str, Any]:
    identity = f"orcastrata:umbrella:v1:{data['host']}/{data['repository']}:{data['graph_id']}"
    record = {"schema_version": 1, "record_type": "umbrella", "umbrella_id": identity,
              "title": data["title"], "summary": data["summary"], "tags": data["tags"],
              "lifecycle": data["lifecycle"], "references": data["references"],
              "digests": data["digests"], "evidence_state": data["evidence_state"],
              "sensitivity": data["sensitivity"], "exportable": data["exportable"]}
    record["record_sha256"] = digest(record)
    return record


def compile_catalog(manifest: Any, root: str | Path = ".") -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) - {"artifact_type", "entries", "schema_version", "generated_at"}:
        raise CatalogError("shape_invalid", "$")
    if set(manifest) < {"artifact_type", "entries", "schema_version"}:
        raise CatalogError("shape_invalid", "$")
    if manifest["schema_version"] != 1 or manifest["artifact_type"] != MANIFEST_TYPE:
        raise CatalogError("manifest_identity_invalid")
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise CatalogError("manifest_entries_invalid", "$.entries")
    if not all(isinstance(entry, dict) for entry in entries):
        raise CatalogError("manifest_entries_invalid", "$.entries")
    entries = sorted(entries, key=canonical_bytes)
    manifest = {**manifest, "entries": entries}
    base = Path(root).resolve()
    records, seen_paths, seen_ids = [], set(), set()
    for index, raw_entry in enumerate(entries):
        path = f"$.entries[{index}]"
        entry = _closed(raw_entry, {"path", "raw_sha256", "projection_sha256", "summary", "tags", "sensitivity", "exportable"}, path)
        if not isinstance(entry["tags"], list) or not isinstance(entry["exportable"], bool) or entry["sensitivity"] not in SENSITIVITY:
            raise CatalogError("manifest_entry_invalid", path)
        if entry["sensitivity"] == "restricted" and entry["exportable"]:
            raise CatalogError("restricted_export_invalid", f"{path}.exportable")
        source = _path(base, entry["path"], f"{path}.path")
        if source in seen_paths:
            raise CatalogError("duplicate_source", f"{path}.path")
        seen_paths.add(source)
        before = source.stat()
        raw = source.read_bytes()
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, CatalogError) as exc:
            raise CatalogError("receipt_invalid", f"{path}.path") from exc
        data = _receipt(raw, value, entry, path)
        after = source.stat()
        if (before.st_mtime_ns, before.st_size, after.st_mtime_ns, after.st_size) != (before.st_mtime_ns, before.st_size, before.st_mtime_ns, before.st_size):
            raise CatalogError("source_changed_during_build", f"{path}.path")
        if source.read_bytes() != raw:
            raise CatalogError("source_changed_during_build", f"{path}.path")
        record = _record(data)
        if record["umbrella_id"] in seen_ids:
            raise CatalogError("duplicate_identity", f"{path}.path")
        seen_ids.add(record["umbrella_id"])
        records.append(record)
    records.sort(key=lambda row: row["umbrella_id"])
    manifest_sha = digest(manifest)
    catalog_sha = digest(records)
    catalog = {"schema_version": 1, "artifact_type": CATALOG_TYPE, "manifest_sha256": manifest_sha,
            "record_count": len(records), "catalog_sha256": catalog_sha, "records": records}
    if "generated_at" in manifest:
        catalog["generated_at"] = _text(manifest["generated_at"], "$.generated_at", 128)
    return catalog


def canonical_jsonl(catalog: dict[str, Any]) -> bytes:
    """Return the complete generation as one canonical JSONL line."""
    return canonical_bytes(catalog) + b"\n"


build_catalog = compile_catalog


def markdown(catalog: dict[str, Any]) -> str:
    lines = ["# Orcastrata Umbrella Catalog", "", f"Catalog digest: `{catalog['catalog_sha256']}`", ""]
    for record in catalog["records"]:
        lines += [f"## {record['title']}", "", f"- ID: `{record['umbrella_id']}`",
                  f"- Summary: {record['summary']}", f"- Lifecycle: `{record['lifecycle']['state']}`",
                  f"- Source: `{record['references']['projection']}`", ""]
    return "\n".join(lines)


def write_catalog(catalog: dict[str, Any], jsonl: str | Path, md: str | Path) -> None:
    jsonl, md = Path(jsonl), Path(md)
    json_bytes = canonical_jsonl(catalog)
    md_bytes = markdown(catalog).encode("utf-8")
    temps = []
    try:
        for target, content in ((jsonl, json_bytes), (md, md_bytes)):
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temps.append((Path(name), target))
        for source, target in temps:
            os.replace(source, target)
    finally:
        for source, _ in temps:
            source.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--jsonl-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    try:
        args = parser.parse_args(argv)
        with open(args.manifest, encoding="utf-8") as stream:
            payload = json.load(stream, object_pairs_hook=_pairs)
        result = compile_catalog(payload, args.root)
        write_catalog(result, args.jsonl_out, args.markdown_out)
        print(json.dumps({"status": "ok", "catalog_sha256": result["catalog_sha256"], "record_count": result["record_count"]}, separators=(",", ":")))
        return 0
    except (CatalogError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "error", "error": str(error)}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
