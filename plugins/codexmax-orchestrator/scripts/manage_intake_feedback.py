#!/usr/bin/env python3
"""Apply durable, append-preserving iterative intake actions."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Sequence


class IntakeError(ValueError):
    """A deterministic, fail-clear intake error."""


RECORD_KINDS = {
    "question", "answer", "comment", "concern", "suggestion", "assumption",
    "decision", "authority_proposal",
}
STATE_KEYS = {"schema_version", "intake_id", "rounds", "records", "action_log"}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _root(path: Path) -> Path:
    if path.is_symlink():
        raise IntakeError("repository_root_symlink_forbidden")
    resolved = path.resolve()
    if not resolved.is_dir():
        raise IntakeError("repository_root_invalid")
    return resolved


def _path(root: Path, candidate: Path, label: str, *, must_exist: bool) -> tuple[Path, str]:
    if candidate.is_absolute():
        raise IntakeError(f"path_absolute_forbidden:{label}")
    if ".." in candidate.parts:
        raise IntakeError(f"path_parent_escape_forbidden:{label}")
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise IntakeError(f"input_symlink_forbidden:{label}")
    if must_exist and not current.exists():
        raise IntakeError(f"input_missing:{label}")
    try:
        resolved = current.resolve(strict=must_exist)
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise IntakeError(f"path_outside_root:{label}") from exc
    except FileNotFoundError as exc:
        raise IntakeError(f"input_missing:{label}") from exc
    if must_exist and not resolved.is_file():
        raise IntakeError(f"input_not_regular:{label}")
    return resolved, relative.as_posix()


def _json_file(path: Path, label: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise IntakeError("input_not_utf8") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntakeError(f"{label}_malformed:json") from exc


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntakeError(f"{label}_malformed:required_string")
    return value.strip()


def validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise IntakeError("state_malformed:fields")
    if value.get("schema_version") != 1:
        raise IntakeError("state_malformed:schema_version")
    _nonempty_string(value.get("intake_id"), "state")
    for key in ("rounds", "records", "action_log"):
        if not isinstance(value.get(key), list):
            raise IntakeError(f"state_malformed:{key}")
    round_ids: set[str] = set()
    for round_value in value["rounds"]:
        if not isinstance(round_value, dict):
            raise IntakeError("state_malformed:round")
        round_id = _nonempty_string(round_value.get("round_id"), "state")
        if round_id in round_ids:
            raise IntakeError(f"state_malformed:duplicate_round:{round_id}")
        round_ids.add(round_id)
        if not isinstance(round_value.get("material_dimensions"), list) or not isinstance(round_value.get("safe_defaults_applied"), list):
            raise IntakeError("state_malformed:round_fields")
    item_ids: set[str] = set()
    action_ids: set[str] = set()
    for item in value["records"]:
        _validate_record(item, round_ids)
        item_id = item["item_id"]
        if item_id in item_ids:
            raise IntakeError(f"duplicate_item_id:{item_id}")
        item_ids.add(item_id)
    for action in value["action_log"]:
        if not isinstance(action, dict) or set(action) != {"action_id", "action"}:
            raise IntakeError("state_malformed:action_log")
        action_id = _nonempty_string(action.get("action_id"), "state")
        if action_id in action_ids:
            raise IntakeError(f"state_malformed:duplicate_action:{action_id}")
        action_ids.add(action_id)
        if not isinstance(action.get("action"), dict):
            raise IntakeError("state_malformed:action")
    return value


def _validate_record(item: Any, round_ids: set[str]) -> None:
    if not isinstance(item, dict):
        raise IntakeError("state_malformed:record")
    required = {"item_id", "kind", "round_id", "classification", "status", "provenance", "created_at", "links", "payload"}
    if set(item) != required:
        raise IntakeError("state_malformed:record_fields")
    item["item_id"] = _nonempty_string(item.get("item_id"), "state")
    kind = _nonempty_string(item.get("kind"), "state")
    if kind not in RECORD_KINDS:
        raise IntakeError(f"unknown_record_kind:{kind}")
    if _nonempty_string(item.get("round_id"), "state") not in round_ids:
        raise IntakeError("state_malformed:unknown_round")
    _nonempty_string(item.get("classification"), "state")
    _nonempty_string(item.get("status"), "state")
    _nonempty_string(item.get("created_at"), "state")
    if not isinstance(item.get("provenance"), dict) or not _nonempty_string(item["provenance"].get("source"), "state"):
        raise IntakeError("state_malformed:provenance")
    if not isinstance(item.get("links"), list) or not isinstance(item.get("payload"), dict):
        raise IntakeError("state_malformed:record_payload")


def empty_state(intake_id: str) -> dict[str, Any]:
    return {"schema_version": 1, "intake_id": _nonempty_string(intake_id, "state"), "rounds": [], "records": [], "action_log": []}


def _action_id(action: Any) -> str:
    if not isinstance(action, dict):
        raise IntakeError("action_malformed:action")
    return _nonempty_string(action.get("action_id"), "action")


def _record_from_action(action: dict[str, Any], round_ids: set[str], existing_ids: set[str], material_questions: dict[str, int]) -> dict[str, Any]:
    record = action.get("record")
    if not isinstance(record, dict):
        raise IntakeError("action_malformed:record")
    required = {"item_id", "kind", "round_id", "classification", "status", "provenance", "created_at", "links", "payload"}
    if set(record) != required:
        raise IntakeError("action_malformed:record_fields")
    record = json.loads(canonical(record))
    item_id = _nonempty_string(record.get("item_id"), "action")
    if item_id in existing_ids:
        raise IntakeError(f"duplicate_item_id:{item_id}")
    kind = _nonempty_string(record.get("kind"), "action")
    if kind not in RECORD_KINDS:
        raise IntakeError(f"unknown_record_kind:{kind}")
    round_id = _nonempty_string(record.get("round_id"), "action")
    if round_id not in round_ids:
        raise IntakeError("action_malformed:unknown_round")
    _nonempty_string(record.get("classification"), "action")
    status = _nonempty_string(record.get("status"), "action")
    _nonempty_string(record.get("created_at"), "action")
    if not isinstance(record.get("provenance"), dict) or not _nonempty_string(record["provenance"].get("source"), "action"):
        raise IntakeError("action_malformed:provenance")
    if not isinstance(record.get("links"), list) or not isinstance(record.get("payload"), dict):
        raise IntakeError("action_malformed:record_payload")
    if kind == "question":
        if record["classification"] == "material":
            if material_questions.get(round_id, 0) >= 3:
                raise IntakeError(f"material_question_limit:{round_id}")
            material_questions[round_id] = material_questions.get(round_id, 0) + 1
        elif status not in {"suppressed", "informational"}:
            raise IntakeError(f"nonmaterial_question_blocking:{item_id}")
    if kind == "authority_proposal" and (status == "approved" or record["payload"].get("authority_granted") is True):
        raise IntakeError("authority_self_grant_forbidden")
    if kind == "decision" and record["payload"].get("changes_authority") is True and record["provenance"].get("authority_source") != "parent_control":
        raise IntakeError("authority_self_grant_forbidden")
    return record


def apply_actions(state: dict[str, Any], actions: Any) -> tuple[dict[str, Any], list[str]]:
    state = json.loads(canonical(validate_state(state)))
    if not isinstance(actions, list):
        raise IntakeError("action_malformed:actions")
    known_actions = {entry["action_id"]: canonical(entry["action"]) for entry in state["action_log"]}
    outcomes: list[str] = []
    for action in actions:
        action_id = _action_id(action)
        encoded = canonical(action)
        if action_id in known_actions:
            if known_actions[action_id] != encoded:
                raise IntakeError(f"conflicting_replay:{action_id}")
            outcomes.append("replayed")
            continue
        action_type = _nonempty_string(action.get("type"), "action")
        if action_type == "open_round":
            round_value = action.get("round")
            if not isinstance(round_value, dict) or set(round_value) != {"round_id", "material_dimensions", "safe_defaults_applied"}:
                raise IntakeError("action_malformed:round")
            round_id = _nonempty_string(round_value.get("round_id"), "action")
            if any(row["round_id"] == round_id for row in state["rounds"]):
                raise IntakeError(f"conflicting_replay:{action_id}")
            if not isinstance(round_value["material_dimensions"], list) or not isinstance(round_value["safe_defaults_applied"], list):
                raise IntakeError("action_malformed:round_fields")
            state["rounds"].append(json.loads(canonical(round_value)))
        elif action_type == "append_record":
            round_ids = {row["round_id"] for row in state["rounds"]}
            existing_ids = {row["item_id"] for row in state["records"]}
            material_questions: dict[str, int] = {}
            for row in state["records"]:
                if row["kind"] == "question" and row["classification"] == "material":
                    material_questions[row["round_id"]] = material_questions.get(row["round_id"], 0) + 1
            state["records"].append(_record_from_action(action, round_ids, existing_ids, material_questions))
        else:
            raise IntakeError(f"action_malformed:unknown_type:{action_type}")
        state["action_log"].append({"action_id": action_id, "action": json.loads(encoded)})
        known_actions[action_id] = encoded
        outcomes.append("applied")
    validate_state(state)
    return state, outcomes


def _write_json(path: Path, value: dict[str, Any]) -> None:
    if not path.parent.is_dir():
        raise IntakeError("state_malformed:parent_missing")
    descriptor, temporary = tempfile.mkstemp(prefix=".intake-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def run(repo_root: Path, state_path: Path, action_path: Path, *, write: bool, intake_id: str | None = None, transcript: str | None = None) -> dict[str, Any]:
    if transcript is not None:
        raise IntakeError("unsupported_input:transcript")
    root = _root(repo_root)
    state, state_relative = _path(root, state_path, "state", must_exist=False)
    actions_path, action_relative = _path(root, action_path, "action", must_exist=True)
    actions_document = _json_file(actions_path, "action")
    if not isinstance(actions_document, dict) or set(actions_document) != {"actions"}:
        raise IntakeError("action_malformed:document")
    if state.exists():
        current = validate_state(_json_file(state, "state"))
    else:
        if intake_id is None:
            raise IntakeError("state_malformed:missing_intake_id")
        current = empty_state(intake_id)
    updated, outcomes = apply_actions(current, actions_document["actions"])
    if write:
        _write_json(state, updated)
    return {"action_path": action_relative, "outcomes": outcomes, "schema_version": 1, "state": updated, "state_path": state_relative, "status": "ok", "written": write}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--action-path", type=Path, required=True)
    parser.add_argument("--intake-id")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--transcript", help="Rejected: transcript context is unsupported.")
    args = parser.parse_args(argv)
    try:
        result = run(args.repo_root, args.state_path, args.action_path, write=args.write, intake_id=args.intake_id, transcript=args.transcript)
    except IntakeError as error:
        print(canonical({"error": str(error), "schema_version": 1, "status": "error"}))
        return 2
    print(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
