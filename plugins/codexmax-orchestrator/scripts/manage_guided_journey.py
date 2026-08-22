#!/usr/bin/env python3
"""Bind effective Codexmax config to durable, transcript-free journey state."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
CONFIG_SCRIPT = Path(__file__).with_name("resolve_codexmax_config.py")
PACKET_KINDS = ("goal", "assignment", "route", "evidence", "validation", "closeout")
MATCHING_ACTIVE_CHOICES = ("continue", "inspect", "revise", "stop_safely")
FAIL_CLOSED_CHOICES = ("inspect", "repair", "start_fresh")
STATE_TOP_KEYS = {
    "schema_version", "journey_id", "identity_inputs", "goalbuddy", "source_hashes",
    "envelope", "state", "generated_artifacts", "transition_history",
}
STATE_REQUIRED_KEYS = STATE_TOP_KEYS
STATE_PHASES = {
    "discover", "detect_conflict", "classify", "question", "preview", "authorize",
    "generate", "execute_verify", "parent_decision", "close_or_resume",
}
STATE_STATUSES = {"active", "stopped"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PACKET_KEYS = {
    "schema_version", "packet_kind", "journey_id", "envelope_sha256",
    "effective_config_sha256", "source_hashes", "effective_config",
    "config_provenance", "hard_constraints",
}


class JourneyError(Exception):
    """Base lifecycle error."""


class StateError(JourneyError):
    pass


class TransitionError(JourneyError):
    pass


class BoardIdentityError(JourneyError):
    pass


def _load_config_module() -> Any:
    spec = importlib.util.spec_from_file_location("codexmax_effective_config", CONFIG_SCRIPT)
    if spec is None or spec.loader is None:
        raise JourneyError("cannot load accepted config resolver")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CONFIG = _load_config_module()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise JourneyError(f"cannot read source {path}: {exc}") from exc
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def normalized_outcome(value: str) -> str:
    normalized = " ".join(value.split()).strip()
    if not normalized:
        raise JourneyError("requested outcome must not be empty")
    return normalized


@dataclass(frozen=True)
class JourneyContext:
    goal_id: str
    checkpoint_id: str
    outcome: str
    repository_rules: Path
    goal_path: Path
    board_state: Path
    accepted_artifacts: tuple[Path, ...]
    config_receipt: dict[str, Any]


def goalbuddy_identity(path: Path) -> tuple[str, str]:
    """Parse the two supported GoalBuddy identity scalars without loading YAML code."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BoardIdentityError(f"cannot read GoalBuddy state {path}: {exc}") from exc
    goal_slug: str | None = None
    active_task: str | None = None
    in_goal = False
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise BoardIdentityError(f"GoalBuddy line {line_number}: tabs are unsupported")
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if indent == 0:
            in_goal = content == "goal:"
            if content.startswith("active_task:"):
                if active_task is not None:
                    raise BoardIdentityError("GoalBuddy active_task is duplicated")
                active_task = CONFIG._scalar(content.split(":", 1)[1], line_number)
        elif in_goal and indent == 2 and content.startswith("slug:"):
            if goal_slug is not None:
                raise BoardIdentityError("GoalBuddy goal.slug is duplicated")
            goal_slug = CONFIG._scalar(content.split(":", 1)[1], line_number)
    if not isinstance(goal_slug, str) or not goal_slug:
        raise BoardIdentityError("GoalBuddy goal.slug is missing or invalid")
    if not isinstance(active_task, str) or not active_task:
        raise BoardIdentityError("GoalBuddy active_task is missing or invalid")
    return goal_slug, active_task


def validate_context_board(context: JourneyContext) -> None:
    goal_slug, active_task = goalbuddy_identity(context.board_state)
    mismatches = []
    if context.goal_id != goal_slug:
        mismatches.append(f"goal_id:{context.goal_id}:{goal_slug}")
    if context.checkpoint_id != active_task:
        mismatches.append(f"checkpoint_id:{context.checkpoint_id}:{active_task}")
    if mismatches:
        raise BoardIdentityError("GoalBuddy identity mismatch: " + ",".join(mismatches))


def journey_id(goal_id: str, outcome: str) -> str:
    inputs = {"goal_id": goal_id, "outcome": normalized_outcome(outcome)}
    return "journey-" + hashlib.sha256(canonical_json(inputs).encode("utf-8")).hexdigest()[:24]


def source_hashes(context: JourneyContext) -> dict[str, str]:
    artifact_rows = [
        {"path": str(path.resolve()), "sha256": sha256_file(path)}
        for path in sorted(context.accepted_artifacts, key=lambda item: str(item.resolve()))
    ]
    return {
        "request": sha256_text(normalized_outcome(context.outcome)),
        "repository_rules": sha256_file(context.repository_rules),
        "goal": sha256_file(context.goal_path),
        "board_state": sha256_file(context.board_state),
        "accepted_artifacts": sha256_text(canonical_json(artifact_rows)),
        "effective_config": sha256_text(canonical_json(context.config_receipt)),
    }


def build_envelope(context: JourneyContext) -> dict[str, Any]:
    validate_context_board(context)
    identity = journey_id(context.goal_id, context.outcome)
    hashes = source_hashes(context)
    return {
        "schema_version": 1,
        "journey_id": identity,
        "goal_id": context.goal_id,
        "checkpoint_id": context.checkpoint_id,
        "effective_config": context.config_receipt["effective_config"],
        "config_provenance": context.config_receipt["provenance"],
        "config_history": context.config_receipt["history"],
        "hard_constraints": context.config_receipt["hard_constraints"],
        "source_hashes": hashes,
    }


def envelope_hash(envelope: dict[str, Any]) -> str:
    return sha256_text(canonical_json(envelope))


def packet_document(kind: str, envelope: dict[str, Any]) -> dict[str, Any]:
    if kind not in PACKET_KINDS:
        raise JourneyError(f"unknown packet kind: {kind}")
    return {
        "schema_version": 1,
        "packet_kind": kind,
        "journey_id": envelope["journey_id"],
        "envelope_sha256": envelope_hash(envelope),
        "effective_config_sha256": envelope["source_hashes"]["effective_config"],
        "source_hashes": envelope["source_hashes"],
        "effective_config": envelope["effective_config"],
        "config_provenance": envelope["config_provenance"],
        "hard_constraints": envelope["hard_constraints"],
    }


def _write_exclusive_json(path: Path, value: Any) -> None:
    if not path.parent.is_dir():
        raise JourneyError(f"parent directory does not exist: {path.parent}")
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    except FileExistsError as exc:
        raise TransitionError(f"destination already exists: {path}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _remove_transaction_paths(paths: list[Path], staging: Path | None = None) -> None:
    for path in reversed(paths):
        try:
            if path.is_file() and path.parent.is_dir():
                path.unlink()
        except OSError:
            pass
    if staging is not None:
        shutil.rmtree(staging, ignore_errors=True)


def write_packets(directory: Path, envelope: dict[str, Any]) -> dict[str, dict[str, str]]:
    if not directory.is_dir():
        raise JourneyError(f"packet directory does not exist: {directory}")
    destinations = [directory / f"{kind}-packet.json" for kind in PACKET_KINDS]
    existing = next((path for path in destinations if path.exists()), None)
    if existing is not None:
        raise TransitionError(f"destination already exists: {existing}")
    staging = Path(tempfile.mkdtemp(prefix=".codexmax-packets-", dir=directory.parent))
    staged_paths: list[Path] = []
    published: list[Path] = []
    result: dict[str, dict[str, str]] = {}
    try:
        for kind in PACKET_KINDS:
            staged = staging / f"{kind}-packet.json"
            document = packet_document(kind, envelope)
            _write_exclusive_json(staged, document)
            staged_paths.append(staged)
        if any(path.exists() for path in destinations):
            raise TransitionError("packet destination appeared during staging")
        for kind, staged, path in zip(PACKET_KINDS, staged_paths, destinations, strict=True):
            document_bytes = staged.read_bytes()
            os.link(staged, path)
            published.append(path)
            result[kind] = {
                "path": str(path.resolve()),
                "journey_id": envelope["journey_id"],
                "envelope_sha256": envelope_hash(envelope),
                "effective_config_sha256": envelope["source_hashes"]["effective_config"],
                "content_sha256": sha256_bytes(document_bytes),
            }
        _remove_transaction_paths([], staging)
        return result
    except Exception:
        _remove_transaction_paths(published, staging)
        raise


def rollback_packets(references: dict[str, Any]) -> None:
    paths: list[Path] = []
    for reference in references.values():
        if not isinstance(reference, dict):
            continue
        path = Path(str(reference.get("path", "")))
        expected = reference.get("content_sha256")
        try:
            if path.is_file() and SHA256_RE.fullmatch(str(expected)) and sha256_file(path) == expected:
                paths.append(path)
        except OSError:
            continue
    _remove_transaction_paths(paths)


def new_state(context: JourneyContext, generated_artifacts: dict[str, Any]) -> dict[str, Any]:
    envelope = build_envelope(context)
    return {
        "schema_version": 1,
        "journey_id": envelope["journey_id"],
        "identity_inputs": {
            "goal_id": context.goal_id,
            "normalized_outcome": normalized_outcome(context.outcome),
        },
        "goalbuddy": {
            "goal_path": str(context.goal_path.resolve()),
            "state_path": str(context.board_state.resolve()),
            "goal_id": context.goal_id,
            "active_checkpoint_id": context.checkpoint_id,
            "board_truth_owner": "GoalBuddy",
            "read_only": True,
        },
        "source_hashes": envelope["source_hashes"],
        "envelope": envelope,
        "state": {"phase": "discover", "classification": "guided_plan", "status": "active"},
        "generated_artifacts": generated_artifacts,
        "transition_history": [{"choice": "start_fresh", "from": "absent", "to": "active"}],
    }


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StateError(f"duplicate state field: {key}")
        result[key] = value
    return result


def validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StateError("state root must be an object")
    unknown = sorted(set(value) - STATE_TOP_KEYS)
    missing = sorted(STATE_REQUIRED_KEYS - set(value))
    if unknown:
        raise StateError(f"unknown state field: {unknown[0]}")
    if missing:
        raise StateError(f"missing state field: {missing[0]}")
    if value["schema_version"] != 1:
        raise StateError("schema_version must equal 1")
    if not isinstance(value["journey_id"], str) or not value["journey_id"]:
        raise StateError("journey_id must be a nonempty string")
    identity_inputs = value["identity_inputs"]
    if not isinstance(identity_inputs, dict) or set(identity_inputs) != {"goal_id", "normalized_outcome"}:
        raise StateError("identity_inputs fields are invalid")
    if not all(isinstance(identity_inputs[field], str) and identity_inputs[field] for field in identity_inputs):
        raise StateError("identity_inputs values are invalid")
    if value["journey_id"] != journey_id(identity_inputs.get("goal_id", ""), identity_inputs.get("normalized_outcome", "")):
        raise StateError("journey identity does not match identity inputs")
    state = value["state"]
    if not isinstance(state, dict) or set(state) != {"phase", "classification", "status"}:
        raise StateError("state lifecycle fields are invalid")
    if state["phase"] not in STATE_PHASES:
        raise StateError("invalid state phase")
    if state["status"] not in STATE_STATUSES:
        raise StateError("invalid state status")
    if not isinstance(value["source_hashes"], dict) or set(value["source_hashes"]) != {
        "request", "repository_rules", "goal", "board_state", "accepted_artifacts", "effective_config",
    }:
        raise StateError("source_hashes fields are invalid")
    artifacts = value["generated_artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != set(PACKET_KINDS):
        raise StateError("generated_artifacts must contain all packet kinds")
    goalbuddy = value["goalbuddy"]
    if not isinstance(goalbuddy, dict) or set(goalbuddy) != {
        "goal_path", "state_path", "goal_id", "active_checkpoint_id", "board_truth_owner", "read_only",
    } or goalbuddy.get("board_truth_owner") != "GoalBuddy" or goalbuddy.get("read_only") is not True:
        raise StateError("GoalBuddy read-only boundary is invalid")
    envelope = value["envelope"]
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema_version", "journey_id", "goal_id", "checkpoint_id", "effective_config",
        "config_provenance", "config_history", "hard_constraints", "source_hashes",
    } or envelope.get("journey_id") != value["journey_id"]:
        raise StateError("state envelope identity mismatch")
    if envelope.get("source_hashes") != value["source_hashes"]:
        raise StateError("state envelope source hashes mismatch")
    if envelope.get("goal_id") != identity_inputs["goal_id"]:
        raise StateError("state envelope goal identity mismatch")
    if envelope.get("checkpoint_id") != goalbuddy.get("active_checkpoint_id"):
        raise StateError("state envelope checkpoint identity mismatch")
    if goalbuddy.get("goal_id") != identity_inputs["goal_id"]:
        raise StateError("GoalBuddy reference identity mismatch")
    expected_hash = envelope_hash(envelope)
    for kind, reference in artifacts.items():
        if not isinstance(reference, dict) or set(reference) != {
            "path", "journey_id", "envelope_sha256", "effective_config_sha256", "content_sha256",
        }:
            raise StateError(f"invalid packet reference: {kind}")
        if reference.get("journey_id") != value["journey_id"] or reference.get("envelope_sha256") != expected_hash:
            raise StateError(f"packet reference envelope mismatch: {kind}")
        if reference.get("effective_config_sha256") != value["source_hashes"]["effective_config"]:
            raise StateError(f"packet reference config mismatch: {kind}")
        if not isinstance(reference.get("path"), str) or not Path(reference["path"]).is_absolute():
            raise StateError(f"packet reference path invalid: {kind}")
        if not SHA256_RE.fullmatch(str(reference.get("envelope_sha256"))) or not SHA256_RE.fullmatch(str(reference.get("effective_config_sha256"))) or not SHA256_RE.fullmatch(str(reference.get("content_sha256"))):
            raise StateError(f"packet reference hash invalid: {kind}")
    if not isinstance(value["transition_history"], list):
        raise StateError("transition_history must be a list")
    return value


def packet_integrity_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    envelope = state["envelope"]
    expected_envelope_hash = envelope_hash(envelope)
    for kind in PACKET_KINDS:
        reference = state["generated_artifacts"][kind]
        path = Path(reference["path"])
        if not path.is_file():
            errors.append(f"packet_missing:{kind}")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"packet_unreadable:{kind}:{exc}")
            continue
        if sha256_bytes(data) != reference["content_sha256"]:
            errors.append(f"packet_content_hash_mismatch:{kind}")
            continue
        try:
            document = json.loads(data.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, StateError):
            errors.append(f"packet_malformed:{kind}")
            continue
        if not isinstance(document, dict) or set(document) != PACKET_KEYS:
            errors.append(f"packet_shape_mismatch:{kind}")
            continue
        if document != packet_document(kind, envelope):
            errors.append(f"packet_envelope_mismatch:{kind}")
        if reference["envelope_sha256"] != expected_envelope_hash:
            errors.append(f"packet_reference_envelope_mismatch:{kind}")
    return errors


def load_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates)
    except StateError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot parse state: {exc}") from exc
    return validate_state(value)


def analyze(state_path: Path, context: JourneyContext) -> dict[str, Any]:
    try:
        current_envelope = build_envelope(context)
    except BoardIdentityError as exc:
        return {"case": "board_mismatch", "mutated": False, "choices": ["inspect"], "error": str(exc)}
    if not state_path.exists():
        return {"case": "absent", "mutated": False, "choices": ["start_fresh"], "journey_id": current_envelope["journey_id"]}
    try:
        prior = load_state(state_path)
    except StateError as exc:
        return {"case": "malformed", "mutated": False, "choices": list(FAIL_CLOSED_CHOICES), "error": str(exc)}
    if prior["journey_id"] != current_envelope["journey_id"]:
        return {
            "case": "distinct_goal", "mutated": False, "choices": ["start_distinct_goal"],
            "active_journey_id": prior["journey_id"], "requested_journey_id": current_envelope["journey_id"],
        }
    stale = sorted(
        key for key, current_value in current_envelope["source_hashes"].items()
        if not SHA256_RE.fullmatch(str(prior["source_hashes"].get(key)))
        or prior["source_hashes"].get(key) != current_value
    )
    if stale:
        return {"case": "stale", "mutated": False, "choices": list(FAIL_CLOSED_CHOICES), "stale_hashes": stale, "journey_id": prior["journey_id"]}
    integrity_errors = packet_integrity_errors(prior)
    if prior["envelope"] != current_envelope:
        integrity_errors.append("state_envelope_recomputed_mismatch")
    if integrity_errors:
        return {
            "case": "integrity_error", "mutated": False,
            "choices": list(FAIL_CLOSED_CHOICES), "integrity_errors": integrity_errors,
            "journey_id": prior["journey_id"],
        }
    if prior["state"]["status"] == "stopped":
        return {"case": "stopped", "mutated": False, "choices": list(FAIL_CLOSED_CHOICES), "journey_id": prior["journey_id"]}
    return {"case": "matching_active", "mutated": False, "choices": list(MATCHING_ACTIVE_CHOICES), "journey_id": prior["journey_id"]}


def _derived_state_path(state_path: Path, label: str, identity: str) -> Path:
    suffix = state_path.suffix or ".json"
    return state_path.with_name(f"{state_path.stem}.{label}-{identity}{suffix}")


def transition(
    state_path: Path,
    packet_directory: Path,
    context: JourneyContext,
    choice: str,
    *,
    preview_authorized: bool,
) -> dict[str, Any]:
    decision = analyze(state_path, context)
    if choice not in decision["choices"]:
        raise TransitionError(f"choice {choice!r} is invalid for {decision['case']}")
    if choice in {"inspect", "continue"}:
        return {**decision, "selected": choice, "mutated": False}
    if not preview_authorized:
        raise TransitionError("explicit preview/authority boundary is required before state creation or mutation")

    if choice in {"revise", "stop_safely"}:
        state = load_state(state_path)
        prior = state["state"]["status"]
        state["state"]["phase"] = "discover" if choice == "revise" else "close_or_resume"
        state["state"]["status"] = "active" if choice == "revise" else "stopped"
        state["transition_history"].append({"choice": choice, "from": prior, "to": state["state"]["status"]})
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"case": decision["case"], "selected": choice, "mutated": True, "state_path": str(state_path.resolve())}

    envelope = build_envelope(context)
    if choice == "start_fresh" and decision["case"] == "absent":
        destination = state_path
    elif choice == "start_distinct_goal":
        destination = _derived_state_path(state_path, "distinct", envelope["journey_id"])
    else:
        destination = _derived_state_path(state_path, choice.replace("start_", ""), envelope_hash(envelope)[7:19])
    if destination.exists():
        raise TransitionError(f"destination already exists: {destination}")
    generated = write_packets(packet_directory, envelope)
    try:
        state = new_state(context, generated)
        state["transition_history"][0] = {
            "choice": choice, "from": decision["case"], "to": "active",
            "source_state_preserved": decision["case"] != "absent",
        }
        _write_exclusive_json(destination, state)
    except Exception:
        rollback_packets(generated)
        raise
    return {
        "case": decision["case"], "selected": choice, "mutated": True,
        "state_path": str(destination.resolve()), "journey_id": state["journey_id"],
        "source_state_preserved": decision["case"] != "absent",
    }


def _path(value: str) -> Path:
    return Path(value).resolve()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("command", choices=("analyze", "transition"))
    root.add_argument("--request", required=True)
    root.add_argument("--goal-id", required=True)
    root.add_argument("--checkpoint-id", required=True)
    root.add_argument("--repository-rules", required=True, type=_path)
    root.add_argument("--goal-path", required=True, type=_path)
    root.add_argument("--board-state", required=True, type=_path)
    root.add_argument("--accepted-artifact", action="append", default=[], type=_path)
    root.add_argument("--state-path", required=True, type=_path)
    root.add_argument("--packet-directory", type=_path)
    root.add_argument("--choice")
    root.add_argument("--preview-authorized", action="store_true")
    root.add_argument("--workspace-config", type=_path)
    root.add_argument("--repo-root", type=_path, default=Path.cwd())
    root.add_argument("--goal-override", type=_path)
    root.add_argument("--active-goal-id")
    root.add_argument("--checkpoint-override", type=_path)
    root.add_argument("--active-checkpoint-id")
    root.add_argument("--operator-override", type=_path)
    return root


def context_from_args(args: argparse.Namespace) -> JourneyContext:
    config_args = argparse.Namespace(
        workspace_config=args.workspace_config, repo_root=args.repo_root,
        goal_override=args.goal_override, goal_id=args.goal_id, active_goal_id=args.active_goal_id or args.goal_id,
        checkpoint_override=args.checkpoint_override, checkpoint_id=args.checkpoint_id,
        active_checkpoint_id=args.active_checkpoint_id or args.checkpoint_id,
        operator_override=args.operator_override,
    )
    receipt = CONFIG.resolve(CONFIG.build_layers(config_args))
    return JourneyContext(
        goal_id=args.goal_id, checkpoint_id=args.checkpoint_id, outcome=args.request,
        repository_rules=args.repository_rules, goal_path=args.goal_path, board_state=args.board_state,
        accepted_artifacts=tuple(args.accepted_artifact), config_receipt=receipt,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        context = context_from_args(args)
        if args.command == "analyze":
            result = analyze(args.state_path, context)
        else:
            if args.choice is None or args.packet_directory is None:
                raise TransitionError("transition requires --choice and --packet-directory")
            result = transition(
                args.state_path, args.packet_directory, context, args.choice,
                preview_authorized=args.preview_authorized,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except CONFIG.UnsafeOverrideError as exc:
        print(f"unsafe override: {exc}", file=sys.stderr)
        return CONFIG.EXIT_UNSAFE_OVERRIDE
    except (CONFIG.ParseError, CONFIG.ValidationError) as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return CONFIG.EXIT_INVALID_CONFIG
    except (CONFIG.ConfigError, JourneyError, OSError) as exc:
        print(f"journey error: {exc}", file=sys.stderr)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
