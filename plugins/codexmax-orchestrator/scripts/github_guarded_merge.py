#!/usr/bin/env python3
"""Merge one exact Orcastrata pull request after closed, fresh gates pass."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


REQUEST_TYPE = "orcastrata_github_guarded_merge_request_v1"
RECEIPT_TYPE = "orcastrata_github_guarded_merge_receipt_v1"
STATE_TYPE = "orcastrata_github_guarded_merge_state_v1"
AUDIT_TYPE = "orcastrata_github_merge_independent_audit_v1"
HOST = "github.com"
REPOSITORY = "Vel-Labs/orcastrata-max"
REQUEST_NAME = "notes/t080-effects/merge-request.json"
STATE_NAME = "notes/t080-effects/merge-state.json"
AUDIT_NAME = "notes/t080-effects/independent-audit.json"
AUDITOR_PROJECTION_NAME = "notes/t080-audit-runtime-projection.final.json"
BOARD_NAME = "state.yaml"
LOCK_NAME = "notes/t080-effects/merge-effect.lock"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MARKER_RE = re.compile(r"orcastrata:lifecycle:[A-Za-z0-9][A-Za-z0-9._-]{0,199}:issue:[1-9][0-9]*\Z")
AUDITOR_RE = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")


class MergeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("github_merge_runtime_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


github = _module("orcastrata_merge_github_read", "github_cli_read.py")
live = _module("orcastrata_merge_issue_live", "github_issue_live.py")
board_adapter = _module("orcastrata_merge_goalbuddy", "workgraph_goalbuddy_adapter.py")


def _closed(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise MergeError(code)
    return value


def _digest(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MergeError("request_invalid") from exc
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise MergeError(code)
    return value


def _request(value: Any) -> dict[str, Any]:
    request = _closed(value, {
        "artifact_type", "evidence", "expected_user", "pull_request",
        "schema_version", "scope", "target",
    }, "request_shape_invalid")
    if request["schema_version"] != 1 or request["artifact_type"] != REQUEST_TYPE:
        raise MergeError("request_identity_invalid")
    if _closed(request["target"], {"host", "repository"}, "target_invalid") != {
        "host": HOST, "repository": REPOSITORY,
    }:
        raise MergeError("authority_target_mismatch")
    if not isinstance(request["expected_user"], str) or not request["expected_user"] or len(request["expected_user"]) > 100:
        raise MergeError("expected_user_invalid")
    pull = _closed(request["pull_request"], {
        "base", "expected_base_sha", "expected_head_sha", "lifecycle_marker", "number",
    }, "pull_request_invalid")
    if type(pull["number"]) is not int or pull["number"] < 1:
        raise MergeError("pull_request_invalid")
    if not isinstance(pull["base"], str) or github.BRANCH_RE.fullmatch(pull["base"]) is None:
        raise MergeError("pull_request_invalid")
    _sha(pull["expected_base_sha"], "pull_request_invalid")
    _sha(pull["expected_head_sha"], "pull_request_invalid")
    if not isinstance(pull["lifecycle_marker"], str) or MARKER_RE.fullmatch(pull["lifecycle_marker"]) is None:
        raise MergeError("pull_request_invalid")
    scope = _closed(request["scope"], {"filenames_sha256", "total_count"}, "scope_invalid")
    if type(scope["total_count"]) is not int or scope["total_count"] < 1:
        raise MergeError("scope_invalid")
    if not isinstance(scope["filenames_sha256"], str) or DIGEST_RE.fullmatch(scope["filenames_sha256"]) is None:
        raise MergeError("scope_invalid")
    evidence = _closed(request["evidence"], {
        "auditor_projection_sha256", "goalbuddy_sha256",
        "independent_audit_sha256", "independent_auditor_id",
    }, "evidence_invalid")
    if any(
        not isinstance(evidence[field], str) or DIGEST_RE.fullmatch(evidence[field]) is None
        for field in ("auditor_projection_sha256", "goalbuddy_sha256", "independent_audit_sha256")
    ) or not isinstance(evidence["independent_auditor_id"], str) or AUDITOR_RE.fullmatch(evidence["independent_auditor_id"]) is None:
        raise MergeError("evidence_invalid")
    return request


def _execution_directory(value: Path) -> Path:
    if not value.is_absolute() or not value.is_dir() or value.is_symlink():
        raise MergeError("execution_directory_invalid")
    resolved = value.resolve(strict=True)
    if resolved != value:
        raise MergeError("execution_directory_invalid")
    return resolved


def _read_regular(path: Path, label: str) -> bytes:
    try:
        return live.adapter._read_regular_bytes(path, label=label)
    except (OSError, live.adapter.AdapterError) as exc:
        raise MergeError(f"{label}_invalid") from exc


def _load_request(root: Path) -> dict[str, Any]:
    try:
        return _request(json.loads(
            _read_regular(root / REQUEST_NAME, "merge_request").decode("utf-8"),
            object_pairs_hook=github._pairs,
        ))
    except (UnicodeDecodeError, json.JSONDecodeError, github.GithubReadError) as exc:
        raise MergeError("merge_request_invalid") from exc


def _state(request: Mapping[str, Any], status: str, merge_commit_sha: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": STATE_TYPE,
        "request_sha256": _digest(request),
        "status": status,
        "merge_commit_sha": merge_commit_sha,
    }


def _load_state(root: Path, request: Mapping[str, Any]) -> dict[str, Any] | None:
    path = root / STATE_NAME
    if not path.exists():
        return None
    try:
        value = json.loads(_read_regular(path, "merge_state").decode("utf-8"), object_pairs_hook=github._pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, github.GithubReadError) as exc:
        raise MergeError("state_invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"artifact_type", "merge_commit_sha", "request_sha256", "schema_version", "status"}
        or value["schema_version"] != 1
        or value["artifact_type"] != STATE_TYPE
        or value["request_sha256"] != _digest(request)
        or value["status"] not in {"effect_started", "unknown", "reconciled_unmerged", "bound"}
        or (value["merge_commit_sha"] is not None and (not isinstance(value["merge_commit_sha"], str) or SHA_RE.fullmatch(value["merge_commit_sha"]) is None))
    ):
        raise MergeError("state_invalid")
    return value


def _state_requires_reconciliation_hint(root: Path) -> bool:
    path = root / STATE_NAME
    if not path.exists():
        return False
    try:
        value = json.loads(_read_regular(path, "merge_state").decode("utf-8"), object_pairs_hook=github._pairs)
    except (MergeError, UnicodeDecodeError, json.JSONDecodeError, github.GithubReadError):
        return True
    if (
        not isinstance(value, Mapping)
        or value.get("artifact_type") != STATE_TYPE
        or value.get("status") not in {"effect_started", "unknown", "reconciled_unmerged", "bound"}
    ):
        return True
    return value["status"] in {"effect_started", "unknown"}


def _load_evidence(root: Path, request: Mapping[str, Any]) -> None:
    board_raw = _read_regular(root / BOARD_NAME, "goalbuddy_state")
    audit_raw = _read_regular(root / AUDIT_NAME, "independent_audit")
    projection_raw = _read_regular(root / AUDITOR_PROJECTION_NAME, "auditor_projection")
    if _bytes_digest(board_raw) != request["evidence"]["goalbuddy_sha256"]:
        raise MergeError("goalbuddy_digest_mismatch")
    if _bytes_digest(audit_raw) != request["evidence"]["independent_audit_sha256"]:
        raise MergeError("independent_audit_digest_mismatch")
    if _bytes_digest(projection_raw) != request["evidence"]["auditor_projection_sha256"]:
        raise MergeError("auditor_projection_digest_mismatch")
    try:
        snapshot = board_adapter.snapshot(root / BOARD_NAME)
        board = board_adapter._parse_board(board_raw)
    except (OSError, UnicodeDecodeError, board_adapter.AdapterError) as exc:
        raise MergeError("goalbuddy_state_invalid") from exc
    if (
        snapshot.get("canonical_owner") != "GoalBuddy"
        or snapshot.get("state_schema_version") != board_adapter.CURRENT_BOARD_VERSION
        or snapshot.get("board_sha256") != request["evidence"]["goalbuddy_sha256"]
    ):
        raise MergeError("goalbuddy_state_invalid")
    if board["active_task"] != "T080" or board["task_statuses"].get("T080") != "active":
        raise MergeError("goalbuddy_task_binding_mismatch")
    dependencies = board["tasks"]["T080"]["dependencies"]
    if not dependencies:
        raise MergeError("dependencies_invalid")
    for dependency in dependencies:
        receipt = board["task_receipts"].get(dependency)
        command_statuses = receipt.get("command_statuses", []) if isinstance(receipt, Mapping) else []
        commands = receipt.get("lists", {}).get("commands", []) if isinstance(receipt, Mapping) else []
        if (
            board["task_statuses"].get(dependency) != "done"
            or not isinstance(receipt, Mapping)
            or receipt.get("present") is not True
            or receipt.get("result") != "done"
            or receipt.get("scalars", {}).get("decision") != "approved"
            or not command_statuses
            or len(command_statuses) != len(commands)
            or any(status != "pass" for status in command_statuses)
        ):
            raise MergeError("dependency_not_ready")
    try:
        audit = json.loads(audit_raw.decode("utf-8"), object_pairs_hook=github._pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, github.GithubReadError) as exc:
        raise MergeError("independent_audit_invalid") from exc
    try:
        projection = json.loads(projection_raw.decode("utf-8"), object_pairs_hook=github._pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, github.GithubReadError) as exc:
        raise MergeError("auditor_projection_invalid") from exc
    if not isinstance(projection, Mapping):
        raise MergeError("auditor_projection_invalid")
    dispatch = projection.get("dispatch_receipt")
    if (
        projection.get("schema_version") != 1
        or projection.get("status") != "ready"
        or projection.get("dispatch_performed") is not True
        or projection.get("provider_dispatch") is not False
        or not isinstance(dispatch, Mapping)
        or dispatch.get("child_task_id") != "T080-A01"
        or dispatch.get("runtime_child_id") != request["evidence"]["independent_auditor_id"]
        or dispatch.get("runtime_surface") != "codex_collaboration"
        or dispatch.get("semantic_role") != "independent_auditor"
        or dispatch.get("provider_dispatch") is not False
    ):
        raise MergeError("auditor_projection_invalid")
    audit = _closed(audit, {
        "artifact_type", "auditor", "board_sha256", "pull_request",
        "schema_version", "task_id", "verdict",
    }, "independent_audit_invalid")
    auditor = _closed(audit["auditor"], {
        "read_only", "runtime_child_id", "runtime_surface",
    }, "independent_audit_invalid")
    facts = _closed(audit["pull_request"], {
        "base_sha", "filenames_sha256", "head_sha", "number", "total_count",
    }, "independent_audit_invalid")
    pull = request["pull_request"]
    scope = request["scope"]
    if (
        audit["schema_version"] != 1
        or audit["artifact_type"] != AUDIT_TYPE
        or auditor != {
            "read_only": True,
            "runtime_child_id": request["evidence"]["independent_auditor_id"],
            "runtime_surface": "codex_collaboration",
        }
        or audit["board_sha256"] != request["evidence"]["goalbuddy_sha256"]
        or audit["task_id"] != "T080"
        or audit["verdict"] != "ACCEPT"
        or facts != {
            "number": pull["number"],
            "base_sha": pull["expected_base_sha"],
            "head_sha": pull["expected_head_sha"],
            "total_count": scope["total_count"],
            "filenames_sha256": scope["filenames_sha256"],
        }
    ):
        raise MergeError("independent_audit_binding_mismatch")


def _lock(root: Path) -> int:
    path = root / LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MergeError("merge_lock_invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as exc:
        try:
            os.close(descriptor)
        except UnboundLocalError:
            pass
        raise MergeError("merge_effect_in_progress") from exc
    except MergeError:
        os.close(descriptor)
        raise
    except OSError as exc:
        raise MergeError("merge_lock_invalid") from exc


def _read(operation: str, arguments: Mapping[str, Any], executable: str, runner, environment) -> Any:
    validated = github._request({
        "schema_version": 1,
        "artifact_type": github.REQUEST_TYPE,
        "operation": operation,
        "arguments": dict(arguments),
    })
    return github._operate(operation, validated[1], validated[2], validated[4], validated[5], executable, runner, environment)[0]


def _exact_pull(request: Mapping[str, Any], pull: Mapping[str, Any]) -> None:
    expected = request["pull_request"]
    if pull["number"] != expected["number"]:
        raise MergeError("pull_request_identity_mismatch")
    if pull["base_ref_name"] != expected["base"] or pull["base_ref_oid"] != expected["expected_base_sha"]:
        raise MergeError("base_sha_mismatch")
    if pull["head_ref_oid"] != expected["expected_head_sha"]:
        raise MergeError("head_sha_mismatch")
    if pull["orcastrata_lifecycle_markers"] != [expected["lifecycle_marker"]]:
        raise MergeError("board_marker_mismatch")


def _bound_observation(request: Mapping[str, Any], value: Mapping[str, Any], code: str) -> None:
    expected = request["pull_request"]
    if value.get("base_sha") != expected["expected_base_sha"] or value.get("head_sha") != expected["expected_head_sha"]:
        raise MergeError(code)


def _fresh_gates(request: Mapping[str, Any], executable: str, runner, environment) -> dict[str, Any]:
    expected = request["pull_request"]
    arguments = {"host": HOST, "repository": REPOSITORY, "number": expected["number"]}
    pull = _read("readPullRequest", arguments, executable, runner, environment)
    _exact_pull(request, pull)
    if pull["merged"]:
        raise MergeError("pull_request_already_merged")
    if pull["state"].lower() != "open" or pull["draft"]:
        raise MergeError("pull_request_not_open_and_ready")
    if pull["mergeable"] is not True or pull["mergeable_state"] != "clean":
        raise MergeError("pull_request_conflict_or_unready")
    requirements = _read(
        "readMergeRequirements",
        {"host": HOST, "repository": REPOSITORY, "branch": expected["base"]},
        executable, runner, environment,
    )
    if (
        requirements["require_code_owner_review"]
        or requirements["require_conversation_resolution"]
        or requirements["require_last_push_approval"]
    ):
        raise MergeError("merge_policy_unsupported")
    checks = _read("listPullRequestChecks", arguments, executable, runner, environment)
    _bound_observation(request, checks, "check_binding_mismatch")
    if checks["possibly_more"]:
        raise MergeError("check_observation_incomplete")
    check_rows: dict[tuple[str, int | None], Mapping[str, Any]] = {}
    for item in checks["items"]:
        identity = (item["name"], item["app_id"])
        if identity in check_rows:
            raise MergeError("check_identity_ambiguous")
        check_rows[identity] = item
        if item["status"] != "completed" or item["conclusion"] not in {"success", "neutral", "skipped"}:
            raise MergeError("checks_not_green")
    for required in requirements["required_checks"]:
        identity = (required["context"], required["app_id"])
        if required["app_id"] is None:
            if not any(name == required["context"] for name, _ in check_rows):
                raise MergeError("required_check_missing")
        elif identity not in check_rows:
            raise MergeError("required_check_missing")
    reviews = _read("listPullRequestReviews", arguments, executable, runner, environment)
    _bound_observation(request, reviews, "review_binding_mismatch")
    if reviews["possibly_more"]:
        raise MergeError("review_observation_incomplete")
    latest: dict[str, Mapping[str, Any]] = {}
    for item in reviews["items"]:
        prior = latest.get(item["reviewer"])
        if prior is not None and item["submitted_at"] == prior["submitted_at"]:
            raise MergeError("review_timestamp_ambiguous")
        if prior is None or item["submitted_at"] > prior["submitted_at"]:
            latest[item["reviewer"]] = item
    if any(item["state"] == "CHANGES_REQUESTED" for item in latest.values()):
        raise MergeError("review_changes_requested")
    approvals = {
        reviewer for reviewer, item in latest.items()
        if reviewer != request["expected_user"]
        and item["state"] == "APPROVED"
        and item["commit_sha"] == expected["expected_head_sha"]
    }
    if len(approvals) < requirements["required_approvals"]:
        raise MergeError("required_review_policy_unmet")
    diff = _read("readPullRequestDiffSummary", arguments, executable, runner, environment)
    _bound_observation(request, diff, "diff_binding_mismatch")
    if diff["total_count"] != request["scope"]["total_count"] or diff["filenames_sha256"] != request["scope"]["filenames_sha256"]:
        raise MergeError("scope_mismatch")
    return pull


def _boundary(called: bool, mutated: bool | str) -> dict[str, Any]:
    return {
        "acceptance_granted": False,
        "authority_granted": False,
        "credentials_read_by_orcastrata": False,
        "github_called": called,
        "github_mutated": mutated,
        "live_execution_available": True,
        "simulation_only": False,
    }


def _receipt(status: str, outcome: str, commands: int, mutated: bool, pull: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": RECEIPT_TYPE,
        "status": status,
        "outcome": outcome,
        "pull_request": {"number": pull["number"], "head_sha": pull["head_ref_oid"], "merge_commit_sha": pull["merge_commit_sha"]},
        "command_count": commands,
        "mutation_attempted": mutated,
        "reconcile_required": False,
        "effect_boundary": _boundary(True, mutated),
    }


def _failure(code: str, commands: int, *, unknown: bool, attempted: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": RECEIPT_TYPE,
        "status": "unknown" if unknown else "error",
        "error": {"code": code},
        "command_count": commands,
        "mutation_attempted": attempted,
        "reconcile_required": unknown,
        "effect_boundary": _boundary(commands > 0, "unknown" if unknown else False),
    }


def execute(execution_directory: Path, *, runner=github._run_command, resolver=github._resolve_gh, environment_source=None) -> dict[str, Any]:
    command_count = 0
    effect_prepared = False
    put_started = False
    pending_reconciliation = False
    descriptor: int | None = None
    try:
        root = _execution_directory(execution_directory)
        descriptor = _lock(root)
        pending_reconciliation = _state_requires_reconciliation_hint(root)
        request = _load_request(root)
        prior = _load_state(root, request)
        pending_reconciliation = pending_reconciliation or (
            prior is not None and prior["status"] in {"effect_started", "unknown"}
        )
        if not pending_reconciliation:
            _load_evidence(root, request)
        executable = resolver()
        environment = github._environment(os.environ if environment_source is None else environment_source)

        def counted(argv: Sequence[str], env: Mapping[str, str]) -> Mapping[str, Any]:
            nonlocal command_count
            command_count += 1
            return runner(argv, env)

        facts = live._identity(executable, environment, HOST, REPOSITORY, counted)
        if facts["username"] != request["expected_user"]:
            raise MergeError("identity_mismatch")
        if facts["permission"] not in live.ALLOWED_PERMISSIONS:
            raise MergeError("repository_write_permission_required")
        arguments = {"host": HOST, "repository": REPOSITORY, "number": request["pull_request"]["number"]}
        if pending_reconciliation:
            pull = _read("readPullRequest", arguments, executable, counted, environment)
            _exact_pull(request, pull)
            if pull["merged"]:
                merge_sha = _sha(pull["merge_commit_sha"], "merged_pull_request_invalid")
                live._write_state(root / STATE_NAME, _state(request, "bound", merge_sha), initial=False)
                return _receipt("bound", "reconciled_merged", command_count, False, pull)
            live._write_state(root / STATE_NAME, _state(request, "reconciled_unmerged"), initial=False)
            return _receipt("ready", "reconciled_unmerged", command_count, False, pull)
        if prior is not None and prior["status"] == "bound":
            pull = _read("readPullRequest", arguments, executable, counted, environment)
            _exact_pull(request, pull)
            if not pull["merged"]:
                raise MergeError("bound_merge_missing")
            _sha(pull["merge_commit_sha"], "merged_pull_request_invalid")
            return _receipt("bound", "reconciled_merged", command_count, False, pull)
        _fresh_gates(request, executable, counted, environment)
        live._write_state(root / STATE_NAME, _state(request, "effect_started"), initial=prior is None)
        effect_prepared = True
        final_pull = _read("readPullRequest", arguments, executable, counted, environment)
        _exact_pull(request, final_pull)
        if final_pull["merged"]:
            merge_sha = _sha(final_pull["merge_commit_sha"], "merged_pull_request_invalid")
            live._write_state(root / STATE_NAME, _state(request, "bound", merge_sha), initial=False)
            effect_prepared = False
            return _receipt("bound", "reconciled_merged", command_count, False, final_pull)
        if final_pull["state"].lower() != "open":
            live._write_state(root / STATE_NAME, _state(request, "reconciled_unmerged"), initial=False)
            effect_prepared = False
            return _receipt("ready", "reconciled_unmerged", command_count, False, final_pull)
        if final_pull["draft"] or final_pull["mergeable"] is not True or final_pull["mergeable_state"] != "clean":
            live._write_state(root / STATE_NAME, _state(request, "reconciled_unmerged"), initial=False)
            effect_prepared = False
            raise MergeError("pre_effect_pull_request_unready")
        endpoint = f"repos/Vel-Labs/orcastrata-max/pulls/{request['pull_request']['number']}/merge"
        argv = (
            executable, "api", "--hostname", HOST, "--method", "PUT", endpoint,
            "-f", f"sha={request['pull_request']['expected_head_sha']}",
        )
        put_started = True
        try:
            merged = github._mapping(github._json_output(github._invoke(argv, counted, environment)))
        except Exception as exc:
            try:
                live._write_state(root / STATE_NAME, _state(request, "unknown"), initial=False)
            except Exception:
                pass
            raise MergeError("merge_outcome_unknown") from exc
        if merged.get("merged") is not True:
            live._write_state(root / STATE_NAME, _state(request, "reconciled_unmerged"), initial=False)
            effect_prepared = False
            raise MergeError("merge_rejected")
        merge_sha = _sha(merged.get("sha"), "merge_outcome_unknown")
        live._write_state(root / STATE_NAME, _state(request, "bound", merge_sha), initial=False)
        effect_prepared = False
        final_pull = dict(final_pull)
        final_pull["merge_commit_sha"] = merge_sha
        return _receipt("bound", "merged", command_count, True, final_pull)
    except (MergeError, github.GithubReadError, live.effect.IssueEffectError, board_adapter.AdapterError) as exc:
        unknown = exc.code in {"merge_effect_in_progress", "merge_outcome_unknown"} or pending_reconciliation or effect_prepared or (put_started and exc.code != "merge_rejected")
        code = exc.code if exc.code == "merge_effect_in_progress" else ("merge_reconciliation_required" if (pending_reconciliation or (effect_prepared and not put_started)) and exc.code != "merge_outcome_unknown" else ("merge_outcome_unknown" if unknown else exc.code))
        return _failure(code, command_count, unknown=unknown, attempted=put_started)
    except Exception:
        unknown = pending_reconciliation or effect_prepared or put_started
        code = "merge_reconciliation_required" if pending_reconciliation or (effect_prepared and not put_started) else ("merge_outcome_unknown" if put_started else "guarded_merge_internal_error")
        return _failure(code, command_count, unknown=unknown, attempted=put_started)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = execute(args.execution_directory)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"] == "bound" else 2


if __name__ == "__main__":
    raise SystemExit(main())
