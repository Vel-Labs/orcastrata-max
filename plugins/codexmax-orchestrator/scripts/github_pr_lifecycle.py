#!/usr/bin/env python3
"""Run one lease-bound branch-to-PR lifecycle without merge authority."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, Mapping, Sequence


REQUEST_TYPE = "orcastrata_github_pr_lifecycle_request_v1"
RECEIPT_TYPE = "orcastrata_github_pr_lifecycle_receipt_v1"
STATE_TYPE = "orcastrata_github_pr_lifecycle_state_v1"
MODES = {"publish", "repair", "observe"}
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
REF_RE = re.compile(r"(?!.*(?:\.\.|//|@\{|\\))[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")


class LifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("github_pr_runtime_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


github = _module("orcastrata_pr_github_read", "github_cli_read.py")
live = _module("orcastrata_pr_issue_live", "github_issue_live.py")
dependencies = _module("orcastrata_pr_workgraph_dependencies", "workgraph_dependencies.py")


def _closed(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise LifecycleError(code)
    return value


def _text(value: Any, code: str, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str) or not value or len(value.encode()) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LifecycleError(code)
    return value


def _body(value: Any) -> str:
    if (
        not isinstance(value, str) or not value or len(value.encode()) > 65536
        or any((ord(character) < 32 and character not in "\t\n\r") or ord(character) == 127 for character in value)
    ):
        raise LifecycleError("pull_request_invalid")
    return github.SECRET_RE.sub("[redacted]", value)


def _request(value: Any) -> dict[str, Any]:
    request = _closed(value, {
        "allowed_paths", "artifact_type", "base", "commit", "expected_base_sha", "expected_head_sha",
        "expected_user", "head", "issue_number", "lease", "lifecycle_id", "mode",
        "pull_request", "remote", "schema_version", "target", "worktree",
    }, "request_shape_invalid")
    if request["schema_version"] != 1 or request["artifact_type"] != REQUEST_TYPE:
        raise LifecycleError("request_identity_invalid")
    if request["mode"] not in MODES:
        raise LifecycleError("mode_invalid")
    target = _closed(request["target"], {"host", "repository"}, "target_invalid")
    github._target(target)
    request["expected_user"] = _text(request["expected_user"], "expected_user_invalid", 100)
    request["lifecycle_id"] = _text(request["lifecycle_id"], "lifecycle_id_invalid", 200)
    if ID_RE.fullmatch(request["lifecycle_id"]) is None:
        raise LifecycleError("lifecycle_id_invalid")
    if type(request["issue_number"]) is not int or request["issue_number"] < 1:
        raise LifecycleError("issue_number_invalid")
    for field in ("base", "head"):
        if not isinstance(request[field], str) or REF_RE.fullmatch(request[field]) is None:
            raise LifecycleError(f"{field}_invalid")
    if request["base"] == request["head"]:
        raise LifecycleError("branch_identity_invalid")
    if not isinstance(request["expected_base_sha"], str) or SHA_RE.fullmatch(request["expected_base_sha"]) is None:
        raise LifecycleError("expected_base_sha_invalid")
    if request["expected_head_sha"] is not None and (
        not isinstance(request["expected_head_sha"], str) or SHA_RE.fullmatch(request["expected_head_sha"]) is None
    ):
        raise LifecycleError("expected_head_sha_invalid")
    request["remote"] = _text(request["remote"], "remote_invalid", 100)
    if request["remote"] != "origin":
        raise LifecycleError("remote_invalid")
    path = Path(_text(request["worktree"], "worktree_invalid", 4096))
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise LifecycleError("worktree_invalid")
    request["worktree"] = str(path.resolve())
    paths = request["allowed_paths"]
    if not isinstance(paths, list) or not paths:
        raise LifecycleError("allowed_paths_invalid")
    try:
        normalized = sorted({dependencies.normalize_path(item) for item in paths})
    except dependencies.DependencyError as exc:
        raise LifecycleError(exc.code) from exc
    if len(normalized) != len(paths):
        raise LifecycleError("allowed_paths_invalid")
    request["allowed_paths"] = normalized
    lease = _closed(request["lease"], {
        "board_sha256", "claim_id", "fencing_token", "holder", "registry_path",
        "work_item_id",
    }, "lease_invalid")
    _text(lease["claim_id"], "lease_invalid", 200)
    _text(lease["work_item_id"], "lease_invalid", 200)
    if type(lease["fencing_token"]) is not int or lease["fencing_token"] < 1:
        raise LifecycleError("lease_invalid")
    try:
        dependencies.validate_holder(lease["holder"])
        dependencies._hash(lease["board_sha256"], "dependency_claim_board_hash_invalid")
    except dependencies.DependencyError as exc:
        raise LifecycleError(exc.code) from exc
    registry = Path(_text(lease["registry_path"], "lease_invalid", 4096))
    if not registry.is_absolute():
        raise LifecycleError("lease_invalid")
    lease["registry_path"] = str(registry)
    if request["mode"] == "observe":
        if request["commit"] is not None or request["pull_request"] is not None:
            raise LifecycleError("observe_payload_invalid")
    else:
        commit = _closed(request["commit"], {"message"}, "commit_invalid")
        _text(commit["message"], "commit_invalid", 4096)
        pull = _closed(request["pull_request"], {"body", "title"}, "pull_request_invalid")
        _text(pull["title"], "pull_request_invalid", 1024)
        pull["body"] = _body(pull["body"])
        if not _body_bound(request, pull["body"]):
            raise LifecycleError("pull_request_issue_binding_missing")
    if request["mode"] in {"observe", "repair"} and request["expected_head_sha"] is None:
        raise LifecycleError("expected_head_sha_required")
    return request


def _active_lease(request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    lease = request["lease"]
    try:
        registry = dependencies.read_registry(Path(lease["registry_path"]))
    except dependencies.DependencyError as exc:
        raise LifecycleError(exc.code) from exc
    row = next((item for item in registry["claims"] if item["claim_id"] == lease["claim_id"]), None)
    if row is None:
        raise LifecycleError("lease_unknown")
    if (
        row["state"] != "active" or row["work_item_id"] != lease["work_item_id"]
        or row["holder"] != lease["holder"] or row["board_sha256"] != lease["board_sha256"]
        or row["fencing_token"] != lease["fencing_token"]
        or row["write_scope"] != request["allowed_paths"]
    ):
        raise LifecycleError("lease_binding_mismatch")
    if now >= dependencies._time(row["expires_at"]):
        raise LifecycleError("lease_expired")
    if now < dependencies._time(row["acquired_at"]):
        raise LifecycleError("lease_clock_reversal")
    return row


def _resolve_git() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise LifecycleError("git_unavailable")
    try:
        resolved = Path(candidate).resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise LifecycleError("git_unavailable") from exc
    if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
        raise LifecycleError("git_unavailable")
    return str(resolved)


def _invoke(argv: Sequence[str], runner, environment: Mapping[str, str]) -> bytes:
    try:
        return github._invoke(argv, runner, environment)
    except github.GithubReadError as exc:
        raise LifecycleError(exc.code) from exc


def _lines(raw: bytes) -> list[str]:
    try:
        return [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise LifecycleError("git_output_invalid") from exc


def _remote_matches(url: str, host: str, repository: str) -> bool:
    suffix = repository + ".git"
    return url in {
        f"https://{host}/{suffix}",
        f"git@{host}:{suffix}",
        f"ssh://git@{host}/{suffix}",
    }


def _api(executable: str, host: str, endpoint: str, method: str = "GET", *fields: tuple[str, Any]) -> list[str]:
    argv = [executable, "api", "--hostname", host, "--method", method, endpoint]
    for key, value in fields:
        argv.extend(("-f", f"{key}={value}"))
    return argv


def _marker(request: Mapping[str, Any]) -> str:
    return f"<!-- orcastrata:lifecycle:{request['lifecycle_id']}:issue:{request['issue_number']} -->"


def _body_bound(request: Mapping[str, Any], body: Any) -> bool:
    text = _body(body)
    issue = re.compile(rf"(?<![0-9])#{request['issue_number']}(?![0-9])")
    return _marker(request) in text and issue.search(text) is not None


def _pull(request: Mapping[str, Any], value: Any) -> dict[str, Any]:
    item = github._mapping(value)
    if not _body_bound(request, item.get("body")):
        raise LifecycleError("pull_request_body_binding_mismatch")
    return github._pull_request(item)


def _require_head(pull: Mapping[str, Any], expected_sha: str | None) -> None:
    if expected_sha is None:
        raise LifecycleError("expected_head_sha_required")
    if pull["head_ref_oid"] != expected_sha:
        raise LifecycleError("pull_request_head_sha_mismatch")


def _pulls(request: Mapping[str, Any], executable: str, runner, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    owner, name = request["target"]["repository"].split("/", 1)
    raw = github._json_output(_invoke(_api(
        executable, request["target"]["host"], f"repos/{owner}/{name}/pulls", "GET",
        ("state", "all"), ("head", f"{owner}:{request['head']}"),
        ("base", request["base"]), ("per_page", 2),
    ), runner, environment))
    if not isinstance(raw, list):
        raise LifecycleError("pr_search_response_invalid")
    pulls = [_pull(request, item) for item in raw]
    if len(pulls) > 1:
        raise LifecycleError("multiple_pr_matches")
    return pulls


def _create_pr(request: Mapping[str, Any], executable: str, runner, environment: Mapping[str, str]) -> dict[str, Any]:
    owner, name = request["target"]["repository"].split("/", 1)
    pull = request["pull_request"]
    raw = github._json_output(_invoke(_api(
        executable, request["target"]["host"], f"repos/{owner}/{name}/pulls", "POST",
        ("title", pull["title"]), ("head", request["head"]), ("base", request["base"]),
        ("body", pull["body"]),
    ), runner, environment))
    return _pull(request, raw)


def _observe(request: Mapping[str, Any], pull: Mapping[str, Any], executable: str, runner, environment: Mapping[str, str]) -> dict[str, Any]:
    owner, name = request["target"]["repository"].split("/", 1)
    repo = f"repos/{owner}/{name}"
    number = pull["number"]
    files = github._json_output(_invoke(_api(
        executable, request["target"]["host"], f"{repo}/pulls/{number}/files", "GET",
        ("per_page", github.MAX_ITEMS), ("page", 1),
    ), runner, environment))
    checks = github._mapping(github._json_output(_invoke(_api(
        executable, request["target"]["host"], f"{repo}/commits/{pull['head_ref_oid']}/check-runs", "GET",
        ("per_page", github.MAX_ITEMS), ("page", 1),
    ), runner, environment)))
    reviews = github._json_output(_invoke(_api(
        executable, request["target"]["host"], f"{repo}/pulls/{number}/reviews", "GET",
        ("per_page", github.MAX_ITEMS), ("page", 1),
    ), runner, environment))
    if not isinstance(files, list) or not isinstance(reviews, list) or not isinstance(checks.get("check_runs"), list):
        raise LifecycleError("pr_observation_invalid")
    total_checks = checks.get("total_count")
    if (
        type(total_checks) is not int or total_checks != len(checks["check_runs"])
        or len(files) >= github.MAX_ITEMS or len(reviews) >= github.MAX_ITEMS
    ):
        raise LifecycleError("pr_observation_incomplete")
    filenames = [github._text(github._mapping(item).get("filename"), maximum=1024) for item in files]
    outside = sorted(set(filenames) - set(request["allowed_paths"]))
    check_rows = [{
        "name": github._text(github._mapping(item).get("name"), maximum=255),
        "status": github._text(github._mapping(item).get("status"), maximum=64),
        "conclusion": github._optional_text(github._mapping(item).get("conclusion"), maximum=64),
    } for item in checks["check_runs"]]
    review_states = [github._text(github._mapping(item).get("state"), maximum=64) for item in reviews]
    reasons = []
    if pull["state"].lower() != "open" or pull["draft"]:
        reasons.append("pull_request_not_open_and_ready")
    if pull["base_ref_name"] != request["base"] or pull["head_ref_name"] != request["head"]:
        reasons.append("pull_request_binding_changed")
    if outside:
        reasons.append("diff_scope_violation")
    if any(row["status"] != "completed" or row["conclusion"] not in {"success", "neutral", "skipped"} for row in check_rows):
        reasons.append("checks_not_green")
    if "CHANGES_REQUESTED" in review_states:
        reasons.append("review_changes_requested")
    return {
        "decision": "repair" if reasons else "ready_for_audit",
        "reasons": reasons,
        "pull_request": dict(pull),
        "changed_paths": filenames,
        "outside_allowed_paths": outside,
        "checks": check_rows,
        "review_states": review_states,
    }


def _state(request: Mapping[str, Any], status: str, pull: Mapping[str, Any] | None = None, head_sha: str | None = None) -> dict[str, Any]:
    binding = {key: request[key] for key in (
        "allowed_paths", "base", "expected_base_sha", "head", "issue_number", "lifecycle_id", "worktree",
    )}
    binding["target"] = dict(request["target"])
    binding["lease"] = {key: request["lease"][key] for key in ("board_sha256", "claim_id", "fencing_token")}
    return {"schema_version": 1, "artifact_type": STATE_TYPE, "status": status, "binding": binding, "head_sha": head_sha, "pull_request": dict(pull) if pull else None}


def _load_state(path: Path, request: Mapping[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(live.adapter._read_regular_bytes(path, label="pr_state").decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, live.adapter.AdapterError) as exc:
        raise LifecycleError("state_invalid") from exc
    expected = _state(request, "unknown")["binding"]
    if (
        not isinstance(value, dict) or set(value) != {"artifact_type", "binding", "head_sha", "pull_request", "schema_version", "status"}
        or value["schema_version"] != 1 or value["artifact_type"] != STATE_TYPE
        or value["status"] not in {"push_started", "pr_create_started", "unknown", "bound"}
        or value["binding"] != expected
        or not isinstance(value["head_sha"], str) or SHA_RE.fullmatch(value["head_sha"]) is None
    ):
        raise LifecycleError("state_invalid")
    return value


def execute(request_value: Any, state_path: Path, *, runner=github._run_command, gh_resolver=github._resolve_gh, git_resolver=_resolve_git, environment_source=None, now=None) -> dict[str, Any]:
    command_count = 0
    mutation_attempted = False
    try:
        request = _request(request_value)
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            raise LifecycleError("current_time_invalid")
        _active_lease(request, current_time.astimezone(timezone.utc))
        if not state_path.is_absolute() or not state_path.parent.is_dir() or state_path.parent.is_symlink():
            raise LifecycleError("state_path_invalid")
        prior = _load_state(state_path, request)
        environment = github._environment(os.environ if environment_source is None else environment_source)

        def counted(argv, env):
            nonlocal command_count
            command_count += 1
            return runner(argv, env)

        gh = gh_resolver()
        facts = live._identity(gh, environment, request["target"]["host"], request["target"]["repository"], counted)
        if facts["username"] != request["expected_user"]:
            raise LifecycleError("identity_mismatch")
        if facts["permission"] not in live.ALLOWED_PERMISSIONS:
            raise LifecycleError("repository_write_permission_required")
        pulls = _pulls(request, gh, counted, environment)
        if request["mode"] == "observe":
            if len(pulls) != 1:
                raise LifecycleError("pull_request_missing")
            _require_head(pulls[0], request["expected_head_sha"])
            observation = _observe(request, pulls[0], gh, counted, environment)
            return _receipt(request, observation, facts, command_count, False)
        if pulls:
            known_head = prior["head_sha"] if prior else request["expected_head_sha"]
            _require_head(pulls[0], known_head)
        if pulls and (request["mode"] == "publish" or (prior and prior["status"] == "push_started")):
            live._write_state(state_path, _state(request, "bound", pulls[0], known_head), initial=prior is None)
            observation = _observe(request, pulls[0], gh, counted, environment)
            return _receipt(request, observation, facts, command_count, False)
        if prior is not None and not pulls and prior["status"] != "push_started":
            return _unknown("prior_pr_effect_requires_reconciliation", command_count)

        git = git_resolver()
        prefix = (git, "-C", request["worktree"])
        root = _invoke((*prefix, "rev-parse", "--show-toplevel"), counted, environment).decode().strip()
        if str(Path(root).resolve()) != request["worktree"]:
            raise LifecycleError("worktree_binding_mismatch")
        remote_url = _invoke((*prefix, "remote", "get-url", request["remote"]), counted, environment).decode().strip()
        if not _remote_matches(remote_url, request["target"]["host"], request["target"]["repository"]):
            raise LifecycleError("remote_binding_mismatch")
        if prior is not None and prior["status"] == "push_started":
            remote = _invoke((*prefix, "ls-remote", "--heads", request["remote"], f"refs/heads/{request['head']}"), counted, environment).decode().strip().split()
            if len(remote) != 2 or remote != [prior["head_sha"], f"refs/heads/{request['head']}"]:
                return _unknown("push_outcome_requires_reconciliation", command_count)
            pull = _create_after_reconciled_push(request, state_path, prior["head_sha"], gh, counted, environment)
            if pull is None:
                return _unknown("pr_create_outcome_unknown", command_count)
            observation = _observe(request, pull, gh, counted, environment)
            return _receipt(request, observation, facts, command_count, True)
        base_sha = _invoke((*prefix, "rev-parse", f"refs/heads/{request['base']}"), counted, environment).decode().strip()
        if base_sha != request["expected_base_sha"]:
            raise LifecycleError("base_sha_mismatch")
        branch = _invoke((*prefix, "branch", "--show-current"), counted, environment).decode().strip()
        if branch == request["base"]:
            _invoke((*prefix, "switch", "-c", request["head"]), counted, environment)
        elif branch != request["head"]:
            raise LifecycleError("branch_binding_mismatch")
        ancestor = _invoke((*prefix, "merge-base", request["expected_base_sha"], "HEAD"), counted, environment).decode().strip()
        if ancestor != request["expected_base_sha"]:
            raise LifecycleError("base_ancestry_mismatch")
        changed = set(_lines(_invoke((*prefix, "diff", "--name-only", "-z", "HEAD", "--"), counted, environment)))
        changed.update(_lines(_invoke((*prefix, "ls-files", "--others", "--exclude-standard", "-z", "--"), counted, environment)))
        if not changed:
            raise LifecycleError("no_changes")
        if changed - set(request["allowed_paths"]):
            raise LifecycleError("local_scope_violation")
        _invoke((*prefix, "add", "--", *request["allowed_paths"]), counted, environment)
        staged = set(_lines(_invoke((*prefix, "diff", "--cached", "--name-only", "-z", "HEAD", "--"), counted, environment)))
        if not staged or staged - set(request["allowed_paths"]):
            raise LifecycleError("staged_scope_violation")
        _invoke((*prefix, "commit", "-m", request["commit"]["message"]), counted, environment)
        head_sha = _invoke((*prefix, "rev-parse", "HEAD"), counted, environment).decode().strip()
        if SHA_RE.fullmatch(head_sha) is None:
            raise LifecycleError("head_sha_invalid")
        live._write_state(state_path, _state(request, "push_started", head_sha=head_sha), initial=prior is None)
        mutation_attempted = True
        try:
            _invoke((*prefix, "push", request["remote"], f"HEAD:refs/heads/{request['head']}"), counted, environment)
        except LifecycleError:
            return _unknown("push_outcome_unknown", command_count)
        pulls = _pulls(request, gh, counted, environment)
        if not pulls:
            live._write_state(state_path, _state(request, "pr_create_started", head_sha=head_sha), initial=False)
            mutation_attempted = True
            try:
                pull = _create_pr(request, gh, counted, environment)
                _require_head(pull, head_sha)
                live._write_state(state_path, _state(request, "bound", pull, head_sha), initial=False)
            except Exception:
                try:
                    live._write_state(state_path, _state(request, "unknown", head_sha=head_sha), initial=False)
                except Exception:
                    pass
                return _unknown("pr_create_outcome_unknown", command_count)
        else:
            pull = pulls[0]
            _require_head(pull, head_sha)
            live._write_state(state_path, _state(request, "bound", pull, head_sha), initial=False)
        observation = _observe(request, pull, gh, counted, environment)
        return _receipt(request, observation, facts, command_count, mutation_attempted)
    except (LifecycleError, github.GithubReadError, dependencies.DependencyError) as exc:
        code = exc.code if hasattr(exc, "code") else "lifecycle_error"
        if mutation_attempted:
            return _unknown(code, command_count)
        return {"schema_version": 1, "artifact_type": RECEIPT_TYPE, "status": "error", "error": {"code": code}, "command_count": command_count, "mutation_attempted": mutation_attempted, "reconcile_required": False, "effect_boundary": _boundary(command_count, False)}
    except Exception:
        if mutation_attempted:
            return _unknown("pr_lifecycle_internal_error", command_count)
        return {"schema_version": 1, "artifact_type": RECEIPT_TYPE, "status": "error", "error": {"code": "pr_lifecycle_internal_error"}, "command_count": command_count, "mutation_attempted": mutation_attempted, "reconcile_required": False, "effect_boundary": _boundary(command_count, False)}


def _create_after_reconciled_push(request, state_path, head_sha, executable, runner, environment):
    live._write_state(state_path, _state(request, "pr_create_started", head_sha=head_sha), initial=False)
    try:
        pull = _create_pr(request, executable, runner, environment)
        _require_head(pull, head_sha)
        live._write_state(state_path, _state(request, "bound", pull, head_sha), initial=False)
        return pull
    except Exception:
        try:
            live._write_state(state_path, _state(request, "unknown", head_sha=head_sha), initial=False)
        except Exception:
            pass
        return None


def _boundary(command_count: int, github_mutated: bool | str) -> dict[str, Any]:
    return {"acceptance_granted": False, "credentials_read_by_orcastrata": False, "github_called": command_count > 0, "github_mutated": github_mutated, "merge_available": False, "merged": False}


def _receipt(request: Mapping[str, Any], observation: Mapping[str, Any], facts: Mapping[str, str], command_count: int, mutated: bool) -> dict[str, Any]:
    return {"schema_version": 1, "artifact_type": RECEIPT_TYPE, "status": observation["decision"], "target": dict(request["target"]), "issue_number": request["issue_number"], "verified_identity": dict(facts), "observation": dict(observation), "command_count": command_count, "mutation_attempted": mutated, "reconcile_required": False, "effect_boundary": _boundary(command_count, mutated)}


def _unknown(code: str, command_count: int) -> dict[str, Any]:
    return {"schema_version": 1, "artifact_type": RECEIPT_TYPE, "status": "unknown", "error": {"code": code}, "command_count": command_count, "mutation_attempted": True, "reconcile_required": True, "effect_boundary": _boundary(command_count, "unknown")}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        request = json.loads(args.request.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        request = None
    receipt = execute(request, args.state)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"] in {"ready_for_audit", "repair"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
