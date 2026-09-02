#!/usr/bin/env python3
"""Credential-blind, read-only GitHub access through the local gh CLI."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Sequence


REQUEST_TYPE = "orcastrata_github_read_request_v1"
RECEIPT_TYPE = "orcastrata_github_read_receipt_v1"
OPERATIONS = (
    "listIssues",
    "listPullRequestChecks",
    "listPullRequestReviews",
    "probeCapability",
    "readIssue",
    "readPullRequest",
    "readPullRequestDiffSummary",
    "readRepository",
)
ARGUMENT_FIELDS = {
    "probeCapability": {"host", "repository"},
    "readRepository": {"host", "repository"},
    "listIssues": {"host", "repository", "limit"},
    "readIssue": {"host", "repository", "number"},
    "readPullRequest": {"host", "repository", "number"},
    "listPullRequestChecks": {"host", "repository", "number"},
    "listPullRequestReviews": {"host", "repository", "number"},
    "readPullRequestDiffSummary": {"host", "repository", "number"},
}
HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
SECRET_RE = re.compile(
    r"(?i)(?:authorization\s*:|bearer\s+[A-Za-z0-9._~+/-]+=*|"
    r"github_pat_[A-Za-z0-9_]+|gh[opusr]_[A-Za-z0-9]+)"
)
MAX_INPUT_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 512 * 1024
MAX_STDERR_BYTES = 64 * 1024
TIMEOUT_SECONDS = 20.0
MAX_ITEMS = 100
DIFF_SUMMARY_JQ = (
    ".[] | {filename, status, additions, deletions, changes}"
)
REVIEW_SUMMARY_JQ = (
    ".[] | {state, commit_id, reviewer: .user.login, submitted_at}"
)
MARKER_RE = re.compile(
    r"<!-- (orcastrata:(?:umbrella|issue):v1:[0-9a-f]{20}) -->"
)
TOKEN_OVERRIDES = {
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GH_HOST",
    "GH_REPO",
}
ENV_ALLOWLIST = {
    "HOME",
    "XDG_CONFIG_HOME",
    "GH_CONFIG_DIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
}
READ_ONLY_EFFECTS = {
    "acceptance_granted": False,
    "authority_granted": False,
    "credentials_read_by_orcastrata": False,
    "github_mutated": False,
    "local_state_mutated": False,
}


class GithubReadError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GithubReadError("json_duplicate_key")
        value[key] = item
    return value


def _loads(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except GithubReadError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubReadError("json_invalid") from exc


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GithubReadError("request_shape_invalid", path)
    return value


def _target(arguments: Mapping[str, Any]) -> tuple[str, str, str, str]:
    host = arguments.get("host")
    repository = arguments.get("repository")
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise GithubReadError("host_invalid", "$.arguments.host")
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise GithubReadError("repository_invalid", "$.arguments.repository")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise GithubReadError("repository_invalid", "$.arguments.repository")
    return host, repository, owner, name


def _positive_integer(value: Any, path: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise GithubReadError("integer_invalid", path)
    return value


def _request(value: Any) -> tuple[str, dict[str, Any], str, str, str, str]:
    request = _closed(
        value,
        {"schema_version", "artifact_type", "operation", "arguments"},
        "$",
    )
    if request["schema_version"] != 1 or request["artifact_type"] != REQUEST_TYPE:
        raise GithubReadError("request_identity_invalid")
    operation = request["operation"]
    if operation not in ARGUMENT_FIELDS:
        raise GithubReadError("operation_unsupported", "$.operation")
    arguments = _closed(
        request["arguments"], ARGUMENT_FIELDS[operation], "$.arguments"
    )
    host, repository, owner, name = _target(arguments)
    if "number" in arguments:
        _positive_integer(arguments["number"], "$.arguments.number", 2_147_483_647)
    if "limit" in arguments:
        _positive_integer(arguments["limit"], "$.arguments.limit", MAX_ITEMS)
    return operation, arguments, host, repository, owner, name


def _resolve_gh() -> str:
    candidate = shutil.which("gh")
    if candidate is None:
        raise GithubReadError("gh_unavailable")
    try:
        resolved = Path(candidate).resolve(strict=True)
        named = resolved.stat()
    except OSError as exc:
        raise GithubReadError("gh_unavailable") from exc
    if not stat.S_ISREG(named.st_mode) or not os.access(resolved, os.X_OK):
        raise GithubReadError("gh_unavailable")
    return str(resolved)


def _environment(source: Mapping[str, str] = os.environ) -> dict[str, str]:
    environment = {
        key: value for key, value in source.items()
        if key in ENV_ALLOWLIST and key not in TOKEN_OVERRIDES
    }
    environment.update({"GH_PROMPT_DISABLED": "1", "NO_COLOR": "1", "PAGER": "cat"})
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=0.5)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=0.5)


def _run_command(argv: Sequence[str], environment: Mapping[str, str]) -> dict[str, Any]:
    process = subprocess.Popen(
        list(argv),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", MAX_STDOUT_BYTES))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", MAX_STDERR_BYTES))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded: str | None = None
    timed_out = False
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process)
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ) for key in selector.get_map().values()
                ]
            for key, _ in events:
                stream, limit = key.data
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max(0, limit - len(buffers[stream]))
                buffers[stream].extend(chunk[:room])
                if len(chunk) > room:
                    exceeded = stream
                    _terminate(process)
                    break
            if exceeded is not None:
                break
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate(process)
    finally:
        selector.close()
        if process.poll() is None:
            _terminate(process)
        process.stdout.close()
        process.stderr.close()
    return {
        "returncode": process.returncode,
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "timed_out": timed_out,
        "exceeded": exceeded,
    }


Runner = Callable[[Sequence[str], Mapping[str, str]], Mapping[str, Any]]


def _invoke(
    argv: Sequence[str], runner: Runner, environment: Mapping[str, str]
) -> bytes:
    try:
        result = runner(tuple(argv), environment)
    except GithubReadError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise GithubReadError("gh_execution_failed") from exc
    if not isinstance(result, Mapping):
        raise GithubReadError("runner_receipt_invalid")
    if result.get("timed_out") is True:
        raise GithubReadError("gh_timeout")
    if result.get("exceeded") in {"stdout", "stderr"}:
        raise GithubReadError("gh_output_limit_exceeded")
    returncode = result.get("returncode")
    stdout = result.get("stdout")
    if type(returncode) is not int or not isinstance(stdout, bytes):
        raise GithubReadError("runner_receipt_invalid")
    if returncode != 0:
        raise GithubReadError("gh_command_failed")
    return stdout


def _json_output(raw: bytes) -> Any:
    if len(raw) > MAX_STDOUT_BYTES:
        raise GithubReadError("gh_output_limit_exceeded")
    try:
        return _loads(raw)
    except GithubReadError as exc:
        raise GithubReadError("gh_response_invalid") from exc


def _json_lines(raw: bytes) -> list[Any]:
    if len(raw) > MAX_STDOUT_BYTES:
        raise GithubReadError("gh_output_limit_exceeded")
    if not raw:
        return []
    lines = raw.splitlines()
    if any(not line for line in lines):
        raise GithubReadError("gh_response_invalid")
    try:
        return [_loads(line) for line in lines]
    except GithubReadError as exc:
        raise GithubReadError("gh_response_invalid") from exc


def _text(value: Any, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GithubReadError("gh_response_invalid")
    return SECRET_RE.sub("[redacted]", value)


def _optional_text(value: Any, *, maximum: int = 512) -> str | None:
    return None if value is None else _text(value, maximum=maximum)


def _integer(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise GithubReadError("gh_response_invalid")
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GithubReadError("gh_response_invalid")
    return value


def _repository(value: Any) -> dict[str, Any]:
    item = _mapping(value)
    permissions = item.get("permissions")
    permission = "unknown"
    if isinstance(permissions, Mapping):
        for key, label in (("admin", "ADMIN"), ("push", "WRITE"), ("pull", "READ")):
            if permissions.get(key) is True:
                permission = label
                break
    return {
        "default_branch": _optional_text(item.get("default_branch"), maximum=255),
        "name_with_owner": _text(item.get("full_name"), maximum=201),
        "viewer_permission": permission,
    }


def _issue(value: Any) -> dict[str, Any]:
    item = _mapping(value)
    labels = item.get("labels", [])
    assignees = item.get("assignees", [])
    body = item.get("body")
    if body is None:
        body = ""
    if not isinstance(labels, list) or not isinstance(assignees, list) or not isinstance(body, str):
        raise GithubReadError("gh_response_invalid")
    markers = MARKER_RE.findall(body)
    if "<!-- orcastrata:" in MARKER_RE.sub("", body) or len(markers) != len(set(markers)):
        raise GithubReadError("github_marker_invalid")
    return {
        "assignees": [
            _text(_mapping(entry).get("login"), maximum=100) for entry in assignees[:MAX_ITEMS]
        ],
        "closed_at": _optional_text(item.get("closed_at"), maximum=64),
        "labels": [
            _text(_mapping(entry).get("name"), maximum=100) for entry in labels[:MAX_ITEMS]
        ],
        "orcastrata_markers": markers,
        "number": _integer(item.get("number")),
        "state": _text(item.get("state"), maximum=32),
        "title": _text(item.get("title"), maximum=1024),
        "updated_at": _text(item.get("updated_at"), maximum=64),
    }


def _pull_request(value: Any) -> dict[str, Any]:
    item = _mapping(value)
    head = _mapping(item.get("head"))
    base = _mapping(item.get("base"))
    return {
        "base_ref_name": _text(base.get("ref"), maximum=255),
        "base_ref_oid": _text(base.get("sha"), maximum=64),
        "draft": item.get("draft") is True,
        "head_ref_name": _text(head.get("ref"), maximum=255),
        "head_ref_oid": _text(head.get("sha"), maximum=64),
        "mergeable": item.get("mergeable") if type(item.get("mergeable")) is bool else None,
        "mergeable_state": _optional_text(item.get("mergeable_state"), maximum=64),
        "number": _integer(item.get("number")),
        "state": _text(item.get("state"), maximum=32),
        "title": _text(item.get("title"), maximum=1024),
        "updated_at": _text(item.get("updated_at"), maximum=64),
    }


def _api(executable: str, host: str, endpoint: str, *fields: tuple[str, Any]) -> list[str]:
    argv = [executable, "api", "--hostname", host, "--method", "GET", endpoint]
    for key, value in fields:
        argv.extend(("-f", f"{key}={value}"))
    return argv


def _diff_summary_argv(executable: str, host: str, endpoint: str) -> list[str]:
    return [
        executable, "api", "--hostname", host, "--method", "GET",
        "--paginate", "--jq", DIFF_SUMMARY_JQ, endpoint,
        "-f", f"per_page={MAX_ITEMS}",
    ]


def _review_summary_argv(executable: str, host: str, endpoint: str) -> list[str]:
    return [
        executable, "api", "--hostname", host, "--method", "GET",
        "--paginate", "--jq", REVIEW_SUMMARY_JQ, endpoint,
        "-f", f"per_page={MAX_ITEMS}",
    ]


def _review(value: Any) -> dict[str, Any]:
    item = _mapping(value)
    if set(item) != {"commit_id", "reviewer", "state", "submitted_at"}:
        raise GithubReadError("gh_response_invalid")
    commit_sha = item["commit_id"]
    if not isinstance(commit_sha, str) or not SHA_RE.fullmatch(commit_sha):
        raise GithubReadError("gh_response_invalid")
    return {
        "commit_sha": commit_sha,
        "reviewer": _text(item["reviewer"], maximum=100),
        "state": _text(item["state"], maximum=64),
        "submitted_at": _text(item["submitted_at"], maximum=64),
    }


def _operate(
    operation: str,
    arguments: Mapping[str, Any],
    host: str,
    owner: str,
    name: str,
    executable: str,
    runner: Runner,
    environment: Mapping[str, str],
) -> tuple[Any, int]:
    repository_endpoint = f"repos/{owner}/{name}"
    if operation == "probeCapability":
        _invoke((executable, "auth", "status", "--active", "--hostname", host), runner, environment)
        data = _repository(_json_output(_invoke(
            _api(executable, host, repository_endpoint), runner, environment
        )))
        return {"authenticated": True, "available": True, "operations": list(OPERATIONS), "repository": data}, 2
    if operation == "readRepository":
        data = _repository(_json_output(_invoke(
            _api(executable, host, repository_endpoint), runner, environment
        )))
        return data, 1
    if operation == "listIssues":
        raw = _json_output(_invoke(_api(
            executable, host, repository_endpoint + "/issues",
            ("state", "all"), ("per_page", arguments["limit"]), ("page", 1),
        ), runner, environment))
        if not isinstance(raw, list):
            raise GithubReadError("gh_response_invalid")
        issues = [_issue(item) for item in raw if isinstance(item, Mapping) and "pull_request" not in item]
        return {
            "items": issues[: arguments["limit"]],
            "limit": arguments["limit"],
            "possibly_more": len(raw) >= arguments["limit"],
        }, 1
    if operation == "readIssue":
        raw = _json_output(_invoke(_api(
            executable, host, f"{repository_endpoint}/issues/{arguments['number']}"
        ), runner, environment))
        if isinstance(raw, Mapping) and "pull_request" in raw:
            raise GithubReadError("github_item_is_pull_request")
        return _issue(raw), 1
    if operation == "readPullRequest":
        raw = _json_output(_invoke(_api(
            executable, host, f"{repository_endpoint}/pulls/{arguments['number']}"
        ), runner, environment))
        return _pull_request(raw), 1
    if operation == "listPullRequestChecks":
        pull = _mapping(_json_output(_invoke(_api(
            executable, host, f"{repository_endpoint}/pulls/{arguments['number']}"
        ), runner, environment)))
        sha = _mapping(pull.get("head")).get("sha")
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            raise GithubReadError("gh_response_invalid")
        raw = _mapping(_json_output(_invoke(_api(
            executable, host, f"{repository_endpoint}/commits/{sha}/check-runs",
            ("per_page", MAX_ITEMS), ("page", 1),
        ), runner, environment)))
        checks = raw.get("check_runs")
        if not isinstance(checks, list):
            raise GithubReadError("gh_response_invalid")
        items = [{
            "app": _optional_text(_mapping(item).get("app", {}).get("name") if isinstance(_mapping(item).get("app"), Mapping) else None, maximum=100),
            "conclusion": _optional_text(_mapping(item).get("conclusion"), maximum=64),
            "name": _text(_mapping(item).get("name"), maximum=255),
            "status": _text(_mapping(item).get("status"), maximum=64),
        } for item in checks[:MAX_ITEMS]]
        total = raw.get("total_count")
        if type(total) is not int or total < len(items):
            raise GithubReadError("gh_response_invalid")
        return {
            "items": items,
            "limit": MAX_ITEMS,
            "possibly_more": total > len(items),
        }, 2
    if operation == "listPullRequestReviews":
        raw = _json_lines(_invoke(_review_summary_argv(
            executable, host,
            f"{repository_endpoint}/pulls/{arguments['number']}/reviews",
        ), runner, environment))
        items = [_review(value) for value in raw]
        return {
            "items": items[:MAX_ITEMS],
            "limit": MAX_ITEMS,
            "possibly_more": len(items) > MAX_ITEMS,
            "total_count": len(items),
        }, 1
    if operation == "readPullRequestDiffSummary":
        raw = _json_lines(_invoke(_diff_summary_argv(
            executable, host, f"{repository_endpoint}/pulls/{arguments['number']}/files",
        ), runner, environment))
        items = []
        filenames = []
        for value in raw:
            item = _mapping(value)
            if set(item) != {"additions", "changes", "deletions", "filename", "status"}:
                raise GithubReadError("gh_response_invalid")
            normalized = {
                "additions": _integer(item["additions"]),
                "changes": _integer(item["changes"]),
                "deletions": _integer(item["deletions"]),
                "filename": _text(item["filename"], maximum=1024),
                "status": _text(item["status"], maximum=32),
            }
            filenames.append(normalized["filename"])
            if len(items) < MAX_ITEMS:
                items.append(normalized)
        if len(filenames) != len(set(filenames)):
            raise GithubReadError("github_diff_filename_duplicate")
        filenames_sha256 = "sha256:" + hashlib.sha256(json.dumps(
            sorted(filenames), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        return {
            "filenames_sha256": filenames_sha256,
            "items": items,
            "limit": MAX_ITEMS,
            "possibly_more": len(filenames) > MAX_ITEMS,
            "total_count": len(filenames),
        }, 1
    raise GithubReadError("operation_unsupported")


def execute(
    request: Any,
    *,
    runner: Runner = _run_command,
    resolver: Callable[[], str] = _resolve_gh,
    environment_source: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    operation = request.get("operation", "unknown") if isinstance(request, dict) else "unknown"
    target: dict[str, str] | None = None
    try:
        operation, arguments, host, repository, owner, name = _request(request)
        target = {"host": host, "repository": repository}
        data, command_count = _operate(
            operation, arguments, host, owner, name, resolver(), runner,
            _environment(environment_source),
        )
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "operation": operation,
            "status": "ok",
            "target": target,
            "data": data,
            "command_count": command_count,
            "effect_boundary": dict(READ_ONLY_EFFECTS),
        }
    except GithubReadError as error:
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "operation": operation if operation in OPERATIONS else "unknown",
            "status": "error",
            "target": target,
            "error": {"code": error.code, "path": error.path},
            "effect_boundary": dict(READ_ONLY_EFFECTS),
        }


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        receipt = execute(None)
        receipt["error"] = {"code": "request_too_large", "path": "$"}
    else:
        try:
            request = _loads(raw)
        except GithubReadError:
            request = None
        receipt = execute(request)
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if receipt["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
