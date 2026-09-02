#!/usr/bin/env python3
"""Prepare and simulate idempotent GitHub issue effects without live execution."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from typing import Any, Callable, Mapping, Sequence


REQUEST_TYPE = "orcastrata_github_issue_effect_request_v1"
RECEIPT_TYPE = "orcastrata_github_issue_effect_receipt_v1"
PROJECTION_TYPE = "orcastrata_github_umbrella_projection_receipt_v1"
FAKE_EXECUTABLE = "<fake-gh>"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_BODY_BYTES = 65_536
MARKER_RE = re.compile(r"orcastrata:(?:umbrella|issue):v1:[0-9a-f]{20}\Z")
HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SIMULATION_BOUNDARY = {
    "acceptance_granted": False,
    "authority_granted": False,
    "credentials_read_by_orcastrata": False,
    "github_called": False,
    "github_mutated": False,
    "live_execution_available": False,
    "simulation_only": True,
}


class IssueEffectError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise IssueEffectError("json_duplicate_key")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IssueEffectError("canonical_json_invalid") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise IssueEffectError("shape_invalid", path)
    return value


def _text(value: Any, path: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 and character not in "\n\t" for character in value)
        or "\r" in value
        or "\x7f" in value
    ):
        raise IssueEffectError("text_invalid", path)
    return value


def _target(value: Any, path: str) -> dict[str, str]:
    target = _closed(value, {"host", "repository"}, path)
    host = target["host"]
    repository = target["repository"]
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise IssueEffectError("host_invalid", path + ".host")
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise IssueEffectError("repository_invalid", path + ".repository")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise IssueEffectError("repository_invalid", path + ".repository")
    return {"host": host, "repository": repository}


def _projection(value: Any) -> dict[str, Any]:
    receipt = _closed(
        value,
        {
            "artifact_type", "canonical_state", "effect_boundary", "graph_id",
            "graph_sha256", "preview", "projection_sha256", "schema_version",
            "status", "target",
        },
        "$.projection",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["artifact_type"] != PROJECTION_TYPE
        or receipt["status"] != "ok"
        or not isinstance(receipt["effect_boundary"], dict)
        or not receipt["effect_boundary"]
        or any(value is not False for value in receipt["effect_boundary"].values())
        or not isinstance(receipt["projection_sha256"], str)
        or not SHA_RE.fullmatch(receipt["projection_sha256"])
        or receipt["projection_sha256"] != _digest(receipt["preview"])
    ):
        raise IssueEffectError("projection_invalid", "$.projection")
    _target(receipt["target"], "$.projection.target")
    canonical = _closed(
        receipt["canonical_state"], {"active_task", "board_sha256", "owner"},
        "$.projection.canonical_state",
    )
    if (
        canonical["owner"] != "GoalBuddy"
        or not isinstance(canonical["board_sha256"], str)
        or not SHA_RE.fullmatch(canonical["board_sha256"])
    ):
        raise IssueEffectError("projection_invalid", "$.projection.canonical_state")
    return copy.deepcopy(receipt)


def _labels(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 100:
        raise IssueEffectError("labels_invalid", path)
    labels = [_text(item, f"{path}[{index}]", 100) for index, item in enumerate(value)]
    if len(labels) != len(set(labels)):
        raise IssueEffectError("labels_invalid", path)
    return labels


def _packet(projection: Mapping[str, Any], stable_id: Any) -> dict[str, Any]:
    stable_id = _text(stable_id, "$.stable_id", 96)
    if not MARKER_RE.fullmatch(stable_id):
        raise IssueEffectError("stable_id_invalid", "$.stable_id")
    preview = _closed(projection["preview"], {"issues", "umbrella"}, "$.projection.preview")
    umbrella = preview["umbrella"]
    issues = preview["issues"]
    if not isinstance(umbrella, dict) or not isinstance(issues, list):
        raise IssueEffectError("projection_invalid", "$.projection.preview")
    matches = [
        ("umbrella", None, umbrella)
        if umbrella.get("stable_id") == stable_id else None
    ] + [
        ("issue", item.get("work_item_id"), item)
        for item in issues if isinstance(item, dict) and item.get("stable_id") == stable_id
    ]
    matches = [match for match in matches if match is not None]
    if len(matches) != 1:
        raise IssueEffectError("stable_id_not_unique", "$.stable_id")
    kind, work_item_id, item = matches[0]
    graph_id = _text(projection["graph_id"], "$.projection.graph_id", 256)
    identity = _digest({
        "graph_id": graph_id,
        "host": projection["target"]["host"],
        "item_id": work_item_id or "umbrella",
        "kind": kind,
        "repository": projection["target"]["repository"].lower(),
    })[7:27]
    if stable_id != f"orcastrata:{kind}:v1:{identity}":
        raise IssueEffectError("stable_id_target_mismatch", "$.stable_id")
    marker = f"<!-- {stable_id} -->"
    body = _text(item.get("body"), "$.projection.preview.body", MAX_BODY_BYTES)
    if body.count(marker) != 1:
        raise IssueEffectError("marker_invalid", "$.projection.preview.body")
    title = _text(item.get("title"), "$.projection.preview.title", 256)
    labels = _labels(item.get("labels"), "$.projection.preview.labels")
    prepared = {
        "board_sha256": projection["canonical_state"]["board_sha256"],
        "body": body,
        "graph_id": graph_id,
        "item_kind": kind,
        "labels": labels,
        "projection_sha256": projection["projection_sha256"],
        "stable_id": stable_id,
        "target": dict(projection["target"]),
        "title": title,
        "work_item_id": work_item_id,
    }
    prepared["payload_sha256"] = _digest({
        "body": body,
        "labels": labels,
        "title": title,
    })
    prepared["effect_id"] = _digest({
        "board_sha256": prepared["board_sha256"],
        "graph_id": prepared["graph_id"],
        "payload_sha256": prepared["payload_sha256"],
        "projection_sha256": prepared["projection_sha256"],
        "stable_id": stable_id,
        "target": prepared["target"],
    })
    return prepared


def _prepare_receipt(value: Any) -> dict[str, Any]:
    receipt = _closed(
        value,
        {
            "artifact_type", "command_count", "effect_boundary", "operation",
            "prepare_sha256", "prepared", "schema_version", "status",
        },
        "$.prepare",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["artifact_type"] != RECEIPT_TYPE
        or receipt["operation"] != "prepare"
        or receipt["status"] != "prepared"
        or receipt["command_count"] != 0
        or receipt["effect_boundary"] != SIMULATION_BOUNDARY
        or receipt["prepare_sha256"] != _digest(receipt["prepared"])
    ):
        raise IssueEffectError("prepare_invalid", "$.prepare")
    prepared = _closed(
        receipt["prepared"],
        {
            "board_sha256", "body", "effect_id", "graph_id", "item_kind", "labels",
            "payload_sha256", "projection_sha256", "stable_id", "target", "title",
            "work_item_id",
        },
        "$.prepare.prepared",
    )
    _target(prepared["target"], "$.prepare.prepared.target")
    if (
        not isinstance(prepared["board_sha256"], str)
        or not SHA_RE.fullmatch(prepared["board_sha256"])
        or not isinstance(prepared["projection_sha256"], str)
        or not SHA_RE.fullmatch(prepared["projection_sha256"])
        or not isinstance(prepared["effect_id"], str)
        or not SHA_RE.fullmatch(prepared["effect_id"])
        or not isinstance(prepared["payload_sha256"], str)
        or not SHA_RE.fullmatch(prepared["payload_sha256"])
        or prepared["item_kind"] not in {"umbrella", "issue"}
        or (prepared["item_kind"] == "umbrella") != (prepared["work_item_id"] is None)
        or not isinstance(prepared["stable_id"], str)
        or not MARKER_RE.fullmatch(prepared["stable_id"])
    ):
        raise IssueEffectError("prepare_invalid", "$.prepare.prepared")
    if prepared["item_kind"] == "issue":
        _text(prepared["work_item_id"], "$.prepare.prepared.work_item_id", 256)
    _text(prepared["body"], "$.prepare.prepared.body", MAX_BODY_BYTES)
    _text(prepared["title"], "$.prepare.prepared.title", 256)
    _labels(prepared["labels"], "$.prepare.prepared.labels")
    expected_payload_sha256 = _digest({
        "body": prepared["body"],
        "labels": prepared["labels"],
        "title": prepared["title"],
    })
    if prepared["payload_sha256"] != expected_payload_sha256:
        raise IssueEffectError("prepare_invalid", "$.prepare.prepared.payload_sha256")
    expected_effect_id = _digest({
        "board_sha256": prepared["board_sha256"],
        "graph_id": prepared["graph_id"],
        "payload_sha256": prepared["payload_sha256"],
        "projection_sha256": prepared["projection_sha256"],
        "stable_id": prepared["stable_id"],
        "target": prepared["target"],
    })
    if prepared["effect_id"] != expected_effect_id:
        raise IssueEffectError("prepare_invalid", "$.prepare.prepared.effect_id")
    graph_id = _text(prepared["graph_id"], "$.prepare.prepared.graph_id", 256)
    identity = _digest({
        "graph_id": graph_id,
        "host": prepared["target"]["host"],
        "item_id": prepared["work_item_id"] or "umbrella",
        "kind": prepared["item_kind"],
        "repository": prepared["target"]["repository"].lower(),
    })[7:27]
    if prepared["stable_id"] != f"orcastrata:{prepared['item_kind']}:v1:{identity}":
        raise IssueEffectError("prepare_invalid", "$.prepare.prepared.stable_id")
    return copy.deepcopy(prepared)


Runner = Callable[[Sequence[str]], Mapping[str, Any]]


def _invoke(argv: Sequence[str], runner: Runner, *, effect: bool) -> bytes:
    try:
        result = runner(tuple(argv))
    except Exception as exc:
        if effect:
            raise IssueEffectError("effect_outcome_unknown") from exc
        raise IssueEffectError("fake_gh_execution_failed") from exc
    if not isinstance(result, Mapping):
        raise IssueEffectError("effect_outcome_unknown" if effect else "fake_gh_receipt_invalid")
    if result.get("timed_out") is True or result.get("exceeded") in {"stdout", "stderr"}:
        raise IssueEffectError("effect_outcome_unknown" if effect else "fake_gh_failed")
    returncode = result.get("returncode")
    stdout = result.get("stdout")
    if type(returncode) is not int or not isinstance(stdout, bytes):
        raise IssueEffectError("effect_outcome_unknown" if effect else "fake_gh_receipt_invalid")
    if returncode != 0:
        raise IssueEffectError("effect_outcome_unknown" if effect else "fake_gh_failed")
    return stdout


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, IssueEffectError) as exc:
        raise IssueEffectError("fake_gh_response_invalid") from exc


def _issue(value: Any, prepared: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or "pull_request" in value:
        raise IssueEffectError("fake_gh_response_invalid")
    number = value.get("number")
    node_id = value.get("node_id")
    url = value.get("html_url")
    body = value.get("body")
    title = value.get("title")
    raw_labels = value.get("labels")
    marker = f"<!-- {prepared['stable_id']} -->"
    if (
        type(number) is not int or number < 1
        or not isinstance(node_id, str) or not node_id.strip() or len(node_id) > 256
        or not isinstance(url, str) or len(url) > 2048
        or not isinstance(body, str)
        or not isinstance(raw_labels, list)
    ):
        raise IssueEffectError("fake_gh_response_invalid")
    labels = []
    for item in raw_labels:
        if not isinstance(item, Mapping):
            raise IssueEffectError("fake_gh_response_invalid")
        labels.append(_text(item.get("name"), "$.fake_issue.labels", 100))
    if (
        body.count(marker) != 1
        or title != prepared["title"]
        or len(labels) != len(set(labels))
        or sorted(labels) != sorted(prepared["labels"])
    ):
        raise IssueEffectError("issue_payload_drift")
    expected = (
        f"https://{prepared['target']['host']}/"
        f"{prepared['target']['repository']}/issues/{number}"
    )
    if url.lower() != expected.lower():
        raise IssueEffectError("fake_gh_response_invalid")
    return {"node_id": node_id, "number": number, "url": url}


def _search_argv(prepared: Mapping[str, Any]) -> list[str]:
    query = (
        f"repo:{prepared['target']['repository']} in:body "
        f'"{prepared["stable_id"]}"'
    )
    return [
        FAKE_EXECUTABLE, "api", "--hostname", prepared["target"]["host"],
        "--method", "GET", "search/issues", "-f", f"q={query}",
        "-f", "per_page=2", "-f", "page=1",
    ]


def _create_argv(prepared: Mapping[str, Any]) -> list[str]:
    owner, name = prepared["target"]["repository"].split("/", 1)
    argv = [
        FAKE_EXECUTABLE, "api", "--hostname", prepared["target"]["host"],
        "--method", "POST", f"repos/{owner}/{name}/issues",
        "-f", f"title={prepared['title']}", "-f", f"body={prepared['body']}",
    ]
    for label in prepared["labels"]:
        argv.extend(("-f", f"labels[]={label}"))
    return argv


def _observe(prepared: Mapping[str, Any], runner: Runner) -> tuple[str, dict[str, Any] | None]:
    value = _json(_invoke(_search_argv(prepared), runner, effect=False))
    if not isinstance(value, Mapping):
        raise IssueEffectError("fake_gh_response_invalid")
    total = value.get("total_count")
    items = value.get("items")
    if type(total) is not int or total < 0 or not isinstance(items, list) or total != len(items):
        raise IssueEffectError("fake_gh_response_invalid")
    exact = []
    marker = f"<!-- {prepared['stable_id']} -->"
    for item in items:
        if isinstance(item, Mapping) and isinstance(item.get("body"), str) and item["body"].count(marker) == 1:
            exact.append(item)
    if total != len(exact):
        raise IssueEffectError("marker_search_drift")
    if len(exact) > 1:
        raise IssueEffectError("marker_ambiguous")
    return ("missing", None) if not exact else ("bound", _issue(exact[0], prepared))


def _request(value: Any) -> tuple[str, dict[str, Any]]:
    request = _closed(value, {"artifact_type", "operation", "schema_version", "value"}, "$")
    if request["schema_version"] != 1 or request["artifact_type"] != REQUEST_TYPE:
        raise IssueEffectError("request_identity_invalid")
    operation = request["operation"]
    if operation == "prepare":
        value = _closed(request["value"], {"projection", "stable_id"}, "$.value")
        return operation, {
            "projection": _projection(value["projection"]),
            "stable_id": value["stable_id"],
        }
    if operation == "simulateApply":
        value = _closed(request["value"], {"prepare"}, "$.value")
        return operation, {"prepared": _prepare_receipt(value["prepare"])}
    raise IssueEffectError("operation_unsupported", "$.operation")


def execute(request: Any, *, runner: Runner | None = None) -> dict[str, Any]:
    operation = request.get("operation", "unknown") if isinstance(request, dict) else "unknown"
    command_count = 0
    try:
        operation, value = _request(request)
        if operation == "prepare":
            prepared = _packet(value["projection"], value["stable_id"])
            return {
                "schema_version": 1,
                "artifact_type": RECEIPT_TYPE,
                "operation": operation,
                "status": "prepared",
                "prepared": prepared,
                "prepare_sha256": _digest(prepared),
                "command_count": 0,
                "effect_boundary": dict(SIMULATION_BOUNDARY),
            }
        if runner is None:
            raise IssueEffectError("simulation_runner_required")
        prepared = value["prepared"]
        command_count = 1
        observed, issue = _observe(prepared, runner)
        if observed == "bound":
            return {
                "schema_version": 1,
                "artifact_type": RECEIPT_TYPE,
                "operation": operation,
                "status": "bound",
                "outcome": "reconciled_existing",
                "effect_id": prepared["effect_id"],
                "issue": issue,
                "command_count": command_count,
                "reconcile_required": False,
                "effect_boundary": dict(SIMULATION_BOUNDARY),
            }
        command_count = 2
        raw = _invoke(_create_argv(prepared), runner, effect=True)
        try:
            issue = _issue(_json(raw), prepared)
        except IssueEffectError as exc:
            raise IssueEffectError("effect_outcome_unknown") from exc
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "operation": operation,
            "status": "bound",
            "outcome": "simulated_created",
            "effect_id": prepared["effect_id"],
            "issue": issue,
            "command_count": command_count,
            "reconcile_required": False,
            "effect_boundary": dict(SIMULATION_BOUNDARY),
        }
    except IssueEffectError as error:
        unknown = error.code == "effect_outcome_unknown"
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "operation": operation if operation in {"prepare", "simulateApply"} else "unknown",
            "status": "unknown" if unknown else "error",
            "error": {"code": error.code, "path": error.path},
            "command_count": command_count,
            "reconcile_required": unknown,
            "effect_boundary": dict(SIMULATION_BOUNDARY),
        }
    except Exception:
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "operation": operation if operation in {"prepare", "simulateApply"} else "unknown",
            "status": "error",
            "error": {"code": "issue_effect_internal_error", "path": "$"},
            "command_count": command_count,
            "reconcile_required": False,
            "effect_boundary": dict(SIMULATION_BOUNDARY),
        }


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        receipt = execute(None)
        receipt["error"] = {"code": "request_too_large", "path": "$"}
    else:
        try:
            request = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, IssueEffectError):
            request = None
        receipt = execute(request)
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if receipt["status"] in {"bound", "prepared"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
