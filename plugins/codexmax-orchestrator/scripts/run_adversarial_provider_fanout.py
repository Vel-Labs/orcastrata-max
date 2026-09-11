#!/usr/bin/env python3
"""Run one bounded task against an explicit set of exact model lanes.

This controller is deliberately a thin Parent-owned fan-out over the accepted
single-task runner.  It never selects a replacement model, retries a lane, or
performs synthesis.  A lane failure is recorded and does not prevent the next
explicit lane from running.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCRIPT = Path(__file__).resolve()


def _load_task_runner() -> Any:
    path = SCRIPT.with_name("run_task_scoped_provider_task.py")
    spec = importlib.util.spec_from_file_location("adversarial_task_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TASK = _load_task_runner()
MAX_LANES = 8
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _text(value: Any, field: str, limit: int = 65536) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > limit:
        raise ValueError(f"{field}_invalid")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise ValueError(f"{field}_invalid")
    return value


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _lane_id(index: int, request: str) -> str:
    suffix = hashlib.sha256(request.encode("utf-8")).hexdigest()[:12]
    return f"lane-{index:02d}-{suffix}"


def _public_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Keep aggregate receipts free of duplicated provider payloads."""
    allowed = (
        "configured", "selected", "called", "completed", "rejected", "reason",
        "binding_id", "task_grant_sha256", "usage", "task_local_binding",
    )
    public = {key: copy.deepcopy(result[key]) for key in allowed if key in result}
    manifest = result.get("manifest")
    if isinstance(manifest, Mapping):
        attempts = manifest.get("attempts") if isinstance(manifest.get("attempts"), list) else []
        public["dispatch"] = {
            "status": manifest.get("status"),
            "failure": copy.deepcopy(manifest.get("failure")),
            "selected_route": manifest.get("selected_route"),
            "artifact": {
                key: manifest.get("artifact", {}).get(key)
                for key in ("sha256", "bytes")
                if isinstance(manifest.get("artifact"), Mapping) and key in manifest["artifact"]
            },
            "attempts": [
                {
                    key: attempt.get(key)
                    for key in (
                        "route_name", "outcome", "returncode", "timed_out",
                        "elapsed_time_ms", "response_identity_validated", "tokens", "cost", "quota",
                    )
                }
                for attempt in attempts if isinstance(attempt, Mapping)
            ],
        }
    return public


def _prepare_lane(
    *, repo_root: Path, request: str, task_id: str, prompt: str,
    read_scope: Sequence[str], evidence_directory: str, expected_artifact: str,
    workspace_config: Path | None, allow_provider_call: bool,
) -> dict[str, Any]:
    """Resolve and probe one lane without starting provider execution."""
    effective = TASK.SERVICE.ProviderTaskExecutionService(
        session_module=TASK.SESSION,
        dispatch_module=TASK.DISPATCH,
        config_module=TASK.CONFIG,
    ).resolve_config(repo_root, workspace_config)
    effective, task_local_binding = TASK.SERVICE.task_local_exact_config(
        effective=effective, request=request,
        session_module=TASK.SESSION, config_module=TASK.CONFIG,
    )
    tool, model = TASK.SESSION.parse_request(request)
    binding_id, binding, route = TASK.SESSION._configured_binding(effective, tool, model)
    probe = None
    if allow_provider_call:
        provider_id, model_token = TASK.SESSION._probe_identity(tool, route, model)
        probe = TASK.SESSION.probe_existing_session(
            tool, provider_id, model_token, runner=subprocess.run,
        )
        assignment, _ = TASK.build_assignment(
            request=request, task_id=task_id, prompt=prompt, repo_root=repo_root,
            read_scope=read_scope, evidence_directory=evidence_directory,
            expected_artifact=expected_artifact, probe_runner=subprocess.run,
            effective=effective, allow_provider_call=True, session_probe=probe,
        )
        checked = TASK.DISPATCH._require_assignment(assignment, repo_root)
        preview = TASK.DISPATCH._resolve_pre_dispatch(copy.deepcopy(checked["route_packet"]))
        if preview.get("status") != "dispatch_required":
            raise ValueError(preview.get("stop_reason", "pre_dispatch_rejected"))
    credential = binding.get("credential_reference", {})
    billing_path = {
        "provider": route["provider"],
        "billing_basis": route["billing_basis"],
        "credential_kind": credential.get("kind"),
        "credential_opaque_id": credential.get("opaque_id"),
    }
    return {
        "binding_id": binding_id,
        "adapter_type": binding["adapter_type"],
        "provider": route["provider"],
        "exact_model": route["exact_model"],
        "route_name": binding["route"]["route_name"],
        "billing_basis": route["billing_basis"],
        "billing_path_sha256": _digest(billing_path),
        "independence_group": route["independence_group"],
        "explicit_tool": tool,
        "effective_config": effective,
        "session_probe": probe,
        "task_local_binding": task_local_binding,
    }


def _validate_independence(prepared: Sequence[Mapping[str, Any]]) -> str:
    """Apply provider_fanout's fail-closed lane-collision rule."""
    mode = (
        "model_diverse"
        if prepared and all(row.get("explicit_tool") == "Command Code" for row in prepared)
        else "provider_diverse"
    )
    if mode == "model_diverse":
        return mode
    for field in (
        "adapter_type", "provider", "billing_path_sha256", "independence_group",
    ):
        values = [row.get(field) for row in prepared]
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"lane_identity_invalid:{field}")
        if len(values) != len(set(values)):
            raise ValueError(f"lane_collision:{field}")
    return mode


def _run_prepared_lane(prepared: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    return TASK.SERVICE.execute_task(
        **kwargs,
        session_module=TASK.SESSION,
        dispatch_module=TASK.DISPATCH,
        config_module=TASK.CONFIG,
        assignment_builder=TASK.build_assignment,
        effective_config=prepared["effective_config"],
        session_probe=prepared["session_probe"],
        allow_task_local_binding=False,
        lifecycle_extra={"task_local_binding": prepared["task_local_binding"]},
    )


def run_fanout(
    *, repo_root: Path, task_id: str, requests: Sequence[str], prompt: str,
    candidate: str, rubric: str, read_scope: Sequence[str],
    evidence_directory: str, workspace_config: Path | None,
    allow_provider_call: bool,
    timeout_seconds: float = 60.0,
    task_runner: Callable[..., dict[str, Any]] | None = None,
    lane_preparer: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute each explicit request once and return a truthful aggregate."""
    task_id = _text(task_id, "task_id", 128)
    if SAFE_ID.fullmatch(task_id) is None:
        raise ValueError("task_id_invalid")
    if not isinstance(requests, (list, tuple)) or not 1 <= len(requests) <= MAX_LANES:
        raise ValueError("requests_invalid")
    normalized = [_text(request, "request", 1024) for request in requests]
    if len(set(normalized)) != len(normalized):
        raise ValueError("requests_must_be_unique")
    prompt = _text(prompt, "prompt")
    candidate = _text(candidate, "candidate")
    rubric = _text(rubric, "rubric")
    evidence_directory = _text(evidence_directory, "evidence_directory", 1024)
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 300
    ):
        raise ValueError("timeout_seconds_invalid")
    frozen = {
        "candidate": candidate,
        "candidate_sha256": _digest(candidate),
        "prompt": prompt,
        "prompt_sha256": _digest(prompt),
        "rubric": rubric,
    }
    frozen["rubric_sha256"] = _digest(rubric)
    frozen["input_sha256"] = _digest(frozen)
    lanes: list[dict[str, Any]] = []
    for index, request in enumerate(normalized, start=1):
        lane_id = _lane_id(index, request)
        lane_evidence = f"{evidence_directory}/fanout/{lane_id}"
        lane_artifact = f"{lane_evidence}/result.json"
        lane = {
            "lane_id": lane_id, "lane_index": index, "request": request,
            "task_id": f"{task_id}-{lane_id}", "evidence_directory": lane_evidence,
            "expected_artifact": lane_artifact, "exact_route": request,
            "frozen_input_sha256": frozen["input_sha256"],
        }
        lanes.append(lane)

    prepare = lane_preparer or _prepare_lane
    prepared_lanes = [
        prepare(
            repo_root=repo_root, request=lane["request"], task_id=lane["task_id"],
            prompt=(
                f"Adversarial review candidate:\n{candidate}\n\n"
                f"Rubric:\n{rubric}\n\n"
                f"Review task:\n{prompt}\n\n"
                "The candidate and rubric are frozen for every lane. Report findings "
                "only; do not modify repository files."
            ),
            read_scope=read_scope, evidence_directory=lane["evidence_directory"],
            expected_artifact=lane["expected_artifact"],
            workspace_config=workspace_config,
            allow_provider_call=allow_provider_call,
        )
        for lane in lanes
    ]
    diversity_mode = _validate_independence(prepared_lanes)
    for lane, prepared in zip(lanes, prepared_lanes):
        lane["route_identity"] = {
            key: prepared[key]
            for key in (
                "binding_id", "adapter_type", "provider", "exact_model",
                "route_name", "billing_basis", "billing_path_sha256",
                "independence_group",
            )
        }

    runner = task_runner
    for lane, prepared in zip(lanes, prepared_lanes):
        lane_prompt = (
            f"Adversarial review candidate:\n{candidate}\n\n"
            f"Rubric:\n{rubric}\n\n"
            f"Review task:\n{prompt}\n\n"
            "The candidate and rubric are frozen for every lane. Report findings "
            "only; do not modify repository files."
        )
        try:
            run_kwargs = dict(
                repo_root=repo_root, request=lane["request"], task_id=lane["task_id"],
                prompt=lane_prompt, read_scope=read_scope,
                evidence_directory=lane["evidence_directory"],
                expected_artifact=lane["expected_artifact"],
                workspace_config=workspace_config,
                allow_provider_call=allow_provider_call,
                probe_runner=subprocess.run,
                timeout_seconds=timeout_seconds,
            )
            result = (
                runner(**run_kwargs)
                if runner is not None
                else (
                    _run_prepared_lane(prepared, **run_kwargs)
                    if allow_provider_call
                    else TASK.run_task(**run_kwargs)
                )
            )
            if not isinstance(result, dict):
                raise ValueError("lane_result_invalid")
            lane.update({
                "status": "completed" if result.get("completed") is True else "rejected",
                "called": result.get("called") is True,
                "completed": result.get("completed") is True,
                "result": _public_result(result),
            })
        except Exception as exc:  # one lane cannot suppress the explicit set
            # A late exception can occur after the dispatcher has durably
            # recorded an attempt.  Preserve that fact in the aggregate
            # receipt; only a proven pre-start failure may report called=false.
            called = TASK.SERVICE.durable_attempt_started(
                Path(repo_root), lane_evidence,
                getattr(exc, "manifest", None)
                if isinstance(getattr(exc, "manifest", None), Mapping) else None,
            )
            lane.update({
                "status": "rejected", "called": called, "completed": False,
                "result": {"rejected": True, "reason": getattr(exc, "code", str(exc))},
            })
    completed = sum(lane["completed"] for lane in lanes)
    called = sum(lane["called"] for lane in lanes)
    return {
        "schema_version": 1,
        "receipt_type": "AdversarialProviderFanoutReceipt",
        "task_id": task_id,
        "fanout_id": f"fanout-{task_id}-{frozen['input_sha256'][-12:]}",
        "frozen_input": {key: value for key, value in frozen.items() if key != "prompt"},
        "lane_count": len(lanes), "called_lane_count": called,
        "completed_lane_count": completed,
        "rejected_lane_count": len(lanes) - completed,
        "called": called > 0, "completed": completed == len(lanes),
        "rejected": completed != len(lanes), "lanes": lanes,
        "diversity_mode": diversity_mode,
        "no_substitution": True, "no_retry_within_lane": True,
        "parent_synthesis_required": True,
        "accepted_by_parent": False, "fold_performed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--request", dest="requests", action="append", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--rubric", required=True)
    parser.add_argument("--workspace-config", type=Path)
    parser.add_argument("--evidence-directory", default="reports/adversarial")
    parser.add_argument("--read-scope", action="append", required=True)
    parser.add_argument("--allow-provider-call", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        result = run_fanout(**vars(args))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["completed"] else 2
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "rejected", "code": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
