#!/usr/bin/env python3
"""Run one guarded provider canary write in an isolated Git worktree."""
from __future__ import annotations

import argparse, copy, hashlib, importlib.util, json, os, stat, sys, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

SCRIPT = Path(__file__).resolve()

def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None: raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module

SESSION = _load("codexmax_write_session", SCRIPT.with_name("verify_configured_tool_session.py"))
DISPATCH = _load("codexmax_write_dispatch", SCRIPT.with_name("run_headless_provider_dispatch.py"))
POLICY, WORK = DISPATCH._execution_policy, DISPATCH._provider_work

def _sha(data: bytes) -> str: return "sha256:" + hashlib.sha256(data).hexdigest()
def _digest(value: Any) -> str: return WORK.canonical_digest(value)
def _time(value: datetime) -> str: return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value or len(value.encode()) > limit:
        raise ValueError(f"{field}_invalid")
    return value

def _relative(value: str, field: str) -> str:
    value = _text(value, field, 1024); path = Path(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or value.startswith("./"):
        raise ValueError(f"{field}_invalid")
    return path.as_posix()

def _target(worktree: Path, relative: str) -> Path:
    if relative == "assignment.md" or relative.startswith(".commandcode/"): raise ValueError("target_reserved")
    cursor = worktree
    for part in Path(relative).parts[:-1]:
        cursor /= part; info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise ValueError("target_component_invalid")
    path = worktree / relative; info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path:
        raise ValueError("target_not_regular_single_link")
    return path

def _assert_isolated(repo_root: Path, worktree: Path) -> None:
    repo, work = repo_root.resolve(strict=True), worktree.resolve(strict=True)
    if repo == work or work.is_relative_to(repo) or repo.is_relative_to(work): raise ValueError("isolated_worktree_required")
    source_git, marker = repo / ".git", work / ".git"
    if not source_git.is_dir() or source_git.is_symlink(): raise ValueError("source_git_directory_required")
    info = marker.lstat()
    if marker.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise ValueError("linked_worktree_marker_invalid")
    raw = marker.read_text().strip()
    if not raw.startswith("gitdir: "): raise ValueError("linked_worktree_marker_invalid")
    admin = Path(raw[8:]); admin = (work / admin).resolve(strict=True) if not admin.is_absolute() else admin.resolve(strict=True)
    common = (admin / (admin / "commondir").read_text().strip()).resolve(strict=True)
    if common != source_git.resolve(strict=True): raise ValueError("worktree_repository_mismatch")

def _parent_fd(root: Path, relative: str, *, create: bool) -> tuple[int, str]:
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("safe_path_invalid")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in parts[:-1]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        return descriptor, parts[-1]
    except Exception:
        os.close(descriptor); raise

def _write_new(root: Path, relative: str, data: bytes, mode: int = 0o600) -> Path:
    descriptor, name = _parent_fd(root, relative, create=True)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=descriptor)
        try: os.write(fd, data); os.fsync(fd)
        finally: os.close(fd)
    finally: os.close(descriptor)
    return root / relative

def _read_safe(root: Path, relative: str) -> bytes:
    descriptor, name = _parent_fd(root, relative, create=False)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise ValueError("safe_file_invalid")
            return os.read(fd, info.st_size + 1)
        finally: os.close(fd)
    finally: os.close(descriptor)

def _overwrite_safe(root: Path, relative: str, data: bytes, expected_current_sha256: str) -> None:
    descriptor, name = _parent_fd(root, relative, create=False)
    try:
        fd = os.open(name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise ValueError("safe_file_invalid")
            current = os.read(fd, info.st_size + 1)
            if _sha(current) != expected_current_sha256: raise ValueError("rollback_after_digest_mismatch")
            os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET); os.write(fd, data); os.fsync(fd)
        finally: os.close(fd)
    finally: os.close(descriptor)

def _controls(workspace: str) -> set[str]:
    return {f"{workspace}/.commandcode/hooks/scoped-write-guard.py", f"{workspace}/.commandcode/settings.json",
            f"{workspace}/.commandcode/scoped-write-descriptor.json", f"{workspace}/.commandcode/runtime-state.json",
            f"{workspace}/assignment.md"}

def _guard_script() -> bytes:
    return b'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path.cwd(); descriptor = json.loads((root / ".commandcode/scoped-write-descriptor.json").read_text())
state_path = root / ".commandcode/runtime-state.json"; state = json.loads(state_path.read_text())
try:
 event = json.load(sys.stdin); tool = event.get("tool_name") or event.get("tool"); values = event.get("tool_input") or event.get("input") or {}
 path = values.get("absolute_path") or values.get("file_path") or values.get("path"); expected = descriptor["sequence"][state["index"]]
 candidate = pathlib.Path(path) if isinstance(path, str) else pathlib.Path("/")
 if not candidate.is_absolute(): candidate = root / candidate
 if tool != expected or candidate.resolve(strict=True) != (root / descriptor["target"]).resolve(strict=True): raise ValueError("sequence_or_target_denied")
 if tool == "write_file" and values.get("content") != descriptor["content"]: raise ValueError("content_denied")
 if tool == "edit_file":
  old = values.get("old_string", values.get("old_value")); new = values.get("new_string", values.get("new_value"))
  proposed = descriptor["before"].replace(old, new, 1) if isinstance(old, str) and isinstance(new, str) and descriptor["before"].count(old) == 1 else None
  if proposed != descriptor["content"] or values.get("replace_all", False) or values.get("replacement_count") not in {None, 1}: raise ValueError("content_denied")
 state["index"] += 1; tmp = state_path.with_suffix(".tmp"); tmp.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\\n"); os.replace(tmp, state_path); print("{}")
except Exception as exc:
 state["last_denial"] = {"tool": locals().get("tool"), "input_keys": sorted(locals().get("values", {}).keys())[:32], "reason": str(exc)}
 tmp = state_path.with_suffix(".tmp"); tmp.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\\n"); os.replace(tmp, state_path)
 print(json.dumps({"decision":"block","reason":str(exc)})); raise SystemExit(2)
'''

def _profile(route: str) -> dict[str, Any]:
    return {"profile_schema_version": 1, "required_source_access": "local_filesystem", "commands_required": False,
            "write_required": True, "browser_required": False, "web_search_required": False, "connector_required": False,
            "billing_ceiling": "non_metered", "consequence_floor": "high", "independence_required": False,
            "primary_route": route, "secondary_01": "none", "secondary_02": "none", "secondary_03": "none",
            "secondary_04": "none", "secondary_05": "none"}

def _schema() -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "required": ["route_identity", "content"], "properties": {
        "content": {"type": "string", "minLength": 1, "maxLength": 4096},
        "route_identity": {"type": "object", "additionalProperties": False,
            "required": ["declared_route", "actual_provider", "actual_model", "fallback_used", "retry_count"],
            "properties": {"declared_route": {"type": "string"}, "actual_provider": {"type": "string"},
                "actual_model": {"type": "string"}, "fallback_used": {"const": False}, "retry_count": {"const": 0}}}}}

def build_write_packet(*, repo_root: Path, worktree: Path, target_path: str, request: str, task_id: str,
                       prompt: str, workspace_config: Path, evidence_directory: str, expected_artifact: str,
                       probe_runner: Callable[..., Any], effective: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    repo_root, worktree = repo_root.resolve(strict=True), worktree.resolve(strict=True); _assert_isolated(repo_root, worktree)
    root, workspace = worktree.parent, worktree.name
    target_relative = _relative(target_path, "target_path"); target = _target(worktree, target_relative)
    config = workspace_config.resolve(strict=True)
    if not config.is_relative_to(worktree): raise ValueError("workspace_config_outside_worktree")
    evidence_relative, artifact_relative = _relative(evidence_directory, "evidence_directory"), _relative(expected_artifact, "expected_artifact")
    if evidence_relative == workspace or evidence_relative.startswith(workspace + "/"):
        raise ValueError("evidence_must_be_outside_worktree")
    if artifact_relative == workspace or artifact_relative.startswith(workspace + "/"):
        raise ValueError("artifact_must_be_outside_worktree")
    task_id, prompt = _text(task_id, "task_id", 128), _text(prompt, "prompt", 16384)
    tool, model = SESSION.parse_request(request)
    if tool != "Command Code": raise ValueError("controlled_write_requires_command_code")
    binding_id, binding, route = SESSION._configured_binding(effective, tool, model)
    provider_id, model_token = SESSION._probe_identity(tool, route, model)
    probe = SESSION.probe_existing_session(tool, provider_id, model_token, runner=probe_runner)
    route_name = binding["route"]["route_name"]; harness_name = POLICY.ROUTE_HARNESS.get(route_name)
    if harness_name is None: raise ValueError("commandcode_write_harness_missing")
    harness = copy.deepcopy(POLICY.ADAPTER_HARNESS_CARDS[harness_name]); now = datetime.now(timezone.utc); expiry = now + timedelta(seconds=300)
    issued_at, expires_at = _time(now), _time(expiry)
    qualification = _digest({"binding_id": binding_id, "probe": probe, "mode": "isolated_development_live_write"})
    intent = POLICY.build_task_intent("bounded_implementation", behavior={"max_turns": 20, "wall_time_seconds": 300},
        requirements={"commands": False, "browser": False, "web_search": False, "connectors": False,
                      "tools": ["read_file", "write_file"]})
    _, base_tree = DISPATCH._workspace_snapshot(worktree, root, excluded_paths=_controls(workspace))
    target_bound = f"{workspace}/{target_relative}"
    grant = {"schema_version": 2, "grant_id": f"grant-{task_id}", "task_id": task_id, "route_name": route_name,
        "access_mode": "scoped_write", "read_scope": [f"{workspace}/**"], "write_scope": [target_bound],
        "command_allowlist": [], "network_policy": "provider_only", "billing_policy": "subscription_only",
        "workspace_mode": "isolated_worktree", "workspace_path": workspace, "base_tree_sha256": base_tree,
        "lease_id": f"lease-{task_id}", "fencing_token": 1, "issued_at": issued_at, "expires_at": expires_at,
        "exclusive_writer": False, "task_intent_sha256": intent["intent_sha256"],
        "tool_allowlist": ["read_file", "write_file", "edit_file"], "browser_policy": "none", "web_search_policy": "none",
        "connector_policy": "none", "validation_commands": [], "no_retry": True,
        "execution_unknown_policy": "preserve_and_stop", "legacy_grant_sha256": None}
    grant["grant_sha256"] = _digest(grant)
    card = {"schema_version": 2, "route_name": route_name, "provider": route["provider"], "exact_model": route["exact_model"],
        "route_id": route["route_id"], "runtime": route["runtime"], "billing_basis": route["billing_basis"],
        "source_access": "local_filesystem", "local_file_access": "read_write", "commands_executable": "no",
        "write_access": "scoped", "network_access": "provider_only", "qualified_at": issued_at, "expires_at": expires_at,
        "qualification_sha256": qualification, "host_identity_sha256": probe["output_sha256"],
        "adapter_harness_sha256": harness["harness_sha256"], "tool_loop": "agentic", "browser_access": "no",
        "web_search_access": "no", "connector_access": "no", "reasoning_controls": copy.deepcopy(harness["reasoning_controls"]),
        "verbosity_controls": copy.deepcopy(harness["verbosity_controls"]), "context_controls": copy.deepcopy(harness["context_controls"]),
        "max_turns": 20, "max_wall_time_seconds": 300, "tool_capabilities": ["read_file", "write_file", "edit_file"],
        "legacy_capability_sha256": None}; card["capability_sha256"] = _digest(card)
    desired = (f"Orcastrata controlled-write canary\nTask: {task_id}\nPrompt SHA-256: {_sha(prompt.encode())}\n").encode()
    before_bytes = target.read_bytes()
    if before_bytes == desired: raise ValueError("provider_write_no_change")
    attempt_id, session_id = "attempt-" + uuid.uuid4().hex[:20], "session-" + uuid.uuid4().hex[:20]
    descriptor = {"target": target_relative, "before": before_bytes.decode(), "content": desired.decode(),
        "sequence": ["read_file", "edit_file", "read_file"]}
    state = {"attempt_id": attempt_id, "session_id": session_id, "index": 0}
    execution_prompt = (prompt + f"\n\nControlled-write canary: use read_file on {target_relative}, then use edit_file with the full current text as old_string and replace it with exactly this UTF-8 text as new_string:\n"
                        + desired.decode() + "Then use read_file on the same target. Do not access or change another path.")
    # Omit matcher so the guard sees every built-in and MCP tool. Command Code's
    # --tools-enable flag exposes withheld tools; it is not a strict allowlist.
    settings = {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "python3 .commandcode/hooks/scoped-write-guard.py"}]}]}}
    artifacts = {
        "guard_sha256": (".commandcode/hooks/scoped-write-guard.py", _guard_script()),
        "settings_sha256": (".commandcode/settings.json", (json.dumps(settings, sort_keys=True, separators=(",", ":")) + "\n").encode()),
        "descriptor_sha256": (".commandcode/scoped-write-descriptor.json", (json.dumps(descriptor, sort_keys=True, separators=(",", ":")) + "\n").encode()),
        "assignment_sha256": ("assignment.md", (execution_prompt + "\n").encode()),
        "state_sha256": (".commandcode/runtime-state.json", (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode())}
    for _, (relative, data) in artifacts.items(): _write_new(worktree, relative, data, 0o700 if relative.endswith(".py") else 0o600)
    guard = {"schema_version": 1, "artifact_type": "CommandCodeScopedWriteGrant", "task_id": task_id,
        "route_name": route_name, "route_id": route["route_id"], "model": route["exact_model"],
        "task_grant_sha256": grant["grant_sha256"], "attempt_id": attempt_id, "session_id": session_id,
        "worktree_path": workspace, "target_path": target_bound, "mutation_tool": "edit_file",
        "before_sha256": _sha(before_bytes), "after_sha256": _sha(desired), "content_sha256": _sha(desired),
        **{field: _sha(data) for field, (_, data) in artifacts.items()}, "hook_event": "PreToolUse", "permission_mode": "bypass",
        "allowed_tools": ["read_file", "write_file", "edit_file"], "tool_sequence": ["read_file", "edit_file", "read_file"],
        "tools_enable_non_authoritative": True, "hook_required": True, "isolated_worktree": True, "no_retry": True,
        "no_fallback": True, "no_hedge": True, "no_model_substitution": True, "shell_allowed": False,
        "tools_all_allowed": False, "proof_scope": "task_scoped_development_worker", "protected_production": False}
    guard["grant_sha256"] = POLICY.canonical_digest(guard)
    POLICY.validate_commandcode_scoped_write_grant(guard, route_name=route_name, model=route["exact_model"], task_id=task_id,
        task_grant_sha256=grant["grant_sha256"], attempt_id=attempt_id, session_id=session_id, worktree_path=workspace)
    provider_work = {"capability_card": card, "task_grant": grant, "task_intent": intent, "harness_card": harness,
        "runtime_constraints": {"health": "eligible", "budget_state": "eligible", "lease_state": "eligible",
            "fence_state": "eligible", "worktree_state": "eligible", "max_turns": 20, "wall_time_seconds": 300,
            "max_input_tokens": 128000, "max_output_tokens": 4096, "max_cost_microusd": 2000000,
            "budget_sha256": _digest({"task_id": task_id, "ceiling": "development_canary"})},
        "commandcode_scoped_write_grant": guard, "legacy_schema_v1": False, "observed_base_tree_sha256": base_tree}
    envelope = {"task_id": task_id, "mutation_mode": "scoped_write",
        "scope": {"requested_read": [f"{workspace}/**"], "requested_write": [target_bound]},
        "bindings": {"authority_sha256": grant["grant_sha256"]}, "provider_work": provider_work}
    selection = SESSION.compile_selection(request, task_id=task_id, task_grant_sha256=grant["grant_sha256"],
        effective_config=effective, probe_runner=probe_runner, session_probe=probe)
    preflight = {"preflight_id": f"isolated-write:{task_id}", "task_id": task_id, "fresh": True,
        "observed_at": issued_at, "expires_at": expires_at, "provider": route["provider"], "model": route["exact_model"],
        "route": route["route_id"], "runtime": route["runtime"], "reasoning": route["reasoning"], "billing": route["billing_basis"],
        "token_limit": None, "availability": "available", "health": "healthy", "authentication": "verified",
        "identity_status": "known_exact", "capability_status": "verified", "identity_evidence": "configured_tool_session_probe:" + probe["output_sha256"],
        "capability_evidence": qualification, "quota": "available", "credential_access_required": False,
        "source_access": "local_filesystem", "input_delivery": "paths_only", "commands_executable": "no",
        "local_file_access": "read_write", "browser_access": "no", "web_search_access": "no", "connector_access": "no",
        "network_access": "provider_only", "citation_support": "no", "write_access": "scoped",
        "read_scope": [f"{workspace}/**"], "write_scope": [target_bound], "authority_scope": [target_bound],
        "consequence_floor": "high", "independence_group": route["independence_group"]}
    registry = copy.deepcopy(effective["route_registry"]); registry["routes"][route_name]["exact_model"] = route["exact_model"]
    profile_name = "isolated_development_write"; registry["task_profiles"][profile_name] = _profile(route_name)
    packet = {"schema_version": 2, "task_id": task_id, "role": "worker", "profile": profile_name,
        "resolution_time": issued_at, "token_limit": None, "allowed_billing": ["subscription"],
        "read_scope": [f"{workspace}/**"], "write_scope": [target_bound], "authority_scope": [target_bound],
        "requirements": {"commands": False, "local_files": True, "browser": False, "web_search": False, "connector": False, "write": True},
        "provider_input": {"source_access": "local_filesystem", "input_delivery": "paths_only", "required_source_access": ["local_filesystem"],
            "source_backed_claims_required": True, "commands_executable": "no", "commands_required": False,
            "named_source_categories": [{"category_id": "repository", "required": True, "source_label": "Isolated worktree paths"}],
            "read_receipt_required": True, "compatibility_gate": {"decision": "compatible", "reason": "compatible"}},
        "independence_required": False, "independence_exclusions": [], "consequence_floor": "high",
        "controls": {"circuit_breaker_threshold": 1, "max_attempts_per_checkpoint": 1, "max_attempts_per_route": 1, "no_improvement_window": 1},
        "preflights": {route_name: preflight}, "attempt_results": {}, "explicit_selection": selection,
        "task_grant_sha256": grant["grant_sha256"], "parent_capability": {"cost_ceiling": 1, "effort_ceiling": 1}, "registry": registry}
    evidence_bound, artifact_bound = evidence_relative, artifact_relative
    assignment = {"schema_version": 1, "dispatch_id": f"isolated-write-{task_id}-{uuid.uuid4().hex[:12]}",
        "supervisor_assignment_id": f"assignment-{task_id}", "supervisor_lane_id": f"lane-{task_id}", "semantic_role": "worker",
        "prompt": execution_prompt, "working_directory": workspace, "expected_artifact": artifact_bound,
        "evidence_directory": evidence_bound, "dispatch_output_scope": [evidence_bound + "/**", str(Path(artifact_bound).parent) + "/**"],
        "proof_mode": "isolated_development_live_write", "authority": {"provider_call_authorized": True,
            "network_authorized": True, "billing_authorized": True, "credential_mechanism_authorized": True,
            "scope_authorized": True, "retention_authorized": True}, "route_packet": packet, "response_schema": _schema()}
    once = {"schema_version": 1, "lease_id": grant["lease_id"], "fencing_token": 1, "attempt_id": attempt_id,
        "task_id": task_id, "assignment_id": assignment["supervisor_assignment_id"], "route_name": route_name,
        "envelope_sha256": _digest(envelope), "preflight_sha256": _digest(preflight), "authority_sha256": _digest(assignment["authority"]),
        "effective_config_sha256": _digest(effective), "evidence_directory": evidence_bound, "expires_at": expires_at,
        "execution_mode": "single_resolved_attempt", "receiver_qualification_sha256": qualification}
    return assignment, envelope, once, before_bytes

def run_write(*, repo_root: Path, worktree: Path, target_path: str, request: str, task_id: str, prompt: str,
              workspace_config: Path, evidence_directory: str, expected_artifact: str, allow_provider_call: bool,
              probe_runner: Callable[..., Any], timeout_seconds: float = 60.0) -> dict[str, Any]:
    if allow_provider_call is not True: return {"called": False, "completed": False, "rejected": True, "reason": "task_scoped_provider_call_not_authorized"}
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 300: raise ValueError("timeout_seconds_invalid")
    worktree = Path(worktree).resolve(strict=True); root = worktree.parent
    effective = DISPATCH._effective_config(root, Path(workspace_config).resolve(strict=True))
    assignment, envelope, binding, before = build_write_packet(repo_root=Path(repo_root), worktree=worktree, target_path=target_path,
        request=request, task_id=task_id, prompt=prompt, workspace_config=Path(workspace_config), evidence_directory=evidence_directory,
        expected_artifact=expected_artifact, probe_runner=probe_runner, effective=effective)
    checked = DISPATCH._require_assignment(assignment, root); packet = copy.deepcopy(checked["route_packet"])
    preview = DISPATCH._resolve_pre_dispatch(packet)
    if preview.get("status") != "dispatch_required": return {"called": False, "completed": False, "rejected": True, "reason": preview.get("stop_reason", preview.get("status"))}
    result = DISPATCH.run_dispatch(checked, packet, root, {}, effective=effective, allow_provider_call=True,
        allow_simulated_process=False, timeout=float(timeout_seconds), stdout_limit=1024 * 1024, stderr_limit=256 * 1024,
        single_attempt_binding=binding, task_envelope=envelope, execution_time=_time(datetime.now(timezone.utc)),
        execution_clock=lambda: _time(datetime.now(timezone.utc)))
    attempts = result.get("attempts") or []; called = any(row.get("returncode") is not None for row in attempts)
    completed = result.get("status") == "selected" and len(attempts) == 1 and attempts[0].get("response_identity_validated") is True and isinstance(result.get("provider_change_receipt"), dict)
    target = worktree / _relative(target_path, "target_path")
    rollback_relative = str(Path(evidence_directory) / "rollback-before.bin")
    rollback_path = _write_new(root, rollback_relative, before)
    if completed:
        for control in sorted(_controls(worktree.name), reverse=True):
            (root / control).unlink()
        for directory in (worktree / ".commandcode/hooks", worktree / ".commandcode"):
            directory.rmdir()
    return {"configured": True, "selected": True, "called": called, "completed": completed, "rejected": not completed,
        "manifest": result, "changed_paths": [target_path] if completed else [], "target_after_sha256": _sha(target.read_bytes()),
        "accepted_by_parent": False, "protected_production": False, "retry_allowed": False, "fallback_allowed": False,
        "rollback": {"available": True, "performed": False, "before": {"path": rollback_path.relative_to(root).as_posix(),
            "bytes": len(before), "sha256": _sha(before)}}}

def rollback(*, worktree: Path, target_path: str, before_blob: Path, expected_after_sha256: str,
             expected_before_sha256: str) -> dict[str, Any]:
    worktree = Path(worktree).resolve(strict=True); target = _target(worktree, _relative(target_path, "target_path"))
    target_relative = target.relative_to(worktree).as_posix()
    if _sha(_read_safe(worktree, target_relative)) != expected_after_sha256: raise ValueError("rollback_after_digest_mismatch")
    blob = Path(before_blob).resolve(strict=True)
    if not blob.is_relative_to(worktree.parent) or blob.is_relative_to(worktree): raise ValueError("rollback_blob_outside_evidence_root")
    blob_relative = blob.relative_to(worktree.parent).as_posix(); before = _read_safe(worktree.parent, blob_relative)
    if _sha(before) != expected_before_sha256: raise ValueError("rollback_before_digest_mismatch")
    _overwrite_safe(worktree, target_relative, before, expected_after_sha256)
    return {"performed": True, "restored_sha256": _sha(_read_safe(worktree, target_relative)), "target_path": target_path}

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "worktree", "workspace-config"): parser.add_argument("--" + name, type=Path, required=True)
    for name in ("target-path", "request", "task-id", "prompt", "evidence-directory", "expected-artifact"): parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0); parser.add_argument("--allow-provider-call", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_write(**vars(args), probe_runner=__import__("subprocess").run); print(json.dumps(result, indent=2, sort_keys=True)); return 0 if result.get("completed") else 2
    except (ValueError, OSError, SESSION.ExplicitSelectionError, DISPATCH.DispatchError) as exc:
        print(json.dumps({"status": "rejected", "code": getattr(exc, "code", "task_scoped_write_rejected"), "detail": str(exc)}, sort_keys=True), file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
