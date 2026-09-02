import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/run_task_scoped_provider_write.py"
spec = importlib.util.spec_from_file_location("task_scoped_provider_write_test", SCRIPT)
write = importlib.util.module_from_spec(spec); sys.modules[spec.name] = write; spec.loader.exec_module(write)
MODEL = "vendor/model-x"; REQUEST = f"Use {MODEL} through Command Code"

def effective():
    value = copy.deepcopy(write.DISPATCH._config.DEFAULTS)
    binding = write.DISPATCH._config._build_authored_binding(
        adapter_type="commandcode", route_name="worker_commandcode_model",
        credential_kind="host_managed", opaque_id="write-test", enabled=True,
        concurrency_cap=None, token_cap=1, exact_model=MODEL)
    value["adapter_registry"]["bindings"][binding["binding_id"]] = binding
    return value

class Completed:
    returncode = 0; stderr = ""

def probe(argv, **kwargs):
    row = Completed()
    row.stdout = (json.dumps({"authenticated": True, "context_window": 128000, "model": MODEL,
        "provider": "Command Code", "user": "operator", "version": "1.38.0"})
        if argv == ["commandcode", "status", "--json"] else MODEL + "\n")
    return row

def layout(parent: Path):
    repo, worktree = parent / "source", parent / "canary"
    repo.mkdir(); (repo / ".git/worktrees/canary").mkdir(parents=True)
    admin = repo / ".git/worktrees/canary"; (admin / "commondir").write_text("../..\n")
    worktree.mkdir(); (worktree / ".git").write_text("gitdir: " + str(admin) + "\n")
    (worktree / "canary.txt").write_text("before\n"); (worktree / "config.yaml").write_text("{}\n")
    return repo, worktree

def kwargs(repo, worktree):
    return {"repo_root": repo, "worktree": worktree, "target_path": "canary.txt", "request": REQUEST,
        "task_id": "T050-test", "prompt": "Prove one exact controlled write.",
        "workspace_config": worktree / "config.yaml", "evidence_directory": "evidence/T050-test",
        "expected_artifact": "evidence/T050-test/result.json", "allow_provider_call": True,
        "probe_runner": probe, "timeout_seconds": 60}

class TaskScopedProviderWriteTests(unittest.TestCase):
    def test_generated_commandcode_hook_enforces_exact_sequence_target_and_content(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            worktree = Path(raw)
            (worktree / ".commandcode/hooks").mkdir(parents=True)
            target = worktree / "canary.txt"; target.write_text("before\n")
            descriptor = {"target": "canary.txt", "before": "before\n", "content": "after\n",
                "sequence": ["read_file", "edit_file", "read_file"]}
            (worktree / ".commandcode/scoped-write-descriptor.json").write_text(json.dumps(descriptor))
            state = {"attempt_id": "attempt", "session_id": "session", "index": 0}
            state_path = worktree / ".commandcode/runtime-state.json"
            state_path.write_text(json.dumps(state))
            hook = worktree / ".commandcode/hooks/scoped-write-guard.py"
            hook.write_bytes(write._guard_script())
            events = [
                {"tool_name": "read_file", "tool_input": {"absolute_path": str(target)}},
                {"tool_name": "edit_file", "tool_input": {"file_path": str(target),
                    "old_string": "before", "new_string": "after"}},
                {"tool_name": "read_file", "tool_input": {"absolute_path": str(target)}},
            ]
            for event in events:
                completed = subprocess.run([sys.executable, str(hook)], cwd=worktree,
                    input=json.dumps(event), text=True, capture_output=True, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(state_path.read_text())["index"], 3)
            denied = subprocess.run([sys.executable, str(hook)], cwd=worktree,
                input=json.dumps({"tool_name": "edit_file", "tool_input": {
                    "file_path": str(target), "old_string": "before\n", "new_string": "wrong\n"}}),
                text=True, capture_output=True, check=False)
            self.assertEqual(denied.returncode, 2)
            denial_state = json.loads(state_path.read_text())["last_denial"]
            self.assertEqual(denial_state["tool"], "edit_file")
            self.assertEqual(denial_state["reason"], "list index out of range")

    def test_commandcode_settings_guard_every_tool(self):
        source = Path(write.__file__).read_text()
        self.assertIn('settings = {"hooks": {"PreToolUse": [{"hooks": [', source)
        self.assertNotIn('"matcher": "read|write|edit"', source)

    def test_authorization_gate_precedes_config_or_dispatch(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree = layout(Path(raw))
            with mock.patch.object(write.DISPATCH, "_effective_config", side_effect=AssertionError("must not resolve")):
                result = write.run_write(**{**kwargs(repo, worktree), "allow_provider_call": False})
        self.assertFalse(result["called"]); self.assertEqual(result["reason"], "task_scoped_provider_call_not_authorized")

    def test_shared_tree_wrong_repository_and_unsafe_target_fail_before_dispatch(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree = layout(Path(raw)); eff = effective()
            with self.assertRaisesRegex(ValueError, "isolated_worktree"):
                write.build_write_packet(**{**{k: v for k, v in kwargs(repo, worktree).items()
                    if k not in {"allow_provider_call", "timeout_seconds"}}, "worktree": repo, "effective": eff})
            (repo / ".git/other").mkdir(); (worktree / ".git").write_text("gitdir: " + str(repo / ".git/other") + "\n")
            (repo / ".git/other/commondir").write_text("../../not-the-source\n")
            with self.assertRaises((ValueError, FileNotFoundError)):
                write.build_write_packet(**{**{k: v for k, v in kwargs(repo, worktree).items()
                    if k not in {"allow_provider_call", "timeout_seconds"}}, "effective": eff})

    def test_direct_dispatch_reconciles_exact_target_and_rollback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree = layout(Path(raw)); before = (worktree / "canary.txt").read_bytes(); captured = {}
            def capture(argv, cwd, deadline, stdout_limit, stderr_limit):
                captured["argv"] = argv; descriptor = json.loads((cwd / ".commandcode/scoped-write-descriptor.json").read_text())
                (cwd / descriptor["target"]).write_text(descriptor["content"])
                state = json.loads((cwd / ".commandcode/runtime-state.json").read_text()); state["index"] = 3
                (cwd / ".commandcode/runtime-state.json").write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
                payload = {"route_identity": {"declared_route": "worker_commandcode_model",
                    "actual_provider": "Command Code", "actual_model": MODEL, "fallback_used": False, "retry_count": 0},
                    "content": "write complete"}
                return {"returncode": 0, "stdout": json.dumps(payload).encode(), "stderr": b"", "timed_out": False,
                        "output_limit_stream": None, "elapsed_time_ms": 2}
            with mock.patch.object(write.DISPATCH, "_effective_config", return_value=effective()), \
                 mock.patch.object(write.DISPATCH, "_capture", side_effect=capture):
                result = write.run_write(**kwargs(repo, worktree))
            self.assertTrue(result["completed"]); self.assertEqual(result["changed_paths"], ["canary.txt"])
            self.assertFalse(result["accepted_by_parent"]); self.assertFalse(result["protected_production"])
            self.assertEqual(captured["argv"][captured["argv"].index("--model") + 1], MODEL)
            self.assertFalse((worktree / ".commandcode").exists()); self.assertFalse((worktree / "assignment.md").exists())
            blob = worktree.parent / result["rollback"]["before"]["path"]
            after = (worktree / "canary.txt").read_bytes(); blob.write_bytes(b"wrong\n")
            with self.assertRaisesRegex(ValueError, "rollback_before_digest_mismatch"):
                write.rollback(worktree=worktree, target_path="canary.txt", before_blob=blob,
                    expected_after_sha256=result["target_after_sha256"], expected_before_sha256=write._sha(before))
            self.assertEqual((worktree / "canary.txt").read_bytes(), after); blob.write_bytes(before)
            rolled = write.rollback(worktree=worktree, target_path="canary.txt", before_blob=blob,
                expected_after_sha256=result["target_after_sha256"], expected_before_sha256=write._sha(before))
            self.assertTrue(rolled["performed"]); self.assertEqual((worktree / "canary.txt").read_bytes(), before)

    def test_preexisting_control_symlink_cannot_escape_worktree(self):
        for link in (".commandcode", ".commandcode/hooks"):
            with self.subTest(link=link), tempfile.TemporaryDirectory(dir=ROOT) as raw:
                repo, worktree = layout(Path(raw)); outside = Path(raw) / "outside"; outside.mkdir()
                if link == ".commandcode/hooks":
                    (worktree / ".commandcode").mkdir()
                (worktree / link).symlink_to(outside, target_is_directory=True)
                with mock.patch.object(write.DISPATCH, "_effective_config", return_value=effective()):
                    with self.assertRaises((ValueError, OSError, write.DISPATCH.DispatchError)):
                        write.run_write(**kwargs(repo, worktree))
                self.assertEqual(list(outside.iterdir()), [])

    def test_out_of_scope_mutation_and_control_drift_hard_stop(self):
        for defect in ("outside", "guard"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory(dir=ROOT) as raw:
                repo, worktree = layout(Path(raw)); (worktree / "other.txt").write_text("safe\n")
                def capture(argv, cwd, deadline, stdout_limit, stderr_limit):
                    descriptor = json.loads((cwd / ".commandcode/scoped-write-descriptor.json").read_text())
                    (cwd / descriptor["target"]).write_text(descriptor["content"])
                    state = json.loads((cwd / ".commandcode/runtime-state.json").read_text()); state["index"] = 3
                    (cwd / ".commandcode/runtime-state.json").write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
                    (cwd / ("other.txt" if defect == "outside" else ".commandcode/settings.json")).write_text("drift\n")
                    payload = {"route_identity": {"declared_route": "worker_commandcode_model", "actual_provider": "Command Code",
                        "actual_model": MODEL, "fallback_used": False, "retry_count": 0}, "content": "done"}
                    return {"returncode": 0, "stdout": json.dumps(payload).encode(), "stderr": b"", "timed_out": False,
                            "output_limit_stream": None, "elapsed_time_ms": 1}
                with mock.patch.object(write.DISPATCH, "_effective_config", return_value=effective()), \
                     mock.patch.object(write.DISPATCH, "_capture", side_effect=capture):
                    with self.assertRaises(write.DISPATCH.DispatchError) as raised: write.run_write(**kwargs(repo, worktree))
                self.assertIn(raised.exception.code, {
                    "commandcode_guard_changed_paths_invalid", "provider_write_outside_scope",
                    "commandcode_guard_artifact_drift",
                })

if __name__ == "__main__": unittest.main()
