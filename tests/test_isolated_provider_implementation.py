import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
PATH = ROOT / "plugins/codexmax-orchestrator/scripts/run_isolated_provider_implementation.py"
SPEC = importlib.util.spec_from_file_location("isolated_provider_implementation_tested", PATH)
impl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = impl
SPEC.loader.exec_module(impl)


def layout(parent: Path):
    repo = parent / "source"
    worktree = parent / "worktree"
    repo.mkdir()
    admin = repo / ".git/worktrees/worktree"
    admin.mkdir(parents=True)
    (admin / "commondir").write_text("../..\n")
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: " + str(admin) + "\n")
    (worktree / "a.txt").write_text("one\ntwo\n")
    (worktree / "b.txt").write_text("red\nblue\n")
    (worktree / "config.yaml").write_text("{}\n")
    evidence = parent / "evidence"
    evidence.mkdir()
    return repo, worktree, evidence


def provider_with(content, *, called=True, completed=True):
    def run(**kwargs):
        artifact = kwargs["repo_root"] / kwargs["expected_artifact"]
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps({
            "route_identity": {
                "declared_route": "worker_commandcode_model",
                "actual_provider": "Command Code",
                "actual_model": "vendor/model-x",
                "fallback_used": False,
                "retry_count": 0,
            },
            "content": content,
        }))
        return {"called": called, "completed": completed, "manifest": {"status": "selected"}}
    return run


class IsolatedProviderImplementationTests(unittest.TestCase):
    def test_task_id_cannot_escape_evidence_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            with mock.patch.object(
                impl.AUTO, "run_automatic_task", side_effect=AssertionError("provider must not run")
            ):
                with self.assertRaises(impl.ImplementationError) as raised:
                    impl.run_implementation(
                        repo_root=repo, worktree=worktree, task_id="../escape",
                        prompt="Update.", authorized_files=["a.txt"],
                        workspace_config=worktree / "config.yaml", evidence_root=evidence,
                        allow_provider_call=True,
                    )
            self.assertEqual(raised.exception.code, "task_id_invalid")
            self.assertEqual(list(evidence.iterdir()), [])

    def test_automatic_worker_returns_patch_parent_applies_validates_and_rolls_back(self):
        patch = (
            "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"
            "--- a/b.txt\n+++ b/b.txt\n@@ -1,2 +1,2 @@\n-red\n+green\n blue\n"
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            command = ["python3", "-m", "unittest", "discover", "-s", ".", "-p", "no-tests-here"]
            completed = subprocess.CompletedProcess(command, 0, b"ok", b"")
            with mock.patch.object(impl.AUTO, "run_automatic_task", side_effect=provider_with(patch)), \
                 mock.patch.object(impl, "run_validation", return_value=[{
                     "argv": command, "execution_status": "completed", "result": "pass", "returncode": 0,
                     "duration_ms": 1, "stdout_sha256": impl.PATCH.sha256(b"ok"), "stderr_sha256": impl.PATCH.sha256(b"")
                 }]):
                result = impl.run_implementation(
                    repo_root=repo, worktree=worktree, task_id="T040-test",
                    prompt="Update the two values.", authorized_files=["a.txt", "b.txt"],
                    workspace_config=worktree / "config.yaml", evidence_root=evidence,
                    allow_provider_call=True, validation_commands=[command],
                )
            self.assertTrue(result["completed"])
            self.assertEqual(result["selection_mode"], "automatic")
            self.assertTrue(result["no_provider_write_authority"])
            self.assertEqual(result["changed_paths"], ["a.txt", "b.txt"])
            self.assertEqual((worktree / "a.txt").read_text(), "one\nthree\n")
            rolled = impl.rollback_implementation(
                manifest_path=Path(result["rollback"]["manifest"]), worktree=worktree,
            )
            self.assertTrue(rolled["performed"])
            self.assertEqual((worktree / "a.txt").read_text(), "one\ntwo\n")

    def test_exact_override_uses_exact_runner(self):
        patch = "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            with mock.patch.object(impl.EXACT, "run_task", side_effect=provider_with(patch)) as exact, \
                 mock.patch.object(impl.AUTO, "run_automatic_task", side_effect=AssertionError("automatic must not run")):
                result = impl.run_implementation(
                    repo_root=repo, worktree=worktree, task_id="T040-exact", prompt="Update the value.",
                    authorized_files=["a.txt"], workspace_config=worktree / "config.yaml",
                    evidence_root=evidence, allow_provider_call=True,
                    exact_request="Use vendor/model-x through Command Code",
                )
            exact.assert_called_once()
            self.assertTrue(result["completed"])
            self.assertEqual(result["selection_mode"], "exact")

    def test_unauthorized_patch_is_rejected_without_mutation_or_bundle(self):
        patch = "--- a/c.txt\n+++ b/c.txt\n@@ -1 +1 @@\n-old\n+new\n"
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            (worktree / "c.txt").write_text("old\n")
            with mock.patch.object(impl.AUTO, "run_automatic_task", side_effect=provider_with(patch)):
                with self.assertRaises(impl.PATCH.PatchError) as raised:
                    impl.run_implementation(
                        repo_root=repo, worktree=worktree, task_id="T040-denied", prompt="Change c.",
                        authorized_files=["a.txt"], workspace_config=worktree / "config.yaml",
                        evidence_root=evidence, allow_provider_call=True,
                    )
            self.assertEqual(raised.exception.code, "patch_path_not_authorized")
            self.assertEqual((worktree / "a.txt").read_text(), "one\ntwo\n")
            self.assertEqual(list(evidence.iterdir()), [])

    def test_validation_failure_preserves_diff_and_parent_acceptance_false(self):
        patch = "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            failure = [{"argv": ["python3", "-m", "unittest"], "execution_status": "completed",
                        "result": "fail", "returncode": 1, "duration_ms": 1,
                        "stdout_sha256": impl.PATCH.sha256(b""), "stderr_sha256": impl.PATCH.sha256(b"failed")}]
            with mock.patch.object(impl.AUTO, "run_automatic_task", side_effect=provider_with(patch)), \
                 mock.patch.object(impl, "run_validation", return_value=failure):
                result = impl.run_implementation(
                    repo_root=repo, worktree=worktree, task_id="T040-fail", prompt="Update.",
                    authorized_files=["a.txt"], workspace_config=worktree / "config.yaml",
                    evidence_root=evidence, allow_provider_call=True,
                    validation_commands=[["python3", "-m", "unittest"]],
                )
            self.assertFalse(result["completed"])
            self.assertFalse(result["accepted_by_parent"])
            self.assertEqual((worktree / "a.txt").read_text(), "one\nthree\n")
            self.assertTrue(Path(result["rollback"]["manifest"]).is_file())

    def test_validation_rejects_shell_paths_inline_code_and_unknown_executable(self):
        for argv, code in (
            (["/bin/sh", "-c", "true"], "validation_executable_not_allowed"),
            (["python3", "-c", "print(1)"], "validation_inline_code_forbidden"),
            (["make", "test"], "validation_executable_not_allowed"),
        ):
            with self.subTest(argv=argv), self.assertRaises(impl.ImplementationError) as raised:
                impl._validation_argv(argv)
            self.assertEqual(raised.exception.code, code)

    def test_rollback_rejects_blob_outside_its_bundle(self):
        patch = "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            repo, worktree, evidence = layout(Path(raw))
            with mock.patch.object(impl.AUTO, "run_automatic_task", side_effect=provider_with(patch)):
                result = impl.run_implementation(
                    repo_root=repo, worktree=worktree, task_id="T040-tamper",
                    prompt="Update.", authorized_files=["a.txt"],
                    workspace_config=worktree / "config.yaml", evidence_root=evidence,
                    allow_provider_call=True,
                )
            manifest = Path(result["rollback"]["manifest"])
            value = json.loads(manifest.read_text())
            value["files"][0]["before_blob"] = str(worktree / "b.txt")
            manifest.write_text(json.dumps(value))
            with self.assertRaises(impl.ImplementationError) as raised:
                impl.rollback_implementation(manifest_path=manifest, worktree=worktree)
            self.assertEqual(raised.exception.code, "rollback_blob_invalid")
            self.assertEqual((worktree / "a.txt").read_text(), "one\nthree\n")


if __name__ == "__main__":
    unittest.main()
