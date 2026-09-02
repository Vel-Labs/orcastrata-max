import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/github_pr_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("github_pr_lifecycle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)

BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40
BOARD_SHA = "sha256:" + "3" * 64


def result(value=b"", *, returncode=0, timed_out=False):
    if not isinstance(value, bytes):
        value = json.dumps(value).encode()
    return {"returncode": returncode, "stdout": value, "stderr": b"", "timed_out": timed_out, "exceeded": None}


def repository(permission="ADMIN"):
    return {
        "archived": False, "disabled": False, "default_branch": "main",
        "full_name": "Vel-Labs/orcastrata-max",
        "permissions": {"admin": permission == "ADMIN", "push": permission in {"ADMIN", "WRITE"}, "pull": True},
    }


def pull(number=12, *, head_sha=HEAD_SHA, body=None):
    return {
        "number": number, "state": "open", "title": "T060", "updated_at": "2026-09-01T00:00:00Z",
        "draft": False, "mergeable": True, "mergeable_state": "clean",
        "body": body or "Closes #7\n\n<!-- orcastrata:lifecycle:T060-W01-A01:issue:7 -->",
        "head": {"ref": "orcastrata/t060", "sha": head_sha},
        "base": {"ref": "main", "sha": BASE_SHA},
    }


class QueueRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, environment):
        self.calls.append((list(argv), dict(environment)))
        if not self.responses:
            raise AssertionError(f"unexpected command: {argv}")
        return self.responses.pop(0)


class GithubPrLifecycleTests(unittest.TestCase):
    def request(self, directory, *, mode="publish"):
        worktree = Path(directory) / "worktree"
        worktree.mkdir()
        registry = Path(directory) / "leases.json"
        claim = {
            "claim_id": "claim-t060", "request_id": "request-t060", "work_item_id": "T060",
            "holder": {"role": "worker", "agent_id": {"value": "T060-W01", "provenance": "parent_assigned"}},
            "attempt": 1, "read_scope": [], "write_scope": ["src/a.py"], "board_sha256": BOARD_SHA,
            "acquired_at": "2026-09-01T00:00:00Z", "expires_at": "2026-09-03T00:00:00Z",
            "fencing_token": 1, "state": "active", "prior_claim_id": None,
            "outcome_history": [{"kind": "claimed", "timestamp": "2026-09-01T00:00:00Z", "reason": "initial_claim"}],
        }
        registry.write_text(json.dumps({"schema_version": 1, "next_fencing_token": 2, "claims": [claim]}), encoding="utf-8")
        return {
            "schema_version": 1, "artifact_type": lifecycle.REQUEST_TYPE, "mode": mode,
            "lifecycle_id": "T060-W01-A01", "target": {"host": "github.com", "repository": "Vel-Labs/orcastrata-max"},
            "expected_user": "velcrafting", "issue_number": 7, "base": "main", "head": "orcastrata/t060",
            "expected_base_sha": BASE_SHA, "expected_head_sha": HEAD_SHA if mode == "observe" else None,
            "worktree": str(worktree.resolve()), "remote": "origin",
            "allowed_paths": ["src/a.py"],
            "lease": {"registry_path": str(registry.resolve()), "claim_id": "claim-t060", "work_item_id": "T060", "holder": claim["holder"], "board_sha256": BOARD_SHA, "fencing_token": 1},
            "commit": None if mode == "observe" else {"message": "T060: bounded PR lifecycle"},
            "pull_request": None if mode == "observe" else {
                "title": "T060: bounded PR lifecycle",
                "body": "Closes #7\n\n<!-- orcastrata:lifecycle:T060-W01-A01:issue:7 -->",
            },
        }

    def execute(self, request, state, runner):
        return lifecycle.execute(
            request, state, runner=runner, gh_resolver=lambda: "/trusted/gh",
            git_resolver=lambda: "/trusted/git", environment_source={"HOME": "/safe", "GH_TOKEN": "drop"},
            now=datetime(2026, 9, 1, 1, tzinfo=timezone.utc),
        )

    def happy_responses(self, *, create=result(pull()), checks=None, reviews=None):
        return [
            result({"login": "velcrafting"}), result(repository()), result([]),
            result(b"WORKTREE"), result(b"https://github.com/Vel-Labs/orcastrata-max.git\n"),
            result((BASE_SHA + "\n").encode()), result(b"main\n"), result(),
            result((BASE_SHA + "\n").encode()), result(b"src/a.py\0"), result(), result(),
            result(b"src/a.py\0"), result(), result((HEAD_SHA + "\n").encode()), result(),
            result([]), create,
            result([{"filename": "src/a.py"}]),
            result({"total_count": len(checks or []), "check_runs": checks or []}),
            result(reviews or []),
        ]

    def test_publish_uses_exact_non_force_commands_and_returns_ready_for_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            responses = self.happy_responses()
            responses[3] = result((str(Path(request["worktree"]).resolve()) + "\n").encode())
            runner = QueueRunner(*responses)
            receipt = self.execute(request, (Path(directory) / "state.json").resolve(), runner)
        self.assertEqual(receipt["status"], "ready_for_audit")
        commands = [call[0] for call in runner.calls]
        push = next(command for command in commands if "push" in command)
        self.assertEqual(push[-3:], ["push", "origin", "HEAD:refs/heads/orcastrata/t060"])
        self.assertFalse(any(item in {"--force", "--force-with-lease", "merge"} for command in commands for item in command))
        self.assertNotIn("GH_TOKEN", runner.calls[0][1])

    def test_scope_and_lease_fail_closed_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            request["allowed_paths"] = ["src/other.py"]
            runner = QueueRunner()
            receipt = self.execute(request, (Path(directory) / "state.json").resolve(), runner)
        self.assertEqual(receipt["error"]["code"], "lease_binding_mismatch")
        self.assertEqual(runner.calls, [])

    def test_unknown_pr_create_reconciles_without_second_post(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            state = (Path(directory) / "state.json").resolve()
            first_responses = self.happy_responses(create=result(timed_out=True))
            first_responses[3] = result((str(Path(request["worktree"]).resolve()) + "\n").encode())
            first_runner = QueueRunner(*first_responses[:18])
            first = self.execute(request, state, first_runner)
            replay = QueueRunner(
                result({"login": "velcrafting"}), result(repository()), result([pull()]),
                result([{"filename": "src/a.py"}]), result({"total_count": 0, "check_runs": []}), result([]),
            )
            second = self.execute(request, state, replay)
        self.assertEqual(first["status"], "unknown")
        self.assertTrue(first["reconcile_required"])
        self.assertEqual(second["status"], "ready_for_audit")
        self.assertFalse(any(command[0][5] == "POST" for command in replay.calls))

    def test_unknown_push_reconciles_remote_sha_before_pr_create(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            state = (Path(directory) / "state.json").resolve()
            responses = self.happy_responses()
            responses[3] = result((str(Path(request["worktree"]).resolve()) + "\n").encode())
            responses[15] = result(timed_out=True)
            first = self.execute(request, state, QueueRunner(*responses[:16]))
            replay = QueueRunner(
                result({"login": "velcrafting"}), result(repository()), result([]),
                result((str(Path(request["worktree"]).resolve()) + "\n").encode()),
                result(b"https://github.com/Vel-Labs/orcastrata-max.git\n"),
                result(f"{HEAD_SHA}\trefs/heads/orcastrata/t060\n".encode()),
                result(pull()), result([{"filename": "src/a.py"}]),
                result({"total_count": 0, "check_runs": []}), result([]),
            )
            second = self.execute(request, state, replay)
        self.assertEqual(first["status"], "unknown")
        self.assertEqual(first["error"]["code"], "push_outcome_unknown")
        self.assertEqual(second["status"], "ready_for_audit")
        self.assertFalse(any("push" in command[0] for command in replay.calls))

    def test_observe_routes_failed_checks_and_review_to_repair_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory, mode="observe")
            runner = QueueRunner(
                result({"login": "velcrafting"}), result(repository()), result([pull()]),
                result([{"filename": "src/a.py"}]),
                result({"total_count": 1, "check_runs": [{"name": "test", "status": "completed", "conclusion": "failure"}]}),
                result([{"state": "CHANGES_REQUESTED"}]),
            )
            receipt = self.execute(request, (Path(directory) / "state.json").resolve(), runner)
        self.assertEqual(receipt["status"], "repair")
        self.assertEqual(receipt["observation"]["reasons"], ["checks_not_green", "review_changes_requested"])
        self.assertFalse(any(command[0][0] == "/trusted/git" for command in runner.calls))

    def test_existing_pr_requires_marker_and_exact_head_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory, mode="observe")
            missing_marker = QueueRunner(
                result({"login": "velcrafting"}), result(repository()),
                result([pull(body="Closes #7")]),
            )
            first = self.execute(request, (Path(directory) / "state.json").resolve(), missing_marker)
            missing_issue = QueueRunner(
                result({"login": "velcrafting"}), result(repository()),
                result([pull(body="<!-- orcastrata:lifecycle:T060-W01-A01:issue:7 -->")]),
            )
            issue_result = self.execute(request, (Path(directory) / "issue-state.json").resolve(), missing_issue)
            wrong_head = QueueRunner(
                result({"login": "velcrafting"}), result(repository()),
                result([pull(head_sha="4" * 40)]),
            )
            second = self.execute(request, (Path(directory) / "other-state.json").resolve(), wrong_head)
        self.assertEqual(first["error"]["code"], "pull_request_body_binding_mismatch")
        self.assertEqual(issue_result["error"]["code"], "pull_request_body_binding_mismatch")
        self.assertEqual(second["error"]["code"], "pull_request_head_sha_mismatch")

    def test_unknown_create_preserves_committed_sha_after_created_head_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            state = (Path(directory) / "state.json").resolve()
            responses = self.happy_responses(create=result(pull(head_sha="4" * 40)))
            responses[3] = result((str(Path(request["worktree"]).resolve()) + "\n").encode())
            receipt = self.execute(request, state, QueueRunner(*responses[:18]))
            persisted = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(persisted["head_sha"], HEAD_SHA)

    def test_state_binding_rejects_changed_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory)
            state = (Path(directory) / "state.json").resolve()
            persisted = lifecycle._state(request, "unknown", head_sha=HEAD_SHA)
            state.write_text(json.dumps(persisted), encoding="utf-8")
            self.assertEqual(persisted["binding"]["allowed_paths"], ["src/a.py"])
            self.assertEqual(persisted["binding"]["expected_base_sha"], BASE_SHA)
            self.assertEqual(persisted["binding"]["lease"], {
                "board_sha256": BOARD_SHA, "claim_id": "claim-t060", "fencing_token": 1,
            })
            self.assertEqual(persisted["binding"]["worktree"], request["worktree"])
            other = Path(directory) / "other-worktree"
            other.mkdir()
            request["worktree"] = str(other.resolve())
            runner = QueueRunner()
            receipt = self.execute(request, state, runner)
        self.assertEqual(receipt["error"]["code"], "state_invalid")
        self.assertEqual(runner.calls, [])

    def test_multiple_pr_matches_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request(directory, mode="observe")
            runner = QueueRunner(result({"login": "velcrafting"}), result(repository()), result([pull(12), pull(13)]))
            receipt = self.execute(request, (Path(directory) / "state.json").resolve(), runner)
        self.assertEqual(receipt["error"]["code"], "multiple_pr_matches")


if __name__ == "__main__":
    unittest.main()
