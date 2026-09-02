import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/github_cli_read.py"
SPEC = importlib.util.spec_from_file_location("github_cli_read", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
github = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(github)


def request(operation, **arguments):
    return {
        "schema_version": 1,
        "artifact_type": github.REQUEST_TYPE,
        "operation": operation,
        "arguments": {
            "host": "github.com",
            "repository": "Vel-Labs/orcastrata-max",
            **arguments,
        },
    }


def result(value=b"{}", *, returncode=0, timed_out=False, exceeded=None, stderr=b""):
    if not isinstance(value, bytes):
        value = json.dumps(value).encode()
    return {
        "returncode": returncode,
        "stdout": value,
        "stderr": stderr,
        "timed_out": timed_out,
        "exceeded": exceeded,
    }


class QueueRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, environment):
        self.calls.append((list(argv), dict(environment)))
        return self.responses.pop(0)


class GithubCliReadTests(unittest.TestCase):
    def execute(self, payload, runner):
        return github.execute(payload, runner=runner, resolver=lambda: "/trusted/gh")

    def assert_read_only(self, calls):
        for argv, _ in calls:
            joined = " ".join(argv)
            self.assertNotIn(" auth token", joined)
            self.assertNotIn("--show-token", argv)
            if "api" in argv:
                self.assertEqual(argv[argv.index("--method") + 1], "GET")

    def test_operation_matrix_returns_only_normalized_data(self):
        repository = {
            "default_branch": "main",
            "full_name": "Vel-Labs/orcastrata-max",
            "permissions": {"admin": False, "push": True, "pull": True},
        }
        issue = {
            "assignees": [{"login": "octo"}],
            "closed_at": None,
            "labels": [{"name": "bug"}],
            "number": 7,
            "state": "open",
            "title": "Bounded read",
            "updated_at": "2026-09-01T00:00:00Z",
        }
        pull = {
            "base": {"ref": "main", "sha": "a" * 40},
            "draft": False,
            "head": {"ref": "feature", "sha": "b" * 40},
            "mergeable": True,
            "mergeable_state": "clean",
            "number": 9,
            "state": "open",
            "title": "Feature",
            "updated_at": "2026-09-01T00:00:00Z",
        }
        cases = [
            ("probeCapability", {}, [result(b"auth detail"), result(repository)], 2),
            ("readRepository", {}, [result(repository)], 1),
            ("listIssues", {"limit": 10}, [result([issue, {**issue, "number": 8, "pull_request": {}}])], 1),
            ("readIssue", {"number": 7}, [result(issue)], 1),
            ("readPullRequest", {"number": 9}, [result(pull)], 1),
            ("listPullRequestChecks", {"number": 9}, [result(pull), result({"total_count": 1, "check_runs": [{"app": {"name": "CI"}, "conclusion": "success", "name": "test", "status": "completed"}]})], 2),
            ("readPullRequestDiffSummary", {"number": 9}, [result([{"additions": 2, "changes": 3, "deletions": 1, "filename": "src/app.py", "status": "modified"}])], 1),
        ]
        for operation, arguments, responses, count in cases:
            with self.subTest(operation=operation):
                runner = QueueRunner(*responses)
                receipt = self.execute(request(operation, **arguments), runner)
                self.assertEqual(receipt["status"], "ok")
                self.assertEqual(receipt["command_count"], count)
                self.assertTrue(all(value is False for value in receipt["effect_boundary"].values()))
                self.assertNotIn("stdout", receipt)
                self.assertNotIn("stderr", receipt)
                self.assert_read_only(runner.calls)
                if operation in {"listIssues", "listPullRequestChecks", "readPullRequestDiffSummary"}:
                    self.assertEqual(set(receipt["data"]), {"items", "limit", "possibly_more"})
        self.assertEqual(cases[0][2][0]["stdout"], b"auth detail")

    def test_exact_target_argv_and_environment_are_bound(self):
        runner = QueueRunner(result({
            "default_branch": "main",
            "full_name": "team/project",
            "permissions": {"pull": True},
        }))
        payload = request("readRepository")
        payload["arguments"] = {"host": "ghe.example.com", "repository": "team/project"}
        receipt = github.execute(
            payload,
            runner=runner,
            resolver=lambda: "/trusted/gh",
            environment_source={
                "HOME": "/safe/home",
                "GH_CONFIG_DIR": "/safe/gh",
                "GH_TOKEN": "must-not-pass",
                "GITHUB_TOKEN": "must-not-pass",
                "GH_HOST": "wrong.example.com",
                "UNRELATED_SECRET": "must-not-pass",
            },
        )
        self.assertEqual(receipt["status"], "ok")
        argv, environment = runner.calls[0]
        self.assertEqual(argv, [
            "/trusted/gh", "api", "--hostname", "ghe.example.com",
            "--method", "GET", "repos/team/project",
        ])
        self.assertEqual(environment["HOME"], "/safe/home")
        self.assertEqual(environment["GH_CONFIG_DIR"], "/safe/gh")
        self.assertEqual(environment["GH_PROMPT_DISABLED"], "1")
        self.assertFalse(set(environment) & {"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "UNRELATED_SECRET"})

    def test_probe_uses_active_auth_without_exposing_auth_output(self):
        runner = QueueRunner(
            result(b"github.com\n token: ghp_secret"),
            result({"default_branch": "main", "full_name": "Vel-Labs/orcastrata-max", "permissions": {"pull": True}}),
        )
        receipt = self.execute(request("probeCapability"), runner)
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(runner.calls[0][0], [
            "/trusted/gh", "auth", "status", "--active", "--hostname", "github.com",
        ])
        self.assertNotIn("ghp_secret", json.dumps(receipt))

    def test_request_boundary_rejects_ambiguous_or_credential_bearing_inputs(self):
        invalid = [
            {**request("readRepository"), "extra": True},
            request("unknown"),
            request("readRepository", repository="https://user:token@github.com/team/project"),
            request("readRepository", host="user@github.com"),
            request("readIssue", number=True),
            request("listIssues", limit=101),
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                resolver = mock.Mock(side_effect=AssertionError("must not resolve gh"))
                receipt = github.execute(payload, runner=mock.Mock(), resolver=resolver)
                self.assertEqual(receipt["status"], "error")
                resolver.assert_not_called()
                self.assertTrue(all(value is False for value in receipt["effect_boundary"].values()))

    def test_failures_never_echo_raw_diagnostics(self):
        failures = [
            result(returncode=1, stderr=b"Authorization: Bearer top-secret"),
            result(timed_out=True),
            result(exceeded="stdout"),
            result(b"not-json"),
            result(b'{"full_name":"a/b","full_name":"secret"}'),
        ]
        expected = [
            "gh_command_failed",
            "gh_timeout",
            "gh_output_limit_exceeded",
            "gh_response_invalid",
            "gh_response_invalid",
        ]
        for response, code in zip(failures, expected):
            with self.subTest(code=code):
                receipt = self.execute(request("readRepository"), QueueRunner(response))
                self.assertEqual(receipt["status"], "error")
                self.assertEqual(receipt["error"]["code"], code)
                encoded = json.dumps(receipt)
                self.assertNotIn("top-secret", encoded)
                self.assertNotIn("not-json", encoded)

    def test_missing_check_total_and_real_process_limits_fail_closed(self):
        pull = {"head": {"sha": "b" * 40}}
        missing_total = QueueRunner(result(pull), result({"check_runs": []}))
        receipt = self.execute(request("listPullRequestChecks", number=9), missing_total)
        self.assertEqual(receipt["error"]["code"], "gh_response_invalid")

        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "gh"
            fake.write_text(
                f"#!{sys.executable}\n"
                "import sys, time\n"
                "if 'slow.example.com' in sys.argv:\n"
                "    time.sleep(1)\n"
                "elif 'stderr.example.com' in sys.argv:\n"
                "    sys.stderr.write('x' * 1024)\n"
                "else:\n"
                "    sys.stdout.write('x' * 1024)\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            cases = (
                ("slow.example.com", "gh_timeout", {"TIMEOUT_SECONDS": 0.05}),
                ("stdout.example.com", "gh_output_limit_exceeded", {"MAX_STDOUT_BYTES": 64}),
                ("stderr.example.com", "gh_output_limit_exceeded", {"MAX_STDERR_BYTES": 64}),
            )
            for host, code, patches in cases:
                payload = request("readRepository")
                payload["arguments"]["host"] = host
                with self.subTest(host=host), mock.patch.multiple(github, **patches):
                    receipt = github.execute(payload, resolver=lambda: str(fake))
                    self.assertEqual(receipt["status"], "error")
                    self.assertEqual(receipt["error"]["code"], code)

    def test_secret_like_structured_values_are_redacted_and_controls_fail(self):
        secret = QueueRunner(result({
            "default_branch": "ghp_abcdefghijklmnop",
            "full_name": "Vel-Labs/orcastrata-max",
            "permissions": {"pull": True},
        }))
        receipt = self.execute(request("readRepository"), secret)
        self.assertEqual(receipt["data"]["default_branch"], "[redacted]")

        control = QueueRunner(result({
            "default_branch": "main\nother",
            "full_name": "Vel-Labs/orcastrata-max",
            "permissions": {"pull": True},
        }))
        receipt = self.execute(request("readRepository"), control)
        self.assertEqual(receipt["error"]["code"], "gh_response_invalid")

    def test_missing_executable_and_malformed_cli_input_fail_closed(self):
        with mock.patch.object(github.shutil, "which", return_value=None):
            receipt = github.execute(request("readRepository"), runner=mock.Mock())
        self.assertEqual(receipt["error"]["code"], "gh_unavailable")

        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input='{"schema_version":1,"schema_version":1}',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        output = json.loads(completed.stdout)
        self.assertEqual(output["status"], "error")
        self.assertNotIn("schema_version", json.dumps(output.get("error", {})))


if __name__ == "__main__":
    unittest.main()
