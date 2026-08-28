import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins/codexmax-orchestrator"
MODEL = "vendor/new-model"


FAKE_COMMANDCODE = r'''#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args == ["status", "--json"]:
    print(json.dumps({
        "authenticated": True,
        "context_window": 128000,
        "model": "vendor/new-model",
        "provider": "Command Code",
        "user": "operator",
        "version": "9.9.9-fake",
    }))
elif args == ["--list-models"]:
    print("Available models  ·  3 models")
    print()
    print("Open Source")
    print()
    print("vendor/new-model                 generic test model")
    print("deepseek/deepseek-v4-pro         long-context reasoning")
    print("deepseek/deepseek-v4-flash       fast reasoning (default)")
else:
    model = args[args.index("--model") + 1]
    print(json.dumps({
        "route_identity": {
            "declared_route": "worker_commandcode_model",
            "actual_provider": "Command Code",
            "actual_model": model,
            "fallback_used": False,
            "retry_count": 0,
        },
        "content": "fake installed-package result",
    }))
'''


class InstalledProviderTaskJourneyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name)
        self.staged = self.root / "installed" / "codexmax-orchestrator"
        shutil.copytree(PACKAGE, self.staged)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        executable = fake_bin / "commandcode"
        executable.write_text(FAKE_COMMANDCODE, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        self.env = dict(os.environ)
        self.env["PATH"] = str(fake_bin) + os.pathsep + self.env.get("PATH", "")

    def tearDown(self):
        self.temporary.cleanup()

    def test_staged_package_runs_unconfigured_exact_model_with_one_real_process(self):
        script = self.staged / "scripts/run_task_scoped_provider_task.py"
        completed = subprocess.run(
            [
                sys.executable, str(script), "--repo-root", str(self.repo),
                "--request", f"Use {MODEL} through Command Code",
                "--task-id", "installed-journey", "--allow-provider-call",
                "--prompt", "Return one bounded result.", "--read-scope", ".",
                "--evidence-directory", "reports/installed",
                "--expected-artifact", "reports/installed/result.json",
            ],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["completed"])
        self.assertTrue(result["called"])
        self.assertTrue(result["task_local_binding"])
        self.assertFalse(result["binding_persisted"])
        self.assertEqual(result["selection"]["requested_model"], MODEL)
        self.assertEqual(result["manifest"]["attempts"][0]["identity"]["model"], MODEL)
        self.assertTrue((self.repo / "reports/installed/result.json").is_file())
        self.assertTrue(str(script).startswith(str(self.staged)))

    def test_staged_package_automatic_role_selects_without_model_input(self):
        script = self.staged / "scripts/run_automatic_provider_task.py"
        completed = subprocess.run(
            [
                sys.executable, str(script), "--repo-root", str(self.repo),
                "--task-id", "installed-auto", "--allow-provider-call",
                "--role", "documenter", "--prompt", "Document the repository.",
                "--read-scope", ".", "--evidence-directory", "reports/auto",
                "--expected-artifact", "reports/auto/result.json",
            ],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["completed"])
        self.assertEqual(result["selected_role"], "documenter")
        self.assertEqual(result["selected_model"], "deepseek/deepseek-v4-flash")
        self.assertTrue((self.repo / "reports/auto/result.json").is_file())


if __name__ == "__main__":
    unittest.main()
