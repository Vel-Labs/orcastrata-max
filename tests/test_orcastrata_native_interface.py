import ast
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins/codexmax-orchestrator"
COMMANDS = {
    "orcastrata-assignment": "codexmax-assignment",
    "orcastrata-orchestrate": "codexmax-orchestrate",
    "orcastrata-discover": "codexmax-discover",
    "orcastrata-github": "codexmax-github",
    "orcastrata-plan": "codexmax-plan",
    "orcastrata-route": "codexmax-route",
    "orcastrata-supervise": "codexmax-supervise",
    "orcastrata-audit": "codexmax-verify",
    "orcastrata-audit-full": "codexmax-audit-full",
    "orcastrata-closeout": "codexmax-closeout",
    "orcastrata-config": "codexmax-config",
    "orcastrata-loop": "codexmax-loop",
}


class OrcastrataNativeInterfaceTests(unittest.TestCase):
    def test_commands_are_thin_aliases_to_existing_skills(self):
        paths = sorted((PLUGIN / "commands").glob("*.toml"))
        self.assertEqual(sorted(path.stem for path in paths), sorted(COMMANDS))
        for path in paths:
            command = tomllib.loads(path.read_text(encoding="utf-8"))
            prompt = command["prompt"]
            tokens = [word for word in prompt.split() if word.startswith("$codexmax-orchestrator:")]
            self.assertEqual(tokens, [f"$codexmax-orchestrator:{COMMANDS[path.stem]}"])
            self.assertIn("{{args}}", prompt)
            self.assertTrue((PLUGIN / "skills" / COMMANDS[path.stem] / "SKILL.md").is_file())

    def test_codex_interface_prompts_use_loadable_skills(self):
        manifest = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
        prompts = manifest["interface"]["defaultPrompt"]
        self.assertGreater(len(prompts), 0)
        self.assertLessEqual(len(prompts), 3)
        for prompt in prompts:
            tokens = [word for word in prompt.split() if word.startswith("$codexmax-orchestrator:")]
            self.assertEqual(len(tokens), 1)
            self.assertTrue((PLUGIN / "skills" / tokens[0].split(":", 1)[1] / "SKILL.md").is_file())
            self.assertNotIn("/orcastrata-", prompt)

    def test_bounded_parallel_planning_does_not_require_board_state(self):
        paths = (
            "assets/contracts/guided-journey.md",
            "assets/contracts/implementation-planning.md",
            "skills/codexmax-plan/SKILL.md",
        )
        obsolete_triggers = (
            "Persistent, parallel,", "persistent, parallel,",
            "persistent, gated, parallel,", "gates, parallel or tandem lanes",
            "- parallel or tandem lanes are useful;",
        )
        for path in paths:
            with self.subTest(path=path):
                text = (PLUGIN / path).read_text(encoding="utf-8")
                for trigger in obsolete_triggers:
                    self.assertNotIn(trigger, text)
                self.assertIn("Parallelism alone does not require GoalBuddy or WorkGraph", text)
                self.assertIn("persistent", text)
                self.assertIn("GoalBuddy", text)

    def test_audit_full_is_advisory_and_read_only(self):
        focused = (PLUGIN / "commands/orcastrata-audit.toml").read_text(encoding="utf-8")
        full = (PLUGIN / "skills/codexmax-audit-full/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("codexmax-verify", focused)
        for verdict in ("`ACCEPT`", "`REVISE`", "`BLOCKED`"):
            self.assertIn(verdict, full)
        for boundary in ("read-only", "Only the Parent can accept", "Never repair"):
            self.assertIn(boundary, full)

    def test_umbrella_catalog_is_opt_in_under_github(self):
        skill = (PLUGIN / "skills/codexmax-github/SKILL.md").read_text(encoding="utf-8")
        readme = (PLUGIN / "README.md").read_text(encoding="utf-8")
        for text in (skill, readme):
            self.assertIn("scripts/umbrella_catalog.py", text)
            self.assertIn("--manifest", text)
            self.assertIn("--root", text)
            self.assertIn("--jsonl-out", text)
            self.assertIn("--markdown-out", text)
            self.assertIn("opt-in", text)
        self.assertIn("GitHub-backed project cadence", readme)
        self.assertIn("high-signal events", readme)
        self.assertIn("Synchronization Cadence", skill)
        self.assertIn("Do not use a lifecycle hook to perform GitHub writes", skill)
        self.assertFalse((PLUGIN / "commands/orcastrata-catalog.toml").exists())

    def test_manifest_wires_the_native_hook(self):
        manifest = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["hooks"], "./hooks/hooks.json")
        hooks = json.loads((PLUGIN / "hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
        self.assertEqual(set(hooks), {"SessionStart", "SubagentStart"})
        commands = [item["hooks"][0]["command"] for rows in hooks.values() for item in rows]
        self.assertTrue(all("CLAUDE_PLUGIN_ROOT" in command and "PLUGIN_ROOT" in command for command in commands))

    def test_claude_manifest_preserves_identity_and_components(self):
        manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "codexmax-orchestrator")
        self.assertEqual(manifest["version"], "1.4.3")
        self.assertNotIn("skills", manifest)
        self.assertNotIn("hooks", manifest)
        self.assertTrue((PLUGIN / "skills").is_dir())
        self.assertTrue((PLUGIN / "hooks/hooks.json").is_file())

    def test_claude_manifest_description_is_host_neutral(self):
        manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
        self.assertIn("governed", manifest["description"])
        self.assertNotIn("native-first for Codex", manifest["description"])

    def test_hook_is_bounded_event_specific_and_stdlib_only(self):
        script = PLUGIN / "hooks/orcastrata_context.py"
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(ast.parse(script.read_text(encoding="utf-8")))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(imports, {"json", "sys"})
        for event in ("SessionStart", "SubagentStart"):
            run = subprocess.run(
                [sys.executable, str(script)],
                input=json.dumps({"hook_event_name": event}),
                text=True,
                capture_output=True,
                check=True,
            )
            output = json.loads(run.stdout)
            specific = output["hookSpecificOutput"]
            self.assertEqual(specific["hookEventName"], event)
            self.assertLessEqual(len(run.stdout.encode("utf-8")), 512)
        malformed = subprocess.run(
            [sys.executable, str(script)], input="not-json", text=True,
            capture_output=True, check=True,
        )
        self.assertEqual(json.loads(malformed.stdout), {})

    def test_local_issue_pr_evidence_does_not_select_board_execution(self):
        run = subprocess.run(
            [sys.executable, str(PLUGIN / "hooks/orcastrata_context.py")],
            input=json.dumps({"hook_event_name": "SessionStart"}),
            text=True, capture_output=True, check=True,
        )
        context = json.loads(run.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Local issue/PR evidence stays board-free", context)
        self.assertIn("Board-backed execution uses GitHub workflow", context)
        self.assertIn("Preserve selected GoalBuddy board and governed WorkGraph dependency authority", context)
        self.assertIn("authentication grants no authority", context)
        skill = (PLUGIN / "skills/codexmax-orchestrate/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Use `direct` or bounded native workers within the task grant", skill)
        self.assertIn("PR draft alone does not require GoalBuddy or WorkGraph", skill)
        self.assertIn("GitHub-backed GoalBuddy or\nWorkGraph project", skill)
        self.assertIn("exact repository and effect authority; local evidence grants\nnone", skill)

    def test_cache_parity_ignores_only_pycache_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "codexmax-orchestrator/1.4.3"
            shutil.copytree(PLUGIN, cache)
            generated = cache / "scripts/__pycache__/generated.cpython-313.pyc"
            generated.parent.mkdir(exist_ok=True)
            generated.write_bytes(b"generated bytecode")
            (generated.parent / "generated.pyo").write_bytes(b"optimized bytecode")
            command = [
                sys.executable,
                str(PLUGIN / "scripts/verify_release_parity.py"),
                "verify",
                "--source-root",
                str(PLUGIN),
                "--cache-root",
                str(cache),
            ]
            passing = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(passing.returncode, 0, passing.stdout)

            unexpected = generated.parent / "unexpected.txt"
            unexpected.write_text("not bytecode", encoding="utf-8")
            rejected = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stdout)["failure"], "cache_file_extra")
            unexpected.unlink()

            (cache / "standalone.pyc").write_bytes(b"unexpected bytecode")
            rejected = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stdout)["failure"], "cache_file_extra")


if __name__ == "__main__":
    unittest.main()
