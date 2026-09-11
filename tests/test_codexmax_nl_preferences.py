import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "codexmax-orchestrator" / "scripts"))
import resolve_codexmax_config as resolver


class NaturalLanguagePreferenceContractTests(unittest.TestCase):
    def test_docs_define_scope_runtime_and_exact_choice(self):
        skill = (ROOT / "plugins/codexmax-orchestrator/skills/codexmax-config/SKILL.md").read_text()
        contract = (ROOT / "plugins/codexmax-orchestrator/assets/contracts/codexmax-config.md").read_text()
        for text in (skill, contract):
            normalized = " ".join(text.split())
            self.assertIn("Precedence is user < project < task", normalized)
            self.assertIn("Task/session or active goal/checkpoint identity must survive resume", normalized)
            self.assertIn("A native work-role preference is stored in the existing `role_preferences.roles.<role>` mapping", normalized)
            self.assertIn("An unavailable `exact_model` returns `resolution_need`", normalized)
            self.assertIn("resolution_need", normalized)
            self.assertIn("controller_execution", normalized)
            self.assertIn("final acceptance", normalized)

    def test_task_layer_overrides_project_and_provenance(self):
        project = {"headless_dispatch": copy.deepcopy(resolver.DEFAULTS["headless_dispatch"])}
        task = {"headless_dispatch": copy.deepcopy(resolver.DEFAULTS["headless_dispatch"])}
        project["headless_dispatch"]["role_priorities"]["worker"]["route_01"] = "worker_luna_xhigh"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_02"] = "worker_minimax_m3_tool_loop"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_03"] = "worker_claude_code_sonnet_5"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_04"] = "worker_grok_4_6"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_05"] = "worker_codex_spark"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_06"] = "none"
        task["headless_dispatch"] = copy.deepcopy(project["headless_dispatch"])
        task["headless_dispatch"]["role_priorities"]["worker"]["route_01"] = "worker_minimax_m3_tool_loop"
        task["headless_dispatch"]["role_priorities"]["worker"]["route_02"] = "worker_luna_xhigh"
        receipt = resolver.resolve([
            resolver.Layer("project", "project", "project", True, None, project),
            resolver.Layer("task", "task", "goal:T", True, None, task),
        ])
        worker = receipt["effective_config"]["headless_dispatch"]["role_priorities"]["worker"]
        self.assertEqual(worker["route_01"], "worker_minimax_m3_tool_loop")
        self.assertEqual(receipt["provenance"]["headless_dispatch.role_priorities.worker.route_01"]["source"], "task")

    def test_inactive_expired_task_does_not_override_project(self):
        project = {"headless_dispatch": copy.deepcopy(resolver.DEFAULTS["headless_dispatch"])}
        task = {"headless_dispatch": copy.deepcopy(resolver.DEFAULTS["headless_dispatch"])}
        project["headless_dispatch"]["role_priorities"]["worker"]["route_01"] = "worker_luna_xhigh"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_02"] = "worker_minimax_m3_tool_loop"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_03"] = "worker_claude_code_sonnet_5"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_04"] = "worker_grok_4_6"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_05"] = "worker_codex_spark"
        project["headless_dispatch"]["role_priorities"]["worker"]["route_06"] = "none"
        task["headless_dispatch"] = copy.deepcopy(project["headless_dispatch"])
        task["headless_dispatch"]["role_priorities"]["worker"]["route_01"] = "worker_minimax_m3_tool_loop"
        task["headless_dispatch"]["role_priorities"]["worker"]["route_02"] = "worker_luna_xhigh"
        receipt = resolver.resolve([
            resolver.Layer("project", "project", "project", True, None, project),
            resolver.Layer("task", "task", "goal:expired", False, "expired_goal_or_identity_mismatch", task),
        ])
        worker = receipt["effective_config"]["headless_dispatch"]["role_priorities"]["worker"]
        self.assertEqual(worker["route_01"], "worker_luna_xhigh")
        self.assertEqual(receipt["provenance"]["headless_dispatch.role_priorities.worker.route_01"]["source"], "project")


if __name__ == "__main__":
    unittest.main()

class RolePreferenceSchemaTests(unittest.TestCase):
    def test_controller_preference_is_separate_from_task_roles_and_has_provenance(self):
        config = {
            "role_preferences": {
                "controller": {
                    "selection_mode": "exact",
                    "exact_model": "gpt-5.6-luna",
                    "reasoning_effort": "high",
                }
            }
        }
        resolver.validate_config(config, partial=True)
        receipt = resolver.resolve([
            resolver.Layer("task", "task", "goal:T", True, None, config)
        ])
        effective = receipt["effective_config"]["role_preferences"]
        self.assertEqual(effective["controller"]["exact_model"], "gpt-5.6-luna")
        self.assertNotIn("controller", resolver.ROLE_NAMES)
        self.assertEqual(
            receipt["provenance"]["role_preferences.controller.exact_model"]["lifetime"],
            "goal:T",
        )

    def test_controller_preference_unknown_field_fails_closed(self):
        with self.assertRaises(resolver.ValidationError):
            resolver.validate_config({
                "role_preferences": {
                    "controller": {"selection_mode": "default", "provider": "x"}
                }
            }, partial=True)

    def test_partial_exact_overlay_can_defer_to_merged_validation(self):
        resolver.validate_config({
            "role_preferences": {"roles": {"worker": {"selection_mode": "exact"}}}
        }, partial=True)

    def test_full_exact_preference_requires_model_and_rejects_whitespace(self):
        full = copy.deepcopy(resolver.DEFAULTS)
        full["role_preferences"]["roles"]["worker"] = {
            "selection_mode": "exact", "exact_model": "unknown", "reasoning_effort": "unknown"
        }
        with self.assertRaises(resolver.ValidationError):
            resolver.validate_config(full, partial=False)
        full["role_preferences"]["roles"]["worker"]["exact_model"] = "   "
        with self.assertRaises(resolver.ValidationError):
            resolver.validate_config(full, partial=False)

    def test_role_preference_unknown_field_fails_closed(self):
        with self.assertRaises(resolver.ValidationError):
            resolver.validate_config({
                "role_preferences": {"roles": {"worker": {"selection_mode": "default", "provider": "x"}}}
            }, partial=True)
