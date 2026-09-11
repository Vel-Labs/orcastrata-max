"""Regression tests for configurable model identity and fixed control authority."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


_PATH = Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py"
_SPEC = importlib.util.spec_from_file_location("resolve_codexmax_config", _PATH)
config = importlib.util.module_from_spec(_SPEC)
sys.modules["resolve_codexmax_config"] = config
assert _SPEC.loader is not None
_SPEC.loader.exec_module(config)


class CodexmaxPreferenceAuthorityTests(unittest.TestCase):
    def _config(self):
        return copy.deepcopy(config.DEFAULTS)

    def test_control_routes_default_to_unknown_identity(self):
        value = self._config()
        parent = value["route_registry"]["routes"]["parent_sol"]
        supervisor = value["route_registry"]["routes"]["supervisor_terra_high"]
        for route in (parent, supervisor):
            for field in ("exact_model", "provider", "runtime", "reasoning", "independence_group"):
                self.assertEqual(route[field], "unknown")

    def test_shipped_template_matches_unknown_control_identity_defaults(self):
        template = (_PATH.parents[1] / "assets/templates/codexmax.config.yaml").read_text()
        parent = template.split("    parent_sol:", 1)[1].split("    supervisor_terra_high:", 1)[0]
        supervisor = template.split("    supervisor_terra_high:", 1)[1].split("    worker_claude_code_sonnet_5:", 1)[0]
        for block in (parent, supervisor):
            for field in ("exact_model", "provider", "runtime", "independence_group"):
                self.assertIn(f'{field}: "unknown"', block)
        self.assertIn('route_kind: "control"', parent)
        self.assertIn('enabled: false', supervisor)
        self.assertIn('escalation_policy: "explicit_only"', supervisor)

    def test_hard_constraints_parent_model_is_unknown(self):
        self.assertEqual(config.HARD_CONSTRAINTS["route_registry.control.parent_model"], "unknown")

    def test_control_routes_accept_explicit_model_and_reasoning_preferences(self):
        value = self._config()
        parent = value["route_registry"]["routes"]["parent_sol"]
        supervisor = value["route_registry"]["routes"]["supervisor_terra_high"]
        parent["exact_model"] = "provider/actual-parent-model"
        parent["reasoning"] = "medium"
        supervisor["exact_model"] = "provider/actual-supervisor-model"
        supervisor["reasoning"] = "low"

        config.validate_config(value, partial=False)

    def test_control_route_kind_remains_fixed(self):
        value = self._config()
        value["route_registry"]["routes"]["parent_sol"]["route_kind"] = "worker"

        with self.assertRaises(config.UnsafeOverrideError):
            config.validate_config(value, partial=False)

    def test_supervisor_safety_controls_remain_fixed(self):
        value = self._config()
        value["route_registry"]["routes"]["supervisor_terra_high"]["enabled"] = True

        with self.assertRaises(config.UnsafeOverrideError):
            config.validate_config(value, partial=False)

        value = self._config()
        value["route_registry"]["routes"]["supervisor_terra_high"]["escalation_policy"] = "automatic"
        with self.assertRaises((config.ValidationError, config.UnsafeOverrideError)):
            config.validate_config(value, partial=False)


if __name__ == "__main__":
    unittest.main()
