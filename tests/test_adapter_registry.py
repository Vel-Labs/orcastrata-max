import importlib.util
from pathlib import Path
import sys
import unittest


_PATH = Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts/adapter_registry.py"
_SPEC = importlib.util.spec_from_file_location("adapter_registry", _PATH)
adapter_registry = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules["adapter_registry"] = adapter_registry
_SPEC.loader.exec_module(adapter_registry)


class DeclarativeModelCandidateTests(unittest.TestCase):
    def _binding(self, model="vendor/model-x"):
        route = {
            "provider": "Command Code", "exact_model": "deepseek/deepseek-v4-pro",
            "route_id": "commandcode-subscription-deepseek-v4-pro",
            "runtime": "Command Code", "reasoning": "provider_default",
            "billing_basis": "subscription", "independence_group": "commandcode_gateway",
        }
        bid = adapter_registry.derive_binding_id(
            adapter_type="commandcode", route_name="worker_deepseek_v4_pro",
            credential_kind="host_managed", opaque_id="test-host", exact_model=model,
        )
        return adapter_registry.build_binding(
            binding_id=bid, adapter_type="commandcode", route_name="worker_deepseek_v4_pro",
            route=route, task_profile={"profile": "test"}, credential_kind="host_managed",
            opaque_id="test-host", exact_model=model,
        )

    def test_new_exact_model_is_configured_not_qualified(self):
        binding = self._binding()
        receipt = adapter_registry.validate_registry(
            adapter_registry.build_registry({binding["binding_id"]: binding}),
            evaluated_at="1970-01-01T00:00:00Z", configuration_only=True,
        )
        self.assertEqual(binding["route"]["exact_model"], "vendor/model-x")
        self.assertEqual(receipt["binding_states"][binding["binding_id"]], "configured")

    def test_model_identity_is_part_of_binding_identity(self):
        self.assertNotEqual(self._binding("vendor/a")["binding_id"], self._binding("vendor/b")["binding_id"])

    def test_secret_like_model_is_rejected(self):
        with self.assertRaises(adapter_registry.AdapterRegistryError):
            self._binding("https://secret.example/model")


if __name__ == "__main__":
    unittest.main()
