import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/compile_terminal_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("compile_terminal_lifecycle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class TerminalLifecycleChildCoverageTest(unittest.TestCase):
    def test_unpaired_terminal_host_record_is_allowed_but_active_agent_is_not(self):
        child_plan = {
            "parent": {"thread_id": "parent-thread", "host_id": "host", "agent_path": "/root"},
            "descendants": [],
        }
        resources = [
            {
                "resource_class": "parent_thread",
                "target": {"thread_id": "parent-thread", "host_id": "host"},
                "ownership": "shared",
                "lifecycle": "active",
            },
            {
                "resource_class": "collaboration_agent",
                "target": {"agent_id": "/root", "host_id": "host"},
                "ownership": "shared",
                "lifecycle": "active",
            },
            {
                "resource_class": "collaboration_agent",
                "target": {"agent_id": "/root/completed-worker", "host_id": "host"},
                "ownership": "goal_owned",
                "lifecycle": "terminal",
                "capabilities": {"archive": False, "remove": False},
            },
        ]
        anchors = {"parent_authority": {"authority_id": "parent-thread"}}

        self.assertEqual(lifecycle._child_resource_maps(child_plan, resources, anchors), {})
        terminal = {
            **resources[-1],
            "resource_id": "completed-worker",
            "capabilities": {"archive": False, "unpin": False, "interrupt": False, "remove": False},
        }
        self.assertEqual(
            lifecycle._compile_action(terminal, {}),
            ("retain_terminal_host_record", "terminal_agent_host_record_only"),
        )

        active_resources = copy.deepcopy(resources)
        active_resources[-1]["lifecycle"] = "active"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(child_plan, active_resources, anchors)

        absent_resources = copy.deepcopy(resources)
        absent_resources[-1]["lifecycle"] = "absent"
        self.assertEqual(lifecycle._child_resource_maps(child_plan, absent_resources, anchors), {})

        absent_archivable_resources = copy.deepcopy(absent_resources)
        absent_archivable_resources[-1]["capabilities"]["archive"] = True
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(child_plan, absent_archivable_resources, anchors)

        absent_removable_resources = copy.deepcopy(absent_resources)
        absent_removable_resources[-1]["capabilities"]["remove"] = True
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(child_plan, absent_removable_resources, anchors)

        archivable_resources = copy.deepcopy(resources)
        archivable_resources[-1]["capabilities"]["archive"] = True
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(child_plan, archivable_resources, anchors)

        removable_resources = copy.deepcopy(resources)
        removable_resources[-1]["capabilities"]["remove"] = True
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(child_plan, removable_resources, anchors)

        listed_plan = copy.deepcopy(child_plan)
        listed_plan["descendants"] = [{
            "thread_id": "missing-thread",
            "agent_path": "/root/completed-worker",
        }]
        with self.assertRaisesRegex(lifecycle.LifecycleError, "parent_child_plan_mismatch"):
            lifecycle._child_resource_maps(listed_plan, resources, anchors)


if __name__ == "__main__":
    unittest.main()
