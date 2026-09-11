import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "codexmax-orchestrator" / "scripts"))
import synchronize_parent_supervisor as sync


RECEIPT = {
    "goal_slug": "fixture-goal",
    "active_task": "T005",
    "goal_sha256": "a" * 64,
    "board_sha256": "b" * 64,
}


def state_pair(parent, supervisor):
    state = sync.initial_state(RECEIPT, "parent-1", "supervisor-1")
    state["parent_route_contract"] = parent
    state["supervisor_route_contract"] = supervisor
    state["last_event_id"] = "init"
    return state


class SynchronizationContractTests(unittest.TestCase):
    def test_initial_state_uses_canonical_roles(self):
        state = sync.initial_state(RECEIPT, "parent-1", "supervisor-1")
        state["last_event_id"] = "init"
        self.assertEqual((state["parent_route_contract"], state["supervisor_route_contract"]), ("parent", "supervisor"))
        sync._validate_state(state, RECEIPT)

    def test_legacy_pair_remains_readable(self):
        sync._validate_state(state_pair("gpt-5.6-sol", "gpt-5.6-terra:high"), RECEIPT)

    def test_canonical_pair_is_readable(self):
        sync._validate_state(state_pair("parent", "supervisor"), RECEIPT)

    def test_legacy_pair_and_record_hash_chain_are_preserved(self):
        state = state_pair("gpt-5.6-sol", "gpt-5.6-terra:high")
        event1 = {
            "schema_version": 1, "event_id": "evt-legacy-1",
            "timestamp": "2026-09-10T12:00:00Z", "source_role": "parent",
            "actor_id": "parent-1", "event_type": "parent_message",
            "payload": {"message_id": "msg-legacy", "text": "continue"},
        }
        after1, payload1 = sync.transition(state, RECEIPT, event1)
        record1 = sync._record(state, after1, event1, payload1)
        after1["event_sequence"] = 1
        after1["last_event_hash"] = record1["event_hash"]
        after1["last_event_id"] = event1["event_id"]
        event2 = {
            "schema_version": 1, "event_id": "evt-legacy-2",
            "timestamp": "2026-09-10T12:00:01Z", "source_role": "supervisor",
            "actor_id": "supervisor-1", "event_type": "milestone",
            "payload": {"summary": "checked"},
        }
        after2, payload2 = sync.transition(after1, RECEIPT, event2)
        record2 = sync._record(after1, after2, event2, payload2)
        self.assertEqual(after2["parent_route_contract"], "gpt-5.6-sol")
        self.assertEqual(after2["supervisor_route_contract"], "gpt-5.6-terra:high")
        self.assertEqual(record2["previous_event_hash"], record1["event_hash"])
        self.assertEqual(record1["event_hash"], sync._hash({k: v for k, v in record1.items() if k != "event_hash"}))
        self.assertEqual(record2["event_hash"], sync._hash({k: v for k, v in record2.items() if k != "event_hash"}))

    def test_mixed_or_unknown_pairs_rejected(self):
        for pair in (("parent", "gpt-5.6-terra:high"), ("worker", "supervisor"), ("unknown", "unknown")):
            with self.subTest(pair=pair):
                with self.assertRaises(sync.SyncError) as ctx:
                    sync._validate_state(state_pair(*pair), RECEIPT)
                self.assertEqual(ctx.exception.code, "control_route_contract_changed")

    def test_actor_identity_and_event_hash_inputs_remain_bound(self):
        state = sync.initial_state(RECEIPT, "parent-1", "supervisor-1")
        state["last_event_id"] = "init"
        event = {
            "schema_version": 1,
            "event_id": "evt-1",
            "timestamp": "2026-09-10T12:00:00Z",
            "source_role": "parent",
            "actor_id": "parent-1",
            "event_type": "parent_message",
            "payload": {"message_id": "msg-1", "text": "resume"},
        }
        after, payload = sync.transition(state, RECEIPT, event)
        record = sync._record(state, after, event, payload)
        self.assertEqual(record["previous_event_hash"], sync.ZERO_HASH)
        self.assertEqual(record["event_hash"], sync._hash({k: v for k, v in record.items() if k != "event_hash"}))
        self.assertEqual(after["parent_id"], "parent-1")
        bad = copy.deepcopy(event)
        bad["actor_id"] = "supervisor-1"
        with self.assertRaises(sync.SyncError) as ctx:
            sync.transition(state, RECEIPT, bad)
        self.assertEqual(ctx.exception.code, "actor_identity_mismatch")


if __name__ == "__main__":
    unittest.main()
