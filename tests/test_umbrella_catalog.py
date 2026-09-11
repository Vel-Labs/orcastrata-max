import hashlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins/codexmax-orchestrator"
spec = importlib.util.spec_from_file_location("umbrella_catalog", PLUGIN / "scripts/umbrella_catalog.py")
assert spec and spec.loader
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
pspec = importlib.util.spec_from_file_location("projection", PLUGIN / "scripts/github_umbrella_projection.py")
assert pspec and pspec.loader
projection = importlib.util.module_from_spec(pspec)
pspec.loader.exec_module(projection)


def receipt(repository="Vel-Labs/orcastrata-max"):
    graph = json.loads((PLUGIN / "assets/templates/workgraph-bounded.json").read_text())
    items = graph["work_items"]
    item = items[0]
    snapshot = {"active_task": item["id"], "board_sha256": "sha256:" + "a" * 64,
                "canonical_owner": "GoalBuddy", "capabilities": {"apply": True,
                "migration_available": False, "migration_required": False,
                "pinned_current_schema_version": 2, "recognized_next_schema_version": 3,
                "recover": True, "snapshot": True}, "operation": "snapshot",
                "protocol": "workgraph_goalbuddy_adapter", "schema_version": 1,
                "state_schema_version": 2, "status": "ok",
                "task_statuses": [{"status": "active" if row is item else "queued", "task_id": row["id"]} for row in items]}
    request = {"artifact_type": projection.REQUEST_TYPE, "goalbuddy_snapshot": snapshot,
               "presentation": {"umbrella": {"acceptance_criteria": ["Done"], "labels": ["orcastrata"],
               "non_goals": ["No merge"], "outcome": "Build it", "title": "Catalog test"},
               "issues": [{"labels": [], "non_goals": ["No extra"], "title": row["id"], "work_item_id": row["id"]} for row in items]},
               "schema_version": 1, "target": {"host": "github.com", "repository": repository}, "workgraph": graph}
    return projection.execute(request)


def write_source(root, name, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    (root / name).write_bytes(raw)
    return {"path": name, "raw_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "projection_sha256": value["projection_sha256"], "summary": "A test receipt.",
            "tags": [{"class": "topic", "value": "umbrella", "owner": "orcastrata", "source": "test"}],
            "sensitivity": "public", "exportable": True}


class UmbrellaCatalogTests(unittest.TestCase):
    def test_compile_and_atomic_outputs_are_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "receipt.json"
            value = receipt()
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            source.write_bytes(raw)
            manifest = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [{
                "path": "receipt.json", "raw_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "projection_sha256": value["projection_sha256"], "summary": "A test receipt.",
                "tags": [{"class": "topic", "value": "umbrella", "owner": "orcastrata", "source": "test"}],
                "sensitivity": "public", "exportable": True}]}
            first = catalog.compile_catalog(manifest, root)
            second = catalog.compile_catalog(manifest, root)
            self.assertEqual(first, second)
            self.assertEqual(first["records"][0]["record_sha256"], catalog.digest({k: v for k, v in first["records"][0].items() if k != "record_sha256"}))
            catalog.write_catalog(first, root / "catalog.jsonl", root / "catalog.md")
            self.assertEqual(json.loads((root / "catalog.jsonl").read_text())["records"], first["records"])
            self.assertIn(first["records"][0]["umbrella_id"], (root / "catalog.md").read_text())

    def test_multiple_sources_sort_reorder_and_generated_at(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = receipt(), receipt("Vel-Labs/another")
            entries = [write_source(root, "b.json", second), write_source(root, "a.json", first)]
            manifest = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": entries}
            a = catalog.compile_catalog(manifest, root)
            manifest["entries"].reverse()
            b = catalog.compile_catalog(manifest, root)
            self.assertEqual(a["records"], b["records"])
            self.assertEqual(a, b)
            self.assertEqual(catalog.canonical_jsonl(a), catalog.canonical_jsonl(b))
            timed = {**manifest, "generated_at": "2026-09-02T00:00:00Z"}
            c = catalog.compile_catalog(timed, root)
            self.assertEqual([r["record_sha256"] for r in b["records"]], [r["record_sha256"] for r in c["records"]])

    def test_presentation_change_preserves_identity_and_changes_record_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); first = receipt(); entry = write_source(root, "r.json", first)
            one = catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)["records"][0]
            changed = receipt(); changed["preview"]["umbrella"]["title"] = "Changed title"; changed["projection_sha256"] = catalog.digest(changed["preview"])
            entry = write_source(root, "r.json", changed)
            two = catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)["records"][0]
            self.assertEqual(one["umbrella_id"], two["umbrella_id"]); self.assertNotEqual(one["record_sha256"], two["record_sha256"])

    def test_cli_writes_outputs_and_fails_for_missing_manifest(self):
        schema = json.loads((PLUGIN / "assets/templates/umbrella-catalog-v1-schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        valid = json.loads((PLUGIN / "assets/templates/umbrella-catalog-v1-valid.json").read_text())
        invalid = json.loads((PLUGIN / "assets/templates/umbrella-catalog-v1-invalid.json").read_text())
        empty = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": []}
        self.assertEqual(valid, catalog.compile_catalog(empty))
        self.assertEqual(set(invalid) - set(valid), {"unexpected"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); entry = write_source(root, "r.json", receipt())
            manifest = root / "manifest.json"; manifest.write_text(json.dumps({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}))
            command = [sys.executable, str(PLUGIN / "scripts/umbrella_catalog.py"), "--manifest", str(manifest), "--root", str(root), "--jsonl-out", str(root / "out.jsonl"), "--markdown-out", str(root / "out.md")]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0); self.assertTrue((root / "out.md").exists()); self.assertEqual(json.loads(result.stdout)["status"], "ok")
            missing_command = command.copy(); missing_command[3] = str(root / "missing.json")
            failed = subprocess.run(missing_command, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 2); self.assertEqual(json.loads(failed.stdout)["status"], "error")

    def test_malformed_receipt_matrix_rejected(self):
        cases = []
        def add(name, mutate, code): cases.append((name, mutate, code))
        add("host spaces", lambda r: r["target"].update(host="bad host"), "host_invalid")
        add("host uppercase", lambda r: r["target"].update(host="GITHUB.COM"), "host_invalid")
        add("repository slash", lambda r: r["target"].update(repository="a/b/c"), "repository_invalid")
        add("repository dot", lambda r: r["target"].update(repository="./repo"), "repository_invalid")
        add("umbrella marker", lambda r: r["preview"]["umbrella"].update(stable_id="bad"), "marker_invalid")
        add("umbrella body marker", lambda r: r["preview"]["umbrella"].update(body="valid body"), "marker_invalid")
        add("issue marker", lambda r: r["preview"]["issues"][0].update(stable_id="bad"), "marker_invalid")
        add("missing issue field", lambda r: r["preview"]["issues"][0].pop("ready"), "shape_invalid")
        add("ready type", lambda r: r["preview"]["issues"][0].update(ready="yes"), "issue_identity_invalid")
        add("duplicate work item", lambda r: r["preview"]["issues"][1].update(work_item_id=r["preview"]["issues"][0]["work_item_id"]), "issue_identity_invalid")
        add("empty issues", lambda r: r["preview"].update(issues=[]), "issue_count_invalid")
        add("too many issues", lambda r: r["preview"]["issues"].extend(copy.deepcopy(r["preview"]["issues"]) * 8), "issue_count_invalid")
        add("duplicate labels", lambda r: r["preview"]["issues"][0].update(labels=["x", "x"]), "list_duplicate")
        add("duplicate dependencies", lambda r: r["preview"]["issues"][0].update(dependencies=["x", "x"]), "list_duplicate")
        add("malformed body", lambda r: r["preview"]["issues"][0].update(body="\x01"), "text_invalid")
        add("malformed title", lambda r: r["preview"]["umbrella"].update(title=""), "text_invalid")
        for name, mutate, code in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); value = receipt(); mutate(value)
                value["projection_sha256"] = catalog.digest(value["preview"])
                entry = write_source(root, "r.json", value)
                with self.assertRaisesRegex(catalog.CatalogError, code):
                    catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)

    def test_receipt_and_manifest_boundaries_fail_closed(self):
        cases = []
        bad = receipt(); bad["status"] = "error"; cases.append(bad)
        bad = receipt(); bad["effect_boundary"]["network_used"] = True; cases.append(bad)
        for value in cases:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); entry = write_source(root, "r.json", value)
                with self.assertRaises(catalog.CatalogError):
                    catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); value = receipt(); entry = write_source(root, "r.json", value)
            entry["projection_sha256"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(catalog.CatalogError, "semantic_digest_mismatch"):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
            entry = write_source(root, "r.json", value); entry["extra"] = True
            with self.assertRaises(catalog.CatalogError):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
            with self.assertRaisesRegex(catalog.CatalogError, "manifest_entries_invalid"):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [1]}, root)

    def test_identity_tags_sensitivity_symlink_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); value = receipt(); entry = write_source(root, "r.json", value)
            duplicate = dict(entry); duplicate["path"] = "r.json"
            manifest = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry, duplicate]}
            with self.assertRaisesRegex(catalog.CatalogError, "duplicate_source"):
                catalog.compile_catalog(manifest, root)
            entry = write_source(root, "r.json", value); entry["tags"] = [entry["tags"][0], dict(entry["tags"][0])]
            with self.assertRaisesRegex(catalog.CatalogError, "tag_duplicate"):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
            entry = write_source(root, "r.json", value); entry["sensitivity"], entry["exportable"] = "restricted", True
            with self.assertRaisesRegex(catalog.CatalogError, "restricted_export_invalid"):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
            link = root / "link.json"
            try:
                link.symlink_to(root / "r.json")
            except OSError:
                self.skipTest("symlinks unavailable")
            entry = write_source(root, "link.json", value)
            with self.assertRaises(catalog.CatalogError):
                catalog.compile_catalog({"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}, root)
            entry = write_source(root, "r.json", value); manifest = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}
            out_json, out_md = root / "catalog.jsonl", root / "catalog.md"; out_json.write_text("old"); out_md.write_text("old")
            catalog.write_catalog(catalog.compile_catalog(manifest, root), out_json, out_md)
            self.assertNotEqual(out_json.read_text(), "old"); self.assertIn("# Orcastrata", out_md.read_text())

    def test_digest_and_containment_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "receipt.json"
            value = receipt()
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            source.write_bytes(raw)
            entry = {"path": "receipt.json", "raw_sha256": "sha256:" + "0" * 64,
                     "projection_sha256": value["projection_sha256"], "summary": "x", "tags": [],
                     "sensitivity": "public", "exportable": True}
            manifest = {"artifact_type": catalog.MANIFEST_TYPE, "schema_version": 1, "entries": [entry]}
            with self.assertRaisesRegex(catalog.CatalogError, "raw_digest_mismatch"):
                catalog.compile_catalog(manifest, root)
            entry["path"] = "../receipt.json"
            with self.assertRaisesRegex(catalog.CatalogError, "source_path_uncontained"):
                catalog.compile_catalog(manifest, root)


if __name__ == "__main__":
    unittest.main()
