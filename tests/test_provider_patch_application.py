import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
PATH = ROOT / "plugins/codexmax-orchestrator/scripts/provider_patch_application.py"
SPEC = importlib.util.spec_from_file_location("provider_patch_application_tested", PATH)
patcher = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = patcher
SPEC.loader.exec_module(patcher)


def authorization(root: Path, *paths: str):
    return [
        {"path": path, "before_sha256": patcher.sha256((root / path).read_bytes()), "max_bytes": 4096}
        for path in paths
    ]


class ProviderPatchApplicationTests(unittest.TestCase):
    def test_applies_two_existing_authorized_files_and_rolls_back(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            root = Path(raw)
            (root / "a.txt").write_text("one\ntwo\n")
            (root / "b.txt").write_text("red\nblue\n")
            allowed = authorization(root, "a.txt", "b.txt")
            receipt = patcher.apply_patch(root=root, authorized_files=allowed, patch_text=(
                "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n"
                "--- a/b.txt\n+++ b/b.txt\n@@ -1,2 +1,2 @@\n-red\n+green\n blue\n"
            ))
            self.assertEqual(receipt["changed_paths"], ["a.txt", "b.txt"])
            self.assertEqual((root / "a.txt").read_text(), "one\nthree\n")
            before = receipt.pop("before_bytes")
            rolled = patcher.rollback(root=root, receipt=receipt, before_bytes=before)
            self.assertEqual(rolled["restored_paths"], ["a.txt", "b.txt"])
            self.assertEqual((root / "a.txt").read_text(), "one\ntwo\n")

    def test_rejects_unauthorized_create_delete_rename_and_binary(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            root = Path(raw)
            (root / "a.txt").write_text("one\n")
            allowed = authorization(root, "a.txt")
            cases = (
                ("--- a/b.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-x\n+y\n", "patch_path_not_authorized"),
                ("--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+x\n", "patch_create_delete_forbidden"),
                ("--- a/a.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-one\n+two\n", "patch_rename_forbidden"),
                ("GIT binary patch\n", "patch_binary_forbidden"),
            )
            for text, code in cases:
                with self.subTest(code=code), self.assertRaises(patcher.PatchError) as raised:
                    patcher.apply_patch(root=root, authorized_files=allowed, patch_text=text)
                self.assertEqual(raised.exception.code, code)

    def test_rejects_before_drift_symlink_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            root = Path(raw)
            target = root / "a.txt"
            target.write_text("one\n")
            allowed = authorization(root, "a.txt")
            target.write_text("drift\n")
            with self.assertRaises(patcher.PatchError) as raised:
                patcher.validate_authorized_files(root, allowed)
            self.assertEqual(raised.exception.code, "authorized_file_before_mismatch")

            target.unlink()
            outside = root / "outside.txt"
            outside.write_text("one\n")
            target.symlink_to(outside)
            with self.assertRaises((patcher.PatchError, OSError)):
                patcher.validate_authorized_files(root, authorization(root, "outside.txt")[:-1] + [
                    {"path": "a.txt", "before_sha256": patcher.sha256(b"one\n"), "max_bytes": 10}
                ])

            target.unlink()
            os.link(outside, target)
            with self.assertRaises(patcher.PatchError) as raised:
                patcher.validate_authorized_files(root, [
                    {"path": "a.txt", "before_sha256": patcher.sha256(b"one\n"), "max_bytes": 10}
                ])
            self.assertEqual(raised.exception.code, "authorized_file_unsafe")

    def test_rejects_context_mismatch_and_result_over_byte_ceiling(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            root = Path(raw)
            (root / "a.txt").write_text("one\n")
            allowed = authorization(root, "a.txt")
            with self.assertRaises(patcher.PatchError) as raised:
                patcher.apply_patch(root=root, authorized_files=allowed, patch_text=(
                    "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-wrong\n+two\n"
                ))
            self.assertEqual(raised.exception.code, "patch_context_mismatch")
            allowed[0]["max_bytes"] = 4
            with self.assertRaises(patcher.PatchError) as raised:
                patcher.apply_patch(root=root, authorized_files=allowed, patch_text=(
                    "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+longer\n"
                ))
            self.assertEqual(raised.exception.code, "patch_result_too_large")

    def test_rollback_prevalidates_all_files_before_restoring_any(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as raw:
            root = Path(raw)
            (root / "a.txt").write_text("one\n")
            (root / "b.txt").write_text("red\n")
            receipt = patcher.apply_patch(
                root=root, authorized_files=authorization(root, "a.txt", "b.txt"),
                patch_text=(
                    "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+two\n"
                    "--- a/b.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-red\n+blue\n"
                ),
            )
            before = receipt.pop("before_bytes")
            (root / "a.txt").write_text("drift\n")
            with self.assertRaises(patcher.PatchError) as raised:
                patcher.rollback(root=root, receipt=receipt, before_bytes=before)
            self.assertEqual(raised.exception.code, "authorized_file_drift")
            self.assertEqual((root / "b.txt").read_text(), "blue\n")


if __name__ == "__main__":
    unittest.main()
