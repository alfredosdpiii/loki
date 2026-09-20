import json
import os
import sys
import time
import unittest
from unittest.mock import patch

import loki
from tests.helpers import temporary_root
from tests.test_repository_guardrails import git


class AdmissionTests(unittest.TestCase):
    def baseline(self, root):
        git(root, "init")
        (root / ".ruff.toml").write_text('[lint]\nselect=["F"]\n')
        (root / "app.py").write_text("def value():\n    return 1\n")
        git(root, "add", ".")
        git(root, "commit", "-m", "baseline")

    def test_invalid_transaction_leaves_all_originals_unchanged(self):
        with temporary_root() as root, temporary_root() as outside:
            self.baseline(root)
            manifest = outside / "batch.json"
            manifest.write_text(
                json.dumps(
                    [
                        {"op": "write", "path": "new.txt", "content": "new"},
                        {
                            "op": "write",
                            "path": "app.py",
                            "content": "value = missing\n",
                        },
                    ]
                )
            )
            with self.assertRaises(ValueError):
                loki.apply_transaction(root, manifest)
            self.assertFalse((root / "new.txt").exists())
            self.assertEqual(
                "def value():\n    return 1\n", (root / "app.py").read_text()
            )

    def test_concurrent_target_change_rejects_without_overwrite(self):
        with temporary_root() as root, temporary_root() as outside:
            self.baseline(root)
            manifest = outside / "batch.json"
            manifest.write_text(
                json.dumps(
                    [{"op": "write", "path": "app.py", "content": "value = 2\n"}]
                )
            )
            original = loki.check_file

            def concurrent_check(*args, **kwargs):
                result = original(*args, **kwargs)
                (root / "app.py").write_text("human_change = 3\n")
                return result

            with patch.object(loki, "check_file", side_effect=concurrent_check):
                with self.assertRaises(ValueError):
                    loki.apply_transaction(root, manifest)
            self.assertEqual("human_change = 3\n", (root / "app.py").read_text())

    def test_rollback_preserves_concurrent_edit_and_restores_other_targets(self):
        with temporary_root() as root, temporary_root() as outside:
            self.baseline(root)
            manifest = outside / "batch.json"
            manifest.write_text(
                json.dumps(
                    [
                        {"op": "write", "path": "first.txt", "content": "transaction"},
                        {"op": "write", "path": "second.txt", "content": "transaction"},
                        {"op": "write", "path": "third.txt", "content": "transaction"},
                    ]
                )
            )
            replace = os.replace

            def fail_third(source, destination, *args, **kwargs):
                if str(destination).endswith("third.txt"):
                    (root / "first.txt").write_text("human edit")
                    raise OSError("simulated disk failure")
                return replace(source, destination, *args, **kwargs)

            with patch.object(os, "replace", side_effect=fail_third):
                with self.assertRaisesRegex(ValueError, "rollback incomplete"):
                    loki.apply_transaction(root, manifest)
            self.assertEqual("human edit", (root / "first.txt").read_text())
            self.assertFalse((root / "second.txt").exists())
            self.assertFalse((root / "third.txt").exists())

    def test_shell_gate_is_conservative_and_nonexecuting(self):
        self.assertIsNone(loki.shell_violation("git status --short"))
        for command in (
            "git reset --hard",
            "printf x > app.py",
            "git diff --output=app.py",
            "echo $(touch canary)",
        ):
            self.assertIsNotNone(loki.shell_violation(command))

    def test_recorded_parser_failure_and_retention(self):
        with temporary_root() as root, temporary_root() as home:
            with (
                patch.dict(os.environ, {"HOME": str(home)}),
                patch.object(loki, "DEFAULT_ROOT", root),
            ):
                with patch.object(sys, "argv", ["loki", "protect", "--record"]):
                    self.assertEqual(2, loki.main())
                self.assertEqual("deny", loki.read_events(root, 1)[0]["outcome"])
                path = loki.event_path(root)
                with path.open("ab") as stream:
                    stream.truncate(5 * 1024 * 1024)
                loki.record_event(root, "protect", [], "allow", time.monotonic())
                self.assertLess(path.stat().st_size, 4096)

    def test_current_user_owned_installation_is_not_independent(self):
        with temporary_root() as root:
            engine = root / "engine.py"
            engine.write_text("pass\n")
            self.assertTrue(loki.installation_violations([engine], os.getuid()))
