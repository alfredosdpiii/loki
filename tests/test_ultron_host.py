"""Ultron host support: minimal install, the ultron preview host and short context."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class MinimalInstallTests(unittest.TestCase):
    def test_minimal_install_writes_only_engine_and_policy(self):
        with temporary_root() as root:
            _, stdout, _ = capture_output(loki.install_minimal, root)
            self.assertIn("minimal", stdout)
            installed = sorted(
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file()
            )
            self.assertEqual([".loki/loki.json", ".loki/loki.py"], installed)
            self.assertEqual(
                Path(loki.__file__).read_bytes(),
                (root / ".loki/loki.py").read_bytes(),
            )

    def test_minimal_install_keeps_existing_policy_and_engine_unless_forced(self):
        with temporary_root() as root:
            write_file(root, ".loki/loki.json", '{"rule_packs": ["core"]}')
            write_file(root, ".loki/loki.py", "# pinned")
            capture_output(loki.install_minimal, root)
            self.assertEqual("# pinned", (root / ".loki/loki.py").read_text())
            capture_output(loki.install_minimal, root, True)
            self.assertNotEqual("# pinned", (root / ".loki/loki.py").read_text())
            self.assertEqual(
                '{"rule_packs": ["core"]}', (root / ".loki/loki.json").read_text()
            )

    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        with argv(*arguments):
            return capture_output(loki.main)

    def test_cli_minimal_flag(self):
        with temporary_root() as root:
            result, _, _ = self.run_main("init", "--minimal", "--dir", str(root))
            self.assertEqual(0, result)
            self.assertTrue((root / ".loki/loki.py").is_file())
            self.assertFalse((root / ".claude").exists())
            self.assertFalse((root / ".github").exists())
            result, _, stderr = self.run_main(
                "init", "--minimal", "--shell-guard", "--dir", str(root)
            )
            self.assertEqual(1, result)
            self.assertIn("--minimal installs only .loki/", stderr)


class UltronHostTests(unittest.TestCase):
    def test_ultron_preview_uses_full_content(self):
        with temporary_root() as root:
            path = write_file(root, "source.py", "old\n")
            payload = {
                "tool_name": "write",
                "tool_input": {"path": str(path), "content": "new\n"},
            }
            self.assertEqual(
                [("source.py", "old\n", "new\n")],
                loki.preview_changes(root, [str(path)], payload, "ultron"),
            )
            edit = {"tool_name": "edit", "tool_input": {"path": str(path)}}
            self.assertIsNone(loki.preview_changes(root, [str(path)], edit, "ultron"))

    def test_ultron_context_is_short_and_follows_rule_packs(self):
        with temporary_root() as root:
            full = loki.injected_context(root, {})
            short = loki.injected_context(root, {}, "ultron")
            self.assertLess(len(short), len(full) // 2)
            self.assertIn("edit() and write()", short)
            self.assertIn("Ruff (Python)", short)
            core = loki.injected_context(root, {"rule_packs": ["core"]}, "ultron")
            self.assertNotIn("Ruff", core)
            self.assertIn("secrets", core)
            self.assertNotIn(
                "Checks:", loki.injected_context(root, {"rule_packs": []}, "ultron")
            )

    def test_context_cli_host_flag(self):
        with temporary_root() as root:
            with argv("--root", str(root), "context", "--host", "ultron"):
                result, stdout, _ = capture_output(loki.main)
            self.assertEqual(0, result)
            context = json.loads(stdout)["hookSpecificOutput"]["additionalContext"]
            self.assertTrue(context.startswith("LOKI guardrails"))

    def test_protect_accepts_ultron_preview_host(self):
        with (
            temporary_root() as root,
            patch.object(loki, "load_config", return_value={}),
            patch.object(loki, "protect_path", return_value=None),
            patch.object(loki, "preview_violations", return_value=["blocked"]) as view,
            patch.object(loki.sys, "stdin") as stdin,
        ):
            stdin.read.return_value = json.dumps(
                {"tool_name": "write", "tool_input": {"path": "a.py", "content": ""}}
            )
            with argv(
                "--root", str(root), "protect", "--file", "a.py", "--preview", "ultron"
            ):
                result, _, stderr = capture_output(loki.main)
            self.assertEqual(2, result)
            self.assertIn("blocked", stderr)
            self.assertEqual("ultron", view.call_args.args[3])


class MinimalRepositoryTests(unittest.TestCase):
    def committed_minimal_repository(self, root: Path) -> None:
        git(root, "init", "-q")
        capture_output(loki.install_minimal, root)
        write_file(root, "app.py", "VALUE = 1\n")
        git(root, "add", ".")
        git(
            root,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "init",
        )

    def test_missing_base_ruff_config_is_reported_not_failed(self):
        with temporary_root() as root:
            self.committed_minimal_repository(root)
            path = write_file(root, "app.py", "VALUE = 2\n")
            with self.assertRaises(loki.MissingRuffConfig):
                loki.ruff_new_violations(root, None, paths={"app.py"})
            with patch.object(loki, "missing_tool", return_value=None):
                warnings: list[str] = []
                self.assertEqual([], loki.check_file(path, root, {}, warnings=warnings))
                self.assertIn("NOT CHECKED python ruff", "\n".join(warnings))
                self.assertIn(
                    "app.py: loki: no committed .ruff.toml",
                    loki.check_file(path, root, {}, True),
                )
                _, _, stderr = capture_output(loki.check_file, path, root, {})
                self.assertIn("NOT CHECKED python ruff", stderr)


if __name__ == "__main__":
    unittest.main()
