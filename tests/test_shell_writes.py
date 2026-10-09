"""`shell-writes`: shell commands that would write source or configuration past Loki's before-write check."""

from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class ShellWriteTargetTests(unittest.TestCase):
    def targets(self, command):
        return loki.shell_write_targets(command)

    def test_write_forms_are_found(self):
        cases = {
            "echo x > src/a.py": [("src/a.py", "redirect")],
            "echo x >> a.py": [("a.py", "redirect")],
            "make 2> err.log": [("err.log", "redirect")],
            "make &> all.log": [("all.log", "redirect")],
            "printf data | tee -a one.py two.py": [
                ("one.py", "tee"),
                ("two.py", "tee"),
            ],
            "sed -i 's/a/b/' x.py": [("x.py", "sed -i")],
            "sed -i.bak -e 's/a/b/' x.py": [("x.py", "sed -i")],
            "perl -pi -e 's/a/b/' x.py y.py": [
                ("x.py", "perl -i"),
                ("y.py", "perl -i"),
            ],
            "cp a.py b.py": [("b.py", "cp")],
            "mv -t dst a.py b.py": [("dst/a.py", "mv"), ("dst/b.py", "mv")],
            "dd if=/dev/zero of=z.bin": [("z.bin", "dd")],
            "sudo tee x.conf": [("x.conf", "tee")],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(expected, self.targets(command))

    def test_here_document_bodies_are_data(self):
        command = "cat > out.py <<'EOF'\nprint('a > b; c | d')\nEOF\necho done"
        self.assertEqual([("out.py", "redirect")], self.targets(command))

    def test_commands_that_write_no_file(self):
        for command in (
            "pytest -q 2>&1 | tail -5",
            "rg -n foo src > /dev/null",
            "sed -n 1p a.py",
            "git status && git log --oneline -3",
            "make 2>/dev/stderr",
        ):
            with self.subTest(command=command):
                self.assertEqual([], self.targets(command))

    def test_unparseable_command_is_unknown(self):
        self.assertIsNone(self.targets("echo 'unterminated > a.py"))


class ShellWritesViolationTests(unittest.TestCase):
    def violation(self, root, command, cwd=None):
        return loki.shell_writes_violation(command, root, cwd or root)

    def test_source_and_config_writes_are_denied(self):
        with temporary_root() as root:
            write_file(root, "src/a.py", "x = 1\n")
            for command in (
                "echo x > src/a.py",
                "sed -i 's/1/2/' src/a.py",
                "printf x | tee package.json",
                "cp /etc/hostname src/",
            ):
                with self.subTest(command=command):
                    self.assertIn(
                        "would skip Loki's write check",
                        self.violation(root, command) or "",
                    )

    def test_notes_data_outside_and_ignored_writes_are_allowed(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, ".gitignore", "build/\n")
            for command in (
                "echo hi > notes.md",
                "git diff > change.patch",
                "npm run build > build/log.txt && echo ok > build/out.js",
                "echo x > /tmp/elsewhere.py",
                "rg -n foo > /dev/null",
                "echo $HOME > $OUT",
            ):
                with self.subTest(command=command):
                    self.assertIsNone(self.violation(root, command))

    def test_protected_policy_is_denied_with_its_own_message(self):
        with temporary_root() as root:
            message = self.violation(root, "echo x >> .loki/loki.json")
            self.assertIn("protected file: .loki/loki.json", message or "")

    def test_relative_targets_resolve_from_the_command_cwd(self):
        with temporary_root() as root:
            write_file(root, "pkg/mod.py", "")
            message = self.violation(root, "echo x > mod.py", cwd=root / "pkg")
            self.assertIn("into pkg/mod.py", message or "")


class ShellWritesCliTests(unittest.TestCase):
    def run_cli(self, root, command):
        payload = json.dumps({"command": command, "cwd": str(root)})
        with (
            patch("sys.stdin", io.StringIO(payload)),
            argv("--root", str(root), "shell-writes"),
        ):
            status, _, stderr = capture_output(loki.dispatch_main)
        return status, stderr

    def test_exit_status_and_reason(self):
        with temporary_root() as root:
            self.assertEqual((0, ""), self.run_cli(root, "pytest -q"))
            status, stderr = self.run_cli(root, "echo x > app.py")
            self.assertEqual(2, status)
            self.assertIn("into app.py", stderr)


if __name__ == "__main__":
    unittest.main()
