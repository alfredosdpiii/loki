import io
import json
import os
import sys
import unittest
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class ShellPermissionTests(unittest.TestCase):
    def baseline(self, root, *, cwd="."):
        git(root, "init")
        write_file(root, "package.json", '{"scripts":{"test":"touch canary"}}\n')
        write_file(root, "test.js", "test('value', () => {});\n")
        config = {
            "shell_commands": [
                {"command": "npm test", "cwd": cwd, "inputs": ["package.json"]}
            ]
        }
        write_file(root, ".loki/loki.json", json.dumps(config))
        git(root, "add", ".")
        git(root, "commit", "-m", "Reviewed command permission")
        return config

    def check(self, root, command="npm test", **overrides):
        payload = {
            "cwd": str(root),
            "tool_name": "Bash",
            "tool_input": {"command": command},
            **overrides,
        }
        with (
            argv("--root", str(root), "shell", "--harness", "claude"),
            patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
        ):
            return capture_output(loki.main)

    def test_reviewed_command_allowed_without_executing_it(self):
        with temporary_root() as root:
            self.baseline(root)
            write_file(root, "test.js", "test('new test', () => {});\n")
            status, _, diagnostic = self.check(root)
            self.assertEqual(0, status, diagnostic)
            self.assertFalse((root / "canary").exists())

    def test_permissions_never_come_from_candidate_policy(self):
        with temporary_root() as root:
            git(root, "init")
            write_file(root, ".loki/loki.json", "{}")
            git(root, "add", ".")
            git(root, "commit", "-m", "No permissions")
            write_file(
                root,
                ".loki/loki.json",
                json.dumps(
                    {
                        "shell_commands": [
                            {
                                "command": "npm test",
                                "cwd": ".",
                                "inputs": ["package.json"],
                            }
                        ]
                    }
                ),
            )
            write_file(root, "package.json", "{}")
            git(root, "add", ".")
            self.assertEqual(2, self.check(root)[0])

    def test_permissions_require_committed_base(self):
        with temporary_root() as root:
            git(root, "init")
            write_file(root, ".loki/loki.json", "{}")
            self.assertEqual(2, self.check(root)[0])

    def test_changed_inputs_and_policy_block(self):
        for changed in ("package.json", ".loki/loki.json"):
            for staged in (False, True):
                with (
                    self.subTest(changed=changed, staged=staged),
                    temporary_root() as root,
                ):
                    self.baseline(root)
                    (root / changed).write_text("{}")
                    if staged:
                        git(root, "add", changed)
                    self.assertEqual(2, self.check(root)[0])

    def test_missing_symlinked_and_mode_changed_inputs_block(self):
        for change in ("missing", "symlink", "mode", "fifo"):
            with self.subTest(change=change), temporary_root() as root:
                self.baseline(root)
                path = root / "package.json"
                if change == "mode":
                    path.chmod(0o755)
                else:
                    path.unlink()
                    if change == "symlink":
                        path.symlink_to("test.js")
                    if change == "fifo":
                        os.mkfifo(path)
                self.assertEqual(2, self.check(root)[0])

    def test_inputs_must_exist_in_base(self):
        with temporary_root() as root:
            self.baseline(root)
            git(root, "rm", "package.json")
            git(root, "commit", "-m", "Remove required input")
            write_file(root, "package.json", "{}")
            self.assertEqual(2, self.check(root)[0])

    def test_git_index_flags_cannot_hide_input_changes(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), temporary_root() as root:
                self.baseline(root)
                git(root, "update-index", flag, "package.json")
                (root / "package.json").write_text('{"scripts":{"test":"changed"}}')
                self.assertEqual(2, self.check(root)[0])

    def test_committed_symlink_cannot_be_an_input(self):
        with temporary_root() as root:
            self.baseline(root)
            (root / "package.json").unlink()
            (root / "package.json").symlink_to("test.js")
            git(root, "add", ".")
            git(root, "commit", "-m", "Symlink input")
            self.assertEqual(2, self.check(root)[0])

    def test_symlinked_input_parent_blocks_even_identical_bytes(self):
        with temporary_root() as root, temporary_root() as outside:
            config = self.baseline(root)
            write_file(root, "inputs/runner", "unchanged")
            config["shell_commands"][0]["inputs"] = ["inputs/runner"]
            (root / ".loki/loki.json").write_text(json.dumps(config))
            git(root, "add", ".")
            git(root, "commit", "-m", "Pin nested input")
            self.assertEqual(0, self.check(root)[0])
            (root / "inputs/runner").unlink()
            (root / "inputs").rmdir()
            write_file(outside, "runner", "unchanged")
            (root / "inputs").symlink_to(outside, target_is_directory=True)
            self.assertEqual(2, self.check(root)[0])

    def test_exact_command_and_cwd_only(self):
        with temporary_root() as root, temporary_root() as outside:
            self.baseline(root)
            (root / "nested").mkdir()
            for command in (
                "npm test -- --update",
                "npm  test",
                "npm test; git reset --hard",
                "npm test > notes.txt",
                "npm test\npwd",
                "npm test # ignored",
                "npm test $(pwd)",
                "npm test *",
                "npm test {a,b}",
                "npm test ~/test",
                "npm test\x01",
            ):
                with self.subTest(command=command):
                    self.assertEqual(2, self.check(root, command)[0])
            for cwd in ("", ".", str(root / "nested"), str(outside), None):
                with self.subTest(cwd=cwd):
                    self.assertEqual(2, self.check(root, cwd=cwd)[0])
            for extra in (
                {"cwd": str(outside)},
                {"command": "npm test", "script": "pwd"},
            ):
                self.assertEqual(2, self.check(root, tool_input=extra)[0])

    def test_nested_grant_requires_exact_non_symlinked_directory(self):
        with temporary_root() as root:
            (root / "nested").mkdir()
            self.baseline(root, cwd="nested")
            self.assertEqual(0, self.check(root, cwd=str(root / "nested"))[0])
            self.assertEqual(2, self.check(root)[0])
            (root / "alias").symlink_to(root / "nested", target_is_directory=True)
            self.assertEqual(2, self.check(root, cwd=str(root / "alias"))[0])

    def test_configuration_rejects_ambiguous_or_unsafe_grants(self):
        valid = {"command": "npm test", "cwd": ".", "inputs": ["package.json"]}
        malformed = [
            None,
            {},
            ["npm test"],
            [{**valid, "unknown": True}],
            [{**valid, "inputs": []}],
            [{**valid, "inputs": ["../package.json"]}],
            [{**valid, "cwd": "/outside"}],
            [{**valid, "cwd": "a/../b"}],
            [{**valid, "command": "npm test > result.txt"}],
            [{**valid, "command": "npm test *"}],
            [{**valid, "command": "git reset --hard"}],
            [valid, valid],
        ]
        for grants in malformed:
            with self.subTest(grants=grants), self.assertRaises(ValueError):
                loki.validate_config({"shell_commands": grants})

    def test_shell_envelope_is_checked_before_fast_allowlist(self):
        with temporary_root() as root:
            for override in (
                {"tool_name": "Write"},
                {"tool_name": []},
                {"cwd": None},
                {"tool_input": {"command": "pwd", "cwd": "/outside"}},
            ):
                with self.subTest(override=override):
                    self.assertEqual(2, self.check(root, "pwd", **override)[0])

    def test_installed_shell_commands_bind_root_in_nested_process_cwd(self):
        import subprocess

        for managed in (False, True):
            with (
                self.subTest(managed=managed),
                temporary_root() as parent,
                temporary_root() as storage,
            ):
                root = parent / "repo with spaces"
                root.mkdir()
                config = self.baseline(root)
                capture_output(loki.install_target, root)
                loki.install_shell_guard(root)
                if managed:
                    capture_output(loki.install_managed, root, storage)
                git(root, "add", ".")
                git(root, "commit", "-m", "Install reviewed hooks")
                (root / "nested").mkdir()
                for filename, tool in (
                    (".claude/settings.json", "Bash"),
                    (".factory/hooks.json", "Execute"),
                ):
                    document = loki.read_json_object(root / filename)
                    groups = document.get("hooks", document)
                    handler = next(
                        hook["command"]
                        for entry in groups["PreToolUse"]
                        for hook in entry["hooks"]
                        if " shell --harness " in hook["command"]
                    )
                    for directory, expected in ((root, 0), (root / "nested", 2)):
                        result = subprocess.run(
                            ["/bin/sh", "-c", handler],
                            cwd=root / "nested",
                            capture_output=True,
                            text=True,
                            input=json.dumps(
                                {
                                    "cwd": str(directory),
                                    "tool_name": tool,
                                    "tool_input": {"command": "npm test"},
                                }
                            ),
                            check=False,
                            timeout=10,
                        )
                        self.assertEqual(expected, result.returncode, result.stderr)
                self.assertEqual(config, loki.load_config(root))
