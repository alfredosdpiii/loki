from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import loki
from tests.helpers import temporary_root


def git(root, *args):
    return subprocess.run(
        [  # noqa: S607 - host Git in disposable repositories
            "git",
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout


class DiffGuardrailTests(unittest.TestCase):
    def test_exact_moves_preserve_tests_but_not_protected_paths(self) -> None:
        content = b"def test_a():\n    assert True\n"
        removed = loki.FileChange("tests/test_old.py", content, None, "100644", None)
        added = loki.FileChange("tests/test_new.py", None, content, None, "100644")
        self.assertEqual([], loki.test_integrity_violations([removed, added]))
        self.assertTrue(
            loki.protected_change_violations(
                [removed, added], {"protected_extra": ["tests/test_old.py"]}
            )
        )
        duplicate = loki.FileChange(
            "tests/test_other.py", content, None, "100644", None
        )
        self.assertTrue(loki.test_integrity_violations([removed, duplicate, added]))

    def test_candidate_read_limit_and_parent_escape(self) -> None:
        with temporary_root() as root, temporary_root() as outside:
            (root / "file").write_bytes(b"12345")
            with self.assertRaises(ValueError):
                loki.candidate_content(root, "file", 4)
            self.assertEqual(
                (b"12345", "100644"), loki.candidate_content(root, "file", 5)
            )
            (root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                loki.candidate_content(root, "escape/file", 5)

    def test_open_parent_is_pinned_during_directory_replacement(self) -> None:
        with temporary_root() as root, temporary_root() as outside:
            (root / "parent").mkdir()
            (root / "parent/file").write_bytes(b"inside")
            (outside / "file").write_bytes(b"outside")
            original_open = os.open

            def replace_after_open(path, flags, *args, **kwargs):
                fd = original_open(path, flags, *args, **kwargs)
                if path == "parent":
                    (root / "parent").rename(root / "moved")
                    (root / "parent").symlink_to(outside, target_is_directory=True)
                return fd

            with patch.object(os, "open", side_effect=replace_after_open):
                self.assertEqual(
                    (b"inside", "100644"),
                    loki.candidate_content(root, "parent/file", 20),
                )

    def test_batch_blobs_preserve_binary_content_and_reject_missing_objects(
        self,
    ) -> None:
        with temporary_root() as root:
            git(root, "init")
            payloads = [b"", b"\0\xff\nheader blob 99\n", b"last byte without newline"]
            for index, payload in enumerate(payloads):
                (root / str(index)).write_bytes(payload)
            git(root, "add", ".")
            git(root, "commit", "-m", "binary baseline")
            for index in range(len(payloads)):
                (root / str(index)).write_bytes(b"changed")
            changes = loki.git_changes(root, None)[1]
            self.assertEqual(payloads, [change.before for change in changes])
            with self.assertRaises(ValueError):
                loki.git_blobs(root, ["0" * 40])

    def test_tracked_parent_escape_still_fails(self) -> None:
        with temporary_root() as root, temporary_root() as outside:
            git(root, "init")
            (root / "nested").mkdir()
            (root / "nested/file").write_text("original")
            git(root, "add", ".")
            git(root, "commit", "-m", "baseline")
            (root / "nested/file").unlink()
            (root / "nested").rmdir()
            (root / "nested").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                loki.git_changes(root, None)

    def test_lock_integrity_is_independent_of_name_approval(self) -> None:
        with temporary_root() as root:
            git(root, "init")
            manifest = root / "package.json"
            lock = root / "package-lock.json"
            manifest.write_text('{"dependencies":{"pkg":"1"}}')
            lock.write_text("{}")
            git(root, "add", ".")
            git(root, "commit", "-m", "base")
            lock.unlink()
            base, changes = loki.git_changes(root, None)
            for approval in (None, ["npm:pkg"]):
                self.assertTrue(
                    any(
                        "tracked lockfile deleted" in item
                        for item in loki.repository_violations(
                            root, {"approved_dependencies": approval}, base, changes
                        )
                    )
                )
            manifest.unlink()
            self.assertEqual(
                [], loki.lockfile_violations(root, loki.git_changes(root, None)[1])
            )
            manifest.write_text("{}")
            lock.symlink_to("package.json")
            self.assertTrue(
                loki.lockfile_violations(root, loki.git_changes(root, None)[1])
            )

    def test_empty_file_commands_do_not_execute_and_real_failures_report(self) -> None:
        with temporary_root() as root:
            command = [sys.executable, "-c", "open('sentinel','w').close()", "{files}"]
            self.assertEqual(
                [],
                loki.command_guardrail_violations(
                    root, {"commands": {"contract": [command]}}, None, []
                ),
            )
            self.assertFalse((root / "sentinel").exists())
            self.assertTrue(
                loki.run_command(
                    [
                        sys.executable,
                        "-c",
                        "import os; os.write(2,b'\\xff'); raise SystemExit(1)",
                    ],
                    root,
                    "contract",
                )
            )
            with self.assertRaises(ValueError):
                loki.validate_config({"commands": {"contracts": []}})

    def test_staged_and_committed_test_deletions_are_checked(self) -> None:
        with temporary_root() as root:
            git(root, "init")
            (root / "tests").mkdir()
            target = root / "tests/test_empty.py"
            target.touch()
            git(root, "add", ".")
            git(root, "commit", "-m", "base")
            base = git(root, "rev-parse", "HEAD").decode().strip()
            target.unlink()
            git(root, "add", "-u")
            self.assertTrue(
                loki.test_integrity_violations(loki.git_changes(root, None)[1])
            )
            git(root, "commit", "-m", "delete")
            self.assertTrue(
                loki.test_integrity_violations(loki.git_changes(root, base)[1])
            )
            for bad in ("", "missing-ref"):
                with self.assertRaises(ValueError):
                    loki.git_changes(root, bad)

    def test_base_owned_policy_blocks_candidate_command(self) -> None:
        with temporary_root() as root:
            git(root, "init")
            (root / ".loki").mkdir()
            (root / "tests/oracles").mkdir(parents=True)
            policy = root / ".loki/loki.json"
            policy.write_text(json.dumps({"protected_extra": ["tests/oracles/**"]}))
            oracle = root / "tests/oracles/a.py"
            oracle.write_text("assert False\n")
            git(root, "add", ".")
            git(root, "commit", "-m", "trusted policy")
            oracle.write_text("assert True\n")
            candidate = {
                "commands": {
                    "contract": [
                        [sys.executable, "-c", "open('sentinel','w').write('bad')"]
                    ]
                }
            }
            policy.write_text(json.dumps(candidate))
            self.assertEqual(1, loki.scan(root, candidate, False, False))
            self.assertFalse((root / "sentinel").exists())
            base, changes = loki.git_changes(root, None)
            self.assertEqual(
                2,
                len(
                    loki.protected_change_violations(
                        changes, loki.base_policy(root, base)
                    )
                ),
            )

    def test_exact_paths_empty_tree_modes_and_git_errors(self) -> None:
        with temporary_root() as root:
            git(root, "init")
            names = ["space name", "tab\tname", 'quote"name', "é"]
            for name in names:
                (root / name).write_bytes(b"")
            base, changes = loki.git_changes(root, None)
            self.assertIsNone(base)
            self.assertEqual(sorted(names), [change.path for change in changes])
            self.assertTrue(all(change.after == b"" for change in changes))
            git(root, "add", ".")
            git(root, "commit", "-m", "base")
            (root / names[0]).chmod(0o755)
            self.assertEqual("100755", loki.git_changes(root, None)[1][0].after_mode)
            (root / names[0]).unlink()
            os.mkfifo(root / names[0])
            with self.assertRaises(ValueError):
                loki.git_changes(root, None)
        with temporary_root() as root:
            self.assertTrue(loki.write_guardrail_violations([root / "a.txt"], root, {}))

    def test_test_heuristics_use_changed_lines(self) -> None:
        changes = [
            loki.FileChange(
                "tests/test_a.py",
                b"def test_a():\n    assert value\n",
                b"@pytest.mark.skip\ndef helper():\n    pass\n",
                "100644",
                "100644",
            )
        ]
        findings = loki.test_integrity_violations(changes)
        self.assertTrue(any("test deleted" in finding for finding in findings))
        self.assertTrue(any("assertion removed" in finding for finding in findings))
        self.assertTrue(any("skip added" in finding for finding in findings))
        with self.assertRaises(ValueError):
            loki.test_integrity_violations(
                [loki.FileChange("tests/test_a.py", b"\xff", b"", "100644", "100644")]
            )


class CommandAdapterTests(unittest.TestCase):
    def test_runs_valid_configured_command_groups_and_bounds_mutmut(self) -> None:
        config = {
            "commands": {
                "contract": [["buf", "breaking", "--against", "{base}"]],
                "property": [["pytest", "tests/properties"]],
                "differential": [["python", "compare.py", "{files}"]],
                "mutation": [["uv", "run", "mutmut", "run", "--max-children", "9"]],
            }
        }
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value="/bin/systemd-run"),
            patch.object(
                loki, "run_command", side_effect=lambda command, _root, label: [label]
            ) as run,
        ):
            self.assertEqual(
                [
                    "contract: buf",
                    "property: pytest",
                    "differential: python",
                    "mutation: uv",
                ],
                loki.command_guardrail_violations(root, config, "main", ["src/app.py"]),
            )
        self.assertEqual(
            ["buf", "breaking", "--against", "main"], run.call_args_list[0].args[0]
        )
        self.assertEqual(
            ["python", "compare.py", "src/app.py"], run.call_args_list[2].args[0]
        )
        self.assertEqual(
            [
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "MemoryMax=8G",
                "uv",
                "run",
                "mutmut",
                "run",
                "--max-children",
                "2",
            ],
            run.call_args_list[3].args[0],
        )
        for call in run.call_args_list:
            self.assertEqual(root, call.args[1])

    def test_command_config_rejects_invalid_shapes_and_missing_base(self) -> None:
        self.assertIn(
            "commands must", loki.configured_commands({"commands": []}, "contract")
        )
        self.assertEqual([], loki.configured_commands({}, "contract"))
        self.assertIn(
            "commands.contract",
            loki.configured_commands({"commands": {"contract": ["bad"]}}, "contract"),
        )
        with temporary_root() as root:
            self.assertEqual(
                ["loki: commands must be a JSON object"] * len(loki.COMMAND_GROUPS),
                loki.command_guardrail_violations(root, {"commands": []}, None, []),
            )
        with temporary_root() as root:
            self.assertEqual(
                ["contract: command requires --base"],
                loki.command_guardrail_violations(
                    root,
                    {"commands": {"contract": [["tool", "{base}"]]}},
                    None,
                    [],
                ),
            )
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value=None),
        ):
            self.assertEqual(
                ["mutation: systemd-run is required for the 8 GB memory limit"],
                loki.command_guardrail_violations(
                    root,
                    {"commands": {"mutation": [["mutmut", "run"]]}},
                    None,
                    [],
                ),
            )
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value=None),
            patch.object(loki, "run_command", return_value=["property ran"]) as run,
        ):
            self.assertEqual(
                [
                    "property ran",
                    "mutation: systemd-run is required for the 8 GB memory limit",
                    "mutation: systemd-run is required for the 8 GB memory limit",
                ],
                loki.command_guardrail_violations(
                    root,
                    {
                        "commands": {
                            "mutation": [["mutmut", "run"], ["mutmut", "run"]],
                            "property": [["python3", "property.py"]],
                        }
                    },
                    None,
                    [],
                ),
            )
            run.assert_called_once_with(
                ["python3", "property.py"], root, "property: python3"
            )
        self.assertIsInstance(
            loki.bounded_mutation_command(["python3", "check.py"]), list
        )


if __name__ == "__main__":
    unittest.main()
