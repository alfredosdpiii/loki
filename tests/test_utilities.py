from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import loki
from tests.helpers import temporary_root, write_file


class ConfigAndPathTests(unittest.TestCase):
    def test_load_config_defaults_and_validates_object(self) -> None:
        with temporary_root() as root:
            self.assertEqual({}, loki.load_config(root))
            write_file(root, ".loki/loki.json", '{"languages":{"go":false}}')
            self.assertEqual({"languages": {"go": False}}, loki.load_config(root))
            write_file(root, ".loki/loki.json", "[]")
            with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                loki.load_config(root)
            write_file(root, ".loki/loki.json", "{")
            with self.assertRaisesRegex(ValueError, "invalid loki config"):
                loki.load_config(root)

    def test_language_enabled_defaults_and_honors_false(self) -> None:
        cases = (
            ({}, True),
            ({"languages": []}, True),
            ({"languages": {"go": 0}}, True),
            ({"languages": {"rust": False}}, True),
            ({"languages": {"go": False}}, False),
        )
        for config, expected in cases:
            with self.subTest(config=config):
                self.assertEqual(expected, loki.language_enabled(config, "go"))

    def test_relative_and_resolved_paths(self) -> None:
        with temporary_root() as root:
            inside = root / "src" / "app.py"
            outside = root.parent / "outside.py"
            self.assertEqual("src/app.py", loki.relative_display(inside, root))
            self.assertEqual(str(outside), loki.relative_display(outside, root))
            self.assertEqual(
                (root / "app.py").resolve(), loki.resolve_file("app.py", root)
            )
            self.assertEqual(outside.resolve(), loki.resolve_file(str(outside), root))

    def test_path_matches_normalizes_and_supports_tree_patterns(self) -> None:
        cases = {
            ("./.loki/loki.py", ".loki/**"): True,
            (".loki", "./.loki/**"): True,
            (".loki\\loki.py", ".loki/**"): True,
            (".loki/loki.py", ".loki\\**"): True,
            ("src/app.py", "src/*.py"): True,
            ("src/nested/app.py", "src/*.py"): True,
            ("src/app.js", "src/*.py"): False,
        }
        for (path, pattern), expected in cases.items():
            with self.subTest(path=path, pattern=pattern):
                self.assertEqual(expected, loki.path_matches(path, pattern))

    def test_protect_path_handles_overrides_extras_and_external_paths(self) -> None:
        with temporary_root() as root:
            self.assertIn(
                "protected file", loki.protect_path(".ruff.toml", root, {}) or ""
            )
            self.assertIn(
                "protected file",
                loki.protect_path(
                    "private/key", root, {"protected_extra": ["private/**"]}
                )
                or "",
            )
            with self.assertRaises(ValueError):
                loki.protect_path("src/app.py", root, {"protected_extra": "bad"})
            self.assertIn(
                "outside project root",
                loki.protect_path(str(root.parent / "outside"), root, {}) or "",
            )
            with patch.dict(os.environ, {"LOKI_ALLOW_PROTECTED": "1"}):
                self.assertIsNone(loki.protect_path(".ruff.toml", root, {}))

    def test_harness_paths_checks_envelopes_and_all_patch_targets(self) -> None:
        with temporary_root() as root:
            payload = {
                "cwd": str(root),
                "tool_name": "Write",
                "tool_input": {"file_path": "src/app.py"},
            }
            self.assertEqual(
                [str(root / "src/app.py")],
                loki.harness_paths(json.dumps(payload), "claude"),
            )
            payload.update(
                tool_name="apply_patch",
                tool_input={
                    "command": '*** Begin Patch\n*** Add File: "new.py"\n+content\n'
                    "*** Update File: old.py\n*** Move to: .loki/loki.py\n"
                    "*** Delete File: gone.py\n*** End Patch"
                },
            )
            self.assertEqual(
                [
                    str(root / name)
                    for name in ('"new.py"', "old.py", ".loki/loki.py", "gone.py")
                ],
                loki.harness_paths(json.dumps(payload), "codex"),
            )
            for raw in ("not json", "{}", '{"tool_input":{}}'):
                with self.assertRaises(ValueError):
                    loki.harness_paths(raw, "claude")
        for body in (
            "*** Add File: a",
            "*** Update File: a",
            "*** Move to: a",
            "*** Delete File: a\n+bad",
            "*** Add File: a\n+ok\n*** Unknown",
        ):
            with self.assertRaises(ValueError):
                loki.patch_paths(f"*** Begin Patch\n{body}\n*** End Patch")


class CommandUtilityTests(unittest.TestCase):
    def test_command_output_strips_and_combines_streams(self) -> None:
        result = subprocess.CompletedProcess([], 1, " out \n\n", " err \n")
        self.assertEqual(["out", "err"], loki.command_output(result))

    def test_run_command_handles_success_failure_empty_output_and_errors(self) -> None:
        with temporary_root() as root:
            success = subprocess.CompletedProcess([], 0, "", "")
            failure = subprocess.CompletedProcess([], 3, "bad\n", "worse\n")
            empty = subprocess.CompletedProcess([], 7, "", "")
            with patch.object(
                loki.subprocess, "run", side_effect=[success, failure, empty]
            ):
                self.assertEqual([], loki.run_command(["tool"], root, "lint"))
                self.assertEqual(
                    ["lint: bad", "lint: worse"],
                    loki.run_command(["tool"], root, "lint"),
                )
                self.assertEqual(
                    ["lint: exited 7"], loki.run_command(["tool"], root, "lint")
                )
            for error in (OSError("missing"), subprocess.TimeoutExpired("tool", 1)):
                with (
                    self.subTest(error=type(error).__name__),
                    patch.object(loki.subprocess, "run", side_effect=error),
                ):
                    self.assertIn("lint:", loki.run_command(["tool"], root, "lint")[0])

    def test_dependency_name_and_local_module(self) -> None:
        self.assertEqual("my_package", loki.dependency_name(" My-Package>=2"))
        self.assertIsNone(loki.dependency_name(" @invalid"))
        with temporary_root() as root:
            write_file(root, "module.py")
            (root / "package").mkdir()
            self.assertTrue(loki.local_python_module(root, "module"))
            self.assertTrue(loki.local_python_module(root, "package"))
            self.assertFalse(loki.local_python_module(root, "missing"))

    def test_selected_paths_rejects_invalid_and_oversized_targets(self) -> None:
        parser = loki.build_parser()
        args = parser.parse_args(
            ["protect", "--file", "a", "--file", "b", "--file", "a"]
        )
        self.assertEqual(["a", "b"], loki.selected_paths(args, parser))
        for path in ("", "bad\0path"):
            with self.assertRaises(ValueError):
                loki.selected_paths(
                    argparse.Namespace(harness=None, file=[path]), parser
                )
        with patch.object(
            sys, "stdin", Mock(read=Mock(return_value="x" * (4 * 1024 * 1024 + 1)))
        ):
            with self.assertRaises(ValueError):
                loki.selected_paths(
                    argparse.Namespace(harness="claude", file=None), parser
                )

    def test_build_parser_accepts_every_command(self) -> None:
        parser = loki.build_parser()
        self.assertEqual("loki", parser.prog)
        self.assertEqual(
            "protect", parser.parse_args(["protect", "--file", "x"]).command
        )
        self.assertEqual(
            "hook", parser.parse_args(["hook", "--harness", "codex"]).command
        )
        scan = parser.parse_args(["scan", "--online", "--strict", "--base", "main"])
        self.assertEqual((True, True, "main"), (scan.online, scan.strict, scan.base))
        init = parser.parse_args(["init", "--force"])
        self.assertEqual((True, "."), (init.force, init.dir))
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        with self.assertRaises(SystemExit):
            parser.parse_args(["hook", "--harness", "other"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["task"])


if __name__ == "__main__":
    unittest.main()
