from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import loki
from tests.helpers import argv, capture_output, temporary_root


class MainTests(unittest.TestCase):
    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        with argv(*arguments):
            result, stdout, stderr = capture_output(loki.main)
        return result, stdout, stderr

    def test_init_success_and_failure(self) -> None:
        with temporary_root() as root, patch.object(loki, "install_target") as install:
            result, _, _ = self.run_main("init", "--dir", str(root), "--force")
            self.assertEqual(0, result)
            install.assert_called_once_with(Path(root), True)
        with patch.object(loki, "install_target", side_effect=ValueError("bad config")):
            result, _, stderr = self.run_main("init")
            self.assertEqual(1, result)
            self.assertIn("loki: bad config", stderr)
        with patch.object(loki, "install_target", side_effect=OSError("denied")):
            result, _, stderr = self.run_main("init")
            self.assertEqual(1, result)
            self.assertIn("loki: denied", stderr)

    def test_invalid_config_exit_code_depends_on_command(self) -> None:
        with patch.object(loki, "load_config", side_effect=ValueError("bad")):
            for arguments, expected in (
                (["protect", "--file", "x"], 2),
                (["hook", "--file", "x"], 2),
                (["scan"], 1),
            ):
                with self.subTest(arguments=arguments):
                    result, _, stderr = self.run_main(*arguments)
                    self.assertEqual(expected, result)

    def test_protect_returns_two_for_any_block_and_zero_when_clean(self) -> None:
        with (
            patch.object(loki, "load_config", return_value={}),
            patch.object(loki, "protect_path", side_effect=["blocked", None]),
        ):
            result, _, stderr = self.run_main("protect", "--file", "x")
            self.assertEqual(2, result)
            self.assertEqual("blocked\n", stderr)
        with (
            patch.object(loki, "load_config", return_value={}),
            patch.object(loki, "protect_path", return_value=None),
        ):
            result, _, stderr = self.run_main("protect", "--file", "x")
            self.assertEqual(0, result)
            self.assertEqual("", stderr)

    def test_malformed_hook_denies_before_any_checker(self) -> None:
        with (
            patch.object(sys, "stdin", Mock(read=Mock(return_value="{"))),
            patch.object(loki, "check_file") as checker,
        ):
            result, stdout, stderr = self.run_main("hook", "--harness", "claude")
            self.assertEqual(2, result)
            self.assertEqual("", stdout)
            self.assertIn("invalid hook input", stderr)
            checker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
