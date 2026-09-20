import json
import subprocess
import unittest
from unittest.mock import patch

import loki
from tests.helpers import temporary_root, write_file
from tests.test_repository_guardrails import git


def report(**groups):
    return json.dumps(
        {
            "findings": {
                f"{level}_confidence": groups.get(level, [])
                for level in ("high", "medium", "low")
            }
        }
    )


def finding(level="high", line=1):
    return {
        "type": f"Misc.{level}",
        "file": "lib/input.ex",
        "line": line,
        "variable": "input",
    }


class SobelowDeltaTests(unittest.TestCase):
    def test_all_threshold_combinations(self):
        for threshold, matches in (
            ("none", set()),
            ("low", {"low", "medium", "high"}),
            ("medium", {"medium", "high"}),
            ("high", {"high"}),
        ):
            for confidence in ("low", "medium", "high"):
                with self.subTest(threshold=threshold, confidence=confidence):
                    self.assertEqual(
                        confidence in matches,
                        loki.severity_matches(confidence, threshold),
                    )

    def fixture(self, root):
        git(root, "init")
        write_file(root, "mix.exs", "# fixture\n")
        write_file(root, ".gitignore", "_build/\ndeps/\n")
        write_file(root, "lib/input.ex", "decode(input)\n")
        write_file(root, "_build/dev/lib/sobelow/ebin/.fixture", "")
        git(root, "add", ".")
        git(root, "commit", "-m", "baseline")

    def compare(self, root, before, after, config=None, status=0):
        outputs = iter([before, after])
        actual_run = subprocess.run

        def run(command, **kwargs):
            if command[0] == "git":
                return actual_run(command, **kwargs)
            self.assertEqual("elixir", command[0])
            self.assertNotIn("mix", command)
            return subprocess.CompletedProcess(command, status, next(outputs), "")

        warnings = []
        with patch.object(loki.subprocess, "run", side_effect=run):
            failures = loki.sobelow_new_violations(
                root, config or {}, warnings=warnings
            )
        return failures, warnings

    def test_none_disables_block_and_warn_but_findings_stay_visible(self):
        with temporary_root() as root:
            self.fixture(root)
            failures, warnings = self.compare(
                root,
                report(),
                report(high=[finding()]),
                {"elixir_security": {"sobelow": {"block": "none", "warn": "none"}}},
            )
            self.assertEqual([], failures)
            self.assertEqual(1, len(warnings))
            self.assertIn("INFO", warnings[0])

    def test_default_thresholds_block_high_warn_medium_and_show_low(self):
        with temporary_root() as root:
            self.fixture(root)
            failures, warnings = self.compare(
                root,
                report(),
                report(
                    high=[finding()],
                    medium=[finding("medium")],
                    low=[finding("low")],
                ),
            )
            self.assertEqual(1, len(failures))
            self.assertIn("lib/input.ex:1", failures[0])
            self.assertEqual(2, len(warnings))
            self.assertIn("WARN", warnings[0])
            self.assertIn("INFO", warnings[1])

    def test_duplicate_findings_are_not_lost(self):
        with temporary_root() as root:
            self.fixture(root)
            write_file(root, "lib/input.ex", "decode(input)\ndecode(input)\n")
            failures, _ = self.compare(
                root,
                report(high=[finding()]),
                report(high=[finding(), finding(line=2)]),
            )
            self.assertEqual(1, len(failures))

    def test_line_shifts_do_not_create_new_findings(self):
        with temporary_root() as root:
            self.fixture(root)
            write_file(root, "lib/input.ex", "\n\ndecode(input)\n")
            failures, warnings = self.compare(
                root, report(high=[finding()]), report(high=[finding(line=3)])
            )
            self.assertEqual(([], []), (failures, warnings))

    def test_analyzer_errors_and_invalid_schema_are_unavailable(self):
        malformed = [
            "{}",
            '{"findings":{}}',
            '{"findings":[]}',
            report(high=[{"file": "lib/input.ex"}]),
            report(high=[{**finding(), "file": "../outside.ex"}]),
            report(high=[{**finding(), "line": "1"}]),
        ]
        with temporary_root() as root:
            self.fixture(root)
            for payload in malformed:
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    self.compare(root, report(), payload)
            with self.assertRaisesRegex(ValueError, "failed"):
                self.compare(root, report(), report(), status=1)

    def test_configuration_changes_are_rejected_before_execution(self):
        for name in (
            "mix.exs",
            "mix.lock",
            ".sobelow-conf",
            ".sobelow-skips",
            "config/config.exs",
        ):
            with self.subTest(name=name), temporary_root() as root:
                self.fixture(root)
                write_file(root, name, "# changed\n")
                with self.assertRaisesRegex(ValueError, "configuration change"):
                    loki.sobelow_new_violations(root, {})

    def test_missing_compiled_analyzer_is_unavailable(self):
        with temporary_root() as root:
            self.fixture(root)
            (root / "_build/dev/lib/sobelow/ebin/.fixture").unlink()
            (root / "_build/dev/lib/sobelow/ebin").rmdir()
            with self.assertRaisesRegex(ValueError, "compiled dev Sobelow"):
                loki.sobelow_new_violations(root, {})

    def test_credo_failure_does_not_skip_sobelow_or_repeat_batch(self):
        with temporary_root() as root:
            write_file(root, "mix.exs", "# fixture\n")
            paths = [
                write_file(root, "lib/one.ex", "# one\n"),
                write_file(root, "lib/two.ex", "# two\n"),
            ]
            checked = set()
            warnings = []
            with (
                patch.object(loki, "missing_tool", return_value=None),
                patch.object(loki, "run_command", return_value=[]),
                patch.object(
                    loki,
                    "credo_new_violations",
                    side_effect=ValueError("missing Credo"),
                ) as credo,
                patch.object(
                    loki, "sobelow_new_violations", return_value=["Sobelow finding"]
                ) as sobelow,
            ):
                results = [
                    loki.check_file(
                        path, root, {}, warnings=warnings, checked_projects=checked
                    )
                    for path in paths
                ]
            self.assertEqual([["Sobelow finding"], []], results)
            self.assertEqual(1, credo.call_count)
            self.assertEqual(1, sobelow.call_count)
            self.assertIn("NOT CHECKED Credo", warnings[0])

    def test_sobelow_timeout_fails_strict_hooks(self):
        with temporary_root() as root:
            write_file(root, "mix.exs", "# fixture\n")
            path = write_file(root, "lib/input.ex", "# fixture\n")
            with (
                patch.object(loki, "missing_tool", return_value=None),
                patch.object(loki, "run_command", return_value=[]),
                patch.object(loki, "credo_new_violations", return_value=[]),
                patch.object(
                    loki,
                    "sobelow_new_violations",
                    side_effect=subprocess.TimeoutExpired("elixir", 1),
                ),
            ):
                self.assertIn(
                    "NOT CHECKED Sobelow",
                    loki.check_file(path, root, {}, strict=True)[0],
                )

    def test_partial_coverage_notices_fail_strict_without_losing_findings(self):
        def sobelow(*args, warnings, **kwargs):
            warnings.append("NOT CHECKED Sobelow coverage: router unavailable")
            return ["new security finding"]

        with temporary_root() as root:
            write_file(root, "mix.exs", "# fixture\n")
            path = write_file(root, "lib/input.ex", "# fixture\n")
            with (
                patch.object(loki, "missing_tool", return_value=None),
                patch.object(loki, "run_command", return_value=[]),
                patch.object(loki, "credo_new_violations", return_value=[]),
                patch.object(loki, "sobelow_new_violations", side_effect=sobelow),
            ):
                failures = loki.check_file(path, root, {}, strict=True)
            self.assertEqual(2, len(failures))
            self.assertIn("router unavailable", failures[1])
