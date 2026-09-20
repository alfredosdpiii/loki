import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import temporary_root
from tests.test_repository_guardrails import git


class ElixirAnalysisTests(unittest.TestCase):
    def test_credo_comparison_rejects_policy_changes_before_analyzer(self):
        with temporary_root() as root:
            git(root, "init")
            (root / "mix.exs").write_text("# fixture\n")
            (root / ".credo.exs").write_text("%{configs: []}\n")
            git(root, "add", ".")
            git(root, "commit", "-m", "base")
            (root / ".credo.exs").write_text("%{configs: [:weakened]}\n")
            with self.assertRaisesRegex(ValueError, "configuration change"):
                loki.credo_new_violations(root)

    def test_scan_checks_each_mix_project_without_dependency_sources(self):
        with temporary_root() as root:
            git(root, "init")
            for name in ("api", "worker"):
                project = root / name
                project.mkdir()
                (project / "mix.exs").write_text("# project\n")
                for ignored in ("deps/library", "_build/dev"):
                    directory = project / ignored
                    directory.mkdir(parents=True)
                    (directory / "bad.py").write_text("not valid Python!")
            visited = []

            def analyze(project, tier, files):
                visited.append(project.name)
                return [
                    {
                        "tool": "compile",
                        "status": "FAIL" if project.name == "worker" else "PASS",
                        "output": "compile failure",
                    }
                ]

            with patch.object(loki, "elixir_analysis", side_effect=analyze):
                self.assertEqual(1, loki.scan(root, {}, False, True))
            self.assertEqual(["api", "worker"], visited)
            self.assertEqual(
                {"api/mix.exs", "worker/mix.exs"},
                {
                    path.relative_to(root).as_posix()
                    for path in loki.iter_source_files(root)
                },
            )

    def test_missing_analyzer_is_not_a_clean_result(self):
        with temporary_root() as root:
            (root / "mix.exs").write_text("defmodule Project do\nend\n")
            with (
                patch.object(loki.shutil, "which", return_value="/bin/mix"),
                patch.object(
                    loki.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "", ""),
                ),
            ):
                report = loki.elixir_analysis(root, "deep", [])
            missing = {
                check["tool"] for check in report if check["status"] == "NOT CHECKED"
            }
            self.assertEqual({"credo", "sobelow", "dialyzer"}, missing)

    def test_structured_security_findings_reach_evidence(self):
        with temporary_root() as root:
            (root / "mix.exs").touch()
            for dependency in ("credo", "sobelow"):
                (root / "deps" / dependency).mkdir(parents=True)
                (root / "deps" / dependency / "mix.exs").touch()

            def run(command, **kwargs):
                if command[1] == "credo":
                    return subprocess.CompletedProcess(command, 0, '{"issues":[]}', "")
                if command[1] == "sobelow":
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        json.dumps(
                            {
                                "findings": {
                                    "high_confidence": [
                                        {
                                            "type": "Misc.BinToTerm",
                                            "file": "lib/input.ex",
                                        }
                                    ]
                                }
                            }
                        ),
                        "",
                    )
                return subprocess.CompletedProcess(command, 0, "", "")

            evidence = {"policies": [], "findings": [], "targets": []}
            token = loki.ACTIVE_EVIDENCE.set(evidence)
            try:
                with (
                    patch.object(loki.shutil, "which", return_value="/bin/mix"),
                    patch.object(loki.subprocess, "run", side_effect=run),
                ):
                    report = loki.elixir_analysis(root, "project", [])
            finally:
                loki.ACTIVE_EVIDENCE.reset(token)
            self.assertEqual("FAIL", report[-1]["status"])
            self.assertIn(
                {
                    "rule": "sobelow:high_confidence:Misc.BinToTerm",
                    "path": "lib/input.ex",
                },
                evidence["findings"],
            )

    def test_sobelow_thresholds_block_only_configured_confidence(self):
        with temporary_root() as root:
            (root / "mix.exs").touch()
            (root / ".credo.exs").write_text("%{configs: []}\n")
            with (
                patch.object(loki, "git_changes", return_value=("base", [])),
                patch.object(loki, "base_policy", return_value=None),
            ):
                with self.assertRaises(ValueError):
                    loki.security_policy(
                        {
                            "elixir_security": {
                                "sobelow": {"block": "low", "warn": "high"}
                            }
                        }
                    )

    def test_target_cannot_escape_mix_project(self):
        with temporary_root() as root:
            (root / "mix.exs").touch()
            with self.assertRaises(ValueError):
                loki.elixir_analysis(root, "fast", [Path("../outside.ex")])
