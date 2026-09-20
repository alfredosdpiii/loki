import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from benchmarks.language_rules import CASES
from tests.helpers import capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class LanguagePolicyTests(unittest.TestCase):
    def test_preview_and_installed_js_rules_stay_aligned(self):
        config = json.loads(loki.template_path(".oxlintrc.json").read_text())
        for rule in loki.JS_PREVIEW_RULES:
            self.assertEqual("error", config["rules"][rule], rule)
        self.assertIn("jest", config["plugins"])
        self.assertIn("vitest", config["plugins"])

    def test_common_js_extensions_are_not_skipped(self):
        for extension in (".mjs", ".cjs", ".mts", ".cts", ".ts", ".tsx", ".js", ".jsx"):
            self.assertEqual("typescript", loki.LANGUAGE_EXTENSIONS[extension])
        with (
            temporary_root() as root,
            patch.dict(os.environ, {"LOKI_STRICT": "0"}),
            patch.object(loki, "preview_changes", return_value=None),
        ):
            for filename in ("module.mjs", "module.cjs", "module.MJS", "module.CTS"):
                warnings = []
                self.assertEqual(
                    [],
                    loki.preview_violations(
                        root, [filename], {}, "claude", deadline=None, warnings=warnings
                    ),
                )
                self.assertTrue(warnings, filename)

    def test_expanded_rule_report_still_requires_consistent_status(self):
        report = {
            "number_of_files": 2,
            "number_of_rules": len(loki.JS_PREVIEW_RULES),
            "diagnostics": [],
        }
        with temporary_root() as root:
            write_file(root, "node_modules/.bin/oxlint")
            for status in (0, 1):
                with patch.object(
                    loki.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], status, json.dumps(report), ""
                    ),
                ):
                    if status:
                        with self.assertRaisesRegex(ValueError, "status disagrees"):
                            loki.preview_oxlint(
                                root,
                                [("source.ts", "", "export const value = 1;")],
                                deadline=None,
                            )
                    else:
                        self.assertEqual(
                            [],
                            loki.preview_oxlint(
                                root,
                                [("source.ts", "", "export const value = 1;")],
                                deadline=None,
                            ),
                        )

    def test_credo_policy_is_installed_only_for_mix_and_preserved(self):
        with temporary_root() as root:
            capture_output(loki.install_target, root)
            self.assertFalse((root / ".credo.exs").exists())
            write_file(root, "mix.exs", "# fixture")
            capture_output(loki.install_target, root, True)
            self.assertEqual(
                loki.template_path(".credo.exs").read_bytes(),
                (root / ".credo.exs").read_bytes(),
            )
            (root / ".credo.exs").write_text("# operator policy")
            capture_output(loki.install_target, root, True)
            self.assertEqual("# operator policy", (root / ".credo.exs").read_text())
            for name in (".credo.exs", "api/.credo.exs"):
                self.assertIn("protected", loki.protect_path(name, root, {}))

    def test_existing_python_and_go_policies_survive_upgrade(self):
        with temporary_root() as root:
            for name in (".ruff.toml", ".golangci.yml"):
                write_file(root, name, "# operator policy")
            capture_output(loki.install_target, root)
            capture_output(loki.install_target, root, True)
            for name in (".ruff.toml", ".golangci.yml"):
                self.assertEqual("# operator policy", (root / name).read_text())

    def test_python_hook_uses_strengthened_committed_policy(self):
        with temporary_root() as root:
            git(root, "init")
            (root / ".ruff.toml").write_bytes(
                loki.template_path(".ruff.toml").read_bytes()
            )
            _, _, defect, repair = CASES["python"][0]
            path = write_file(root, "app.py", repair)
            git(root, "add", ".")
            git(root, "commit", "-m", "Reviewed Ruff rules")
            path.write_text(defect)
            findings = loki.check_file(path, root, {}, strict=True)
            self.assertTrue(any("RUF006" in item for item in findings), findings)
            path.write_text(repair)
            self.assertEqual([], loki.check_file(path, root, {}, strict=True))

    @unittest.skipUnless(os.environ.get("LOKI_TEST_OXLINT"), "real analyzer required")
    def test_new_js_rules_deny_defects_and_accept_repairs(self):
        with temporary_root() as root:
            binary = root / "node_modules/.bin/oxlint"
            binary.parent.mkdir(parents=True)
            binary.symlink_to(Path(os.environ["LOKI_TEST_OXLINT"]).resolve())
            for name, rule, defect, repair in CASES["typescript"]:
                with self.subTest(name=name):
                    messages = loki.preview_oxlint(
                        root,
                        [("source.test.ts", "", defect)],
                        deadline=None,
                    )
                    self.assertTrue(
                        any(rule in message for message in messages), messages
                    )
                    self.assertEqual(
                        [],
                        loki.preview_oxlint(
                            root,
                            [("source.test.ts", "", repair)],
                            deadline=None,
                        ),
                    )
                    self.assertEqual(
                        [],
                        loki.preview_oxlint(
                            root,
                            [("source.test.ts", defect, "\n" + defect)],
                            deadline=None,
                        ),
                    )
