import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class PreviewContractTests(unittest.TestCase):
    def check(self, root, name, data, *, harness="claude", strict=False):
        payload = {"cwd": str(root), "tool_name": name, "tool_input": data}
        with (
            argv("--root", str(root), "protect", "--harness", harness),
            patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            patch.dict(os.environ, {"LOKI_STRICT": "1" if strict else "0"}),
        ):
            return capture_output(loki.main)

    def test_unavailable_analyzer_never_looks_like_a_clean_check(self):
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value=None),
        ):
            data = {"file_path": "new.ts", "content": "export const value = 1;\n"}
            status, output, diagnostic = self.check(root, "Write", data)
            self.assertEqual(0, status)
            self.assertIn("NOT CHECKED", diagnostic)
            self.assertIn("built-in fallback rules applied", diagnostic)
            self.assertEqual(
                "PreToolUse", json.loads(output)["hookSpecificOutput"]["hookEventName"]
            )
            self.assertEqual(2, self.check(root, "Write", data, strict=True)[0])
            self.assertFalse((root / "new.ts").exists())

    def test_fallback_rules_still_deny_without_oxlint(self):
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value=None),
        ):
            data = {"file_path": "new.ts", "content": "try {run()} catch {}"}
            status, _, diagnostic = self.check(root, "Write", data)
            self.assertEqual(2, status)
            self.assertIn("no-empty: empty catch block", diagnostic)
            self.assertIn("NOT CHECKED pre-write content", diagnostic)

    def test_multiedit_reconstructs_sequentially_without_writing(self):
        with temporary_root() as root:
            path = write_file(root, "source.ts", "const result = old;\n")
            payload = {
                "tool_name": "MultiEdit",
                "tool_input": {
                    "edits": [
                        {"old_string": "old", "new_string": "intermediate"},
                        {"old_string": "intermediate", "new_string": "final"},
                    ]
                },
            }
            self.assertEqual(
                [("source.ts", "const result = old;\n", "const result = final;\n")],
                loki.preview_changes(root, [str(path)], payload, "claude"),
            )
            self.assertEqual("const result = old;\n", path.read_text())

    def test_ambiguous_edits_and_unknown_patch_modes_are_explicit(self):
        with temporary_root() as root:
            path = write_file(root, "source.ts", "value value")
            payload = {
                "tool_name": "Edit",
                "tool_input": {
                    "old_string": "value",
                    "new_string": "changed",
                },
            }
            self.assertIsNone(
                loki.preview_changes(root, [str(path)], payload, "claude")
            )
            payload["tool_input"]["replace_all"] = True
            self.assertEqual(
                "changed changed",
                loki.preview_changes(root, [str(path)], payload, "claude")[0][2],
            )
            payload["tool_name"] = "apply_patch"
            self.assertIsNone(loki.preview_changes(root, [str(path)], payload, "codex"))

    def test_factory_and_pi_replacements_use_host_fields(self):
        for harness, tool, source, target in (
            ("factory", "Edit", "old_str", "new_str"),
            ("pi", "edit", "oldText", "newText"),
        ):
            with self.subTest(harness=harness), temporary_root() as root:
                path = write_file(root, "source.ts", "old")
                payload = {
                    "tool_name": tool,
                    "tool_input": {source: "old", target: "new"},
                }
                self.assertEqual(
                    [("source.ts", "old", "new")],
                    loki.preview_changes(root, [str(path)], payload, harness),
                )

    def test_replacement_growth_is_bounded_before_allocation(self):
        with temporary_root() as root:
            path = write_file(root, "source.ts", "a" * 4096)
            payload = {
                "tool_name": "Edit",
                "tool_input": {
                    "old_string": "a",
                    "new_string": "b" * 4096,
                    "replace_all": True,
                },
            }
            with self.assertRaisesRegex(ValueError, "4 MiB"):
                loki.preview_changes(root, [str(path)], payload, "claude")

    def test_failed_or_incomplete_reports_are_never_clean(self):
        empty = {"number_of_files": 2, "number_of_rules": 3, "diagnostics": []}
        cases = [
            (0, "{}", ""),
            (1, json.dumps(empty), ""),
            (0, json.dumps(empty), "coverage skipped"),
            (0, json.dumps({**empty, "number_of_files": 1}), ""),
            (0, json.dumps({**empty, "number_of_rules": 0}), ""),
            (-9, "", ""),
            (0, "broken JSON", ""),
        ]
        with temporary_root() as root:
            write_file(root, "node_modules/.bin/oxlint", "")
            for status, stdout, stderr in cases:
                with (
                    self.subTest(status=status, stdout=stdout, stderr=stderr),
                    patch.object(
                        loki.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(
                            [], status, stdout, stderr
                        ),
                    ),
                ):
                    code, _, diagnostic = self.check(
                        root,
                        "Write",
                        {
                            "file_path": "source.ts",
                            "content": "try {run()} catch {}",
                        },
                        strict=True,
                    )
                    self.assertEqual(2, code)
                    self.assertIn("NOT CHECKED", diagnostic)


@unittest.skipUnless(
    os.environ.get("LOKI_TEST_OXLINT"), "set LOKI_TEST_OXLINT for real analyzer"
)
class RealPreviewTests(PreviewContractTests):
    def prepare(
        self, root, before="export const value = 1;\n", filename="source.test.ts"
    ):
        target = write_file(root, filename, before)
        binary = root / "node_modules/.bin/oxlint"
        binary.parent.mkdir(parents=True)
        binary.symlink_to(Path(os.environ["LOKI_TEST_OXLINT"]).resolve())
        return target

    def test_new_empty_catches_and_test_disabling_block(self):
        cases = [
            "try { run(); } catch {}",
            'import {test} from "vitest"; test.skip("x",()=>{});',
            'import {test as check} from "vitest"; check.skip("x",()=>{});',
            'import {test} from "vitest"; test["skip"]("x",()=>{});',
            "/* oxlint-disable */\ntry { run(); } catch {}",
            "/* eslint-disable no-empty */\ntry { run(); } catch {}",
        ]
        for content in cases:
            with self.subTest(content=content), temporary_root() as root:
                path = self.prepare(root)
                status, _, diagnostic = self.check(
                    root,
                    "Write",
                    {
                        "file_path": str(path),
                        "content": content,
                    },
                    strict=True,
                )
                self.assertEqual(2, status, diagnostic)
                self.assertNotIn("NOT CHECKED", diagnostic)
                self.assertEqual("export const value = 1;\n", path.read_text())

    def test_legitimate_lookalikes_and_handled_catches_pass(self):
        cases = [
            'const message = "test.skip() and catch {}";',
            "const regex = /catch {}/;",
            '// test.skip("x"); catch {}\nexport const value = 2;',
            "const test = {skip() {return true;}}; test.skip();",
            "try { run(); } catch { /* Expected: optional file may not exist. */ }",
            "try { run(); } catch (error) { throw error; }",
            'import {test} from "vitest"; test("value", () => {});',
        ]
        for content in cases:
            with self.subTest(content=content), temporary_root() as root:
                path = self.prepare(root)
                status, _, diagnostic = self.check(
                    root,
                    "Write",
                    {
                        "file_path": str(path),
                        "content": content,
                    },
                    strict=True,
                )
                self.assertEqual(0, status, diagnostic)
                self.assertEqual("", diagnostic)

    def test_existing_debt_line_shifts_repairs_and_multiplicity(self):
        before = "try { oldCall(); } catch {}\n"
        with temporary_root() as root:
            path = self.prepare(root, before)
            for content in ("\n" + before, before + "export const value = 2;\n", ""):
                status, _, diagnostic = self.check(
                    root,
                    "Write",
                    {
                        "file_path": str(path),
                        "content": content,
                    },
                    strict=True,
                )
                self.assertEqual(0, status, diagnostic)
            status, _, diagnostic = self.check(
                root,
                "Write",
                {
                    "file_path": str(path),
                    "content": before + before,
                },
                strict=True,
            )
            self.assertEqual(2, status, diagnostic)

    def test_candidate_configuration_cannot_disable_preview(self):
        with temporary_root() as root:
            path = self.prepare(root)
            write_file(root, ".oxlintrc.json", '{"rules":{"no-empty":"off"}}')
            write_file(root, "oxlint.config.ts", 'throw new Error("must not execute");')
            write_file(root, ".eslintignore", "*")
            status, _, diagnostic = self.check(
                root,
                "Write",
                {
                    "file_path": str(path),
                    "content": "try {run()} catch {}",
                },
                strict=True,
            )
            self.assertEqual(2, status, diagnostic)
            self.assertNotIn("NOT CHECKED", diagnostic)

    def test_edit_is_checked_before_content_lands(self):
        with temporary_root() as root:
            path = self.prepare(root, "try {run()} catch (error) { throw error; }\n")
            status, _, diagnostic = self.check(
                root,
                "Edit",
                {
                    "file_path": str(path),
                    "old_string": " throw error; ",
                    "new_string": "",
                },
                strict=True,
            )
            self.assertEqual(2, status, diagnostic)
            self.assertNotIn("NOT CHECKED", diagnostic)
            self.assertIn("throw error", path.read_text())

    def test_unicode_before_diagnostic_is_supported(self):
        with temporary_root() as root:
            path = self.prepare(root)
            status, _, diagnostic = self.check(
                root,
                "Write",
                {
                    "file_path": str(path),
                    "content": 'const word = "日本語"; try {run()} catch {}',
                },
                strict=True,
            )
            self.assertEqual(2, status, diagnostic)
            self.assertNotIn("NOT CHECKED", diagnostic)

    def test_installed_claude_and_factory_handlers_check_proposed_content(self):
        with temporary_root() as root:
            git(root, "init")
            path = self.prepare(root)
            capture_output(loki.install_target, root)
            for filename, tool in (
                (".claude/settings.json", "Write"),
                (".factory/hooks.json", "Create"),
            ):
                document = loki.read_json_object(root / filename)
                groups = document.get("hooks", document)
                handler = groups["PreToolUse"][0]["hooks"][0]["command"]
                for content, expected in (
                    ("try {run()} catch {}", 2),
                    ("try {run()} catch (error) {throw error}", 0),
                ):
                    result = subprocess.run(
                        ["/bin/sh", "-c", handler],
                        cwd=root,
                        env={**os.environ, "FACTORY_PROJECT_DIR": str(root)},
                        input=json.dumps(
                            {
                                "cwd": str(root),
                                "tool_name": tool,
                                "tool_input": {
                                    "file_path": str(path),
                                    "content": content,
                                },
                            }
                        ),
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertEqual(expected, result.returncode, result.stderr)
                    self.assertNotIn("NOT CHECKED", result.stderr)
                    self.assertEqual("export const value = 1;\n", path.read_text())
