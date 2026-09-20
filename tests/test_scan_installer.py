from __future__ import annotations

import tomllib
import unittest
from unittest.mock import patch

import loki
from tests.helpers import capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class ScanTests(unittest.TestCase):
    def test_clean_empty_scan_passes(self) -> None:
        with temporary_root() as root:
            result, stdout, _ = capture_output(loki.scan, root, {}, False, False)
            self.assertEqual(0, result)
            self.assertIn("NOT CHECKED repository", stdout)

    def test_scan_reports_skips_and_strict_missing_tools(self) -> None:
        with temporary_root() as root:
            git(root, "init")
            write_file(root, "app.go", "value")
            with patch.object(loki, "scan_command", return_value=("golangci-lint", [])):
                result, stdout, _ = capture_output(loki.scan, root, {}, False, False)
                self.assertEqual(0, result)
                result, stdout, _ = capture_output(loki.scan, root, {}, False, True)
                self.assertEqual(1, result)
                self.assertIn("loki: missing golangci-lint", stdout)

    def test_scan_honors_language_disable_empty_messages_and_cap(self) -> None:
        with temporary_root() as root:
            write_file(root, "disabled.go", "value")
            write_file(root, "app.py", "value=1")
            many = [f"message {index}" for index in range(loki.MAX_VIOLATIONS + 5)]
            with (
                patch.object(loki, "scan_command", return_value=(None, [["ruff"]])),
                patch.object(loki, "run_command", return_value=[]),
                patch.object(loki, "python_ast_violations", return_value=many),
            ):
                result, stdout, _ = capture_output(
                    loki.scan,
                    root,
                    {"languages": {"go": False}},
                    False,
                    False,
                )
            self.assertEqual(1, result)
            self.assertNotIn("[go]", stdout)
            self.assertEqual(loki.MAX_VIOLATIONS, stdout.count("message "))


class JsonAndMergeTests(unittest.TestCase):
    def test_json_helpers_read_write_and_validate(self) -> None:
        with temporary_root() as root:
            path = root / "nested/config.json"
            self.assertEqual({}, loki.read_json_object(path))
            loki.write_json(path, {"value": 1})
            self.assertEqual('{\n  "value": 1\n}\n', path.read_text(encoding="utf-8"))
            self.assertEqual({"value": 1}, loki.read_json_object(path))
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected a JSON object"):
                loki.read_json_object(path)
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                loki.read_json_object(path)

            with patch.object(loki.Path, "read_text", side_effect=OSError("denied")):
                with self.assertRaisesRegex(ValueError, "invalid JSON"):
                    loki.read_json_object(path)

    def test_merge_hook_config_appends_once_and_rejects_wrong_shapes(self) -> None:
        entry = {"hooks": [{"command": ".loki/loki.py"}]}
        fragment = {"hooks": {"PreToolUse": [entry]}}
        existing = {"other": True}
        self.assertIs(existing, loki.merge_hook_config(existing, fragment))
        self.assertEqual({"other": True, "hooks": {"PreToolUse": [entry]}}, existing)
        loki.merge_hook_config(existing, fragment)
        self.assertEqual([entry], existing["hooks"]["PreToolUse"])
        invalid = [
            ({"hooks": []}, fragment, "hooks must"),
            ({}, {"hooks": []}, "template hooks"),
            ({"hooks": {"PreToolUse": {}}}, fragment, "hooks.PreToolUse"),
            ({}, {"hooks": {"PreToolUse": {}}}, "hooks.PreToolUse"),
        ]
        for current, incoming, message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaises(ValueError),
            ):
                loki.merge_hook_config(current, incoming)

    def test_merge_factory_hooks_appends_once_and_rejects_wrong_shapes(self) -> None:
        entry = {"hooks": [{"command": ".loki/loki.py"}]}
        fragment = {"PreToolUse": [entry]}
        existing = {"other": True}
        self.assertIs(existing, loki.merge_factory_hooks(existing, fragment))
        self.assertEqual({"other": True, "PreToolUse": [entry]}, existing)
        loki.merge_factory_hooks(existing, fragment)
        self.assertEqual([entry], existing["PreToolUse"])
        for current, incoming in (
            ({"PreToolUse": {}}, fragment),
            ({}, {"PreToolUse": {}}),
        ):
            with (
                self.subTest(current=current, incoming=incoming),
                self.assertRaisesRegex(ValueError, "PreToolUse must"),
            ):
                loki.merge_factory_hooks(current, incoming)

    def test_merge_oxlint_unions_lists_and_overrides_mappings(self) -> None:
        existing = {
            "ignorePatterns": ["existing"],
            "plugins": ["typescript"],
            "jsPlugins": [],
            "categories": {"correctness": "warn"},
            "rules": {"old": "warn"},
        }
        template = {
            "ignorePatterns": ["existing", "new"],
            "plugins": ["unicorn"],
            "jsPlugins": [{"name": "anti-slop"}],
            "categories": {"correctness": "error"},
            "rules": {"new": "error"},
        }
        self.assertIs(existing, loki.merge_oxlint(existing, template))
        self.assertEqual(
            {
                "ignorePatterns": ["existing", "new"],
                "plugins": ["typescript", "unicorn"],
                "jsPlugins": [{"name": "anti-slop"}],
                "categories": {"correctness": "error"},
                "rules": {"old": "warn", "new": "error"},
            },
            existing,
        )
        for current, template, message in (
            ({"plugins": {}}, {"plugins": []}, "plugins"),
            ({"rules": []}, {"rules": {}}, "rules"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                loki.merge_oxlint(current, template)
        self.assertEqual(
            {"ignorePatterns": [], "jsPlugins": [], "categories": {}},
            loki.merge_oxlint({}, {"plugins": {}, "rules": []}),
        )


class InstallerTests(unittest.TestCase):
    def test_codex_activation_preserves_settings_and_is_idempotent(self):
        cases = (
            "",
            'model = "fixture"\n',
            "[features] # keep comment\nother = true\n",
            'description = """\n[features]\nunchanged text\n"""\n'
            "[features]\nother = true\n",
        )
        for text in cases:
            with self.subTest(text=text), temporary_root() as root:
                path = write_file(root, ".codex/config.toml", text)
                expected = tomllib.loads(text)
                expected.setdefault("features", {})["hooks"] = True
                loki.enable_codex_hooks(root)
                self.assertEqual(expected, tomllib.loads(path.read_text()))
                once = path.read_bytes()
                loki.enable_codex_hooks(root)
                self.assertEqual(once, path.read_bytes())
                self.assertIsNotNone(loki.protect_path(".codex/config.toml", root, {}))

    def test_codex_activation_preserves_explicit_disable_and_inline_tables(self):
        for text in (
            "[features]\nhooks = false\n",
            "features = {other = true}\n",
        ):
            with self.subTest(text=text), temporary_root() as root:
                path = write_file(root, ".codex/config.toml", text)
                _, output, _ = capture_output(loki.enable_codex_hooks, root)
                self.assertIn("SKIP Codex hooks activation", output)
                self.assertEqual(text, path.read_text())

    def test_copy_owned_handles_files_directories_force_and_skip(self) -> None:
        with temporary_root() as root:
            source_file = write_file(root, "source.txt", "one")
            target_file = root / "nested/target.txt"
            loki.copy_owned(source_file, target_file, False)
            source_file.write_text("two", encoding="utf-8")
            loki.copy_owned(source_file, target_file, False)
            self.assertEqual("one", target_file.read_text(encoding="utf-8"))
            loki.copy_owned(source_file, target_file, True)
            self.assertEqual("two", target_file.read_text(encoding="utf-8"))
            source_dir = root / "source-dir"
            write_file(source_dir, "item", "new")
            target_dir = root / "target-dir"
            write_file(target_dir, "old", "old")
            loki.copy_owned(source_dir, target_dir, True)
            self.assertFalse((target_dir / "old").exists())
            self.assertEqual("new", (target_dir / "item").read_text(encoding="utf-8"))

    def test_template_path_finds_templates_and_rejects_missing(self) -> None:
        self.assertEqual(
            loki.SOURCE_ROOT / "templates" / "loki.yml",
            loki.template_path("loki.yml"),
        )
        with self.assertRaisesRegex(FileNotFoundError, "missing installer template"):
            loki.template_path("missing")

    def test_install_target_creates_full_payload_and_preserves_existing_configs(
        self,
    ) -> None:
        with temporary_root() as root:
            write_file(root, ".ruff.toml", "existing")
            write_file(root, ".golangci.yml", "existing")
            write_file(root, ".github/workflows/loki.yml", "existing")
            write_file(root, "package.json", "{}")
            write_file(root, "pnpm-lock.yaml", "")
            result, stdout, _ = capture_output(loki.install_target, root)
            self.assertIsNone(result)
            for relative in (
                ".loki/loki.json",
                ".loki/loki.py",
                ".loki/oxlint/anti-slop/index.ts",
                ".claude/settings.json",
                ".codex/hooks.json",
                ".factory/hooks.json",
                ".pi/extensions/loki.ts",
                ".omp/extensions/loki.ts",
                ".oxlintrc.json",
            ):
                self.assertTrue((root / relative).is_file(), relative)
            self.assertEqual(
                "existing", (root / ".ruff.toml").read_text(encoding="utf-8")
            )
            self.assertIn("SKIP .ruff.toml", stdout)
            self.assertIn("pnpm add -D", stdout)
            self.assertIn("Installed loki", stdout)

    def test_install_target_package_manager_commands(self) -> None:
        cases = {
            "bun.lock": "bun add -d",
            "bun.lockb": "bun add -d",
            "pnpm-lock.yaml": "pnpm add -D",
            "yarn.lock": "yarn add -D",
            None: "npm i -D",
        }
        for lockfile, command in cases.items():
            with self.subTest(lockfile=lockfile), temporary_root() as root:
                write_file(root, "package.json", "{}")
                if lockfile:
                    write_file(root, lockfile)
                _, stdout, _ = capture_output(loki.install_target, root)
                self.assertIn(command, stdout)

    def test_install_target_skips_typescript_oxlint_config(self) -> None:
        with temporary_root() as root:
            write_file(root, "oxlint.config.ts", "export default {}")
            _, stdout, _ = capture_output(loki.install_target, root)
            self.assertFalse((root / ".oxlintrc.json").exists())
            self.assertIn("SKIP oxlint.config.ts", stdout)
            self.assertIn("template:", stdout)

    def test_install_target_propagates_invalid_existing_json(self) -> None:
        with temporary_root() as root:
            write_file(root, ".claude/settings.json", "[]")
            with self.assertRaisesRegex(ValueError, "expected a JSON object"):
                loki.install_target(root)

    def test_install_target_force_replaces_owned_directories(self) -> None:
        with temporary_root() as root:
            write_file(root, ".loki/oxlint/anti-slop/stale.ts", "stale")
            loki.install_target(root, True)
            self.assertFalse((root / ".loki/oxlint/anti-slop/stale.ts").exists())
            self.assertTrue((root / ".loki/oxlint/anti-slop/index.ts").is_file())

    def test_force_refreshes_owned_engine_and_shims(self) -> None:
        with temporary_root() as root:
            loki.install_target(root)
            write_file(root, ".loki/loki.py", "stale")
            write_file(root, ".pi/extensions/loki.ts", "stale")
            loki.install_target(root, True)
            self.assertNotEqual(
                "stale", (root / ".loki/loki.py").read_text(encoding="utf-8")
            )
            self.assertNotEqual(
                "stale", (root / ".pi/extensions/loki.ts").read_text(encoding="utf-8")
            )


if __name__ == "__main__":
    unittest.main()
