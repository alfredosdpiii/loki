import json
import os
import subprocess
import unittest

import loki
from tests.helpers import capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


class InstalledHookTests(unittest.TestCase):
    def test_factory_shell_guard_matches_execute(self):
        with temporary_root() as root:
            capture_output(loki.install_target, root)
            loki.install_shell_guard(root)
            document = loki.read_json_object(root / ".factory/hooks.json")
            entries = document["PreToolUse"]
            shell = [
                entry
                for entry in entries
                if any(
                    " shell --harness " in hook["command"] for hook in entry["hooks"]
                )
            ]
            self.assertEqual(1, len(shell))
            self.assertEqual("Execute", shell[0]["matcher"])

    def run_handler(self, command, root, payload=None):
        return subprocess.run(
            ["/bin/sh", "-c", command],
            cwd=root / "nested",
            env={**os.environ, "FACTORY_PROJECT_DIR": str(root)},
            input=json.dumps(payload or {}),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_nested_hooks_and_managed_upgrade_preserve_other_handlers(self):
        for managed in (False, True):
            with (
                self.subTest(managed=managed),
                temporary_root() as parent,
                temporary_root() as storage,
            ):
                root = parent / "project with spaces"
                root.mkdir()
                git(root, "init")
                (root / "nested").mkdir()
                write_file(
                    root,
                    ".loki/loki.json",
                    '{"rule_packs":["phoenix"],"elixir_security":'
                    '{"sobelow":{"block":"medium","warn":"low"}}}',
                )
                unrelated = {"type": "command", "command": "printf user-handler"}
                write_file(
                    root,
                    ".claude/settings.json",
                    json.dumps(
                        {"hooks": {"UserPromptSubmit": [{"hooks": [unrelated]}]}}
                    ),
                )
                for _ in range(2):
                    capture_output(loki.install_target, root, True)
                    loki.install_shell_guard(root)
                    if managed:
                        capture_output(loki.install_managed, root, storage)
                if managed:
                    write_file(
                        root,
                        ".loki/loki.py",
                        "raise RuntimeError('candidate engine')\n",
                    )
                for harness, filename, event in (
                    ("claude", ".claude/settings.json", "UserPromptSubmit"),
                    ("codex", ".codex/hooks.json", "SessionStart"),
                    ("factory", ".factory/hooks.json", "SessionStart"),
                ):
                    document = loki.read_json_object(root / filename)
                    groups = document.get("hooks", document)
                    handlers = [
                        handler for entry in groups[event] for handler in entry["hooks"]
                    ]
                    owned = [h for h in handlers if ".loki/loki.py" in h["command"]]
                    self.assertEqual(1, len(owned))
                    if harness == "claude":
                        self.assertIn(unrelated, handlers)
                    result = self.run_handler(owned[0]["command"], root)
                    self.assertEqual(0, result.returncode, result.stderr)
                    specific = json.loads(result.stdout)["hookSpecificOutput"]
                    self.assertEqual(event, specific["hookEventName"])
                    self.assertIn(
                        "medium confidence findings block",
                        specific["additionalContext"],
                    )
                    self.assertNotIn("Python edits", specific["additionalContext"])
                    pre = groups["PreToolUse"][0]["hooks"][0]["command"]
                    payload = {
                        "cwd": str(root),
                        "tool_name": "Create" if harness == "factory" else "Write",
                        "tool_input": {"file_path": str(root / "ordinary.txt")},
                    }
                    if harness == "codex":
                        payload["tool_name"] = "apply_patch"
                        payload["tool_input"] = {
                            "command": "*** Begin Patch\n*** Add File: ordinary.txt\n"
                            "+hello\n*** End Patch"
                        }
                    allowed = self.run_handler(pre, root, payload)
                    self.assertEqual(0, allowed.returncode, allowed.stderr)
                    self.assertEqual("", allowed.stdout)
                    payload["tool_input"]["file_path"] = str(root / ".loki/loki.json")
                    if harness == "codex":
                        payload["tool_input"]["command"] = (
                            "*** Begin Patch\n*** Add File: .loki/loki.json\n"
                            "+{}\n*** End Patch"
                        )
                    denied = self.run_handler(pre, root, payload)
                    self.assertEqual(2, denied.returncode)
                if managed:
                    for relative in (".pi/extensions/loki.ts", ".loki/loki-shim.ts"):
                        source = (root / relative).read_text()
                        self.assertIn(str(storage), source)
                        self.assertNotIn("`${root}/.loki/loki.py`", source)

    def test_missing_installed_checker_fails_all_shell_wrappers(self):
        with temporary_root() as root:
            git(root, "init")
            (root / "nested").mkdir()
            capture_output(loki.install_target, root)
            (root / ".loki/loki.py").unlink()
            for filename in (
                ".claude/settings.json",
                ".codex/hooks.json",
                ".factory/hooks.json",
            ):
                document = loki.read_json_object(root / filename)
                for entries in document.get("hooks", document).values():
                    for entry in entries:
                        for handler in entry["hooks"]:
                            result = self.run_handler(handler["command"], root)
                            self.assertEqual(2, result.returncode)
                            self.assertIn("loki:", result.stderr)
