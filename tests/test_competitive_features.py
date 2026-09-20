import hashlib
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import temporary_root
from tests.test_repository_guardrails import git


class CompetitiveFeaturesTests(unittest.TestCase):
    def test_rule_context_includes_selected_packs_and_thresholds(self):
        with temporary_root() as root:
            (root / "api").mkdir()
            (root / "api/mix.exs").write_text("# mix")
            context = loki.injected_context(
                root,
                {
                    "rule_packs": ["core", "phoenix", "shell"],
                    "elixir_security": {"sobelow": {"block": "medium", "warn": "low"}},
                },
            )
            self.assertIn("medium confidence findings block", context)
            self.assertIn("Shell redirects", context)
            self.assertNotIn("Python edits", context)

    def test_context_cli_emits_session_context_json(self):
        with temporary_root() as root:
            (root / ".loki").mkdir()
            (root / ".loki/loki.json").write_text(
                json.dumps(
                    {
                        "rule_packs": ["core", "phoenix"],
                        "elixir_security": {
                            "sobelow": {"block": "high", "warn": "medium"}
                        },
                    }
                )
            )
            result = subprocess.run(  # noqa: S603 - local fixture CLI
                [
                    sys.executable,
                    str(Path(loki.__file__).resolve()),
                    "context",
                    "--root",
                    str(root),
                    "--event",
                    "SessionStart",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            output = json.loads(result.stdout)
            self.assertEqual(
                "SessionStart", output["hookSpecificOutput"]["hookEventName"]
            )
            self.assertIn(
                "LOKI POLICY GUIDANCE",
                output["hookSpecificOutput"]["additionalContext"],
            )
            self.assertIn(
                "Sobelow high confidence findings block",
                output["hookSpecificOutput"]["additionalContext"],
            )

    def test_rule_pack_and_security_policy_reject_unsafe_shapes(self):
        with self.assertRaises(ValueError):
            loki.validate_config({"rule_packs": ["unknown"]})
        with self.assertRaises(ValueError):
            loki.validate_config(
                {"elixir_security": {"sobelow": {"block": "low", "warn": "high"}}}
            )

    def test_python_batch_detects_later_target_with_one_comparison(self):
        with temporary_root() as root:
            git(root, "init")
            (root / ".ruff.toml").write_text('[lint]\nselect=["F"]\n')
            targets = [root / "first.py", root / "second.py"]
            for path in targets:
                path.write_text("value = 1\n")
            git(root, "add", ".")
            git(root, "commit", "-m", "baseline")
            targets[0].write_text("value = 2\n")
            targets[1].write_text("value = missing\n")
            checked = set()
            with patch.object(
                loki, "ruff_new_violations", wraps=loki.ruff_new_violations
            ) as compare:
                findings = []
                for path in targets:
                    findings.extend(
                        loki.check_file(
                            path,
                            root,
                            {},
                            batch_paths=targets,
                            checked_projects=checked,
                        )
                    )
            self.assertTrue(any("second.py: F821" in item for item in findings))
            self.assertEqual(1, compare.call_count)

    def test_hook_records_base_bytes_and_rule_without_message_inference(self):
        with temporary_root() as root, temporary_root() as home:
            git(root, "init")
            (root / ".loki").mkdir()
            policy = b'{"protected_extra":["oracle.txt"]}\n'
            (root / ".loki/loki.json").write_bytes(policy)
            (root / "oracle.txt").write_text("trusted")
            git(root, "add", ".")
            git(root, "commit", "-m", "trusted baseline")
            base = git(root, "rev-parse", "HEAD").decode().strip()
            (root / ".loki/loki.json").write_text("{}")
            (root / "oracle.txt").write_text("weakened")
            result = subprocess.run(  # noqa: S603 - local fixture CLI
                [
                    sys.executable,
                    str(Path(loki.__file__).resolve()),
                    "hook",
                    "--file",
                    "ordinary.txt",
                    "--record",
                ],
                cwd=root,
                env={**os.environ, "HOME": str(home)},
                capture_output=True,
                check=False,
            )
            self.assertEqual(2, result.returncode)
            with patch.dict(os.environ, {"HOME": str(home)}):
                event = loki.read_events(root, 1)[0]
            self.assertIn(
                {
                    "source": "base",
                    "path": ".loki/loki.json",
                    "base": base,
                    "sha256": hashlib.sha256(policy).hexdigest(),
                },
                event["policies"],
            )
            self.assertIn(
                {"rule": "protected-content", "path": "oracle.txt"}, event["findings"]
            )
            self.assertEqual(["ordinary.txt"], event["targets"])

    def test_policy_digest_is_not_reread_after_evaluation(self):
        with temporary_root() as root, temporary_root() as home:
            (root / ".loki").mkdir()
            path = root / ".loki/loki.json"
            path.write_bytes(b"{}")
            evidence = {"policies": [], "findings": [], "targets": []}
            token = loki.ACTIVE_EVIDENCE.set(evidence)
            try:
                loki.load_config(root)
            finally:
                loki.ACTIVE_EVIDENCE.reset(token)
            path.write_bytes(b'{"languages":{}}')
            with patch.dict(os.environ, {"HOME": str(home)}):
                loki.record_event(
                    root, "protect", [], "allow", time.monotonic(), evidence=evidence
                )
                event = loki.read_events(root, 1)[0]
            self.assertEqual(
                hashlib.sha256(b"{}").hexdigest(), event["policies"][0]["sha256"]
            )

    def test_net_new_uses_base_configuration_and_preserves_old_debt(self):
        with temporary_root() as root:
            git(root, "init")
            (root / ".ruff.toml").write_text('[lint]\nselect=["F"]\n')
            source = root / "app.py"
            source.write_text("import os\nvalue = 1\n")
            git(root, "add", ".")
            git(root, "commit", "-m", "baseline")
            source.write_text("\nimport os\nvalue = 2\n")
            self.assertEqual([], loki.ruff_new_violations(root, None))
            self.assertEqual([], loki.check_file(source, root, {}))
            source.write_text("import os\nvalue = missing\n")
            self.assertTrue(
                any("F821" in item for item in loki.ruff_new_violations(root, None))
            )
            self.assertTrue(
                any("F821" in item for item in loki.check_file(source, root, {}))
            )
            (root / ".ruff.toml").write_text('[lint]\nignore=["F821"]\n')
            self.assertTrue(
                any(
                    "protected" in item for item in loki.ruff_new_violations(root, None)
                )
            )

    def test_event_records_metadata_without_source_or_commands(self):
        with temporary_root() as root, temporary_root() as home:
            with patch.dict(os.environ, {"HOME": str(home)}):
                loki.record_event(root, "protect", ["app.py"], "deny", time.monotonic())
                events = loki.read_events(root, 1)
                self.assertEqual("deny", events[0]["outcome"])
                self.assertNotIn("content", events[0])
                self.assertNotIn("command", events[0])
                self.assertEqual(64, len(events[0]["engine_sha256"]))
