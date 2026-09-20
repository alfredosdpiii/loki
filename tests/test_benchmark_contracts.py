import json
import unittest
from pathlib import Path

from benchmarks import compare_hooks, host_context


class BenchmarkContractTests(unittest.TestCase):
    def test_json_denial_with_zero_exit_is_not_allow(self):
        output = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}})
        self.assertEqual("deny", compare_hooks.decision(0, output, ""))
        self.assertEqual("deny", compare_hooks.decision(2, "", "blocked"))
        self.assertEqual("allow", compare_hooks.decision(0, "", ""))

    def test_unavailable_and_review_are_not_clean_results(self):
        for status, output, diagnostic in (
            (1, "", "crashed"),
            (0, "not JSON", ""),
        ):
            with self.subTest(status=status, diagnostic=diagnostic):
                self.assertEqual(
                    "unavailable", compare_hooks.decision(status, output, diagnostic)
                )
        self.assertEqual(
            "review",
            compare_hooks.decision(
                0, '{"hookSpecificOutput":{"permissionDecision":"ask"}}', ""
            ),
        )

    def test_admission_and_coverage_are_separate(self):
        for diagnostic in ("NOT CHECKED compiler", "evaluator skipped"):
            self.assertEqual("allow", compare_hooks.decision(0, "", diagnostic))
            self.assertTrue(compare_hooks.coverage_unavailable("", diagnostic))
        self.assertEqual("deny", compare_hooks.decision(2, "", "NOT CHECKED compiler"))
        self.assertFalse(compare_hooks.coverage_unavailable("", ""))

    def test_host_environment_does_not_inherit_credentials(self):
        env = host_context.isolated_env(Path("/fixture/home"), "/usr/bin")
        self.assertEqual("/fixture/home", env["HOME"])
        self.assertEqual("/usr/bin", env["PATH"])
        self.assertNotIn("AUTH_TOKEN", env)
        self.assertNotIn("FACTORY_API_KEY", env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual("1", env["PI_OFFLINE"])

    def test_stub_answer_cannot_supply_policy_marker(self):
        encoded = json.dumps(host_context.anthropic_events())
        self.assertNotIn(host_context.MARKER, encoded)
        self.assertNotIn(host_context.MARKER, host_context.PROMPT)
        self.assertIn("fixture-ok", encoded)
