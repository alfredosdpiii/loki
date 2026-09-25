import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import loki
from benchmarks import comprehensive, corpus, native_projects, report_comprehensive


def result(status=0, stdout="", stderr=""):
    return {"exit": status, "stdout": stdout, "stderr": stderr, "ms": 1.0}


class ComprehensiveBenchmarkTests(unittest.TestCase):
    def test_fixture_policy_preserves_valid_shipped_rule_packs(self):
        raw = json.loads((comprehensive.SOURCE / "templates/loki.json").read_text())
        config = comprehensive.reviewed_policy(raw)
        self.assertEqual(loki.rule_packs(raw), loki.rule_packs(config))
        self.assertIn("phoenix", loki.rule_packs(config))
        self.assertEqual([], raw["shell_commands"])
        self.assertEqual(1, len(config["shell_commands"]))

    def test_post_json_block_with_exit_zero_is_denial(self):
        self.assertEqual(
            "deny",
            comprehensive.decode(
                result(stdout='{"decision":"block","reason":"broken"}'),
                "PostToolUse",
            ),
        )

    def test_bad_protocol_is_not_a_pass(self):
        for response in (
            result(1),
            result(None),
            result(stdout="bad JSON"),
            result(stdout="[]"),
            result(stdout='{"hookSpecificOutput":[] }'),
            result(stdout='{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}'),
            result(stdout='{"hookSpecificOutput":{"permissionDecision":"maybe"}}'),
        ):
            with self.subTest(response=response):
                self.assertEqual(
                    "unavailable", comprehensive.decode(response, "PostToolUse")
                )

    def test_terminal_only_stderr_cannot_earn_detection(self):
        stages = comprehensive.summarize_stage(
            [result(stderr="F821 found")], "PostToolUse", ["F821"]
        )
        self.assertFalse(stages["targeted"])
        stages = comprehensive.summarize_stage(
            [result(2, stderr="F821 found")], "PostToolUse", ["F821"]
        )
        self.assertTrue(stages["targeted"])

    def test_unrelated_denial_and_coverage_warning_are_not_success(self):
        pre = comprehensive.summarize_stage(
            [result(2, stderr="NOT CHECKED compiler")], "PreToolUse", ["F821"]
        )
        self.assertEqual(
            "blocked_unrelated", comprehensive.classify("defect", pre, None)
        )
        self.assertTrue(pre["coverage_warning"])
        self.assertEqual("false_block", comprehensive.classify("control", pre, None))

    def test_post_detection_does_not_become_prevention(self):
        pre = comprehensive.summarize_stage([result()], "PreToolUse", ["F821"])
        post = comprehensive.summarize_stage(
            [result(stdout='{"decision":"block","reason":"F821"}')],
            "PostToolUse",
            ["F821"],
        )
        self.assertEqual(
            "detected_after_write", comprehensive.classify("defect", pre, post)
        )
        self.assertEqual(
            "false_post_block", comprehensive.classify("control", pre, post)
        )

    def test_repetitions_are_not_independent_accuracy_samples(self):
        pre = comprehensive.summarize_stage([result()], "PreToolUse", [])
        event = {"step": 0, "outcome": "admitted", "pre": pre, "post": None}
        report = comprehensive.summarize(
            [
                {
                    "case": "one",
                    "product": "loki",
                    "profile": "shared",
                    "events": [event, event, event],
                }
            ]
        )
        self.assertEqual(1, report["shared/loki"]["steps"])
        self.assertEqual({"admitted": 1}, report["shared/loki"]["outcomes"])

    def test_corpus_pairs_and_missing_security_are_preserved(self):
        manifest = corpus.manifest()
        self.assertEqual(manifest, corpus.manifest())
        cases = manifest["cases"]
        self.assertGreaterEqual(len(cases), 90)
        pairs = {}
        for case in cases:
            for item in case["steps"]:
                self.assertIn(item["kind"], ("control", "defect"))
                if item["kind"] == "defect":
                    self.assertTrue(item["markers"])
            if case["pair"]:
                pairs.setdefault(case["pair"], set()).add(case["steps"][0]["kind"])
        self.assertTrue(all(value == {"control", "defect"} for value in pairs.values()))
        self.assertIn("elixir/ssrf/defect", {case["id"] for case in cases})

    def test_executor_and_evidence_refuse_unsafe_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                comprehensive.write(root, "../escape.txt", "never written")
            evidence = root / "evidence.json"
            comprehensive.save(evidence, {"first": True})
            with self.assertRaises(FileExistsError):
                comprehensive.save(evidence, {"replacement": True})

    def test_quantiles_and_wilson_limits(self):
        self.assertEqual(10, comprehensive.percentile(list(range(1, 11)), 0.95))
        self.assertIsNone(comprehensive.interval(0, 0))
        self.assertEqual(0, comprehensive.interval(0, 10)[0])
        self.assertEqual(1, comprehensive.interval(10, 10)[1])

    def test_empty_audit_inventory_cannot_be_scored_as_detection(self):
        self.assertEqual(
            "",
            comprehensive.audit_messages(
                '{"ubs_unsafe_format_string":{"issues":0,"details":[]}}'
            ),
        )
        self.assertIn(
            "F821",
            comprehensive.audit_messages(
                '{"ruff":{"issues":1,"details":[{"message":"F821"}]}}'
            ),
        )

    def test_exact_edit_uses_native_payload(self):
        item = corpus.step("app.py", "value = 2\n", "control", tool="Edit")
        data = json.loads(
            comprehensive.payload(
                Path("/fixture"),
                item,
                item["content"],
                "PreToolUse",
                "session",
                b"value = 1\n",
            )
        )
        self.assertEqual("value = 1\n", data["tool_input"]["old_string"])
        self.assertEqual("value = 2\n", data["tool_input"]["new_string"])
        self.assertNotIn("content", data["tool_input"])

    def test_sandbox_preserves_explicit_runtime_and_drops_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                hex_archive=None,
                node=Path("/chosen/node/bin/node"),
                erlang_bin=Path("/chosen/erlang/bin"),
                golangci=Path("/chosen/go/golangci-lint"),
                python_tools=Path("/chosen/python/bin"),
                loki_daemon=False,
            )
            with patch.dict(
                "os.environ",
                {"PATH": "/usr/bin", "AUTH_TOKEN": "fixture-value"},
                clear=True,
            ):
                sandbox = comprehensive.Sandbox(root, args)
            self.assertNotIn("AUTH_TOKEN", sandbox.env)
            self.assertEqual("0", sandbox.env["LOKI_DAEMON"])
            paths = sandbox.env["PATH"].split(":")
            self.assertLess(paths.index("/chosen/erlang/bin"), paths.index("/usr/bin"))

    def evidence(self, root, outcomes):
        item = {
            "id": "fixture",
            "language": "python",
            "family": "bug",
            "pair": None,
            "steps": [{"kind": "defect", "markers": ["F821"]}],
        }
        comprehensive.save(
            root / "manifest.json",
            {
                "schedule": [["fixture", "loki", "shared"]],
                "corpus": {"cases": [item]},
                "runs": len(outcomes),
            },
        )
        comprehensive.save(root / "summary.json", {"identity_unchanged": True})
        comprehensive.save(
            root / "record-0000.json",
            {
                "case": "fixture",
                "product": "loki",
                "profile": "shared",
                "events": [
                    {
                        "step": 0,
                        "repetition": index,
                        "outcome": outcome,
                        "pre": comprehensive.summarize_stage(
                            [result(2, stderr="F821")]
                            if outcome == "prevented"
                            else [result()],
                            "PreToolUse",
                            ["F821"],
                        ),
                        "post": None,
                        "cache_state": "first-invocation" if index == 0 else "repeated",
                        "post_modified_written_bytes": False,
                        "pre_modified_bytes": False,
                    }
                    for index, outcome in enumerate(outcomes)
                ],
            },
        )

    def test_report_requires_every_repetition_to_detect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.evidence(root, ["prevented", "missed", "prevented"])
            _, rows = report_comprehensive.measurements(root)
            self.assertFalse(rows[0]["caught_all_runs"])
            self.assertTrue(rows[0]["inconsistent"])
            self.assertEqual(1, report_comprehensive.counts(rows)["defects"])

    def test_report_rejects_missing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.evidence(root, ["prevented"])
            (root / "record-0000.json").unlink()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                report_comprehensive.measurements(root)

    def test_report_does_not_drop_infrastructure_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.evidence(root, ["prevented"])
            (root / "record-0000.json").write_text(
                json.dumps(
                    {
                        "case": "fixture",
                        "product": "loki",
                        "profile": "shared",
                        "error": "fixture setup failed",
                    }
                )
            )
            _, rows = report_comprehensive.measurements(root)
            score = report_comprehensive.counts(rows)
            self.assertEqual(1, score["defects"])
            self.assertEqual(1, score["errors"])
            self.assertEqual(0, score["caught"])

    def test_partial_success_cannot_hide_a_failed_trial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.evidence(root, ["prevented"])
            path = root / "record-0000.json"
            value = json.loads(path.read_text())
            value["error"] = "later trial failed"
            path.write_text(json.dumps(value))
            _, rows = report_comprehensive.measurements(root)
            self.assertFalse(rows[0]["caught_all_runs"])
            self.assertFalse(rows[0]["prevented_all_runs"])

    def test_each_repetition_uses_an_independent_trial(self):
        item = corpus.corpus()[0]
        sample = {"setup_ms": 1, "events": [], "audit_scans": [], "warmups": []}
        with patch.object(comprehensive, "evaluate_trial", return_value=sample) as run:
            comprehensive.evaluate(item, "loki", "shared", SimpleNamespace(runs=3))
        self.assertEqual([0, 1, 2], [call.args[-1] for call in run.call_args_list])

    def test_native_configuration_keeps_case_source_unchanged(self):
        case = corpus.corpus()[0]
        native = native_projects.native_case(case)
        self.assertEqual(case["steps"], native["steps"])
        self.assertNotIn("pyproject.toml", case["base"])
        self.assertIn("[tool.mypy]", native["base"]["pyproject.toml"])

    def test_native_fixture_restores_helpers_after_failure(self):
        writer, policy = comprehensive.write, comprehensive.reviewed_policy
        with patch.object(
            native_projects, "original_baseline", side_effect=ValueError("fixture")
        ):
            with self.assertRaisesRegex(ValueError, "fixture"):
                native_projects.baseline(
                    Path("/fixture"), corpus.corpus()[0], "loki", None, "shared"
                )
        self.assertIs(writer, comprehensive.write)
        self.assertIs(policy, comprehensive.reviewed_policy)

    def test_scorer_does_not_match_across_escaped_json_lines(self):
        stage = comprehensive.summarize_stage(
            [
                result(
                    stdout=json.dumps(
                        {
                            "hookSpecificOutput": {
                                "additionalContext": "Derive expected results.\n"
                                "Use executable tests, not introspection."
                            }
                        }
                    )
                )
            ],
            "PostToolUse",
            [r"expected.*int"],
        )
        self.assertTrue(stage["targeted"])
        self.assertFalse(report_comprehensive.targeted(stage, [r"expected.*int"]))

    def test_scorer_ignores_module_notices_but_keeps_real_syntax_errors(self):
        stage = comprehensive.summarize_stage(
            [
                result(
                    2,
                    stderr="Reparsing as ES module because module syntax was detected.",
                )
            ],
            "PostToolUse",
            ["syntax"],
        )
        self.assertFalse(report_comprehensive.targeted(stage, ["syntax"]))
        stage["handlers"].append(result(2, stderr="SyntaxError: unexpected token"))
        self.assertTrue(report_comprehensive.targeted(stage, ["syntax"]))
