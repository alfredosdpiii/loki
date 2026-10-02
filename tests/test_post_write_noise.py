"""Post-write checks report only what an edit introduced.

Regression tests for a pilot in which `hook` ran with the default policy (no
`.loki/`) in real repositories and reported existing code after small edits: an
untouched abstract method as a "stub body", imports of the project's own
dependencies as unresolved, and the complexity of an unrelated function that
shared a name with another.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_python_ast import interpreter, no_project_python
from tests.test_slop import branchy, commit

WIDGETS = '''import datetime

import numpy
from docutils import nodes


class Widget:
    def render(self, name, value):
        return str(value)


class MultiWidget(Widget):
    def decompress(self, value):
        """
        Return a list of decompressed values for the given compressed value.
        """
        raise NotImplementedError("Subclasses must implement this method.")


def unfinished():
    pass


class SelectDateWidget(Widget):
    def value_from_datadict(self, y, m, d):
        try:
            date_value = datetime.date(int(y), int(m), int(d))
        except ValueError:
            return "%s-%s-%s" % (y or 0, m or 0, d or 0)
        return date_value.isoformat()
'''
EDITED = WIDGETS.replace(
    "        except ValueError:\n",
    '        except OverflowError:\n            return ""\n        except ValueError:\n',
)
HEADER = "post-write check failed"


class PostWriteNoiseTests(unittest.TestCase):
    def hook(self, root: Path, *arguments: str, tool: str | None = "ruff"):
        """Run `hook` in-process; `tool` is the missing analyzer (None: Ruff is clean)."""
        with (
            argv("--root", str(root), "hook", *arguments),
            patch.object(loki, "missing_tool", return_value=tool),
            patch.object(loki, "ruff_new_violations", return_value=[]),
        ):
            return capture_output(loki.main)

    def test_untouched_abstract_method_and_imports_are_not_reported(self):
        """The Django case: a two-line edit far from `decompress`."""
        with temporary_root() as root, no_project_python():
            commit(root, {"django/forms/widgets.py": WIDGETS})
            write_file(root, "django/forms/widgets.py", EDITED)
            self.assertFalse((root / ".loki").exists())
            status, stdout, stderr = self.hook(
                root, "--file", "django/forms/widgets.py"
            )
            self.assertEqual(0, status)
            self.assertEqual("", stdout)
            self.assertEqual("NOT CHECKED python: missing ruff\n", stderr)

    def test_existing_findings_pass_when_lines_shift(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": WIDGETS})
            write_file(root, "app.py", '"""Widgets."""\n\nVALUE = 1\n\n' + WIDGETS)
            status, _, stderr = self.hook(root, "--file", "app.py", tool=None)
            self.assertEqual(0, status)
            self.assertNotIn("python-ast", stderr)
            self.assertNotIn(HEADER, stderr)

    def test_new_stub_is_reported_without_the_existing_one(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": WIDGETS})
            write_file(root, "app.py", EDITED + "\n\ndef added():\n    pass\n")
            status, _, stderr = self.hook(root, "--file", "app.py")
            self.assertEqual(2, status)
            self.assertEqual(
                [
                    "loki: post-write check failed; files are already changed.",
                    "app.py:35: python-ast: stub body in added",
                    "NOT CHECKED python: missing ruff",
                ],
                stderr.splitlines(),
            )

    def test_new_file_is_checked_whole(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": "VALUE = 1\n"})
            write_file(root, "fresh.py", "def todo():\n    ...\n")
            status, _, stderr = self.hook(root, "--file", "fresh.py")
            self.assertEqual(2, status)
            self.assertIn("fresh.py:1: python-ast: stub body in todo", stderr)

    def test_new_import_is_resolved_by_the_project_interpreter(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": WIDGETS})
            write_file(root, "app.py", "import invented_package\n" + WIDGETS)
            python = interpreter(
                root.parent, f"{root.name}-python", '["invented_package"]'
            )
            self.addCleanup(python.unlink)
            status, _, stderr = self.hook(
                root, "--file", "app.py", "--python", str(python), tool=None
            )
            self.assertEqual(2, status)
            self.assertEqual(
                [
                    "loki: post-write check failed; files are already changed.",
                    "app.py:1: python-ast: unresolved import invented_package",
                ],
                stderr.splitlines(),
            )
            with patch.dict(os.environ, {"LOKI_PYTHON": str(python)}):
                status, _, stderr = self.hook(root, "--file", "app.py", tool=None)
            self.assertEqual(2, status)
            self.assertIn("unresolved import invented_package", stderr)
            present = interpreter(root.parent, f"{root.name}-present")
            self.addCleanup(present.unlink)
            status, _, stderr = self.hook(
                root, "--file", "app.py", "--python", str(present), tool=None
            )
            self.assertEqual((0, ""), (status, stderr))

    def test_new_import_without_an_interpreter_is_not_checked(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": WIDGETS})
            write_file(root, "app.py", "import invented_package\n" + WIDGETS)
            status, _, stderr = self.hook(root, "--file", "app.py", tool=None)
            self.assertEqual(0, status)
            self.assertEqual(
                "NOT CHECKED python imports: no project interpreter found "
                "(set LOKI_PYTHON or pass --python)\n",
                stderr,
            )
            with patch.dict(os.environ, {"LOKI_STRICT": "1"}):
                status, _, stderr = self.hook(root, "--file", "app.py", tool=None)
            self.assertEqual(2, status)
            self.assertIn(HEADER, stderr)
            self.assertIn("NOT CHECKED python imports", stderr)

    def test_strict_mode_still_fails_missing_analyzers(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": WIDGETS})
            write_file(root, "app.py", EDITED)
            with patch.dict(os.environ, {"LOKI_STRICT": "1"}):
                status, _, stderr = self.hook(root, "--file", "app.py")
            self.assertEqual(2, status)
            self.assertEqual(
                [
                    "loki: post-write check failed; files are already changed.",
                    "app.py: loki: missing ruff",
                ],
                stderr.splitlines(),
            )

    def test_namesake_functions_are_not_compared_with_each_other(self):
        """`__init__ cyclomatic complexity 1 -> 14` for an untouched method."""
        simple = "class A:\n    def __init__(self, x):\n        self.x = x\n\n"
        method = "".join(
            "    " + line for line in branchy("__init__", 13).splitlines(keepends=True)
        )
        source = simple + "class B:\n" + method + "\n" + simple.replace("A", "C")
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": source})
            write_file(
                root, "app.py", source.replace("self.x = x", "self.x = x + 1", 1)
            )
            self.assertEqual(
                [], loki.written_slop(root, [root / "app.py"], deadline=None)
            )
            grown = source.replace("if x == 0:", "if x == 0 or x == 99:")
            write_file(root, "app.py", grown)
            notes = loki.written_slop(root, [root / "app.py"], deadline=None)
            self.assertEqual(1, len(notes), notes)
            self.assertIn("__init__ cyclomatic complexity 14 -> 15 (> 10)", notes[0])
            self.assertTrue(notes[0].startswith("app.py:6: "), notes[0])

    def test_changed_functions_pairs_namesakes_conservatively(self):
        def metric(name: str, start: int, end: int, complexity: int):
            return loki.FunctionMetric("a.py", name, start, end, complexity, 1, 0)

        before = "def f(): one\ndef f(): two\ndef g(): old\n"
        after = "def f(): two\ndef f(): changed\ndef f(): added\ndef h(): new\n"
        old = [metric("f", 1, 1, 3), metric("f", 2, 2, 12), metric("g", 3, 3, 2)]
        new = [
            metric("f", 1, 1, 12),
            metric("f", 2, 2, 20),
            metric("f", 3, 3, 30),
            metric("h", 4, 4, 11),
        ]
        pairs = loki.changed_functions(old, new, before, after)
        self.assertEqual(
            [("f", 20, 3), ("f", 30, 3), ("h", 11, None)],
            [
                (item.name, item.complexity, prior and prior.complexity)
                for item, prior in pairs
            ],
        )

    def test_advisory_findings_do_not_fail_the_check(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": "def f(x):\n    return x\n"})
            write_file(root, "app.py", branchy("f", 12))
            status, stdout, stderr = self.hook(root, "--file", "app.py")
            self.assertEqual(0, status)
            self.assertEqual("", stdout)
            self.assertNotIn(HEADER, stderr)
            self.assertIn("loki/slop-complexity", stderr)
            self.assertIn("NOT CHECKED python: missing ruff", stderr)

    def test_failed_text_output_labels_advisory_lines(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": "def f(x):\n    return x\n"})
            write_file(root, "app.py", branchy("f", 12) + "\n\ndef todo():\n    pass\n")
            status, _, stderr = self.hook(root, "--file", "app.py")
            self.assertEqual(2, status)
            lines = stderr.splitlines()
            self.assertEqual(
                [
                    "loki: post-write check failed; files are already changed.",
                    "app.py:29: python-ast: stub body in todo",
                    "loki: advisory (not blocking):",
                ],
                lines[:3],
            )
            self.assertIn("loki/slop-complexity", lines[3])
            self.assertEqual("NOT CHECKED python: missing ruff", lines[4])

    def test_json_format_separates_blocking_advisory_and_not_checked(self):
        with temporary_root() as root, no_project_python():
            commit(root, {"app.py": "def f(x):\n    return x\n"})
            write_file(root, "app.py", branchy("f", 12))
            status, stdout, stderr = self.hook(
                root, "--file", "app.py", "--format", "json"
            )
            self.assertEqual(0, status)
            report = json.loads(stdout)
            self.assertEqual("passed", report["status"])
            self.assertEqual(loki.__version__, report["loki"])
            self.assertEqual("hook", report["command"])
            self.assertEqual([], report["blocking"])
            self.assertEqual(
                ["NOT CHECKED python: missing ruff"], report["not_checked"]
            )
            (advisory,) = report["advisory"]
            self.assertEqual(
                ("app.py", 1, "loki/slop-complexity"),
                (advisory["path"], advisory["line"], advisory["rule"]),
            )
            self.assertIn("loki/slop-complexity", stderr)

            write_file(root, "app.py", branchy("f", 12) + "\n\ndef todo():\n    pass\n")
            status, stdout, _ = self.hook(root, "--file", "app.py", "--format", "json")
            self.assertEqual(2, status)
            report = json.loads(stdout)
            self.assertEqual("blocked", report["status"])
            self.assertEqual(
                [
                    {
                        "text": "app.py:29: python-ast: stub body in todo",
                        "path": "app.py",
                        "line": 29,
                        "rule": "python-ast",
                    }
                ],
                report["blocking"],
            )
            self.assertEqual(1, len(report["advisory"]))

            write_file(root, "app.py", "def f(x):\n    return x + 1\n")
            status, stdout, stderr = self.hook(
                root, "--file", "app.py", "--format", "json", tool=None
            )
            self.assertEqual((0, ""), (status, stderr))
            report = json.loads(stdout)
            self.assertEqual("passed", report["status"])
            self.assertEqual([], report["blocking"] + report["advisory"])

    def test_json_format_reports_errors_and_unparsed_findings(self):
        with temporary_root() as root:
            commit(root, {"app.py": "VALUE = 1\n"})
            payload = json.dumps({"tool_input": {"file_path": "app.py"}})
            with patch.object(loki.sys, "stdin") as stdin:
                stdin.read.return_value = payload
                status, stdout, stderr = self.hook(
                    root, "--harness", "claude", "--format", "json"
                )
            self.assertEqual(2, status)
            report = json.loads(stdout)
            self.assertEqual("error", report["status"])
            self.assertIn("--format json requires --file", report["error"])
            self.assertIn("--format json requires --file", stderr)
            with patch.object(
                loki, "load_config", side_effect=ValueError("bad policy")
            ):
                status, stdout, _ = self.hook(
                    root, "--file", "app.py", "--format", "json"
                )
            self.assertEqual(2, status)
            self.assertEqual("error", json.loads(stdout)["status"])
            self.assertEqual(
                {"text": "git: cannot resolve HEAD"},
                loki.hook_report("hook", ["git: cannot resolve HEAD"], [])["blocking"][
                    0
                ],
            )
            self.assertEqual(
                {"text": "app.py: F401: unused", "path": "app.py", "rule": "F401"},
                loki.hook_report("hook", ["app.py: F401: unused"], [])["blocking"][0],
            )

    def test_context_names_engine_formats_for_hosts_only(self):
        with temporary_root() as root:
            with argv("--root", str(root), "context", "--host", "ultron"):
                _, stdout, _ = capture_output(loki.main)
            self.assertEqual(
                {"version": loki.__version__, "formats": ["text", "json"]},
                json.loads(stdout)["loki"],
            )
            with argv("--root", str(root), "context"):
                _, stdout, _ = capture_output(loki.main)
            self.assertEqual(["hookSpecificOutput"], list(json.loads(stdout)))

    def test_scan_reports_unknown_imports_once(self):
        with temporary_root() as root, no_project_python():
            commit(
                root,
                {
                    "a.py": "import numpy\n",
                    "b.py": "import pandas\n",
                    "c.py": "X = 1\n",
                },
            )
            with patch.object(loki, "scan_command", return_value=(None, [])):
                status, stdout, _ = capture_output(loki.scan, root, {}, False, False)
                self.assertEqual(0, status)
                self.assertEqual(1, stdout.count("NOT CHECKED python imports"))
                status, stdout, _ = capture_output(loki.scan, root, {}, False, True)
                self.assertEqual(1, status)
                self.assertEqual(1, stdout.count("NOT CHECKED python imports"))
                python = interpreter(root.parent, f"{root.name}-python", '["pandas"]')
                self.addCleanup(python.unlink)
                status, stdout, _ = capture_output(
                    loki.scan, root, {}, False, True, None, str(python)
                )
                self.assertEqual(1, status)
                self.assertIn("b.py:1: python-ast: unresolved import pandas", stdout)
                self.assertNotIn("numpy", stdout)


if __name__ == "__main__":
    unittest.main()
