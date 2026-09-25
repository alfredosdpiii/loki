import io
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git

TSC = Path.home() / ".cache/loki-bench/ts/node_modules/typescript/bin/tsc"


def metrics(path, text):
    return {
        item.name: (item.complexity, item.nesting)
        for item in loki.function_metrics(path, text)
    }


def commit(root, files):
    git(root, "init", "-q")
    for name, content in files.items():
        write_file(root, name, content)
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")


def branchy(name, count, language="python"):
    """A function with exactly `count` if-branches (CC = count + 1)."""
    if language == "python":
        body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(count))
        return f"def {name}(x):\n{body}    return -1\n"
    body = "".join(f"  if (x === {i}) {{ return {i}; }}\n" for i in range(count))
    return f"export function {name}(x: number): number {{\n{body}  return -1;\n}}\n"


def repeated(prefix):
    """A block of over 100 normalized tokens; identifiers differ per prefix."""
    lines = [
        f"def {prefix}_total(items, rate, floor):",
        f"    {prefix}_sum = 0",
        "    for item in items:",
        "        if item.price > floor and item.quantity > 0:",
        f"            {prefix}_sum += item.price * item.quantity * (1 + rate)",
        "        elif item.price < 0:",
        "            raise ValueError('negative price', item.price, item.name)",
        "        else:",
        f"            {prefix}_sum -= item.discount * rate + floor - item.fee",
        f"    return round({prefix}_sum, 2), len(items), max(i.price for i in items)",
    ]
    return "\n".join(lines) + "\n"


class ComplexityTests(unittest.TestCase):
    def test_python_is_exact(self):
        text = (
            "def f(x, y):\n"
            "    if x and y or x:\n"
            "        for i in range(x):\n"
            "            while i:\n"
            "                i -= 1\n"
            "    elif y:\n"
            "        pass\n"
            "    try:\n        pass\n    except ValueError:\n        pass\n"
            "    z = [a for a in y if a]\n"
            "    def inner():\n        return 1 if x else 2\n"
            "    match x:\n        case 1:\n            pass\n        case _:\n            pass\n"
            "    return z\n"
        )
        found = metrics("a.py", text)
        # if + 2 boolean operators + for + while + elif + except + comprehension
        # (for + if) + one non-default match case = 10 decisions.
        self.assertEqual((11, 3), found["f"])
        self.assertEqual((2, 0), found["inner"])
        self.assertEqual({}, metrics("a.py", "def f(:\n"))

    def test_structural_approximation_for_other_languages(self):
        cases = {
            "a.rs": (
                "fn f(x: Option<u8>) -> u8 {\n"
                "    if x.is_some() && true { return 1; }\n"
                "    match x { Some(1) => 1, Some(_) => 2, None => 3 }\n}\n",
                4,
            ),
            "a.ex": "defmodule A do\n  def f(x) do\n    if x, do: 1, else: 2\n  end\nend\n",
            "a.rb": "def f(x)\n  return 1 if x && x > 2\n  2\nend\n",
            "A.java": (
                "class A {\n  int f(int x) {\n"
                "    if (x > 1 || x < 0) { return 1; }\n"
                "    for (int i = 0; i < x; i++) { x--; }\n    return x;\n  }\n}\n"
            ),
            "a.kt": "fun f(x: Int): Int {\n    if (x > 1) { return 1 }\n    return 0\n}\n",
            "a.ts": "function f(x) { if (x) { return 1; } return x ?? 2; }\n",
        }
        expected = {"a.rs": 5, "a.ex": 2, "a.rb": 3, "A.java": 4, "a.kt": 2, "a.ts": 3}
        for path, case in cases.items():
            text = case[0] if isinstance(case, tuple) else case
            with self.subTest(path=path):
                found = loki.masked_functions(path, text, loki.slop_language(path))
                self.assertEqual(expected[path], found[0].complexity, found)
        self.assertEqual([], loki.function_metrics("README.md", "x"))

    @unittest.skipUnless(shutil.which("go"), "Go unavailable")
    def test_go_is_exact_and_closures_are_separate(self):
        text = (
            "package main\nfunc f(x int) int {\n"
            "\tif x > 1 && x < 5 { return 1 }\n"
            "\tfor i := 0; i < x; i++ {\n"
            "\t\tswitch i { case 1: return 2; case 2: return 3; default: }\n\t}\n"
            "\tg := func() int { if x > 0 { return 1 }; return 0 }\n\treturn g()\n}\n"
            "type T struct{}\nfunc (t *T) M() {}\n"
        )
        with temporary_root() as home, patch.dict(os.environ, {"HOME": str(home)}):
            found = loki.go_function_metrics({"a.go": text})["a.go"]
        self.assertEqual(
            {("f", 6, 2), ("<anonymous>", 2, 1), ("T.M", 1, 0)},
            {(item.name, item.complexity, item.nesting) for item in found},
        )

    @unittest.skipUnless(shutil.which("elixir"), "Elixir unavailable")
    def test_elixir_is_exact(self):
        text = (
            'defmodule A do\n  @moduledoc "é"\n'
            "  def f(x) when is_integer(x) do\n"
            "    case x do\n      1 -> :one\n      2 -> :two\n      _ -> :other\n    end\n"
            "  end\n"
            "  def g(x), do: if x and true, do: 1, else: 2\n"
            "  defp h(x) do\n    with {:ok, a} <- x, {:ok, b} <- a do\n      b\n"
            "    else\n      _ -> nil\n    end\n  end\nend\n"
        )
        found = loki.elixir_function_metrics({"a.ex": text, "bad.ex": "def ("})
        self.assertEqual(
            {("f", 3), ("g", 3), ("h", 4)},
            {(item.name, item.complexity) for item in found["a.ex"]},
        )
        self.assertEqual([], found["bad.ex"])

    @unittest.skipUnless(
        TSC.is_file() and shutil.which("node"), "TypeScript unavailable"
    )
    def test_typescript_is_exact(self):
        with (
            temporary_root() as root,
            patch.object(loki.shutil, "which", return_value=str(TSC)),
        ):
            found = loki.typescript_function_metrics(
                root,
                {
                    "a.ts": "export function f(x?: {a?: number}) {\n"
                    "  const g = () => x ?? 1;\n"
                    "  return x?.a && x.a > 1 ? 1 : 2;\n}\n"
                },
            )
        by_name = {item.name: item.complexity for item in found["a.ts"]}
        # optional chain, &&, conditional = 3 decisions; the arrow function has ??.
        self.assertEqual({"f": 4, "g": 2}, by_name)


class DuplicationAndCycleTests(unittest.TestCase):
    def test_renamed_copies_are_one_group_and_self_repetition_is_not(self):
        files = {"a.py": repeated("alpha"), "b.py": "\n\n" + repeated("beta")}
        covered, groups = loki.clone_lines(files)
        self.assertEqual(1, len(groups))
        self.assertEqual({"a.py", "b.py"}, {path for path, _, _ in groups[0]})
        self.assertEqual(set(range(3, 13)), covered["b.py"])
        table = (
            "VALUES = [\n"
            + "".join(f"    ({i}, 'x', {i}.5),\n" for i in range(200))
            + "]\n"
        )
        self.assertEqual([], loki.clone_lines({"t.py": table})[1])
        focused = loki.clone_lines({**files, "c.py": "x = 1\n"}, focus={"c.py"})
        self.assertEqual([], focused[1])

    def test_import_cycles(self):
        python = loki.python_import_graph(
            {
                "pkg/__init__.py": "",
                "pkg/a.py": "from pkg import b\n",
                "pkg/b.py": "from . import a\nimport os\n",
                "pkg/c.py": "import pkg.a\n",
                "broken.py": "import (",
            }
        )
        self.assertEqual([["pkg/a.py", "pkg/b.py"]], loki.import_cycles(python))
        script = loki.javascript_import_graph(
            {
                "src/a.ts": "import { b } from './b';\n",
                "src/b.ts": "import { a } from './a.js';\n",
                "src/c.ts": "import type { a } from './a';\nimport './d';\n",
                "src/d/index.ts": "import { c } from '../c';\n",
            }
        )
        self.assertEqual(
            [["src/a.ts", "src/b.ts"], ["src/c.ts", "src/d/index.ts"]],
            loki.import_cycles(script),
        )
        elixir = loki.elixir_import_graph(
            {
                "lib/a.ex": "defmodule A do\n  import B\nend\n",
                "lib/b.ex": "defmodule B do\n  use A\n  alias C\nend\n",
                "lib/c.ex": "defmodule C do\n  require A\nend\n",
            }
        )
        self.assertEqual([["lib/a.ex", "lib/b.ex"]], loki.import_cycles(elixir))

    def test_verbosity_heuristics(self):
        python = (
            "def f(x):\n    if x:\n        return True\n    else:\n        return False\n"
            "def g(x):\n    y = x + 1\n    return y\n"
            "def h():\n    try:\n        run()\n    except ValueError:\n        raise\n"
            "ok = flag == True\n# value = compute()\n# a note\n"
        )
        self.assertEqual(
            {2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 14, 15},
            loki.verbose_lines("a.py", python),
        )
        script = (
            "if (x) { return true; } else { return false; }\nconst y = z === true;\n"
        )
        script += "// const old = 1;\n// explain\n"
        self.assertEqual({1, 2, 3}, loki.verbose_lines("a.ts", script))
        self.assertEqual(set(), loki.verbose_lines("a.py", "def f(:"))


class IndexTests(unittest.TestCase):
    def test_formula_matches_trellis_constants(self):
        self.assertEqual(100, loki.slop_saturate(0.5, 0.25))
        self.assertAlmostEqual(40.0, loki.slop_saturate(0.1, 0.25))
        self.assertAlmostEqual(40.938, loki.slop_count(20, 20), places=3)
        with temporary_root() as root:
            files = {
                "src/app.py": branchy("big", 14) + repeated("alpha"),
                "src/other.py": repeated("beta"),
                "tests/test_app.py": branchy("hidden", 30),
                "vendor/lib.py": branchy("vendored", 30),
            }
            report = loki.slop_measure(root, files)
        self.assertEqual(1, report["metrics"]["eroded_functions"])
        self.assertEqual(["big"], [item["function"] for item in report["hotspots"]])
        self.assertEqual(1, report["metrics"]["clone_groups"])
        expected = (
            0.5
            * (
                loki.slop_saturate(report["metrics"]["eroded_share"], 0.25)
                + loki.slop_count(1, 20)
            )
            / 2
        )
        self.assertAlmostEqual(
            expected, report["contributions"]["complexity-erosion"], 1
        )
        self.assertEqual(
            int(sum(report["contributions"].values()) + 0.5), report["index"]
        )

    def test_policy_validation(self):
        for bad in ({"slop": []}, {"slop": {"x": 1}}, {"slop": {"block": 1}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                loki.validate_config(bad)
        with self.assertRaises(ValueError):
            loki.validate_config({"slop": {"max_index": 101}})
        loki.validate_config({"slop": {"block": True, "max_index": 50}})


class CommandTests(unittest.TestCase):
    def run_slop(self, root, *extra):
        with argv("--root", str(root), "slop", *extra):
            return capture_output(loki.main)

    def test_audit_baseline_and_policy(self):
        with temporary_root() as root:
            commit(root, {"app.py": "def small(x):\n    return x\n"})
            status, output, _ = self.run_slop(root)
            self.assertEqual(0, status)
            self.assertIn("Sloppiness index: 0/100", output)
            write_file(root, "app.py", branchy("big", 20))
            status, output, _ = self.run_slop(root, "--base", "HEAD")
            self.assertEqual(0, status)
            self.assertIn("new hotspot app.py:1 big", output)
            self.assertIn("(+", output)
            write_file(
                root,
                ".loki/loki.json",
                json.dumps({"slop": {"max_index": 5, "max_index_increase": 1}}),
            )
            status, output, _ = self.run_slop(root, "--base", "HEAD", "--json")
            self.assertEqual(1, status)
            report = json.loads(output)
            self.assertEqual(2, len(report["policy_failures"]))
            self.assertEqual("big", report["current"]["hotspots"][0]["function"])
            status, _, diagnostic = self.run_slop(root, "--base", "missing-ref")
            self.assertEqual(1, status)
            self.assertIn("loki:", diagnostic)

    def test_sources_follow_git_and_budgets(self):
        with temporary_root() as root:
            write_file(root, "loose.py", "x = 1\n")
            write_file(root, "node_modules/x.js", "x\n")
            self.assertEqual({"loose.py"}, set(loki.repository_sources(root)))
            commit(root, {".gitignore": "ignored/\n", "a.py": "y = 2\n"})
            write_file(root, "ignored/b.py", "z\n")
            write_file(root, "new.go", "package main\n")
            write_file(root, "big.py", "x" * (1024 * 1024 + 1))
            self.assertEqual(
                {"a.py", "loose.py", "new.go"}, set(loki.repository_sources(root))
            )
            with self.assertRaises(ValueError):
                loki.repository_sources(root, limit=4)


class WriteTimeTests(unittest.TestCase):
    def hook(self, root, path):
        payload = {
            "cwd": str(root),
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": ""},
        }
        with (
            argv("--root", str(root), "hook", "--harness", "claude"),
            patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            patch.object(loki, "check_file", return_value=[]),
        ):
            return capture_output(loki.main)

    def test_new_hotspots_clones_and_cycles_are_advisory(self):
        with temporary_root() as root:
            commit(
                root,
                {
                    "app.py": branchy("grow", 12) + "def calm(x):\n    return x\n",
                    "lib.py": repeated("alpha"),
                    "pkg/__init__.py": "",
                    "pkg/a.py": "X = 1\n",
                    "pkg/b.py": "from pkg import a\n",
                },
            )
            write_file(root, "app.py", branchy("grow", 14) + branchy("calm", 12))
            write_file(root, "copy.py", repeated("beta"))
            write_file(root, "pkg/a.py", "from pkg import b\nX = 1\n")
            notes = loki.written_slop(
                root,
                [
                    root / "app.py",
                    root / "copy.py",
                    root / "pkg/a.py",
                    root / "none.txt",
                ],
                deadline=None,
            )
            text = "\n".join(notes)
            self.assertIn("grow cyclomatic complexity 13 -> 15", text)
            self.assertIn("calm cyclomatic complexity 1 -> 13 (> 10)", text)
            write_file(root, "fresh.py", branchy("fresh", 11))
            fresh = loki.written_slop(root, [root / "fresh.py"], deadline=None)
            self.assertIn("fresh cyclomatic complexity 12 (> 10)", fresh[0])
            self.assertIn("copy.py:1: loki/slop-duplication", text)
            self.assertIn("lib.py:1-10", text)
            self.assertIn(
                "loki/slop-import-cycle: import cycle pkg/a.py -> pkg/b.py", text
            )
            write_file(
                root, "app.py", branchy("grow", 12) + "def calm(x):\n    return x\n"
            )
            self.assertEqual(
                [], loki.written_slop(root, [root / "app.py"], deadline=None)
            )
            self.assertEqual(
                [], loki.written_slop(root, [root / "x.md"], deadline=None)
            )
            with patch.object(loki, "SLOP_WRITE_BUDGET", 1):
                notes = loki.written_slop(root, [root / "copy.py"], deadline=None)
            self.assertEqual([], notes)

    def test_hook_reports_by_default_and_blocks_when_configured(self):
        with temporary_root() as root:
            commit(root, {"app.py": "def f(x):\n    return x\n"})
            write_file(root, "app.py", branchy("f", 12))
            status, output, diagnostic = self.hook(root, "app.py")
            self.assertEqual(0, status)
            self.assertIn("loki/slop-complexity", output + diagnostic)
            write_file(root, ".loki/loki.json", json.dumps({"slop": {"block": True}}))
            git(root, "add", ".loki/loki.json")
            git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "p")
            status, _, diagnostic = self.hook(root, "app.py")
            self.assertEqual(2, status)
            self.assertIn("loki/slop-complexity", diagnostic)
            with patch.object(loki, "written_slop", side_effect=ValueError("broken")):
                status, _, diagnostic = self.hook(root, "app.py")
            self.assertEqual(0, status)
            self.assertIn("NOT CHECKED slop: broken", diagnostic)
