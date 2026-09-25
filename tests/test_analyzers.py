import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git

BENCH = Path.home() / ".cache/loki-bench"
MYPY = shutil.which("mypy") or str(BENCH / "py/bin/mypy")
GOLANGCI = shutil.which("golangci-lint") or str(BENCH / "golangci/golangci-lint")


def commit(root, files):
    git(root, "init", "-q")
    for name, content in files.items():
        write_file(root, name, content)
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class ToolResolutionTests(unittest.TestCase):
    def test_project_tools_win_over_path(self):
        with temporary_root() as root:
            with patch.object(loki.shutil, "which", return_value="/usr/bin/oxlint"):
                self.assertEqual("/usr/bin/oxlint", loki.resolve_tool(root, "oxlint"))
                write_file(root, "node_modules/.bin/oxlint")
                self.assertEqual(
                    str(root / "node_modules/.bin/oxlint"),
                    loki.resolve_tool(root, "oxlint"),
                )

    def test_typescript_compiler_resolution(self):
        with temporary_root() as root:
            tsc = write_file(root, "global/typescript/bin/tsc")
            with patch.object(loki.shutil, "which", return_value=str(tsc)):
                self.assertIsNone(loki.typescript_compiler(root))
                compiler = write_file(root, "global/typescript/lib/typescript.js")
                self.assertEqual(compiler, loki.typescript_compiler(root))
                local = write_file(root, "node_modules/typescript/lib/typescript.js")
                self.assertEqual(local, loki.typescript_compiler(root))
            with patch.object(loki.shutil, "which", return_value=None):
                (root / "node_modules/typescript/lib/typescript.js").unlink()
                self.assertIsNone(loki.typescript_compiler(root))


class MypyTests(unittest.TestCase):
    def test_missing_mypy_or_paths_is_silent(self):
        with temporary_root() as root:
            with patch.object(loki.shutil, "which", return_value=None):
                self.assertEqual([], loki.mypy_violations(root, ["a.py"]))
            with patch.object(loki.shutil, "which", return_value="/bin/mypy"):
                self.assertEqual([], loki.mypy_violations(root, []))

    def test_net_new_errors_use_shadowed_committed_text(self):
        outputs = [
            completed(
                1,
                'app.py:3: error: Incompatible return value type (got "str", '
                'expected "int")  [return-value]\n'
                'app.py:1: error: Name "old" is not defined  [name-defined]\n'
                "other.py:1: error: ignored  [misc]\napp.py:1: note: hint\n",
            ),
            completed(
                1, 'app.py:1: error: Name "old" is not defined  [name-defined]\n'
            ),
        ]
        with temporary_root() as root:
            commit(root, {"app.py": "old\n"})
            write_file(root, ".venv/bin/mypy")
            write_file(root, "app.py", "old\ndef f() -> int:\n    return 'x'\n")
            real = subprocess.run

            def run_tool(command, **kwargs):
                if command[0] == "git":
                    return real(command, **kwargs)
                return outputs.pop(0)

            with patch.object(loki.subprocess, "run", side_effect=run_tool) as run:
                self.assertEqual(
                    [
                        "app.py:3: mypy[return-value]: Incompatible return value type "
                        '(got "str", expected "int")'
                    ],
                    loki.mypy_violations(root, ["app.py"]),
                )
            calls = [call.args[0] for call in run.call_args_list]
            calls = [command for command in calls if command[0] != "git"]
            self.assertEqual(str(root / ".venv/bin/mypy"), calls[0][0])
            self.assertIn("--shadow-file", calls[1])

    def test_unannotated_files_skip_mypy(self):
        with temporary_root() as root:
            write_file(root, "app.py", "def f(a):\n    return a\n")
            with (
                patch.object(loki.shutil, "which", return_value="/bin/mypy"),
                patch.object(loki.subprocess, "run") as run,
            ):
                self.assertEqual([], loki.mypy_violations(root, ["app.py"]))
            run.assert_not_called()

    def test_clean_run_skips_base_and_crashes_raise(self):
        with temporary_root() as root:
            write_file(root, "app.py", "x: int = 1\n")
            with (
                patch.object(loki.shutil, "which", return_value="/bin/mypy"),
                patch.object(loki.subprocess, "run", return_value=completed()) as run,
            ):
                self.assertEqual([], loki.mypy_violations(root, ["app.py"]))
                self.assertEqual(1, run.call_count)
            with (
                patch.object(loki.shutil, "which", return_value="/bin/mypy"),
                patch.object(loki.subprocess, "run", return_value=completed(2, "", "")),
            ):
                with self.assertRaisesRegex(ValueError, "mypy exited 2"):
                    loki.mypy_violations(root, ["app.py"])

    @unittest.skipUnless(os.access(MYPY, os.X_OK), "mypy unavailable")
    def test_real_mypy_reports_new_return_type_error_only(self):
        with temporary_root() as root:
            commit(root, {"app.py": "def old() -> int:\n    return 'debt'\n"})
            write_file(
                root,
                "app.py",
                "\n\ndef old() -> int:\n    return 'debt'\n\n"
                "def count() -> int:\n    return 'three'\n",
            )
            with (
                patch.object(loki.shutil, "which", return_value=MYPY),
                patch.dict(os.environ, {"HOME": str(root / "home")}),
            ):
                findings = loki.mypy_violations(root, ["app.py"])
        self.assertEqual(1, len(findings))
        self.assertIn("app.py:7: mypy[return-value]", findings[0])


class GolangciTests(unittest.TestCase):
    def test_outcomes(self):
        with temporary_root() as root:
            with patch.object(loki.shutil, "which", return_value=None):
                self.assertEqual([], loki.golangci_violations(root, "./"))
            with patch.object(loki.shutil, "which", return_value="/bin/golangci-lint"):
                with patch.object(loki.subprocess, "run", return_value=completed()):
                    self.assertEqual([], loki.golangci_violations(root, "./"))
                issue = "main.go:3:15: Error return value is not checked (errcheck)"
                with patch.object(
                    loki.subprocess, "run", return_value=completed(1, issue + "\n\n")
                ):
                    self.assertEqual(
                        [f"golangci-lint: {issue}"],
                        loki.golangci_violations(root, "./"),
                    )
                for result in (completed(3, "", "config error"), completed(1, "", "")):
                    with patch.object(loki.subprocess, "run", return_value=result):
                        with self.assertRaises(ValueError):
                            loki.golangci_violations(root, "./")

    @unittest.skipUnless(
        os.access(GOLANGCI, os.X_OK) and shutil.which("go"), "golangci-lint unavailable"
    )
    def test_real_golangci_reports_only_changed_lines(self):
        with temporary_root() as root:
            commit(
                root,
                {
                    "go.mod": "module example.invalid/x\n\ngo 1.25\n",
                    "main.go": 'package main\nimport "os"\n'
                    'func main() { _ = os.Remove("old") }\n',
                    ".golangci.yml": (
                        Path(loki.__file__).parent / "templates/.golangci.yml"
                    ).read_text(),
                },
            )
            write_file(
                root,
                "extra.go",
                'package main\nimport "os"\nfunc extra() { _ = os.Remove("new") }\n'
                "var _ = extra\n",
            )
            with (
                patch.object(loki.shutil, "which", return_value=GOLANGCI),
                patch.dict(os.environ, {"GOFLAGS": "-mod=mod"}),
            ):
                findings = loki.golangci_violations(root, "./")
        self.assertTrue(findings)
        self.assertTrue(all("extra.go" in item for item in findings))


class ClippyTests(unittest.TestCase):
    def message(self, file, line, code, text, level="warning", primary=True):
        return json.dumps(
            {
                "reason": "compiler-message",
                "message": {
                    "level": level,
                    "message": text,
                    "code": {"code": code} if code else None,
                    "spans": [
                        {"file_name": file, "line_start": line, "is_primary": primary}
                    ],
                },
            }
        )

    def test_cargo_project_lookup(self):
        with temporary_root() as root:
            write_file(root, "crate/Cargo.toml", "[package]\n")
            source = write_file(root, "crate/src/lib.rs")
            self.assertEqual(
                (root / "crate").resolve(), loki.cargo_project(source, root)
            )
            self.assertIsNone(loki.cargo_project(write_file(root, "x.rs"), root))
            self.assertIsNone(loki.cargo_project(Path("/elsewhere/x.rs"), root))

    def test_diagnostics_are_parsed_and_filtered(self):
        with temporary_root() as root:
            write_file(root, "src/lib.rs", "fn a() { todo!() }\n")
            stdout = "\n".join(
                [
                    "not json",
                    json.dumps({"reason": "build-finished"}),
                    self.message(
                        "src/lib.rs", 1, "clippy::todo", "`todo` should not be present"
                    ),
                    self.message("src/lib.rs", 1, None, "aborting", level="error"),
                    self.message("src/lib.rs", 1, "x", "note", level="note"),
                    self.message("src/lib.rs", 1, "x", "secondary", primary=False),
                    self.message("../outside.rs", 1, "x", "outside"),
                ]
            )
            with patch.object(
                loki.subprocess, "run", return_value=completed(0, stdout)
            ):
                found = loki.clippy_diagnostics(root, root / "target", deadline=None)
            self.assertEqual(
                [
                    (
                        (
                            "src/lib.rs",
                            "clippy::todo",
                            "`todo` should not be present",
                            "fn a() { todo!() }",
                        ),
                        1,
                    ),
                    (("src/lib.rs", "error", "aborting", "fn a() { todo!() }"), 1),
                ],
                found,
            )
            with patch.object(
                loki.subprocess, "run", return_value=completed(101, "", "error: bad\n")
            ):
                with self.assertRaisesRegex(
                    ValueError, "cargo clippy failed: error: bad"
                ):
                    loki.clippy_diagnostics(root, root / "target", deadline=None)
            with patch.object(loki.subprocess, "run", return_value=completed(101)):
                with self.assertRaisesRegex(ValueError, "exit 101"):
                    loki.clippy_diagnostics(root, root / "target", deadline=None)

    def test_net_new_against_materialized_base(self):
        with temporary_root() as root:
            commit(
                root,
                {"Cargo.toml": "[package]\n", "src/lib.rs": "fn a() { todo!() }\n"},
            )
            source = write_file(
                root, "src/lib.rs", "\nfn a() { todo!() }\nfn b() { todo!() }\n"
            )
            old = (("src/lib.rs", "clippy::todo", "todo", "fn a() { todo!() }"), 1)
            current = [
                (("src/lib.rs", "clippy::todo", "todo", "fn a() { todo!() }"), 2),
                (("src/lib.rs", "clippy::todo", "todo", "fn b() { todo!() }"), 3),
            ]
            with (
                patch.object(loki.shutil, "which", return_value="/bin/cargo"),
                patch.object(
                    loki, "clippy_diagnostics", side_effect=[current, [old]]
                ) as diagnostics,
            ):
                self.assertEqual(
                    ["src/lib.rs:3: clippy::todo: todo"],
                    loki.clippy_violations(source, root),
                )
            self.assertEqual(2, diagnostics.call_count)
            with (
                patch.object(loki.shutil, "which", return_value="/bin/cargo"),
                patch.object(loki, "clippy_diagnostics", return_value=[]),
            ):
                self.assertEqual([], loki.clippy_violations(source, root))
            with patch.object(loki.shutil, "which", return_value=None):
                self.assertEqual([], loki.clippy_violations(source, root))

    def test_new_crate_has_empty_base(self):
        with temporary_root() as root:
            commit(root, {"README.md": "x\n"})
            write_file(root, "Cargo.toml", "[package]\n")
            source = write_file(root, "src/lib.rs", "fn b() { todo!() }\n")
            current = [
                (("src/lib.rs", "clippy::todo", "todo", "fn b() { todo!() }"), 1)
            ]
            with (
                patch.object(loki.shutil, "which", return_value="/bin/cargo"),
                patch.object(loki, "clippy_diagnostics", return_value=current),
            ):
                self.assertEqual(
                    ["src/lib.rs:1: clippy::todo: todo"],
                    loki.clippy_violations(source, root),
                )

    @unittest.skipUnless(shutil.which("cargo"), "cargo unavailable")
    def test_real_clippy_reports_type_errors(self):
        with temporary_root() as root:
            commit(
                root,
                {
                    "Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\n'
                    'edition = "2021"\n',
                    "src/lib.rs": "pub fn count() -> u32 { 1 }\n",
                },
            )
            source = write_file(
                root, "src/lib.rs", 'pub fn count() -> u32 { "five" }\n'
            )
            findings = loki.clippy_violations(source, root)
        self.assertTrue(any("E0308" in item for item in findings), findings)


class TypescriptModeTests(unittest.TestCase):
    def test_explicit_settings_and_default_mode(self):
        with temporary_root() as root:
            with patch.object(
                loki, "typescript_violations", return_value=["e"]
            ) as check:
                self.assertEqual(
                    [], loki.typescript_findings(root, {"typescript_check": False})
                )
                self.assertEqual(
                    ["e"], loki.typescript_findings(root, {"typescript_check": True})
                )
                self.assertEqual([], loki.typescript_findings(root, {}))
                write_file(root, "tsconfig.json", "{}")
                self.assertEqual(["e"], loki.typescript_findings(root, {}))
            self.assertEqual(2, check.call_count)

    def test_default_mode_reports_setup_problems_as_not_checked(self):
        def missing(root, *, deadline=None, notices=None):
            notices.append("typescript: required TypeScript compiler is missing")
            return []

        with temporary_root() as root:
            write_file(root, "tsconfig.json", "{}")
            with patch.object(loki, "typescript_violations", side_effect=missing):
                warnings = []
                self.assertEqual(
                    [], loki.typescript_findings(root, {}, warnings=warnings)
                )
                self.assertIn("NOT CHECKED typescript types", warnings[0])
                result = capture_output(loki.typescript_findings, root, {})
                self.assertIn("NOT CHECKED", result[2])
                with patch.dict(os.environ, {"LOKI_STRICT": "1"}):
                    self.assertEqual(1, len(loki.typescript_findings(root, {})))
            with patch.object(
                loki, "typescript_violations", side_effect=ValueError("broken")
            ):
                warnings = []
                loki.typescript_findings(root, {}, warnings=warnings)
                self.assertEqual(["NOT CHECKED typescript types: broken"], warnings)

    def test_setup_problems_block_only_when_explicit(self):
        with temporary_root() as root:
            with patch.object(loki, "typescript_compiler", return_value=None):
                notices = []
                self.assertEqual([], loki.typescript_violations(root, notices=notices))
                self.assertEqual(1, len(notices))
                self.assertEqual(1, len(loki.typescript_violations(root)))


class ShellGuardTests(unittest.TestCase):
    def violation(self, command):
        with temporary_root() as root:
            root = root.resolve()
            (root / "docs").mkdir()
            return loki.shell_violation(command, root=root, cwd=root)

    def test_print_redirects_only_reach_plain_project_notes(self):
        self.assertIsNone(self.violation("printf 'note' > notes.txt"))
        self.assertIsNone(self.violation("echo done >> docs/log.md"))
        for command, expected in (
            ("printf 'x' > app.py", "shell redirect into app.py bypasses write"),
            ("printf 'x' > .env.txt", "bypasses write checks"),
            ("echo x > docs", "directory target"),
            ("echo x > ../outside.txt", "escapes the repository root"),
            ("printf x > .claude/settings.json", "protected"),
            ("cat secret > notes.txt", "other than echo/printf"),
            ("printf $HOME > notes.txt", "other than echo/printf"),
        ):
            with self.subTest(command=command):
                self.assertIn(expected, self.violation(command) or "")

    def test_redirect_parsing(self):
        self.assertEqual(
            ("printf note", "a.txt"), loki.shell_redirect("printf note>a.txt")
        )
        for command in (
            "echo a > b > c",
            "echo a | tee b",
            "echo 'x",
            "> a",
            "echo a &> b",
        ):
            with self.subTest(command=command):
                self.assertIsNone(loki.shell_redirect(command))

    def test_destructive_git_is_named(self):
        for command in (
            "git reset --hard",
            "git clean -fd",
            "git clean --force",
            "git push --force",
            "git push origin :main",
            "git branch -D topic",
            "git branch --delete --force topic",
            "git stash drop",
            "git checkout -- app.py",
            "git restore app.py",
            "git rebase main",
        ):
            with self.subTest(command=command):
                message = self.violation(command)
                self.assertIn("destructive", message)
                self.assertIn(command.split()[1], message)
        for command in (
            "git checkout -b topic",
            "git branch -d topic",
            "git clean -n",
            "git commit -m x",
        ):
            with self.subTest(command=command):
                self.assertNotIn("destructive", self.violation(command))

    def test_plain_printing_is_allowed(self):
        self.assertIsNone(self.violation("echo hello"))
        self.assertIsNone(self.violation("printf done"))


TSC = BENCH / "ts/node_modules/typescript/bin/tsc"


@unittest.skipUnless(TSC.is_file() and shutil.which("node"), "TypeScript unavailable")
class RealTypescriptTests(unittest.TestCase):
    def test_ancestor_type_roots_do_not_create_findings(self):
        with temporary_root() as parent:
            write_file(
                parent,
                "node_modules/@types/outside/index.d.ts",
                "declare const x: 1;\n",
            )
            root = parent / "repo"
            root.mkdir()
            commit(
                root,
                {
                    "tsconfig.json": json.dumps(
                        {"compilerOptions": {"strict": True, "noEmit": True}}
                    ),
                    "src/main.ts": "export const value: number = 1;\n",
                },
            )
            write_file(root, "src/main.ts", "export const value: number = 2;\n")
            with patch.object(loki.shutil, "which", return_value=str(TSC)):
                self.assertEqual([], loki.typescript_findings(root, {}))
                write_file(root, "src/main.ts", 'export const value: number = "two";\n')
                findings = loki.typescript_findings(root, {})
        self.assertEqual(1, len(findings))
        self.assertIn("src/main.ts:1: TS2322", findings[0])


class PreviewTypescriptTests(unittest.TestCase):
    def test_preconditions_and_failures_defer_to_post_write(self):
        with temporary_root() as root:
            changes = [("src/a.ts", "", "x")]
            self.assertEqual(
                [], loki.preview_typescript(root, {}, changes, deadline=None)
            )
            write_file(root, "tsconfig.json", "{}")
            self.assertEqual(
                [],
                loki.preview_typescript(
                    root, {"typescript_check": False}, changes, deadline=None
                ),
            )
            self.assertEqual(
                [],
                loki.preview_typescript(root, {}, [("a.py", "", "x")], deadline=None),
            )
            with patch.object(
                loki, "typescript_violations", side_effect=ValueError("x")
            ):
                self.assertEqual(
                    [], loki.preview_typescript(root, {}, changes, deadline=None)
                )
            with patch.object(
                loki, "typescript_violations", return_value=["e"]
            ) as check:
                self.assertEqual(
                    ["e"], loki.preview_typescript(root, {}, changes, deadline=None)
                )
            self.assertEqual({"src/a.ts": "x"}, check.call_args.kwargs["overrides"])

    def test_proposed_json_is_a_setup_notice(self):
        with temporary_root() as root:
            commit(root, {"tsconfig.json": "{}"})
            notices = []
            with patch.object(
                loki, "typescript_compiler", return_value=root / "tsc.js"
            ):
                self.assertEqual(
                    [],
                    loki.typescript_violations(
                        root, notices=notices, overrides={"data.json": "{}"}
                    ),
                )
            self.assertIn("data.json: JSON/config change", notices[0])


@unittest.skipUnless(TSC.is_file() and shutil.which("node"), "TypeScript unavailable")
class RealPreviewTypescriptTests(unittest.TestCase):
    def test_proposed_errors_are_found_and_clean_states_are_remembered(self):
        with temporary_root() as root, temporary_root() as home:
            commit(
                root,
                {
                    "tsconfig.json": json.dumps(
                        {"compilerOptions": {"strict": True, "noEmit": True}}
                    ),
                    "src/api.ts": "export function amount() { return 4; }\n",
                    "src/main.ts": "import { amount } from './api';\n"
                    "export const value: number = amount();\n",
                },
            )
            with (
                patch.object(loki.shutil, "which", return_value=str(TSC)),
                patch.dict(os.environ, {"HOME": str(home)}),
            ):
                broken = [
                    ("src/api.ts", "", 'export function amount() { return "5"; }\n')
                ]
                findings = loki.preview_typescript(root, {}, broken, deadline=None)
                self.assertEqual(1, len(findings))
                self.assertIn("src/main.ts:2: TS2322", findings[0])
                self.assertEqual(
                    "export function amount() { return 4; }\n",
                    (root / "src/api.ts").read_text(),
                )
                clean = "export function amount() { return 5; }\n"
                self.assertEqual(
                    [],
                    loki.preview_typescript(
                        root, {}, [("src/api.ts", "", clean)], deadline=None
                    ),
                )
                write_file(root, "src/api.ts", clean)
                with patch.object(loki, "typescript_diagnostics") as compile_:
                    self.assertEqual([], loki.typescript_findings(root, {}))
                compile_.assert_not_called()
                write_file(
                    root, "src/api.ts", 'export function amount() { return "6"; }\n'
                )
                self.assertEqual(1, len(loki.typescript_findings(root, {})))


@unittest.skipUnless(
    os.access(GOLANGCI, os.X_OK) and shutil.which("go"), "Go toolchain unavailable"
)
class RealGoHookTests(unittest.TestCase):
    def test_vet_and_golangci_run_together(self):
        real = shutil.which

        def which(name):
            return GOLANGCI if name == "golangci-lint" else real(name)

        with temporary_root() as root, temporary_root() as cache:
            commit(
                root,
                {
                    "go.mod": "module example.invalid/x\n\ngo 1.25\n",
                    "main.go": "// Package main is a fixture.\npackage main\n\n"
                    "func main() {}\n",
                    ".golangci.yml": (
                        Path(loki.__file__).parent / "templates/.golangci.yml"
                    ).read_text(),
                },
            )
            env = {"GOCACHE": str(cache / "go"), "GOTOOLCHAIN": "local"}
            with (
                patch.object(loki.shutil, "which", side_effect=which),
                patch.dict(os.environ, env),
            ):
                path = write_file(
                    root,
                    "main.go",
                    '// Package main is a fixture.\npackage main\n\nimport "os"\n\n'
                    'func main() { _ = os.Remove("x") }\n',
                )
                findings = loki.check_file(path, root, {}, checked_projects=set())
                self.assertTrue(any("errcheck" in item for item in findings), findings)
                write_file(
                    root, "main.go", "package main\n\nfunc main() { missing() }\n"
                )
                findings = loki.check_file(path, root, {})
                self.assertTrue(findings)
                self.assertTrue(all(item.startswith("go vet") for item in findings))


class OxlintPostWriteTests(unittest.TestCase):
    def run_oxlint(self, result=None, error=None):
        with temporary_root() as root:
            path = write_file(root, "a.ts", "x")
            warnings = []
            with (
                patch.object(loki, "resolve_tool", return_value="/bin/oxlint"),
                patch.object(
                    loki.subprocess, "run", return_value=result, side_effect=error
                ),
            ):
                findings = loki.oxlint_violations(
                    path, root, "a.ts", deadline=None, warnings=warnings
                )
            return findings, warnings

    def test_errors_block_and_warnings_are_advisory(self):
        warning = "a.ts:1:1: Use toSorted [Warning/unicorn(no-array-sort)]"
        error = "a.ts:1:2: Unexpected empty block [Error/eslint(no-empty)]"
        findings, warnings = self.run_oxlint(completed(0, warning + "\n1 problem\n"))
        self.assertEqual([], findings)
        self.assertIn("oxlint advisory (not blocking):\n" + warning, warnings[0])
        findings, warnings = self.run_oxlint(completed(1, f"{error}\n{warning}\n"))
        self.assertEqual([f"oxlint: {error}"], findings)
        self.assertEqual(1, len(warnings))
        findings, _ = self.run_oxlint(completed(1, "", "config broken"))
        self.assertEqual(["oxlint: config broken"], findings)
        findings, _ = self.run_oxlint(error=OSError("missing"))
        self.assertEqual(["oxlint: missing"], findings)

    def test_advisory_context_is_capped(self):
        lines = "\n".join(f"a.ts:{n}:1: w [Warning/x(y)]" for n in range(1, 13))
        _, warnings = self.run_oxlint(completed(0, lines))
        self.assertIn("... 2 more", warnings[0])
        self.assertEqual(11, warnings[0].count("\n"))
        with temporary_root() as root:
            path = write_file(root, "a.ts", "x")
            with (
                patch.object(loki, "resolve_tool", return_value="/bin/oxlint"),
                patch.object(loki.subprocess, "run", return_value=completed(0, lines)),
            ):
                output = capture_output(
                    loki.oxlint_violations,
                    path,
                    root,
                    "a.ts",
                    deadline=None,
                    warnings=None,
                )
            self.assertIn("oxlint advisory", output[2])


@unittest.skipUnless(TSC.is_file() and shutil.which("node"), "TypeScript unavailable")
class RealNewTypescriptFileTests(unittest.TestCase):
    def test_new_files_are_checked_before_the_write(self):
        with temporary_root() as root, temporary_root() as home:
            commit(
                root,
                {
                    "tsconfig.json": json.dumps(
                        {
                            "compilerOptions": {"strict": True, "noEmit": True},
                            "include": ["src/**/*.ts"],
                        }
                    ),
                    "src/main.ts": "export const value = 1;\n",
                },
            )
            with (
                patch.object(loki.shutil, "which", return_value=str(TSC)),
                patch.dict(os.environ, {"HOME": str(home)}),
            ):
                bad = 'export const port: number = "80";\n'
                findings = loki.preview_typescript(
                    root, {}, [("src/config.ts", "", bad)], deadline=None
                )
                self.assertEqual(1, len(findings))
                self.assertIn("src/config.ts:1: TS2322", findings[0])
                # Outside include: not checked, so no validated-state marker.
                loose = [("scripts/x.ts", "", bad)]
                self.assertEqual(
                    [], loki.preview_typescript(root, {}, loose, deadline=None)
                )
                write_file(root, "scripts/x.ts", bad)
                with patch.object(
                    loki,
                    "typescript_diagnostics",
                    wraps=loki.typescript_diagnostics,
                ) as compile_:
                    loki.typescript_findings(root, {})
                compile_.assert_called()
