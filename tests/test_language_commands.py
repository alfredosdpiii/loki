from __future__ import annotations

import unittest
from unittest.mock import patch

import loki
from tests.helpers import temporary_root, write_file


class MissingToolTests(unittest.TestCase):
    def test_reports_required_tool_for_every_language(self) -> None:
        with temporary_root() as root:
            with patch.object(loki.shutil, "which", return_value=None) as which:
                self.assertEqual("ruff", loki.missing_tool("python", root))
                self.assertEqual(
                    "node_modules/.bin/oxlint", loki.missing_tool("typescript", root)
                )
                self.assertEqual("gofmt", loki.missing_tool("go", root))
                self.assertEqual("rustfmt", loki.missing_tool("rust", root))
                self.assertEqual("mix", loki.missing_tool("elixir", root))
                self.assertEqual("toolchain", loki.missing_tool("unknown", root))
                self.assertEqual(
                    ["ruff", "gofmt", "rustfmt", "mix"],
                    [call.args[0] for call in which.call_args_list],
                )
            (root / "node_modules/.bin").mkdir(parents=True)
            (root / "node_modules/.bin/oxlint").touch()
            with patch.object(
                loki.shutil, "which", side_effect=lambda name: f"/bin/{name}"
            ):
                for language in ("python", "typescript", "go", "rust", "elixir"):
                    with self.subTest(language=language):
                        self.assertIsNone(loki.missing_tool(language, root))
            with patch.object(
                loki.shutil,
                "which",
                side_effect=lambda name: "/bin/gofmt" if name == "gofmt" else None,
            ):
                self.assertEqual("go", loki.missing_tool("go", root))


class WriteTimeCommandTests(unittest.TestCase):
    def test_rust_runs_formatter(self) -> None:
        with temporary_root() as root:
            path = write_file(root, "main.rs", "fn main() {}\n")
            with (
                patch.object(loki, "missing_tool", return_value=None),
                patch.object(loki, "run_command", return_value=[]) as run,
            ):
                self.assertEqual([], loki.check_file(path, root, {}))
                run.assert_called_once_with(
                    ["rustfmt", str(path)], root, "rustfmt", deadline=None
                )

    def test_ignores_unknown_disabled_and_missing_files(self) -> None:
        with temporary_root() as root:
            text = write_file(root, "readme.txt", "text")
            python = write_file(root, "app.py", "return_value = 1\n")
            self.assertEqual([], loki.check_file(text, root, {}))
            self.assertEqual(
                [], loki.check_file(python, root, {"languages": {"python": False}})
            )
            self.assertEqual([], loki.check_file(root / "missing.py", root, {}))

    def test_missing_tool_passes_unless_strict(self) -> None:
        with temporary_root() as root:
            path = write_file(root, "app.py", "value = 1\n")
            with patch.object(loki, "missing_tool", return_value="ruff"):
                self.assertEqual([], loki.check_file(path, root, {}, False))
                self.assertEqual(
                    ["app.py: loki: missing ruff"],
                    loki.check_file(path, root, {}, True),
                )

    def test_elixir_without_mix_project_runs_no_commands(self) -> None:
        with temporary_root() as root:
            path = write_file(root, "app.ex", "value")
            with (
                patch.object(loki, "missing_tool", return_value=None),
                patch.object(loki, "run_command") as run,
            ):
                self.assertEqual([], loki.check_file(path, root, {}))
                run.assert_not_called()

    def test_go_uses_root_and_nested_package_paths(self) -> None:
        with temporary_root() as root:
            paths = [
                write_file(root, "main.go", "package main"),
                write_file(root, "pkg/app.go", "package pkg"),
            ]
            expected_packages = ["./", "./pkg"]
            for path, package in zip(paths, expected_packages, strict=True):
                with (
                    patch.object(loki, "missing_tool", return_value=None),
                    patch.object(loki, "run_command", return_value=[]) as run,
                ):
                    self.assertEqual([], loki.check_file(path, root, {}))
                self.assertEqual(
                    [
                        (["gofmt", "-w", str(path)], "gofmt"),
                        (["go", "vet", package], "go vet"),
                    ],
                    [(call.args[0], call.args[2]) for call in run.call_args_list],
                )

    def test_outside_file_never_reaches_formatter(self) -> None:
        with temporary_root() as root, temporary_root() as outside:
            path = write_file(outside, "app.go", "package app")
            with patch.object(loki, "run_command") as run:
                self.assertIn(
                    "outside project root", loki.check_file(path, root, {})[0]
                )
                run.assert_not_called()


class ScanCommandTests(unittest.TestCase):
    def test_source_walk_skips_tooling_directories(self) -> None:
        with temporary_root() as root:
            kept = write_file(root, "src/app.py")
            for directory in loki.SKIP_DIRECTORIES:
                write_file(root, f"{directory}/ignored.py")
            write_file(root, "src/readme.txt")
            self.assertEqual([kept], list(loki.iter_source_files(root)))

    def test_scan_commands_cover_every_language_and_missing_tool(self) -> None:
        with temporary_root() as root:
            files = [write_file(root, "src/app.py"), write_file(root, "src/other.py")]
            (root / "node_modules/.bin").mkdir(parents=True)
            (root / "node_modules/.bin/oxlint").touch()
            with patch.object(
                loki.shutil, "which", side_effect=lambda name: f"/bin/{name}"
            ):
                self.assertEqual(
                    (
                        None,
                        [
                            ["ruff", "check", "src/app.py", "src/other.py"],
                            ["ruff", "format", "--check", "src/app.py", "src/other.py"],
                        ],
                    ),
                    loki.scan_command("python", files, root),
                )
                self.assertEqual(
                    (None, [["golangci-lint", "run"]]),
                    loki.scan_command("go", files, root),
                )
                self.assertEqual(
                    (
                        None,
                        [
                            [
                                "cargo",
                                "clippy",
                                "--all-targets",
                                "--",
                                "-D",
                                "warnings",
                                "-D",
                                "clippy::todo",
                                "-D",
                                "clippy::unimplemented",
                                "-D",
                                "clippy::unwrap_used",
                                "-D",
                                "clippy::expect_used",
                            ]
                        ],
                    ),
                    loki.scan_command("rust", files, root),
                )
                self.assertEqual(
                    (
                        None,
                        [
                            ["mix", "credo", "--strict"],
                            ["mix", "compile", "--warnings-as-errors"],
                        ],
                    ),
                    loki.scan_command("elixir", files, root),
                )
                self.assertEqual(
                    (
                        None,
                        [
                            [
                                str(root / "node_modules/.bin/oxlint"),
                                "src/app.py",
                                "src/other.py",
                            ]
                        ],
                    ),
                    loki.scan_command("typescript", files, root),
                )
            with patch.object(loki.shutil, "which", return_value=None) as which:
                self.assertEqual(("cargo", []), loki.scan_command("rust", files, root))
                which.assert_called_once_with("cargo")
            for language, missing in (
                ("python", "ruff"),
                ("go", "golangci-lint"),
                ("rust", "cargo"),
                ("elixir", "mix"),
            ):
                with (
                    self.subTest(language=language),
                    patch.object(loki.shutil, "which", return_value=None),
                ):
                    self.assertEqual(
                        (missing, []), loki.scan_command(language, files, root)
                    )
            (root / "node_modules/.bin/oxlint").unlink()
            self.assertEqual(
                ("node_modules/.bin/oxlint", []),
                loki.scan_command("typescript", files, root),
            )
            self.assertEqual(
                ("toolchain", []), loki.scan_command("unknown", files, root)
            )


if __name__ == "__main__":
    unittest.main()
