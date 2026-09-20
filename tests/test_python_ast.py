from __future__ import annotations

import unittest
from unittest.mock import patch

import loki
from tests.helpers import temporary_root, write_file


class DependencyDeclarationTests(unittest.TestCase):
    def test_reads_pyproject_and_requirements(self) -> None:
        with temporary_root() as root:
            write_file(
                root,
                "pyproject.toml",
                '[project]\ndependencies = ["Requests>=2", "my-package", 4]\n',
            )
            write_file(
                root,
                "requirements-dev.txt",
                "# comment\n-r base.txt\nOther_Dep==1\n\n",
            )
            self.assertEqual(
                {"requests", "my_package", "other_dep"},
                loki.declared_python_dependencies(root),
            )

    def test_ignores_invalid_and_unreadable_dependency_files(self) -> None:
        with temporary_root() as root:
            pyproject = write_file(root, "pyproject.toml", "{")
            requirements = write_file(root, "requirements.txt", "package")
            original = loki.Path.read_text

            def read_text(path, *args, **kwargs):
                if path == requirements:
                    raise OSError("denied")
                return original(path, *args, **kwargs)

            with patch.object(loki.Path, "read_text", read_text):
                self.assertEqual(set(), loki.declared_python_dependencies(root))
            requirements.unlink()
            pyproject.write_text("", encoding="utf-8")
            self.assertEqual(set(), loki.declared_python_dependencies(root))
            pyproject.unlink()
            self.assertEqual(set(), loki.declared_python_dependencies(root))
            write_file(root, "pyproject.toml", "project = []")
            self.assertEqual(set(), loki.declared_python_dependencies(root))

    def test_dependency_parsing_handles_non_list_and_invalid_requirement_lines(
        self,
    ) -> None:
        with temporary_root() as root:
            write_file(root, "pyproject.toml", '[project]\ndependencies = "bad"\n')
            write_file(root, "requirements.txt", "@invalid\nvalid-package\n")
            self.assertEqual({"valid_package"}, loki.declared_python_dependencies(root))

    def test_dependency_parsing_handles_empty_list_and_non_string_entry(self) -> None:
        with temporary_root() as root:
            write_file(root, "pyproject.toml", "[project]\ndependencies = [4]\n")
            self.assertEqual(set(), loki.declared_python_dependencies(root))


class PythonAstViolationTests(unittest.TestCase):
    def violations(
        self, source: str, dependencies: set[str] | None = None
    ) -> list[str]:
        with temporary_root() as root:
            path = write_file(root, "app.py", source)
            return loki.python_ast_violations(path, root, dependencies)

    def test_detects_every_supported_stub_shape(self) -> None:
        source = """
def pass_stub():
    pass

async def ellipsis_stub():
    ...

def raised_name():
    raise NotImplementedError

def raised_call():
    \"\"\"documented\"\"\"
    raise NotImplementedError()
"""
        self.assertEqual(
            [
                "app.py:2: python-ast: stub body in pass_stub",
                "app.py:5: python-ast: stub body in ellipsis_stub",
                "app.py:8: python-ast: stub body in raised_name",
                "app.py:11: python-ast: stub body in raised_call",
            ],
            self.violations(source),
        )

    def test_does_not_flag_non_stub_function_shapes(self) -> None:
        source = """
def documented_only():
    \"\"\"documentation is a real body\"\"\"

def two_statements():
    pass
    return 1

def other_raise():
    raise RuntimeError()

def attribute_raise():
    raise errors.NotImplementedError()

value = 1
"""
        messages = self.violations(source)
        self.assertFalse(any("stub body" in message for message in messages))

    def test_import_resolution_covers_all_sources(self) -> None:
        with temporary_root() as root:
            write_file(root, "local_file.py")
            (root / "local_package").mkdir()
            path = write_file(
                root,
                "app.py",
                "\n".join(
                    [
                        "import json",
                        "import declared_dep.submodule",
                        "import local_file",
                        "import local_package.child",
                        "from . import sibling",
                        "from pathlib import Path",
                        "import missing_one, missing_two",
                        "from missing_three.submodule import item",
                    ]
                ),
            )
            messages = loki.python_ast_violations(path, root, {"declared_dep"})
            self.assertEqual(
                {"missing_one", "missing_two", "missing_three"},
                {
                    message.rsplit(" ", 1)[-1]
                    for message in messages
                    if "unresolved import" in message
                },
            )

    def test_reports_syntax_missing_and_decode_errors(self) -> None:
        with temporary_root() as root:
            syntax = write_file(root, "syntax.py", "def broken(:\n")
            missing = root / "missing.py"
            binary = root / "binary.py"
            binary.write_bytes(b"\xff")
            cases = {
                syntax: "syntax.py: python-ast: invalid syntax",
                missing: "missing.py: python-ast:",
                binary: "binary.py: python-ast:",
            }
            for path, prefix in cases.items():
                with self.subTest(path=path.name):
                    messages = loki.python_ast_violations(path, root)
                    self.assertEqual(1, len(messages))
                    self.assertTrue(messages[0].startswith(prefix), messages[0])

    def test_uses_declared_dependencies_when_not_supplied(self) -> None:
        with temporary_root() as root:
            write_file(root, "requirements.txt", "declared-package")
            path = write_file(root, "app.py", "import declared_package\n")
            self.assertEqual([], loki.python_ast_violations(path, root))

    def test_caps_violations(self) -> None:
        source = "\n".join(
            f"import missing_{index}" for index in range(loki.MAX_VIOLATIONS + 5)
        )
        self.assertEqual(loki.MAX_VIOLATIONS, len(self.violations(source, set())))


if __name__ == "__main__":
    unittest.main()
