from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import capture_output, temporary_root, write_file


def interpreter(root: Path, relative: str, missing: str = "[]") -> Path:
    """A stand-in project interpreter that reports `missing` (a JSON list)."""
    path = write_file(root, relative, f"#!/bin/sh\necho '{missing}'\n")
    path.chmod(0o755)
    return path


def no_project_python():
    """An environment that names no project interpreter."""
    kept = {
        key: value
        for key, value in os.environ.items()
        if key not in {"LOKI_PYTHON", "VIRTUAL_ENV", "CONDA_PREFIX"}
    }
    return patch.dict(os.environ, kept, clear=True)


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

    def test_does_not_flag_abstract_and_base_class_declarations(self) -> None:
        source = """
import abc
import typing
from abc import ABC, ABCMeta, abstractmethod
from typing import Protocol, overload

class Widget:
    def decompress(self, value):
        \"\"\"Subclasses implement this.\"\"\"
        raise NotImplementedError("Subclasses must implement this method.")

    def render(self):
        raise NotImplementedError

class Base(ABC):
    def hook(self):
        pass

    async def later(self):
        ...

class Meta(metaclass=abc.ABCMeta):
    def hook(self):
        pass

class Reader(Protocol):
    def read(self) -> bytes: ...

class Generic(typing.Protocol[int]):
    def read(self) -> bytes: ...

class Plain:
    @abstractmethod
    def one(self):
        pass

    @abc.abstractmethod
    def two(self): ...

    @property
    @abc.abstractproperty
    def three(self):
        pass

@overload
def convert(value: int) -> int: ...
@typing.overload
def convert(value: str) -> str: ...
def convert(value):
    return value
"""
        self.assertEqual([], self.violations(source, {"abc", "typing"}))

    def test_still_flags_placeholders_that_are_not_declarations(self) -> None:
        source = """
class Service:
    def save(self):
        pass

    def load(self):
        ...

    def run(self):
        def helper():
            raise NotImplementedError
        return helper

class Other(Service, metaclass=type):
    def save(self):
        \"\"\"Not yet.\"\"\"
        pass

def todo():
    raise NotImplementedError("later")

def dynamic():
    raise make_error()

def reraised():
    raise
"""
        self.assertEqual(
            [
                "app.py:3: python-ast: stub body in save",
                "app.py:6: python-ast: stub body in load",
                "app.py:10: python-ast: stub body in helper",
                "app.py:15: python-ast: stub body in save",
                "app.py:19: python-ast: stub body in todo",
            ],
            self.violations(source),
        )

    def test_import_resolution_covers_all_sources(self) -> None:
        with temporary_root() as root:
            write_file(root, "local_file.py")
            (root / "local_package").mkdir()
            write_file(root, "src/in_src/__init__.py")
            write_file(root, "tools/sibling_module.py")
            source = "\n".join(
                [
                    "import json",
                    "import __main__",
                    "import sys, builtins",
                    "import declared_dep.submodule",
                    "import local_file",
                    "import local_package.child",
                    "import in_src",
                    "import sibling_module",
                    "from . import sibling",
                    "from pathlib import Path",
                    "import missing_one, missing_two",
                    "from missing_three.submodule import item",
                    "try:",
                    "    import optional_one",
                    "    from optional_two import thing",
                    "except ImportError:",
                    "    optional_one = None",
                    "try:",
                    "    import optional_three",
                    "except (ValueError, ModuleNotFoundError):",
                    "    pass",
                    "try:",
                    "    import optional_four",
                    "except:",
                    "    pass",
                    "try:",
                    "    import guarded_wrongly",
                    "except KeyError:",
                    "    pass",
                ]
            )
            path = write_file(root, "tools/app.py", source)
            unknown = {
                module
                for _, module in loki.python_unknown_imports(
                    loki.ast.parse(source), root, path.parent, {"declared_dep"}
                )
            }
            self.assertEqual(
                {"missing_one", "missing_two", "missing_three", "guarded_wrongly"},
                unknown,
            )
            python = interpreter(root, "bin/python", '["missing_one", "missing_three"]')
            messages = loki.python_ast_violations(
                path, root, {"declared_dep"}, python=str(python)
            )
            self.assertEqual(
                [
                    "tools/app.py:11: python-ast: unresolved import missing_one",
                    "tools/app.py:12: python-ast: unresolved import missing_three",
                ],
                messages,
            )

    def test_imports_resolve_against_the_project_interpreter(self) -> None:
        """Not against the interpreter running Loki, whose packages are its own."""
        with temporary_root() as root, temporary_root() as packages:
            write_file(packages, "project_only_dependency/__init__.py")
            path = write_file(root, "app.py", "import project_only_dependency\n")
            with patch.dict(os.environ, {"PYTHONPATH": str(packages)}):
                self.assertEqual(
                    [], loki.python_ast_violations(path, root, python=sys.executable)
                )
            loki.IMPORT_MEMO.clear()
            with patch.dict(os.environ, {"PYTHONPATH": ""}):
                self.assertEqual(
                    ["app.py:1: python-ast: unresolved import project_only_dependency"],
                    loki.python_ast_violations(path, root, python=sys.executable),
                )

    def test_project_interpreter_detection_order(self) -> None:
        with temporary_root() as root, temporary_root() as elsewhere:
            with no_project_python():
                self.assertIsNone(loki.project_python(root))
                venv = interpreter(root, "venv/bin/python3")
                self.assertEqual(str(venv), loki.project_python(root))
                dotvenv = interpreter(root, ".venv/bin/python")
                self.assertEqual(str(dotvenv), loki.project_python(root))
                conda = interpreter(elsewhere, "conda/bin/python")
                with patch.dict(os.environ, {"CONDA_PREFIX": str(conda.parents[1])}):
                    self.assertEqual(str(conda), loki.project_python(root))
                    active = interpreter(elsewhere, "active/Scripts/python.exe")
                    with patch.dict(
                        os.environ, {"VIRTUAL_ENV": str(active.parents[1])}
                    ):
                        self.assertEqual(str(active), loki.project_python(root))
                        with patch.dict(os.environ, {"LOKI_PYTHON": "/named/python"}):
                            self.assertEqual("/named/python", loki.project_python(root))
                            self.assertEqual(
                                "/flag/python",
                                loki.project_python(root, "/flag/python"),
                            )
                with patch.dict(os.environ, {"VIRTUAL_ENV": str(elsewhere / "gone")}):
                    self.assertEqual(str(dotvenv), loki.project_python(root))

    def test_unknown_imports_are_not_checked_without_a_project_interpreter(
        self,
    ) -> None:
        with temporary_root() as root, no_project_python():
            path = write_file(root, "app.py", "import numpy\nimport pandas\n")
            warnings: list[str] = []
            self.assertEqual(
                [], loki.python_ast_violations(path, root, warnings=warnings)
            )
            self.assertEqual(
                [], loki.python_ast_violations(path, root, warnings=warnings)
            )
            self.assertEqual(
                [
                    "NOT CHECKED python imports: no project interpreter found "
                    "(set LOKI_PYTHON or pass --python)"
                ],
                warnings,
            )
            self.assertEqual(
                warnings, loki.python_ast_violations(path, root, strict=True)
            )
            result, _, stderr = capture_output(loki.python_ast_violations, path, root)
            self.assertEqual([], result)
            self.assertEqual(warnings[0] + "\n", stderr)
            clean = write_file(root, "clean.py", "import json\n")
            self.assertEqual([], loki.python_ast_violations(clean, root, strict=True))

    def test_unusable_project_interpreters_are_not_checked(self) -> None:
        with temporary_root() as root:
            path = write_file(root, "app.py", "import numpy\n")
            failing = write_file(
                root, "bin/failing", "#!/bin/sh\necho broken >&2\nexit 3\n"
            )
            silent = write_file(root, "bin/silent", "#!/bin/sh\nexit 3\n")
            garbage = interpreter(root, "bin/garbage", "not json")
            scalar = interpreter(root, "bin/scalar", "3")
            for script in (failing, silent):
                script.chmod(0o755)
            cases = {
                str(root / "bin/absent"): "bin/absent unavailable: ",
                str(failing): "bin/failing unavailable: broken",
                str(silent): "bin/silent unavailable: exited 3",
                str(garbage): "bin/garbage unavailable: ",
                str(scalar): "bin/scalar unavailable: exited 0",
            }
            for python, reason in cases.items():
                with self.subTest(python=python):
                    messages = loki.python_ast_violations(
                        path, root, python=python, strict=True
                    )
                    self.assertEqual(1, len(messages))
                    self.assertTrue(
                        messages[0].startswith(
                            "NOT CHECKED python imports: project interpreter"
                        ),
                        messages[0],
                    )
                    self.assertIn(reason, messages[0])
            working = interpreter(root, "bin/python")
            with patch.object(
                loki.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("python", 15),
            ):
                self.assertIn(
                    "timed out",
                    loki.python_ast_violations(
                        path, root, python=str(working), strict=True
                    )[0],
                )
            self.assertIn(
                "hook deadline exceeded",
                loki.python_ast_violations(
                    path, root, python=str(working), strict=True, deadline=0
                )[0],
            )

    def test_interpreter_answers_are_asked_once_per_module(self) -> None:
        with temporary_root() as root:
            python = interpreter(root, "bin/python", '["absent"]')
            real = subprocess.run
            with patch.object(loki.subprocess, "run", side_effect=real) as run:
                first = loki.resolve_imports(
                    root, ["absent", "present"], python=str(python)
                )
                again = loki.resolve_imports(
                    root, ["present", "absent"], python=str(python)
                )
                self.assertEqual({"absent"}, first)
                self.assertEqual(first, again)
                self.assertEqual(1, run.call_count)
                self.assertEqual(set(), loki.resolve_imports(root, [], python="/none"))

    def test_base_text_limits_findings_to_what_the_edit_introduced(self) -> None:
        base = """import numpy

class Widget:
    def decompress(self, value):
        raise NotImplementedError

def existing():
    pass

def moved():
    pass
"""
        edited = """import numpy
import pandas

def moved():
    pass

class Widget:
    def decompress(self, value):
        raise NotImplementedError

def existing():
    pass

def added():
    pass

def existing():
    pass
"""
        with temporary_root() as root:
            python = interpreter(root, "bin/python", '["numpy", "pandas"]')
            path = write_file(root, "app.py", edited)
            self.assertEqual(
                [
                    "app.py:14: python-ast: stub body in added",
                    "app.py:17: python-ast: stub body in existing",
                    "app.py:2: python-ast: unresolved import pandas",
                ],
                loki.python_ast_violations(path, root, base=base, python=str(python)),
            )
            path.write_text(base, encoding="utf-8")
            self.assertEqual(
                [], loki.python_ast_violations(path, root, base=base, strict=True)
            )

    def test_a_base_that_does_not_parse_is_not_checked(self) -> None:
        with temporary_root() as root:
            path = write_file(root, "legacy.py", "print 'still python 2'\n")
            warnings: list[str] = []
            self.assertEqual(
                [],
                loki.python_ast_violations(
                    path, root, base="print 'python 2'\n", warnings=warnings
                ),
            )
            self.assertEqual(
                ["NOT CHECKED python ast: legacy.py does not parse at the base"],
                warnings,
            )
            self.assertEqual(
                warnings,
                loki.python_ast_violations(
                    path, root, base="print 'python 2'\n", strict=True
                ),
            )
            broken = loki.python_ast_violations(path, root, base="VALUE = 1\n")
            self.assertEqual(1, len(broken))
            self.assertTrue(broken[0].startswith("legacy.py: python-ast:"))

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
            f"def stub_{index}(): pass" for index in range(loki.MAX_VIOLATIONS + 5)
        )
        self.assertEqual(loki.MAX_VIOLATIONS, len(self.violations(source, set())))


if __name__ == "__main__":
    unittest.main()
