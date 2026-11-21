#!/usr/bin/env python3
"""Deterministic write-time and CI guardrails for AI-edited repositories."""

from __future__ import annotations

import argparse
import ast
import contextlib
import difflib
import fnmatch
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

__version__ = "0.1.9"

SOURCE_ROOT = Path(__file__).resolve().parent
INSTALLED = SOURCE_ROOT.name == ".loki"
DEFAULT_ROOT = SOURCE_ROOT.parent if INSTALLED else Path.cwd()
MAX_VIOLATIONS = 40
COMMAND_TIMEOUT = 120

ACTIVE_EVIDENCE: ContextVar[dict[str, Any] | None] = ContextVar(
    "loki_evidence", default=None
)


def evidence_policy(
    source: str, path: str, raw: bytes | None, *, base: str | None = None
) -> None:
    evidence = ACTIVE_EVIDENCE.get()
    if evidence is None:
        return
    import hashlib

    policy = {
        "source": source,
        "path": path,
        "base": base,
        "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
    }
    if policy not in evidence["policies"]:
        evidence["policies"].append(policy)


def evidence_finding(rule: str, path: str | None = None) -> None:
    evidence = ACTIVE_EVIDENCE.get()
    if evidence is not None:
        evidence["findings"].append({"rule": rule, "path": path})


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".mjs": "typescript",
    ".cjs": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".ex": "elixir",
    ".exs": "elixir",
    ".heex": "elixir",
}

PROTECTED_PATHS = (
    ".loki/**",
    ".claude/settings.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".factory/hooks.json",
    ".pi/extensions/loki.ts",
    ".omp/extensions/loki.ts",
    ".github/workflows/loki.yml",
    ".oxlintrc.json",
    ".ruff.toml",
    ".credo.exs",
    "**/.credo.exs",
    ".golangci.yml",
    "buf.yaml",
    "buf.work.yaml",
    "oasdiff.yaml",
    "atlas.hcl",
)

SKIP_DIRECTORIES = {
    ".git",
    ".loki",
    ".mutmut-cache",
    ".venv",
    "mutants",
    "node_modules",
    "venv",
    "__pycache__",
    "deps",
    "_build",
}

MANIFEST_LOCKFILES = {
    "npm": (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
    ),
    "pypi": ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"),
    "go": ("go.sum",),
    "crates": ("Cargo.lock",),
    "hex": ("mix.lock",),
}
ECOSYSTEM_MANIFEST = {
    "npm": "package.json",
    "pypi": "pyproject.toml",
    "go": "go.mod",
    "crates": "Cargo.toml",
    "hex": "mix.exs",
}
COMMAND_GROUPS = ("contract", "property", "differential", "mutation")
RULE_PACKS = ("core", "python", "typescript", "phoenix", "shell")
SECURITY_LEVELS = ("none", "low", "medium", "high")
TYPESCRIPT_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
JS_PREVIEW_RULES = (
    "no-empty",
    "no-async-promise-executor",
    "no-promise-executor-return",
    "no-unsafe-finally",
    "no-unsafe-optional-chaining",
    "no-constant-binary-expression",
    "no-debugger",
    "jest/no-disabled-tests",
    "vitest/no-disabled-tests",
    "jest/no-focused-tests",
    "vitest/no-focused-tests",
)


def rule_packs(config: dict[str, Any]) -> tuple[str, ...]:
    value = config.get("rule_packs", list(RULE_PACKS))
    if not isinstance(value, list) or any(item not in RULE_PACKS for item in value):
        raise ValueError("loki: rule_packs must contain known rule-pack names")
    return tuple(dict.fromkeys(value))


def security_policy(config: dict[str, Any]) -> dict[str, str]:
    value = config.get("elixir_security", {})
    if not isinstance(value, dict):
        raise ValueError("loki: elixir_security must be an object")
    if set(value) - {"sobelow"}:
        raise ValueError("loki: unknown elixir_security option")
    sobelow = value.get("sobelow", {})
    if not isinstance(sobelow, dict):
        raise ValueError("loki: elixir_security.sobelow must be an object")
    if set(sobelow) - {"block", "warn"}:
        raise ValueError("loki: unknown Sobelow option")
    block = sobelow.get("block", "high")
    warn = sobelow.get("warn", "medium")
    if block not in SECURITY_LEVELS or warn not in SECURITY_LEVELS:
        raise ValueError("loki: Sobelow levels must be none, low, medium or high")
    if (
        block != "none"
        and warn != "none"
        and SECURITY_LEVELS.index(warn) > SECURITY_LEVELS.index(block)
    ):
        raise ValueError("loki: Sobelow warn level cannot be stricter than block level")
    return {"block": block, "warn": warn}


def injected_context(
    root: Path, config: dict[str, Any], host: str | None = None
) -> str:
    packs = rule_packs(config)
    if host == "ultron":
        return ultron_context(packs)
    lines = [
        "LOKI POLICY GUIDANCE. This describes configured policy, not proof that "
        "hooks or analyzers are active. NOT CHECKED means coverage is unavailable.",
        "When a rule reports a violation, fix it and retry. Do not weaken the "
        "checker, policy, tests or hooks.",
        "Use verified file tools. Do not route writes through shell commands "
        "to bypass checks.",
    ]
    if "core" in packs:
        lines.append(
            "Protected policy, hook, workflow and quality files require "
            "independent review."
        )
    if "python" in packs:
        lines.append(
            "Python edits must introduce no new Ruff findings and preserve "
            "meaningful tests."
        )
    if "typescript" in packs:
        lines.append(
            "TypeScript edits must pass Oxlint and enabled project-wide type "
            "checks, including consumers."
        )
    if "phoenix" in packs:
        policy = security_policy(config)
        lines.extend(
            [
                "Phoenix/Elixir hooks check formatting, net-new Credo and "
                "source-security Sobelow findings. Compilation and HEEx component "
                "checks require the project tier; they do not run on every write.",
                (
                    "Sobelow blocking is disabled; "
                    if policy["block"] == "none"
                    else f"Sobelow {policy['block']} confidence findings block; "
                )
                + (
                    "warnings are disabled. Lower levels remain visible as info."
                    if policy["warn"] == "none"
                    else f"{policy['warn']} findings warn. Lower levels remain visible."
                ),
                "Use Ecto parameterization, supervised processes, validated "
                "changesets and assigns-based authorization.",
            ]
        )
    if "shell" in packs:
        lines.append(
            "Shell redirects, substitutions, compound commands and destructive "
            "Git operations require review when the optional shell guard is "
            "installed. Selecting this guidance pack does not install that guard."
        )
    return "\n".join(lines)


def ultron_context(packs: Iterable[str]) -> str:
    """Short guidance for Ultron, whose model writes files from a Python REPL."""
    checks = {
        "core": "secrets, security rules, protected files",
        "python": "Ruff (Python)",
        "typescript": "Oxlint and type checks (TS/JS)",
        "phoenix": "Credo and Sobelow (Elixir)",
    }
    listed = "; ".join(checks[pack] for pack in checks if pack in set(packs))
    return (
        "LOKI guardrails: edit() and write() are checked before the file "
        "changes. Change source and configuration with edit()/write(): a bash() "
        "command that writes them (redirect, tee, sed -i, cp/mv) is refused. "
        "Other writes (Path.write_text, programs) are checked after the cell. "
        "A blocked write raises ValueError with the finding: fix the cause and "
        "retry. Never weaken Loki, its policy (.loki/), tests or hooks."
        + (f" Checks: {listed}." if listed else "")
    )


TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|spec)(/|$)|(^|/)(test_[^/]+|[^/]+_(?:test|spec))\.[^.]+$|\.(?:test|spec)\.[^.]+$",
    re.IGNORECASE,
)
TEST_DECLARATION_RE = re.compile(
    r"^\s*(?:(?:async\s+)?def\s+test_|func\s+Test|(?:it|test|describe)\s*\(|test\s+\")"
)
ASSERTION_RE = re.compile(
    r"\b(?:assert\w*|expect|refute|should|require\.(?:Equal|NoError|Error))\b"
)
SKIP_RE = re.compile(
    r"(?:pytest\.mark\.(?:skip|xfail)|unittest\.skip|\b(?:it|test|describe)\.skip\s*\(|"
    r"\bt\.Skipf?\s*\(|#\s*\[ignore\]|@Ignore\b|@tag\s+:skip\b)"
)
QUALITY_POLICY_RE = re.compile(
    r"(?:fail_under|coverageThreshold|mutation(?:Score|Threshold)|"
    r"mutate_only_covered_lines|max-children|MemoryMax)"
)
QUALITY_POLICY_PATHS = (
    "pyproject.toml",
    ".coveragerc",
    "**/stryker*.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)


def load_config(root: Path) -> dict[str, Any]:
    path = root / ".loki" / "loki.json"
    if not path.is_file():
        evidence_policy("candidate", ".loki/loki.json", None)
        return {}
    try:
        raw = path.read_bytes()
        evidence_policy("candidate", ".loki/loki.json", raw)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{path}: invalid loki config: {error}") from error
    return validate_config(value)


def _validate_config_lists(value: dict[str, Any]) -> None:
    for key in ("approved_dependencies", "private_packages"):
        items = value.get(key, None if key == "approved_dependencies" else [])
        if key == "approved_dependencies" and items is None:
            continue
        if not isinstance(items, list) or any(
            not isinstance(item, str) or not item or "\0" in item for item in items
        ):
            raise ValueError(f"loki: {key} must be a list of nonempty strings")


def _validate_config_languages_and_commands(value: dict[str, Any]) -> None:
    languages = value.get("languages", {})
    if not isinstance(languages, dict) or any(
        language not in LANGUAGE_EXTENSIONS.values() or not isinstance(enabled, bool)
        for language, enabled in languages.items()
    ):
        raise ValueError("loki: languages must map known language names to booleans")
    commands = value.get("commands", {})
    if not isinstance(commands, dict):
        raise ValueError("loki: commands must be a JSON object")
    for group in commands:
        if group not in COMMAND_GROUPS:
            raise ValueError(f"loki: unknown command group: {group}")
    for group in COMMAND_GROUPS:
        if isinstance(result := configured_commands(value, group), str):
            raise ValueError(result)


def validate_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("loki config must be a JSON object")
    unknown = value.keys() - {
        "approved_dependencies",
        "commands",
        "languages",
        "private_packages",
        "protected_extra",
        "typescript_check",
        "rule_packs",
        "elixir_security",
        "shell_commands",
        "slop",
        "hygiene",
    }
    if unknown:
        raise ValueError(f"loki: unknown configuration key: {sorted(unknown)[0]}")
    protected_patterns(value)
    rule_packs(value)
    security_policy(value)
    shell_permissions(value)
    slop_policy(value)
    hygiene_policy(value)
    if not isinstance(value.get("typescript_check", False), bool):
        raise ValueError("typescript_check must be a boolean")
    _validate_config_lists(value)
    _validate_config_languages_and_commands(value)
    return value


def language_enabled(config: dict[str, Any], language: str) -> bool:
    languages = config.get("languages", {})
    return not isinstance(languages, dict) or languages.get(language, True) is not False


def relative_display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def resolve_file(path: str, root: Path) -> Path:
    candidate = Path(path).expanduser()
    return (
        candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    )


def path_matches(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/")
    normalized = pattern.replace("\\", "/")
    if normalized_path.startswith("./"):
        normalized_path = normalized_path[2:]
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.endswith("/**"):
        prefix = normalized[:-3].rstrip("/")
        return normalized_path == prefix or normalized_path.startswith(f"{prefix}/")
    return fnmatch.fnmatch(normalized_path, normalized)


def protected_patterns(config: dict[str, Any]) -> tuple[str, ...]:
    extra = config.get("protected_extra", [])
    if not isinstance(extra, list) or any(
        not isinstance(item, str) or not item or "\0" in item for item in extra
    ):
        raise ValueError("protected_extra must be a list of nonempty strings")
    return (*PROTECTED_PATHS, *extra)


def protect_path(
    path: str, root: Path, config: dict[str, Any], *, allow_override: bool = True
) -> str | None:
    valid_path(path)
    patterns = protected_patterns(config)
    root = root.resolve()
    lexical = Path(os.path.abspath(root / Path(path).expanduser()))
    resolved = lexical.resolve()
    try:
        relatives = [
            candidate.relative_to(root).as_posix() for candidate in (lexical, resolved)
        ]
    except ValueError:
        evidence_finding("root-confinement", path)
        return f"loki: outside project root: {path}"
    if resolved.is_dir():
        evidence_finding("directory-target", path)
        return f"loki: directory target is not a file: {path}"
    if allow_override and os.environ.get("LOKI_ALLOW_PROTECTED") == "1":
        return None
    if any(
        path_matches(relative, pattern)
        for relative in relatives
        for pattern in patterns
    ):
        evidence_finding("protected-path", relatives[0])
        return (
            f"loki: protected file: {relatives[0]} "
            "(set LOKI_ALLOW_PROTECTED=1 to override)"
        )
    return None


def valid_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("path must be a nonempty string without NUL")
    return value


def _patch_operation(line: str) -> str | None:
    for op in ("Add", "Update", "Delete"):
        if line.startswith(f"*** {op} File: "):
            return op
    return None


def _step_patch_update_line(
    line: str, content: int, pending_context: bool
) -> tuple[int, bool, bool]:
    if line == "@@" or line.startswith("@@ "):
        if pending_context:
            raise ValueError("empty change hunk")
        return content, True, False
    if line and line[0] in "+- ":
        return content + 1, False, False
    if line == "*** End of File" and content and not pending_context:
        return content, pending_context, True
    raise ValueError("unknown patch structural marker")


def _check_patch_body_complete(
    operation: str, content: int, moved: bool, pending: bool
) -> None:
    empty_add = operation == "Add" and not content
    empty_update = operation == "Update" and not content and not moved
    if pending or empty_add or empty_update:
        raise ValueError("empty patch operation")


def _scan_patch_body(lines: list[str], index: int, operation: str, moved: bool) -> int:
    content = 0
    pending_context = False
    ended = False
    while index < len(lines) - 1:
        line = lines[index]
        if _patch_operation(line) is not None:
            break
        if ended or operation == "Delete":
            raise ValueError("unexpected patch body")
        if operation == "Add":
            if not line.startswith("+"):
                raise ValueError("Add requires added content lines")
            content += 1
        else:
            content, pending_context, ended = _step_patch_update_line(
                line, content, pending_context
            )
        index += 1
    _check_patch_body_complete(operation, content, moved, pending_context)
    return index


def _split_patch_lines(patch: str) -> list[str]:
    if not isinstance(patch, str) or "\0" in patch:
        raise ValueError("patch must be a string without NUL")
    lines = patch.split("\n")
    if lines[-1:] == [""]:
        lines.pop()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("invalid patch boundaries")
    return lines


def patch_paths(patch: str) -> list[str]:
    lines = _split_patch_lines(patch)
    paths: list[str] = []
    index = 1
    while index < len(lines) - 1:
        header = lines[index]
        operation = _patch_operation(header)
        if operation is None:
            raise ValueError("unknown patch operation")
        paths.append(valid_path(header[len(f"*** {operation} File: ") :]))
        index += 1
        moved = operation == "Update" and lines[index].startswith("*** Move to: ")
        if moved:
            paths.append(valid_path(lines[index][len("*** Move to: ") :]))
            index += 1
        index = _scan_patch_body(lines, index, operation, moved)
    return list(dict.fromkeys(paths))


def _parse_harness_envelope(raw: str) -> tuple[str, dict[str, Any], str]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("hook envelope must be an object")
    name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    cwd = valid_path(payload.get("cwd"))
    if not os.path.isabs(cwd):
        raise ValueError("cwd must be absolute")
    if not isinstance(name, str) or not name or not isinstance(tool_input, dict):
        raise ValueError("tool_name and object tool_input are required")
    return name, tool_input, cwd


def harness_paths(raw: str, harness: str) -> list[str]:
    name, tool_input, cwd = _parse_harness_envelope(raw)
    supported = {
        "claude": {"Write", "Edit", "MultiEdit"},
        "codex": {"apply_patch"},
        "factory": {"Create", "Edit", "ApplyPatch"},
    }
    if name not in supported.get(harness, set()):
        raise ValueError(f"loki: unsupported {harness} tool: {name}")
    if harness == "factory" and name == "ApplyPatch":
        raise ValueError("loki: unsupported factory ApplyPatch payload")
    paths = (
        patch_paths(tool_input.get("command"))
        if harness == "codex"
        else [valid_path(tool_input.get("file_path"))]
    )
    return list(
        dict.fromkeys(os.path.abspath(os.path.join(cwd, path)) for path in paths)
    )


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def command_output(result: subprocess.CompletedProcess[str]) -> list[str]:
    """Non-empty stripped lines of stdout then stderr, without terminal colors."""
    parts = (ANSI_ESCAPE_RE.sub("", part) for part in (result.stdout, result.stderr))
    text = "\n".join(part.strip() for part in parts if part.strip())
    return [line.strip() for line in text.splitlines() if line.strip()]


def run_command(
    command: list[str], root: Path, label: str, *, deadline: float | None = None
) -> list[str]:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout(deadline),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        evidence_finding("checker-unavailable")
        return [f"{label}: {error}"]
    if result.returncode == 0:
        return []
    evidence_finding("external-check-failed")
    lines = command_output(result)
    if not lines:
        lines = [f"exited {result.returncode}"]
    return [f"{label}: {line}" for line in lines]


def dependency_name(requirement: str) -> str | None:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    return match.group(1).lower().replace("-", "_") if match else None


def _pyproject_dependencies(root: Path) -> set[str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return set()
    with contextlib.suppress(OSError, tomllib.TOMLDecodeError):
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data.get("project", {})
        values = project.get("dependencies", []) if isinstance(project, dict) else []
        if isinstance(values, list):
            return {
                name
                for value in values
                if isinstance(value, str) and (name := dependency_name(value))
            }
    return set()


def _requirements_dependencies(root: Path) -> set[str]:
    found: set[str] = set()
    for requirements in root.glob("requirements*.txt"):
        with contextlib.suppress(OSError):
            for line in requirements.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if (
                    stripped
                    and not stripped.startswith(("#", "-"))
                    and (name := dependency_name(stripped))
                ):
                    found.add(name)
    return found


def declared_python_dependencies(root: Path) -> set[str]:
    return _pyproject_dependencies(root) | _requirements_dependencies(root)


def local_python_module(root: Path, module: str, directory: Path | None = None) -> bool:
    """A module of the project itself: at the root, under src/, or beside the file."""
    bases = [root, root / "src"] + ([directory] if directory is not None else [])
    return any(
        (base / f"{module}.py").is_file() or (base / module).is_dir() for base in bases
    )


ABSTRACT_DECORATORS = {
    "abstractmethod",
    "abstractproperty",
    "abstractclassmethod",
    "abstractstaticmethod",
    "overload",
}
INTERFACE_BASES = {"ABC", "Protocol"}
OPTIONAL_IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError", "Exception"}


def reference_name(node: ast.AST) -> str | None:
    """The last name of a decorator, base class or exception reference."""
    if isinstance(node, (ast.Call, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else None


def interface_class(node: ast.ClassDef) -> bool:
    """An ABC or Protocol: its methods are declarations, not unfinished code."""
    return any(reference_name(base) in INTERFACE_BASES for base in node.bases) or any(
        keyword.arg == "metaclass" and reference_name(keyword.value) == "ABCMeta"
        for keyword in node.keywords
    )


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_ellipsis_or_pass(statement: ast.stmt) -> bool:
    return isinstance(statement, ast.Pass) or (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


def stub_statement(node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    """The single placeholder statement a function consists of, if it is one."""
    body = node.body[1:] if node.body and _is_docstring(node.body[0]) else node.body
    if len(body) != 1:
        return None
    statement = body[0]
    if _is_ellipsis_or_pass(statement):
        return statement
    if isinstance(statement, ast.Raise) and isinstance(
        statement.exc, (ast.Name, ast.Call)
    ):
        exception = statement.exc
        name = exception if isinstance(exception, ast.Name) else exception.func
        if isinstance(name, ast.Name) and name.id == "NotImplementedError":
            return statement
    return None


def _is_declared_stub(
    child: ast.FunctionDef | ast.AsyncFunctionDef,
    owner: ast.ClassDef | None,
    statement: ast.stmt | None,
) -> bool:
    return (
        any(
            reference_name(decorator) in ABSTRACT_DECORATORS
            for decorator in child.decorator_list
        )
        or (owner is not None and interface_class(owner))
        or (owner is not None and isinstance(statement, ast.Raise))
    )


def python_stubs(tree: ast.AST) -> list[tuple[int, str]]:
    """(line, name) of placeholder function bodies.

    Declarations are not placeholders: abstract and overloaded functions, the
    methods of an ABC or Protocol, and a method that raises NotImplementedError
    for subclasses to override.
    """
    found: list[tuple[int, str]] = []

    def visit(node: ast.AST, owner: ast.ClassDef | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                statement = stub_statement(child)
                if statement is not None and not _is_declared_stub(
                    child, owner, statement
                ):
                    found.append((child.lineno, child.name))
                visit(child, None)
            else:
                visit(child, child if isinstance(child, ast.ClassDef) else None)

    visit(tree, None)
    return sorted(found)


def _catches_optional_import(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    items = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(reference_name(item) in OPTIONAL_IMPORT_ERRORS for item in items)


def _optional_import_nodes(tree: ast.AST) -> set[int]:
    optional: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
            _catches_optional_import(handler) for handler in node.handlers
        ):
            for statement in node.body:
                optional.update(id(inner) for inner in ast.walk(statement))
    return optional


def _is_known_python_module(
    module: str, root: Path, directory: Path, declared: set[str]
) -> bool:
    return (
        module in sys.stdlib_module_names
        or module in sys.builtin_module_names
        or module == "__main__"
        or module.lower().replace("-", "_") in declared
        or local_python_module(root, module, directory)
    )


def python_unknown_imports(
    tree: ast.AST, root: Path, directory: Path, declared: set[str]
) -> list[tuple[int, str]]:
    """(line, module) of absolute imports that nothing in the repository explains.

    The standard library, declared dependencies, the project's own modules and
    imports guarded by `except ImportError` are known. Whether the rest exist is
    a question for the project's interpreter (resolve_imports).
    """
    optional = _optional_import_nodes(tree)
    imported: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if id(node) in optional:
            continue
        if isinstance(node, ast.Import):
            imported.extend(
                (node.lineno, alias.name.split(".", 1)[0]) for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.append((node.lineno, node.module.split(".", 1)[0]))
    return [
        (line, module)
        for line, module in imported
        if not _is_known_python_module(module, root, directory, declared)
    ]


IMPORT_PROBE = """
import json, sys
try:
    from importlib.util import find_spec as find
except ImportError:
    from pkgutil import find_loader as find
missing = []
for name in sys.argv[1:]:
    try:
        found = find(name) is not None
    except Exception:
        found = False
    if not found:
        missing.append(name)
print(json.dumps(missing))
"""
IMPORT_MEMO: dict[tuple[str, str], dict[str, bool]] = {}


def project_python(root: Path, explicit: str | None = None) -> str | None:
    """The interpreter the project runs on, never the one running Loki.

    In order: --python or LOKI_PYTHON, the virtual or conda environment active
    in the hook's environment, then a .venv or venv directory in the project.
    """
    named = explicit or os.environ.get("LOKI_PYTHON")
    if named:
        return named
    prefixes = [
        Path(value)
        for variable in ("VIRTUAL_ENV", "CONDA_PREFIX")
        if (value := os.environ.get(variable))
    ]
    for prefix in (*prefixes, root / ".venv", root / "venv"):
        for relative in ("bin/python", "bin/python3", "Scripts/python.exe"):
            if (prefix / relative).is_file():
                return str(prefix / relative)
    return None


def _probe_python_imports(
    interpreter: str, root: Path, asked: list[str], deadline: float | None
) -> list[str]:
    try:
        result = subprocess.run(
            [interpreter, "-c", IMPORT_PROBE, *asked],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=min(15, command_timeout(deadline)),
            check=False,
        )
        missing = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ValueError(
            f"project interpreter {interpreter} unavailable: {error}"
        ) from error
    if not isinstance(missing, list):
        raise ValueError(
            f"project interpreter {interpreter} unavailable: "
            + (result.stderr.strip()[:200] or f"exited {result.returncode}")
        )
    return missing


def resolve_imports(
    root: Path,
    modules: Iterable[str],
    *,
    python: str | None = None,
    deadline: float | None = None,
) -> set[str]:
    """The modules the project's interpreter cannot import.

    Raises ValueError when that cannot be known: no project interpreter was
    named or found, or it did not answer.
    """
    wanted = sorted(set(modules))
    if not wanted:
        return set()
    interpreter = project_python(root, python)
    if interpreter is None:
        raise ValueError(
            "no project interpreter found (set LOKI_PYTHON or pass --python)"
        )
    known = IMPORT_MEMO.setdefault((interpreter, str(root)), {})
    asked = [module for module in wanted if module not in known]
    if asked:
        missing = _probe_python_imports(interpreter, root, asked, deadline)
        known.update({module: module not in missing for module in asked})
    return {module for module in wanted if not known[module]}


def not_checked(message: str, strict: bool, warnings: list[str] | None) -> list[str]:
    """Report unavailable coverage: a failure in strict mode, else a warning."""
    if strict:
        return [message]
    if warnings is None:
        print(message, file=sys.stderr)
    elif message not in warnings:
        warnings.append(message)
    return []


def net_new(
    found: list[tuple[int, str]], prior: list[tuple[int, str]], after: str, before: str
) -> list[tuple[int, str]]:
    """Findings absent from the base, matched by finding and source-line text."""
    seen = Counter((name, line_text(before, line)) for line, name in prior)
    kept = []
    for line, name in found:
        key = (name, line_text(after, line))
        if seen[key] > 0:
            seen[key] -= 1
        else:
            kept.append((line, name))
    return kept


def python_ast_violations(
    path: Path,
    root: Path,
    dependencies: set[str] | None = None,
    *,
    base: str = "",
    python: str | None = None,
    strict: bool = False,
    warnings: list[str] | None = None,
    deadline: float | None = None,
) -> list[str]:
    """Placeholder bodies and unresolvable imports in a Python file.

    With `base` (the file's committed text) only findings the edit introduced
    are reported, matched by finding and source-line text, so existing debt and
    shifted lines pass. Without it the whole file is checked.
    """
    display = relative_display(path, root)
    try:
        old = ast.parse(base)
    except (SyntaxError, ValueError):
        # Another Python dialect: there is nothing to compare the edit against.
        return not_checked(
            f"NOT CHECKED python ast: {display} does not parse at the base",
            strict,
            warnings,
        )
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as error:
        evidence_finding("python-syntax", display)
        return [f"{display}: python-ast: {error}"]
    declared = (
        dependencies if dependencies is not None else declared_python_dependencies(root)
    )
    directory = path.resolve().parent
    stubs = net_new(python_stubs(tree), python_stubs(old), source, base)
    imports = net_new(
        python_unknown_imports(tree, root, directory, declared),
        python_unknown_imports(old, root, directory, declared),
        source,
        base,
    )
    violations = [
        f"{display}:{line}: python-ast: stub body in {name}" for line, name in stubs
    ]
    try:
        missing = resolve_imports(
            root, {module for _, module in imports}, python=python, deadline=deadline
        )
    except ValueError as error:
        violations.extend(
            not_checked(f"NOT CHECKED python imports: {error}", strict, warnings)
        )
    else:
        violations.extend(
            f"{display}:{line}: python-ast: unresolved import {module}"
            for line, module in imports
            if module in missing
        )
    return violations[:MAX_VIOLATIONS]


JS_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
JS_REGEX_KEYWORDS = {
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
}
AUTHORIZATION_KEY_RE = re.compile(
    r"[a-z_]*?(?:admin|superuser|super_user|staff|role|roles|permission|"
    r"permissions|privilege|privileges|scope|scopes|authorized|authorised)"
    r"[a-z_?]*",
    re.I,
)
TEST_FRAMEWORKS = {
    "vitest",
    "jest",
    "@jest/globals",
    "mocha",
    "node:test",
    "bun:test",
    "ava",
    "tap",
}
TEST_FUNCTIONS = ("describe", "it", "test", "suite", "context", "bench")
REQUEST_NAMES = {"request", "req", "params", "query_params", "form", "cookies"}
SERVER_ATTRIBUTES = {"user", "session", "auth", "state", "identity", "principal"}
ELIXIR_HTTP_CALL_RE = re.compile(
    r"(?<![\w.]):(?:httpc|hackney)\.request\s*\(|"
    r"(?<![\w.])(?:HTTPoison|Req|Tesla)\.(?:get|post|put|patch|delete|head|"
    r"options|request|new)!?\s*\(|(?<![\w.])Finch\.build\s*\(|"
    r"(?<![\w.])Mint\.HTTP\.connect\s*\("
)
OPEN_REDIRECT = (
    "open redirect: unvalidated navigation target; check it against an "
    "allowlist of paths or origins"
)
Finding = tuple[str, str, int]


def blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] != "\n":
            chars[index] = " "


def closing_quote(text: str, start: int, quote: str, multiline: bool) -> int:
    """Index of the closing quote, or where an unterminated literal stops."""
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote or (char == "\n" and not multiline):
            return index
        index += 1
    return len(text)


def comment_end(text: str, index: int) -> int | None:
    """End of a // or /* comment starting at index, if one starts there."""
    pair = text[index : index + 2]
    if pair == "//":
        end = text.find("\n", index)
        return len(text) if end < 0 else end
    if pair == "/*":
        end = text.find("*/", index + 2)
        return len(text) if end < 0 else end + 2
    return None


def _js_regex_end(text: str, index: int) -> int:
    end, in_class = index + 1, False
    while end < len(text) and text[end] != "\n":
        if text[end] == "\\":
            end += 2
            continue
        if text[end] == "/" and not in_class:
            break
        if text[end] in "[]":
            in_class = text[end] == "["
        end += 1
    return end


def _js_allows_regex(previous: str, word: str) -> bool:
    return not previous or previous in JS_REGEX_PRECEDERS or word in JS_REGEX_KEYWORDS


def _advance_js_token(char: str, previous: str, word: str) -> tuple[str, str]:
    if char.isalnum() or char in "_$":
        return "word", (word + char if previous == "word" else char)
    if not char.isspace():
        return char, ""
    return previous, word


def mask_javascript(text: str) -> str:
    """Blank comments and literal contents; quotes and offsets stay in place."""
    chars = list(text)
    index, previous, word = 0, "", ""
    while index < len(text):
        char = text[index]
        if (end := comment_end(text, index)) is not None:
            blank(chars, index, end)
            index = end
            continue
        if char in "'\"`":
            end = closing_quote(text, index + 1, char, char == "`")
            blank(chars, index + 1, end)
            index, previous, word = end + 1, char, ""
            continue
        if char == "/" and _js_allows_regex(previous, word):
            end = _js_regex_end(text, index)
            blank(chars, index + 1, end)
            index, previous, word = end + 1, "/", ""
            continue
        previous, word = _advance_js_token(char, previous, word)
        index += 1
    return "".join(chars)


def _is_elixir_char_literal(text: str, index: int) -> bool:
    if text[index] != "?" or index + 1 >= len(text):
        return False
    return index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_?!")


def _mask_elixir_string(
    text: str, chars: list[str], index: int, closers: dict[str, str]
) -> int:
    opener = text[index]
    triple = text[index : index + 3]
    if triple in ('"""', "'''"):
        end = text.find(triple, index + 3)
        end = len(text) if end < 0 else end
        blank(chars, index + 3, end)
        return end + 3
    end = closing_quote(text, index + 1, closers.get(opener, opener), True)
    blank(chars, index + 1, end)
    return end + 1


def mask_elixir(text: str) -> str:
    chars = list(text)
    closers = {"(": ")", "[": "]", "{": "}", "<": ">"}
    index = 0
    while index < len(text):
        char = text[index]
        if char == "#":
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            blank(chars, index, end)
            index = end
            continue
        if _is_elixir_char_literal(text, index):
            width = 3 if text[index + 1] == "\\" else 2
            blank(chars, index + 1, index + width)
            index += width
            continue
        if char == "~" and index + 2 < len(text) and text[index + 1].isalpha():
            index += 2
        elif char not in "\"'":
            index += 1
            continue
        index = _mask_elixir_string(text, chars, index, closers)
    return "".join(chars)


RUST_INTERESTING = re.compile(r"/[/*]|b?r#*\"|[\"']")
RUST_RAW = re.compile(r"b?r(#*)\"")
RUST_CHAR = re.compile(r"'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'\n])'")
GO_INTERESTING = re.compile(r"/[/*]|[\"'`]")


def _rust_block_comment_end(text: str, index: int) -> int:
    depth, end = 1, index + 2
    while end < len(text) and depth:
        step = text[end : end + 2]
        depth += {"/*": 1, "*/": -1}.get(step, 0)
        end += 2 if step in ("/*", "*/") else 1
    return end


def _mask_rust_raw_string(text: str, chars: list[str], index: int) -> int:
    identifier = index and (text[index - 1].isalnum() or text[index - 1] == "_")
    raw = RUST_RAW.match(text, index)
    if raw is None or identifier:
        return text.index('"', index)
    start = raw.end()
    end = text.find('"' + raw.group(1), start)
    end = len(text) if end < 0 else end
    blank(chars, start, end)
    return end + 1 + len(raw.group(1))


def _mask_rust_token(text: str, chars: list[str], index: int) -> int:
    if text[index] == "`":
        end = text.find("`", index + 1)
        end = len(text) if end < 0 else end
        blank(chars, index + 1, end)
        return end + 1
    if text.startswith("/*", index):
        end = _rust_block_comment_end(text, index)
        blank(chars, index, end)
        return end
    if text.startswith("//", index):
        end = text.find("\n", index)
        end = len(text) if end < 0 else end
        blank(chars, index, end)
        return end
    if text[index] not in "\"'":
        return _mask_rust_raw_string(text, chars, index)
    if text[index] == '"':
        end = closing_quote(text, index + 1, '"', True)
        blank(chars, index + 1, end)
        return end + 1
    if literal := RUST_CHAR.match(text, index):
        blank(chars, index + 1, literal.end() - 1)
        return literal.end()
    return index + 1


def mask_rust(text: str, go: bool = False) -> str:
    """Blank comments and literals in Rust, Go and other C-family source."""
    chars = list(text)
    index = 0
    interesting = GO_INTERESTING if go else RUST_INTERESTING
    while found := interesting.search(text, index):
        index = _mask_rust_token(text, chars, found.start())
    return "".join(chars)


def matching_close(masked: str, start: int) -> int:
    """Index just past the bracket closing masked[start], or the text end."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for index in range(start, len(masked)):
        char = masked[index]
        if char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
            if not stack:
                return index + 1
    return len(masked)


def split_arguments(masked: str, start: int) -> list[tuple[int, int]]:
    """Top-level argument spans inside the parenthesis at masked[start]."""
    end = matching_close(masked, start) - 1
    spans, depth, begin = [], 0, start + 1
    for index in range(start + 1, end):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and not depth:
            spans.append((begin, index))
            begin = index + 1
    if masked[begin:end].strip():
        spans.append((begin, end))
    return spans


def expression_end(masked: str, start: int) -> int:
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if not depth:
                return index
            depth -= 1
        elif not depth and (char in ";\n," or masked.startswith("=>", index)):
            return index
    return len(masked)


def javascript_literal(text: str, masked: str, start: int, end: int) -> str | None:
    """Constant text of a single string-literal expression, else None."""
    value = masked[start:end].strip()
    if len(value) < 2 or value[0] not in "'\"`" or value[-1] != value[0]:
        return None
    if value[1:-1].strip():
        return None
    offset = masked.index(value[0], start)
    literal = text[offset + 1 : offset + len(value) - 1]
    return None if value[0] == "`" and "${" in literal else literal


SANITIZER_CALL_RE = re.compile(
    r"\s*[\w$.]*?(?:(?<!un)safe|sanitiz|validat|allow|trusted|whitelist)[\w$]*\s*\(",
    re.I,
)


def fixed_origin(text: str, masked: str, start: int, end: int) -> bool:
    """True when a leading literal pins navigation to a same-origin path or host,
    or the target comes straight from a sanitizer-named function."""
    if javascript_literal(text, masked, start, end) is not None:
        return True
    if SANITIZER_CALL_RE.match(masked[start:end]):
        return True
    value = masked[start:end].lstrip()
    if not value or value[0] not in "'\"`":
        return False
    offset = masked.index(value[0], start)
    prefix = text[offset + 1 : closing_quote(text, offset + 1, value[0], True)]
    prefix = prefix.split("${", 1)[0]
    return bool(re.match(r"/(?!/)|[#?]|[a-z][a-z0-9+.-]*://[^/\s]+/", prefix, re.I))


def _js_xss_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"\.\s*(innerHTML|outerHTML)\s*\+?=(?!=)", masked):
        end = expression_end(masked, match.end())
        if javascript_literal(text, masked, match.end(), end) is None:
            findings.append(
                (
                    "loki/unsanitized-html",
                    f"cross-site scripting (XSS): non-literal HTML assigned to "
                    f"{match.group(1)}; use textContent or a sanitizer",
                    match.start(),
                )
            )
    for match in re.finditer(
        r"\.\s*(insertAdjacentHTML)\s*\(|(?<![\w$.])document\s*\.\s*(writeln|write)"
        r"\s*\(",
        masked,
    ):
        arguments = split_arguments(masked, match.end() - 1)
        position = 1 if match.group(1) else 0
        if len(arguments) > position and (
            javascript_literal(text, masked, *arguments[position]) is None
        ):
            sink = match.group(1) or f"document.{match.group(2)}"
            findings.append(
                (
                    "loki/unsanitized-html",
                    f"cross-site scripting (XSS): non-literal HTML passed to {sink}",
                    match.start(),
                )
            )
    for match in re.finditer(
        r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", masked
    ):
        end = expression_end(masked, match.end())
        if javascript_literal(text, masked, match.end(), end) is None:
            findings.append(
                (
                    "loki/unsanitized-html",
                    "cross-site scripting (XSS): non-literal dangerouslySetInnerHTML",
                    match.start(),
                )
            )
    return findings


def _js_redirect_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(
        r"(?<![\w$.])(?:(?:window|document|self|top)\s*\.\s*)?location"
        r"(?:\s*\.\s*href)?\s*=(?!=)",
        masked,
    ):
        declaration = re.search(r"\b(?:const|let|var)\s*$", masked[: match.start()])
        if not declaration and not fixed_origin(
            text, masked, match.end(), expression_end(masked, match.end())
        ):
            findings.append(("loki/open-redirect", OPEN_REDIRECT, match.start()))
    for match in re.finditer(
        r"(?<![\w$])location\s*\.\s*(?:assign|replace)\s*\(", masked
    ):
        arguments = split_arguments(masked, match.end() - 1)
        if arguments and not fixed_origin(text, masked, *arguments[0]):
            findings.append(("loki/open-redirect", OPEN_REDIRECT, match.start()))
    for match in re.finditer(r"\bres(?:ponse)?\s*\.\s*redirect\s*\(", masked):
        arguments = split_arguments(masked, match.end() - 1)
        if arguments and re.search(
            r"\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)\b",
            masked[arguments[-1][0] : arguments[-1][1]],
        ):
            findings.append(("loki/open-redirect", OPEN_REDIRECT, match.start()))
    return findings


def _js_redirect_and_tls_findings(text: str, masked: str) -> list[Finding]:
    findings = _js_redirect_findings(text, masked)
    for match in re.finditer(
        r"\brejectUnauthorized\s*:\s*false\b|"
        r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*(?:\]\s*)?=(?!=)\s*['\"`]?\s*0",
        text,
    ):
        if masked[match.start()] != " ":
            findings.append(("loki/tls-verification", TLS_VERIFICATION, match.start()))
    return findings


def _js_command_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    shell = re.search(r"child_process|(['\"])node:child_process\1", text)
    aliases = re.findall(
        r"\b([\w$]+)\s*=\s*(?:util\s*\.\s*)?promisify\s*\(\s*"
        r"(?:child_process\s*\.\s*)?exec\s*\)",
        masked,
    )
    runners = "|".join(["exec", "execSync", *map(re.escape, aliases)])
    for match in re.finditer(
        rf"(?:(?<![\w$.])|\bchild_process\s*\.\s*)({runners})\s*\(", masked
    ):
        arguments = split_arguments(masked, match.end() - 1)
        if (
            shell
            and arguments
            and javascript_literal(text, masked, *arguments[0]) is None
        ):
            findings.append(
                (
                    "loki/command-injection",
                    f"shell command injection: non-literal command passed to "
                    f"{match.group(1)}; use execFile or spawn with an argument array",
                    match.start(),
                )
            )
    return findings


def _js_sql_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"\.\s*(?:query|execute|raw|unsafe|prepare)\s*\(", masked):
        arguments = split_arguments(masked, match.end() - 1)
        if not arguments:
            continue
        start, end = arguments[0]
        argument = text[start:end]
        if not re.search(SQL_WORD, argument, re.I):
            continue
        if "${" not in argument and not re.search(r"['\"`]\s*\+|\+\s*['\"`]", argument):
            continue
        identifier = (
            "${" in argument
            and "+" not in argument
            and all(
                re.search(SQL_IDENTIFIER_POSITION, argument[: found.start()], re.I)
                for found in re.finditer(r"\$\{", argument)
            )
        )
        findings.append(
            (
                "loki/sql-injection",
                SQL_IDENTIFIER if identifier else SQL_QUERY,
                match.start(),
            )
        )
    return findings


def _js_command_and_sql_findings(text: str, masked: str) -> list[Finding]:
    return [
        *_js_command_findings(text, masked),
        *_js_sql_findings(text, masked),
    ]


def _is_js_secret_expr(side: str) -> bool:
    return bool(
        re.search(r"\.digest\(|(?:signature|hmac|digest)[\w$]*$", side, re.I)
        and not re.search(r"\.length$", side)
    )


def _is_js_timing_pair(sides: list[str], raw_expr: str) -> bool:
    if any(side.startswith("`") for side in sides) and "${" not in raw_expr:
        return False
    if not any(_is_js_secret_expr(side) for side in sides):
        return False
    return not any(
        re.fullmatch(r"null|undefined|true|false|\d+|[\w$.]*\.length", side)
        for side in sides
    )


def _js_timing_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(
        r"([\w$.]+(?:\([^()]*\))?|`[^`]*`)\s*(?:===?|!==?)\s*"
        r"([\w$.]+(?:\([^()]*\))?|`[^`]*`)",
        masked,
    ):
        sides = [match.group(1), match.group(2)]
        if _is_js_timing_pair(sides, text[match.start() : match.end()]):
            findings.append(
                (
                    "loki/timing-compare",
                    "timing attack: signature or digest compared with ==; use "
                    "crypto.timingSafeEqual",
                    match.start(),
                )
            )
    return findings


def _js_crypto_and_origin_findings(text: str, masked: str) -> list[Finding]:
    findings = _js_timing_findings(text, masked)
    for match in re.finditer(r"\baddEventListener\s*\(\s*(['\"`])", masked):
        quote = masked.index(match.group(1), match.start())
        if not text.startswith("message", quote + 1):
            continue
        handler = masked[match.end() : matching_close(masked, match.end() - 2)]
        if not re.search(r"\.\s*origin\b|\borigin\s*[,}=]", handler):
            findings.append(
                (
                    "loki/postmessage-origin",
                    "message event handler never checks event.origin; any window "
                    "can post to it",
                    match.start(),
                )
            )
    return findings


def _js_ssrf_findings(masked: str) -> list[Finding]:
    findings: list[Finding] = []
    source = r"\breq(?:uest)?\s*\.\s*(?:query|body|params|url)\b"
    tainted = {
        match.group(1)
        for match in re.finditer(
            rf"\b(?:const|let|var)\s+([\w$]+)\s*=([^;\n]*){source}", masked
        )
        # A value passed through an allow/validate/sanitize function is clean.
        if not re.search(
            r"(?<!un)(?:safe|sanitiz|validat|allow|trusted|whitelist)\w*\s*\(",
            match.group(2),
            re.I,
        )
    }
    for group in re.findall(
        rf"\b(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*{source}", masked
    ):
        tainted.update(item.split(":")[-1].strip() for item in group.split(","))
    for match in re.finditer(
        r"(?<![\w$.])(?:fetch|got|axios(?:\s*\.\s*(?:get|post|put|delete|head|request))?"
        r"|https?\s*\.\s*(?:get|request))\s*\(",
        masked,
    ):
        arguments = split_arguments(masked, match.end() - 1)
        target = masked[arguments[0][0] : arguments[0][1]] if arguments else ""
        words = set(re.findall(r"(?<![\w$.])([\w$]+)", target))
        if re.search(source, target) or words & (tainted - {""}):
            findings.append(
                (
                    "loki/ssrf",
                    "server-side request forgery (SSRF): outbound request URL comes "
                    "from request data; validate the host against an allowlist",
                    match.start(),
                )
            )
    return findings


def _js_prototype_pollution_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(
        r"\bfunction\s+([\w$]+)\s*\(|\b(?:const|let)\s+([\w$]+)\s*=\s*"
        r"(?:async\s*)?\([^)]*\)[^={]*=>\s*\{",
        masked,
    ):
        name = match.group(1) or match.group(2)
        opening = masked.find("{", match.end() - 1)
        if opening < 0:
            continue
        end = matching_close(masked, opening)
        body = masked[opening:end]
        loop = re.search(
            r"for\s*\(\s*(?:const|let|var)\s+\[?\s*([\w$]+)[^)]*?"
            r"(?:\bof\s+Object\s*\.\s*(?:keys|entries)|\bin\b)",
            body,
        )
        if (
            loop
            and re.search(rf"(?<![\w$.]){re.escape(name)}\s*\(", body[1:])
            and re.search(rf"\[\s*{re.escape(loop.group(1))}\s*\]\s*=(?!=)", body)
            and not re.search(
                r"__proto__|prototype|constructor|hasOwn", text[opening:end]
            )
        ):
            findings.append(
                (
                    "loki/prototype-pollution",
                    "prototype pollution: recursive merge copies arbitrary keys; skip "
                    "__proto__, constructor and prototype or use Object.create(null)",
                    match.start(),
                )
            )
    return findings


def _js_runtime_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, offset in javascript_regexes(text, masked):
        if nested_quantifier(pattern):
            findings.append((REDOS_RULE, REDOS_MESSAGE, offset))
    if "clearInterval" not in masked:
        for match in re.finditer(r"(?<![\w$.])setInterval\s*\(", masked):
            findings.append(
                (
                    "loki/timer-leak",
                    "setInterval without any clearInterval in this file: the timer "
                    "and everything it captures are never released",
                    match.start(),
                )
            )
    for match in re.finditer(
        r"(?<![\w$.])((?:[\w$]+\s*\.\s*)*[\w$]+)\s*\.\s*forEach\s*\(", masked
    ):
        callback = masked[match.end() - 1 : matching_close(masked, match.end() - 1)]
        parts = re.split(r"\s*\.\s*", match.group(1))
        receiver = r"\s*\.\s*".join(map(re.escape, parts))
        if re.search(rf"(?<![\w$.]){receiver}\s*\.\s*splice\s*\(", callback):
            findings.append(
                (
                    "loki/mutation-during-iteration",
                    f"{match.group(1)} is spliced while forEach iterates it, which "
                    "skips the next element; filter into a new array instead",
                    match.start(),
                )
            )
    for match in re.finditer(r"(?<![\w$.])(eval|new\s+Function)\s*\(", masked):
        arguments = split_arguments(masked, match.end() - 1)
        if arguments and javascript_literal(text, masked, *arguments[-1]) is None:
            callee = re.sub(r"\s+", " ", match.group(1))
            findings.append(
                (
                    "loki/code-eval",
                    f"dynamic code execution: non-literal source passed to {callee}",
                    match.start(),
                )
            )
    return findings


def javascript_rules(text: str) -> list[Finding]:
    masked = mask_javascript(text)
    return [
        *_js_xss_findings(text, masked),
        *_js_redirect_and_tls_findings(text, masked),
        *_js_command_and_sql_findings(text, masked),
        *_js_crypto_and_origin_findings(text, masked),
        *_js_ssrf_findings(masked),
        *_js_prototype_pollution_findings(text, masked),
        *_js_runtime_findings(text, masked),
    ]


REDOS_RULE = "loki/redos"
REDOS_MESSAGE = (
    "ReDoS: nested quantifier such as (a+)+ causes catastrophic backtracking on "
    "crafted input; remove the nesting or bound the repetition"
)


def _char_class_contains(members: list[str], delimiter: str) -> bool:
    inside = False
    for index, member in enumerate(members):
        ranged = (
            0 < index < len(members) - 1
            and member == "-"
            and members[index - 1][-1] <= delimiter <= members[index + 1][-1]
        )
        if ranged or (member[-1] == delimiter and member != "-"):
            inside = True
    if members[:1] == ["-"] or members[-1:] == ["-"]:
        inside = inside or delimiter == "-"
    return inside


def delimiter_separated(body: str) -> bool:
    """Whether a repeated group starts or ends with a literal no atom can absorb."""
    literal = r"(?:\\[^dDwWsSbB]|[^\\\[(.|^$?*+{}])"
    found = re.match(rf"{literal}(?![?*+{{])", body) or re.search(
        rf"(?<!\\){literal}$", body
    )
    if not found:
        return False
    delimiter = found.group(0)[-1]
    if re.search(r"(?<!\\)\.|\\[SWD]", body):
        return False
    for match in re.finditer(r"\[(\^?)((?:\\.|[^\]\\])*)\]", body):
        members = re.findall(r"\\.|.", match.group(2))
        if _char_class_contains(members, delimiter) != bool(match.group(1)):
            return False
    return True


def _closes_nested_quantifier(
    pattern: str, index: int, inner: bool, start: int
) -> bool:
    if not inner:
        return False
    body = re.sub(r"^\?(?:[:=!]|<[=!]|<\w+>)", "", pattern[start:index])
    delimited = "|" not in body and delimiter_separated(body)
    return not delimited and bool(re.match(r"[+*]|\{\d+,\}", pattern[index + 1 :]))


def _is_quantifier_at(pattern: str, index: int) -> bool:
    char = pattern[index]
    return char in "+*" or (
        char == "{" and bool(re.match(r"\{\d*,\d*\}", pattern[index:]))
    )


def _step_quantifier_stack(pattern: str, index: int, stack: list[list[Any]]) -> bool:
    char = pattern[index]
    if char == "(":
        stack.append([False, index + 1])
    elif stack and _is_quantifier_at(pattern, index):
        stack[-1][0] = True
    elif char == ")" and stack:
        inner, start = stack.pop()
        if _closes_nested_quantifier(pattern, index, inner, start):
            return True
        if inner and stack:
            stack[-1][0] = True
    return False


def nested_quantifier(pattern: str) -> bool:
    """A group containing a quantifier that is itself repeated: (x+)+, (x*)*, (x+){2,}.

    A group that begins or ends with a required literal delimiter, such as
    (?:-[a-z]+)* or (\\d+,)*, cannot match ambiguously across repetitions and is
    not reported.
    """
    stack: list[list[Any]] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = pattern.find("]", index + 2)
            index = len(pattern) if close < 0 else close + 1
            continue
        if _step_quantifier_stack(pattern, index, stack):
            return True
        index += 1
    return False


def javascript_regexes(text: str, masked: str) -> list[tuple[str, int]]:
    """Regex literal bodies and new RegExp("...") patterns with their offsets."""
    found = []
    for match in re.finditer(r"/( *)/[dgimsuyv]*", masked):
        if match.group(1):
            body = text[match.start(1) : match.end(1)]
            found.append((body, match.start()))
    for match in re.finditer(r"\bRegExp\s*\(\s*(['\"`])", masked):
        close = closing_quote(text, match.end(), match.group(1), False)
        found.append((text[match.end() : close].replace("\\\\", "\\"), match.start()))
    return found


def javascript_test_names(relative: str, text: str, masked: str) -> set[str]:
    """Test-framework bindings in scope: imports, aliases and test-file globals."""
    names = set(TEST_FUNCTIONS) if TEST_PATH_RE.search(relative) else set()
    for statement in re.finditer(r"\bimport\s*\{([^}]*)\}\s*from\s*(['\"])", masked):
        end = closing_quote(text, statement.end(), statement.group(2), False)
        if text[statement.end() : end] in TEST_FRAMEWORKS:
            for item in statement.group(1).split(","):
                parts = item.split()
                if parts and parts[0] in TEST_FUNCTIONS:
                    names.add(parts[-1])
    declared = re.findall(r"\b(?:const|let|var|function|class)\s+([\w$]+)", masked)
    return names - set(declared)


def _js_fallback_test_findings(relative: str, text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for name in sorted(javascript_test_names(relative, text, masked)):
        for match in re.finditer(
            rf"(?<![\w$.]){re.escape(name)}\s*(?:\.\s*(only|skip)\b|"
            r"\[\s*(['\"`])\s*\2\s*\])\s*\(",
            masked,
        ):
            kind = match.group(1)
            if kind is None:
                quote = masked.index(match.group(2), match.start())
                kind = text[
                    quote + 1 : closing_quote(text, quote + 1, text[quote], False)
                ]
            if kind == "only":
                findings.append(
                    (
                        "no-focused-tests",
                        "focused test (.only) silently skips the rest of the suite",
                        match.start(),
                    )
                )
            elif kind == "skip":
                findings.append(
                    (
                        "no-disabled-tests",
                        "disabled test (.skip) removes coverage",
                        match.start(),
                    )
                )
    return findings


def javascript_fallback_rules(relative: str, text: str) -> list[Finding]:
    """Parser-free equivalents of the Oxlint preview rules, used only without it."""
    masked = mask_javascript(text)
    findings: list[Finding] = []
    for match in re.finditer(r"\bcatch\s*(?:\([^()]*\))?\s*\{", masked):
        if not text[match.end() : matching_close(masked, match.end() - 1) - 1].strip():
            findings.append(
                ("no-empty", "empty catch block swallows the error", match.start())
            )
    for match in re.finditer(r"\bnew\s+Promise\s*\(\s*async\b", masked):
        findings.append(
            (
                "no-async-promise-executor",
                "async Promise executor functions are not allowed",
                match.start(),
            )
        )
    for match in re.finditer(r"\bfinally\s*\{", masked):
        body = masked[match.end() : matching_close(masked, match.end() - 1) - 1]
        control = re.search(r"\b(return|throw|break|continue)\b", body)
        if control and not re.search(r"=>|\bfunction\b|\bclass\b", body):
            findings.append(
                (
                    "no-unsafe-finally",
                    f"unsafe finally: {control.group(1)} in finally overrides "
                    "try/catch control flow",
                    match.end() + control.start(),
                )
            )
    for match in re.finditer(r"(?<![\w$.])debugger\b", masked):
        findings.append(("no-debugger", "debugger statement", match.start()))
    findings.extend(_js_fallback_test_findings(relative, text, masked))
    return findings


def _request_field_target(node: ast.AST) -> tuple[ast.AST, ast.AST] | None:
    if isinstance(node, ast.Subscript):
        return node.slice, node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        return node.args[0], node.func.value
    return None


def request_field(node: ast.AST) -> str | None:
    """Privilege-looking key read from client-controlled request data."""
    target = _request_field_target(node)
    if target is None:
        return None
    key, owner = target
    if not (
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and AUTHORIZATION_KEY_RE.fullmatch(key.value)
    ):
        return None
    while isinstance(owner, ast.Attribute):
        if owner.attr in SERVER_ATTRIBUTES:
            return None
        owner = owner.value
    return (
        key.value if isinstance(owner, ast.Name) and owner.id in REQUEST_NAMES else None
    )


PYTHON_HTTP_CALLS = {
    f"{module}.{method}"
    for module in ("requests", "httpx")
    for method in ("get", "post", "put", "patch", "delete", "head", "options")
} | {"requests.request", "httpx.request", "urllib.request.urlopen", "urlopen"}


def request_source(node: ast.AST) -> bool:
    """Any value read from client-controlled request data."""
    if isinstance(node, ast.Subscript):
        owner = node.value
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "getlist"}
    ):
        owner = node.func.value
    elif isinstance(node, ast.Attribute):
        owner = node
    else:
        return False
    while isinstance(owner, ast.Attribute):
        if owner.attr in SERVER_ATTRIBUTES:
            return False
        owner = owner.value
    return isinstance(owner, ast.Name) and owner.id in REQUEST_NAMES


PYTHON_PATH_CALLS = {"open", "io.open", "os.path.join", "Path", "pathlib.Path"}
PATH_SANITIZERS = ("basename", "secure_filename", "is_relative_to", "commonpath")
PATH_SANITIZERS += ("relative_to",)


def tainted_by(node: ast.AST, tainted: set[str]) -> bool:
    """Whether an expression reads request data or an already tainted name."""
    return any(
        request_source(item) or (isinstance(item, ast.Name) and item.id in tainted)
        for item in ast.walk(node)
    )


def assigned_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    """Every name bound by an assignment's targets."""
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {
        item.id
        for target in targets
        for item in ast.walk(target)
        if isinstance(item, ast.Name)
    }


def tainted_names(nodes: list[ast.AST]) -> set[str]:
    """Names assigned from request data, followed through two rounds."""
    tainted: set[str] = set()
    for _ in range(2):
        for node in nodes:
            if (
                isinstance(node, ast.Assign | ast.AnnAssign)
                and node.value
                and tainted_by(node.value, tainted)
            ):
                tainted.update(assigned_names(node))
    return tainted


def request_scopes(tree: ast.AST) -> list[tuple[list[tuple[ast.Call, str]], set[str]]]:
    """Each function (or the module) that reads request data: its calls with
    their callee text, and the names tainted through plain assignments.

    Computed once per tree and shared by every request-taint rule.
    """
    names: dict[int, str] = {}
    found = []
    functions = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    )
    for scope in [tree, *functions]:
        nodes = list(ast.walk(scope))
        # Taint starts only at request data, so a scope that reads none has no findings.
        if not any(map(request_source, nodes)):
            continue
        tainted = tainted_names(nodes)
        calls = []
        for node in nodes:
            if isinstance(node, ast.Call):
                if id(node) not in names:
                    names[id(node)] = ast.unparse(node.func)
                calls.append((node, names[id(node)]))
        found.append((calls, tainted))
    return found


def _call_uses_tainted_args(node: ast.Call, arguments: Any, tainted: set[str]) -> bool:
    return any(tainted_by(argument, tainted) for argument in arguments(node))


def request_tainted_calls(
    scopes: list[tuple[list[tuple[ast.Call, str]], set[str]]],
    sink: Any,
    arguments: Any,
    *,
    sanitizer: Any = None,
) -> list[ast.Call]:
    """Calls accepted by sink whose chosen arguments derive from request data.

    A scope that calls a function whose last name the sanitizer accepts is
    treated as validated.
    """
    found = []
    for calls, tainted in scopes:
        if sanitizer and any(sanitizer(name.split(".")[-1]) for _, name in calls):
            continue
        for node, name in calls:
            if sink(name) and _call_uses_tainted_args(node, arguments, tainted):
                found.append(node)
                break
    unique = {(call.lineno, call.col_offset): call for call in found}
    return list(unique.values())


def python_ssrf(scopes: list[Any]) -> list[ast.Call]:
    """HTTP client calls whose URL derives from request data."""
    return request_tainted_calls(
        scopes,
        lambda name: name in PYTHON_HTTP_CALLS,
        lambda call: call.args[:1] + [k.value for k in call.keywords if k.arg == "url"],
    )


def python_path_traversal(scopes: list[Any]) -> list[ast.Call]:
    """File paths built from request data without a containment check."""
    return request_tainted_calls(
        scopes,
        lambda name: name in PYTHON_PATH_CALLS or name.endswith(".joinpath"),
        lambda call: [*call.args, *(k.value for k in call.keywords)],
        sanitizer=lambda name: name in PATH_SANITIZERS,
    )


SQL_CALLS = {"execute", "executemany", "executescript", "raw", "text"}
# Text just before a hole that puts it where SQL expects a value, not a clause or name.
SQL_VALUE_POSITION = r"(?:[=<>(,]|\b(?:like|in|values|limit|offset))\s*$"
DESERIALIZE_CALLS = {
    f"{module}.{name}"
    for module in ("pickle", "cPickle", "_pickle", "dill", "marshal")
    for name in ("load", "loads")
}
UNSAFE_YAML_LOADERS = {"Loader", "FullLoader", "UnsafeLoader"}
UNSAFE_YAML_LOADERS |= {f"C{name}" for name in UNSAFE_YAML_LOADERS}
HTTP_CLIENT_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
HTTP_CLIENT_METHODS |= {"request", "send", "stream", "Client", "AsyncClient"}
REDIRECT_CALLS = {"redirect", "RedirectResponse", "HttpResponseRedirect"}


def addends(node: ast.AST) -> list[ast.AST]:
    """The operands of a chain of + additions."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return addends(node.left) + addends(node.right)
    return [node]


def joined_sql_holes(node: ast.JoinedStr) -> tuple[str, list[str]]:
    """f-string text and the text before each {hole}."""
    befores: list[str] = []
    text = ""
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            befores.append(text)
        else:
            text += str(getattr(value, "value", ""))
    return text, befores


def added_sql_holes(node: ast.BinOp) -> tuple[str, list[str]]:
    """Constant text of a + chain and the text before each non-constant."""
    befores: list[str] = []
    text = ""
    for item in addends(node):
        if isinstance(item, ast.Constant):
            text += str(item.value)
        else:
            befores.append(text)
    return text, befores


def percent_sql_holes(node: ast.BinOp) -> tuple[str, list[str]]:
    """`"..." % values` text and the text before each %s-style hole."""
    if isinstance(node.left, ast.Constant) and not isinstance(node.right, ast.Constant):
        text = str(node.left.value)
        holes = re.finditer(r"%(?:\(\w+\))?[sdifr]", text)
        return text, [text[: hole.start()] for hole in holes]
    return "", []


def format_sql_holes(node: ast.Call) -> tuple[str, list[str]]:
    """`"...".format(values)` text and the text before each {hole}."""
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and (node.args or node.keywords)
    ):
        text = str(node.func.value.value)
        holes = re.finditer(r"\{[^{}]*\}", text)
        return text, [text[: hole.start()] for hole in holes]
    return "", []


def sql_holes(node: ast.AST) -> tuple[str, list[str]]:
    """The constant text of a built string and the text before each hole."""
    if isinstance(node, ast.JoinedStr):
        return joined_sql_holes(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return added_sql_holes(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return percent_sql_holes(node)
    if isinstance(node, ast.Call):
        return format_sql_holes(node)
    return "", []


def built_sql(node: ast.AST) -> bool:
    """SQL text with a non-constant spliced in where the query expects a value.

    Holes in clause or name positions (`WHERE 1=1 {filters}`, `FROM {table}`)
    pass: they are nearly always fixed fragments chosen in code.
    """
    text, befores = sql_holes(node)
    return bool(re.search(r"\b(?:select|insert|update|delete)\b", text, re.I)) and any(
        re.search(SQL_VALUE_POSITION, before, re.I) or before.count("'") % 2
        for before in befores
    )


def unsafe_yaml(call: ast.Call) -> bool:
    """yaml.load without a loader or with a full one, or yaml.unsafe_load."""
    name = ast.unparse(call.func)
    if name in {"yaml.unsafe_load", "yaml.unsafe_load_all"}:
        return True
    loader = call.args[1:2] + [k.value for k in call.keywords if k.arg == "Loader"]
    return name in {"yaml.load", "yaml.load_all"} and (
        not loader or ast.unparse(loader[0]).split(".")[-1] in UNSAFE_YAML_LOADERS
    )


def tls_unverified(call: ast.Call) -> bool:
    """An HTTP client call with verify=False, or an unverified SSL context."""
    name = ast.unparse(call.func)
    client = name.split(".")[0] in {"requests", "httpx"} or (
        name.split(".")[-1] in HTTP_CLIENT_METHODS
    )
    return name == "ssl._create_unverified_context" or (
        client
        and any(
            k.arg == "verify"
            and isinstance(k.value, ast.Constant)
            and k.value.value is False
            for k in call.keywords
        )
    )


def redirect_sanitizer(name: str) -> bool:
    return bool(re.search(r"safe|saniti|valid|allowed|trusted", name, re.I))


def secret_value(node: ast.AST, derived: set[str] = frozenset()) -> bool:
    """A MAC, digest or signature value: by call, by name, or assigned from one."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in {"digest", "hexdigest"}
    name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")
    return name in derived or bool(re.search(r"(?:signature|hmac|digest)$", name, re.I))


def secret_names(tree: ast.AST) -> set[str]:
    """Names assigned from digest calls or signature-named values."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            secret_value(item) for item in ast.walk(node.value)
        ):
            names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
    return names


def computed_call(node: ast.AST, values: dict[str, str]) -> str | None:
    """The call expression a value came from: directly or via a local name."""
    if isinstance(node, ast.Name):
        return values.get(node.id)
    return ast.dump(node) if isinstance(node, ast.Call) else None


def _assertion_pair(node: ast.AST) -> list[ast.AST]:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"assertEqual", "assertEquals", "assertAlmostEqual"}
    ):
        return node.args[:2]
    if (
        isinstance(node, ast.Assert)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.ops[0], ast.Eq)
    ):
        return [node.test.left, node.test.comparators[0]]
    return []


def _function_call_bindings(function: ast.AST) -> dict[str, str]:
    return {
        target.id: ast.dump(node.value)
        for node in ast.walk(function)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def tautological_assertions(tree: ast.AST) -> list[ast.AST]:
    """Assertions in tests comparing two copies of the same computed call."""
    found: list[ast.AST] = []
    for function in ast.walk(tree):
        if not (
            isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef)
            and function.name.startswith("test")
        ):
            continue
        values = _function_call_bindings(function)
        for node in ast.walk(function):
            pair = _assertion_pair(node)
            if len(pair) == 2 and (left := computed_call(pair[0], values)) is not None:
                if left == computed_call(pair[1], values):
                    found.append(node)
    return found


def _assign_disables_hostname_check(node: ast.Assign) -> bool:
    return (
        isinstance(node.value, ast.Constant)
        and node.value.value is False
        and any(
            isinstance(target, ast.Attribute) and target.attr == "check_hostname"
            for target in node.targets
        )
    )


def _python_node_security_findings(node: ast.AST, offsets: list[int]) -> list[Finding]:
    if not isinstance(node, ast.Call | ast.Assign):
        return []
    at = offsets[node.lineno - 1] + node.col_offset
    if isinstance(node, ast.Assign):
        return (
            [("loki/tls-verification", TLS_VERIFICATION, at)]
            if _assign_disables_hostname_check(node)
            else []
        )
    findings: list[Finding] = []
    name = ast.unparse(node.func)
    if name.split(".")[-1] in SQL_CALLS and node.args and built_sql(node.args[0]):
        findings.append(("loki/sql-injection", SQL_QUERY, at))
    if unsafe_yaml(node):
        findings.append(
            (
                "loki/unsafe-deserialization",
                f"unsafe deserialization: {name} without SafeLoader can build "
                "arbitrary Python objects; use yaml.safe_load",
                at,
            )
        )
    if tls_unverified(node):
        findings.append(("loki/tls-verification", TLS_VERIFICATION, at))
    return findings


def _python_tainted_security_findings(
    scopes: list[Any], offsets: list[int]
) -> list[Finding]:
    findings: list[Finding] = []
    first = lambda call: call.args[:1]  # noqa: E731
    for call in request_tainted_calls(
        scopes, lambda name: name in {"eval", "exec", "compile"}, first
    ):
        findings.append(
            (
                "loki/code-eval",
                f"dynamic code execution: non-literal source passed to "
                f"{ast.unparse(call.func)}",
                offsets[call.lineno - 1] + call.col_offset,
            )
        )
    for call in request_tainted_calls(
        scopes, lambda name: name in DESERIALIZE_CALLS, first
    ):
        findings.append(
            (
                "loki/unsafe-deserialization",
                f"unsafe deserialization: request data passed to "
                f"{ast.unparse(call.func)} can run arbitrary code; use JSON or "
                "verify a signature first",
                offsets[call.lineno - 1] + call.col_offset,
            )
        )
    for call in request_tainted_calls(
        scopes,
        lambda name: (
            name in REDIRECT_CALLS
            or (name.split(".")[-1] in REDIRECT_CALLS and not name.startswith("self."))
        ),
        lambda call: call.args[:1] + [k.value for k in call.keywords if k.arg == "url"],
        sanitizer=redirect_sanitizer,
    ):
        findings.append(
            (
                "loki/open-redirect",
                OPEN_REDIRECT,
                offsets[call.lineno - 1] + call.col_offset,
            )
        )
    return findings


def python_injection_rules(
    tree: ast.AST, scopes: list[Any], offsets: list[int]
) -> list[Finding]:
    """SQL built from values, unsafe YAML, disabled TLS, and request data reaching
    eval, deserializers or redirects."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        findings.extend(_python_node_security_findings(node, offsets))
    findings.extend(_python_tainted_security_findings(scopes, offsets))
    return findings


SHELL_RUNNERS = {"run", "call", "Popen", "check_call", "check_output"}
REGEX_CALLS = {
    f"re.{name}"
    for name in (
        "compile",
        "match",
        "search",
        "fullmatch",
        "findall",
        "finditer",
        "sub",
        "split",
    )
}
PATH_TRAVERSAL_MESSAGE = (
    "path traversal: file path built from request data; take the base "
    "name or resolve it and check it stays under the intended directory"
)
TAUTOLOGICAL_MESSAGE = (
    "tautological assertion: the expected value is computed by the "
    "same call as the result, so the test always passes"
)
PYTHON_SSRF_MESSAGE = (
    "server-side request forgery (SSRF): outbound request URL comes "
    "from request data; validate the host against an allowlist"
)
TIMING_COMPARE_MESSAGE = (
    "timing attack: signature or digest compared with ==; use hmac.compare_digest"
)


def line_offsets(text: str) -> list[int]:
    """Character offset where each line starts, plus the end of the text."""
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def decision_operands(node: ast.AST) -> list[ast.AST]:
    """The expressions a comparison, boolean or branch test decides on."""
    if isinstance(node, ast.Compare):
        return [node.left, *node.comparators]
    if isinstance(node, ast.BoolOp):
        return node.values
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return [node.operand]
    if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert)):
        return [node.test]
    return []


def request_authorization_findings(tree: ast.AST, offsets: list[int]) -> list[Finding]:
    """Decisions that trust an authorization-looking request field."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        for operand in decision_operands(node):
            if key := request_field(operand):
                findings.append(
                    (
                        "loki/request-authorization",
                        f"authorization decision trusts client-controlled request "
                        f'field "{key}"; derive privilege from the authenticated '
                        "server-side identity",
                        offsets[operand.lineno - 1] + operand.col_offset,
                    )
                )
    return findings


def _is_shell_list_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and ast.unparse(node.func).split(".")[-1] in SHELL_RUNNERS
        and bool(node.args)
        and isinstance(node.args[0], ast.List)
    )


def shell_command_call(node: ast.AST) -> bool:
    """subprocess-style call running `sh -c` with a non-constant after -c."""
    if not _is_shell_list_call(node):
        return False
    elts = getattr(getattr(node, "args", [None])[0], "elts", ())
    constant = [item.value if isinstance(item, ast.Constant) else None for item in elts]
    return bool(
        constant[:1]
        and constant[0] in SHELLS
        and "-c" in constant
        and any(value is None for value in constant[constant.index("-c") :])
    )


def secret_compare(node: ast.AST, derived: set[str]) -> bool:
    """== or != between a secret value and something other than a constant."""
    if not (
        isinstance(node, ast.Compare)
        and all(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops)
    ):
        return False
    operands = [node.left, *node.comparators]
    return any(secret_value(item, derived) for item in operands) and not any(
        isinstance(item, ast.Constant) for item in operands
    )


def shell_and_timing_findings(tree: ast.AST, offsets: list[int]) -> list[Finding]:
    """Shell commands built from values and secrets compared with ==."""
    derived = secret_names(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if shell_command_call(node):
            at = offsets[node.lineno - 1] + node.col_offset
            findings.append(("loki/command-injection", SHELL_COMMAND, at))
        if secret_compare(node, derived):
            at = offsets[node.lineno - 1] + node.col_offset
            findings.append(("loki/timing-compare", TIMING_COMPARE_MESSAGE, at))
    return findings


def redos_call(node: ast.AST) -> bool:
    """re.* call on a constant pattern with a nested quantifier."""
    return bool(
        isinstance(node, ast.Call)
        and ast.unparse(node.func) in REGEX_CALLS
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and nested_quantifier(node.args[0].value)
    )


def node_findings(
    rule: str, message: str, nodes: Iterable[ast.AST], offsets: list[int]
) -> list[Finding]:
    """One finding per node, at the node's start."""
    return [
        (rule, message, offsets[node.lineno - 1] + node.col_offset) for node in nodes
    ]


def python_rules(text: str) -> list[Finding]:
    tree = None
    with contextlib.suppress(SyntaxError, ValueError):
        tree = ast.parse(text)
    if tree is None:
        return []
    offsets = line_offsets(text)
    findings = request_authorization_findings(tree, offsets)
    findings += shell_and_timing_findings(tree, offsets)
    redos = filter(redos_call, ast.walk(tree))
    findings += node_findings(REDOS_RULE, REDOS_MESSAGE, redos, offsets)
    scopes = request_scopes(tree)
    findings += node_findings(
        "loki/path-traversal",
        PATH_TRAVERSAL_MESSAGE,
        python_path_traversal(scopes),
        offsets,
    )
    findings += node_findings(
        "loki/tautological-test",
        TAUTOLOGICAL_MESSAGE,
        tautological_assertions(tree),
        offsets,
    )
    findings += node_findings(
        "loki/ssrf", PYTHON_SSRF_MESSAGE, python_ssrf(scopes), offsets
    )
    findings.extend(python_injection_rules(tree, scopes, offsets))
    return findings


def _elixir_auth_and_taint(text: str, masked: str) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    for match in re.finditer(
        r"(?<![\w.])(?:conn\s*\.\s*)?(?:params|query_params|body_params)\s*\[\s*\"",
        masked,
    ):
        close = closing_quote(text, match.end(), '"', False)
        key = text[match.end() : close]
        after = masked[masked.find("]", close) + 1 :]
        before = masked[: match.start()]
        if AUTHORIZATION_KEY_RE.fullmatch(key) and (
            re.match(r"\s*(?:===?|!==?|and\b|or\b|&&|\|\|)", after)
            or re.search(
                r"(?:\bif|\bunless|\bnot|!|\bwhen|\band|\bor|&&|\|\|)\s*$", before
            )
        ):
            findings.append(
                (
                    "loki/request-authorization",
                    f"authorization decision trusts client-controlled request "
                    f'param "{key}"; derive privilege from the authenticated '
                    "server-side identity (conn.assigns)",
                    match.start(),
                )
            )
    tainted: set[str] = set()
    for head in re.finditer(r"\bdefp?\s+[\w?!]+\s*\(", masked):
        arguments = masked[head.end() : matching_close(masked, head.end() - 1) - 1]
        tainted.update(re.findall(r"=>\s*([a-z][\w]*)", arguments))
        tainted.update(re.findall(r"\b([a-z]\w*params)\b", arguments))
        for pair in re.finditer(r"\"\s*\"\s*=>\s*(true|false)\b", arguments):
            start = head.end() + pair.start()
            key = text[start + 1 : closing_quote(text, start + 1, '"', False)]
            if AUTHORIZATION_KEY_RE.fullmatch(key):
                findings.append(
                    (
                        "loki/request-authorization",
                        f"authorization decision trusts client-controlled request "
                        f'param "{key}"; derive privilege from the authenticated '
                        "server-side identity (conn.assigns)",
                        start,
                    )
                )
    tainted.update(re.findall(r"^\s*([a-z]\w*)\s*=[^\n]*\bparams\b", masked, re.M))
    return findings, tainted


def _elixir_redirect_and_ssrf(masked: str, tainted: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for call in re.finditer(r"\bredirect\s*\(", masked):
        arguments = masked[call.end() : matching_close(masked, call.end() - 1) - 1]
        external = re.search(r"\bexternal:\s*([^,)]+)", arguments)
        if external and (
            set(re.findall(r"(?<![\w.:])([a-z]\w*)", external.group(1))) & tainted
            or re.search(r"\bparams\b", external.group(1))
        ):
            findings.append(
                (
                    "loki/open-redirect",
                    "open redirect: external redirect target comes from request "
                    "params; allow only known hosts or same-site paths",
                    call.start(),
                )
            )
    for call in ELIXIR_HTTP_CALL_RE.finditer(masked):
        arguments = masked[call.end() : matching_close(masked, call.end() - 1) - 1]
        words = set(re.findall(r"(?<![\w.:])([a-z]\w*)\b", arguments))
        if words & tainted or re.search(r"\b(?:query_|body_)?params\b", arguments):
            findings.append(
                (
                    "loki/ssrf",
                    "server-side request forgery (SSRF): outbound request to an "
                    "untrusted URL from request parameters; validate the host "
                    "against an allowlist",
                    call.start(),
                )
            )
    return findings


def _elixir_date_sort_findings(masked: str) -> list[Finding]:
    findings: list[Finding] = []
    field = r"\.\w*(?:_at|_on|date|time|timestamp)\b"
    for call in re.finditer(r"\bEnum\.(?:sort_by|max_by|min_by)\s*\(", masked):
        arguments = [
            masked[start:end].strip()
            for start, end in split_arguments(masked, call.end() - 1)
        ]
        mapper = next((item for item in arguments if re.search(field, item)), None)
        sorter = arguments[-1] if arguments and arguments[-1] != mapper else ""
        if mapper and (not sorter or re.fullmatch(r":(?:asc|desc)", sorter)):
            findings.append(
                (
                    "loki/structural-date-sort",
                    "structural comparison: DateTime/Date values sorted with plain "
                    "term ordering; pass DateTime (or {:desc, DateTime}) as the sorter",
                    call.start(),
                )
            )
    return findings


def _elixir_file_and_sort(masked: str) -> list[Finding]:
    findings = _elixir_date_sort_findings(masked)
    for match in re.finditer(
        r"\{:ok,\s*[\w_]+\}\s*=\s*File\.(read|open|stat|ls|lstat|read_link)\s*\(",
        masked,
    ):
        findings.append(
            (
                "loki/unhandled-error-tuple",
                f"{{:ok, _}} = File.{match.group(1)}(...) raises MatchError on "
                "{:error, reason}; use case/with, or the ! variant deliberately",
                match.start(),
            )
        )
    for match in re.finditer(
        r"\{:ok,\s*([a-z]\w*)\}\s*(?:=|<-)\s*File\.open\s*\(", masked
    ):
        if not re.search(rf"\bFile\.close\s*\(\s*{match.group(1)}\b", masked):
            findings.append(
                (
                    "loki/resource-leak",
                    f"file handle {match.group(1)} from File.open is never closed; "
                    "use File.open/3 with a function or File.close",
                    match.start(),
                )
            )
    return findings


def _elixir_shell_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for call in re.finditer(r"\bSystem\.cmd\s*\(\s*\"", masked):
        program = text[call.end() : closing_quote(text, call.end(), '"', False)]
        arguments = text[call.end() : matching_close(masked, call.end() - 2)]
        if (
            program in SHELLS
            and '"-c"' in arguments
            and (
                "#{" in arguments
                or re.search(r",\s*(?![\"\s])[a-z_]\w*\s*[\]<]", arguments)
            )
        ):
            findings.append(("loki/command-injection", SHELL_COMMAND, call.start()))
    for call in re.finditer(r"(?<![\w.]):os\.cmd\s*\(", masked):
        arguments = text[call.end() : matching_close(masked, call.end() - 1) - 1]
        if "#{" in arguments or not re.fullmatch(r"\s*~c?[\"'].*[\"']\s*", arguments):
            findings.append(("loki/command-injection", SHELL_COMMAND, call.start()))
    return findings


def elixir_rules(text: str) -> list[Finding]:
    masked = mask_elixir(text)
    auth_findings, tainted = _elixir_auth_and_taint(text, masked)
    return [
        *auth_findings,
        *_elixir_redirect_and_ssrf(masked, tainted),
        *_elixir_file_and_sort(masked),
        *_elixir_shell_findings(text, masked),
    ]


SHELLS = {"sh", "bash", "zsh", "dash", "/bin/sh", "/bin/bash", "/usr/bin/env"}
TLS_VERIFICATION = (
    "TLS certificate verification disabled; trust the needed CA "
    "instead of turning verification off"
)
SQL_WORD = r"\b(?:select|insert|update|delete)\b"
SQL_QUERY = (
    "SQL injection: query text built by concatenation or "
    "interpolation; use parameterized placeholders"
)
SQL_IDENTIFIER = (
    "SQL injection: table or column name interpolated into the query; "
    "placeholders cannot bind identifiers, so map it to a fixed set of "
    "known names before building the query"
)
SHELL_COMMAND = (
    "shell command injection: command string built from variables runs through "
    "a shell with -c; pass the program and arguments separately"
)


def _rust_function_findings(masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for function in re.finditer(r"\bfn\s+\w+[^{;]*\{", masked):
        body = masked[function.end() - 1 : matching_close(masked, function.end() - 1)]
        writer = re.search(r"\bBufWriter\s*::\s*(?:new|with_capacity)\s*\(", body)
        if writer and not re.search(
            r"\.flush\s*\(|\binto_inner\s*\(|->\s*[^{]*BufWriter",
            masked[function.start() : function.end()] + body,
        ):
            findings.append(
                (
                    "loki/unflushed-writer",
                    "BufWriter dropped without flush(): write errors on drop are "
                    "silently discarded; call flush()? before returning",
                    function.end() - 1 + writer.start(),
                )
            )
        for match in re.finditer(
            r"\.get_unchecked(?:_mut)?\s*\(\s*([A-Za-z_]\w*)", body
        ):
            index = re.escape(match.group(1))
            if not re.search(
                rf"\b{index}\s*(?:<|>=)|(?:>|<=)\s*{index}\b|assert!\([^;]*\b{index}\b",
                body,
            ):
                findings.append(
                    (
                        "loki/unchecked-index",
                        "get_unchecked index is not bounds-checked in this function; "
                        "an out-of-bounds index is undefined behaviour",
                        function.end() - 1 + match.start(),
                    )
                )
    return findings


def _rust_sql_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(
        r"(?:(?<![\w.])(?:sqlx\s*::\s*)?query(?:_as|_scalar)?(?:\s*::\s*<[^>()]*>)?"
        r"|\.\s*execute|(?<![\w.])(?:diesel\s*::\s*)?sql_query)"
        r"\s*\(\s*&?\s*format\s*!\s*\(",
        masked,
    ):
        arguments = split_arguments(masked, match.end() - 1)
        literal = text[slice(*arguments[0])].strip() if arguments else ""
        if not re.match(r'r?#*"', literal):
            continue
        holes = re.finditer(r"\{(\{)?", literal)
        if message := sql_message(
            literal, [h.start() for h in holes if not h.group(1)]
        ):
            findings.append(("loki/sql-injection", message, match.start()))
    return findings


def rust_rules(text: str) -> list[Finding]:
    masked = mask_rust(text)
    findings: list[Finding] = [
        (
            "loki/placeholder",
            f"{match.group(1)}!() placeholder left in code panics at runtime",
            match.start(),
        )
        for match in re.finditer(r"(?<![\w:])(todo|unimplemented)\s*!\s*[(\[{]", masked)
    ]
    findings.extend(_rust_function_findings(masked))
    for match in re.finditer(r"\bCommand\s*::\s*new\s*\(\s*\"", masked):
        program = text[match.end() : closing_quote(text, match.end(), '"', False)]
        end = masked.find(";", match.end())
        chain = text[match.end() : len(text) if end < 0 else end]
        dynamic = re.search(r"format!|\.args?\s*\(\s*(?![\"\[\s])", chain)
        if program in SHELLS and '"-c"' in chain and dynamic:
            findings.append(("loki/command-injection", SHELL_COMMAND, match.start()))
    for match in re.finditer(
        r"\.\s*danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)", masked
    ):
        findings.append(("loki/tls-verification", TLS_VERIFICATION, match.start()))
    findings.extend(_rust_sql_findings(text, masked))
    return findings


SECRET_PATTERNS = (
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{60,})"),
    ("private key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{20,}"),
    ("Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("model provider API key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{40,}"),
)
SECRET_RE = re.compile("|".join(f"({pattern})" for _, pattern in SECRET_PATTERNS))
PLACEHOLDER_RE = re.compile(r"example|placeholder|dummy|fake|redacted|x{6}", re.I)
WORKFLOW_PATH_RE = re.compile(
    r"(?:^|/)\.github/(?:workflows/[^/]+|actions/.+/action)\.ya?ml$"
)
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.[\w.*\[\]'-]*?\b(?:title|body|message|"
    r"head_ref|ref|label|name|email|default_branch|page_name))\s*\}\}"
)


def entropy(value: str) -> float:
    import math

    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def generic_rules(relative: str, text: str) -> list[Finding]:
    """Rules for every text file: credentials, conflict markers, CI injection."""
    findings: list[Finding] = []
    for match in SECRET_RE.finditer(text):
        token = match.group(0)
        if PLACEHOLDER_RE.search(token) or (
            "PRIVATE KEY" not in token and entropy(token) < 3.0
        ):
            continue
        kind = SECRET_PATTERNS[match.lastindex - 1][0]
        findings.append(
            (
                "loki/secret",
                f"hardcoded credential ({kind}); load it from the environment or a "
                "secret store and rotate the exposed value",
                match.start(),
            )
        )
    if re.search(r"^<{7} ", text, re.M) and re.search(r"^>{7} ", text, re.M):
        for match in re.finditer(r"^(?:<{7}|>{7}) ", text, re.M):
            findings.append(
                (
                    "loki/conflict-marker",
                    "unresolved merge conflict marker",
                    match.start(),
                )
            )
    if WORKFLOW_PATH_RE.search(relative):
        findings.extend(workflow_injection(text))
    return findings


def workflow_injection(text: str) -> list[Finding]:
    """Untrusted event fields interpolated into `run:` shell scripts."""
    findings: list[Finding] = []
    offset, block = 0, None
    for line in text.splitlines(keepends=True):
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if block is not None and stripped and indent <= block:
            block = None
        key = re.match(r"(?:-\s+)?run:\s*(.*)$", stripped)
        if key:
            block = indent if key.group(1).strip()[:1] in ("|", ">", "") else None
        if key or block is not None:
            for match in UNTRUSTED_CONTEXT_RE.finditer(line):
                findings.append(
                    (
                        "loki/actions-injection",
                        "script injection: untrusted GitHub event field interpolated "
                        "into a run step; pass it through env and quote it",
                        offset + match.start(),
                    )
                )
        offset += len(line)
    return findings


GO_STRING = r'\s*(?:"[^"\n]*"|`[^`]*`)\s*'


def go_literal(masked: str) -> bool:
    """A masked Go expression that is only string literals joined with +."""
    return bool(re.fullmatch(rf"{GO_STRING}(?:\+{GO_STRING})*", masked))


def top_level_split(
    masked: str, start: int, end: int, char: str
) -> list[tuple[int, int]]:
    spans, depth, begin = [], 0, start
    for index in range(start, end):
        if masked[index] in "([{":
            depth += 1
        elif masked[index] in ")]}":
            depth -= 1
        elif masked[index] == char and not depth:
            spans.append((begin, index))
            begin = index + 1
    return [*spans, (begin, end)]


def sql_message(literal: str, holes: list[int]) -> str | None:
    """SQL injection message for query text with non-literal values at holes."""
    if not holes or not re.search(SQL_WORD, literal, re.I):
        return None
    if all(re.search(SQL_IDENTIFIER_POSITION, literal[:hole], re.I) for hole in holes):
        return SQL_IDENTIFIER
    return SQL_QUERY


def _go_sprintf_sql_message(text: str, masked: str, open_paren: int) -> str | None:
    inner = split_arguments(masked, open_paren)
    dynamic = [span for span in inner[1:] if not go_literal(masked[slice(*span)])]
    if not dynamic or not go_literal(masked[slice(*inner[0])]):
        return None
    literal = text[slice(*inner[0])]
    holes = re.finditer(r"%(?:%|[-+# 0-9.]*([sv]))", literal)
    return sql_message(literal, [h.start() for h in holes if h.group(1)])


def _go_sql_arg_message(text: str, masked: str, start: int, end: int) -> str | None:
    sprintf = re.match(r"\s*fmt\s*\.\s*Sprintf\s*\(", masked[start:end])
    if sprintf:
        return _go_sprintf_sql_message(text, masked, start + sprintf.end() - 1)
    parts = top_level_split(masked, start, end, "+")
    literals = [part for part in parts if go_literal(masked[slice(*part)])]
    if not literals or len(literals) == len(parts):
        return None
    return sql_message("".join(text[slice(*p)] for p in literals), [0])


def _go_sql_findings(text: str, masked: str) -> list[Finding]:
    findings: list[Finding] = []
    for call in re.finditer(
        r"\.\s*(?:Query|QueryRow|Exec|Prepare)(Context)?\s*\(", masked
    ):
        arguments = split_arguments(masked, call.end() - 1)[bool(call.group(1)) :]
        if not arguments:
            continue
        if message := _go_sql_arg_message(text, masked, *arguments[0]):
            findings.append(("loki/sql-injection", message, call.start()))
    return findings


def _go_zip_slip_findings(text: str, masked: str) -> list[Finding]:
    if not re.search(r'"archive/(?:zip|tar)"', text):
        return []
    findings: list[Finding] = []
    for function in re.finditer(r"\bfunc\b[^{]*\{", masked):
        end = matching_close(masked, function.end() - 1)
        body = masked[function.end() - 1 : end]
        joined = re.search(r"\b(?:filepath|path)\.Join\s*\([^)]*\b\w+\.Name\b", body)
        guarded = re.search(
            r"\bIsLocal\s*\(|\bfilepath\.Rel\s*\(|\bHasPrefix\s*\(|"
            r"\bValidPath\s*\(|\bContains\s*\([^)]*\.\.",
            text[function.end() - 1 : end],
        )
        if joined and not guarded:
            findings.append(
                (
                    "loki/zip-slip",
                    "path traversal (zip slip): archive entry name joined into a "
                    "path without checking it stays inside the destination; use "
                    "filepath.IsLocal",
                    function.end() - 1 + joined.start(),
                )
            )
    return findings


def go_rules(text: str) -> list[Finding]:
    """Zip slip, SQL built with Sprintf or +, shell -c commands, TLS skip-verify."""
    masked = mask_rust(text, go=True)
    findings: list[Finding] = [
        ("loki/tls-verification", TLS_VERIFICATION, match.start())
        for match in re.finditer(
            r"\bInsecureSkipVerify\s*(?::|=(?!=))\s*true\b", masked
        )
    ]
    for call in re.finditer(r"\bexec\s*\.\s*Command(Context)?\s*\(", masked):
        arguments = split_arguments(masked, call.end() - 1)[bool(call.group(1)) :]
        words = [text[a:b].strip().strip('"`') for a, b in arguments[:2]]
        if (
            len(arguments) > 2
            and words[0] in SHELLS
            and words[1] == "-c"
            and not go_literal(masked[slice(*arguments[2])])
        ):
            findings.append(("loki/command-injection", SHELL_COMMAND, call.start()))
    findings.extend(_go_sql_findings(text, masked))
    findings.extend(_go_zip_slip_findings(text, masked))
    return findings


def content_rule_findings(
    relative: str, text: str, *, fallback: bool = False
) -> list[Finding]:
    language = LANGUAGE_EXTENSIONS.get(Path(relative).suffix.lower())
    if fallback:
        return (
            javascript_fallback_rules(relative, text)
            if language == "typescript"
            else []
        )
    rules = {
        "typescript": javascript_rules,
        "python": python_rules,
        "elixir": elixir_rules,
        "rust": rust_rules,
        "go": go_rules,
    }
    # Pure in (path, text): the daemon warms this for committed files, so the
    # unchanged base side of a write is a cache hit in its forked request.
    return content_memo(
        "rules",
        relative,
        text,
        lambda: (
            generic_rules(relative, text)
            + (rules[language](text) if language in rules else [])
        ),
    )


def content_rule_violations(
    changes: list[tuple[str, str, str]], *, fallback: bool = False
) -> list[str]:
    """Net-new tool-free findings, matched by rule, message and line text."""

    violations: list[str] = []
    for relative, old, new in changes:
        counts: list[Counter[tuple[str, str, str]]] = []
        lines: dict[tuple[str, str, str], int] = {}
        for side, content in enumerate((old, new)):
            counter: Counter[tuple[str, str, str]] = Counter()
            for rule, message, offset in content_rule_findings(
                relative, content, fallback=fallback
            ):
                number = content.count("\n", 0, offset) + 1
                key = (rule, message, content.splitlines()[number - 1].strip())
                counter[key] += 1
                if side:
                    lines.setdefault(key, number)
            counts.append(counter)
        for key, count in (counts[1] - counts[0]).items():
            rule, message, _ = key
            evidence_finding(rule, relative)
            violations.extend([f"{relative}:{lines[key]}: {rule}: {message}"] * count)
    return violations[:MAX_VIOLATIONS]


def resolve_tool(root: Path, name: str) -> str | None:
    """Prefer the project's pinned Node tool, then the same tool on PATH."""
    local = root / "node_modules" / ".bin" / name
    return str(local) if local.is_file() else shutil.which(name)


def typescript_compiler(root: Path) -> Path | None:
    local = root / "node_modules/typescript/lib/typescript.js"
    if local.is_file():
        return local
    if tsc := shutil.which("tsc"):
        compiler = Path(tsc).resolve().parent.parent / "lib/typescript.js"
        if compiler.is_file():
            return compiler
    return None


# --- Structural sloppiness -------------------------------------------------
# Erosion and verbosity follow https://earendil.com/posts/measuring-code-sloppiness/
# and the index follows trellis's provisional formula (scoring 0.2.0), extended
# from TypeScript to every Loki language.

SLOP_COMPLEXITY = 10
CLONE_MIN_TOKENS = 100
CLONE_MIN_LINES = 3
SLOP_DIMENSIONS = (
    # dimension, weight, density metric @ saturation, count metric, log scale
    ("complexity-erosion", 0.5, "eroded_share", 0.25, "eroded_functions", 20),
    ("duplication", 0.3, "duplication_density", 0.15, "clone_groups", 15),
    ("import-cycle", 0.2, "cycle_density", 0.10, "cycle_groups", 5),
)
SLOP_EXTENSIONS = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".php": "php",
    ".rb": "ruby",
}
BRACE_LANGUAGES = {"java", "kotlin", "csharp", "c", "cpp", "swift", "scala", "php"}
EXACT_COMPLEXITY = {"python", "typescript", "go", "elixir"}
SLOP_KEYWORDS = {
    "python": "and as assert async await break class continue def del elif else "
    "except finally for from global if import in is lambda nonlocal not or pass "
    "raise return try while with yield None True False match case",
    "typescript": "async await break case catch class const continue default delete "
    "do else enum export extends false finally for function if import in instanceof "
    "let new null of return static super switch this throw true try typeof var void "
    "while yield interface type implements",
    "go": "break case chan const continue default defer else fallthrough for func go "
    "goto if import interface map package range return select struct switch type var "
    "nil true false",
    "rust": "as async await break const continue crate else enum extern false fn for "
    "if impl in let loop match mod move mut pub ref return self Self static struct "
    "super trait true type unsafe use where while",
    "elixir": "after and case catch cond def defp defmodule defstruct do else end fn "
    "for if in nil not or raise receive rescue true false try unless when with",
    "brace": "abstract break case catch class const continue default do else enum "
    "extends false final finally for foreach func fun function if implements import "
    "in interface internal let namespace new null override private protected public "
    "return static struct super switch this throw true try val var void when while",
    "ruby": "begin break case class def do else elsif end ensure false for if in module "
    "next nil not or and rescue return self then true unless until when while yield",
}


def slop_language(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    return LANGUAGE_EXTENSIONS.get(suffix) or SLOP_EXTENSIONS.get(suffix)


def slop_mask(language: str, text: str) -> str:
    if language == "python":
        return mask_python(text)
    if language == "typescript":
        return mask_javascript(text)
    if language in {"elixir", "ruby"}:
        return mask_elixir(text)
    return mask_rust(text)


@dataclass(frozen=True)
class FunctionMetric:
    path: str
    name: str
    start: int
    end: int
    complexity: int
    sloc: int
    nesting: int

    @property
    def mass(self) -> float:
        return self.complexity * self.sloc**0.5


def source_lines(masked: str, start: int, end: int) -> int:
    """Non-blank lines once comments and literal contents are masked."""
    lines = masked.splitlines()[start - 1 : end]
    return sum(1 for line in lines if line.strip())


def python_functions(path: str, text: str) -> list[FunctionMetric]:
    """Exact McCabe-style complexity; nested functions count for themselves."""
    return content_memo(
        "python-functions", path, text, lambda: python_functions_uncached(path, text)
    )


def _python_decision_weight(child: ast.AST) -> int:
    if isinstance(
        child,
        ast.If | ast.For | ast.AsyncFor | ast.While | ast.IfExp | ast.ExceptHandler,
    ):
        return 1
    if isinstance(child, ast.match_case) and not (
        isinstance(child.pattern, ast.MatchAs) and child.pattern.pattern is None
    ):
        # A bare `case _:` is the default branch, like `default:` elsewhere.
        return 1
    if isinstance(child, ast.BoolOp):
        return len(child.values) - 1
    if isinstance(child, ast.comprehension):
        return 1 + len(child.ifs)
    return 0


def python_functions_uncached(path: str, text: str) -> list[FunctionMetric]:
    tree = None
    with contextlib.suppress(SyntaxError, ValueError):
        tree = ast.parse(text)
    if tree is None:
        return []
    lines = text.splitlines()
    results = []

    def decisions(node: ast.AST, depth: int) -> tuple[int, int]:
        total, deepest = 0, depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                continue
            nested = isinstance(
                child,
                ast.If
                | ast.For
                | ast.AsyncFor
                | ast.While
                | ast.Try
                | ast.With
                | ast.Match,
            )
            total += _python_decision_weight(child)
            count, reached = decisions(child, depth + 1 if nested else depth)
            total += count
            deepest = max(deepest, reached)
        return total, deepest

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = node.end_lineno or node.lineno
            count, depth = decisions(node, 0)
            sloc = sum(
                1
                for line in lines[node.lineno - 1 : end]
                if line.strip() and not line.strip().startswith("#")
            )
            results.append(
                FunctionMetric(
                    path, node.name, node.lineno, end, 1 + count, sloc, depth
                )
            )
    return results


def _indent_function_spans(masked: str) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    lines = masked.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for index, line in enumerate(lines):
        head = re.match(r"(\s*)defp?\s+(?:self\.)?([\w?!=]+)", line)
        if not head:
            continue
        if re.search(r",\s*do:", line):
            spans.append((head.group(2), offsets[index], offsets[index + 1]))
            continue
        indent = len(head.group(1))
        for other in range(index + 1, len(lines)):
            if (
                lines[other].strip() == "end"
                and len(lines[other]) - len(lines[other].lstrip()) <= indent
            ):
                spans.append((head.group(2), offsets[index], offsets[other + 1]))
                break
    return spans


def _brace_function_spans(masked: str, language: str) -> list[tuple[str, int, int]]:
    pattern = {
        "go": r"\bfunc\s*(?:\([^)]*\)\s*)?([\w]*)\s*\(",
        "rust": r"\bfn\s+(\w+)",
        "typescript": r"\bfunction\s*\*?\s*([\w$]*)\s*\(|([\w$]+)\s*=\s*"
        r"(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*(?::[^=;{]+)?=>\s*\{|"
        r"^\s*(?:(?:public|private|protected|static|async|get|set)\s+)*"
        r"([\w$]+)\s*\([^()]*\)\s*(?::[^{;]+)?\{",
    }.get(
        language,
        # Brace languages: `fun`/`func`/`function`/`def` heads, or C-family
        # `type name(params) {` heads.
        r"\b(?:fun|func|function|def)\s+(?:[\w.<>]+\.)?([\w$]+)|"
        r"^[ \t]*(?:[\w<>\[\],.*&:~?]+[ \t]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)"
        r"[^;{}=]*\{",
    )
    spans: list[tuple[str, int, int]] = []
    for match in re.finditer(pattern, masked, re.M):
        opening = masked.find("{", match.end() - 1)
        if opening < 0 or ";" in masked[match.end() : opening]:
            continue
        name = next((group for group in match.groups() if group), "<anonymous>")
        if name in {"if", "for", "while", "switch", "catch", "function", "foreach"}:
            continue
        spans.append((name, match.start(), matching_close(masked, opening)))
    return spans


def _masked_nesting_depth(body: str) -> int:
    depth, deepest = 0, 0
    for char in body:
        if char in "{(":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "})":
            depth -= 1
    return max(0, deepest - 1)


def _masked_function_metric(
    path: str,
    masked: str,
    language: str,
    decision: str,
    span: tuple[str, int, int],
    spans: list[tuple[str, int, int]],
) -> FunctionMetric:
    name, start, end = span
    body = masked[start:end]
    # Nested functions are measured separately, never folded into the parent.
    for _, inner_start, inner_end in spans:
        if start < inner_start and inner_end <= end:
            body = body.replace(masked[inner_start:inner_end], "", 1)
    count = len(re.findall(decision, body))
    if language == "rust":
        # A match with n arms adds n - 1 decisions.
        count -= len(re.findall(r"\bmatch\b", body))
    if language == "elixir":
        count -= len(re.findall(r"\bfn\b", body))
    first = masked.count("\n", 0, start) + 1
    last = masked.count("\n", 0, max(start, end - 1)) + 1
    return FunctionMetric(
        path,
        name,
        first,
        last,
        1 + max(0, count),
        source_lines(masked, first, last),
        _masked_nesting_depth(body),
    )


def masked_functions(path: str, text: str, language: str) -> list[FunctionMetric]:
    """Approximate complexity for Go, Rust, Elixir (and JS/TS without a compiler).

    Functions are found structurally on masked source; decisions are counted as
    branch keywords, match/case arms and short-circuit operators in the body,
    excluding nested functions.
    """
    masked = slop_mask(language, text)
    spans = (
        _indent_function_spans(masked)
        if language in {"elixir", "ruby"}
        else _brace_function_spans(masked, language)
    )
    decision = {
        "go": r"\bif\b|\bfor\b|\bcase\b|&&|\|\|",
        "rust": r"\bif\b|\bwhile\b|\bfor\b|=>|&&|\|\||\?(?![\w?])",
        "typescript": r"\bif\b|\bfor\b|\bwhile\b|\bcase\b|\bcatch\b|&&|\|\||\?\?|\?\.|"
        r"\?(?![.?])",
        "elixir": r"\bif\b|\bunless\b|->|&&|\|\||\band\b|\bor\b",
        "ruby": r"\b(?:if|unless|elsif|while|until|for|when|rescue)\b|&&|\|\||"
        r"\band\b|\bor\b",
    }.get(
        language,
        r"\b(?:if|for|foreach|while|case|catch|when)\b|&&|\|\||\?\?|\?(?![.:?])",
    )
    return [
        _masked_function_metric(path, masked, language, decision, span, spans)
        for span in spans
    ]


def function_metrics(
    path: str, text: str, exact: list[FunctionMetric] | None = None
) -> list[FunctionMetric]:
    """Exact metrics when a parser supplied them, else structural approximation."""
    language = slop_language(path)
    if language == "python":
        return python_functions(path, text)
    if exact is not None:
        return exact
    return [] if language is None else masked_functions(path, text, language)


def exact_function_metrics(
    root: Path, texts: dict[str, str], *, deadline: float | None = None
) -> tuple[dict[str, list[FunctionMetric]], set[str]]:
    """Parser-backed metrics for TS/JS, Go and Elixir, plus languages left approximate."""
    exact: dict[str, list[FunctionMetric]] = {}
    approximate: set[str] = set()
    for language, measure in (
        (
            "typescript",
            lambda chosen: typescript_function_metrics(root, chosen, deadline=deadline),
        ),
        ("go", lambda chosen: go_function_metrics(chosen, deadline=deadline)),
        ("elixir", lambda chosen: elixir_function_metrics(chosen, deadline=deadline)),
    ):
        chosen = {
            path: text
            for path, text in texts.items()
            if slop_language(path) == language
        }
        if not chosen:
            continue
        result = measure(chosen)
        if result is None:
            approximate.add(language)
        else:
            exact.update(result)
    approximate.update(
        language
        for path in texts
        if (language := slop_language(path)) and language not in EXACT_COMPLEXITY
    )
    return exact, approximate


SLOP_TYPESCRIPT = r"""
const ts = require(process.argv[1]);
const files = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const decision = new Set([ts.SyntaxKind.IfStatement, ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement, ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement, ts.SyntaxKind.DoStatement, ts.SyntaxKind.CaseClause,
  ts.SyntaxKind.CatchClause, ts.SyntaxKind.ConditionalExpression]);
const logical = new Set([ts.SyntaxKind.AmpersandAmpersandToken,
  ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]);
const nesting = new Set([ts.SyntaxKind.IfStatement, ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement, ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement, ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.SwitchStatement, ts.SyntaxKind.TryStatement]);
const out = {};
for (const [name, text] of Object.entries(files)) {
  const file = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true);
  const functions = [];
  const measure = (fn, label) => {
    let complexity = 1, deepest = 0;
    const walk = (node, depth) => {
      if (node !== fn && ts.isFunctionLike(node)) return;
      if (decision.has(node.kind)) complexity++;
      if (ts.isBinaryExpression(node) && logical.has(node.operatorToken.kind)) complexity++;
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node) ||
           ts.isCallExpression(node)) && node.questionDotToken) complexity++;
      const next = nesting.has(node.kind) ? depth + 1 : depth;
      deepest = Math.max(deepest, next);
      ts.forEachChild(node, child => walk(child, next));
    };
    ts.forEachChild(fn, child => walk(child, 0));
    const start = file.getLineAndCharacterOfPosition(fn.getStart(file)).line + 1;
    const end = file.getLineAndCharacterOfPosition(fn.getEnd()).line + 1;
    functions.push([label, start, end, complexity, deepest]);
  };
  const visit = node => {
    if (ts.isFunctionLike(node) && node.body) {
      const label = node.name && ts.isIdentifier(node.name) ? node.name.text
        : ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)
          ? node.parent.name.text : '<anonymous>';
      measure(node, label);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  out[name] = functions;
}
console.log(JSON.stringify(out));
"""


def typescript_function_metrics(
    root: Path, texts: dict[str, str], *, deadline: float | None = None
) -> dict[str, list[FunctionMetric]] | None:
    """Exact TS/JS complexity from the TypeScript parser, or None without one."""
    compiler = typescript_compiler(root)
    if compiler is None or not texts:
        return None
    report = None
    with contextlib.suppress(OSError, ValueError, subprocess.TimeoutExpired):
        result = subprocess.run(
            ["node", "-e", SLOP_TYPESCRIPT, str(compiler.resolve())],
            input=json.dumps(texts),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout(deadline),
            check=False,
        )
        if not result.returncode:
            report = json.loads(result.stdout)
    if report is None:
        return None
    metrics = {}
    for name, functions in report.items():
        masked = mask_javascript(texts[name])
        metrics[name] = [
            FunctionMetric(
                name,
                label,
                start,
                end,
                complexity,
                source_lines(masked, start, end),
                depth,
            )
            for label, start, end, complexity, depth in functions
        ]
    return metrics


SLOP_GO = r"""package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

type function struct {
	Name       string `json:"name"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Complexity int    `json:"complexity"`
	Nesting    int    `json:"nesting"`
}

func nests(node ast.Node) bool {
	switch node.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
		*ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	}
	return false
}

// measure counts gocyclo decisions; function literals are measured separately.
func measure(fset *token.FileSet, root ast.Node, body *ast.BlockStmt, name string,
	out *[]function) {
	complexity, deepest := 1, 0
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if literal, ok := node.(*ast.FuncLit); ok {
			measure(fset, literal, literal.Body, "<anonymous>", out)
			return false
		}
		stack = append(stack, node)
		switch item := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			if item.List != nil {
				complexity++
			}
		case *ast.CommClause:
			if item.Comm != nil {
				complexity++
			}
		case *ast.BinaryExpr:
			if item.Op == token.LAND || item.Op == token.LOR {
				complexity++
			}
		}
		depth := 0
		for _, open := range stack {
			if nests(open) {
				depth++
			}
		}
		if depth > deepest {
			deepest = depth
		}
		return true
	})
	*out = append(*out, function{name, fset.Position(root.Pos()).Line,
		fset.Position(root.End()).Line, complexity, deepest})
}

func main() {
	var files map[string]string
	if err := json.NewDecoder(os.Stdin).Decode(&files); err != nil {
		os.Exit(2)
	}
	result := map[string][]function{}
	for name, text := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, text, parser.SkipObjectResolution)
		functions := []function{}
		if err == nil {
			for _, declaration := range file.Decls {
				item, ok := declaration.(*ast.FuncDecl)
				if !ok || item.Body == nil {
					continue
				}
				label := item.Name.Name
				if item.Recv != nil && len(item.Recv.List) == 1 {
					receiver := item.Recv.List[0].Type
					if star, ok := receiver.(*ast.StarExpr); ok {
						receiver = star.X
					}
					if ident, ok := receiver.(*ast.Ident); ok {
						label = ident.Name + "." + label
					}
				}
				measure(fset, item, item.Body, label, &functions)
			}
		}
		result[name] = functions
	}
	json.NewEncoder(os.Stdout).Encode(result)
}
"""

SLOP_ELIXIR = r"""
defmodule LokiSlop do
  @branches [:if, :unless]
  @clauses [:case, :cond, :receive]
  @nesting [:if, :unless, :case, :cond, :receive, :with, :try, :fn]
  @boolean [:and, :or, :&&, :||]
  @definitions [:def, :defp, :defmacro, :defmacrop]

  def main do
    # A file, not stdin: unicode-mode stdio rejects sources with non-Latin-1 text.
    [path] = System.argv()
    read(File.read!(path))
  end

  defp read(""), do: :ok

  defp read(data) do
    [name, rest] = :binary.split(data, "\n")
    [size, rest] = :binary.split(rest, "\n")
    count = String.to_integer(size)
    <<text::binary-size(count), rest::binary>> = rest
    measure(name, text)
    read(rest)
  end

  defp measure(name, text) do
    case Code.string_to_quoted(text, token_metadata: true) do
      {:ok, ast} ->
        Macro.prewalk(ast, nil, fn
          {kind, meta, [head | body]} = node, acc when kind in @definitions ->
            emit(name, head, meta, body)
            {node, acc}

          node, acc ->
            {node, acc}
        end)

      _ ->
        IO.puts("#{name}\tUNPARSED")
    end
  end

  defp label({:when, _, [call | _]}), do: label(call)
  defp label({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp label(_), do: "<anonymous>"

  defp emit(name, head, meta, body) do
    start = Keyword.get(meta, :line, 0)
    finish = get_in(meta, [:end, :line]) || last_line(body, start)
    {complexity, nesting} = walk(body, 0)
    IO.puts(Enum.join([name, label(head), start, finish, 1 + complexity, nesting], "\t"))
  end

  defp last_line(node, line) do
    {_, found} =
      Macro.prewalk(node, line, fn
        {_, meta, _} = item, acc when is_list(meta) -> {item, max(acc, meta[:line] || acc)}
        item, acc -> {item, acc}
      end)

    found
  end

  # Returns {decisions, deepest nesting} for a subtree.
  defp walk({kind, _, args}, depth) when is_atom(kind) and is_list(args) do
    own =
      cond do
        kind in @branches -> 1
        kind in @clauses -> max(length(arms(args)) - 1, 0)
        kind == :with -> Enum.count(args, &match?({:<-, _, _}, &1)) + length(arms(args, :else))
        kind == :try -> length(arms(args, :rescue)) + length(arms(args, :catch))
        kind == :fn -> max(length(args) - 1, 0)
        kind in @boolean and length(args) == 2 -> 1
        true -> 0
      end

    inner = if kind in @nesting, do: depth + 1, else: depth
    {count, deepest} = walk(args, inner)
    {own + count, max(deepest, if(kind in @nesting, do: inner, else: depth))}
  end

  defp walk({left, right}, depth), do: walk([left, right], depth)

  defp walk(list, depth) when is_list(list) do
    Enum.reduce(list, {0, depth}, fn item, {count, deepest} ->
      {inner, reached} = walk(item, depth)
      {count + inner, max(deepest, reached)}
    end)
  end

  defp walk({callee, _, args}, depth) when is_list(args), do: walk([callee | args], depth)
  defp walk(_, depth), do: {0, depth}

  defp arms(args, key \\ :do) do
    Enum.find_value(args, [], fn
      list when is_list(list) ->
        case Keyword.get(list, key) do
          clauses when is_list(clauses) -> Enum.filter(clauses, &match?({:->, _, _}, &1))
          _ -> nil
        end

      _ ->
        nil
    end)
  end
end

LokiSlop.main()
"""


def go_function_metrics(
    texts: dict[str, str], *, deadline: float | None = None
) -> dict[str, list[FunctionMetric]] | None:
    """Exact gocyclo complexity from go/ast; the helper is built once and cached."""
    import hashlib

    if not texts or not shutil.which("go"):
        return None
    digest = hashlib.sha256(SLOP_GO.encode()).hexdigest()[:16]
    tool = Path.home() / ".cache/loki/tools" / f"gometrics-{digest}"
    report = None
    with contextlib.suppress(OSError, ValueError, subprocess.TimeoutExpired):
        if not tool.is_file():
            source = tool.with_suffix(".src")
            source.mkdir(parents=True, exist_ok=True)
            (source / "go.mod").write_text("module lokimetrics\n\ngo 1.21\n")
            (source / "main.go").write_text(SLOP_GO)
            built = subprocess.run(
                ["go", "build", "-o", str(tool), "."],
                cwd=source,
                capture_output=True,
                env={**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod"},
                timeout=command_timeout(deadline),
                check=False,
            )
            if built.returncode:
                return None
        result = subprocess.run(
            [str(tool)],
            input=json.dumps(texts),
            capture_output=True,
            encoding="utf-8",
            timeout=command_timeout(deadline),
            check=False,
        )
        if result.returncode == 0:
            report = json.loads(result.stdout)
    if report is None:
        return None
    metrics = {}
    for name, functions in report.items():
        masked = mask_rust(texts[name])
        metrics[name] = [
            FunctionMetric(
                name,
                item["name"],
                item["start"],
                item["end"],
                item["complexity"],
                source_lines(masked, item["start"], item["end"]),
                item["nesting"],
            )
            for item in functions
        ]
    return metrics


def _parse_elixir_metrics_output(
    stdout: str, texts: dict[str, str]
) -> dict[str, list[FunctionMetric]]:
    metrics: dict[str, list[FunctionMetric]] = {name: [] for name in texts}
    masks: dict[str, str] = {}
    for line in stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or fields[0] not in texts:
            continue
        name, label, start, end, complexity, nesting = fields
        if name not in masks:
            masks[name] = mask_elixir(texts[name])
        metrics[name].append(
            FunctionMetric(
                name,
                label,
                int(start),
                int(end),
                int(complexity),
                source_lines(masks[name], int(start), int(end)),
                int(nesting),
            )
        )
    return metrics


def elixir_function_metrics(
    texts: dict[str, str], *, deadline: float | None = None
) -> dict[str, list[FunctionMetric]] | None:
    """Exact clause-aware complexity from Elixir's own parser."""
    if not texts or not shutil.which("elixir"):
        return None
    import tempfile

    payload = "".join(
        f"{name}\n{len(text.encode('utf-8'))}\n{text}" for name, text in texts.items()
    )
    result = None
    with contextlib.suppress(OSError, subprocess.TimeoutExpired, ValueError):
        with tempfile.NamedTemporaryFile(suffix=".loki") as handle:
            handle.write(payload.encode("utf-8"))
            handle.flush()
            result = subprocess.run(
                ["elixir", "-e", SLOP_ELIXIR, handle.name],
                capture_output=True,
                timeout=command_timeout(deadline),
                check=False,
            )
    if result is None or result.returncode:
        return None
    return _parse_elixir_metrics_output(
        result.stdout.decode("utf-8", errors="replace"), texts
    )


def elixir_import_graph(files: dict[str, str]) -> dict[str, set[str]]:
    """Compile-time dependencies (import, use, require) between project modules."""
    owners: dict[str, str] = {}
    for path, text in files.items():
        if Path(path).suffix in {".ex", ".exs"}:
            for module in re.findall(
                r"^\s*defmodule\s+([\w.]+)", mask_elixir(text), re.M
            ):
                owners[module] = path
    graph: dict[str, set[str]] = {}
    for path, text in files.items():
        if Path(path).suffix not in {".ex", ".exs"}:
            continue
        masked = mask_elixir(text)
        targets = re.findall(r"^\s*(?:import|use|require)\s+([\w.]+)", masked, re.M)
        graph[path] = {
            owners[target]
            for target in targets
            if target in owners and owners[target] != path
        }
    return graph


def normalized_tokens(path: str, text: str) -> list[tuple[str, int]]:
    """Tokens with identifiers and literals replaced by placeholders, per line."""
    language = slop_language(path)
    if language is None:
        return []
    masked = slop_mask(language, text)
    family = "brace" if language in BRACE_LANGUAGES else language
    keywords = set(SLOP_KEYWORDS[family].split())
    tokens = []
    line = 1
    for match in re.finditer(r"\n|[A-Za-z_]\w*|\d[\w.]*|([\"'`])\s*\1|\S", masked):
        symbol = match.group(0)
        if symbol == "\n":
            line += 1
            continue
        if symbol[0].isalpha() or symbol[0] == "_":
            symbol = symbol if symbol in keywords else "I"
        elif symbol[0].isdigit():
            symbol = "N"
        elif match.group(1):
            symbol = "S"
        tokens.append((symbol, line))
    return tokens


def mask_python(text: str) -> str:
    """Blank Python comments and string contents, keeping quotes and offsets."""
    import io as _io
    import tokenize

    chars = list(text)
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    with contextlib.suppress(tokenize.TokenError, SyntaxError, IndentationError):
        for token in tokenize.generate_tokens(_io.StringIO(text).readline):
            if token.type not in (tokenize.COMMENT, tokenize.STRING):
                continue
            start = offsets[token.start[0] - 1] + token.start[1]
            end = offsets[token.end[0] - 1] + token.end[1]
            if token.type == tokenize.COMMENT:
                blank(chars, start, end)
                continue
            quote = re.match(r"[A-Za-z]*('''|\"\"\"|'|\")", token.string)
            width = len(quote.group(0)) if quote else 1
            blank(chars, start + width, end - len(quote.group(1)) if quote else end - 1)
    return "".join(chars)


WINDOW_CACHE: dict[tuple[str, str], tuple[list[tuple[str, int]], list[int]]] = {}
CONTENT_MEMO: dict[tuple[str, str, bytes], Any] = {}
TOKEN_CODES: dict[str, int] = {}


def token_windows(path: str, text: str) -> tuple[list[tuple[str, int]], list[int]]:
    """Normalized tokens and rolling hashes of every 100-token window, cached."""
    import hashlib

    key = (path, hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest())
    if key in WINDOW_CACHE:
        return WINDOW_CACHE[key]
    modulus, base = (1 << 61) - 1, 1_000_003
    power = pow(base, CLONE_MIN_TOKENS - 1, modulus)
    tokens = normalized_tokens(path, text)
    hashes = []
    value = 0
    codes = [TOKEN_CODES.setdefault(token, len(TOKEN_CODES) + 1) for token, _ in tokens]
    for index, code in enumerate(codes):
        if index >= CLONE_MIN_TOKENS:
            value = (value - codes[index - CLONE_MIN_TOKENS] * power) % modulus
        value = (value * base + code) % modulus
        if index >= CLONE_MIN_TOKENS - 1:
            hashes.append(value)
    if len(WINDOW_CACHE) > 50_000:
        WINDOW_CACHE.clear()
    WINDOW_CACHE[key] = (tokens, hashes)
    return tokens, hashes


def _clone_runs(
    duplicates: list[list[tuple[str, int]]],
) -> tuple[list[tuple[str, int, int]], dict[tuple[str, int], int]]:
    covered_tokens: dict[str, set[int]] = {}
    for positions in duplicates:
        for path, index in positions:
            covered_tokens.setdefault(path, set()).update(
                range(index, index + CLONE_MIN_TOKENS)
            )
    run_of: dict[tuple[str, int], int] = {}
    runs: list[tuple[str, int, int]] = []
    for path, indexes in covered_tokens.items():
        for index in sorted(indexes):
            if (path, index - 1) in run_of:
                run = run_of[(path, index - 1)]
                runs[run] = (path, runs[run][1], index)
            else:
                run = len(runs)
                runs.append((path, index, index))
            run_of[(path, index)] = run
    return runs, run_of


def _group_clone_runs(
    runs: list[tuple[str, int, int]],
    run_of: dict[tuple[str, int], int],
    duplicates: list[list[tuple[str, int]]],
) -> dict[int, list[int]]:
    parent = list(range(len(runs)))

    def find(item: int) -> int:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for positions in duplicates:
        first = find(run_of[positions[0]])
        for position in positions[1:]:
            parent[find(run_of[position])] = first
    components: dict[int, list[int]] = {}
    for run in range(len(runs)):
        components.setdefault(find(run), []).append(run)
    return components


def _filter_indexed_focus(
    indexed: dict[str, tuple[list[tuple[str, int]], list[int]]],
    focus: set[str] | None,
) -> tuple[dict[str, tuple[list[tuple[str, int]], list[int]]], set[int]]:
    if focus is None:
        return indexed, set()
    wanted = {value for path in focus if path in indexed for value in indexed[path][1]}
    filtered = {
        path: item
        for path, item in indexed.items()
        if path in focus or not wanted.isdisjoint(item[1])
    }
    return filtered, wanted


def _index_clone_windows(
    files: dict[str, str], focus: set[str] | None
) -> tuple[dict[str, list[tuple[str, int]]], list[list[tuple[str, int]]]]:
    indexed, wanted = _filter_indexed_focus(
        {path: token_windows(path, text) for path, text in files.items()}, focus
    )
    streams = {path: tokens for path, (tokens, _) in indexed.items()}
    windows: dict[int, list[tuple[str, int]]] = {}
    for path, (_, hashes) in indexed.items():
        for index, value in enumerate(hashes):
            if focus is None or value in wanted:
                windows.setdefault(value, []).append((path, index))
    duplicates = [positions for positions in windows.values() if len(positions) > 1]
    return streams, duplicates


def _component_clone_lines(
    members: list[int],
    runs: list[tuple[str, int, int]],
    streams: dict[str, list[tuple[str, int]]],
    focus: set[str] | None,
) -> list[tuple[str, int, int]] | None:
    if len(members) < 2:
        return None
    lines = [
        (path, streams[path][first][1], streams[path][last][1])
        for run in members
        for path, first, last in (runs[run],)
    ]
    if all(end - start + 1 < CLONE_MIN_LINES for _, start, end in lines):
        return None
    if focus is not None and not any(path in focus for path, _, _ in lines):
        return None
    return lines


def _collect_clone_spans(
    components: dict[int, list[int]],
    runs: list[tuple[str, int, int]],
    streams: dict[str, list[tuple[str, int]]],
    focus: set[str] | None,
) -> tuple[dict[str, set[int]], list[list[tuple[str, int, int]]]]:
    covered: dict[str, set[int]] = {}
    spans = []
    for members in components.values():
        lines = _component_clone_lines(members, runs, streams, focus)
        if lines is None:
            continue
        for path, start, end in lines:
            covered.setdefault(path, set()).update(range(start, end + 1))
        spans.append(sorted(lines))
    return covered, sorted(spans)


def clone_lines(
    files: dict[str, str], *, focus: set[str] | None = None
) -> tuple[dict[str, set[int]], list[list[tuple[str, int, int]]]]:
    """Normalized-token clones of at least 100 tokens and 3 lines.

    Windows of 100 normalized tokens are rolling-hashed. With focus, only files
    sharing a window with a focus file are examined, and only groups with a
    focus member are kept. Returns the union of cloned lines per file and each
    group's member line spans.
    """
    streams, duplicates = _index_clone_windows(files, focus)
    # Tokens covered by a duplicated window form maximal runs per file; runs that
    # share a window are one clone group. A repetitive region that only matches
    # itself is a single run and is not a clone.
    runs, run_of = _clone_runs(duplicates)
    components = _group_clone_runs(runs, run_of, duplicates)
    return _collect_clone_spans(components, runs, streams, focus)


def content_memo(kind: str, path: str, text: str, compute: Any) -> Any:
    """Memoize per-file analysis by content; the daemon keeps this warm."""
    import hashlib

    key = (kind, path, hashlib.blake2b(text.encode("utf-8"), digest_size=16).digest())
    if key not in CONTENT_MEMO:
        if len(CONTENT_MEMO) > 50_000:
            CONTENT_MEMO.clear()
        CONTENT_MEMO[key] = compute()
    return CONTENT_MEMO[key]


def python_imports(path: str, text: str) -> list[tuple[int | None, str, list[str]]]:
    """(relative level or None for `import`, module, names) for each import."""

    def parse() -> list[tuple[int | None, str, list[str]]]:
        tree = None
        with contextlib.suppress(SyntaxError, ValueError):
            tree = ast.parse(text)
        if tree is None:
            return []
        found: list[tuple[int | None, str, list[str]]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.append((None, "", [alias.name for alias in node.names]))
            elif isinstance(node, ast.ImportFrom):
                aliases = [alias.name for alias in node.names]
                found.append((node.level, node.module or "", aliases))
        return found

    return content_memo("imports", path, text, parse)


def _resolved_python_import_names(
    package: str, level: int | None, base: str, aliases: list[str]
) -> list[str]:
    if level is None:
        return aliases
    if level:
        parts = package.split(".")[: len(package.split(".")) - level + 1]
        base = ".".join([*parts, base] if base else parts)
    return [base, *(f"{base}.{alias}" for alias in aliases)]


def python_import_graph(files: dict[str, str]) -> dict[str, set[str]]:
    modules = {
        Path(path)
        .with_suffix("")
        .as_posix()
        .replace("/", ".")
        .removesuffix(".__init__"): path
        for path in files
        if path.endswith(".py")
    }
    graph: dict[str, set[str]] = {}
    for module, path in modules.items():
        package = (
            module.rsplit(".", 1)[0] if not path.endswith("__init__.py") else module
        )
        edges = set()
        for level, base, aliases in python_imports(path, files[path]):
            for name in _resolved_python_import_names(package, level, base, aliases):
                if name in modules and modules[name] != path:
                    edges.add(modules[name])
        graph[path] = edges
    return graph


def javascript_import_graph(files: dict[str, str]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    suffixes = (
        "",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mts",
        ".mjs",
        "/index.ts",
        "/index.js",
    )
    for path, text in files.items():
        if LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower()) != "typescript":
            continue
        edges = set()
        for match in re.finditer(
            r"^\s*(?:import|export)(?!\s+type\b)[^;'\"]*?from\s*(['\"])(\.{1,2}/[^'\"]+)\1"
            r"|^\s*import\s*(['\"])(\.{1,2}/[^'\"]+)\3",
            text,
            re.M,
        ):
            specifier = match.group(2) or match.group(4)
            base = os.path.normpath(os.path.join(os.path.dirname(path), specifier))
            base = re.sub(r"\.(?:js|mjs|cjs)$", "", base)
            target = next(
                (base + suffix for suffix in suffixes if base + suffix in files), None
            )
            if target and target != path:
                edges.add(target)
        graph[path] = edges
    return graph


def _tarjan_step(
    graph: dict[str, set[str]],
    index: dict[str, int],
    low: dict[str, int],
    stack: list[str],
    on_stack: set[str],
    work: list[tuple[str, Any]],
    counter: int,
) -> tuple[bool, int]:
    node, edges = work[-1]
    for target in edges:
        if target not in index:
            index[target] = low[target] = counter
            stack.append(target)
            on_stack.add(target)
            work.append((target, iter(sorted(graph.get(target, ())))))
            return True, counter + 1
        if target in on_stack:
            low[node] = min(low[node], index[target])
    return False, counter


def import_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Strongly connected components with more than one module (Tarjan)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[list[str]] = []
    counter = 0
    for start in sorted(graph):
        if start in index:
            continue
        work = [(start, iter(sorted(graph.get(start, ()))))]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, _ = work[-1]
            advanced, counter = _tarjan_step(
                graph, index, low, stack, on_stack, work, counter
            )
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = _pop_scc(stack, on_stack, node)
                if len(component) > 1:
                    cycles.append(sorted(component))
    return sorted(cycles)


def _pop_scc(stack: list[str], on_stack: set[str], node: str) -> list[str]:
    component = []
    while True:
        item = stack.pop()
        on_stack.discard(item)
        component.append(item)
        if item == node:
            return component


def _python_verbose_assign_return(body: list[Any], flagged: set[int]) -> None:
    for first, second in zip(body, body[1:], strict=False):
        if (
            isinstance(first, ast.Assign)
            and len(first.targets) == 1
            and isinstance(first.targets[0], ast.Name)
            and isinstance(second, ast.Return)
            and isinstance(second.value, ast.Name)
            and second.value.id == first.targets[0].id
        ):
            flagged.update({first.lineno, second.lineno})


def _is_bool_return_if(node: ast.AST) -> bool:
    if not (isinstance(node, ast.If) and len(node.body) == 1 and len(node.orelse) == 1):
        return False
    return all(
        isinstance(item, ast.Return)
        and isinstance(item.value, ast.Constant)
        and isinstance(item.value.value, bool)
        for item in (node.body[0], node.orelse[0])
    )


def _is_bare_reraise_try(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Try)
        and bool(node.handlers)
        and not node.finalbody
        and not node.orelse
        and all(
            len(handler.body) == 1
            and isinstance(handler.body[0], ast.Raise)
            and handler.body[0].exc is None
            for handler in node.handlers
        )
    )


def _python_verbose_node(node: ast.AST, flagged: set[int]) -> None:
    if _is_bool_return_if(node) or _is_bare_reraise_try(node):
        flagged.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    if isinstance(node, ast.Compare) and any(
        isinstance(item, ast.Constant) and isinstance(item.value, bool)
        for item in node.comparators
    ):
        flagged.add(node.lineno)
    body = getattr(node, "body", None)
    if isinstance(body, list):
        _python_verbose_assign_return(body, flagged)


def _python_verbose_lines(text: str) -> set[int]:
    flagged: set[int] = set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return flagged
    for node in ast.walk(tree):
        _python_verbose_node(node, flagged)
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not (stripped.startswith("#") and len(stripped) > 2):
            continue
        try:
            code = ast.parse(stripped[1:].strip())
        except (SyntaxError, ValueError):
            continue
        if code.body and not isinstance(code.body[0], ast.Expr | ast.Pass):
            flagged.add(number)
    return flagged


def _typescript_verbose_lines(text: str) -> set[int]:
    flagged: set[int] = set()
    masked = mask_javascript(text)
    for match in re.finditer(
        r"\bif\s*\([^()]*\)\s*\{?\s*return\s+(true|false)\s*;?\s*\}?\s*else\s*\{?"
        r"\s*return\s+(true|false)\s*;?\s*\}?|[!=]==?\s*(?:true|false)\b",
        masked,
    ):
        first = masked.count("\n", 0, match.start()) + 1
        flagged.update(range(first, first + match.group(0).count("\n") + 1))
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") and re.search(
            r"[;{}]\s*$|^//\s*(?:const|let|return|if|await)\b", stripped
        ):
            flagged.add(number)
    return flagged


def verbose_lines(path: str, text: str) -> set[int]:
    """Lines matching handcrafted verbosity heuristics (for the verbosity ratio)."""
    language = LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower())
    if language == "python":
        return _python_verbose_lines(text)
    if language == "typescript":
        return _typescript_verbose_lines(text)
    return set()


def slop_saturate(value: float, saturation: float) -> float:
    return 100 * min(1.0, value / saturation)


def slop_count(count: float, scale: float) -> float:
    import math

    blend = math.log(1 + count / scale)
    return 100 * blend / (1 + blend)


def _nonempty_line_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0


def _slop_raw_metrics(
    production: dict[str, str],
    functions: list[FunctionMetric],
    eroded: list[FunctionMetric],
    covered: dict[str, set[int]],
    groups: list[list[tuple[str, int, int]]],
    graph: dict[str, set[str]],
    cycles: list[list[str]],
    approximate: set[str],
) -> dict[str, Any]:
    total_mass = sum(item.mass for item in functions)
    lines = sum(_nonempty_line_count(text) for text in production.values())
    cloned = sum(len(value) for value in covered.values())
    verbose_count = sum(
        len(verbose_lines(path, text) | covered.get(path, set()))
        for path, text in production.items()
    )
    return {
        "functions": len(functions),
        "eroded_functions": len(eroded),
        "eroded_share": _safe_ratio(sum(item.mass for item in eroded), total_mass),
        "duplication_density": _safe_ratio(cloned, lines),
        "clone_groups": len(groups),
        "cycle_density": _safe_ratio(sum(len(cycle) for cycle in cycles), len(graph)),
        "cycle_groups": len(cycles),
        "verbosity": _safe_ratio(verbose_count, lines),
        "lines": lines,
        "approximate_complexity": sorted(approximate),
        "languages": sorted({slop_language(path) for path in production}),
    }


def _slop_hotspots(eroded: list[FunctionMetric]) -> list[dict[str, Any]]:
    return [
        {
            "path": item.path,
            "function": item.name,
            "lines": [item.start, item.end],
            "complexity": item.complexity,
            "sloc": item.sloc,
            "nesting": item.nesting,
            "mass": round(item.mass, 1),
        }
        for item in sorted(eroded, key=lambda item: -item.mass)
    ]


def _slop_contributions(raw: dict[str, Any]) -> dict[str, float]:
    return {
        name: round(
            weight
            * (slop_saturate(raw[density], saturation) + slop_count(raw[count], scale))
            / 2,
            2,
        )
        for name, weight, density, saturation, count, scale in SLOP_DIMENSIONS
    }


def _slop_production_files(files: dict[str, str]) -> dict[str, str]:
    return {
        path: text
        for path, text in files.items()
        if slop_language(path) and slop_included(path) and not TEST_PATH_RE.search(path)
    }


def _slop_clone_groups_payload(
    groups: list[list[tuple[str, int, int]]],
) -> list[list[dict[str, Any]]]:
    return [
        [{"path": path, "lines": [start, end]} for path, start, end in group]
        for group in groups
    ]


def slop_measure(
    root: Path, files: dict[str, str], *, deadline: float | None = None
) -> dict[str, Any]:
    """Raw structural metrics and the 0-100 sloppiness index (lower is better)."""
    production = _slop_production_files(files)
    exact, approximate = exact_function_metrics(root, production, deadline=deadline)
    functions = [
        metric
        for path, text in production.items()
        for metric in function_metrics(path, text, exact.get(path))
    ]
    eroded = [item for item in functions if item.complexity > SLOP_COMPLEXITY]
    covered, groups = clone_lines(production)
    graph = {
        **python_import_graph(production),
        **javascript_import_graph(production),
        **elixir_import_graph(production),
    }
    cycles = import_cycles(graph)
    raw = _slop_raw_metrics(
        production, functions, eroded, covered, groups, graph, cycles, approximate
    )
    contributions = _slop_contributions(raw)
    return {
        "index": max(0, min(100, int(sum(contributions.values()) + 0.5))),
        "contributions": contributions,
        "metrics": raw,
        "hotspots": _slop_hotspots(eroded),
        "clone_groups": _slop_clone_groups_payload(groups),
        "import_cycles": cycles,
    }


SLOP_WRITE_BUDGET = 2 * 1024 * 1024


def slop_policy(config: dict[str, Any]) -> dict[str, Any]:
    policy = config.get("slop", {})
    if not isinstance(policy, dict) or policy.keys() - {
        "block",
        "max_index",
        "max_index_increase",
    }:
        raise ValueError(
            "slop must be an object with block, max_index, max_index_increase"
        )
    if not isinstance(policy.get("block", False), bool):
        raise ValueError("slop.block must be a boolean")
    for key in ("max_index", "max_index_increase"):
        if key in policy and (
            type(policy[key]) is not int or not 0 <= policy[key] <= 100
        ):
            raise ValueError(f"slop.{key} must be an integer from 0 to 100")
    return policy


SLOP_EXCLUDED_DIRECTORIES = {
    "vendor",
    "third_party",
    "third-party",
    "external",
    "generated",
    "dist",
    "build",
    "target",
    "coverage",
}


def slop_included(path: str) -> bool:
    """Vendored, generated, build-output and Loki-owned code is not project debt."""
    parts = Path(path).parts
    if any(path_matches(path, pattern) for pattern in PROTECTED_PATHS):
        return False
    return not SLOP_EXCLUDED_DIRECTORIES & set(parts[:-1]) and not re.search(
        r"\.(?:min|generated|pb|g)\.[\w]+$|_pb2\.py$", path
    )


def _is_repo_source(root: Path, name: str) -> bool:
    return bool(
        name
        and slop_language(name)
        and not SKIP_DIRECTORIES & set(Path(name).parts)
        and (root / name).is_file()
    )


def source_paths(root: Path) -> list[Path]:
    """Tracked and non-ignored untracked sources; every source outside Git."""
    try:
        listing = git_output(
            root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
        )
    except ValueError:
        return sorted(
            path
            for path in root.rglob("*")
            if path.is_file()
            and slop_language(path.name)
            and not SKIP_DIRECTORIES & set(path.relative_to(root).parts)
        )
    return sorted(
        root / name
        for raw in listing.split(b"\0")
        if _is_repo_source(root, name := os.fsdecode(raw))
    )


def repository_sources(root: Path, limit: int | None = None) -> dict[str, str]:
    """Readable source files by repository-relative path, within a byte budget."""
    files: dict[str, str] = {}
    total = 0
    for path in source_paths(root):
        try:
            size = path.stat().st_size
            if size > 1024 * 1024:
                continue
            total += size
            if limit is not None and total > limit:
                raise ValueError("repository exceeds the write-time slop budget")
            files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return files


def base_sources(root: Path, reference: str) -> dict[str, str]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="loki-slop-") as directory:
        base = Path(directory) / "base"
        commit = git_output(root, ["rev-parse", "--verify", f"{reference}^{{commit}}"])
        materialize_base(root, commit.decode("ascii").strip(), base)
        return repository_sources(base)


def slop_report_text(report: dict[str, Any], top: int) -> str:
    metrics = report["metrics"]
    lines = [
        f"Sloppiness index: {report['index']}/100 (lower is better; "
        "trellis 0.2.0-provisional weights)",
        f"  complexity-erosion {report['contributions']['complexity-erosion']:5.1f}  "
        f"eroded share {metrics['eroded_share']:.2f}, "
        f"{metrics['eroded_functions']} of {metrics['functions']} functions with "
        f"CC > {SLOP_COMPLEXITY}",
        f"  duplication        {report['contributions']['duplication']:5.1f}  "
        f"density {metrics['duplication_density']:.2f}, "
        f"{metrics['clone_groups']} clone groups",
        f"  import-cycle       {report['contributions']['import-cycle']:5.1f}  "
        f"density {metrics['cycle_density']:.2f}, {metrics['cycle_groups']} cycles",
        f"Verbosity {metrics['verbosity']:.2f} over {metrics['lines']} lines "
        "(reported, not scored)",
    ]
    if metrics["approximate_complexity"]:
        lines.append(
            "Complexity approximated structurally for: "
            + ", ".join(metrics["approximate_complexity"])
        )
    if {"go", "rust"} & set(metrics["languages"]):
        lines.append(
            "Import cycles: not measured for Go (rejected by the compiler) or Rust "
            "(module cycles are legal)"
        )
    for item in report["hotspots"][:top]:
        lines.append(
            f"hotspot {item['path']}:{item['lines'][0]} {item['function']} "
            f"CC {item['complexity']}, {item['sloc']} SLOC, mass {item['mass']}"
        )
    for group in report["clone_groups"][:top]:
        members = ", ".join(
            f"{m['path']}:{m['lines'][0]}-{m['lines'][1]}" for m in group
        )
        lines.append(f"clone {members}")
    for cycle in report["import_cycles"][:top]:
        lines.append("import cycle " + " -> ".join(cycle))
    return "\n".join(lines)


def _slop_policy_failures(
    policy: dict[str, Any], current: dict[str, Any], previous: dict[str, Any] | None
) -> list[str]:
    failures = []
    if "max_index" in policy and current["index"] > policy["max_index"]:
        failures.append(
            f"index {current['index']} exceeds max_index {policy['max_index']}"
        )
    if previous is not None and "max_index_increase" in policy:
        increase = current["index"] - previous["index"]
        if increase > policy["max_index_increase"]:
            failures.append(
                f"index rose by {increase}, above max_index_increase "
                f"{policy['max_index_increase']}"
            )
    return failures


def _print_slop_base_diff(
    base: str | None, previous: dict[str, Any], current: dict[str, Any]
) -> None:
    print(
        f"Base {base}: index {previous['index']} -> {current['index']} "
        f"({current['index'] - previous['index']:+d})"
    )
    known = {(item["path"], item["function"]) for item in previous["hotspots"]}
    for item in current["hotspots"]:
        if (item["path"], item["function"]) not in known:
            print(f"new hotspot {item['path']}:{item['lines'][0]} {item['function']}")


def slop_command(
    root: Path, config: dict[str, Any], base: str | None, as_json: bool, top: int
) -> int:
    policy = slop_policy(config)
    current = slop_measure(root, repository_sources(root))
    previous = slop_measure(root, base_sources(root, base)) if base else None
    failures = _slop_policy_failures(policy, current, previous)
    if as_json:
        print(
            json.dumps(
                {"current": current, "base": previous, "policy_failures": failures},
                indent=2,
            )
        )
        return int(bool(failures))
    print(slop_report_text(current, top))
    if previous is not None:
        _print_slop_base_diff(base, previous, current)
    for failure in failures:
        print(f"loki slop: {failure}")
    return int(bool(failures))


def changed_functions(
    old: list[FunctionMetric], new: list[FunctionMetric], before: str, after: str
) -> list[tuple[FunctionMetric, FunctionMetric | None]]:
    """Functions an edit added or changed, each with its committed counterpart.

    A function whose source is in the base under the same name is unchanged,
    wherever it moved, so namesakes (`__init__`, overrides in sibling classes)
    are never compared with each other. The rest pair by name in source order;
    when their counts differ, the most complex remaining namesake stands in.
    """

    def source(lines: list[str], item: FunctionMetric) -> str:
        return "\n".join(line.strip() for line in lines[item.start - 1 : item.end])

    old_lines, new_lines = before.splitlines(), after.splitlines()
    committed: dict[str, list[tuple[str, FunctionMetric]]] = {}
    for item in old:
        committed.setdefault(item.name, []).append((source(old_lines, item), item))
    changed: dict[str, list[FunctionMetric]] = {}
    for item in new:
        text = source(new_lines, item)
        namesakes = committed.get(item.name, [])
        same = next((entry for entry in namesakes if entry[0] == text), None)
        if same is None:
            changed.setdefault(item.name, []).append(item)
        else:
            namesakes.remove(same)
    pairs: list[tuple[FunctionMetric, FunctionMetric | None]] = []
    for name, items in changed.items():
        rest = [item for _, item in committed.get(name, [])]
        fallback = max(rest, key=lambda item: item.complexity, default=None)
        for index, item in enumerate(items):
            pairs.append((item, rest[index] if len(rest) == len(items) else fallback))
    return sorted(pairs, key=lambda pair: pair[0].start)


def _exact_written_metrics(
    root: Path,
    names: list[str],
    before: dict[str, str],
    after: dict[str, str],
    deadline: float | None,
) -> tuple[dict[str, list[FunctionMetric]], dict[str, list[FunctionMetric]]]:
    # One analyzer call covers both versions; BEAM-backed Elixir stays structural
    # at write time and exact in `loki slop` audits.
    cheap = {
        key: text
        for name in names
        if slop_language(name) in {"typescript", "go"}
        for key, text in (
            (f"after/{name}", after[name]),
            (f"before/{name}", before[name]),
        )
        if text
    }
    exact, _ = exact_function_metrics(root, cheap, deadline=deadline)
    return (
        {key[7:]: value for key, value in exact.items() if key.startswith("before/")},
        {key[6:]: value for key, value in exact.items() if key.startswith("after/")},
    )


def _written_complexity_notes(
    root: Path,
    names: list[str],
    before: dict[str, str],
    after: dict[str, str],
    deadline: float | None,
) -> list[str]:
    exact_before, exact_after = _exact_written_metrics(
        root, names, before, after, deadline
    )
    notes: list[str] = []
    for name in names:
        for item, prior in changed_functions(
            function_metrics(name, before[name], exact_before.get(name)),
            function_metrics(name, after[name], exact_after.get(name)),
            before[name],
            after[name],
        ):
            if item.complexity > SLOP_COMPLEXITY and (
                prior is None or item.complexity > prior.complexity
            ):
                change = f"{prior.complexity} -> " if prior is not None else ""
                notes.append(
                    f"{name}:{item.start}: loki/slop-complexity: {item.name} cyclomatic "
                    f"complexity {change}{item.complexity} (> {SLOP_COMPLEXITY}); "
                    "split it into smaller functions"
                )
    return notes


def _format_clone_group_note(group: list[tuple[str, int, int]], focus: set[str]) -> str:
    here = next((member for member in group if member[0] in focus), group[0])
    others = ", ".join(
        f"{path}:{start}-{end}"
        for path, start, end in group
        if (path, start, end) != here
    )
    return (
        f"{here[0]}:{here[1]}: loki/slop-duplication: lines {here[1]}-{here[2]} "
        f"duplicate {others}; reuse or extract the shared code"
    )


def _written_clone_notes(
    repository: dict[str, str], before: dict[str, str], focus: set[str]
) -> list[str]:
    _, groups_after = clone_lines(repository, focus=focus)
    _, groups_before = clone_lines({**repository, **before}, focus=focus)
    if len(groups_after) <= len(groups_before):
        return []
    seen = {tuple(sorted(path for path, _, _ in group)) for group in groups_before}
    return [
        _format_clone_group_note(group, focus)
        for group in groups_after
        if tuple(sorted(path for path, _, _ in group)) not in seen
    ]


def _written_cycle_notes(
    repository: dict[str, str], before: dict[str, str], focus: set[str]
) -> list[str]:
    old_graph = {
        **python_import_graph({**repository, **before}),
        **javascript_import_graph({**repository, **before}),
    }
    new_graph = {
        **python_import_graph(repository),
        **javascript_import_graph(repository),
    }
    old_cycles = {tuple(cycle) for cycle in import_cycles(old_graph)}
    return [
        f"{next(iter(focus & set(cycle)))}: loki/slop-import-cycle: import cycle "
        + " -> ".join(cycle)
        for cycle in import_cycles(new_graph)
        if tuple(cycle) not in old_cycles and focus & set(cycle)
    ]


def written_slop(
    root: Path, targets: list[Path], *, deadline: float | None
) -> list[str]:
    """Hotspots, clones and cycles an edit introduces, against committed text."""
    names = [
        path.relative_to(root).as_posix()
        for path in targets
        if path.is_file() and slop_language(path.name)
    ]
    if not names:
        return []
    after = {name: (root / name).read_text(encoding="utf-8") for name in names}
    before = {name: head_text(root, name, deadline=deadline) for name in names}
    notes = _written_complexity_notes(root, names, before, after, deadline)
    try:
        # A warm daemon cache makes larger repositories affordable.
        budget = SLOP_WRITE_BUDGET * (16 if WINDOW_CACHE else 1)
        repository = repository_sources(root, limit=budget)
    except ValueError:
        return notes
    focus = set(names)
    notes.extend(_written_clone_notes(repository, before, focus))
    notes.extend(_written_cycle_notes(repository, before, focus))
    return notes[:MAX_VIOLATIONS]


def ruff_command(root: Path) -> list[str] | None:
    """Ruff from the project's .venv or venv, PATH, then the project's `-m ruff`.

    Never installs anything: no network, no uvx.
    """
    for prefix in (".venv", "venv"):
        if (local := root / prefix / "bin/ruff").is_file():
            return [str(local)]
    if shutil.which("ruff"):
        return ["ruff"]
    with contextlib.suppress(ValueError):
        if "ruff" not in resolve_imports(root, ["ruff"]):
            return [str(project_python(root)), "-m", "ruff"]
    return None


def missing_tool(language: str, root: Path) -> str | None:
    checks = {
        "python": lambda: None if ruff_command(root) else "ruff",
        "typescript": lambda: None if resolve_tool(root, "oxlint") else "oxlint",
        "go": lambda: (
            "gofmt"
            if not shutil.which("gofmt")
            else (None if shutil.which("go") else "go")
        ),
        "rust": lambda: None if shutil.which("rustfmt") else "rustfmt",
        "elixir": lambda: None if shutil.which("mix") else "mix",
    }
    check = checks.get(language)
    return check() if check is not None else "toolchain"


MYPY_LINE_RE = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+): error: (?P<message>.*?)"
    r"(?:  \[(?P<code>[\w-]+)\])?$"
)
RUST_LINTS = ("clippy::todo", "clippy::unimplemented")
RUST_LINTS += ("clippy::unwrap_used", "clippy::expect_used")


def head_text(root: Path, relative: str, *, deadline: float | None = None) -> str:
    """Committed HEAD text, or empty text for a file absent from HEAD."""
    return revision_text(root, "HEAD", relative, deadline=deadline)


def revision_text(
    root: Path, revision: str, relative: str, *, deadline: float | None = None
) -> str:
    """Text at `revision`, or empty text for a file absent there."""
    row = git_output(
        root, ["ls-tree", "-z", revision, "--", relative], deadline=deadline
    )
    if not row:
        return ""
    _, kind, oid = row.split(b"\t", 1)[0].decode("ascii").split()
    if kind != "blob":
        return ""
    blob = git_blobs(root, [oid], deadline=deadline)[oid]
    return blob.decode("utf-8", errors="replace")


def written_content_violations(
    path: Path, root: Path, relative: str, *, fallback: bool, deadline: float | None
) -> list[str]:
    change = None
    with contextlib.suppress(OSError, UnicodeDecodeError, ValueError):
        if path.stat().st_size > 4 * 1024 * 1024:
            return []
        before = head_text(root, relative, deadline=deadline)
        change = (relative, before, path.read_text(encoding="utf-8"))
    if change is None:
        return []
    violations = content_rule_violations([change])
    if fallback:
        violations.extend(content_rule_violations([change], fallback=True))
    return violations


def line_text(content: str, number: int) -> str:
    lines = content.splitlines()
    return lines[number - 1].strip() if 0 < number <= len(lines) else ""


def hygiene_policy(config: dict[str, Any]) -> str:
    level = config.get("hygiene", "on")
    if level not in ("off", "on", "all"):
        raise ValueError("hygiene must be 'off', 'on', or 'all'")
    return level


def hygiene_level(config: dict[str, Any], env: str | None = None) -> str:
    """`LOKI_HYGIENE`, else the `hygiene` policy, else on."""
    named = (env if env is not None else os.environ.get("LOKI_HYGIENE") or "").strip()
    named = named.lower()
    if named == "all":
        return "all"
    if named in {"off", "0", "false", "no", "none"}:
        return "off"
    if named in {"on", "1", "true", "yes"}:
        return "on"
    return hygiene_policy(config)


@dataclass(frozen=True)
class HygieneSquiggle:
    line: int
    kind: str
    message: str


# dense_line, deep_nesting and cramped_layout fire on formatter-clean code and
# poor_naming on long test names; level `all` adds them.
HYGIENE_DEFAULT_KINDS = frozenset(
    {"swallowed_error", "noisy_comment", "duplicate_block", "special_casing"}
)
NITS_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs"})
HYGIENE_SUFFIXES = NITS_SUFFIXES | {
    ".go",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".zig",
    ".java",
    ".cs",
    ".lua",
}
NITS_COMMIT = "67c94b9f76054375f37b2df8e624a2f4d48ec0cc"
NITS_REQUIREMENT = f"git+https://github.com/jkomyno/nits@{NITS_COMMIT}"
# nits enables a rule by default at this precision; below it only `all` reports.
NITS_MIN_PRECISION = 0.80
HYGIENE_MAX_NOTES = 10
HYGIENE_SNIPPET_CHARS = 80
HYGIENE_MAX_CHANGED_FILES = 40
HYGIENE_SECONDS = 20
# Drivers exit 3 when their import is missing and 4 when the tool itself failed.
HYGIENE_FAILED = 4

HYGIENE_DRIVER = r"""
import io, json, sys, types
try:
    import numpy
except ImportError:
    raise SystemExit(3)
try:
    request = json.load(sys.stdin)
    module = types.ModuleType("codehygiene")
    sys.modules["codehygiene"] = module
    exec(compile(request["source"], "codehygiene/__init__.py", "exec"), module.__dict__)
    with numpy.load(io.BytesIO(bytes.fromhex(request["weights"]))) as archive:
        weights = module.unpack_ternary_archive(archive["trits"], archive["vecs"], str(archive["meta"].item()))
    found = [
        [[s.line, s.kind, s.message] for s in module.score(text, weights=weights).squiggles]
        for text in request["texts"]
    ]
except Exception as error:
    sys.stderr.write(f"{type(error).__name__}: {error}\n")
    raise SystemExit(4)
json.dump(found, sys.stdout)
"""

NITS_DRIVER = r"""
import json, sys
try:
    import nits
except ImportError:
    raise SystemExit(3)
try:
    request = json.load(sys.stdin)
    everything = request["all"]
    floor = None if everything else request["min_precision"]
    found = []
    for name, text in request["files"]:
        lang = nits.lang_for_path(name)
        findings = nits.check_source(text, lang=lang, include_opt_in=everything, min_precision=floor) if lang else []
        found.append([[f.line, f.rule, f"p{nits.precision_of(f.rule, lang):.2f} {f.message}"] for f in findings])
except Exception as error:
    sys.stderr.write(f"{type(error).__name__}: {error}\n")
    raise SystemExit(4)
json.dump(found, sys.stdout)
"""


def _launchers(python: str | None, requirement: str) -> list[list[str]]:
    found = [[python]] if python else []
    if [sys.executable] not in found:
        found.append([sys.executable])
    if uv := shutil.which("uv"):
        found.append(
            [
                uv,
                "run",
                "-q",
                "--offline",
                "--no-project",
                "--with",
                requirement,
                "python",
            ]
        )
    return found


HYGIENE_SERVER_DRIVER = r"""
import io, json, sys, types
try:
    import numpy
except ImportError:
    raise SystemExit(3)
init = json.loads(sys.stdin.readline())
module = types.ModuleType("codehygiene")
sys.modules["codehygiene"] = module
exec(compile(init["args"]["source"], "codehygiene/__init__.py", "exec"), module.__dict__)
with numpy.load(io.BytesIO(bytes.fromhex(init["args"]["weights"]))) as archive:
    weights = module.unpack_ternary_archive(archive["trits"], archive["vecs"], str(archive["meta"].item()))
sys.stdout.write(json.dumps({"id": init["id"], "result": True}) + "\n")
sys.stdout.flush()
for raw in sys.stdin:
    if not raw.strip():
        continue
    request = json.loads(raw)
    try:
        found = [
            [[s.line, s.kind, s.message] for s in module.score(text, weights=weights).squiggles]
            for text in request["args"]
        ]
        reply = {"id": request["id"], "result": found}
    except Exception as error:
        reply = {"id": request["id"], "error": f"{type(error).__name__}: {error}"}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
"""

NITS_SERVER_DRIVER = r"""
import json, sys
try:
    import nits
except ImportError:
    raise SystemExit(3)
for raw in sys.stdin:
    if not raw.strip():
        continue
    request = json.loads(raw)
    args = request["args"]
    if args == "ping":
        sys.stdout.write(json.dumps({"id": request["id"], "result": True}) + "\n")
        sys.stdout.flush()
        continue
    try:
        everything = args["all"]
        floor = None if everything else args["min_precision"]
        found = []
        for name, text in args["files"]:
            lang = nits.lang_for_path(name)
            findings = nits.check_source(text, lang=lang, include_opt_in=everything, min_precision=floor) if lang else []
            found.append([[f.line, f.rule, f"p{nits.precision_of(f.rule, lang):.2f} {f.message}"] for f in findings])
        reply = {"id": request["id"], "result": found}
    except Exception as error:
        reply = {"id": request["id"], "error": f"{type(error).__name__}: {error}"}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
"""


def hygiene_env() -> dict[str, str]:
    """Single-threaded BLAS environment so hygiene checks run beside session work."""
    return {**os.environ, "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1"}


def parse_hygiene_reply(reply: Any) -> list[list[HygieneSquiggle]]:
    return [
        [
            HygieneSquiggle(int(line), str(kind), str(message))
            for line, kind, message in file
        ]
        for file in reply
    ]


def hygiene_launchers(python: str | None = None) -> list[list[str]]:
    """The given Python, Loki's, then uv's with NumPy from its cache."""
    return _launchers(python, "numpy")


def nits_launchers(python: str | None = None) -> list[list[str]]:
    """The given Python, Loki's, then uv's with pinned nits from its cache."""
    return _launchers(python, NITS_REQUIREMENT)


def drive_hygiene_tool(
    launchers: list[list[str]],
    driver: str,
    request_payload: dict[str, Any],
    *,
    deadline: float | None,
    missing: str,
) -> tuple[list[list[HygieneSquiggle]] | None, str | None]:
    """Runs `driver` in the first launcher whose Python has its import."""
    request = json.dumps(request_payload).encode("utf-8")
    env = hygiene_env()
    for launcher in launchers:
        try:
            result = subprocess.run(
                [*launcher, "-I", "-c", driver],
                cwd=tempfile.gettempdir(),
                input=request,
                capture_output=True,
                env=env,
                timeout=command_timeout(deadline),
                check=False,
            )
        except (subprocess.TimeoutExpired, ValueError):
            return None, "timed out"
        except OSError:
            continue
        if result.returncode == 0:
            try:
                return parse_hygiene_reply(json.loads(result.stdout)), None
            except (ValueError, TypeError):
                return None, "unreadable reply"
        if result.returncode == HYGIENE_FAILED:
            lines = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
            return None, (lines[-1] if lines else "failed")[:200]
    return None, missing


def _query_warm_hygiene(
    name: str, payload: Any, deadline: float | None
) -> tuple[list[list[HygieneSquiggle]] | None, str | None]:
    worker = HYGIENE_WORKERS.get(name)
    if worker is None:
        return None, "worker not warmed"
    try:
        return (
            parse_hygiene_reply(
                worker.request(
                    payload, deadline, error_prefix=f"{name}: worker unavailable"
                )
            ),
            None,
        )
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
        return None, str(error)


def vendored_codehygiene_payload() -> tuple[dict[str, str] | None, str | None]:
    vendored = SOURCE_ROOT / "vendor" / "codehygiene"
    try:
        return (
            {
                "source": (vendored / "__init__.py").read_text(encoding="utf-8"),
                "weights": (vendored / "weights.npz").read_bytes().hex(),
            },
            None,
        )
    except OSError:
        return None, "vendored codehygiene model is missing"


def hygiene_score(
    texts: list[str],
    *,
    deadline: float | None = None,
    launchers: list[list[str]] | None = None,
    python: str | None = None,
) -> tuple[list[list[HygieneSquiggle]] | None, str | None]:
    """The vendored codehygiene model's squiggles for each text."""
    if launchers is None and python is None:
        warm, _ = _query_warm_hygiene("hygiene", texts, deadline)
        if warm is not None:
            return warm, None
    payload, missing_error = vendored_codehygiene_payload()
    if payload is None:
        return None, missing_error
    return drive_hygiene_tool(
        hygiene_launchers(python) if launchers is None else launchers,
        HYGIENE_DRIVER,
        {**payload, "texts": texts},
        deadline=deadline,
        missing="needs NumPy, which neither Loki's Python nor uv's cache has "
        "(`uv run --with numpy python -c pass` fetches it once)",
    )


def nits_score(
    files: list[tuple[str, str]],
    *,
    all_rules: bool = False,
    deadline: float | None = None,
    launchers: list[list[str]] | None = None,
    python: str | None = None,
) -> tuple[list[list[HygieneSquiggle]] | None, str | None]:
    """nits' findings for each `(name, text)`."""
    payload = {"files": files, "all": all_rules, "min_precision": NITS_MIN_PRECISION}
    if launchers is None and python is None:
        warm, _ = _query_warm_hygiene("nits", payload, deadline)
        if warm is not None:
            return warm, None
    return drive_hygiene_tool(
        nits_launchers(python) if launchers is None else launchers,
        NITS_DRIVER,
        payload,
        deadline=deadline,
        missing="nits is in neither Loki's Python nor uv's cache "
        f"(`uv run --no-project --with {NITS_REQUIREMENT} python -c pass` fetches it once)",
    )


def added_line_numbers(before: str, after: str) -> set[int]:
    """The 1-based lines of `after` that are not in `before`."""
    matcher = difflib.SequenceMatcher(
        None, before.splitlines(), after.splitlines(), autojunk=False
    )
    return {
        line
        for tag, _, _, j1, j2 in matcher.get_opcodes()
        if tag != "equal"
        for line in range(j1 + 1, j2 + 1)
    }


def _format_hygiene_note(
    name: str, after: str, tool: str, item: HygieneSquiggle
) -> str:
    snippet = line_text(after, item.line)[:HYGIENE_SNIPPET_CHARS]
    kind = item.kind.replace("_", "-")
    return f"{name}:{item.line}: loki/{tool}-{kind}: {item.message}: `{snippet}`"


def _include_model_squiggle(
    item: HygieneSquiggle,
    added: set[int],
    seen: set[tuple[int, str]],
    level: str,
) -> bool:
    return (
        item.line in added
        and (level == "all" or item.kind in HYGIENE_DEFAULT_KINDS)
        and (item.line, item.kind) not in seen
    )


def merge_hygiene_notes(
    name: str,
    before: str,
    after: str,
    model: list[HygieneSquiggle],
    nits: list[HygieneSquiggle],
    level: str,
) -> list[str]:
    """nits findings on added lines, then model squiggles nits did not repeat."""
    if level == "off":
        return []
    added = added_line_numbers(before, after)
    kept = [item for item in nits if item.line in added]
    seen = {(item.line, item.kind) for item in kept}
    model_kept = [
        item for item in model if _include_model_squiggle(item, added, seen, level)
    ]
    return [_format_hygiene_note(name, after, "nits", item) for item in kept] + [
        _format_hygiene_note(name, after, "hygiene", item) for item in model_kept
    ]


def hygiene_checked(name: str) -> bool:
    return Path(name).suffix.lower() in HYGIENE_SUFFIXES and slop_included(name)


def nits_reads(name: str) -> bool:
    return Path(name).suffix.lower() in NITS_SUFFIXES


def _read_hygiene_sources(root: Path, files: list[str]) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    for name in filter(hygiene_checked, files):
        with contextlib.suppress(OSError, UnicodeDecodeError):
            sources.append((name, (root / name).read_text(encoding="utf-8")))
    return sources


def _collect_hygiene_notes(
    root: Path,
    base: str,
    level: str,
    sources: list[tuple[str, str]],
    scored: list[list[HygieneSquiggle]],
    parsed: list[list[HygieneSquiggle]],
    deadline: float,
    gaps: list[str],
) -> list[str]:
    found: list[str] = []
    for (name, after), model, nits in zip(sources, scored, parsed, strict=True):
        if not model and not nits:
            continue
        try:
            before = revision_text(root, base, name, deadline=deadline)
        except ValueError as error:
            found.clear()
            gaps.append(f"NOT CHECKED hygiene: {error}")
            break
        found.extend(merge_hygiene_notes(name, before, after, model, nits, level))
    if len(found) > HYGIENE_MAX_NOTES:
        more = len(found) - HYGIENE_MAX_NOTES
        found = [*found[:HYGIENE_MAX_NOTES], f"... {more} more hygiene notes"]
    return found


def hygiene_against(
    root: Path,
    files: list[str],
    base: str,
    level: str,
    *,
    deadline: float | None = None,
    python: str | None = None,
    model_launchers: list[list[str]] | None = None,
    nits_runner: list[list[str]] | None = None,
) -> list[str]:
    """Hygiene advisories for the lines `files` add against `base`, with one
    `NOT CHECKED <tool>` line per tool that could not run."""
    if level == "off":
        return []
    sources = _read_hygiene_sources(root, files)
    if not sources:
        return []
    if deadline is None:
        deadline = time.monotonic() + HYGIENE_SECONDS
    gaps: list[str] = []
    empty: list[list[HygieneSquiggle]] = [[] for _ in sources]

    def settle(
        tool: str, scored: tuple[Any, str | None]
    ) -> list[list[HygieneSquiggle]]:
        if scored[0] is None:
            gaps.append(f"NOT CHECKED {tool}: {scored[1]}")
            return empty
        return scored[0]

    # nits answers in a fraction of a second; the model may take the deadline.
    parsed = empty
    if any(nits_reads(name) for name, _ in sources):
        parsed = settle(
            "nits",
            nits_score(
                sources,
                all_rules=level == "all",
                deadline=deadline,
                launchers=nits_runner,
                python=python,
            ),
        )
    scored = settle(
        "hygiene",
        hygiene_score(
            [text for _, text in sources],
            deadline=deadline,
            launchers=model_launchers,
            python=python,
        ),
    )
    found = _collect_hygiene_notes(
        root, base, level, sources, scored, parsed, deadline, gaps
    )
    return found + gaps


def written_hygiene(
    root: Path,
    targets: list[Path],
    level: str,
    *,
    deadline: float | None = None,
    python: str | None = None,
) -> list[str]:
    """Hygiene advisories for written files against HEAD."""
    names = [path.relative_to(root).as_posix() for path in targets]
    return hygiene_against(root, names, "HEAD", level, deadline=deadline, python=python)


def changed_hygiene(
    root: Path,
    base: str,
    level: str,
    *,
    deadline: float | None = None,
    python: str | None = None,
) -> list[str]:
    """Hygiene advisories for every line the working tree adds against `base`."""
    if level == "off":
        return []
    listed = git_output(
        root,
        ["diff", "--name-only", "-z", "--diff-filter=AM", base, "--"],
        deadline=deadline,
    )
    untracked = git_output(
        root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        deadline=deadline,
    )
    names = sorted(
        {
            name
            for name in (listed + untracked)
            .decode("utf-8", errors="replace")
            .split("\0")
            if name
        }
    )
    return hygiene_against(
        root,
        names[:HYGIENE_MAX_CHANGED_FILES],
        base,
        level,
        deadline=deadline,
        python=python,
    )


def annotated_python(text: str) -> bool:
    """Whether mypy's default mode would check more than module-level code."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.returns is not None
            or any(
                argument.annotation is not None
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            )
        ):
            return True
    return False


def possibly_existing(keys: Iterable[tuple], texts: dict[str, str]) -> bool:
    """Whether any finding's source line also appears in its committed text.

    Fingerprints include the line text, so a finding on a line absent from the
    base cannot be old debt; only otherwise is a base analysis run needed.
    """
    lines: dict[str, set[str]] = {}
    for key in keys:
        path, text = key[0], key[-1]
        if not text:
            return True
        if path not in lines:
            lines[path] = {line.strip() for line in texts.get(path, "").splitlines()}
        if text in lines[path]:
            return True
    return False


def mypy_binary(root: Path) -> str | None:
    for prefix in (".venv", "venv"):
        if (local := root / prefix / "bin/mypy").is_file():
            return str(local)
    return shutil.which("mypy")


def mypy_state(root: Path) -> Path:
    import hashlib

    identity = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:16]
    state = Path.home() / ".cache/loki/mypy" / identity
    state.mkdir(parents=True, exist_ok=True)
    config = state / "mypy.ini"
    if not config.is_file():
        config.write_text("[mypy]\n", encoding="utf-8")
    return state


def mypy_flags(state: Path, *, daemon: bool = False) -> list[str]:
    """Fixed flags: the project cannot weaken this check from the working tree."""
    return [
        "--config-file",
        str(state / "mypy.ini"),
        "--cache-dir",
        str(state / "cache"),
        "--no-error-summary",
        "--show-error-codes",
        "--no-color-output",
        "--hide-error-context",
        "--no-pretty",
        "--ignore-missing-imports",
        # dmypy cannot follow imports silently; its extra reports are filtered.
        f"--follow-imports={'normal' if daemon else 'silent'}",
        "--explicit-package-bases",
    ]


def mypy_run(
    root: Path,
    paths: list[str],
    *,
    deadline: float | None,
    shadows: list[str] | None = None,
) -> str:
    """mypy output for paths: the warm daemon when available, else a cold run."""
    if MYPY_DAEMON is not None and not shadows:
        command = [MYPY_DAEMON[0], "--status-file", str(MYPY_DAEMON[1]), "check"]
        result = subprocess.run(
            [*command, *paths],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout(deadline),
            check=False,
        )
        if result.returncode in (0, 1):
            return result.stdout
    mypy = mypy_binary(root)
    if mypy is None:
        raise ValueError("mypy unavailable")
    result = subprocess.run(
        [mypy, *mypy_flags(mypy_state(root)), *(shadows or []), *paths],
        cwd=root,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    if result.returncode not in (0, 1):
        reason = (result.stderr or result.stdout).strip()
        raise ValueError(reason or f"mypy exited {result.returncode}")
    return result.stdout


def mypy_errors(
    output: str, contents: dict[str, str]
) -> tuple[Counter[tuple], dict[tuple, int]]:
    found: Counter[tuple] = Counter()
    lines: dict[tuple, int] = {}
    for line in output.splitlines():
        if (match := MYPY_LINE_RE.match(line)) and match["path"] in contents:
            number = int(match["line"])
            key = (
                match["path"],
                match["code"] or "misc",
                match["message"],
                line_text(contents[match["path"]], number),
            )
            found[key] += 1
            lines.setdefault(key, number)
    return found, lines


def _mypy_base_errors(
    root: Path, paths: list[str], before: dict[str, str], deadline: float | None
) -> Counter[tuple]:
    with tempfile.TemporaryDirectory(prefix="loki-mypy-") as directory:
        shadows = []
        for index, name in enumerate(paths):
            shadow = Path(directory) / f"{index}.py"
            shadow.write_text(before[name], encoding="utf-8")
            shadows.extend(["--shadow-file", name, str(shadow)])
        output = mypy_run(root, paths, deadline=deadline, shadows=shadows)
        return mypy_errors(output, before)[0]


def mypy_violations(
    root: Path, paths: list[str], *, deadline: float | None = None
) -> list[str]:
    """Net-new mypy errors in written files, against their committed text."""
    if not paths or mypy_binary(root) is None:
        return []
    after = {name: (root / name).read_text(encoding="utf-8") for name in paths}
    # Unannotated code is mostly skipped by mypy's defaults; avoid a cold start.
    if not any(annotated_python(text) for text in after.values()):
        return []
    current, numbers = mypy_errors(mypy_run(root, paths, deadline=deadline), after)
    if not current:
        return []
    before = {name: head_text(root, name, deadline=deadline) for name in paths}
    previous = (
        _mypy_base_errors(root, paths, before, deadline)
        if possibly_existing(current, before)
        else Counter()
    )
    violations = []
    for key, count in (current - previous).items():
        name, code, message, _ = key
        evidence_finding(f"mypy:{code}", name)
        violations.extend([f"{name}:{numbers[key]}: mypy[{code}]: {message}"] * count)
    return violations[:MAX_VIOLATIONS]


def golangci_violations(
    root: Path, package: str, *, deadline: float | None = None
) -> list[str]:
    """Issues golangci-lint attributes to lines changed since HEAD."""
    binary = shutil.which("golangci-lint")
    if not binary:
        return []
    result = subprocess.run(
        [
            binary,
            "run",
            "--new-from-rev=HEAD",
            "--output.text.path=stdout",
            "--output.text.colors=false",
            "--output.text.print-issued-lines=false",
            "--show-stats=false",
            package,
        ],
        cwd=root,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    if result.returncode == 0:
        return []
    issues = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 1 or not issues:
        reason = (result.stderr or result.stdout).strip()
        raise ValueError(reason or f"golangci-lint exited {result.returncode}")
    evidence_finding("golangci-lint")
    return [f"golangci-lint: {issue}" for issue in issues][:MAX_VIOLATIONS]


def cargo_project(path: Path, root: Path) -> Path | None:
    project = path.parent.resolve()
    while project.is_relative_to(root.resolve()):
        if (project / "Cargo.toml").is_file():
            return project
        if project == root.resolve():
            break
        project = project.parent
    return None


def _cargo_edition_entry(directory: Path, inherit: bool) -> Any:
    data: dict[str, Any] = {}
    with contextlib.suppress(OSError, tomllib.TOMLDecodeError):
        data = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    table = (
        (data.get("workspace") or {}).get("package") if inherit else data.get("package")
    )
    return table.get("edition") if isinstance(table, dict) else None


def cargo_edition(crate: Path | None, root: Path) -> str | None:
    """The crate's Rust edition from Cargo.toml, following `edition.workspace = true` up to the workspace."""
    if crate is None:
        return None
    inherit = False
    directory = crate.resolve()
    while directory.is_relative_to(root.resolve()):
        edition = _cargo_edition_entry(directory, inherit)
        if isinstance(edition, str):
            return edition
        if isinstance(edition, dict) and edition.get("workspace") is True:
            inherit = True
        if directory == root.resolve():
            break
        directory = directory.parent
    return None


def clippy_command(target: Path) -> list[str]:
    command = ["cargo", "clippy", "--offline", "--all-targets"]
    command += ["--message-format=json", "--target-dir", str(target), "--"]
    for lint in RUST_LINTS:
        command.extend(["-W", lint])
    return command


def _clippy_message(line: str) -> dict[str, Any] | None:
    item = None
    with contextlib.suppress(ValueError):
        item = json.loads(line)
    if not isinstance(item, dict) or item.get("reason") != "compiler-message":
        return None
    message = item.get("message")
    if not isinstance(message, dict) or message.get("level") not in (
        "error",
        "warning",
    ):
        return None
    return message


def _parse_clippy_line(
    line: str, crate: Path
) -> tuple[tuple[str, str, str, str], int] | None:
    message = _clippy_message(line)
    if message is None:
        return None
    span = next(
        (span for span in message.get("spans", []) if span.get("is_primary")), None
    )
    if span is None:
        return None
    source = (crate / span["file_name"]).resolve()
    if not source.is_relative_to(crate.resolve()):
        return None
    relative = source.relative_to(crate.resolve()).as_posix()
    text = line_text(source.read_text(encoding="utf-8"), span["line_start"])
    code = (message.get("code") or {}).get("code") or message["level"]
    return (relative, code, message["message"], text), span["line_start"]


def _raise_clippy_failure(result: subprocess.CompletedProcess[str]) -> None:
    stderr = result.stderr.strip()
    if "--offline was specified" in stderr or "no matching package named" in stderr:
        raise ValueError(
            "cargo clippy needs dependencies that are not downloaded yet; "
            "run `cargo fetch` once to check this crate"
        )
    if "either src/lib.rs, src/main.rs, a [lib] section" in stderr:
        raise ValueError("the crate has no library or binary target yet")
    reason = stderr.splitlines()[-1:] or [f"exit {result.returncode}"]
    raise ValueError(f"cargo clippy failed: {reason[0]}")


def clippy_diagnostics(
    crate: Path, target: Path, *, deadline: float | None
) -> list[tuple[tuple[str, str, str, str], int]]:
    """Clippy/rustc warnings and errors: (file, code, message, line text), line."""
    result = subprocess.run(
        clippy_command(target),
        cwd=crate,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    found = [
        entry
        for line in result.stdout.splitlines()
        if (entry := _parse_clippy_line(line, crate)) is not None
    ]
    if result.returncode and not found:
        _raise_clippy_failure(result)
    return found


def clippy_violations(
    path: Path, root: Path, *, deadline: float | None = None
) -> list[str]:
    """Net-new Clippy and compiler diagnostics for the crate containing path."""
    crate = cargo_project(path, root)
    if crate is None or not shutil.which("cargo"):
        return []
    target = crate / "target"
    current = clippy_diagnostics(crate, target, deadline=deadline)
    if not current:
        return []
    prefix = crate.resolve().relative_to(root.resolve())
    texts = {
        key[0]: head_text(root, (prefix / key[0]).as_posix(), deadline=deadline)
        for key, _ in current
    }
    previous: list[tuple[tuple[str, str, str, str], int]] = []
    if possibly_existing([key for key, _ in current], texts):
        previous = clippy_base(root, prefix, target, deadline=deadline)
    # Line numbers shift between snapshots; match on the line's text instead.
    remaining = Counter(key for key, _ in previous)
    violations = []
    for key, line in current:
        if remaining[key]:
            remaining[key] -= 1
            continue
        relative, code, message, _ = key
        name = (prefix / relative).as_posix()
        evidence_finding(f"clippy:{code}", name)
        violations.append(f"{name}:{line}: {code}: {message}")
    return violations[:MAX_VIOLATIONS]


def clippy_base(
    root: Path, prefix: Path, target: Path, *, deadline: float | None
) -> list[tuple[tuple[str, str, str, str], int]]:
    """Diagnostics for the committed crate, built in a materialized snapshot."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="loki-clippy-") as directory:
        base = Path(directory) / "base"
        commit = git_output(
            root, ["rev-parse", "--verify", "HEAD^{commit}"], deadline=deadline
        )
        materialize_base(root, commit.decode("ascii").strip(), base, deadline=deadline)
        return (
            clippy_diagnostics(base / prefix, target, deadline=deadline)
            if (base / prefix / "Cargo.toml").is_file()
            else []
        )


def _report_oxlint_advisory(advisory: list[str], warnings: list[str] | None) -> None:
    if not advisory:
        return
    extra = f"\n... {len(advisory) - 10} more" if len(advisory) > 10 else ""
    message = "oxlint advisory (not blocking):\n" + "\n".join(advisory[:10]) + extra
    if warnings is None:
        print(message, file=sys.stderr)
    else:
        warnings.append(message)


def _oxlint_result_violations(
    result: subprocess.CompletedProcess[str], warnings: list[str] | None
) -> list[str]:
    findings = [
        line.strip()
        for line in result.stdout.splitlines()
        if re.search(r"\[(?:Error|Warning)/", line)
    ]
    _report_oxlint_advisory(
        [line for line in findings if "[Warning/" in line], warnings
    )
    if not result.returncode:
        return []
    evidence_finding("external-check-failed")
    errors = [line for line in findings if "[Error/" in line]
    return [f"oxlint: {line}" for line in errors or command_output(result)]


def oxlint_violations(
    path: Path,
    root: Path,
    display: str,
    *,
    deadline: float | None,
    warnings: list[str] | None,
) -> list[str]:
    """Oxlint errors block; warning-level policy reaches the agent as context."""
    command = [str(resolve_tool(root, "oxlint")), "--fix", "--format", "unix", display]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout(deadline),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        evidence_finding("checker-unavailable")
        return [f"oxlint: {error}"]
    return _oxlint_result_violations(result, warnings)


def mix_project(path: Path, root: Path) -> Path | None:
    root = root.resolve()
    project = path.parent.resolve()
    if not project.is_relative_to(root):
        raise ValueError("Mix project target outside repository")
    while True:
        if (project / "mix.exs").is_file():
            return project
        if project == root:
            return None
        project = project.parent


def _emit_check_notice(
    message: str,
    strict: bool,
    warnings: list[str] | None,
    violations: list[str],
    *,
    strict_message: str | None = None,
) -> None:
    if strict:
        violations.append(strict_message or message)
    elif warnings is not None:
        warnings.append(message)
    else:
        print(message, file=sys.stderr)


def _run_optional_analyzer(
    label: str,
    check: Any,
    arguments: tuple[Any, ...],
    *,
    deadline: float | None,
    strict: bool,
    warnings: list[str] | None,
    violations: list[str],
) -> None:
    """Run an analyzer whose absence or failure is reported, never hidden."""
    try:
        violations.extend(check(*arguments, deadline=deadline))
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as error:
        message = f"NOT CHECKED {label}: {str(error).strip()[:300]}"
        _emit_check_notice(message, strict, warnings, violations)


def _run_python_ruff(
    root: Path,
    display: str,
    names: list[str],
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    violations: list[str],
) -> None:
    try:
        violations.extend(
            ruff_new_violations(root, None, paths=set(names), deadline=deadline)
        )
    except SnapshotTooLarge as error:
        violations.extend(
            not_checked(f"NOT CHECKED python ruff: {error}", strict, warnings)
        )
    except MissingRuffConfig as error:
        # A minimal install (init --minimal) adds no .ruff.toml.
        _emit_check_notice(
            f"NOT CHECKED python ruff: {error}",
            strict,
            warnings,
            violations,
            strict_message=f"{display}: loki: {error}",
        )


def _check_python_file(
    path: Path,
    root: Path,
    display: str,
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    batch_paths: list[Path] | None,
    checked_projects: set[tuple[str, Path]] | None,
    violations: list[str],
) -> None:
    key = ("python", root)
    if checked_projects is not None and key in checked_projects:
        return
    selected = batch_paths if batch_paths is not None else [path]
    names = sorted(
        item.relative_to(root).as_posix()
        for item in selected
        if item.suffix == ".py" and item.is_file()
    )
    _run_python_ruff(
        root,
        display,
        names,
        strict,
        deadline=deadline,
        warnings=warnings,
        violations=violations,
    )
    if not violations:
        _run_optional_analyzer(
            "python types",
            mypy_violations,
            (root, names),
            deadline=deadline,
            strict=strict,
            warnings=warnings,
            violations=violations,
        )
    if checked_projects is not None:
        checked_projects.add(key)


def _check_go_file(
    path: Path,
    root: Path,
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    checked_projects: set[tuple[str, Path]] | None,
    violations: list[str],
) -> None:
    violations.extend(
        run_command(["gofmt", "-w", str(path)], root, "gofmt", deadline=deadline)
    )
    try:
        directory = path.parent.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        directory = "."
    package = "./" if directory == "." else f"./{directory}"
    key = ("go", root / directory)
    lint = None
    if checked_projects is None or key not in checked_projects:
        from concurrent.futures import ThreadPoolExecutor

        # Both tools build the package; overlapping them hides one cold start.
        with ThreadPoolExecutor(max_workers=1) as pool:
            lint = pool.submit(golangci_violations, root, package, deadline=deadline)
            vet = run_command(["go", "vet", package], root, "go vet", deadline=deadline)
            lint.exception()
        if checked_projects is not None:
            checked_projects.add(key)
    else:
        vet = run_command(["go", "vet", package], root, "go vet", deadline=deadline)
    violations.extend(vet)
    if lint is not None and not violations:
        # Compile errors from go vet make lint results redundant.
        _run_optional_analyzer(
            "golangci-lint",
            lambda deadline: lint.result(),
            (),
            deadline=deadline,
            strict=strict,
            warnings=warnings,
            violations=violations,
        )


def _check_rust_file(
    path: Path,
    root: Path,
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    checked_projects: set[tuple[str, Path]] | None,
    violations: list[str],
) -> None:
    crate = cargo_project(path, root)
    edition = cargo_edition(crate, root)
    violations.extend(
        run_command(
            ["rustfmt", *(["--edition", edition] if edition else []), str(path)],
            root,
            "rustfmt",
            deadline=deadline,
        )
    )
    key = ("rust", crate or root)
    if checked_projects is None or key not in checked_projects:
        _run_optional_analyzer(
            "clippy",
            clippy_violations,
            (path, root),
            deadline=deadline,
            strict=strict,
            warnings=warnings,
            violations=violations,
        )
        if checked_projects is not None:
            checked_projects.add(key)


def _collect_elixir_jobs(
    jobs: dict[str, Any],
    notices: dict[str, list[str]],
    strict: bool,
    warnings: list[str] | None,
    violations: list[str],
) -> None:
    for analyzer, job in jobs.items():
        try:
            violations.extend(job.result())
            for notice in notices[analyzer]:
                _emit_check_notice(
                    notice,
                    strict and notice.startswith("NOT CHECKED"),
                    warnings,
                    violations,
                )
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            _emit_check_notice(
                f"NOT CHECKED {analyzer}: {error}", strict, warnings, violations
            )


def _submit_elixir_analyzer(
    pool: Any,
    name: str,
    project: Path,
    config: dict[str, Any],
    deadline: float | None,
    notices: list[str],
) -> Any:
    if name == "Credo":
        return pool.submit(credo_new_violations, project, deadline=deadline)
    return pool.submit(
        sobelow_new_violations,
        project,
        config,
        deadline=deadline,
        warnings=notices,
    )


def _check_elixir_file(
    path: Path,
    root: Path,
    config: dict[str, Any],
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    checked_projects: set[tuple[str, Path]] | None,
    violations: list[str],
) -> list[str] | None:
    project = mix_project(path, root)
    if project is None:
        message = "NOT CHECKED elixir: enclosing Mix project required"
        if strict:
            return [message]
        _emit_check_notice(message, False, warnings, violations)
        return []
    from concurrent.futures import ThreadPoolExecutor

    key = ("elixir", project)
    reused = checked_projects is not None and key in checked_projects
    analyzers = (
        []
        if reused
        else ["Credo", *(["Sobelow"] if "phoenix" in rule_packs(config) else [])]
    )
    notices: dict[str, list[str]] = {name: [] for name in analyzers}
    # Format, Credo and Sobelow each start a BEAM; run them side by side.
    with ThreadPoolExecutor(max_workers=3) as pool:
        formatting = pool.submit(
            run_command,
            ["mix", "format", "--check-formatted", str(path)],
            project,
            "mix format",
            deadline=deadline,
        )
        jobs = {
            name: _submit_elixir_analyzer(
                pool, name, project, config, deadline, notices[name]
            )
            for name in analyzers
        }
    violations.extend(formatting.result())
    if reused:
        return violations[:MAX_VIOLATIONS]
    _collect_elixir_jobs(jobs, notices, strict, warnings, violations)
    if checked_projects is not None:
        checked_projects.add(key)
    return None


def _check_language_file(
    language: str,
    path: Path,
    root: Path,
    display: str,
    config: dict[str, Any],
    strict: bool,
    *,
    deadline: float | None,
    warnings: list[str] | None,
    batch_paths: list[Path] | None,
    checked_projects: set[tuple[str, Path]] | None,
    violations: list[str],
) -> list[str] | None:
    if language == "python":
        _check_python_file(
            path,
            root,
            display,
            strict,
            deadline=deadline,
            warnings=warnings,
            batch_paths=batch_paths,
            checked_projects=checked_projects,
            violations=violations,
        )
    elif language == "typescript":
        violations.extend(
            oxlint_violations(path, root, display, deadline=deadline, warnings=warnings)
        )
    elif language == "go":
        _check_go_file(
            path,
            root,
            strict,
            deadline=deadline,
            warnings=warnings,
            checked_projects=checked_projects,
            violations=violations,
        )
    elif language == "rust":
        _check_rust_file(
            path,
            root,
            strict,
            deadline=deadline,
            warnings=warnings,
            checked_projects=checked_projects,
            violations=violations,
        )
    elif language == "elixir":
        return _check_elixir_file(
            path,
            root,
            config,
            strict,
            deadline=deadline,
            warnings=warnings,
            checked_projects=checked_projects,
            violations=violations,
        )
    return None


def _check_python_ast_file(
    path: Path,
    root: Path,
    display: str,
    *,
    python: str | None,
    strict: bool,
    warnings: list[str] | None,
    deadline: float | None,
) -> list[str]:
    base = ""
    with contextlib.suppress(ValueError):
        # No committed base (outside Git, or before the first commit).
        base = head_text(root, display, deadline=deadline)
    return python_ast_violations(
        path,
        root,
        base=base,
        python=python,
        strict=strict,
        warnings=warnings,
        deadline=deadline,
    )


def check_file(
    path: Path,
    root: Path,
    config: dict[str, Any],
    strict: bool = False,
    *,
    deadline: float | None = None,
    warnings: list[str] | None = None,
    batch_paths: list[Path] | None = None,
    checked_projects: set[tuple[str, Path]] | None = None,
    python: str | None = None,
) -> list[str]:
    if message := protect_path(str(path), root, config):
        return [message]
    language = LANGUAGE_EXTENSIONS.get(path.suffix.lower())
    if not path.is_file():
        return []
    display = relative_display(path, root)
    if not language or not language_enabled(config, language):
        return written_content_violations(
            path, root, display, fallback=False, deadline=deadline
        )
    missing = missing_tool(language, root)
    violations = written_content_violations(
        path,
        root,
        display,
        fallback=language == "typescript" and missing is not None,
        deadline=deadline,
    )
    if missing:
        _emit_check_notice(
            f"NOT CHECKED {language}: missing {missing}",
            strict,
            warnings,
            violations,
            strict_message=f"{display}: loki: missing {missing}",
        )
    else:
        early = _check_language_file(
            language,
            path,
            root,
            display,
            config,
            strict,
            deadline=deadline,
            warnings=warnings,
            batch_paths=batch_paths,
            checked_projects=checked_projects,
            violations=violations,
        )
        if early is not None:
            return early
    if language == "python":
        violations.extend(
            _check_python_ast_file(
                path,
                root,
                display,
                python=python,
                strict=strict,
                warnings=warnings,
                deadline=deadline,
            )
        )
    return violations[:MAX_VIOLATIONS]


def _run_sobelow_workspace(
    command: list[str], workspace: Path, deadline: float | None, notices: set[str]
) -> list[tuple[tuple, int]]:
    result = subprocess.run(
        command,
        cwd=workspace,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    if result.returncode:
        raise ValueError(f"Sobelow failed (exit {result.returncode})")
    if result.stderr.strip():
        notices.add("NOT CHECKED Sobelow coverage: " + result.stderr.strip())
    return sobelow_findings(result.stdout, workspace)


def _format_sobelow_delta(
    reports: list[list[tuple[tuple, int]]],
    relative: Path,
    thresholds: dict[str, str],
    warnings: list[str] | None,
) -> list[str]:
    old = Counter(key for key, _ in reports[0])
    findings = []
    for key, location in reports[1]:
        if old[key]:
            old[key] -= 1
            continue
        confidence, path, rule, _, _ = key
        evidence_finding(
            f"sobelow:{confidence}:{rule.split(':', 1)[0]}",
            (relative / path).as_posix(),
        )
        message = (
            f"{(relative / path).as_posix()}:{location}: Sobelow {confidence}: {rule}"
        )
        if severity_matches(confidence, thresholds["block"]):
            findings.append(message)
            continue
        label = "WARN" if severity_matches(confidence, thresholds["warn"]) else "INFO"
        notice = f"NOT BLOCKED {label} {message}"
        if warnings is not None:
            warnings.append(notice)
        else:
            print(notice, file=sys.stderr)
    return findings


def _check_sobelow_config_changes(changes: list[FileChange], relative: Path) -> None:
    for change in changes:
        name = Path(change.path)
        if name.name in {"mix.exs", "mix.lock", ".sobelow-conf", ".sobelow-skips"} or (
            name.is_relative_to(relative / "config")
        ):
            raise ValueError(
                f"{change.path}: analyzer configuration change requires review"
            )


def _emit_sobelow_notices(notices: set[str], warnings: list[str] | None) -> None:
    for notice in sorted(notices):
        if warnings is not None:
            warnings.append(notice)
        else:
            print(notice, file=sys.stderr)


def sobelow_new_violations(
    project: Path,
    config: dict[str, Any],
    *,
    deadline: float | None = None,
    warnings: list[str] | None = None,
) -> list[str]:
    thresholds = security_policy(config)
    project = project.resolve()
    root = Path(
        os.fsdecode(
            git_output(project, ["rev-parse", "--show-toplevel"], deadline=deadline)
        ).strip()
    ).resolve()
    base, changes = git_changes(root, None, deadline=deadline)
    if base is None:
        raise ValueError("Sobelow comparison requires committed base")
    if protected := protected_change_violations(
        changes, base_policy(root, base, deadline=deadline) or {}
    ):
        return protected
    relative = project.relative_to(root)
    _check_sobelow_config_changes(changes, relative)
    ebin = project / "_build/dev/lib/sobelow/ebin"
    if not ebin.is_dir():
        raise ValueError("compiled dev Sobelow required; prepare dependencies first")
    # Execute only the prepared analyzer, never candidate Mix aliases or configs.
    # Dependency vulnerability checks need separate coverage, not shared deps trees.
    command = [
        "elixir",
        "-pa",
        str(ebin),
        "-pa",
        str(project / "_build/dev/lib/jason/ebin"),
        "-e",
        "Mix.start(); Mix.Tasks.Sobelow.run(System.argv())",
        "--",
        "--private",
        "--strict",
        "--no-config",
        "--ignore",
        "Vuln",
        "--format",
        "json",
        "--threshold",
        "low",
    ]
    with tempfile.TemporaryDirectory(prefix="loki-sobelow-") as directory:
        before = Path(directory) / "before"
        materialize_base(root, base, before, deadline=deadline)
        after = Path(directory) / "after"
        shutil.copytree(before, after)
        for change in changes:
            apply_snapshot_change(after, change)
        notices: set[str] = set()
        reports = [
            _run_sobelow_workspace(command, workspace, deadline, notices)
            for workspace in (before / relative, after / relative)
        ]
        _emit_sobelow_notices(notices, warnings)
        return _format_sobelow_delta(reports, relative, thresholds, warnings)


def severity_matches(confidence: str, threshold: str) -> bool:
    return threshold != "none" and SECURITY_LEVELS.index(
        confidence
    ) >= SECURITY_LEVELS.index(threshold)


def _validate_sobelow_item_fields(item: Any) -> tuple[str, str, int]:
    if not isinstance(item, dict):
        raise ValueError("finding must be an object")
    filename, rule, line = item["file"], item["type"], item["line"]
    if not (isinstance(filename, str) and filename and isinstance(rule, str) and rule):
        raise ValueError("invalid finding path or rule")
    if type(line) is not int or line < 0:
        raise ValueError("invalid finding line")
    return filename, rule, line


def _parse_sobelow_item(
    confidence: str, item: Any, workspace: Path
) -> tuple[tuple[str, str, str, str, str], int]:
    filename, rule, line = _validate_sobelow_item_fields(item)
    path = (workspace / filename).resolve()
    name = path.relative_to(workspace.resolve()).as_posix()
    lines = path.read_text(encoding="utf-8").splitlines()
    if line > len(lines):
        raise ValueError("finding line outside source")
    text = lines[line - 1].strip() if line else ""
    details = json.dumps(
        {
            key: value
            for key, value in item.items()
            if key not in {"file", "line", "column", "type", "fingerprint"}
        },
        sort_keys=True,
    )
    return (confidence, name, rule, text, details), line


def sobelow_findings(output: str, workspace: Path) -> list[tuple[tuple, int]]:
    try:
        payload = json.loads(output)
        groups = payload["findings"]
        expected = {f"{level}_confidence" for level in SECURITY_LEVELS[1:]}
        if not isinstance(groups, dict) or set(groups) != expected:
            raise ValueError("invalid confidence groups")
        findings = []
        for confidence in ("high", "medium", "low"):
            items = groups[f"{confidence}_confidence"]
            if not isinstance(items, list):
                raise ValueError("findings must be arrays")
            findings.extend(
                _parse_sobelow_item(confidence, item, workspace) for item in items
            )
        return findings
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise ValueError(f"Sobelow unavailable: invalid report ({error})") from error


def iter_source_files(root: Path) -> Iterable[Path]:
    for directory, names, files in os.walk(root):
        names[:] = [name for name in names if name not in SKIP_DIRECTORIES]
        base = Path(directory)
        for name in files:
            path = base / name
            if path.relative_to(root).as_posix() in {
                ".pi/extensions/loki.ts",
                ".omp/extensions/loki.ts",
            }:
                continue
            if path.suffix.lower() in LANGUAGE_EXTENSIONS:
                yield path


def _run_credo_workspace(
    workspace: Path, ebin: list[Path], config_file: Path, deadline: float | None
) -> Counter[tuple[str, str, str, str]]:
    runner = "Application.ensure_all_started(:credo); Credo.CLI.main(System.argv())"
    command = [
        "elixir",
        *[part for path in ebin for part in ("-pa", str(path))],
        "-e",
        runner,
        "--",
        "--strict",
        "--format",
        "json",
        "--config-file",
        str(config_file),
    ]
    result = subprocess.run(
        command,
        cwd=workspace,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    try:
        issues = json.loads(result.stdout)["issues"]
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(
            "Credo unavailable: " + result.stderr + result.stdout
        ) from error
    if result.returncode and not issues:
        raise ValueError("Credo failed without diagnostics")
    fingerprints = []
    for issue in issues:
        path = (workspace / issue["filename"]).resolve()
        name = path.relative_to(workspace).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        line = issue.get("line_no") or 0
        text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        fingerprints.append((name, issue["check"], issue["message"], text))
    return Counter(fingerprints)


def _check_credo_config_changes(changes: list[FileChange]) -> None:
    for change in changes:
        if Path(change.path).name in {".credo.exs", "mix.exs", "mix.lock"}:
            raise ValueError(
                f"{change.path}: analyzer configuration change requires review"
            )


def _format_credo_delta(counts: list[Counter[tuple[str, str, str, str]]]) -> list[str]:
    findings = []
    for (path, check, message, _), count in (counts[1] - counts[0]).items():
        evidence_finding(check, path)
        findings.extend([f"{path}: {check}: {message}"] * count)
    return findings


def credo_new_violations(project: Path, *, deadline: float | None = None) -> list[str]:
    project = project.resolve()
    root = Path(
        os.fsdecode(
            git_output(project, ["rev-parse", "--show-toplevel"], deadline=deadline)
        ).strip()
    ).resolve()
    base, changes = git_changes(root, None, deadline=deadline)
    if base is None:
        raise ValueError("Credo comparison requires committed base")
    _check_credo_config_changes(changes)
    if protected := protected_change_violations(
        changes, base_policy(root, base, deadline=deadline) or {}
    ):
        return protected
    relative = project.relative_to(root)
    config_path = (relative / ".credo.exs").as_posix()
    raw = git_output(root, ["show", f"{base}:{config_path}"], deadline=deadline)
    evidence_policy("base", config_path, raw, base=base)
    # Run the same trusted compiled analyzer without evaluating candidate mix.exs.
    ebin = sorted((project / "_build/dev/lib").glob("*/ebin"))
    if not any(path.parent.name == "credo" for path in ebin):
        raise ValueError("compiled dev Credo required; prepare dependencies first")
    with tempfile.TemporaryDirectory(prefix="loki-credo-") as directory:
        before = Path(directory) / "before"
        materialize_base(root, base, before, deadline=deadline)
        after = Path(directory) / "after"
        shutil.copytree(before, after)
        for change in changes:
            apply_snapshot_change(after, change)
        config_file = before / relative / ".credo.exs"
        counts = [
            _run_credo_workspace(workspace, ebin, config_file, deadline)
            for workspace in (before / relative, after / relative)
        ]
        return _format_credo_delta(counts)


def _elixir_tier_checks(
    tier: str, selected: list[str]
) -> list[tuple[str, list[str], str | None]]:
    checks: list[tuple[str, list[str], str | None]] = [
        ("format", ["mix", "format", "--check-formatted", *selected], None),
        ("credo", ["mix", "credo", "--strict", "--format", "json", *selected], "credo"),
    ]
    if tier in {"project", "deep"}:
        checks.extend(
            [
                ("compile", ["mix", "compile", "--warnings-as-errors"], None),
                (
                    "sobelow",
                    [
                        "mix",
                        "sobelow",
                        "--private",
                        "--format",
                        "json",
                        "--exit",
                        "high",
                    ],
                    "sobelow",
                ),
            ]
        )
    if tier == "deep":
        checks.append(
            ("dialyzer", ["mix", "dialyzer", "--format", "short"], "dialyxir")
        )
    return checks


def _run_elixir_tool(
    project: Path,
    tool: str,
    command: list[str],
    dependency: str | None,
    deadline: float | None,
) -> tuple[str, str]:
    if not shutil.which("mix"):
        return "NOT CHECKED", "mix is missing"
    if dependency and not (project / "deps" / dependency / "mix.exs").is_file():
        return "NOT CHECKED", f"required analyzer dependency missing: {dependency}"
    try:
        result = subprocess.run(
            command,
            cwd=project,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout(deadline),
            env={**os.environ, "MIX_ENV": "dev"},
            check=False,
        )
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        status = "PASS" if result.returncode == 0 else "FAIL"
        if tool in {"credo", "sobelow"}:
            return _record_elixir_json(tool, result.stdout, status, output)
        return status, output
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as error:
        return "NOT CHECKED", str(error)


def elixir_analysis(
    project: Path, tier: str, files: list[Path], *, deadline: float | None = None
) -> list[dict[str, Any]]:
    project = project.resolve()
    if tier not in {"fast", "project", "deep"}:
        raise ValueError("unknown Elixir analysis tier")
    if not (project / "mix.exs").is_file():
        raise ValueError("Mix project required; use --project api for nested projects")
    selected = []
    for path in files:
        candidate = (project / path).resolve()
        if not candidate.is_file():
            raise ValueError(f"Elixir target is not a file: {path}")
        try:
            selected.append(candidate.relative_to(project).as_posix())
        except ValueError as error:
            raise ValueError("Elixir target outside Mix project") from error
    report = []
    for tool, command, dependency in _elixir_tier_checks(tier, selected):
        start = time.monotonic()
        status, output = _run_elixir_tool(project, tool, command, dependency, deadline)
        report.append(
            {
                "tool": tool,
                "status": status,
                "output": output,
                "duration_ms": round((time.monotonic() - start) * 1000, 2),
            }
        )
        if status != "PASS":
            evidence_finding(f"elixir:{tool}:{status.lower().replace(' ', '-')}")
    return report


def _record_elixir_json(
    tool: str, stdout: str, status: str, output: str
) -> tuple[str, str]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return "NOT CHECKED", "analyzer did not return valid JSON: " + output
    if not isinstance(payload, dict):
        raise ValueError("analyzer JSON must be an object")
    if tool == "credo":
        for issue in payload.get("issues", []):
            evidence_finding(issue["check"], issue.get("filename"))
        return status, output
    for confidence, issues in payload.get("findings", {}).items():
        for issue in issues:
            evidence_finding(f"sobelow:{confidence}:{issue['type']}", issue.get("file"))
    return status, output


def _python_scan_command(
    relative_files: list[str], root: Path
) -> tuple[str | None, list[list[str]]]:
    ruff = ruff_command(root)
    if not ruff:
        return "ruff", []
    return None, [
        [*ruff, "check", *relative_files],
        [*ruff, "format", "--check", *relative_files],
    ]


def _typescript_scan_command(
    relative_files: list[str], root: Path
) -> tuple[str | None, list[list[str]]]:
    oxlint = resolve_tool(root, "oxlint")
    return (None, [[oxlint, *relative_files]]) if oxlint else ("oxlint", [])


def _rust_scan_command(
    relative_files: list[str], root: Path
) -> tuple[str | None, list[list[str]]]:
    if not shutil.which("cargo"):
        return "cargo", []
    return None, [
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
    ]


def scan_command(
    language: str, files: list[Path], root: Path
) -> tuple[str | None, list[list[str]]]:
    relative_files = [relative_display(path, root) for path in files]
    builders = {
        "python": _python_scan_command,
        "typescript": _typescript_scan_command,
        "go": lambda _f, _r: (
            (None, [["golangci-lint", "run"]])
            if shutil.which("golangci-lint")
            else ("golangci-lint", [])
        ),
        "rust": _rust_scan_command,
        "elixir": lambda _f, _r: (
            (
                None,
                [
                    ["mix", "credo", "--strict"],
                    ["mix", "compile", "--warnings-as-errors"],
                ],
            )
            if shutil.which("mix")
            else ("mix", [])
        ),
    }
    builder = builders.get(language)
    return builder(relative_files, root) if builder is not None else ("toolchain", [])


def _npm_manifest_dependencies(root: Path, found: set[tuple[str, str]]) -> None:
    import contextlib

    package_json = root / "package.json"
    if not package_json.is_file():
        return
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(package_json.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for field in ("dependencies", "devDependencies"):
                values = data.get(field, {})
                if isinstance(values, dict):
                    found.update(
                        ("npm", name) for name in values if isinstance(name, str)
                    )


def _python_manifest_dependencies(root: Path, found: set[tuple[str, str]]) -> None:
    found.update(
        ("pypi", name.replace("_", "-")) for name in declared_python_dependencies(root)
    )


def _go_manifest_dependencies(root: Path, found: set[tuple[str, str]]) -> None:
    import contextlib

    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return
    with contextlib.suppress(OSError):
        text = go_mod.read_text(encoding="utf-8")
        in_require = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line == "require (":
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            pattern = r"([^\s]+)\s+v" if in_require else r"require\s+([^\s]+)\s+v"
            if match := re.match(pattern, line):
                found.add(("go", match.group(1)))


def _cargo_and_mix_dependencies(root: Path, found: set[tuple[str, str]]) -> None:
    import contextlib

    cargo_toml = root / "Cargo.toml"
    if cargo_toml.is_file():
        with contextlib.suppress(OSError, tomllib.TOMLDecodeError):
            data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
            values = data.get("dependencies", {})
            if isinstance(values, dict):
                found.update(
                    ("crates", name) for name in values if isinstance(name, str)
                )
    mix_exs = root / "mix.exs"
    if mix_exs.is_file():
        with contextlib.suppress(OSError):
            text = mix_exs.read_text(encoding="utf-8")
            found.update(
                ("hex", name)
                for name in re.findall(r"\{\s*:([a-zA-Z0-9_]+)\s*,\s*[\"']", text)
            )


def manifest_dependencies(root: Path) -> list[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    _npm_manifest_dependencies(root, found)
    _python_manifest_dependencies(root, found)
    _go_manifest_dependencies(root, found)
    _cargo_and_mix_dependencies(root, found)
    return sorted(found)


def go_proxy_name(module: str) -> str:
    return "".join(
        f"!{character.lower()}" if character.isupper() else character
        for character in module
    )


def registry_url(ecosystem: str, name: str) -> str:
    import urllib.parse

    quoted = urllib.parse.quote(name, safe="" if ecosystem != "go" else "/")
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{quoted}"
    if ecosystem == "pypi":
        return f"https://pypi.org/pypi/{quoted}/json"
    if ecosystem == "crates":
        return f"https://crates.io/api/v1/crates/{quoted}"
    if ecosystem == "go":
        module = urllib.parse.quote(go_proxy_name(name), safe="/")
        return f"https://proxy.golang.org/{module}/@latest"
    return f"https://hex.pm/api/packages/{quoted}"


def dependency_violation(item: tuple[str, str]) -> str | None:
    import urllib.error
    import urllib.request

    ecosystem, name = item
    request = urllib.request.Request(  # noqa: S310 - fixed HTTPS registry endpoints
        registry_url(ecosystem, name), headers={"User-Agent": "loki/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=5):  # noqa: S310
            return None
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return f"{ecosystem}: package not found: {name}"
        return f"{ecosystem}: registry check unavailable: {name}: HTTP {error.code}"
    except (OSError, urllib.error.URLError) as error:
        return f"{ecosystem}: registry check unavailable: {name}: {error}"


def slopsquatting_violations(root: Path, config: dict[str, Any]) -> list[str]:
    import concurrent.futures

    prefixes = config.get("private_packages", [])
    private = (
        tuple(value for value in prefixes if isinstance(value, str))
        if isinstance(prefixes, list)
        else ()
    )
    dependencies = [
        item for item in manifest_dependencies(root) if not item[1].startswith(private)
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        return [
            violation
            for violation in executor.map(dependency_violation, dependencies)
            if violation
        ]


class SnapshotTooLarge(ValueError):
    """The working tree's changes are too big to snapshot in one check."""


@dataclass(frozen=True)
class FileChange:
    path: str
    before: bytes | None
    after: bytes | None
    before_mode: str | None
    after_mode: str | None


def command_timeout(deadline: float | None) -> float:
    remaining = (
        COMMAND_TIMEOUT
        if deadline is None
        else min(COMMAND_TIMEOUT, deadline - time.monotonic())
    )
    if remaining <= 0:
        raise ValueError("loki: hook deadline exceeded")
    return remaining


def git_output(
    root: Path,
    arguments: list[str],
    *,
    deadline: float | None = None,
    input_data: bytes | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--literal-pathspecs", *arguments],
            cwd=root,
            capture_output=True,
            input=input_data,
            timeout=command_timeout(deadline),
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"git: {error}") from error
    if result.returncode:
        reason = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git: {reason or f'exited {result.returncode}'}")
    return result.stdout


def _parse_blob_header(row: bytes, oid: str, message: str) -> int:
    fields = row.split()
    if (
        len(fields) != 3
        or fields[0] != oid.encode("ascii")
        or fields[1] != b"blob"
        or not fields[2].isdigit()
    ):
        raise ValueError(message)
    return int(fields[2])


def _unpack_git_blobs(unique: list[str], data: bytes) -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    offset = 0
    for oid in unique:
        end = data.find(b"\n", offset)
        if end < 0:
            raise ValueError("git: invalid batch blob response")
        size = _parse_blob_header(
            data[offset:end], oid, "git: invalid batch blob response"
        )
        start = end + 1
        end = start + size
        if end >= len(data) or data[end : end + 1] != b"\n":
            raise ValueError("git: truncated batch blob response")
        blobs[oid] = data[start:end]
        offset = end + 1
    if offset != len(data):
        raise ValueError("git: unexpected batch blob response")
    return blobs


def git_blobs(
    root: Path, oids: list[str], *, deadline: float | None = None
) -> dict[str, bytes]:
    unique = list(dict.fromkeys(oids))
    if not unique:
        return {}
    if len(unique) > 100_000:
        raise SnapshotTooLarge("git: snapshot exceeds 100000 base objects")
    request = ("\n".join(unique) + "\n").encode("ascii")
    metadata = git_output(
        root, ["cat-file", "--batch-check"], deadline=deadline, input_data=request
    ).splitlines()
    if len(metadata) != len(unique):
        raise ValueError("git: invalid batch metadata response")
    total = 0
    for oid, row in zip(unique, metadata, strict=True):
        total += _parse_blob_header(row, oid, "git: invalid batch metadata response")
        if total > 64 * 1024 * 1024:
            raise SnapshotTooLarge("git: snapshot base content exceeds 64 MiB")
    data = git_output(
        root,
        ["cat-file", "--batch"],
        deadline=deadline,
        input_data=request,
    )
    return _unpack_git_blobs(unique, data)


def candidate_content(
    root: Path, name: str, remaining: int
) -> tuple[bytes | None, str | None]:
    """Pin each resolved parent component before opening a changed candidate."""
    parent = (root / name).parent.resolve()
    relative = parent.relative_to(root)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_fd
        filename = os.path.basename(name)
        mode = os.stat(filename, dir_fd=directory, follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            content = os.fsencode(os.readlink(filename, dir_fd=directory))
            if len(content) > remaining:
                raise SnapshotTooLarge("git: snapshot content exceeds 64 MiB")
            return content, "120000"
        if not stat.S_ISREG(mode):
            raise ValueError(f"loki: unsupported changed file type: {name}")
        fd = os.open(
            filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"loki: unsupported changed file type: {name}")
            if info.st_size > remaining:
                raise SnapshotTooLarge("git: snapshot content exceeds 64 MiB")
            content = source.read(remaining + 1)
            if len(content) > remaining:
                raise SnapshotTooLarge("git: snapshot content exceeds 64 MiB")
            return content, "100755" if info.st_mode & stat.S_IXUSR else "100644"
    except FileNotFoundError:
        return None, None
    finally:
        os.close(directory)


def repository_gap(root: Path, *, deadline: float | None = None) -> str | None:
    """Why git cannot compare root (no repository, or a subdirectory of one), else None."""
    try:
        top = git_output(root, ["rev-parse", "--show-toplevel"], deadline=deadline)
    except ValueError as error:
        return str(error)
    if Path(os.fsdecode(top).rstrip("\n")).resolve() != root.resolve():
        return "git: project root must be the repository root"
    return None


def _resolve_git_base(
    root: Path, base: str | None, deadline: float | None
) -> str | None:
    if base is not None and re.fullmatch(r"(?:0{40}|0{64})", base):
        return None
    options = dict(
        cwd=root,
        capture_output=True,
        timeout=command_timeout(deadline),
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        check=False,
    )
    try:
        commit = subprocess.run(
            [
                "git",
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{base if base is not None else 'HEAD'}^{{commit}}",
            ],
            **options,
        )
        if commit.returncode == 0:
            return commit.stdout.decode("ascii").strip()
        if base is not None:
            raise ValueError("git: invalid base reference")
        options["timeout"] = command_timeout(deadline)
        symbolic = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], **options)
        if symbolic.returncode != 0 or not symbolic.stdout.startswith(b"refs/heads/"):
            raise ValueError("git: cannot resolve HEAD")
        options["timeout"] = command_timeout(deadline)
        exists = subprocess.run(
            [
                "git",
                "show-ref",
                "--verify",
                "--quiet",
                os.fsdecode(symbolic.stdout).rstrip("\n"),
            ],
            **options,
        )
        if exists.returncode != 1:
            raise ValueError("git: cannot resolve HEAD commit")
        return None
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"git: {error}") from error


def _verify_tracked_file_types(
    root: Path, entries: dict[str, tuple[str, str, str]], deadline: float | None
) -> None:
    # Git can omit tracked files replaced by FIFOs. Inspect directory entries
    # without following symlinks; reuse parent validation only in this sweep.
    parents: dict[str, set[str]] = {}
    for name, (before_mode, _, _) in entries.items():
        if before_mode != "160000":
            parent, filename = os.path.split(name)
            parents.setdefault(parent, set()).add(filename)
    for parent, filenames in parents.items():
        command_timeout(deadline)
        directory = os.path.realpath(os.path.join(root, parent))
        if os.path.commonpath((str(root), directory)) != str(root):
            raise ValueError(f"loki: outside project root: {parent}")
        _check_directory_children(directory, parent, filenames)


def _check_directory_children(directory: str, parent: str, filenames: set[str]) -> None:
    import contextlib

    with contextlib.suppress(FileNotFoundError), os.scandir(directory) as children:
        for child in children:
            if (
                child.name in filenames
                and not child.is_file(follow_symlinks=False)
                and not child.is_symlink()
            ):
                name = os.path.join(parent, child.name)
                raise ValueError(f"loki: unsupported changed file type: {name}")


def _git_tree_and_names(
    root: Path, resolved: str | None, deadline: float | None
) -> tuple[dict[str, tuple[str, str, str]], bytes]:
    if not resolved:
        return {}, git_output(
            root,
            ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            deadline=deadline,
        )
    entries: dict[str, tuple[str, str, str]] = {}
    for entry in git_output(
        root, ["ls-tree", "-r", "-z", resolved], deadline=deadline
    ).split(b"\0"):
        if entry:
            metadata, path = entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            entries[os.fsdecode(path)] = (mode, kind, oid)
    _verify_tracked_file_types(root, entries, deadline)
    names = git_output(
        root,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            resolved,
            "--",
        ],
        deadline=deadline,
    )
    names += git_output(
        root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        deadline=deadline,
    )
    return entries, names


def _build_file_change(
    root: Path,
    name: str,
    entries: dict[str, tuple[str, str, str]],
    blobs: dict[str, bytes],
    remaining_bytes: int,
) -> tuple[FileChange | None, int]:
    path = root / name
    try:
        Path(os.path.abspath(path)).relative_to(root)
        path.parent.resolve().relative_to(root)
    except ValueError as error:
        raise ValueError(f"loki: outside project root: {name}") from error
    before = before_mode = None
    if name in entries:
        before_mode, kind, oid = entries[name]
        if kind != "blob" or before_mode not in {"100644", "100755", "120000"}:
            raise ValueError(f"loki: unsupported changed file type: {name}")
        before = blobs[oid]
    after, after_mode = candidate_content(root, name, remaining_bytes)
    remaining_bytes -= len(after) if after is not None else 0
    if before != after or before_mode != after_mode:
        return FileChange(name, before, after, before_mode, after_mode), remaining_bytes
    return None, remaining_bytes


def _validate_git_changes_state(
    root: Path, base: str | None, deadline: float | None
) -> None:
    gap = repository_gap(root, deadline=deadline)
    if gap is not None:
        raise ValueError(gap)
    if git_output(root, ["ls-files", "--unmerged", "-z"], deadline=deadline):
        raise ValueError("loki: unresolved index conflict")
    if base == "":
        raise ValueError("git: empty base reference")


def _select_changed_names(names: bytes, only: set[str] | None) -> list[str]:
    changed_names = sorted({os.fsdecode(name) for name in names.split(b"\0") if name})
    if only is not None:
        return [name for name in changed_names if name in only]
    return changed_names


def git_changes(
    root: Path,
    base: str | None,
    *,
    deadline: float | None = None,
    only: set[str] | None = None,
) -> tuple[str | None, list[FileChange]]:
    """The changes against base; `only` limits the snapshot to those repository-relative paths."""
    root = root.resolve()
    _validate_git_changes_state(root, base, deadline)
    resolved = _resolve_git_base(root, base, deadline)
    entries, names = _git_tree_and_names(root, resolved, deadline)
    changed_names = _select_changed_names(names, only)
    blobs = git_blobs(
        root,
        [
            entries[name][2]
            for name in changed_names
            if name in entries and entries[name][1] == "blob"
        ],
        deadline=deadline,
    )
    changes: list[FileChange] = []
    remaining_bytes = 64 * 1024 * 1024 - sum(len(blob) for blob in blobs.values())
    for name in changed_names:
        change, remaining_bytes = _build_file_change(
            root, name, entries, blobs, remaining_bytes
        )
        if change is not None:
            changes.append(change)
    return resolved, changes


def base_policy(
    root: Path, base: str | None, *, deadline: float | None = None
) -> dict[str, Any] | None:
    if base is None:
        evidence_policy("base", ".loki/loki.json", None, base=base)
        return None
    entry = git_output(
        root, ["ls-tree", "-z", base, "--", ".loki/loki.json"], deadline=deadline
    )
    if not entry:
        evidence_policy("base", ".loki/loki.json", None, base=base)
        return None
    metadata, _ = entry.rstrip(b"\0").split(b"\t", 1)
    mode, kind, oid = metadata.decode("ascii").split()
    if mode not in {"100644", "100755"} or kind != "blob":
        raise ValueError("loki: base policy must be a regular file")
    raw = git_output(root, ["cat-file", "blob", oid], deadline=deadline)
    evidence_policy("base", ".loki/loki.json", raw, base=base)
    value = json.loads(raw.decode("utf-8"))
    return validate_config(value)


# Text just before an interpolation that puts it where SQL expects a table or column name.
SQL_IDENTIFIER_POSITION = (
    r"(?:\b(?:from|into|update|join|table|exists)|\b(?:order|group)\s+by|[\"`\[.])\s*$"
)


def protected_change_violations(
    changes: list[FileChange], base_config: dict[str, Any]
) -> list[str]:
    patterns = protected_patterns(base_config)
    findings = []
    for change in changes:
        if any(path_matches(change.path, pattern) for pattern in patterns):
            evidence_finding("protected-content", change.path)
            findings.append(f"{change.path}: protected content changed")
    return findings


def _regular_test_key(change: FileChange, added: bool) -> tuple[bytes, str] | None:
    if not TEST_PATH_RE.search(change.path):
        return None
    if added and change.before is None and change.after is not None:
        if change.after_mode in {"100644", "100755"}:
            return change.after, change.after_mode
    if not added and change.after is None and change.before is not None:
        if change.before_mode in {"100644", "100755"}:
            return change.before, change.before_mode
    return None


def _moved_test_paths(changes: list[FileChange]) -> set[str]:
    # Pair one deletion with one addition; duplicate content is not a blanket waiver.
    additions: dict[tuple[bytes, str], list[str]] = {}
    for change in changes:
        if key := _regular_test_key(change, added=True):
            additions.setdefault(key, []).append(change.path)
    moved: set[str] = set()
    for change in changes:
        if (key := _regular_test_key(change, added=False)) and (
            destinations := additions.get(key)
        ):
            moved.update((change.path, destinations.pop()))
    return moved


def _changed_lines(change: FileChange) -> tuple[list[str], list[str]]:
    try:
        before = (change.before or b"").decode("utf-8").splitlines()
        after = (change.after or b"").decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(
            f"loki: cannot inspect non-UTF-8 test/config: {change.path}"
        ) from error
    removed: list[str] = []
    added: list[str] = []
    for tag, i, j, a, b in difflib.SequenceMatcher(
        None, before, after, autojunk=False
    ).get_opcodes():
        if tag != "equal":
            removed.extend(before[i:j])
            added.extend(after[a:b])
    return removed, added


def _count_matches(pattern: re.Pattern[str], lines: list[str]) -> int:
    return sum(bool(pattern.search(line)) for line in lines)


def _test_file_integrity(
    change: FileChange, removed: list[str], added: list[str]
) -> list[str]:
    path = change.path
    found: list[str] = []
    if change.before is not None and change.after is None:
        evidence_finding("test-file-deleted", path)
        found.append(f"{path}: test file deleted")
    if _count_matches(TEST_DECLARATION_RE, removed) > _count_matches(
        TEST_DECLARATION_RE, added
    ):
        evidence_finding("test-deleted", path)
        found.append(f"{path}: test deleted")
    if _count_matches(ASSERTION_RE, removed) > _count_matches(ASSERTION_RE, added):
        evidence_finding("assertion-removed", path)
        found.append(f"{path}: assertion removed")
    if any(SKIP_RE.search(line) for line in added):
        evidence_finding("test-skip-added", path)
        found.append(f"{path}: test skip added")
    return found


def test_integrity_violations(changes: list[FileChange]) -> list[str]:
    violations: list[str] = []
    moved = _moved_test_paths(changes)
    for change in changes:
        path = change.path
        if path in moved:
            continue
        is_test = bool(TEST_PATH_RE.search(path))
        is_policy = any(path_matches(path, pattern) for pattern in QUALITY_POLICY_PATHS)
        if not is_test and not is_policy:
            continue
        removed, added = _changed_lines(change)
        if is_test:
            violations.extend(_test_file_integrity(change, removed, added))
        if is_policy and any(
            QUALITY_POLICY_RE.search(line) for line in [*removed, *added]
        ):
            evidence_finding("quality-threshold-changed", path)
            violations.append(f"{path}: quality threshold changed")
    return violations[:MAX_VIOLATIONS]


def dependency_policy_violations(root: Path, config: dict[str, Any]) -> list[str]:
    approved = config.get("approved_dependencies")
    if approved is None:
        return []
    if not isinstance(approved, list) or not all(
        isinstance(value, str) for value in approved
    ):
        return ["loki: approved_dependencies must be a list of ecosystem:name strings"]

    allowed = set(approved)
    unapproved = [
        (ecosystem, name)
        for ecosystem, name in manifest_dependencies(root)
        if f"{ecosystem}:{name}" not in allowed
    ]
    violations = [
        f"{ECOSYSTEM_MANIFEST[ecosystem]}: unapproved dependency: {ecosystem}:{name}"
        for ecosystem, name in unapproved
    ]
    return violations


def _lockfile_violation(
    lockfile: str, change: FileChange | None, remains: bool
) -> str | None:
    if change is None:
        return None
    if change.after_mode is not None and change.after_mode not in {"100644", "100755"}:
        return f"loki: unsupported changed file type: {lockfile}"
    if change.before is not None and change.after is None and remains:
        return f"{lockfile}: tracked lockfile deleted"
    return None


def lockfile_violations(root: Path, changes: list[FileChange]) -> list[str]:
    violations: list[str] = []
    changed = {change.path: change for change in changes}
    for ecosystem, lockfiles in MANIFEST_LOCKFILES.items():
        manifest = root / ECOSYSTEM_MANIFEST[ecosystem]
        try:
            remains = stat.S_ISREG(manifest.lstat().st_mode)
        except FileNotFoundError:
            remains = False
        for lockfile in lockfiles:
            if message := _lockfile_violation(lockfile, changed.get(lockfile), remains):
                violations.append(message)
    return violations


def configured_commands(config: dict[str, Any], group: str) -> list[list[str]] | str:
    commands = config.get("commands", {})
    if not isinstance(commands, dict):
        return "loki: commands must be a JSON object"
    values = commands.get(group, [])
    if not isinstance(values, list) or any(
        not isinstance(value, list)
        or not value
        or not all(isinstance(part, str) and part for part in value)
        for value in values
    ):
        return f"loki: commands.{group} must be a list of non-empty string arrays"
    return values


def bounded_mutation_command(command: list[str]) -> list[str] | str:
    if not shutil.which("systemd-run"):
        return "mutation: systemd-run is required for the 8 GB memory limit"
    bounded = list(command)
    if "mutmut" in bounded and "run" in bounded:
        while "--max-children" in bounded:
            index = bounded.index("--max-children")
            del bounded[index : index + 2]
        bounded.extend(("--max-children", "2"))
    return [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "-p",
        "MemoryMax=8G",
        *bounded,
    ]


def expand_command(
    command: list[str], base: str | None, paths: list[str]
) -> list[str] | str:
    expanded: list[str] = []
    for part in command:
        if part == "{base}":
            if not base:
                return "command requires --base"
            expanded.append(base)
        elif part == "{files}":
            expanded.extend(paths)
        else:
            expanded.append(part)
    return expanded


def command_guardrail_violations(
    root: Path, config: dict[str, Any], base: str | None, paths: list[str]
) -> list[str]:
    violations: list[str] = []
    for group in COMMAND_GROUPS:
        commands = configured_commands(config, group)
        if isinstance(commands, str):
            violations.append(commands)
            continue
        for command in commands:
            if "{files}" in command and not paths:
                print(f"NOT APPLICABLE {group}: no changed files")
                continue
            expanded = expand_command(command, base, paths)
            if isinstance(expanded, str):
                violations.append(f"{group}: {expanded}")
                continue
            if group == "mutation":
                expanded = bounded_mutation_command(expanded)
                if isinstance(expanded, str):
                    violations.append(expanded)
                    continue
            violations.extend(run_command(expanded, root, f"{group}: {command[0]}"))
    return violations


def repository_violations(
    root: Path, config: dict[str, Any], base: str | None, changes: list[FileChange]
) -> list[str]:
    protected = protected_change_violations(changes, config)
    if protected:
        return protected
    paths = [change.path for change in changes]
    violations = [
        *test_integrity_violations(changes),
        *dependency_policy_violations(root, config),
        *lockfile_violations(root, changes),
        *changed_content_violations(changes),
    ]
    if not configured_commands(config, "contract") and any(
        change.path in ECOSYSTEM_MANIFEST.values() and change.before != change.after
        for change in changes
    ):
        print(
            "NOT CHECKED lock synchronization: configure a frozen-lock command "
            "in commands.contract"
        )
    if not violations:
        violations.extend(command_guardrail_violations(root, config, base, paths))
    return violations[:MAX_VIOLATIONS]


def changed_content_violations(changes: list[FileChange]) -> list[str]:
    """Net-new built-in content findings across changed text files."""
    pairs = []
    for change in changes:
        if change.after is None or len(change.after) > 4 * 1024 * 1024:
            continue
        try:
            before = (change.before or b"").decode("utf-8")
            pairs.append((change.path, before, change.after.decode("utf-8")))
        except UnicodeDecodeError:
            continue
    return content_rule_violations(pairs)


def _load_write_changes(
    root: Path,
    touched: set[str],
    deadline: float | None,
    warnings: list[str] | None,
) -> tuple[str | None, list[FileChange]]:
    try:
        return git_changes(root, None, deadline=deadline)
    except SnapshotTooLarge as error:
        # Too many or too large uncommitted changes to compare them all: check the written files only.
        note = (
            f"NOT CHECKED repository changes: {error}; protected-file, test and lockfile "
            "checks covered only the files this write changed"
        )
        try:
            result = git_changes(root, None, deadline=deadline, only=touched)
        except SnapshotTooLarge as written:
            result = (None, [])
            note = f"NOT CHECKED repository changes: {written}"
        if warnings is not None:
            warnings.append(note)
        return result


def write_guardrail_violations(
    paths: list[Path],
    root: Path,
    config: dict[str, Any],
    *,
    deadline: float | None = None,
    warnings: list[str] | None = None,
) -> list[str]:
    gap = repository_gap(root, deadline=deadline)
    if gap is not None:
        strict = os.environ.get("LOKI_STRICT") == "1"
        return not_checked(f"NOT CHECKED repository changes: {gap}", strict, warnings)
    try:
        touched = {
            Path(os.path.abspath(path)).relative_to(root.resolve()).as_posix()
            for path in paths
        }
        base, changes = _load_write_changes(root, touched, deadline, warnings)
        policy = base_policy(root, base, deadline=deadline)
        if protected := protected_change_violations(
            changes, policy if policy is not None else {}
        ):
            return protected
        violations = test_integrity_violations(
            [change for change in changes if change.path in touched]
        )
        violations.extend(lockfile_violations(root, changes))
        if touched.intersection(ECOSYSTEM_MANIFEST.values()):
            violations.extend(dependency_policy_violations(root, config))
        return violations[:MAX_VIOLATIONS]
    except (ValueError, OSError) as error:
        return [str(error)]


def _scan_repository(
    root: Path, config: dict[str, Any], strict: bool, base: str | None
) -> tuple[dict[str, Any] | None, int]:
    try:
        git_output(root, ["rev-parse", "--show-toplevel"])
    except ValueError as error:
        if strict or base is not None:
            print(str(error))
            return None, 1
        print("NOT CHECKED repository: git repository required")
        return config, 0
    try:
        resolved_base, changes = git_changes(root, base)
        policy = base_policy(root, resolved_base)
        protected = protected_change_violations(
            changes, policy if policy is not None else {}
        )
        if protected:
            print("\n".join(protected))
            return None, 1
        effective = policy if policy is not None else config
        findings = repository_violations(root, effective, resolved_base, changes)
        if findings:
            print("\n".join(findings))
            return None, 1
        return effective, 0
    except (ValueError, OSError) as error:
        print(f"loki: {error}")
        return None, 1


def _record_elixir_project_check(
    label: str,
    check: dict[str, Any],
    strict: bool,
    violations: dict[str, list[str]],
) -> None:
    print(f"[{label}] {check['status']}")
    failed = check["status"] == "FAIL" or (strict and check["status"] == "NOT CHECKED")
    if failed:
        violations.setdefault("elixir", []).append(f"{label}: {check['output']}")
    elif check["output"]:
        print(check["output"])


def _scan_elixir_projects(
    root: Path, files: list[Path], strict: bool, violations: dict[str, list[str]]
) -> None:
    projects = {mix_project(path, root) for path in files}
    if None in projects:
        print("NOT CHECKED elixir: source files without an enclosing Mix project")
        if strict:
            violations.setdefault("elixir", []).append("Mix project required")
    for project in sorted(item for item in projects if item is not None):
        for check in elixir_analysis(project, "project", []):
            label = f"{project.relative_to(root)}:{check['tool']}"
            _record_elixir_project_check(label, check, strict, violations)


def _scan_python_ast(
    root: Path,
    files: list[Path],
    dependencies: set[str] | None,
    python: str | None,
    strict: bool,
    violations: dict[str, list[str]],
) -> None:
    notices: list[str] = []
    for path in files:
        violations.setdefault("python", []).extend(
            python_ast_violations(
                path,
                root,
                dependencies,
                python=python,
                strict=strict,
                warnings=notices,
            )
        )
        if len(violations["python"]) >= MAX_VIOLATIONS:
            break
    # One interpreter answers for every file; say so once.
    violations["python"] = list(dict.fromkeys(violations["python"]))
    for notice in notices:
        print(notice)


def _scan_language_group(
    language: str,
    files: list[Path],
    root: Path,
    strict: bool,
    dependencies: set[str],
    python: str | None,
    violations: dict[str, list[str]],
) -> None:
    if language == "elixir":
        _scan_elixir_projects(root, files, strict, violations)
        return
    missing, commands = scan_command(language, files, root)
    if missing:
        print(f"SKIP {language} (no {missing})")
        if strict:
            violations.setdefault(language, []).append(f"loki: missing {missing}")
    for command in commands:
        violations.setdefault(language, []).extend(
            run_command(command, root, command[0])
        )
    if language == "python":
        _scan_python_ast(root, files, dependencies, python, strict, violations)


def _print_scan_violations(violations: dict[str, list[str]]) -> int:
    failed = False
    for language, messages in violations.items():
        if not messages:
            continue
        failed = True
        print(f"[{language}]")
        for message in messages[:MAX_VIOLATIONS]:
            print(message)
    return 1 if failed else 0


def scan(
    root: Path,
    config: dict[str, Any],
    online: bool,
    strict: bool,
    base: str | None = None,
    python: str | None = None,
) -> int:
    config = validate_config(config)
    effective, status = _scan_repository(root, config, strict, base)
    if effective is None:
        return status
    config = effective
    grouped: dict[str, list[Path]] = {}
    for path in iter_source_files(root):
        language = LANGUAGE_EXTENSIONS[path.suffix.lower()]
        if language_enabled(config, language):
            grouped.setdefault(language, []).append(path)
    violations: dict[str, list[str]] = {}
    dependencies = declared_python_dependencies(root)
    for language in ("python", "typescript", "go", "rust", "elixir"):
        if files := grouped.get(language):
            _scan_language_group(
                language, files, root, strict, dependencies, python, violations
            )
    if grouped.get("typescript"):
        violations.setdefault("typescript", []).extend(
            typescript_findings(root, config)
        )
    if online and (dependency_issues := slopsquatting_violations(root, config)):
        violations["dependencies"] = dependency_issues
    return _print_scan_violations(violations)


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def merge_hook_config(
    existing: dict[str, Any], fragment: dict[str, Any]
) -> dict[str, Any]:
    hooks = existing.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("hooks must be a JSON object")
    fragment_hooks = fragment.get("hooks", {})
    if not isinstance(fragment_hooks, dict):
        raise ValueError("template hooks must be a JSON object")
    merge_factory_hooks(hooks, fragment_hooks)
    return existing


def _is_loki_hook_handler(handler: Any) -> bool:
    return (
        isinstance(handler, dict)
        and isinstance(handler.get("command"), str)
        and ".loki/loki.py" in handler["command"]
    )


def merge_factory_hooks(
    existing: dict[str, Any], fragment: dict[str, Any]
) -> dict[str, Any]:
    for event, entries in fragment.items():
        current = existing.setdefault(event, [])
        if not isinstance(current, list) or not isinstance(entries, list):
            raise ValueError(f"{event} must be a JSON array")
        retained = []
        for entry in current:
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                handlers = [
                    handler
                    for handler in entry["hooks"]
                    if not _is_loki_hook_handler(handler)
                ]
                if handlers:
                    retained.append({**entry, "hooks": handlers})
            else:
                retained.append(entry)
        existing[event] = [*retained, *entries]
    return existing


def merge_oxlint(existing: dict[str, Any], template: dict[str, Any]) -> dict[str, Any]:
    for field in ("ignorePatterns", "plugins", "jsPlugins"):
        incoming = template.get(field, [])
        if not isinstance(incoming, list):
            continue
        current = existing.setdefault(field, [])
        if not isinstance(current, list):
            raise ValueError(f"{field} must be a JSON array")
        for item in incoming:
            if item not in current:
                current.append(item)
    for field in ("categories", "rules"):
        incoming = template.get(field, {})
        if not isinstance(incoming, dict):
            continue
        current = existing.setdefault(field, {})
        if not isinstance(current, dict):
            raise ValueError(f"{field} must be a JSON object")
        current.update(incoming)
    return existing


def copy_owned(source: Path, target: Path, force: bool) -> None:
    if target.exists() and not force:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
    else:
        shutil.copy2(source, target)


def template_path(name: str) -> Path:
    path = SOURCE_ROOT / "templates" / name
    if not path.is_file():
        raise FileNotFoundError(f"missing installer template: {path}")
    return path


def _codex_hooks_candidates(text: str, document: dict[str, Any]) -> list[str]:
    if "features" not in document:
        return [text + "\n[features]\nhooks = true\n"]
    return [
        text[: match.end()] + "\nhooks = true\n" + text[match.end() :]
        for match in re.finditer(
            r"(?m)^\s*\[features\][ \t]*(?:#[^\n]*)?(?:\n|$)", text
        )
    ]


def enable_codex_hooks(target: Path) -> None:
    path = target / ".codex/config.toml"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    document = tomllib.loads(text)
    features = document.get("features", {})
    if not isinstance(features, dict):
        raise ValueError("Codex features must be a TOML table")
    if features.get("hooks") is True:
        return
    if "hooks" in features:
        print(
            "SKIP Codex hooks activation: existing features.hooks is not true; "
            "enable it explicitly in .codex/config.toml."
        )
        return
    expected = {**document, "features": {**features, "hooks": True}}
    valid = []
    for candidate in _codex_hooks_candidates(text, document):
        with contextlib.suppress(tomllib.TOMLDecodeError):
            if tomllib.loads(candidate) == expected:
                valid.append(candidate)
    if len(valid) != 1:
        print(
            "SKIP Codex hooks activation: preserve existing TOML layout; "
            "set features.hooks = true manually in .codex/config.toml."
        )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(valid[0], encoding="utf-8")


def install_minimal(target: Path, force: bool = False) -> None:
    """Install only the engine and default policy in .loki/, for hosts that
    run the engine themselves (Ultron). No agent hooks, linter configuration
    or CI workflow are written."""
    target = target.expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    copy_owned(Path(__file__).resolve(), target / ".loki" / "loki.py", force)
    config_path = target / ".loki" / "loki.json"
    if not config_path.exists():
        shutil.copy2(template_path("loki.json"), config_path)
    print("Installed loki engine and policy in .loki/ (minimal).")
    print(
        "Commit .loki/: policy is read from the committed version; "
        "scan reports it as awaiting review until then."
    )


def _install_linter_templates(target: Path) -> None:
    oxlint_json = target / ".oxlintrc.json"
    oxlint_ts = target / "oxlint.config.ts"
    if oxlint_json.is_file() or not oxlint_ts.is_file():
        existing = read_json_object(oxlint_json)
        template = read_json_object(template_path(".oxlintrc.json"))
        write_json(oxlint_json, merge_oxlint(existing, template))
    else:
        print(
            "SKIP oxlint.config.ts (merge these template fields manually: "
            "ignorePatterns, jsPlugins, plugins, categories, rules)"
        )
        print(f"  template: {template_path('.oxlintrc.json')}")
    for relative, template in (
        (Path(".ruff.toml"), ".ruff.toml"),
        (Path(".golangci.yml"), ".golangci.yml"),
        (Path(".github/workflows/loki.yml"), "loki.yml"),
    ):
        destination = target / relative
        if destination.exists():
            print(
                f"SKIP {relative.as_posix()} "
                f"(exists; reconcile with {template_path(template)})"
            )
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(template_path(template), destination)


def _install_js_and_elixir_hints(target: Path) -> None:
    if (target / "mix.exs").is_file():
        credo = target / ".credo.exs"
        if credo.exists():
            print("SKIP .credo.exs (exists; reconcile with templates/.credo.exs)")
        else:
            shutil.copy2(template_path(".credo.exs"), credo)
    if not (target / "package.json").is_file():
        return
    if (target / "bun.lock").exists() or (target / "bun.lockb").exists():
        command = "bun add -d oxlint @oxlint/plugins"
    elif (target / "pnpm-lock.yaml").exists():
        command = "pnpm add -D oxlint @oxlint/plugins"
    elif (target / "yarn.lock").exists():
        command = "yarn add -D oxlint @oxlint/plugins"
    else:
        command = "npm i -D oxlint @oxlint/plugins"
    print(f"Install JavaScript guardrail dependencies: {command}")


def install_target(target: Path, force: bool = False) -> None:
    target = target.expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    copy_owned(Path(__file__).resolve(), target / ".loki" / "loki.py", force)
    copy_owned(
        SOURCE_ROOT / "vendor" / "anti-slop",
        target / ".loki" / "oxlint" / "anti-slop",
        force,
    )
    copy_owned(
        SOURCE_ROOT / "vendor" / "landmines",
        target / ".loki" / "oxlint" / "landmines",
        force,
    )
    copy_owned(
        SOURCE_ROOT / "vendor" / "codehygiene",
        target / ".loki" / "vendor" / "codehygiene",
        force,
    )
    config_path = target / ".loki" / "loki.json"
    if not config_path.exists():
        shutil.copy2(template_path("loki.json"), config_path)
    for destination, template in (
        (target / ".claude" / "settings.json", "claude-settings.fragment.json"),
        (target / ".codex" / "hooks.json", "codex-hooks.json"),
    ):
        existing = read_json_object(destination)
        fragment = read_json_object(template_path(template))
        write_json(destination, merge_hook_config(existing, fragment))
    enable_codex_hooks(target)
    factory_hooks = target / ".factory" / "hooks.json"
    write_json(
        factory_hooks,
        merge_factory_hooks(
            read_json_object(factory_hooks),
            read_json_object(template_path("factory-hooks.json")),
        ),
    )
    shim = SOURCE_ROOT / "shim" / "loki.ts"
    copy_owned(shim, target / ".pi" / "extensions" / "loki.ts", True)
    copy_owned(shim, target / ".loki" / "loki-shim.ts", True)
    omp_source = (SOURCE_ROOT / "shim" / "loki-omp.ts").read_text(encoding="utf-8")
    marker = 'from "./loki.ts"'
    if omp_source.count(marker) != 1:
        raise ValueError("OMP shared import marker must occur exactly once")
    omp_entry = target / ".omp" / "extensions" / "loki.ts"
    omp_entry.parent.mkdir(parents=True, exist_ok=True)
    omp_entry.write_text(
        omp_source.replace(marker, 'from "../../.loki/loki-shim.ts"'), encoding="utf-8"
    )
    _install_linter_templates(target)
    _install_js_and_elixir_hints(target)
    print("Installed loki project guardrails.")
    print("Codex: run /hooks and approve the project hooks.")
    print("Factory: project hooks are installed in .factory/hooks.json.")
    print("Pi: accept the project trust prompt.")
    print("Claude Code and OMP: no trust action required.")
    print(
        "Policy bootstrap or upgrade changes require independent review; "
        "scan reports them until accepted into the base."
    )
    # The global command when installed; the pinned engine from a plain checkout.
    print(f"Verify: {'loki' if shutil.which('loki') else 'python3 .loki/loki.py'} scan")


def _parse_preview_edit_fields(
    edit: Any, fields: tuple[str, str, str]
) -> tuple[str, str, bool] | None:
    if not isinstance(edit, dict):
        raise ValueError("invalid edit preview")
    source, replacement = (edit.get(key) for key in fields[:2])
    replace_all = edit.get(fields[2], False)
    if not (isinstance(source, str) and source and isinstance(replacement, str)):
        return None
    if not isinstance(replace_all, bool):
        raise ValueError("replacement mode must be boolean")
    return source, replacement, replace_all


def _apply_one_preview_edit(
    content: str, edit: Any, fields: tuple[str, str, str]
) -> str | None:
    parsed = _parse_preview_edit_fields(edit, fields)
    if parsed is None:
        return None
    source, replacement, replace_all = parsed
    matches = content.count(source)
    if not matches or (matches != 1 and not replace_all):
        return None
    size = len(content.encode("utf-8")) + matches * (
        len(replacement.encode("utf-8")) - len(source.encode("utf-8"))
    )
    if size > 4 * 1024 * 1024:
        raise ValueError("preview exceeds 4 MiB")
    return content.replace(source, replacement, -1 if replace_all else 1)


def _apply_preview_edits(
    old: str, edits: Any, harness: str | None, deadline: float | None
) -> str | None:
    if not isinstance(edits, list) or not 1 <= len(edits) <= 256:
        raise ValueError("edit preview requires 1 to 256 edits")
    fields = (
        ("oldText", "newText", "replace_all")
        if harness == "pi"
        else ("old_str", "new_str", "change_all")
        if harness == "factory"
        else ("old_string", "new_string", "replace_all")
    )
    content = old
    for edit in edits:
        command_timeout(deadline)
        updated = _apply_one_preview_edit(content, edit, fields)
        if updated is None:
            return None
        content = updated
    return content


PREVIEW_OPERATIONS = {
    ("claude", "Write"),
    ("claude", "Edit"),
    ("claude", "MultiEdit"),
    ("factory", "Create"),
    ("factory", "Edit"),
    ("pi", "write"),
    ("pi", "edit"),
    ("omp", "write"),
    ("ultron", "write"),
}


def _reconstruct_preview_content(
    name: Any,
    data: dict[str, Any],
    before: bytes | None,
    old: str,
    harness: str | None,
    deadline: float | None,
) -> str | None:
    if name in {"Write", "Create", "write"}:
        content = data.get("content")
        # Older path-only hook envelopes remain usable, but are not content checks.
        if content is None:
            return None
        if not isinstance(content, str):
            raise ValueError("preview content must be text")
        return content
    if before is None:
        raise ValueError("edit preview requires an existing file")
    edits = data.get("edits") if name == "MultiEdit" else [data]
    return _apply_preview_edits(old, edits, harness, deadline)


def preview_changes(
    root: Path,
    paths: list[str],
    payload: Any,
    harness: str | None,
    *,
    deadline: float | None = None,
) -> list[tuple[str, str, str]] | None:
    """Reconstruct only host operations whose exact replacement is known."""
    if not isinstance(payload, dict) or not isinstance(payload.get("tool_input"), dict):
        raise ValueError("invalid preview envelope")
    data = payload["tool_input"]
    name = payload.get("tool_name")
    if (harness, name) not in PREVIEW_OPERATIONS:
        return None
    if len(paths) != 1:
        raise ValueError("single-file preview requires one target")
    path = Path(os.path.abspath(root / paths[0]))
    relative = path.relative_to(root).as_posix()
    if path.resolve() != path:
        raise ValueError("preview through symlinked paths is unsupported")
    before, mode = candidate_content(root, relative, 4 * 1024 * 1024)
    if mode not in (None, "100644", "100755"):
        raise ValueError("preview requires a regular file")
    old = (before or b"").decode("utf-8")
    content = _reconstruct_preview_content(name, data, before, old, harness, deadline)
    if content is None:
        return None
    if len(content.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("preview exceeds 4 MiB")
    return [(relative, old, content)]


def _validate_oxlint_span(
    span: dict[str, Any], content: str, encoded: bytes
) -> tuple[int, int, int]:
    offset, length, line = (span.get(key) for key in ("offset", "length", "line"))
    if (
        type(offset) is not int
        or type(length) is not int
        or type(line) is not int
        or offset < 0
        or length < 0
        or offset + length > len(encoded)
        or line < 1
        or line > len(content.splitlines())
    ):
        raise ValueError("invalid Oxlint preview diagnostic span")
    return offset, length, line


def _oxlint_first_span(item: dict[str, Any]) -> dict[str, Any] | None:
    labels = item.get("labels")
    if isinstance(labels, list) and labels and isinstance(labels[0], dict):
        span = labels[0].get("span")
        if isinstance(span, dict):
            return span
    return None


def _oxlint_diagnostic_fingerprint(
    item: Any, files: dict[str, tuple[str, str, str]]
) -> tuple[str, tuple[str, str, str, str, str], int]:
    if (
        not isinstance(item, dict)
        or not isinstance(item.get("filename"), str)
        or item["filename"] not in files
    ):
        raise ValueError("invalid Oxlint preview diagnostic")
    side, relative, content = files[item["filename"]]
    code = item.get("code")
    message = item.get("message")
    span = _oxlint_first_span(item)
    if not (
        isinstance(code, str)
        and code
        and isinstance(message, str)
        and message
        and span is not None
    ):
        raise ValueError("unpositioned Oxlint preview diagnostic")
    encoded = content.encode("utf-8")
    offset, length, line = _validate_oxlint_span(span, content, encoded)
    fingerprint = (
        relative,
        code,
        message,
        content.splitlines()[line - 1].strip(),
        encoded[offset : offset + length].decode("utf-8"),
    )
    return side, fingerprint, line


def _write_oxlint_preview_files(
    work: Path, changes: list[tuple[str, str, str]]
) -> tuple[Path, dict[str, tuple[str, str, str]]]:
    config = work / "config.json"
    config.write_text(
        json.dumps(
            {
                "plugins": ["jest", "vitest"],
                "categories": {"correctness": "off"},
                "rules": {rule: "error" for rule in JS_PREVIEW_RULES},
            }
        ),
        encoding="utf-8",
    )
    files: dict[str, tuple[str, str, str]] = {}
    for index, (relative, old, new) in enumerate(changes):
        for side, content in (("before", old), ("after", new)):
            # Neutralize directives in analysis copies, never in user files.
            content = content.replace("eslint", "xslint").replace("oxlint", "xxlint")
            path = work / side / str(index) / Path(relative).name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            files[path.relative_to(work).as_posix()] = (side, relative, content)
    return config, files


def _parse_oxlint_preview_report(
    result: subprocess.CompletedProcess[str],
    files: dict[str, tuple[str, str, str]],
) -> list[str]:
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise ValueError("Oxlint preview failed or reported incomplete coverage")
    report = json.loads(result.stdout)
    if (
        not isinstance(report, dict)
        or report.get("number_of_files") != len(files)
        or report.get("number_of_rules") != len(JS_PREVIEW_RULES)
        or not isinstance(report.get("diagnostics"), list)
    ):
        raise ValueError("invalid or incomplete Oxlint preview report")
    if bool(report["diagnostics"]) != bool(result.returncode):
        raise ValueError("Oxlint preview status disagrees with diagnostics")
    counts: dict[str, Counter[tuple[str, str, str, str, str]]] = {
        "before": Counter(),
        "after": Counter(),
    }
    locations: dict[tuple[str, str, str, str, str], int] = {}
    for item in report["diagnostics"]:
        side, fingerprint, line = _oxlint_diagnostic_fingerprint(item, files)
        counts[side][fingerprint] += 1
        locations[fingerprint] = line
    violations = []
    for fingerprint, count in (counts["after"] - counts["before"]).items():
        relative, code, message, _, _ = fingerprint
        evidence_finding("preview-" + code, relative)
        violations.extend(
            [f"{relative}:{locations[fingerprint]}: {code}: {message}"] * count
        )
    return violations[:MAX_VIOLATIONS]


def preview_oxlint(
    root: Path,
    changes: list[tuple[str, str, str]],
    *,
    deadline: float | None,
) -> list[str]:
    binary = resolve_tool(root, "oxlint")
    if not binary:
        raise ValueError("missing oxlint for content preview")
    with tempfile.TemporaryDirectory(prefix="loki-preview-") as directory:
        work = Path(directory)
        config, files = _write_oxlint_preview_files(work, changes)
        result = subprocess.run(
            [
                str(Path(binary).resolve()),
                "-c",
                str(config),
                "--disable-nested-config",
                "--no-ignore",
                "--threads",
                "1",
                "--format",
                "json",
                *[str(work / name) for name in files],
            ],
            cwd=work,
            capture_output=True,
            text=True,
            check=False,
            timeout=command_timeout(deadline),
        )
        return _parse_oxlint_preview_report(result, files)


def _preview_js_violations(
    root: Path,
    config: dict[str, Any] | None,
    changes: list[tuple[str, str, str]],
    violations: list[str],
    deadline: float | None,
) -> None:
    if config is not None and not violations:
        violations.extend(preview_typescript(root, config, changes, deadline=deadline))
    try:
        violations.extend(preview_oxlint(root, changes, deadline=deadline))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        violations.extend(content_rule_violations(changes, fallback=True))
        raise


def preview_violations(
    root: Path,
    paths: list[str],
    payload: Any,
    harness: str | None,
    *,
    deadline: float | None,
    warnings: list[str],
    config: dict[str, Any] | None = None,
) -> list[str]:
    if payload is None:
        return []
    languages = {LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower()) for path in paths}
    javascript = "typescript" in languages
    violations: list[str] = []
    changes = None
    try:
        changes = preview_changes(root, paths, payload, harness, deadline=deadline)
        if changes is None:
            raise ValueError("host operation has no exact content preview")
        violations.extend(content_rule_violations(changes))
        violations.extend(preview_ruff(root, changes, deadline=deadline))
        if javascript:
            _preview_js_violations(root, config, changes, violations, deadline)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        # Post-write checks still inspect languages without Oxlint preview rules.
        if not javascript:
            return violations
        evidence_finding("preview-unavailable")
        suffix = "; built-in fallback rules applied" if changes is not None else ""
        message = f"NOT CHECKED pre-write content: {error}{suffix}"
        if os.environ.get("LOKI_STRICT") == "1":
            return [*violations, message]
        warnings.append(message)
    return violations[:MAX_VIOLATIONS]


def selected_paths(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> list[str]:
    if args.harness:
        raw = sys.stdin.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("hook input exceeds 4 MiB")
        args.hook_payload = json.loads(raw)
        return harness_paths(raw, args.harness)
    if args.file:
        if getattr(args, "preview", None):
            raw = sys.stdin.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("preview input exceeds 4 MiB")
            args.hook_payload = json.loads(raw)
        return list(dict.fromkeys(valid_path(path) for path in args.file))
    raise ValueError("one of --file or --harness is required")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loki")
    parser.add_argument("--version", action="version", version=f"loki {__version__}")
    parser.add_argument("--root", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    boundary = subparsers.add_parser("verify-installation")
    boundary.add_argument("--engine", type=Path, required=True)
    boundary.add_argument("--registration", type=Path, action="append", required=True)
    boundary.add_argument("--agent-uid", type=int, required=True)
    explain = subparsers.add_parser("explain")
    explain.add_argument("--limit", type=int, default=20)
    context = subparsers.add_parser("context")
    context.add_argument("--root", type=Path, default=argparse.SUPPRESS)
    context.add_argument(
        "--event", choices=("SessionStart", "UserPromptSubmit"), default="SessionStart"
    )
    context.add_argument("--host", choices=("ultron",))
    elixir = subparsers.add_parser("elixir")
    elixir.add_argument("--project", type=Path, default=Path("."))
    elixir.add_argument(
        "--tier", choices=("fast", "project", "deep"), default="project"
    )
    elixir.add_argument("--file", type=Path, action="append", default=[])
    elixir.add_argument("--json", action="store_true")
    elixir.add_argument("--credo-new", action="store_true")
    transaction = subparsers.add_parser("apply")
    transaction.add_argument("--manifest", type=Path, required=True)
    transaction.add_argument("--check-only", action="store_true")
    shell = subparsers.add_parser("shell")
    shell.add_argument(
        "--harness", choices=("claude", "factory", "omp", "pi"), required=True
    )
    shell.add_argument("--record", action="store_true")
    shell_writes = subparsers.add_parser("shell-writes")
    shell_writes.add_argument("--harness", choices=("ultron",), default="ultron")
    for name in ("protect", "hook"):
        child = subparsers.add_parser(name)
        child.add_argument("--root", type=Path, default=argparse.SUPPRESS)
        targets = child.add_mutually_exclusive_group(required=True)
        targets.add_argument("--file", action="append")
        targets.add_argument("--harness", choices=("claude", "codex", "factory"))
        child.add_argument("--record", action="store_true")
        child.add_argument("--format", choices=("text", "json"), default="text")
        child.add_argument("--python", help="the project's Python interpreter")
        if name == "protect":
            child.add_argument("--preview", choices=("pi", "omp", "ultron"))
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--online", action="store_true")
    scan_parser.add_argument("--strict", action="store_true")
    scan_parser.add_argument("--base")
    scan_parser.add_argument("--ruff-new", action="store_true")
    scan_parser.add_argument("--python", help="the project's Python interpreter")
    slop = subparsers.add_parser("slop")
    slop.add_argument("--base", help="compare against this revision")
    slop.add_argument("--json", action="store_true")
    slop.add_argument("--top", type=int, default=10)
    hygiene = subparsers.add_parser("hygiene")
    hygiene.add_argument("--base", default="HEAD", help="compare against this revision")
    hygiene.add_argument("--file", action="append")
    hygiene.add_argument("--level", choices=("on", "all"))
    hygiene.add_argument("--json", action="store_true")
    hygiene.add_argument("--python", help="the project's Python interpreter")
    daemon = subparsers.add_parser("daemon")
    daemon.add_argument("action", choices=("serve", "start", "stop", "status"))
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--dir", default=".")
    init_parser.add_argument("--managed-dir", type=Path)
    init_parser.add_argument("--shell-guard", action="store_true")
    init_parser.add_argument("--minimal", action="store_true")
    return parser


def _record_cli_evidence(
    started: float, status: int, diagnostic: str, evidence: dict[str, Any]
) -> int:
    operation = next(
        (arg for arg in sys.argv[1:] if arg in {"protect", "hook", "shell"}), "invalid"
    )
    root = daemon_root(sys.argv[1:])
    if status and not evidence["findings"]:
        evidence["findings"].append({"rule": "unclassified-failure", "path": None})
    try:
        record_event(
            root,
            operation,
            evidence["targets"],
            "deny" if status else "warning" if diagnostic else "allow",
            started,
            evidence=evidence,
        )
    except (OSError, ValueError) as error:
        print(f"loki: evidence unavailable: {error}", file=sys.stderr)
        return 2
    return status


def main() -> int:
    if "--record" not in sys.argv[1:]:
        return dispatch_main()
    started = time.monotonic()
    errors = io.StringIO()
    evidence: dict[str, Any] = {"policies": [], "findings": [], "targets": []}
    token = ACTIVE_EVIDENCE.set(evidence)
    try:
        with contextlib.redirect_stderr(errors):
            try:
                status = dispatch_main()
            except SystemExit as error:
                evidence_finding("invalid-cli")
                status = error.code if isinstance(error.code, int) else 2
    finally:
        ACTIVE_EVIDENCE.reset(token)
    diagnostic = errors.getvalue()
    print(diagnostic, end="", file=sys.stderr)
    return _record_cli_evidence(started, status, diagnostic, evidence)


def _print_hygiene_notes(notes: list[str], as_json: bool) -> None:
    if as_json:
        not_checked = [note for note in notes if note.startswith("NOT CHECKED")]
        findings = [note for note in notes if not note.startswith("NOT CHECKED")]
        print(json.dumps({"findings": findings, "not_checked": not_checked}))
    elif notes:
        print("\n".join(notes))


def hygiene_command(root: Path, config: dict[str, Any], args: Any) -> int:
    configured = hygiene_level(config)
    level = args.level or ("on" if configured == "off" else configured)
    deadline = time.monotonic() + COMMAND_TIMEOUT
    notes = (
        hygiene_against(
            root,
            [valid_path(path) for path in args.file],
            args.base,
            level,
            deadline=deadline,
            python=args.python,
        )
        if args.file
        else changed_hygiene(
            root, args.base, level, deadline=deadline, python=args.python
        )
    )
    _print_hygiene_notes(notes, args.json)
    return 0


def _run_elixir_command(args: Any) -> int:
    try:
        if args.credo_new:
            findings = credo_new_violations(args.project.resolve())
            print(
                json.dumps({"tool": "credo", "findings": findings})
                if args.json
                else "\n".join(findings)
            )
            return int(bool(findings))
        report = elixir_analysis(args.project.resolve(), args.tier, args.file)
        if args.json:
            print(json.dumps(report))
            return int(any(item["status"] != "PASS" for item in report))
        for item in report:
            print(f"[{item['tool']}] {item['status']}")
            if item["output"]:
                print(item["output"])
        return int(any(item["status"] != "PASS" for item in report))
    except (OSError, ValueError) as error:
        print(f"loki: Elixir analysis unavailable: {error}", file=sys.stderr)
        return 1


def _run_verify_installation_command(args: Any) -> int:
    findings = installation_violations(
        [args.engine, *args.registration], args.agent_uid
    )
    for finding in findings:
        print(finding)
    if not findings:
        print(
            "Ownership/mode checks passed; ACLs, privileged access and host "
            "activation require operator verification"
        )
    return int(bool(findings))


def _run_context_command(args: Any) -> int:
    try:
        context_root = (args.root or DEFAULT_ROOT).resolve()
        config = load_config(context_root)
        output: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": args.event,
                "additionalContext": injected_context(context_root, config, args.host),
            }
        }
        if args.host:
            # What a host that runs the engine itself may ask of it.
            output["loki"] = {"version": __version__, "formats": ["text", "json"]}
        print(json.dumps(output))
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: context unavailable: {error}", file=sys.stderr)
        return 2


def _read_shell_envelope() -> dict[str, Any]:
    raw = sys.stdin.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("shell envelope exceeds 4 MiB")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("invalid shell envelope")
    return payload


def _run_shell_command(args: Any) -> int:
    try:
        payload = _read_shell_envelope()
        if not isinstance(payload.get("tool_input"), dict):
            raise ValueError("invalid shell envelope")
        root = (args.root or DEFAULT_ROOT).resolve()
        cwd = shell_cwd(payload, args.harness, root)
        if reason := shell_violation(
            payload["tool_input"].get("command"), root=root, cwd=cwd
        ):
            print(reason, file=sys.stderr)
            return 2
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: invalid shell input: {error}", file=sys.stderr)
        return 2


def _run_shell_writes_command(args: Any) -> int:
    try:
        payload = _read_shell_envelope()
        root = (args.root or DEFAULT_ROOT).resolve()
        cwd = Path(payload.get("cwd") or root).resolve()
        if reason := shell_writes_violation(payload.get("command"), root, cwd):
            print(reason, file=sys.stderr)
            return 2
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: invalid shell input: {error}", file=sys.stderr)
        return 2


def _run_apply_command(args: Any) -> int:
    try:
        apply_transaction(
            (args.root or DEFAULT_ROOT).resolve(), args.manifest, args.check_only
        )
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: {error}", file=sys.stderr)
        return 2


def _run_explain_command(args: Any) -> int:
    try:
        for event in read_events(DEFAULT_ROOT.resolve(), args.limit):
            print(json.dumps(event, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: {error}", file=sys.stderr)
        return 1


def _run_init_command(args: Any) -> int:
    try:
        if args.minimal:
            if args.shell_guard or args.managed_dir:
                raise ValueError(
                    "--minimal installs only .loki/; "
                    "it takes neither --shell-guard nor --managed-dir"
                )
            install_minimal(Path(args.dir), args.force)
            return 0
        install_target(Path(args.dir), args.force)
        if args.shell_guard:
            install_shell_guard(Path(args.dir).resolve())
        if args.managed_dir:
            install_managed(Path(args.dir).resolve(), args.managed_dir.resolve())
        return 0
    except (OSError, ValueError) as error:
        print(f"loki: {error}", file=sys.stderr)
        return 1


def _run_scan_command(root: Path, config: dict[str, Any], args: Any) -> int:
    if args.ruff_new:
        try:
            findings = ruff_new_violations(root, args.base)
            if findings:
                print("\n".join(findings))
            return int(bool(findings))
        except (OSError, ValueError) as error:
            print(f"loki: {error}", file=sys.stderr)
            return 1
    return scan(
        root,
        config,
        args.online,
        args.strict or os.environ.get("LOKI_STRICT") == "1",
        args.base,
        args.python,
    )


def _run_post_write_advisories(
    root: Path,
    targets: list[Path],
    config: dict[str, Any],
    args: Any,
    deadline: float,
    messages: list[str],
    warnings: list[str],
) -> None:
    # Structural sloppiness is advisory unless slop.block is set.
    try:
        notes = written_slop(root, targets, deadline=deadline)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        notes = [f"NOT CHECKED slop: {error}"]
    if slop_policy(config).get("block"):
        messages.extend(note for note in notes if "NOT CHECKED" not in note)
        warnings.extend(note for note in notes if "NOT CHECKED" in note)
    else:
        warnings.extend(notes)
    if (level := hygiene_level(config)) != "off":
        try:
            warnings.extend(
                written_hygiene(
                    root,
                    targets,
                    level,
                    deadline=deadline,
                    python=args.python,
                )
            )
        except (OSError, ValueError) as error:
            warnings.append(f"NOT CHECKED hygiene: {error}")


def _run_hook_checks(
    root: Path,
    paths: list[str],
    config: dict[str, Any],
    args: Any,
    deadline: float,
    warnings: list[str],
) -> list[str]:
    targets = [Path(os.path.abspath(root / path)) for path in paths]
    messages = list(
        write_guardrail_violations(
            targets, root, config, deadline=deadline, warnings=warnings
        )
    )
    if messages:
        return messages
    if any(target.suffix in TYPESCRIPT_SUFFIXES for target in targets):
        messages.extend(
            typescript_findings(root, config, deadline=deadline, warnings=warnings)
        )
    if messages:
        return messages
    _run_post_write_advisories(
        root, targets, config, args, deadline, messages, warnings
    )
    checked_projects: set[tuple[str, Path]] = set()
    strict = os.environ.get("LOKI_STRICT") == "1"
    for target in targets:
        messages.extend(
            check_file(
                target,
                root,
                config,
                strict,
                deadline=deadline,
                warnings=warnings,
                batch_paths=targets,
                checked_projects=checked_projects,
                python=args.python,
            )
        )
    return messages


def _emit_guard_blocking(args: Any, messages: list[str], warnings: list[str]) -> int:
    if args.command == "hook":
        print(
            "loki: post-write check failed; files are already changed.",
            file=sys.stderr,
        )
    advisory = [item for item in warnings if not item.startswith("NOT CHECKED")]
    unchecked = [item for item in warnings if item.startswith("NOT CHECKED")]
    # Only the lines above the label failed the check.
    label = ["loki: advisory (not blocking):"] if advisory else []
    lines = [*messages, *label, *advisory, *unchecked]
    print("\n".join(lines[:MAX_VIOLATIONS]), file=sys.stderr)
    return 2


def _emit_guard_result(args: Any, messages: list[str], warnings: list[str]) -> int:
    warnings = list(dict.fromkeys(warnings))
    if args.format == "json":
        print(json.dumps(hook_report(args.command, messages, warnings)))
    if messages:
        return _emit_guard_blocking(args, messages, warnings)
    if warnings:
        text = "\n".join(warnings)
        print(text, file=sys.stderr)
        if args.harness:
            event_name = "PreToolUse" if args.command == "protect" else "PostToolUse"
            print(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": event_name,
                            "additionalContext": text,
                        }
                    }
                )
            )
    return 0


def _report_guard_error(args: Any, error: Exception, value_finding: str) -> None:
    evidence_finding(value_finding if isinstance(error, ValueError) else "guard-error")
    prefix = (
        "invalid hook input"
        if isinstance(error, ValueError)
        else f"guard error: {type(error).__name__}"
    )
    print(f"loki: {prefix}: {error}", file=sys.stderr)
    if getattr(args, "format", "text") == "json":
        print(json.dumps(hook_report(args.command, [], [], f"{prefix}: {error}")))


def _evaluate_guard_messages(
    root: Path,
    config: dict[str, Any],
    args: Any,
    parser: argparse.ArgumentParser,
    deadline: float,
    warnings: list[str],
) -> list[str]:
    if args.format == "json" and args.harness:
        raise ValueError("--format json requires --file")
    paths = selected_paths(args, parser)
    if (evidence := ACTIVE_EVIDENCE.get()) is not None:
        evidence["targets"] = paths
    messages = [
        message for path in paths if (message := protect_path(path, root, config))
    ]
    if messages:
        return messages
    if args.command == "protect":
        return preview_violations(
            root,
            paths,
            getattr(args, "hook_payload", None),
            args.harness or args.preview,
            deadline=deadline,
            warnings=warnings,
            config=config,
        )
    if args.command == "hook":
        return _run_hook_checks(root, paths, config, args, deadline, warnings)
    return messages


def _run_guard_command(
    root: Path, config: dict[str, Any], args: Any, parser: argparse.ArgumentParser
) -> int:
    warnings: list[str] = []
    try:
        messages = _evaluate_guard_messages(
            root, config, args, parser, time.monotonic() + 20, warnings
        )
    except Exception as error:
        _report_guard_error(args, error, "invalid-input")
        return 2
    return _emit_guard_result(args, messages, warnings)


STANDALONE_COMMANDS = {
    "elixir": _run_elixir_command,
    "verify-installation": _run_verify_installation_command,
    "context": _run_context_command,
    "shell": _run_shell_command,
    "shell-writes": _run_shell_writes_command,
    "apply": _run_apply_command,
    "explain": _run_explain_command,
    "init": _run_init_command,
}


def _dispatch_root_command(
    root: Path, config: dict[str, Any], args: Any, parser: argparse.ArgumentParser
) -> int:
    if args.command == "slop":
        try:
            return slop_command(root, config, args.base, args.json, args.top)
        except (OSError, ValueError) as error:
            print(f"loki: {error}", file=sys.stderr)
            return 1
    if args.command == "hygiene":
        try:
            return hygiene_command(root, config, args)
        except (OSError, ValueError) as error:
            print(f"loki: {error}", file=sys.stderr)
            return 1
    if args.command == "scan":
        return _run_scan_command(root, config, args)
    return _run_guard_command(root, config, args, parser)


def dispatch_main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "daemon":
        return daemon_command(args.action, (args.root or DEFAULT_ROOT).resolve())
    if handler := STANDALONE_COMMANDS.get(args.command):
        return handler(args)
    root = (getattr(args, "root", None) or DEFAULT_ROOT).resolve()
    try:
        config = load_config(root)
    except Exception as error:
        _report_guard_error(args, error, "invalid-policy")
        return 2 if args.command in {"protect", "hook"} else 1
    return _dispatch_root_command(root, config, args, parser)


FINDING_RE = re.compile(
    r"^(?P<path>[^:\s][^:\n]*?)(?::(?P<line>\d+))?: (?P<rule>[^:\s][^:\n]*?): "
)


def hook_report(
    command: str, messages: list[str], warnings: list[str], error: str | None = None
) -> dict[str, Any]:
    """`--format json`: what blocked, what is advisory and what was not checked.

    `status` is `blocked` (exit status 2) exactly when `blocking` has findings,
    else `passed`. `advisory` findings and `not_checked` notes never fail the
    check; with LOKI_STRICT=1 a missing check is a blocking finding instead.
    """

    def entry(text: str) -> dict[str, Any]:
        item: dict[str, Any] = {"text": text}
        if match := FINDING_RE.match(text):
            item["path"] = match["path"]
            if match["line"]:
                item["line"] = int(match["line"])
            item["rule"] = match["rule"]
        return item

    report = {
        "loki": __version__,
        "command": command,
        "status": "error" if error is not None else "blocked" if messages else "passed",
        "blocking": [entry(text) for text in messages[:MAX_VIOLATIONS]],
        "advisory": [
            entry(text) for text in warnings if not text.startswith("NOT CHECKED")
        ],
        "not_checked": [text for text in warnings if text.startswith("NOT CHECKED")],
    }
    if error is not None:
        report["error"] = error
    return report


def installation_violations(paths: list[Path], agent_uid: int) -> list[str]:
    findings = []
    if agent_uid == 0:
        return ["root agents cannot be confined by ownership checks"]
    for path in paths:
        if path.is_symlink() or not path.is_file():
            findings.append(f"{path}: regular non-symlink file required")
            continue
        for candidate in (path.absolute(), *path.absolute().parents):
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                findings.append(f"{candidate}: symlinked installation ancestor")
                break
            if metadata.st_uid == agent_uid or metadata.st_mode & 0o022:
                findings.append(f"{candidate}: agent-owned or group/world writable")
                break
    return findings


def _rewrite_managed_hook(
    handler: dict[str, Any],
    event: str,
    harness: str,
    engine: Path,
    root: Path,
    shlex: Any,
) -> None:
    command = handler.get("command", "")
    if ".loki/loki.py" not in command:
        return
    operations = [
        name
        for name in ("context", "protect", "hook", "shell")
        if f" {name} --" in command
    ]
    if len(operations) != 1:
        raise ValueError("unrecognized owned hook command")
    operation = operations[0]
    arguments = (
        f"--event {shlex.quote(event)}"
        if operation == "context"
        else f"--harness {harness}"
    )
    handler["command"] = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(engine))} "
        f"--root {shlex.quote(str(root))} {operation} {arguments} "
        "|| { printf '%s\\n' 'loki: hook command failed' >&2; "
        "exit 2; } "
        "# .loki/loki.py managed engine"
    )


def _rewrite_managed_hooks_file(
    path: Path, harness: str, engine: Path, root: Path, shlex: Any
) -> None:
    document = read_json_object(path)
    groups = document.get("hooks", document)
    for event, entries in groups.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            for handler in entry.get("hooks", []):
                _rewrite_managed_hook(handler, event, harness, engine, root, shlex)
    write_json(path, document)


def _rewrite_managed_shim_file(path: Path, engine: Path) -> None:
    source = path.read_text(encoding="utf-8")
    marker = "`${root}/.loki/loki.py`"
    if source.count(marker) != 1:
        raise ValueError("shared adapter engine marker unavailable")
    path.write_text(source.replace(marker, json.dumps(str(engine))), encoding="utf-8")


def install_managed(root: Path, destination: Path) -> None:
    import hashlib
    import shlex

    if destination.is_relative_to(root):
        raise ValueError("managed engine must be outside the repository")
    content = Path(__file__).read_bytes()
    release = destination / hashlib.sha256(content).hexdigest()
    release.mkdir(parents=True, exist_ok=True)
    engine = release / "loki.py"
    if engine.exists() and engine.read_bytes() != content:
        raise ValueError("managed release content mismatch")
    if not engine.exists():
        engine.write_bytes(content)
    engine.chmod(0o444)
    for relative, harness in (
        (".claude/settings.json", "claude"),
        (".codex/hooks.json", "codex"),
        (".factory/hooks.json", "factory"),
    ):
        _rewrite_managed_hooks_file(root / relative, harness, engine, root, shlex)
    for relative in (".pi/extensions/loki.ts", ".loki/loki-shim.ts"):
        _rewrite_managed_shim_file(root / relative, engine)
    print(f"Managed engine: {engine}")
    print("Owner-writable installation is not an OS security boundary.")


def missing_engine_guard(root: str) -> str:
    """Shell prefix for an owned hook: pass with a note on a branch that does not have Loki.

    That is a checkout whose HEAD has no `.loki/loki.py` while another ref does. An engine deleted from the working
    tree that HEAD still tracks, or one that was never committed anywhere, still fails closed.
    """
    return (
        f'R={root}; [ -f "$R/.loki/loki.py" ] || '
        'git -C "$R" cat-file -e HEAD:.loki/loki.py 2>/dev/null || '
        '[ -z "$(git -C "$R" rev-list -1 --all -- .loki/loki.py 2>/dev/null)" ] || '
        "{ printf '%s\\n' 'loki: .loki/loki.py is not on this branch; Loki did not check this' >&2; "
        "exit 0; }; "
    )


def install_shell_guard(root: Path) -> None:
    import shlex

    for relative, harness in (
        (".claude/settings.json", "claude"),
        (".factory/hooks.json", "factory"),
    ):
        path = root / relative
        document = read_json_object(path)
        groups = document["hooks"] if harness == "claude" else document
        command = (
            f"{missing_engine_guard(shlex.quote(str(root)))}"
            f"{shlex.quote(sys.executable)} {shlex.quote(str(root / '.loki/loki.py'))} "
            f"--root {shlex.quote(str(root))} shell --harness {harness} || "
            "{ printf '%s\\n' 'loki: shell guard failed' >&2; exit 2; }"
        )
        entries = groups.setdefault("PreToolUse", [])
        entries[:] = [
            entry
            for entry in entries
            if not (
                entry.get("matcher") in {"Bash", "Execute"}
                and any(
                    " shell --harness " in handler.get("command", "")
                    for handler in entry.get("hooks", [])
                )
            )
        ]
        entries.append(
            {
                "matcher": "Execute" if harness == "factory" else "Bash",
                "hooks": [{"type": "command", "command": command, "timeout": 30}],
            }
        )
        write_json(path, document)
    for relative in (".pi/extensions/loki.ts", ".loki/loki-shim.ts"):
        path = root / relative
        source = path.read_text(encoding="utf-8")
        marker = '  for (const phase of ["tool_call", "tool_result"]) {'
        if source.count(marker) != 1:
            raise ValueError("shell adapter registration marker unavailable")
        registration = """  api.on("tool_call", async (event, ctx) => {
    if (!event || typeof event !== "object" || !("toolName" in event)) return;
    if (event.toolName !== "bash") return;
    try {
      const input = "input" in event ? event.input : undefined;
      const result = spawnSync("python3",
        [...checkerArgs(root), "shell", "--harness", "omp"],
        {cwd:root, encoding:"utf8", timeout:30000,
         input:JSON.stringify({cwd:ctx?.cwd, tool_name:"Bash", tool_input:input})});
      if (result.error || result.signal || result.status !== 0) {
        return {block:true,
          reason:result.stderr?.trim() || "loki: shell checker unavailable"};
      }
    } catch { return {block:true, reason:"loki: invalid shell event"}; }
  });
"""
        path.write_text(source.replace(marker, registration + marker), encoding="utf-8")


SHELL_UNSUPPORTED_MARKERS = (
    ">",
    "<",
    "`",
    "$",
    ";",
    "|",
    "&",
    "(",
    ")",
    "*",
    "?",
    "[",
    "]",
    "{",
    "}",
    "~",
    "#",
    "!",
)


def _check_shell_command_text(command: Any) -> str:
    if not isinstance(command, str) or not command.strip() or "\0" in command:
        raise ValueError("shell command must be a nonempty string")
    if len(command) > 4096 or any(
        ord(char) < 32 or ord(char) == 127 for char in command
    ):
        raise ValueError("shell command is too long or contains control characters")
    if any(marker in command for marker in SHELL_UNSUPPORTED_MARKERS):
        raise ValueError(
            "loki: shell syntax unsupported: redirects, substitutions "
            "and compound commands or expansions require review"
        )
    return command


def simple_shell_words(command: Any) -> list[str]:
    import shlex

    words = shlex.split(_check_shell_command_text(command))
    if not words or "=" in words[0] or "/" in words[0]:
        raise ValueError("shell command requires a plain executable name")
    return words


def _validate_shell_permission_path(name: Any) -> None:
    if (
        not isinstance(name, str)
        or not name
        or "\0" in name
        or "\\" in name
        or Path(name).is_absolute()
        or ".." in Path(name).parts
        or Path(name).as_posix() != name
    ):
        raise ValueError("shell permission paths must be canonical and relative")


def _validate_shell_grant(grant: Any) -> tuple[str, str]:
    if not isinstance(grant, dict) or set(grant) != {"command", "cwd", "inputs"}:
        raise ValueError("shell permissions require command, cwd and inputs")
    if simple_shell_words(grant["command"])[0] == "git":
        raise ValueError("shell permissions cannot override Git restrictions")
    inputs = grant["inputs"]
    if (
        not isinstance(inputs, list)
        or not 1 <= len(inputs) <= 64
        or any(not isinstance(name, str) for name in inputs)
    ):
        raise ValueError("shell permission inputs must list 1 to 64 files")
    for name in [grant["cwd"], *inputs]:
        _validate_shell_permission_path(name)
    if "." in inputs:
        raise ValueError("shell permission inputs must be files")
    return grant["command"], grant["cwd"]


def shell_permissions(config: dict[str, Any]) -> list[dict[str, Any]]:
    grants = config.get("shell_commands", [])
    if not isinstance(grants, list) or len(grants) > 64:
        raise ValueError("shell_commands must be a list of at most 64 permissions")
    seen = set()
    for grant in grants:
        key = _validate_shell_grant(grant)
        if key in seen:
            raise ValueError("duplicate shell permission")
        seen.add(key)
    return grants


def _validate_shell_cwd_path(directory: Any, root: Path) -> Path:
    if not isinstance(directory, str) or not directory or "\0" in directory:
        raise ValueError("shell cwd must be an absolute directory")
    cwd = Path(directory)
    if (
        not cwd.is_absolute()
        or cwd != cwd.resolve()
        or not cwd.is_relative_to(root)
        or not cwd.is_dir()
    ):
        raise ValueError("shell cwd must be a non-symlinked directory inside the root")
    return cwd


def shell_cwd(payload: dict[str, Any], harness: str, root: Path) -> Path:
    names = {
        "claude": {"Bash"},
        "factory": {"Execute"},
        "pi": {"bash", "Bash"},
        "omp": {"bash", "Bash"},
    }
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or tool_name not in names[harness]:
        raise ValueError("unexpected shell tool name")
    # Metadata cannot change cwd, environment or the command being admitted.
    fields = {
        "command",
        "description",
        "timeout",
        "run_in_background",
        "summary",
        "riskLevel",
        "riskLevelReason",
        "fireAndForget",
    }
    if payload["tool_input"].keys() - fields:
        raise ValueError("unsupported shell input fields")
    return _validate_shell_cwd_path(payload.get("cwd"), root)


def _load_shell_base_entries(
    root: Path, base: str, paths: list[str], deadline: float
) -> dict[str, list[str]]:
    entries = {}
    for row in git_output(
        root, ["ls-tree", "-z", base, "--", *paths], deadline=deadline
    ).split(b"\0"):
        if row:
            metadata, path = row.split(b"\t", 1)
            entries[os.fsdecode(path)] = metadata.decode("ascii").split()
    if any(
        name not in entries
        or entries[name][0] not in {"100644", "100755"}
        or entries[name][1] != "blob"
        for name in paths
    ):
        raise ValueError("shell permission inputs must be committed regular files")
    return entries


def _verify_shell_permission_inputs(
    root: Path,
    paths: list[str],
    entries: dict[str, list[str]],
    blobs: dict[str, bytes],
    deadline: float,
) -> str | None:
    remaining = 64 * 1024 * 1024 - sum(len(blob) for blob in blobs.values())
    for name in paths:
        command_timeout(deadline)
        path = root / name
        if path.resolve() != path:
            raise ValueError(f"shell permission input is symlinked: {name}")
        content, mode = candidate_content(root, name, remaining)
        remaining -= len(content) if content is not None else 0
        if content != blobs[entries[name][2]] or mode != entries[name][0]:
            evidence_finding("shell-permission-input-changed", name)
            return f"loki: shell permission input differs from base: {name}"
    return None


def reviewed_shell_violation(command: str, root: Path, cwd: Path) -> str | None:
    deadline = time.monotonic() + 20
    actual = os.fsdecode(
        git_output(root, ["rev-parse", "--show-toplevel"], deadline=deadline)
    ).rstrip("\n")
    if Path(actual).resolve() != root:
        raise ValueError("shell permissions require the repository root")
    base = (
        git_output(
            root,
            ["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
            deadline=deadline,
        )
        .decode("ascii")
        .strip()
    )
    config = base_policy(root, base, deadline=deadline) or {}
    grant = next(
        (
            item
            for item in shell_permissions(config)
            if item["command"] == command and root / item["cwd"] == cwd
        ),
        None,
    )
    if grant is None:
        evidence_finding("shell-command-review")
        return "loki: no committed permission for this exact shell command and cwd"
    paths = list(dict.fromkeys([".loki/loki.json", *grant["inputs"]]))
    entries = _load_shell_base_entries(root, base, paths, deadline)
    blobs = git_blobs(root, [entries[name][2] for name in paths], deadline=deadline)
    return _verify_shell_permission_inputs(root, paths, entries, blobs, deadline)


TEXT_REDIRECT_SUFFIXES = {".txt", ".md", ".log", ".rst", ".csv", ".tsv", ".adoc"}
PRINT_COMMANDS = {"echo", "printf"}


def shell_redirect(command: str) -> tuple[str, str] | None:
    """Split `command > target` or `>>`; None unless that is the only operator."""
    import shlex

    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens = None
    with contextlib.suppress(ValueError):
        tokens = list(lexer)
    if tokens is None:
        return None
    operators = [token for token in tokens if set(token) <= set("();<>|&")]
    if len(tokens) < 3 or operators != [tokens[-2]] or tokens[-2] not in (">", ">>"):
        return None
    return shlex.join(tokens[:-2]), tokens[-1]


def redirect_violation(target: str, root: Path, cwd: Path) -> str | None:
    """Printing into project notes is allowed; source and policy writes are not."""
    path = Path(os.path.abspath(cwd / target))
    if not path.is_relative_to(root) or path.resolve() != path:
        evidence_finding("shell-redirect-outside")
        return "loki: shell redirect target escapes the repository root"
    if message := protect_path(str(path), root, load_config(root)):
        return message
    relative = path.relative_to(root)
    if (
        path.suffix.lower() not in TEXT_REDIRECT_SUFFIXES
        or any(part.startswith(".") for part in relative.parts)
        or path.is_dir()
    ):
        evidence_finding("shell-redirect-write", relative.as_posix())
        return (
            f"loki: shell redirect into {relative.as_posix()} bypasses write "
            "checks; use file edit tools for source and configuration files"
        )
    return None


def _destructive_git_clean(options: set[str]) -> bool:
    return "--force" in options or any(
        option.startswith("-") and not option.startswith("--") and "f" in option
        for option in options
    )


def _destructive_git_push(options: set[str]) -> bool:
    return bool(
        options & {"-f", "--force", "--force-with-lease", "--delete", "--mirror"}
    ) or any(option.startswith((":", "+")) for option in options)


def destructive_git(words: list[str]) -> bool:
    command, options = (words[1] if len(words) > 1 else ""), set(words[2:])
    checks = {
        "reset": lambda: bool(options & {"--hard", "--merge", "--keep"}),
        "clean": lambda: _destructive_git_clean(options),
        "push": lambda: _destructive_git_push(options),
        "branch": lambda: "-D" in options or {"--delete", "--force"} <= options,
        "stash": lambda: bool(options & {"drop", "clear"}),
        "checkout": lambda: bool(options & {"--", ".", "-f", "--force"}),
    }
    if check := checks.get(command):
        return check()
    return command in {"restore", "rebase", "filter-branch", "update-ref"}


def _shell_redirect_violation(
    command: str, root: Path, cwd: Path
) -> tuple[bool, str | None]:
    redirect = shell_redirect(command)
    if redirect is None:
        return False, None
    printer, target = redirect
    with contextlib.suppress(ValueError):
        if simple_shell_words(printer)[0] in PRINT_COMMANDS:
            return True, redirect_violation(target, root, cwd)
    evidence_finding("shell-redirect-write")
    return (
        True,
        "loki: shell redirect from a command other than echo/printf "
        "requires review; use file edit tools for writes",
    )


def _git_shell_violation(words: list[str]) -> tuple[bool, str | None]:
    if len(words) >= 2 and words[1] in {"status", "diff", "log", "show", "rev-parse"}:
        if any(
            word.startswith(("--output", "--ext-diff", "--textconv", "--exec"))
            for word in words[2:]
        ):
            evidence_finding("shell-option-review")
            return True, "loki: shell Git option requires review"
        return True, None
    if destructive_git(words):
        evidence_finding("shell-destructive-git")
        return (
            True,
            f"loki: blocked destructive Git command `{' '.join(words[:4])}`: it can "
            "discard uncommitted work or rewrite history; ask the user to run it",
        )
    return False, None


def _is_safe_builtin_shell(words: list[str]) -> bool:
    return (words[0] in {"pwd", "whoami"} and len(words) == 1) or (
        words[0] in PRINT_COMMANDS
    )


def _parse_shell_words_or_error(command: Any) -> tuple[list[str] | None, str | None]:
    try:
        return simple_shell_words(command), None
    except ValueError as error:
        evidence_finding("shell-syntax-review")
        return None, str(error)


def _shell_words_violation(
    command: Any, words: list[str], root: Path | None, cwd: Path | None
) -> str | None:
    if words[0] == "git":
        handled, message = _git_shell_violation(words)
        if handled:
            return message
    if _is_safe_builtin_shell(words):
        return None
    if root is not None and cwd is not None and words[0] != "git":
        return reviewed_shell_violation(command, root, cwd)
    evidence_finding("shell-command-review")
    return "loki: shell command requires review; use verified file tools for writes"


def shell_violation(
    command: Any, *, root: Path | None = None, cwd: Path | None = None
) -> str | None:
    # Exact permissions authorize execution, not its transitive filesystem effects.
    if isinstance(command, str) and root is not None and cwd is not None:
        handled, message = _shell_redirect_violation(command, root, cwd)
        if handled:
            return message
    words, syntax_error = _parse_shell_words_or_error(command)
    if words is None:
        return syntax_error
    return _shell_words_violation(command, words, root, cwd)


SHELL_WRITE_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
# Output a shell command may write into the project without Loki's check: prose and data, never source or config.
SHELL_WRITE_DATA_SUFFIXES = TEXT_REDIRECT_SUFFIXES | {".patch", ".diff", ".out", ".err"}
SHELL_COMMAND_PREFIXES = {"sudo", "env", "command", "time", "nice", "nohup", "exec"}


def strip_heredocs(command: str) -> str:
    """Drop here-document bodies, which are data, so the rest parses as shell words."""
    lines, out, delimiter = command.split("\n"), [], None
    for line in lines:
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        out.append(line)
        if found := re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line):
            delimiter = found.group(2)
    return "\n".join(out)


def _sed_inplace_targets(args: list[str]) -> list[tuple[str, str]]:
    files, scripted, skip = [], False, False
    for arg in args:
        if skip:
            skip = False
        elif arg in {"-e", "-f", "--expression", "--file"}:
            scripted = skip = True
        elif not arg.startswith("-"):
            files.append(arg)
    return [(arg, "sed -i") for arg in (files if scripted else files[1:])]


def _perl_inplace_targets(args: list[str]) -> list[tuple[str, str]]:
    files, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg in {"-e", "-E"}:
            skip = True
        elif not arg.startswith("-"):
            files.append(arg)
    return [(arg, "perl -i") for arg in files]


def _copy_flag_targets(
    name: str, args: list[str], plain: list[str]
) -> list[tuple[str, str]] | None:
    if "-t" in args and args.index("-t") + 1 < len(args):
        directory = args[args.index("-t") + 1]
        sources = [arg for arg in plain if arg != directory]
        return [(str(Path(directory) / Path(src).name), name) for src in sources]
    return None


def _copy_write_targets(
    name: str, args: list[str], plain: list[str]
) -> list[tuple[str, str]]:
    if (flagged := _copy_flag_targets(name, args, plain)) is not None:
        return flagged
    if len(plain) < 2:
        return []
    destination = plain[-1]
    if len(plain) > 2 or destination.endswith("/") or Path(destination).is_dir():
        return [(str(Path(destination) / Path(src).name), name) for src in plain[:-1]]
    return [(destination, name)]


def _is_sed_inplace(args: list[str]) -> bool:
    return any(arg == "-i" or arg.startswith(("-i", "--in-place")) for arg in args)


def _is_perl_inplace(args: list[str]) -> bool:
    return any(re.fullmatch(r"-[a-zA-Z]*i\S*", arg) for arg in args)


def _dd_write_targets(args: list[str]) -> list[tuple[str, str]]:
    return [(arg[3:], "dd") for arg in args if arg.startswith("of=")]


def _inplace_write_targets(name: str, args: list[str]) -> list[tuple[str, str]]:
    if name == "sed" and _is_sed_inplace(args):
        return _sed_inplace_targets(args)
    if name == "perl" and _is_perl_inplace(args):
        return _perl_inplace_targets(args)
    return []


def _shell_command_write_targets(name: str, args: list[str]) -> list[tuple[str, str]]:
    plain = [arg for arg in args if not arg.startswith("-")]
    if name == "tee":
        return [(arg, "tee") for arg in plain]
    if name in {"sed", "perl"}:
        return _inplace_write_targets(name, args)
    if name in {"cp", "mv", "install"}:
        return _copy_write_targets(name, args, plain)
    if name == "dd":
        return _dd_write_targets(args)
    return []


def _shell_write_tokens(command: str) -> list[str] | None:
    import shlex

    lexer = shlex.shlex(strip_heredocs(command), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens = None
    with contextlib.suppress(ValueError):
        tokens = list(lexer)
    return tokens


def _strip_shell_prefixes(words: list[str]) -> None:
    while words and (
        ("=" in words[0] and not words[0].startswith("-"))
        or words[0] in SHELL_COMMAND_PREFIXES
    ):
        words.pop(0)


def _update_shell_cd(name: str, args: list[str], moved: str) -> str:
    moves = [arg for arg in args if arg not in {"-L", "-P", "-e", "-@", "--"}]
    if name != "popd" and len(moves) == 1 and moves[0] != "-":
        return os.path.join(moved, moves[0])
    return "$CD"


def _place_shell_targets(
    targets: list[tuple[str, str]], placed: int, moved: str
) -> int:
    if moved:
        targets[placed:] = [
            (os.path.join(moved, target), how) for target, how in targets[placed:]
        ]
    return len(targets)


def _flush_shell_words(
    words: list[str], targets: list[tuple[str, str]], placed: int, moved: str
) -> tuple[int, str]:
    _strip_shell_prefixes(words)
    if not words:
        return placed, moved
    name, args = Path(words[0]).name, words[1:]
    words.clear()
    if name in {"cd", "pushd", "popd"}:
        return placed, _update_shell_cd(name, args, moved)
    targets.extend(_shell_command_write_targets(name, args))
    return _place_shell_targets(targets, placed, moved), moved


def _is_redirect_operator(token: str) -> bool:
    return token in {">", ">>", ">|", "&>", "&>>"} or (
        token.endswith((">", ">>")) and set(token) <= set("<>&|;()")
    )


def _apply_shell_scopes(token: str, moved: str, scopes: list[str]) -> str:
    for char in token:
        if char == "(":
            scopes.append(moved)
        elif char == ")" and scopes:
            moved = scopes.pop()
    return moved


def _is_fd_redirect(tokens: list[str], index: int) -> bool:
    return (
        tokens[index].isdigit()
        and index + 1 < len(tokens)
        and tokens[index + 1] in {">", ">>"}
    )


def shell_write_targets(command: str) -> list[tuple[str, str]] | None:
    """The files a shell command writes, as (target, how); None when it cannot be parsed.

    Covers redirects (`>`, `>>`, `>|`, `&>`), here-documents written to a file, `tee`, in-place `sed -i` and
    `perl -i`, `cp`/`mv`/`install` destinations and `dd of=`. Writes a program makes itself are not visible here.
    """
    tokens = _shell_write_tokens(command)
    if tokens is None:
        return None
    targets: list[tuple[str, str]] = []
    words: list[str] = []
    moved, placed, scopes, index = "", 0, [], 0
    while index < len(tokens):
        token = tokens[index]
        if _is_redirect_operator(token):
            if index + 1 < len(tokens):
                targets.append((tokens[index + 1], "redirect"))
                placed = _place_shell_targets(targets, placed, moved)
            index += 2
            continue
        if set(token) <= set("();<>|&"):
            placed, moved = _flush_shell_words(words, targets, placed, moved)
            moved = _apply_shell_scopes(token, moved, scopes)
            index += 1
            continue
        if not _is_fd_redirect(tokens, index):
            words.append(token)
        index += 1
    _flush_shell_words(words, targets, placed, moved)
    return [
        (target, how)
        for target, how in targets
        if target not in SHELL_WRITE_SINKS
        and not target.startswith(("/dev/fd/", "/proc/self/fd/"))
    ]


def _shell_write_target_violation(
    target: str, how: str, root: Path, cwd: Path, config: dict[str, Any]
) -> str | None:
    if any(marker in target for marker in ("$", "`", "*", "?", "~")):
        return None
    path = Path(os.path.abspath(cwd / target))
    if not path.is_relative_to(root):
        return None
    relative = path.relative_to(root)
    if message := protect_path(str(path), root, config):
        return message
    if path.suffix.lower() in SHELL_WRITE_DATA_SUFFIXES and not any(
        part.startswith(".") for part in relative.parts
    ):
        return None
    if git_ignored(root, relative.as_posix()):
        return None
    evidence_finding("shell-write", relative.as_posix())
    return (
        f"loki: `{how}` into {relative.as_posix()} would skip Loki's write check; "
        "write source and configuration files with the file edit tools (Ultron: edit()/write())"
    )


def shell_writes_violation(command: Any, root: Path, cwd: Path) -> str | None:
    """Deny a shell command that writes source or configuration inside the project: those writes skip Loki's
    before-write check, so they go through the harness's file tools instead. Notes, logs, ignored output and
    files outside the project are allowed, and so is every command that writes no file."""
    if not isinstance(command, str) or not command.strip():
        return None
    targets = shell_write_targets(command)
    if not targets:
        return None
    root = root.resolve()
    config = load_config(root)
    for target, how in targets:
        if message := _shell_write_target_violation(target, how, root, cwd, config):
            return message
    return None


def git_ignored(root: Path, relative: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-q", "--", relative],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _parse_transaction_op_names(operation: Any) -> tuple[str, list[str]]:
    if not isinstance(operation, dict) or operation.get("op") not in {
        "write",
        "delete",
        "move",
    }:
        raise ValueError("operation must be write, delete or move")
    path = valid_path(operation.get("path"))
    if Path(path).as_posix() != path:
        raise ValueError("transaction paths must use canonical POSIX spelling")
    names = [path]
    if operation["op"] == "move":
        names.append(valid_path(operation.get("to")))
        if names[1] == path or Path(names[1]).as_posix() != names[1]:
            raise ValueError("move requires a distinct canonical destination")
    return operation["op"], names


def _plan_one_transaction_op(
    root: Path,
    operation: Any,
    config: dict[str, Any],
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
) -> None:
    op, names = _parse_transaction_op_names(operation)
    path = names[0]
    for name in names:
        _validate_transaction_target(
            root, name, config, desired, originals, desired_modes
        )
    if op == "write":
        if not isinstance(operation.get("content"), str):
            raise ValueError("write content must be a string")
        desired[path] = operation["content"].encode("utf-8")
        return
    if originals[path][0] is None:
        raise ValueError(f"transaction source is missing: {path}")
    desired[path] = None
    if op == "move":
        destination = names[1]
        if originals[destination][0] is not None:
            raise ValueError("move destination already exists")
        desired[destination] = originals[path][0]
        desired_modes[destination] = originals[path][1] or "100644"


def _plan_transaction_operations(
    root: Path, operations: list[Any], config: dict[str, Any]
) -> tuple[
    dict[str, bytes | None],
    dict[str, tuple[bytes | None, str | None]],
    dict[str, str],
]:
    desired: dict[str, bytes | None] = {}
    originals: dict[str, tuple[bytes | None, str | None]] = {}
    desired_modes: dict[str, str] = {}
    for operation in operations:
        _plan_one_transaction_op(
            root, operation, config, desired, originals, desired_modes
        )
    return desired, originals, desired_modes


def _validate_transaction_target(
    root: Path,
    name: str,
    config: dict[str, Any],
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
) -> None:
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("transaction paths must be repository-relative")
    if Path(name).parts[0] in {".git", "node_modules"}:
        raise ValueError("transaction cannot mutate Git metadata or dependencies")
    parent = (root / name).parent
    if parent.resolve() != parent:
        raise ValueError("transaction symlinked parents are unsupported")
    if name in desired:
        raise ValueError(f"duplicate transaction target: {name}")
    if reason := protect_path(name, root, config, allow_override=False):
        raise ValueError(reason)
    originals[name] = candidate_content(root, name, 64 * 1024 * 1024)
    if originals[name][1] == "120000":
        raise ValueError("transaction symlink targets are unsupported")
    desired_modes[name] = originals[name][1] or "100644"


def _build_transaction_workspace(
    root: Path,
    directory: str,
    base: str,
    existing: list[FileChange],
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
    deadline: float,
) -> Path:
    workspace = Path(directory) / "candidate"
    materialize_base(root, base, workspace, deadline=deadline)
    for change in existing:
        apply_snapshot_change(workspace, change)
    for name, content in desired.items():
        mode = desired_modes[name]
        apply_snapshot_change(
            workspace,
            FileChange(
                name,
                originals[name][0],
                content,
                originals[name][1],
                mode if content is not None else None,
            ),
        )
    # Materialize the real base, then overlay proposed bytes.
    git_output(workspace, ["init"], deadline=deadline)
    baseline = Path(directory) / "baseline"
    materialize_base(root, base, baseline, deadline=deadline)
    git_output(baseline, ["init"], deadline=deadline)
    git_output(baseline, ["add", "."], deadline=deadline)
    git_output(
        baseline,
        [
            "-c",
            "user.name=Loki",
            "-c",
            "user.email=loki@example.invalid",
            "commit",
            "-m",
            "isolated base",
        ],
        deadline=deadline,
    )
    shutil.rmtree(workspace / ".git")
    shutil.copytree(baseline / ".git", workspace / ".git")
    if (root / "node_modules").is_dir():
        (workspace / "node_modules").symlink_to(
            (root / "node_modules").resolve(), target_is_directory=True
        )
    return workspace


def _check_transaction_candidate(
    root: Path,
    directory: str,
    base: str,
    existing: list[FileChange],
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
    config: dict[str, Any],
    deadline: float,
) -> None:
    workspace = _build_transaction_workspace(
        root, directory, base, existing, desired, originals, desired_modes, deadline
    )
    findings = write_guardrail_violations(
        [workspace / name for name in desired],
        workspace,
        config,
        deadline=deadline,
    )
    if any(Path(name).suffix in TYPESCRIPT_SUFFIXES for name in desired):
        findings.extend(typescript_findings(workspace, config, deadline=deadline))
    python_targets = [
        workspace / name
        for name, content in desired.items()
        if content is not None and name.endswith(".py")
    ]
    checked_projects: set[tuple[str, Path]] = set()
    for target in python_targets:
        findings.extend(
            check_file(
                target,
                workspace,
                config,
                True,
                deadline=deadline,
                batch_paths=python_targets,
                checked_projects=checked_projects,
            )
        )
    if findings:
        raise ValueError("; ".join(findings))


def _rollback_transaction(
    root: Path,
    applied: list[str],
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
    failure: OSError,
) -> None:
    unrecovered = []
    for name in reversed(applied):
        try:
            expected = (
                (desired[name], desired_modes[name])
                if desired[name] is not None
                else (None, None)
            )
            if candidate_content(root, name, 64 * 1024 * 1024) != expected:
                unrecovered.append(f"{name}: changed after application")
                continue
            original, mode = originals[name]
            if original is None:
                (root / name).unlink(missing_ok=True)
            else:
                (root / name).write_bytes(original)
                (root / name).chmod(0o755 if mode == "100755" else 0o644)
        except (OSError, ValueError) as error:
            unrecovered.append(f"{name}: {error}")
    if unrecovered:
        raise ValueError(
            f"transaction failed: {failure}; rollback incomplete: "
            + "; ".join(unrecovered)
        ) from failure


def _commit_transaction_files(
    root: Path,
    desired: dict[str, bytes | None],
    originals: dict[str, tuple[bytes | None, str | None]],
    desired_modes: dict[str, str],
) -> None:
    applied: list[str] = []
    try:
        for name, content in desired.items():
            target = root / name
            if content is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(
                    prefix=".loki-write-", dir=target.parent
                )
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(content)
                        os.fchmod(
                            stream.fileno(),
                            0o755 if desired_modes[name] == "100755" else 0o644,
                        )
                    os.replace(temporary, target)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            applied.append(name)
    except OSError as failure:
        _rollback_transaction(root, applied, desired, originals, desired_modes, failure)
        raise


def _verify_transaction_unchanged(
    root: Path,
    base: str,
    existing: list[FileChange],
    originals: dict[str, tuple[bytes | None, str | None]],
    deadline: float,
) -> None:
    current_base, current_changes = git_changes(root, None, deadline=deadline)
    if current_base != base or current_changes != existing:
        raise ValueError("concurrent repository modification; retry transaction")
    # Recheck targets before mutation; the lock serializes Loki writers.
    for name, original in originals.items():
        if candidate_content(root, name, 64 * 1024 * 1024) != original:
            raise ValueError(f"concurrent target modification: {name}")


def apply_transaction(root: Path, manifest: Path, check_only: bool = False) -> None:
    import fcntl

    if manifest.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("transaction manifest exceeds 4 MiB")
    operations = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(operations, list) or not operations:
        raise ValueError("transaction requires a nonempty operation list")
    deadline = time.monotonic() + 20
    base, existing = git_changes(root, None, deadline=deadline)
    if base is None:
        raise ValueError("transaction requires committed base")
    config = base_policy(root, base, deadline=deadline) or load_config(root)
    if blocked := protected_change_violations(existing, config):
        raise ValueError("; ".join(blocked))
    desired, originals, desired_modes = _plan_transaction_operations(
        root, operations, config
    )
    git_dir = Path(
        os.fsdecode(git_output(root, ["rev-parse", "--absolute-git-dir"])).strip()
    )
    with (git_dir / "loki-transaction.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="loki-transaction-") as directory:
            _check_transaction_candidate(
                root,
                directory,
                base,
                existing,
                desired,
                originals,
                desired_modes,
                config,
                deadline,
            )
            _verify_transaction_unchanged(root, base, existing, originals, deadline)
            if check_only:
                print("Transaction checks passed; no files written")
                return
            _commit_transaction_files(root, desired, originals, desired_modes)
    print(f"Applied {len(desired)} targets; not an OS-atomic multi-file commit")


TYPESCRIPT_CHECKER = r"""
const path = require('node:path');
const fs = require('node:fs');
const compilers = new Map();
const parsedFiles = new Map();

function isThenable(checker, type) {
  return (type.isUnion() ? type.types : [type]).some(part => {
    const then = part.getProperty('then');
    return then !== undefined && checker.getTypeOfSymbol(then).getCallSignatures().length > 0;
  });
}

// Type-aware findings that plain linters without type information cannot see.
function semanticFindings(ts, program, root) {
  const checker = program.getTypeChecker();
  const found = [];
  for (const file of program.getSourceFiles()) {
    const relative = path.relative(root, file.fileName);
    if (file.isDeclarationFile || relative.startsWith('..') ||
        relative.split(path.sep).includes('node_modules')) continue;
    const visit = node => {
      if (ts.isExpressionStatement(node)) {
        const expression = node.expression;
        const callee = ts.isCallExpression(expression) &&
          ts.isPropertyAccessExpression(expression.expression)
          ? expression.expression.name.text : '';
        const handled = callee === 'catch' ||
          (callee === 'then' && expression.arguments.length > 1);
        if (!ts.isVoidExpression(expression) && !ts.isAwaitExpression(expression) &&
            !handled && (ts.isCallExpression(expression) || ts.isNewExpression(expression)) &&
            isThenable(checker, checker.getTypeAtLocation(expression))) {
          found.push([file, node, 'loki/floating-promise',
            'floating promise: this Promise is not awaited, returned, voided or ' +
            'handled with .catch, so its rejection is lost']);
        }
      }
      if (ts.isCallExpression(node) && node.arguments.length === 0 &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === 'sort') {
        const receiver = checker.getTypeAtLocation(node.expression.expression);
        const element = checker.isArrayType(receiver)
          ? checker.getTypeArguments(receiver)[0] : undefined;
        if (element && (element.flags & (ts.TypeFlags.NumberLike | ts.TypeFlags.BigIntLike))) {
          found.push([file, node, 'loki/numeric-sort',
            'numeric array sorted without a comparator is ordered lexicographically ' +
            '(10 before 9); pass (a, b) => a - b']);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return found.map(([file, node, code, message]) => {
    const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line;
    return [path.relative(root, file.fileName), code, message,
      file.text.split(/\r?\n/)[line].trim(), line];
  });
}

function check(compilerPath, root, trusted, overridesPath, shadow) {
  if (!compilers.has(compilerPath)) compilers.set(compilerPath, require(compilerPath));
  const ts = compilers.get(compilerPath);
  const configPath = path.join(root, 'tsconfig.json');
  const read = ts.readConfigFile(configPath, file => file === configPath && trusted
    ? fs.readFileSync(trusted, 'utf8') : ts.sys.readFile(file));
  if (read.error) throw new Error(
    ts.flattenDiagnosticMessageText(read.error.messageText, '\n'));
  const confined = file => {
    const relative = path.relative(root, path.resolve(file));
    if (relative === '..' || relative.startsWith('../') || path.isAbsolute(relative))
      throw new Error('TypeScript configuration escapes isolated workspace');
  };
  const configHost = {...ts.sys,
    readFile(file) { confined(file); return ts.sys.readFile(file); },
    fileExists(file) { confined(file); return ts.sys.fileExists(file); }
  };
  const parsed = ts.parseJsonConfigFileContent(read.config, configHost, root,
    {noEmit:true, incremental:false}, configPath);
  if (parsed.errors.length) throw new Error(parsed.errors.map(d =>
    ts.flattenDiagnosticMessageText(d.messageText, '\n')).join('\n'));
  // Default type roots walk up past the repository; keep them inside it.
  if (parsed.options.typeRoots === undefined)
    parsed.options.typeRoots = [path.join(root, 'node_modules', '@types')];
  const host = ts.createCompilerHost(parsed.options);
  const compilerRoot = path.dirname(path.dirname(path.resolve(compilerPath)));
  const readable = file => {
    const full = path.resolve(file);
    if (full.startsWith(compilerRoot + path.sep)) return;
    confined(full);
  };
  // Proposed contents for pre-write checks, keyed by absolute path; never written.
  const overrides = overridesPath ? JSON.parse(fs.readFileSync(overridesPath, 'utf8')) : {};
  const proposed = file => Object.hasOwn(overrides, path.resolve(file));
  const originalRead = host.readFile;
  const originalExists = host.fileExists;
  host.fileExists = file => {
    if (proposed(file)) return true;
    try { readable(file); } catch { return false; }
    return originalExists(file);
  };
  host.readFile = file => {
    if (proposed(file)) return overrides[path.resolve(file)];
    readable(file);
    return originalRead(file);
  };
  // A long-lived checker reuses parsed files, including the standard library.
  host.getSourceFile = (file, version) => {
    const text = host.readFile(file);
    if (text === undefined) return undefined;
    const key = `${version}\0${file}`;
    const cached = parsedFiles.get(key);
    if (cached !== undefined && cached.text === text) return cached;
    if (parsedFiles.size > 20000) parsedFiles.clear();
    const parsedFile = ts.createSourceFile(file, text, version);
    parsedFiles.set(key, parsedFile);
    return parsedFile;
  };
  // New proposed files: match them against include/exclude from an empty shadow tree.
  if (shadow) {
    try {
      const extra = ts.parseJsonConfigFileContent(read.config, ts.sys, shadow,
        {noEmit:true}, path.join(shadow, 'tsconfig.json'));
      for (const file of extra.fileNames) {
        const real = path.join(root, path.relative(shadow, file));
        if (proposed(real) && !parsed.fileNames.includes(real)) parsed.fileNames.push(real);
      }
    } catch {
      // Unmatched new files are reported as uncovered and checked after the write.
    }
  }
  const program = ts.createProgram(parsed.fileNames, parsed.options, host);
  const uncovered = Object.keys(overrides).filter(file =>
    /\.[cm]?tsx?$/.test(file) && !program.getSourceFile(file));
  const diagnostics = ts.getPreEmitDiagnostics(program).map(d => {
    const file = d.file ? path.relative(root, d.file.fileName) : '';
    const line = d.file && d.start !== undefined
      ? d.file.getLineAndCharacterOfPosition(d.start).line : -1;
    const text = line >= 0 ? d.file.text.split(/\r?\n/)[line].trim() : '';
    return [file, d.code, ts.flattenDiagnosticMessageText(d.messageText, '\n'), text,
      line];
  });
  return {diagnostics: [...diagnostics, ...semanticFindings(ts, program, root)], uncovered};
}

if (process.argv[1] === '--serve') {
  const lines = require('node:readline').createInterface({input: process.stdin});
  lines.on('line', line => {
    const {id, args} = JSON.parse(line);
    let reply;
    try { reply = {id, result: check(...args)}; }
    catch (error) { reply = {id, error: String(error && error.message || error)}; }
    process.stdout.write(JSON.stringify(reply) + '\n');
  });
} else {
  console.log(JSON.stringify(check(...process.argv.slice(1, 6))));
}
"""


def typescript_diagnostics(
    compiler: Path,
    workspace: Path,
    trusted: Path | None,
    deadline: float | None,
    overrides: Path | None = None,
    shadow: Path | None = None,
) -> tuple[Counter[tuple], dict[tuple, int], list[str]]:
    """Diagnostics, their first lines, and proposed TypeScript files not checked."""
    arguments = [str(compiler.resolve()), str(workspace), str(trusted or "")]
    arguments += [str(overrides or ""), str(shadow or "")]
    worker = TYPESCRIPT_WORKERS.get(arguments[0])
    if worker is not None:
        try:
            return typescript_report(worker.request(arguments, deadline))
        except (OSError, ValueError, subprocess.TimeoutExpired):
            TYPESCRIPT_WORKERS.pop(arguments[0], None)
    result = subprocess.run(
        ["node", "-e", TYPESCRIPT_CHECKER, *arguments],
        cwd=workspace,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=command_timeout(deadline),
        check=False,
    )
    if result.returncode:
        raise ValueError(f"typescript: checker unavailable: {result.stderr.strip()}")
    return typescript_report(json.loads(result.stdout))


def typescript_report(
    report: dict[str, Any],
) -> tuple[Counter[tuple], dict[tuple, int], list[str]]:
    found: Counter[tuple] = Counter()
    lines: dict[tuple, int] = {}
    for file, code, message, text, line in report["diagnostics"]:
        found[(file, code, message, text)] += 1
        lines.setdefault((file, code, message, text), line + 1)
    return found, lines, report["uncovered"]


def typescript_state(
    root: Path,
    base: str,
    config: bytes,
    changes: list[FileChange],
    overrides: dict[str, str] | None,
) -> Path:
    """Marker path naming one exact candidate tree: base, config and changes."""
    import hashlib

    files = {change.path: change.after for change in changes}
    files.update(
        {name: text.encode("utf-8") for name, text in (overrides or {}).items()}
    )
    digest = hashlib.sha256(f"{base}\0".encode() + hashlib.sha256(config).digest())
    for name in sorted(files):
        content = files[name]
        digest.update(hashlib.sha256(os.fsencode(name)).digest())
        digest.update(b"-" if content is None else hashlib.sha256(content).digest())
    identity = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:16]
    return Path.home() / ".cache/loki/typescript" / identity / digest.hexdigest()


JSONC_TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|,(?=\s*[}\]])', re.S)


def strip_jsonc(text: str) -> str:
    """tsconfig's JSON dialect as plain JSON: comments and trailing commas dropped."""
    return JSONC_TOKEN_RE.sub(lambda m: m[0] if m[0][0] == '"' else "", text)


def typescript_extends(raw: bytes | None) -> set[str] | None:
    """Repository paths the committed tsconfig.json extends; None when unreadable.

    Package names resolve into node_modules, which is refused separately.
    """
    config = None
    with contextlib.suppress(ValueError):
        config = json.loads(strip_jsonc(raw.decode("utf-8") if raw else ""))
    if config is None:
        return None
    targets = config.get("extends", []) if isinstance(config, dict) else []
    names = set()
    targets = [targets] if isinstance(targets, str) else targets
    for target in targets if isinstance(targets, list) else []:
        if isinstance(target, str) and target.startswith("."):
            path = os.path.normpath(target)
            names.update({path, f"{path}.json"})
    return names


def typescript_config_json(name: str, extends: set[str] | None) -> bool:
    """Whether a JSON file can change compiler options or module resolution.

    An unreadable committed tsconfig.json (comments, say) keeps every JSON file.
    """
    base = os.path.basename(name)
    return name.endswith(".json") and (
        extends is None
        or name in extends
        or base == "package.json"
        or base.startswith(("tsconfig", "jsconfig"))
    )


def _prepare_ts_overrides(
    root: Path, directory: str, overrides: dict[str, str] | None
) -> tuple[Path | None, Path | None]:
    if overrides is None:
        return None, None
    proposed = Path(directory) / "overrides.json"
    proposed.write_text(
        json.dumps({str(root / name): text for name, text in overrides.items()}),
        encoding="utf-8",
    )
    shadow = Path(directory) / "shadow"
    for name in overrides:
        if not (root / name).exists():
            (shadow / name).parent.mkdir(parents=True, exist_ok=True)
            (shadow / name).touch()
    return proposed, shadow if shadow.is_dir() else None


def _ts_base_diagnostics(
    root: Path,
    base: str,
    directory: str,
    compiler: Path,
    after: Counter[tuple],
    deadline: float | None,
) -> Counter[tuple]:
    texts = {}
    for name in {key[0] for key in after if key[0]}:
        try:
            texts[name] = git_output(
                root, ["show", f"{base}:{name}"], deadline=deadline
            ).decode("utf-8", errors="replace")
        except ValueError:
            texts[name] = ""
    if not possibly_existing(after, texts):
        return Counter()
    before = Path(directory) / "before"
    materialize_base(root, base, before, deadline=deadline)
    if (root / "node_modules").is_dir():
        (before / "node_modules").symlink_to(
            (root / "node_modules").resolve(), target_is_directory=True
        )
    previous, _, _ = typescript_diagnostics(compiler, before, None, deadline)
    return previous


def _ts_setup_result(message: str, notices: list[str] | None) -> list[str]:
    if notices is None:
        return [message]
    notices.append(message)
    return []


def _ts_config_change_message(
    changes: list[FileChange],
    overrides: dict[str, str] | None,
    extends: set[str] | None,
) -> str | None:
    for name in [*(change.path for change in changes), *(overrides or {})]:
        if typescript_config_json(name, extends):
            return f"{name}: JSON/config change requires separate review"
        if name.startswith("node_modules/"):
            return "typescript: dependency changes require separate review"
    return None


def _format_ts_delta(
    after: Counter[tuple], previous: Counter[tuple], lines: dict[tuple, int]
) -> list[str]:
    findings = []
    for key, count in (after - previous).items():
        path, code, message, _ = key
        evidence_finding(f"typescript:{code}", path)
        label = code if isinstance(code, str) else f"TS{code}"
        findings.extend([f"{path}:{lines[key]}: {label}: {message}"] * count)
    return findings


def _run_ts_comparison(
    root: Path,
    base: str,
    compiler: Path,
    raw: bytes,
    marker: Path,
    overrides: dict[str, str] | None,
    deadline: float | None,
) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="loki-typescript-") as directory:
        trusted = Path(directory) / "tsconfig.json"
        trusted.write_bytes(raw)
        proposed, shadow = _prepare_ts_overrides(root, directory, overrides)
        # Most edits are clean: build the base snapshot only when errors appear.
        after, lines, uncovered = typescript_diagnostics(
            compiler, root, trusted, deadline, proposed, shadow
        )
        if not after:
            # A proposed file outside the program was not checked: no marker.
            if overrides is not None and not uncovered:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
            return []
        previous = _ts_base_diagnostics(
            root, base, directory, compiler, after, deadline
        )
        return _format_ts_delta(after, previous, lines)


def typescript_violations(
    root: Path,
    *,
    deadline: float | None = None,
    notices: list[str] | None = None,
    overrides: dict[str, str] | None = None,
) -> list[str]:
    """Net-new project type errors, using the committed tsconfig.json.

    Setup problems are findings when the check is explicitly enabled, and
    notices when it runs by default. Overrides check proposed contents before
    a write; a clean result marks that exact tree, so the post-write hook for
    the same bytes does not compile it again.
    """
    compiler = typescript_compiler(root)
    if compiler is None:
        return _ts_setup_result(
            "typescript: required TypeScript compiler is missing", notices
        )
    base, changes = git_changes(root, None, deadline=deadline)
    if base is None:
        return _ts_setup_result("typescript: committed base required", notices)
    policy = base_policy(root, base, deadline=deadline) or {}
    if findings := protected_change_violations(changes, policy):
        return findings
    raw = None
    with contextlib.suppress(ValueError):
        raw = git_output(root, ["show", f"{base}:tsconfig.json"], deadline=deadline)
    if message := _ts_config_change_message(
        changes, overrides, typescript_extends(raw)
    ):
        return _ts_setup_result(message, notices)
    if raw is None:
        return _ts_setup_result("typescript: committed tsconfig.json required", notices)
    evidence_policy("base", "tsconfig.json", raw, base=base)
    marker = typescript_state(root, base, raw, changes, overrides)
    if overrides is None and marker.is_file():
        return []
    return _run_ts_comparison(root, base, compiler, raw, marker, overrides, deadline)


def preview_typescript(
    root: Path,
    config: dict[str, Any],
    changes: list[tuple[str, str, str]],
    *,
    deadline: float | None,
) -> list[str]:
    """Type-check proposed TypeScript before it lands; post-write reports gaps."""
    if (
        config.get("typescript_check") is False
        or not (root / "tsconfig.json").is_file()
    ):
        return []
    overrides = {
        name: new
        for name, _, new in changes
        if Path(name).suffix.lower() in TYPESCRIPT_SUFFIXES
    }
    if not overrides:
        return []
    with contextlib.suppress(OSError, ValueError, subprocess.TimeoutExpired):
        return typescript_violations(
            root, deadline=deadline, notices=[], overrides=overrides
        )
    return []


def typescript_findings(
    root: Path,
    config: dict[str, Any],
    *,
    deadline: float | None = None,
    warnings: list[str] | None = None,
) -> list[str]:
    """Explicit true/false wins; by default, check committed TypeScript projects."""
    setting = config.get("typescript_check")
    if setting is not None:
        return typescript_violations(root, deadline=deadline) if setting else []
    if not (root / "tsconfig.json").is_file():
        return []
    notices: list[str] = []
    try:
        findings = typescript_violations(root, deadline=deadline, notices=notices)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        findings, notices = [], [*notices, str(error).strip()[:300]]
    messages = [f"NOT CHECKED typescript types: {notice}" for notice in notices]
    if os.environ.get("LOKI_STRICT") == "1":
        return [*findings, *messages]
    if warnings is None:
        for message in messages:
            print(message, file=sys.stderr)
    else:
        warnings.extend(messages)
    return findings


def _parse_base_tree_entries(
    root: Path, base: str, deadline: float | None
) -> list[tuple[str, str, str]]:
    entries = []
    for row in git_output(root, ["ls-tree", "-r", "-z", base], deadline=deadline).split(
        b"\0"
    ):
        if not row:
            continue
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = os.fsdecode(raw_path)
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"isolated checks: unsupported base entry: {name}")
        if (
            Path(name).is_absolute()
            or ".." in Path(name).parts
            or name.startswith("node_modules/")
        ):
            raise ValueError(f"isolated checks: unsupported base path: {name}")
        entries.append((name, mode, oid))
    return entries


def materialize_base(
    root: Path, base: str, destination: Path, *, deadline: float | None = None
) -> None:
    destination.mkdir(parents=True)
    entries = _parse_base_tree_entries(root, base, deadline)
    blobs = git_blobs(root, [oid for _, _, oid in entries], deadline=deadline)
    for name, mode, oid in entries:
        if Path(name).name.startswith("tsconfig") and name.endswith(".json"):
            evidence_policy("base", name, blobs[oid], base=base)
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blobs[oid])
        path.chmod(0o755 if mode == "100755" else 0o644)


def apply_snapshot_change(root: Path, change: FileChange) -> None:
    path = root / change.path
    if change.after is None:
        path.unlink(missing_ok=True)
    elif change.after_mode in {"100644", "100755"}:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(change.after)
        path.chmod(0o755 if change.after_mode == "100755" else 0o644)
    else:
        raise ValueError(f"isolated checks: unsupported candidate entry: {change.path}")


def ruff_delta(
    raw: bytes,
    pairs: list[tuple[str, bytes, bytes]],
    *,
    deadline: float | None,
    ruff: list[str],
) -> list[str]:
    """Ruff findings present in each candidate but not its base, by line text."""
    import tempfile

    config = tomllib.loads(raw.decode("utf-8"))
    if "extend" in config:
        raise ValueError("net-new Ruff requires self-contained base .ruff.toml")
    with tempfile.TemporaryDirectory(prefix="loki-ruff-") as directory:
        trusted = Path(directory) / "ruff.toml"
        trusted.write_bytes(raw)
        violations = []
        for path, before, after in pairs:
            counts = []
            for content in (before, after):
                result = subprocess.run(
                    [
                        *ruff,
                        "check",
                        "--no-cache",
                        "--no-respect-gitignore",
                        "--config",
                        str(trusted),
                        "--output-format",
                        "json",
                        "--stdin-filename",
                        path,
                        "-",
                    ],
                    input=content,
                    cwd=directory,
                    capture_output=True,
                    timeout=command_timeout(deadline),
                    check=False,
                )
                if result.returncode not in (0, 1):
                    raise ValueError(
                        "Ruff unavailable: "
                        + result.stderr.decode("utf-8", errors="replace")
                    )
                diagnostics = json.loads(result.stdout)
                lines = content.decode("utf-8").splitlines()
                counts.append(
                    Counter(
                        (
                            item["code"],
                            item["message"],
                            lines[item["location"]["row"] - 1].strip()
                            if 0 < item["location"]["row"] <= len(lines)
                            else "",
                        )
                        for item in diagnostics
                    )
                )
            for (code, message, _), count in (counts[1] - counts[0]).items():
                evidence_finding(f"ruff:{code}", path)
                violations.extend([f"{path}: {code}: {message}"] * count)
        return violations


class MissingRuffConfig(ValueError):
    """No committed base or base .ruff.toml, so net-new Ruff has no trusted config."""


def _ruff_change_pairs(
    changes: list[FileChange], paths: set[str] | None
) -> list[tuple[str, bytes, bytes]]:
    return [
        (change.path, change.before or b"", change.after)
        for change in changes
        if (paths is None or change.path in paths)
        and change.path.endswith(".py")
        and change.after is not None
    ]


def ruff_new_violations(
    root: Path,
    reference: str | None,
    *,
    paths: set[str] | None = None,
    deadline: float | None = None,
) -> list[str]:
    gap = repository_gap(root, deadline=deadline)
    if gap is not None:
        raise MissingRuffConfig(gap)
    base, changes = git_changes(root, reference, deadline=deadline)
    if base is None:
        raise MissingRuffConfig("net-new Ruff requires a committed base")
    policy = base_policy(root, base, deadline=deadline)
    protected = protected_change_violations(changes, policy or {})
    if protected:
        return protected
    listed = git_output(
        root, ["ls-tree", "--name-only", base, "--", ".ruff.toml"], deadline=deadline
    )
    if not listed.strip():
        raise MissingRuffConfig("no committed .ruff.toml")
    raw = git_output(root, ["show", f"{base}:.ruff.toml"], deadline=deadline)
    evidence_policy("base", ".ruff.toml", raw, base=base)
    ruff = ruff_command(root) or ["ruff"]
    return ruff_delta(
        raw, _ruff_change_pairs(changes, paths), deadline=deadline, ruff=ruff
    )


def preview_ruff(
    root: Path, changes: list[tuple[str, str, str]], *, deadline: float | None
) -> list[str]:
    """Pre-write net-new Ruff with the committed config; post-write reports gaps."""
    pairs = [
        (path, old.encode("utf-8"), new.encode("utf-8"))
        for path, old, new in changes
        if path.endswith(".py")
    ]
    ruff = ruff_command(root) if pairs else None
    if not ruff:
        return []
    with contextlib.suppress(
        OSError, ValueError, subprocess.TimeoutExpired, tomllib.TOMLDecodeError
    ):
        raw = git_output(root, ["show", "HEAD:.ruff.toml"], deadline=deadline)
        evidence_policy("base", ".ruff.toml", raw, base="HEAD")
        return ruff_delta(raw, pairs, deadline=deadline, ruff=ruff)
    return []


def event_path(root: Path) -> Path:
    import hashlib

    identity = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()
    return Path.home() / ".local/state/loki" / identity / "events.jsonl"


def record_event(
    root: Path,
    operation: str,
    paths: list[str],
    outcome: str,
    started: float,
    *,
    evidence: dict[str, Any] | None = None,
) -> None:
    import fcntl
    import hashlib

    path = event_path(root)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    event = {
        "time": time.time(),
        "operation": operation,
        "outcome": outcome,
        "targets": paths,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "scope": "delivered event only",
        "engine_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "resolution": "inspect diagnostic; protected changes need independent review",
        "schema_version": 2,
        "findings": (evidence or {}).get("findings", []),
        "policies": (evidence or {}).get("policies", []),
    }
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if os.fstat(stream.fileno()).st_size > 4 * 1024 * 1024:
            stream.seek(0)
            stream.truncate()
            stream.write(
                json.dumps({"event": "retention-reset", "time": time.time()}) + "\n"
            )
        stream.write(json.dumps(event) + "\n")


def read_events(root: Path, limit: int) -> list[dict[str, Any]]:
    from collections import deque

    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    path = event_path(root)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in deque(stream, maxlen=limit)]


DAEMON_COMMANDS = {"protect", "hook", "shell"}
DAEMON_IDLE_SECONDS = 30 * 60
DAEMON_REQUEST_SECONDS = 60
TYPESCRIPT_WORKERS: dict[str, CheckerWorker] = {}
HYGIENE_WORKERS: dict[str, CheckerWorker] = {}
MYPY_DAEMON: tuple[str, Path] | None = None


def engine_digest() -> str:
    import hashlib

    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def daemon_paths(root: Path) -> tuple[Path, Path] | None:
    """Socket and lock paths for a repository, or None when the path is too long."""
    import hashlib

    identity = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:16]
    directory = Path.home() / ".cache/loki/d"
    socket_path = directory / identity
    # sockaddr_un holds 108 bytes including the terminating NUL.
    if len(os.fsencode(socket_path)) > 107:
        return None
    return socket_path, directory / f"{identity}.lock"


def daemon_root(argv: list[str]) -> Path:
    if "--root" in argv and argv.index("--root") + 1 < len(argv):
        return Path(argv[argv.index("--root") + 1]).resolve()
    return DEFAULT_ROOT.resolve()


def daemon_client(argv: list[str]) -> int | None:
    """Forward a hook to the repository's warm daemon; None means run locally.

    The daemon only changes where the engine runs, never what it decides:
    it must report the same engine digest, and any failure before a reply
    falls back to the in-process path.
    """
    import socket

    if os.environ.get("LOKI_DAEMON") == "0" or not DAEMON_COMMANDS & set(argv):
        return None
    root = daemon_root(argv)
    paths = daemon_paths(root)
    if paths is None:
        return None
    if not paths[0].exists():
        daemon_autostart(root, paths)
        return None
    raw = sys.stdin.read() if "--harness" in argv or "--preview" in argv else ""
    sys.stdin = io.StringIO(raw)
    request = {
        "engine": engine_digest(),
        "argv": argv,
        "stdin": raw,
        "cwd": os.getcwd(),
        "env": dict(os.environ),
    }
    reply = None
    with contextlib.suppress(OSError, ValueError):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(DAEMON_REQUEST_SECONDS)
            connection.connect(str(paths[0]))
            connection.sendall(json.dumps(request).encode("utf-8") + b"\n")
            connection.shutdown(socket.SHUT_WR)
            reply = json.loads(receive_all(connection))
    if not isinstance(reply, dict) or reply.get("stale") or "exit" not in reply:
        return None
    sys.stdout.write(reply["stdout"])
    sys.stderr.write(reply["stderr"])
    return int(reply["exit"])


def receive_all(connection: Any) -> bytes:
    chunks = []
    while chunk := connection.recv(65536):
        chunks.append(chunk)
    return b"".join(chunks)


def daemon_autostart(root: Path, paths: tuple[Path, Path]) -> None:
    """Start one detached daemon for this repository; never block the hook."""
    socket_path, lock = paths
    with contextlib.suppress(OSError):
        lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if time.time() - lock.stat().st_mtime < 120:
                return
            lock.unlink(missing_ok=True)
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--root", str(root)]
            + ["daemon", "serve"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )


class CheckerWorker:
    """A long-lived line-oriented JSON worker (TypeScript, codehygiene, nits)."""

    def __init__(
        self, command: list[str], cwd: Path, *, env: dict[str, str] | None = None
    ) -> None:
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.sequence = 0
        # Raw reads with our own buffer: select() cannot see buffered file data.
        self.pending = b""

    def readline(self, deadline: float | None) -> bytes:
        import select

        if self.process.stdout is None:
            raise ValueError("checker worker has no pipes")
        descriptor = self.process.stdout.fileno()
        while b"\n" not in self.pending:
            ready, _, _ = select.select([descriptor], [], [], command_timeout(deadline))
            if not ready:
                raise subprocess.TimeoutExpired("checker worker", 0)
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                raise ValueError("checker worker exited")
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        return line

    def request(
        self,
        arguments: Any,
        deadline: float | None,
        *,
        error_prefix: str = "typescript: checker unavailable",
    ) -> Any:
        # No poll(): request children are forks and cannot wait on the worker.
        # A dead worker shows up as a broken pipe or end of output instead.
        if self.process.stdin is None:
            raise ValueError("checker worker has no pipes")
        self.sequence += 1
        identity = f"{os.getpid()}-{self.sequence}"
        message = json.dumps({"id": identity, "args": arguments}) + "\n"
        try:
            self.process.stdin.write(message.encode("utf-8"))
            self.process.stdin.flush()
        except BrokenPipeError as error:
            raise ValueError("checker worker exited") from error
        while True:
            reply = json.loads(self.readline(deadline))
            # Replies for abandoned requests (a killed request child) are skipped.
            if reply.get("id") != identity:
                continue
            if "error" in reply:
                raise ValueError(f"{error_prefix}: {reply['error']}")
            return reply["result"]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def _prewarm_hygiene_worker(
    name: str,
    launchers: list[list[str]],
    driver: str,
    handshake: Any,
    deadline: float | None,
) -> None:
    env = hygiene_env()
    temp_dir = Path(tempfile.gettempdir())
    for launcher in launchers:
        try:
            worker = CheckerWorker([*launcher, "-I", "-c", driver], temp_dir, env=env)
        except OSError:
            continue
        try:
            worker.request(
                handshake, deadline, error_prefix=f"{name}: worker unavailable"
            )
            HYGIENE_WORKERS[name] = worker
            return
        except (OSError, ValueError, subprocess.TimeoutExpired):
            worker.close()


def prewarm_hygiene_workers(deadline: float | None) -> None:
    payload, _ = vendored_codehygiene_payload()
    if payload is not None:
        _prewarm_hygiene_worker(
            "hygiene",
            hygiene_launchers(),
            HYGIENE_SERVER_DRIVER,
            payload,
            deadline,
        )
    _prewarm_hygiene_worker(
        "nits",
        nits_launchers(),
        NITS_SERVER_DRIVER,
        "ping",
        deadline,
    )


def _prewarm_typescript(root: Path, deadline: float) -> None:
    compiler = typescript_compiler(root)
    if compiler is None or not (root / "tsconfig.json").is_file():
        return
    worker = CheckerWorker(["node", "-e", TYPESCRIPT_CHECKER, "--", "--serve"], root)
    TYPESCRIPT_WORKERS[str(compiler.resolve())] = worker
    try:
        worker.request([str(compiler.resolve()), str(root), "", "", ""], deadline)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"loki daemon: TypeScript worker unavailable: {error}", file=sys.stderr)
        worker.close()
        TYPESCRIPT_WORKERS.clear()


def _prewarm_dmypy(root: Path, deadline: float) -> None:
    global MYPY_DAEMON
    mypy = mypy_binary(root)
    dmypy = Path(mypy).with_name("dmypy") if mypy else None
    if dmypy is None or not dmypy.is_file():
        return
    state = mypy_state(root)
    status = state / "dmypy.json"
    start = [str(dmypy), "--status-file", str(status), "start", "--"]
    result = subprocess.run(
        [*start, *mypy_flags(state, daemon=True)],
        cwd=root,
        capture_output=True,
        timeout=command_timeout(deadline),
        check=False,
    )
    if result.returncode:
        print(f"loki daemon: dmypy unavailable: {result.stderr!r}", file=sys.stderr)
        return
    MYPY_DAEMON = (str(dmypy), status)
    sources = [
        path.relative_to(root).as_posix()
        for path in iter_source_files(root)
        if path.suffix == ".py"
    ][:200]
    if sources:
        mypy_run(root, sources, deadline=deadline)


def _prewarm_source_caches(root: Path) -> None:
    try:
        for path, text in repository_sources(root, limit=64 * 1024 * 1024).items():
            token_windows(path, text)
            content_rule_findings(path, text)
            if slop_language(path) == "python":
                python_imports(path, text)
                python_functions(path, text)
    except ValueError:
        WINDOW_CACHE.clear()
        CONTENT_MEMO.clear()


def _prewarm_build_caches(root: Path, deadline: float) -> None:
    warmers = []
    if (root / "go.mod").is_file() and shutil.which("go"):
        warmers.append(["go", "vet", "./..."])
        if shutil.which("golangci-lint"):
            warmers.append(["golangci-lint", "run", "./..."])
    if (root / "Cargo.toml").is_file() and shutil.which("cargo"):
        warmers.append(clippy_command(root / "target"))
    for command in warmers:
        try:
            subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                timeout=command_timeout(deadline),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            break


def prewarm(root: Path) -> None:
    """Load analyzers and fill build caches before the daemon accepts hooks."""
    deadline = time.monotonic() + 120
    _prewarm_typescript(root, deadline)
    _prewarm_dmypy(root, deadline)
    _prewarm_source_caches(root)
    _prewarm_build_caches(root, deadline)
    prewarm_hygiene_workers(deadline)


def daemon_stop_workers() -> None:
    for worker in TYPESCRIPT_WORKERS.values():
        worker.close()
    TYPESCRIPT_WORKERS.clear()
    for worker in HYGIENE_WORKERS.values():
        worker.close()
    HYGIENE_WORKERS.clear()
    if MYPY_DAEMON is not None:
        subprocess.run(
            [MYPY_DAEMON[0], "--status-file", str(MYPY_DAEMON[1]), "kill"],
            capture_output=True,
            timeout=10,
            check=False,
        )


def peer_uid(connection: Any) -> int | None:
    import socket
    import struct

    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


def daemon_request(request: dict[str, Any]) -> dict[str, Any]:
    """Run one hook invocation in this (forked) process, capturing its output."""
    import contextlib

    os.chdir(request["cwd"])
    os.environ.clear()
    os.environ.update(request["env"])
    sys.argv = ["loki", *request["argv"]]
    sys.stdin = io.StringIO(request["stdin"])
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            status = main()
        except SystemExit as error:
            status = error.code if isinstance(error.code, int) else 2
        except Exception as error:
            print(
                f"loki: daemon error: {type(error).__name__}: {error}", file=sys.stderr
            )
            status = 2
    return {"exit": status, "stdout": stdout.getvalue(), "stderr": stderr.getvalue()}


def daemon_command(action: str, root: Path) -> int:
    """serve runs in the foreground; start, stop and status manage it."""
    import socket

    if action == "serve":
        return daemon_serve(root)
    paths = daemon_paths(root)
    if paths is None:
        print("loki: daemon unavailable: socket path too long", file=sys.stderr)
        return 1
    running = False
    if paths[0].exists():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(2)
                probe.connect(str(paths[0]))
                if action == "stop":
                    probe.sendall(b'{"engine": "stop"}')
            running = True
        except OSError:
            running = False
    if action == "start" and not running:
        daemon_autostart(root, paths)
    print(f"loki daemon: {'running' if running else 'not running'} ({paths[0]})")
    return 0


def _handle_daemon_connection(connection: Any, engine: str) -> bool:
    """Handle one client connection; return True when the daemon should exit."""
    with connection:
        connection.settimeout(DAEMON_REQUEST_SECONDS)
        uid = peer_uid(connection)
        if uid is not None and uid != os.getuid():
            return False
        request = None
        with contextlib.suppress(OSError, ValueError):
            request = json.loads(receive_all(connection))
        if request is None:
            return False
        if request.get("engine") != engine:
            with contextlib.suppress(OSError):
                connection.sendall(b'{"stale": true}')
            return True
        daemon_dispatch(connection, request)
        return False


def daemon_serve(root: Path) -> int:
    import socket

    paths = daemon_paths(root)
    if paths is None:
        print("loki: daemon socket path too long", file=sys.stderr)
        return 1
    socket_path, lock = paths
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if socket_path.parent.stat().st_uid != os.getuid():
        print("loki: daemon directory is not owned by this user", file=sys.stderr)
        return 1
    engine = engine_digest()
    try:
        started = time.monotonic()
        prewarm(root)
        print(
            f"loki daemon: warmed in {time.monotonic() - started:.1f}s; "
            f"TypeScript workers {len(TYPESCRIPT_WORKERS)}, "
            f"hygiene workers {len(HYGIENE_WORKERS)}, "
            f"dmypy {'on' if MYPY_DAEMON else 'off'}",
            file=sys.stderr,
            flush=True,
        )
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        socket_path.unlink(missing_ok=True)
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(16)
        server.settimeout(30)
        idle_since = time.monotonic()
        while root.is_dir() and engine_digest() == engine:
            try:
                connection, _ = server.accept()
            except TimeoutError:
                if time.monotonic() - idle_since > DAEMON_IDLE_SECONDS:
                    break
                continue
            idle_since = time.monotonic()
            if _handle_daemon_connection(connection, engine):
                break
    finally:
        daemon_stop_workers()
        socket_path.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)
    return 0


def daemon_dispatch(connection: Any, request: dict[str, Any]) -> None:
    """Serve one request in a forked child; the parent keeps warm state intact."""
    pid = os.fork()
    if pid == 0:
        try:
            reply = daemon_request(request)
            connection.sendall(json.dumps(reply).encode("utf-8"))
        finally:
            os._exit(0)
    limit = time.monotonic() + DAEMON_REQUEST_SECONDS
    while time.monotonic() < limit:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            return
        time.sleep(0.002)
    os.kill(pid, 9)
    os.waitpid(pid, 0)


def cli() -> int:
    """Console entry point: the warm daemon when available, else in-process."""
    status = daemon_client(sys.argv[1:])
    return main() if status is None else status


if __name__ == "__main__":
    raise SystemExit(cli())
