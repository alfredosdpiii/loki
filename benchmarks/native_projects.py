"""Sensitivity run with native-language manifests instead of shared JS scaffolding."""

import hashlib
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from benchmarks import comprehensive  # noqa: E402

original_baseline = comprehensive.baseline
original_identity = comprehensive.identity
original_save = comprehensive.save


def native_case(case):
    if case["language"] != "python":
        return case
    return {
        **case,
        "base": {
            "pyproject.toml": (
                '[project]\nname = "guardrail-fixture"\nversion = "0.1.0"\n'
                'requires-python = ">=3.11"\n\n'
                "[tool.ruff]\n\n[tool.mypy]\ncheck_untyped_defs = true\n"
            ),
            **case["base"],
        },
    }


def baseline(root, case, product, sandbox, profile):
    original_write = comprehensive.write
    original_policy = comprehensive.reviewed_policy
    native = case["language"] in ("python", "go", "rust", "elixir")

    def write(target, name, content):
        if not (native and target == root and name == "package.json"):
            original_write(target, name, content)

    comprehensive.write = write
    if native:
        comprehensive.reviewed_policy = dict
    try:
        return original_baseline(root, native_case(case), product, sandbox, profile)
    finally:
        comprehensive.write = original_write
        comprehensive.reviewed_policy = original_policy


def identity(args):
    source = Path(__file__).resolve()
    return {
        **original_identity(args),
        str(source): hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def save(path, value):
    if path.name == "manifest.json":
        value = {
            **value,
            "configuration": (
                "Native manifests for Python/Go/Rust/Elixir; no JS package manifest "
                "or npm grant. Python pyproject declares Ruff and mypy. "
                "Other installed policies and corpus source are unchanged."
            ),
        }
    return original_save(path, value)


def main():
    comprehensive.baseline = baseline
    comprehensive.identity = identity
    comprehensive.save = save
    try:
        return comprehensive.main()
    finally:
        comprehensive.baseline = original_baseline
        comprehensive.identity = original_identity
        comprehensive.save = original_save


if __name__ == "__main__":
    raise SystemExit(main())
