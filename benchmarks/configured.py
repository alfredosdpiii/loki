"""Repeat the JS/TS corpus with Loki's documented project type-check opt-in."""

import hashlib
import json
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from benchmarks import comprehensive  # noqa: E402

original_baseline = comprehensive.baseline
original_identity = comprehensive.identity


def baseline(root, case, product, sandbox, profile):
    initial = original_baseline(root, case, product, sandbox, profile)
    if product == "loki" and case["language"] == "typescript":
        policy = root / ".loki/loki.json"
        config = json.loads(policy.read_text())
        config["typescript_check"] = True
        policy.write_text(json.dumps(config) + "\n")
        comprehensive.git(root, "add", ".loki/loki.json")
        comprehensive.git(root, "commit", "-m", "Enable reviewed project type checks")
        initial[".loki/loki.json"] = policy.read_bytes()
    return initial


def identity(args):
    source = Path(__file__).resolve()
    return {
        **original_identity(args),
        str(source): hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def main():
    comprehensive.baseline = baseline
    comprehensive.identity = identity
    try:
        return comprehensive.main()
    finally:
        comprehensive.baseline = original_baseline
        comprehensive.identity = original_identity


if __name__ == "__main__":
    raise SystemExit(main())
