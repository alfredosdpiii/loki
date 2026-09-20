"""Repeat matched pre-hook probes with the current language-rule fixtures."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from benchmarks import compare_hooks, language_rules  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interlinked", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--oxlint", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    checkout, node, oxlint = (
        path.resolve() for path in (args.interlinked, args.node, args.oxlint)
    )
    revision = compare_hooks.run(
        ["git", "rev-parse", "HEAD"], checkout, required=True
    ).stdout.strip()
    if revision != compare_hooks.PIN:
        parser.error("competitor revision differs from the benchmark pin")
    if compare_hooks.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        checkout,
        required=True,
    ).stdout.strip():
        parser.error("competitor tracked files must be clean")
    additional = [
        (
            f"rules: {name} {phase}",
            category,
            "Write",
            "source.test.ts" if name == "focused test" else "source.ts",
            content,
        )
        for name, _, defect, repair in language_rules.CASES["typescript"]
        for phase, category, content in (
            ("defect", "harmful", defect),
            ("repair", "legitimate", repair),
        )
    ]
    compare_hooks.CONTENT_CONTROLS = [*compare_hooks.CONTENT_CONTROLS, *additional]
    cases = [*compare_hooks.CASES, *compare_hooks.CONTENT_CONTROLS]
    if len({case[0] for case in cases}) != len(cases):
        raise ValueError("duplicate case labels")
    identity = {
        "interlinked_sha": revision,
        "interlinked_hook_sha256": hashlib.sha256(
            (checkout / "dist/hook-entry.js").read_bytes()
        ).hexdigest(),
        "interlinked_server_sha256": hashlib.sha256(
            (checkout / "dist/harness/server.js").read_bytes()
        ).hexdigest(),
        "loki_sha256": hashlib.sha256((SOURCE / "loki.py").read_bytes()).hexdigest(),
        "node_version": compare_hooks.run(
            [str(node), "--version"], checkout, required=True
        ).stdout.strip(),
        "oxlint_version": compare_hooks.run(
            [str(oxlint), "--version"], checkout, required=True
        ).stdout.strip(),
        "cases": cases,
        "runs": args.runs,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for profile, reviewed, analyzer in (
        ("analyzer-default-permissions", False, oxlint),
        ("analyzer-reviewed-test", True, oxlint),
        ("no-analyzer-reviewed-test", True, None),
    ):
        print(f"Running {profile}: {len(cases)} cases", flush=True)
        events, capabilities = compare_hooks.compare(
            checkout, node, args.runs, reviewed, analyzer, True
        )
        if (
            identity["loki_sha256"]
            != hashlib.sha256((SOURCE / "loki.py").read_bytes()).hexdigest()
        ):
            raise RuntimeError("engine changed during comparison")
        report = {
            **identity,
            "profile": profile,
            "scope": (
                "Claude pre-hooks, warm competitor daemon, no proposed tools executed"
            ),
            "loki_shell_guard": True,
            "analyzer_available": analyzer is not None,
            "loki_shell_permissions": (
                [compare_hooks.REVIEWED_TEST_COMMAND] if reviewed else []
            ),
            "events": events,
            "competitor_capabilities": capabilities,
        }
        destination = args.output_dir / f"{profile}.json"
        if destination.exists():
            raise FileExistsError(
                f"refusing to replace existing evidence: {destination}"
            )
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Saved {destination}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
