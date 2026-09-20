"""Compare delivered Claude pre-hooks, explicitly in Interlinked cold mode."""

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PIN = "a2d4e41fb1ccb0a6514e9e177170f0386e399f06"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interlinked", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--socket", type=Path)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be positive")
    if bool(args.workspace) != bool(args.socket):
        parser.error("warm runs require both --workspace and --socket")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=args.interlinked, text=True
    ).strip()
    if revision != PIN:
        parser.error(f"Interlinked must be pinned to {PIN}")
    source = Path(__file__).resolve().parents[1] / "loki.py"
    report = {
        "interlinked_sha": revision,
        "loki_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "mode": "warm pre-hooks"
        if args.socket
        else "cold pre-hooks; evaluator unavailable",
        "results": [],
    }
    with tempfile.TemporaryDirectory() as directory:
        root = args.workspace.resolve() if args.workspace else Path(directory)
        if not args.workspace:
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
        home = root / "home"
        home.mkdir(exist_ok=True)
        socket = args.socket.resolve() if args.socket else root / "absent.sock"
        env = {
            **os.environ,
            "HOME": str(home),
            "INTERLINKED_SOCKET": str(socket),
        }
        for case, path in [
            ("ordinary", "ordinary.txt"),
            ("outside", "../outside.txt"),
            ("hook-policy", ".claude/settings.json"),
        ]:
            payload = json.dumps(
                {
                    "cwd": str(root),
                    "session_id": "benchmark",
                    "tool_name": "Write",
                    "tool_input": {
                        "file_path": str(root / path),
                        "content": "ordinary content\n",
                    },
                }
            )
            for label, command in [
                (
                    "loki",
                    [sys.executable, str(source), "protect", "--harness", "claude"],
                ),
                (
                    "interlinked",
                    [
                        "node",
                        str(args.interlinked / "dist/hook-entry.js"),
                        "--runner",
                        "claude-code",
                        "--event",
                        "PreToolUse",
                        "--socket",
                        str(socket),
                    ],
                ),
            ]:
                samples = []
                for _ in range(args.runs):
                    started = time.perf_counter()
                    result = subprocess.run(
                        command,
                        cwd=root,
                        env=env,
                        input=payload,
                        text=True,
                        capture_output=True,
                        timeout=30,
                    )
                    samples.append((time.perf_counter() - started) * 1000)
                if "unknown runner" in result.stderr:
                    raise RuntimeError("invalid competitor runner protocol")
                output = json.loads(result.stdout) if result.stdout.strip() else {}
                decision = output.get("hookSpecificOutput", {}).get(
                    "permissionDecision"
                )
                report["results"].append(
                    {
                        "case": case,
                        "tool": label,
                        "exit": result.returncode,
                        "denied": result.returncode == 2 or decision == "deny",
                        "unavailable": "evaluator skipped" in result.stderr,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "median_ms": round(statistics.median(samples), 2),
                        "max_ms": round(max(samples), 2),
                    }
                )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
