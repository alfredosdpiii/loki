"""Run a controlled installed-hook workload; never claim multi-day observation."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(argv, root, **kwargs):
    return subprocess.run(
        argv, cwd=root, capture_output=True, text=True, timeout=30, **kwargs
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "loki.py"
    events = []
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="loki-dogfood-") as directory:
        root = Path(directory)
        assert run(["git", "init"], root).returncode == 0
        assert (
            run(
                [
                    sys.executable,
                    str(source),
                    "init",
                    "--dir",
                    directory,
                    "--shell-guard",
                ],
                root,
            ).returncode
            == 0
        )
        (root / "app.py").write_text("def answer():\n    return 42\n")
        assert run(["git", "add", "."], root).returncode == 0
        assert (
            run(
                [
                    "git",
                    "commit",
                    "-m",
                    "fixture baseline",
                ],
                root,
            ).returncode
            == 0
        )
        engine = root / ".loki/loki.py"
        for label, content, expected in [
            ("valid change", "def answer():\n    return 43\n", 0),
            ("undefined name", "def answer():\n    return missing\n", 2),
            ("repair", "def answer():\n    return 44\n", 0),
        ]:
            pre = run(
                [sys.executable, str(engine), "protect", "--file", "app.py"], root
            )
            assert pre.returncode == 0
            (root / "app.py").write_text(content)
            tick = time.monotonic()
            result = run(
                [sys.executable, str(engine), "hook", "--file", "app.py"], root
            )
            events.append(
                {
                    "task": label,
                    "expected_exit": expected,
                    "exit": result.returncode,
                    "ms": round((time.monotonic() - tick) * 1000, 2),
                    "diagnostic": result.stderr,
                }
            )
            assert result.returncode == expected, result.stderr
    report = {
        "started": started,
        "finished": time.time(),
        "scope": "controlled workload; not autonomous or multi-day",
        "engine_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "events": events,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
