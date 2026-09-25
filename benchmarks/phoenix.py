"""Installed-hook Phoenix benchmark. Analyze bad examples; never execute them."""

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
FIXTURE = SOURCE / "benchmarks/fixtures/phoenix"
CONTROLLER = "lib/loki_phoenix_fixture_web/input_controller.ex"
COMPONENT = "lib/loki_phoenix_fixture_web/components.ex"


def run(command, root, *, input=None, timeout=60, required=False):
    result = subprocess.run(
        command,
        cwd=root,
        input=input,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if required and result.returncode:
        raise RuntimeError(f"{command[0]} failed:\n{result.stderr}{result.stdout}")
    return result


def controller(body):
    return (
        "defmodule LokiPhoenixFixtureWeb.InputController do\n"
        "  @moduledoc false\n"
        "  use LokiPhoenixFixtureWeb, :controller\n\n"
        f"  {body}\nend\n"
    )


CASES = [
    (
        "unsafe deserialization",
        "Misc.BinToTerm",
        'def handle(_conn, %{"input" => input}), do: :erlang.binary_to_term(input)',
        'def handle(_conn, %{"input" => input}), do: Jason.decode!(input)',
    ),
    (
        "controller SQL injection",
        "SQL.Query",
        'def handle(_conn, %{"id" => id}), '
        'do: Repo.query("SELECT * FROM users WHERE id = #{id}")',
        'def handle(_conn, %{"id" => id}), '
        'do: Repo.query("SELECT * FROM users WHERE id = $1", [id])',
    ),
    (
        "controller code evaluation",
        "RCE.CodeModule",
        'def handle(_conn, %{"input" => input}), do: Code.eval_string(input)',
        'def handle(_conn, %{"input" => input}), do: Jason.decode!(input)',
    ),
    (
        "controller atom exhaustion",
        "DOS.StringToAtom",
        'def handle(_conn, %{"input" => input}), do: String.to_atom(input)',
        'def handle(_conn, %{"input" => input}), do: input in ["admin", "reader"]',
    ),
    (
        "caller-controlled URL",
        None,
        'def handle(_conn, %{"url" => url}), '
        "do: :httpc.request(String.to_charlist(url))",
        'def handle(_conn, _params), do: :httpc.request(~c"https://example.invalid/")',
    ),
    (
        "client-controlled authorization",
        None,
        'def handle(_conn, params), do: params["admin"] == true',
        "def handle(conn, _params), do: conn.assigns.current_user.admin?",
    ),
]


def benchmark(prepared, repetitions, block):
    if (prepared / "mix.exs").read_bytes() != (FIXTURE / "mix.exs").read_bytes():
        raise ValueError("prepared project must use the benchmark's pinned mix.exs")
    if (prepared / "mix.lock").read_bytes() != (FIXTURE / "mix.lock").read_bytes():
        raise ValueError("prepared project must use the benchmark's pinned mix.lock")
    events = []
    with tempfile.TemporaryDirectory(prefix="loki-phoenix-benchmark-") as directory:
        root = Path(directory)
        shutil.copytree(FIXTURE, root, dirs_exist_ok=True)
        for name in ("deps", "_build"):
            shutil.copytree(prepared / name, root / name, symlinks=True)
        (root / ".gitignore").write_text("deps/\n_build/\n")
        run(["git", "init"], root, required=True)
        run(
            [sys.executable, str(SOURCE / "loki.py"), "init", "--dir", str(root)],
            root,
            required=True,
        )
        policy_path = root / ".loki/loki.json"
        policy = json.loads(policy_path.read_text())
        policy["elixir_security"]["sobelow"] = {
            "block": block,
            "warn": "low" if block == "low" else "medium",
        }
        policy_path.write_text(json.dumps(policy))
        # A committed Sobelow suppression must not weaken Loki's source-security gate.
        (root / ".sobelow-conf").write_text(
            '[ignore: ["Misc.BinToTerm"], skip: true]\n'
        )
        run(["mix", "format"], root, required=True)
        run(["git", "add", "."], root, required=True)
        run(["git", "commit", "-m", "Phoenix benchmark baseline"], root, required=True)
        baseline = {
            name: (root / name).read_text()
            for name in (CONTROLLER, COMPONENT, "lib/old_debt.ex")
        }
        groups = json.loads((root / ".claude/settings.json").read_text())["hooks"]
        pre = groups["PreToolUse"][0]["hooks"][0]["command"]
        post = groups["PostToolUse"][0]["hooks"][0]["command"]
        nested = root / "lib"

        def evaluate(label, path, source, *, expected=None, rule=None):
            for name, content in baseline.items():
                (root / name).write_text(content)
            payload = json.dumps(
                {
                    "cwd": str(root),
                    "tool_name": "Write",
                    "tool_input": {"file_path": str(root / path)},
                }
            )
            admission = run(
                ["/bin/sh", "-c", pre], nested, input=payload, required=True
            )
            (root / path).write_text(source)
            run(["mix", "format", path], root, required=True)
            written = (root / path).read_bytes()
            timings, result = [], None
            for _ in range(repetitions):
                started = time.monotonic()
                result = run(["/bin/sh", "-c", post], nested, input=payload)
                timings.append(round((time.monotonic() - started) * 1000, 2))
            combined = result.stderr + result.stdout
            checked = "NOT CHECKED" not in combined
            matched = rule is not None and rule in combined
            event = {
                "case": label,
                "stage": "post-write",
                "pre_exit": admission.returncode,
                "exit": result.returncode,
                "coverage_available": checked,
                "expected_rule": rule,
                "targeted_finding": matched,
                "security_block": matched and result.returncode == 2,
                "expected_exit": expected,
                "expectation_met": (
                    checked
                    and (expected is None or result.returncode == expected)
                    and (rule is None or matched)
                ),
                "security_scope": (
                    "known coverage gap"
                    if expected is None
                    else "behavioral regression"
                ),
                "bytes_landed_before_check": True,
                "hook_preserved_written_bytes": written == (root / path).read_bytes(),
                "median_ms": statistics.median(timings),
                "samples_ms": timings,
                "diagnostic": result.stderr,
                "model_context": result.stdout,
            }
            events.append(event)
            return event

        evaluate(
            "valid edit with existing debt",
            CONTROLLER,
            baseline[CONTROLLER].replace("Jason.decode!", "Jason.decode"),
            expected=0,
        )
        evaluate(
            "old findings shifted down",
            "lib/old_debt.ex",
            baseline["lib/old_debt.ex"].replace(
                "defmodule OldDebt do\n",
                "defmodule OldDebt do\n  # Existing finding moved, not added.\n",
            ),
            expected=0,
        )
        for label, rule, bad, repair in CASES:
            evaluate(
                label,
                CONTROLLER,
                controller(bad),
                expected=(0 if block == "none" else 2) if rule else None,
                rule=rule,
            )
            evaluate(label + " repair", CONTROLLER, controller(repair), expected=0)
        evaluate(
            "plain helper code evaluation",
            CONTROLLER,
            controller("def handle(input), do: Code.eval_string(input)").replace(
                "  use LokiPhoenixFixtureWeb, :controller\n", ""
            ),
            expected=2 if block == "low" else 0,
            rule="RCE.CodeModule",
        )

        for name, content in baseline.items():
            (root / name).write_text(content)
        for label, source, expected, marker in (
            ("valid component", baseline[COMPONENT], 0, None),
            (
                "missing required component attr",
                baseline[COMPONENT].replace(' name="World"', ""),
                1,
                "required attribute",
            ),
            (
                "malformed HEEx",
                baseline[COMPONENT].replace("</p>", "</section>"),
                1,
                "unmatched closing tag",
            ),
            ("component repair", baseline[COMPONENT], 0, None),
        ):
            (root / COMPONENT).write_text(source)
            started = time.monotonic()
            result = run(
                [
                    sys.executable,
                    str(root / ".loki/loki.py"),
                    "elixir",
                    "--project",
                    str(root),
                    "--tier",
                    "project",
                    "--json",
                ],
                root,
            )
            report = json.loads(result.stdout)
            compile_check = next(item for item in report if item["tool"] == "compile")
            passed = compile_check["status"] == "PASS"
            targeted = marker is None or marker in compile_check["output"]
            events.append(
                {
                    "case": label,
                    "stage": "explicit project tier",
                    "compile_status": compile_check["status"],
                    "expected_compile_exit": expected,
                    "expectation_met": passed == (expected == 0) and targeted,
                    "whole_gate_exit": result.returncode,
                    "whole_gate_note": "Existing debt can fail other checks.",
                    "ms": round((time.monotonic() - started) * 1000, 2),
                    "checks": report,
                }
            )
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared-project", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument(
        "--sobelow-block", choices=("none", "low", "medium", "high"), default="high"
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    versions = {
        name: run([name, "--version"], SOURCE).stdout.strip()
        for name in ("elixir", "git")
    }
    report = {
        "scope": "installed commands, not live agents or production security",
        "engine_sha256": hashlib.sha256((SOURCE / "loki.py").read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256((FIXTURE / "mix.lock").read_bytes()).hexdigest(),
        "versions": versions,
        "environment": {"mix_env": os.environ.get("MIX_ENV", "dev")},
        "sobelow_block": args.sobelow_block,
        "events": benchmark(
            args.prepared_project.resolve(), args.runs, args.sobelow_block
        ),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    failures = [
        event["case"] for event in report["events"] if not event["expectation_met"]
    ]
    print(
        json.dumps(
            {
                "events": len(report["events"]),
                "failed_expectations": failures,
                "report": str(args.output),
            },
            indent=2,
        )
    )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
