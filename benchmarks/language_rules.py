"""Check language policies against defects and repairs without running fixture code."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import loki  # noqa: E402 - run the workspace engine

CASES = {
    "python": [
        (
            "dangling task",
            "RUF006",
            "import asyncio\n\n\nasync def run():\n    await asyncio.sleep(1)\n"
            "\nasync def start():\n    asyncio.create_task(run())\n",
            "import asyncio\n\n\nasync def run():\n    await asyncio.sleep(1)\n"
            "\nasync def start():\n    return asyncio.create_task(run())\n",
        ),
        (
            "direct logger construction",
            "LOG001",
            "import logging\n\nlogger = logging.Logger(__name__)\n",
            "import logging\n\nlogger = logging.getLogger(__name__)\n",
        ),
        ("stale suppression", "RUF100", "value = 1  # noqa: F821\n", "value = 1\n"),
        (
            "logging format mismatch",
            "PLE1205",
            "import logging\n\nlogger = logging.getLogger(__name__)\n"
            'logger.info("done", 1)\n',
            "import logging\n\nlogger = logging.getLogger(__name__)\n"
            'logger.info("done %s", 1)\n',
        ),
    ],
    "typescript": [
        (
            "async Promise executor",
            "no-async-promise-executor",
            "new Promise(async (resolve) => { resolve(1); });",
            "new Promise((resolve) => { resolve(1); });",
        ),
        (
            "ignored Promise executor return",
            "no-promise-executor-return",
            "new Promise((resolve) => { return 1; });",
            "new Promise((resolve) => { resolve(1); });",
        ),
        (
            "finally overrides failure",
            "no-unsafe-finally",
            "function run() { try { throw new Error(); } finally { return 1; } }",
            "function run() { try { throw new Error(); } finally { cleanup(); } }",
        ),
        (
            "unsafe optional chaining",
            "no-unsafe-optional-chaining",
            "const value = (item?.nested).value;",
            "const value = item?.nested?.value;",
        ),
        (
            "constant nullish condition",
            "no-constant-binary-expression",
            "const value = (item === 1) ?? false;",
            "const value = item ?? false;",
        ),
        ("debugger statement", "no-debugger", "debugger;", 'const text = "debugger;";'),
        (
            "focused test",
            "no-focused-tests",
            'import {test} from "vitest"; test.only("value", () => {});',
            'import {test} from "vitest"; test("value", () => {});',
        ),
    ],
    "go": [
        (
            "explicitly discarded error",
            "errcheck",
            'package main\nimport "os"\nfunc main() { _ = os.Remove("missing") }\n',
            'package main\nimport ("os"; "fmt")\n'
            'func main() { if err := os.Remove("missing"); err != nil '
            "{ fmt.Println(err) } }\n",
        ),
        (
            "unchecked type assertion",
            "errcheck",
            "package main\nfunc read(v any) string { return v.(string) }\n"
            'func main() { _ = read("value") }\n',
            "package main\nfunc read(v any) string { s, ok := v.(string); "
            'if !ok { return "" }; return s }\nfunc main() { _ = read("value") }\n',
        ),
        (
            "wrapped error comparison",
            "errorlint",
            'package main\nimport "io"\n'
            "func done(err error) bool { return err == io.ErrUnexpectedEOF }\n"
            "func main() { _ = done(nil) }\n",
            'package main\nimport ("io"; "errors")\n'
            "func done(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }\n"
            "func main() { _ = done(nil) }\n",
        ),
        (
            "discarded nonnil error",
            "nilerr",
            "package main\nfunc check(err error) error { "
            "if err != nil { return nil }; return nil }\n"
            "func main() { if err := check(nil); err != nil { panic(err) } }\n",
            "package main\nfunc check(err error) error { return err }\n"
            "func main() { if err := check(nil); err != nil { panic(err) } }\n",
        ),
        (
            "duration multiplied by duration",
            "durationcheck",
            'package main\nimport "time"\n'
            "func scale(delay time.Duration) time.Duration { "
            "return delay * time.Millisecond }\n"
            "func main() { _ = scale(time.Second) }\n",
            'package main\nimport "time"\n'
            "func scale(delay time.Duration) time.Duration { return delay }\n"
            "func main() { _ = scale(time.Second) }\n",
        ),
    ],
    "rust": [
        (
            "ignored Result",
            "unused_must_use",
            'pub fn run() { std::fs::read_to_string("input"); }\n',
            "pub fn run() -> std::io::Result<String> "
            '{ std::fs::read_to_string("input") }\n',
        ),
        (
            "panic through expect",
            "clippy::expect_used",
            'pub fn value(input: Option<u8>) -> u8 { input.expect("missing") }\n',
            "pub fn value(input: Option<u8>) -> u8 { input.unwrap_or(0) }\n",
        ),
    ],
    "elixir": [
        (
            "runtime atom creation",
            "UnsafeToAtom",
            "def value(input), do: String.to_atom(input)",
            "def value(input), do: String.to_existing_atom(input)",
        ),
        (
            "shell execution API",
            "UnsafeExec",
            "def value(input), do: :os.cmd(input)",
            'def value(input), do: System.cmd("echo", [input])',
        ),
        (
            "discarded immutable result",
            "UnusedEnumOperation",
            "def value(input) do\n    Enum.map(input, &String.trim/1)\n"
            "    input\n  end",
            "def value(input), do: Enum.map(input, &String.trim/1)",
        ),
    ],
}


def run(command, root):
    return subprocess.run(  # noqa: S603 - fixed analyzer commands in disposable fixtures
        command,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def analyze(language, source, root, args):
    if language == "python":
        (root / "app.py").write_text(source)
        return run(
            [
                "ruff",
                "check",
                "--config",
                str(SOURCE / "templates/.ruff.toml"),
                "--output-format",
                "json",
                "app.py",
            ],
            root,
        )
    if language == "typescript":
        if not args.oxlint:
            return None
        binary = root / "node_modules/.bin/oxlint"
        if not binary.exists():
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.symlink_to(args.oxlint.resolve())
        messages = loki.preview_oxlint(
            root, [("source.test.ts", "", source)], deadline=None
        )
        return subprocess.CompletedProcess(
            [], int(bool(messages)), "\n".join(messages), ""
        )
    if language == "go":
        if not args.golangci:
            return None
        (root / "go.mod").write_text("module example.invalid/loki/rules\n\ngo 1.25\n")
        (root / "main.go").write_text(
            "// Package main validates Loki rules.\n" + source
        )
        return run(
            [
                str(args.golangci.resolve()),
                "run",
                "--config",
                str(SOURCE / "templates/.golangci.yml"),
            ],
            root,
        )
    if language == "rust":
        (root / "Cargo.toml").write_text(
            '[package]\nname="loki_rule_fixture"\nversion="0.1.0"\nedition="2021"\n'
        )
        (root / "src").mkdir(exist_ok=True)
        (root / "src/lib.rs").write_text(source)
        _, commands = loki.scan_command("rust", [], root)
        command = commands[0]
        index = command.index("--")
        return run(
            [*command[:index], "--offline", "--message-format=json", *command[index:]],
            root,
        )
    if not args.credo_project:
        return None
    (root / "lib").mkdir(exist_ok=True)
    (root / "lib/rule_fixture.ex").write_text(
        "defmodule RuleFixture do\n  @moduledoc false\n  " + source + "\nend\n"
    )
    shutil.copyfile(SOURCE / "templates/.credo.exs", root / ".credo.exs")
    ebin = sorted((args.credo_project / "_build/dev/lib").glob("*/ebin"))
    if not any(path.parent.name == "credo" for path in ebin):
        raise ValueError("prepared Credo BEAM files are required")
    return run(
        [
            "elixir",
            *[part for path in ebin for part in ("-pa", str(path))],
            "-e",
            "Application.ensure_all_started(:credo); Credo.CLI.main(System.argv())",
            "--",
            "--strict",
            "--format",
            "json",
            "--config-file",
            str(root / ".credo.exs"),
        ],
        root,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oxlint", type=Path)
    parser.add_argument("--golangci", type=Path)
    parser.add_argument("--credo-project", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for language, cases in CASES.items():
        with tempfile.TemporaryDirectory(prefix=f"loki-rules-{language}-") as directory:
            root = Path(directory)
            for name, rule, defect, repair in cases:
                for phase, source in (("defect", defect), ("repair", repair)):
                    try:
                        result = analyze(language, source, root, args)
                        output = (result.stdout + result.stderr) if result else ""
                        passed = bool(
                            result is not None
                            and (
                                (
                                    result.returncode
                                    == {
                                        "rust": 101,
                                        "elixir": 16,
                                    }.get(language, 1)
                                    and rule in output
                                )
                                if phase == "defect"
                                else result.returncode == 0
                            )
                        )
                        status = result.returncode if result else None
                    except (
                        OSError,
                        ValueError,
                        IndexError,
                        subprocess.TimeoutExpired,
                    ) as error:
                        status, output, passed = None, str(error), False
                    results.append(
                        {
                            "language": language,
                            "case": name,
                            "phase": phase,
                            "rule": rule,
                            "exit": status,
                            "expectation_met": passed,
                            "output": output,
                        }
                    )
                    print(language, name, phase, "PASS" if passed else "FAIL")
    report = {
        "scope": (
            "shipped rules on isolated defects and repairs; no fixture code executed"
        ),
        "engine_sha256": hashlib.sha256((SOURCE / "loki.py").read_bytes()).hexdigest(),
        "policy_sha256": {
            name: hashlib.sha256((SOURCE / "templates" / name).read_bytes()).hexdigest()
            for name in (".ruff.toml", ".oxlintrc.json", ".golangci.yml", ".credo.exs")
        },
        "results": results,
    }
    versions = {
        "ruff": ["ruff", "--version"],
        "go": ["go", "version"],
        "clippy": ["cargo", "clippy", "--version"],
        "elixir": ["elixir", "--version"],
    }
    for name, binary in (("oxlint", args.oxlint), ("golangci", args.golangci)):
        if binary:
            versions[name] = [str(binary.resolve()), "--version"]
    report["versions"] = {}
    for name, command in versions.items():
        try:
            result = run(command, SOURCE)
            report["versions"][name] = {
                "exit": result.returncode,
                "output": (result.stdout + result.stderr).strip(),
            }
        except (OSError, subprocess.TimeoutExpired) as error:
            report["versions"][name] = {"exit": None, "output": str(error)}
    if args.credo_project:
        report["credo_lock_sha256"] = hashlib.sha256(
            (args.credo_project / "mix.lock").read_bytes()
        ).hexdigest()
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return int(not all(result["expectation_met"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
