"""Matched, network-isolated installed-hook lifecycles with immutable evidence."""

import argparse
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from benchmarks import compare_hooks, corpus  # noqa: E402

LANGUAGE_FILES = {
    "python": {"app.py": "def total():\n    return 42\n"},
    "typescript": {"src/main.ts": "export const value = 1;\n"},
    "javascript": {"checks.test.js": "export const value = 1;\n"},
    "go": {
        "go.mod": "module example.invalid/loki/benchmark\n\ngo 1.25\n",
        "main.go": (
            "// Package main is a benchmark fixture.\npackage main\nfunc main() {}\n"
        ),
    },
    "rust": {
        "Cargo.toml": (
            '[package]\nname="guardrail_fixture"\nversion="0.1.0"\nedition="2021"\n'
        ),
        "src/lib.rs": "pub fn count() -> u32 { 1 }\n",
    },
}
UNAVAILABLE = re.compile(
    r"NOT CHECKED|evaluator skipped|NOT validated|timed out|"
    r"(?:analyzer|compiler|tool).{0,50}(?:unavailable|not found)|"
    r"could not (?:connect|run)|ECONNREFUSED",
    re.I,
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def decode(result, phase):
    """Decode native Claude output, including exit-zero post-tool blocks."""
    status, output = result["exit"], result["stdout"]
    if status not in (0, 2):
        return "unavailable"
    if status == 2:
        return "deny"
    if not output.strip():
        return "allow"
    try:
        value = json.loads(output)
    except ValueError:
        return "unavailable"
    if not isinstance(value, dict):
        return "unavailable"
    if value.get("continue") is False or value.get("decision") == "block":
        return "deny"
    specific = value.get("hookSpecificOutput", {})
    if not isinstance(specific, dict):
        return "unavailable"
    if specific.get("hookEventName", phase) != phase:
        return "unavailable"
    permission = specific.get("permissionDecision")
    if permission not in (None, "allow", "deny", "ask"):
        return "unavailable"
    return {"deny": "deny", "ask": "review"}.get(permission, "allow")


def visible_text(result):
    """Exit-zero stderr is terminal-only, not feedback seen by Claude."""
    text = result["stdout"]
    if result["exit"] == 2:
        text += "\n" + result["stderr"]
    return text


def summarize_stage(results, phase, markers):
    decisions = [decode(result, phase) for result in results]
    decision = next(
        (kind for kind in ("deny", "review", "unavailable") if kind in decisions),
        "allow" if results else "unavailable",
    )
    visible = "\n".join(visible_text(result) for result in results)
    raw = "\n".join(result["stdout"] + result["stderr"] for result in results)
    return {
        "decision": decision,
        "targeted": any(re.search(marker, visible, re.I) for marker in markers),
        "coverage_warning": bool(UNAVAILABLE.search(raw)),
        "feedback_present": bool(visible.strip()),
        "ms": sum(result["ms"] for result in results),
        "handlers": results,
    }


def classify(kind, pre, post):
    """A denial alone is not proof that the intended defect was identified."""
    if kind == "control":
        if pre["decision"] in ("deny", "review"):
            return "false_block"
        if post and post["decision"] in ("deny", "review"):
            return "false_post_block"
        if pre["decision"] == "unavailable" or (
            post and post["decision"] == "unavailable"
        ):
            return "unavailable"
        return "admitted"
    if pre["decision"] == "deny":
        return "prevented" if pre["targeted"] else "blocked_unrelated"
    if pre["decision"] == "unavailable":
        return "unavailable"
    if post and post["targeted"]:
        return "detected_after_write"
    if post and post["decision"] == "unavailable":
        return "unavailable"
    return "missed"


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def interval(successes, count):
    """Wilson 95% interval, descriptive only for this non-random case corpus."""
    if not count:
        return None
    z = 1.959963984540054
    p = successes / count
    center = (p + z * z / (2 * count)) / (1 + z * z / count)
    half = z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count))
    half /= 1 + z * z / count
    return [round(max(0, center - half), 4), round(min(1, center + half), 4)]


def audit_messages(output):
    """Only actual diagnostic entries count, never an empty registry's keys."""
    value = json.loads(output)
    messages = []
    if not isinstance(value, dict):
        raise ValueError("audit output must be an object")
    for group in value.values():
        if not isinstance(group, dict):
            continue
        if any(
            isinstance(group.get(key), int) and group[key] > 0
            for key in ("issues", "findings", "secrets", "vulnerabilities")
        ):
            messages.extend(
                json.dumps(detail)
                for detail in group.get("details", [])
                if isinstance(detail, (dict, str))
            )
    return "\n".join(messages)


class Sandbox:
    def __init__(self, parent, args):
        self.parent = parent
        self.args = args
        home = parent / "home"
        home.mkdir()
        if args.hex_archive:
            shutil.copytree(
                args.hex_archive, home / ".mix/archives" / args.hex_archive.name
            )
        self.env = {
            "HOME": str(home),
            "PATH": ":".join(
                [
                    str(args.node.parent),
                    str(args.erlang_bin),
                    str(Path(sys.executable).parent),
                    str(args.golangci.parent),
                    str(args.python_tools),
                    os.environ["PATH"],
                ]
            ),
            "NO_COLOR": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "INTERLINKED_SYNC_MODE": "local",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
            "GOCACHE": str(parent / "go-cache"),
            "GOPATH": str(parent / "go-path"),
            "GOTOOLCHAIN": "local",
            "MIX_HOME": str(home / ".mix"),
            "HEX_HOME": str(home / ".hex"),
        }
        # Select only runtime settings, never inherit credentials or agent config.
        for key in ("RUSTUP_TOOLCHAIN", "ERL_FLAGS", "ERL_AFLAGS"):
            if key in os.environ:
                self.env[key] = os.environ[key]

    def command(self, argv):
        return [
            "bwrap",
            "--die-with-parent",
            "--unshare-net",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            str(self.parent),
            str(self.parent),
            "--tmpfs",
            "/tmp",  # noqa: S108 - private tmpfs mount, not a shared temporary file
            "--bind",
            str(self.parent),
            str(self.parent),
            # Toolchains and competitor builds in /tmp remain read-only.
            *[
                part
                for path in self.args.tool_roots
                for part in ("--ro-bind", str(path), str(path))
            ],
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            *[str(part) for part in argv],
        ]

    def run(self, argv, root, *, payload=None, required=False, timeout=60):
        started = time.monotonic()
        process = subprocess.Popen(
            self.command(argv),
            cwd=root,
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(payload, timeout=timeout)
            status = process.returncode
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            status, stderr = None, stderr + "\nbenchmark timeout"
        result = {
            "exit": status,
            "stdout": stdout,
            "stderr": stderr,
            "ms": round((time.monotonic() - started) * 1000, 3),
        }
        if required and status != 0:
            raise RuntimeError(json.dumps({"command": list(map(str, argv)), **result}))
        return result


def write(root, name, content):
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("benchmark executor refuses escaped writes")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def git(root, *args):
    # Use the existing configured author identity, not a synthesized fixture author.
    return compare_hooks.run(["git", *args], root, required=True)


def handler_commands(root, phase, tool):
    groups = json.loads((root / ".claude/settings.json").read_text())["hooks"]
    return [
        handler["command"]
        for group in groups.get(phase, [])
        if group.get("matcher", "") in ("", "*") or re.fullmatch(group["matcher"], tool)
        for handler in group["hooks"]
        if handler.get("type") == "command"
    ]


def reviewed_policy(config):
    return {**config, "shell_commands": [compare_hooks.REVIEWED_TEST_COMMAND]}


def baseline(root, case, product, sandbox, profile):
    args = sandbox.args
    root.mkdir()
    git(root, "init", "-b", "main")
    write(
        root,
        ".gitignore",
        "node_modules/\n.loki/evidence/\n.interlinked/\ndeps/\n_build/\ntarget/\n",
    )
    write(
        root,
        "package.json",
        '{"private":true,"scripts":{"test":"node --test"},'
        '"devDependencies":{"typescript":"5.9.3","oxlint":"1.83.0"}}\n',
    )
    if case["language"] == "elixir":
        shutil.copytree(
            SOURCE / "benchmarks/fixtures/phoenix", root, dirs_exist_ok=True
        )
        for name in ("deps", "_build"):
            shutil.copytree(args.phoenix / name, root / name, symlinks=True)
    for name, content in {
        **LANGUAGE_FILES.get(case["language"], {}),
        **case["base"],
    }.items():
        write(root, name, content)
    if case["language"] in ("typescript", "javascript"):
        write(
            root,
            "tsconfig.json",
            json.dumps(
                {
                    "compilerOptions": {
                        "strict": True,
                        "noEmit": True,
                        "target": "ES2022",
                        "module": "ESNext",
                        "moduleResolution": "Bundler",
                        "skipLibCheck": True,
                    },
                    "include": ["src/**/*.ts"],
                }
            ),
        )
        write(
            root,
            "biome.json",
            json.dumps(
                {
                    "formatter": {"enabled": False},
                    "linter": {"enabled": True, "rules": {"recommended": True}},
                    "assist": {"enabled": False},
                }
            ),
        )
    for index in range(case.get("tracked_files", 0)):
        write(root, f"corpus/file-{index:05}.txt", "Tracked workload fixture.\n")
    if product == "loki":
        sandbox.run(
            [
                sys.executable,
                SOURCE / "loki.py",
                "init",
                "--dir",
                root,
                "--shell-guard",
            ],
            root,
            required=True,
        )
        policy = root / ".loki/loki.json"
        config = reviewed_policy(json.loads(policy.read_text()))
        policy.write_text(json.dumps(config) + "\n")
        sandbox.run(
            [sys.executable, root / ".loki/loki.py", "context", "--root", root],
            root,
            required=True,
        )
    else:
        sandbox.run(
            [
                args.node,
                args.interlinked / "dist/index.js",
                "install-hooks",
                "--runner",
                "claude-code",
                "--scope",
                "project",
                "--mode",
                "balanced",
                "--json",
            ],
            root,
            required=True,
        )
    if profile == "shared":
        modules = root / "node_modules"
        (modules / ".bin").mkdir(parents=True)
        for name, binary in (
            ("oxlint", args.oxlint),
            ("tsc", args.typescript / "bin/tsc"),
            ("biome", args.biome),
        ):
            (modules / ".bin" / name).symlink_to(binary)
        (modules / "typescript").symlink_to(args.typescript, target_is_directory=True)
        (modules / "@biomejs").symlink_to(
            args.biome.parent.parent / "@biomejs", target_is_directory=True
        )
        # Plugin imports resolve relative to installed source, not the Oxlint binary.
        (modules / "@oxlint").symlink_to(
            args.oxlint.parent.parent / "@oxlint", target_is_directory=True
        )
    if case["id"] == "admission/policy-via-symlink":
        (root / "policy-link").symlink_to(".claude/settings.json")
    git(root, "add", ".")
    git(root, "commit", "-m", "Comprehensive benchmark fixture")
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
        and not p.is_symlink()
        and not any(
            part in {".git", "node_modules", "deps", "_build", ".interlinked"}
            for part in p.relative_to(root).parts
        )
    }


def formatted(step, language, root, sandbox):
    content = step["content"]
    if step.get("admission_only"):
        return content
    if language == "elixir":
        result = sandbox.run(
            ["mix", "format", "-"], root, payload=content, required=True
        )
        return result["stdout"]
    if language == "go":
        content = "// Package main is a benchmark fixture.\n" + content
        return sandbox.run(["gofmt"], root, payload=content, required=True)["stdout"]
    if language == "rust":
        return sandbox.run(
            ["rustfmt", "--emit", "stdout", "--edition", "2021"],
            root,
            payload=content,
            required=True,
        )["stdout"]
    return content


def payload(root, step, content, phase, session, before, *, tool_id=None):
    tool_input = (
        {"command": content}
        if step["tool"] == "Bash"
        else {"file_path": str(root / step["path"]), "content": content}
    )
    if step["tool"] == "Edit":
        if before is None:
            raise ValueError("exact Edit requires an existing fixture file")
        tool_input = {
            "file_path": str(root / step["path"]),
            "old_string": before.decode(),
            "new_string": content,
        }
    return json.dumps(
        {
            "cwd": str(root),
            "session_id": session,
            "tool_use_id": tool_id or session + "-tool",
            "hook_event_name": phase,
            "tool_name": step["tool"],
            "tool_input": tool_input,
            "tool_response": {
                "success": True,
                "type": "create" if before is None else "update",
            },
        }
    )


def lifecycle(root, case, sandbox, repetition):
    events = []
    for index, step in enumerate(case["steps"]):
        content = formatted(step, case["language"], root, sandbox)
        path = root / step["path"] if step["path"] else None
        before = path.read_bytes() if path and path.is_file() else None
        stages = {}
        landed = False
        for phase in ("PreToolUse", "PostToolUse"):
            if phase == "PostToolUse":
                if (
                    step.get("admission_only")
                    or stages["PreToolUse"]["decision"] != "allow"
                ):
                    break
                write(root, step["path"], content)
                landed = True
            commands = handler_commands(root, phase, step["tool"])
            results = [
                sandbox.run(
                    ["/bin/sh", "-c", command],
                    root,
                    payload=payload(
                        root,
                        step,
                        content,
                        phase,
                        f"bench-{repetition}",
                        before,
                        tool_id=f"bench-{repetition}-step-{index}",
                    ),
                    timeout=45,
                )
                for command in commands
            ]
            stages[phase] = summarize_stage(results, phase, step["markers"])
        pre, post = stages["PreToolUse"], stages.get("PostToolUse")
        after = path.read_bytes() if path and path.is_file() else None
        events.append(
            {
                "step": index,
                "kind": step["kind"],
                "repetition": repetition,
                "cache_state": (
                    "first-invocation" if repetition == 0 else "startup-warmed"
                ),
                "outcome": classify(step["kind"], pre, post),
                "bytes_landed": landed,
                "proposed_sha256": hashlib.sha256(content.encode()).hexdigest(),
                "post_modified_written_bytes": landed and after != content.encode(),
                "pre_modified_bytes": not landed and before != after,
                "pre": pre,
                "post": post,
            }
        )
    return events


def evaluate_trial(case, product, profile, args, repetition):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="b-", dir=args.work_dir) as directory:
        parent = Path(directory)
        sandbox = Sandbox(parent, args)
        root = parent / "project"
        baseline(root, case, product, sandbox, profile)
        daemon = None
        log = (parent / "daemon.log").open("w+")
        try:
            if product == "interlinked":
                sock = root / ".interlinked/harness.sock"
                sock.parent.mkdir(exist_ok=True)
                sandbox.env["INTERLINKED_SOCKET"] = str(sock)
                daemon = subprocess.Popen(
                    sandbox.command(
                        [
                            args.node,
                            args.interlinked / "dist/harness/server.js",
                            "--cwd",
                            root,
                            "--socket",
                            sock,
                            "--protocol",
                            "raw",
                        ]
                    ),
                    cwd=root,
                    env=sandbox.env,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
                compare_hooks.wait_for_socket(sock, daemon)
            warmups = []
            if repetition:
                status_step = corpus.step(
                    None, "git status --short", "control", tool="Bash"
                )
                for index in range(2):
                    for command in handler_commands(root, "PreToolUse", "Bash"):
                        warmups.append(
                            sandbox.run(
                                ["/bin/sh", "-c", command],
                                root,
                                payload=payload(
                                    root,
                                    status_step,
                                    status_step["content"],
                                    "PreToolUse",
                                    f"bench-{repetition}",
                                    None,
                                    tool_id=f"warmup-{index}",
                                ),
                            )
                        )
            setup_ms = round((time.monotonic() - started) * 1000, 3)
            events = lifecycle(root, case, sandbox, repetition)
            scans = []
            if args.scan and repetition == 0 and case["language"] in ("go", "rust"):
                # Independent audit: intentionally materialize even pre-denied source.
                # This is not credited as prevention or ordinary-hook detection.
                for item in case["steps"]:
                    write(
                        root,
                        item["path"],
                        formatted(item, case["language"], root, sandbox),
                    )
                    command = (
                        [
                            sys.executable,
                            root / ".loki/loki.py",
                            "scan",
                            "--base",
                            "HEAD",
                        ]
                        if product == "loki"
                        else [
                            args.node,
                            args.interlinked / "dist/index.js",
                            "verify",
                            "--json",
                        ]
                    )
                    result = sandbox.run(command, root, timeout=120)
                    try:
                        findings = (
                            audit_messages(result["stdout"])
                            if product == "interlinked"
                            else result["stdout"] + result["stderr"]
                        )
                    except ValueError:
                        findings = ""
                    scans.append(
                        {
                            **result,
                            "kind": item["kind"],
                            "targeted": result["exit"] in (0, 1, 2)
                            and any(
                                re.search(marker, findings, re.I)
                                for marker in item["markers"]
                            ),
                        }
                    )
            return {
                "case": case["id"],
                "language": case["language"],
                "family": case["family"],
                "pair": case["pair"],
                "product": product,
                "profile": profile,
                "setup_ms": setup_ms,
                "events": events,
                "audit_scans": scans,
                "warmups": warmups,
            }
        finally:
            if daemon is not None and daemon.poll() is None:
                os.killpg(daemon.pid, signal.SIGTERM)
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(daemon.pid, signal.SIGKILL)
                    daemon.wait(timeout=5)
            log.close()


def evaluate(case, product, profile, args):
    """Never share reservations, diagnostic caches, or worktree state across trials."""
    records = []
    errors = []
    for repetition in range(args.runs):
        try:
            records.append(evaluate_trial(case, product, profile, args, repetition))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(f"trial {repetition}: {type(error).__name__}: {error}")
    record = {
        "case": case["id"],
        "language": case["language"],
        "family": case["family"],
        "pair": case["pair"],
        "product": product,
        "profile": profile,
        "setup_ms": [item["setup_ms"] for item in records],
        "events": [event for item in records for event in item["events"]],
        "audit_scans": [scan for item in records for scan in item["audit_scans"]],
        "warmups": [result for item in records for result in item["warmups"]],
    }
    if errors:
        record["error"] = "\n".join(errors)
    return record


def summarize(records):
    groups = {}
    for record in records:
        key = f"{record['profile']}/{record['product']}"
        group = groups.setdefault(
            key,
            {
                "outcomes": Counter(),
                "steps": 0,
                "errors": [],
                "timings": [],
                "coverage_warning_steps": 0,
                "inconsistent_cases": [],
            },
        )
        if "error" in record:
            group["errors"].append({"case": record["case"], "error": record["error"]})
            continue
        by_step = {}
        for event in record["events"]:
            by_step.setdefault(event["step"], []).append(event)
            group["timings"].append(
                event["pre"]["ms"] + (event["post"]["ms"] if event["post"] else 0)
            )
        # Repetitions are timing/stability samples, not independent accuracy cases.
        for events in by_step.values():
            outcomes = {event["outcome"] for event in events}
            if len(outcomes) > 1:
                group["inconsistent_cases"].append(record["case"])
            group["outcomes"][events[0]["outcome"]] += 1
            group["steps"] += 1
            group["coverage_warning_steps"] += int(
                any(
                    event["pre"]["coverage_warning"]
                    or (event["post"] and event["post"]["coverage_warning"])
                    for event in events
                )
            )
    for group in groups.values():
        values = group.pop("timings")
        group["latency_ms"] = (
            {
                "median": statistics.median(values),
                "p95": percentile(values, 0.95),
                "max": max(values),
            }
            if values
            else None
        )
    return groups


def identity(args):
    paths = [
        SOURCE / "loki.py",
        *sorted((SOURCE / "templates").glob("*")),
        *sorted((SOURCE / "shim").glob("*.ts")),
        args.interlinked / "dist/index.js",
        args.interlinked / "dist/hook-entry.js",
        args.interlinked / "dist/harness/server.js",
        SOURCE / "benchmarks/corpus.py",
        SOURCE / "benchmarks/comprehensive.py",
        args.node.resolve(),
        args.oxlint.resolve(),
        args.typescript / "lib/typescript.js",
        args.biome.resolve(),
        args.golangci,
        args.phoenix / "mix.lock",
        *sorted((SOURCE / "vendor").rglob("*.ts")),
    ]
    return {str(path): digest(path) for path in paths if path.is_file()}


def versions(args):
    commands = {
        "python": [sys.executable, "--version"],
        "node": [args.node, "--version"],
        "ruff": ["ruff", "--version"],
        "mypy": [args.python_tools / "mypy", "--version"],
        "oxlint": [args.oxlint, "--version"],
        "typescript": [args.node, args.typescript / "bin/tsc", "--version"],
        "biome": [args.biome, "--version"],
        "go": ["go", "version"],
        "golangci": [args.golangci, "version"],
        "rust": ["cargo", "clippy", "--version"],
        "elixir": ["elixir", "--version"],
    }
    with tempfile.TemporaryDirectory(prefix="loki-benchmark-versions-") as directory:
        sandbox = Sandbox(Path(directory), args)
        return {
            name: sandbox.run(command, Path(directory))
            for name, command in commands.items()
        }


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "interlinked",
        "node",
        "oxlint",
        "typescript",
        "biome",
        "python-tools",
        "golangci",
        "phoenix",
        "output",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--hex-archive", type=Path, required=True)
    parser.add_argument("--erlang-bin", type=Path, required=True)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=SOURCE / "artifacts/tmp/b",
        help="Fixture parent outside OS temporary roots, to avoid scratchpad policy",
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20260921)
    parser.add_argument(
        "--profiles",
        nargs="+",
        choices=("shared", "missing-js"),
        default=["shared", "missing-js"],
    )
    parser.add_argument("--case", help="Regex filter; recorded in the manifest")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Also run independent Go/Rust audit commands",
    )
    parser.add_argument(
        "--competitor-revision",
        default=compare_hooks.PIN,
        help="Expected Interlinked commit; recorded in the manifest",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    for name in (
        "interlinked",
        "node",
        "oxlint",
        "typescript",
        "biome",
        "python_tools",
        "hex_archive",
        "erlang_bin",
        "work_dir",
        "golangci",
        "phoenix",
        "output",
    ):
        setattr(args, name, getattr(args, name).absolute())
    revision = git(args.interlinked, "rev-parse", "HEAD").stdout.strip()
    if revision != args.competitor_revision:
        parser.error("competitor revision differs from the declared pin")
    if git(
        args.interlinked, "status", "--porcelain", "--untracked-files=no"
    ).stdout.strip():
        parser.error("competitor tracked files must be clean")
    args.tool_roots = sorted(
        {
            args.interlinked,
            args.oxlint.parent.parent.parent,
            args.typescript.parent.parent,
            args.golangci.parent,
            args.phoenix,
            args.biome.parent.parent.parent,
            args.python_tools.parent,
        }
    )
    if not shutil.which("bwrap"):
        parser.error("bubblewrap is required; no unsandboxed fallback")
    frozen = corpus.manifest()
    cases = [
        case
        for case in frozen["cases"]
        if not args.case or re.search(args.case, case["id"])
    ]
    if not cases:
        parser.error("case selection is empty")
    args.output.mkdir(parents=True, exist_ok=False)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    stamp = identity(args)
    rng = random.Random(args.seed)  # noqa: S311 - reproducible scheduling, not security
    schedule = [
        (case, product, profile)
        for profile in args.profiles
        for case in cases
        if profile == "shared" or case["language"] in ("typescript", "javascript")
        for product in ("loki", "interlinked")
    ]
    rng.shuffle(schedule)
    save(
        args.output / "manifest.json",
        {
            "corpus": frozen,
            "identity": stamp,
            "runs": args.runs,
            "seed": args.seed,
            "case_filter": args.case,
            "competitor_revision": revision,
            "argv": sys.argv,
            "versions": versions(args),
            "machine": {
                "platform": platform.platform(),
                "logical_cpus": os.cpu_count(),
                "python": platform.python_version(),
            },
            "schedule": [
                [case["id"], product, profile] for case, product, profile in schedule
            ],
            "scope": (
                "Synthetic installed Claude pre/post lifecycles; "
                "no models; no Bash payload execution."
            ),
            "configuration": (
                "Loki shell guard and committed npm test grant; "
                "Interlinked balanced; shared analyzer paths."
            ),
            "isolation": (
                "Fresh fixtures/homes/processes per repetition, "
                "network namespace, read-only host filesystem, "
                "fixture and private /tmp writable."
            ),
            "warmup": (
                "Trial zero has no warmup. Later independent trials send two "
                "git-status pre-hook envelopes in the same session. No commands "
                "are executed; this warms startup, not compiler result caches."
            ),
            "limitations": [
                "Author-written cases are not independent or "
                "representative of production.",
                "First invocation is not an OS-cold disk/cache measurement.",
                "Additional context can be advisory; post-write findings "
                "do not prevent bytes landing.",
                "Generic denial without a target marker is not credited "
                "as targeted prevention.",
                "Real host activation and explicit audit scans are separate "
                "from hook effectiveness.",
                "Go/Rust audit commands have different product-defined scopes.",
            ],
        },
    )
    records = []
    for index, (case, product, profile) in enumerate(schedule):
        print(
            f"{index + 1}/{len(schedule)} {profile} {product} {case['id']}", flush=True
        )
        try:
            record = evaluate(case, product, profile, args)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record = {
                "case": case["id"],
                "product": product,
                "profile": profile,
                "error": f"{type(error).__name__}: {error}",
            }
        save(args.output / f"record-{index:04}.json", record)
        records.append(record)
    unchanged = stamp == identity(args)
    save(
        args.output / "summary.json",
        {
            "identity_unchanged": unchanged,
            "groups": summarize(records),
            "corpus_sha256": frozen["sha256"],
        },
    )
    if not unchanged:
        raise RuntimeError("benchmark inputs changed during execution")
    return int(any("error" in record for record in records))


if __name__ == "__main__":
    raise SystemExit(main())
