"""Verify real host context delivery against a credential-free loopback model."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
MARKER = "LOKI POLICY GUIDANCE"
BASE_PROMPT = "Retain this host system instruction: context-fixture-base."
PROMPT = "Reply exactly fixture-ok. Do not use tools."


def isolated_env(home, path):
    return {
        "HOME": str(home),
        "PATH": path,
        "TERM": "dumb",
        "NO_COLOR": "1",
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_DATA_HOME": str(home / "data"),
        "XDG_STATE_HOME": str(home / "state"),
        "XDG_RUNTIME_DIR": str(home / "runtime"),
        "PI_OFFLINE": "1",
        "PI_TELEMETRY": "0",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
    }


def anthropic_events():
    message = {
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-5",
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 0},
    }
    return [
        ("message_start", {"type": "message_start", "message": message}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "fixture-ok"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 1},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]


class ModelStub(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.reply({"object": "list", "data": [{"id": "fixture", "object": "model"}]})

    def reply(self, payload):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        payload = json.loads(self.rfile.read(length))
        if self.path.startswith("/api/"):
            # Factory's platform traffic stays local too; only model calls
            # establish whether guidance reached the model context.
            self.reply({})
            return
        if "count_tokens" in self.path:
            self.reply({"input_tokens": 1})
            return
        encoded = json.dumps(payload)
        self.server.observations.append(
            {
                "endpoint": self.path,
                "policy_present": MARKER in encoded,
                "python_guidance_present": "Python edits must introduce no new Ruff"
                in encoded,
                "base_prompt_preserved": BASE_PROMPT in encoded,
                "prompt_present": PROMPT in encoded,
                "request_bytes": length,
            }
        )
        if "/messages" in self.path:
            events = anthropic_events()
        elif "/responses" in self.path:
            item = {
                "id": "msg_fixture",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [
                    {"type": "output_text", "text": "fixture-ok", "annotations": []}
                ],
            }
            response = {
                "id": "resp_fixture",
                "object": "response",
                "status": "completed",
                "model": "fixture",
                "output": [item],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }
            events = [
                (
                    "response.created",
                    {
                        "type": "response.created",
                        "response": {**response, "status": "in_progress", "output": []},
                    },
                ),
                (
                    "response.output_item.added",
                    {
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": item,
                    },
                ),
                (
                    "response.output_text.delta",
                    {
                        "type": "response.output_text.delta",
                        "output_index": 0,
                        "content_index": 0,
                        "item_id": "msg_fixture",
                        "delta": "fixture-ok",
                    },
                ),
                (
                    "response.output_item.done",
                    {
                        "type": "response.output_item.done",
                        "output_index": 0,
                        "item": item,
                    },
                ),
                (
                    "response.completed",
                    {"type": "response.completed", "response": response},
                ),
            ]
        else:
            events = [
                (
                    None,
                    {
                        "id": "chatcmpl_fixture",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "fixture",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "content": "fixture-ok"},
                                "finish_reason": None,
                            }
                        ],
                    },
                ),
                (
                    None,
                    {
                        "id": "chatcmpl_fixture",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "fixture",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 1,
                            "total_tokens": 2,
                        },
                    },
                ),
                (None, "[DONE]"),
            ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for event, data in events:
            if event:
                self.wfile.write(f"event: {event}\n".encode())
            text = data if isinstance(data, str) else json.dumps(data)
            self.wfile.write(f"data: {text}\n\n".encode())
        self.wfile.flush()


def host_command(host, binary, root, home, url, enabled):
    env = isolated_env(
        home, str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
    )
    if host in {"pi", "omp"}:
        agent = home / f".{host}/agent"
        agent.mkdir(parents=True)
        env["PI_CODING_AGENT_DIR"] = str(agent)
        models = {
            "providers": {
                "loki-fixture": {
                    "baseUrl": url + "/v1",
                    "api": "openai-completions",
                    "apiKey": "fixture-only-not-a-credential",
                    "models": [
                        {
                            "id": "fixture",
                            "name": "Fixture",
                            "reasoning": False,
                            "input": ["text"],
                            "contextWindow": 128000,
                            "maxTokens": 1024,
                            "cost": {
                                "input": 0,
                                "output": 0,
                                "cacheRead": 0,
                                "cacheWrite": 0,
                            },
                        }
                    ],
                }
            }
        }
        (agent / "models.json").write_text(json.dumps(models))
        command = [
            binary,
            "--model",
            "loki-fixture/fixture",
            "--no-session",
            "--no-tools",
            "--no-skills",
            "--thinking",
            "off",
            "--system-prompt",
            BASE_PROMPT,
        ]
        if host == "pi":
            command += [
                "--offline",
                "--no-context-files",
                "--no-prompt-templates",
                "--no-themes",
                "--approve",
            ]
        else:
            command += ["--no-rules", "--no-lsp", "--no-pty", "--no-title"]
        if not enabled:
            command += ["--no-extensions"]
        return command + ["--print", PROMPT], env
    if host == "claude":
        env["ANTHROPIC_BASE_URL"] = url
        env["ANTHROPIC_API_KEY"] = "fixture-only-not-a-credential"
        command = [
            binary,
            "--print",
            "--model",
            "claude-sonnet-4-5",
            "--tools",
            "",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--system-prompt",
            BASE_PROMPT,
            "--setting-sources",
            "project",
            PROMPT,
        ]
        if not enabled:
            (root / ".claude/settings.json").write_text("{}")
        return command, env
    if host == "codex":
        env["CODEX_HOME"] = str(home / ".codex")
        (home / ".codex").mkdir()
        (home / ".codex/config.toml").write_text(
            f'[projects.{json.dumps(str(root))}]\ntrust_level = "trusted"\n'
        )
        command = [
            binary,
            "--dangerously-bypass-hook-trust",
            "-c",
            f"developer_instructions={json.dumps(BASE_PROMPT)}",
            "-c",
            'model_provider="loki-fixture"',
            "-c",
            'model_providers.loki-fixture.name="Fixture"',
            "-c",
            f'model_providers.loki-fixture.base_url="{url}/v1"',
            "-c",
            'model_providers.loki-fixture.wire_api="responses"',
            "-c",
            "model_providers.loki-fixture.requires_openai_auth=false",
            "exec",
            "--sandbox",
            "read-only",
            "--model",
            "fixture",
            "--skip-git-repo-check",
            PROMPT,
        ]
        if not enabled:
            (root / ".codex/hooks.json").write_text('{"hooks":{}}')
        return command, env
    if host == "factory":
        settings = home / ".factory/settings.json"
        settings.parent.mkdir()
        settings.write_text(
            json.dumps(
                {
                    "customModels": [
                        {
                            "model": "fixture",
                            "displayName": "Fixture",
                            "baseUrl": url + "/v1",
                            "apiKey": "fixture-only-not-a-credential",
                            "provider": "generic-chat-completion-api",
                            "maxOutputTokens": 1024,
                        }
                    ]
                }
            )
        )
        (root / "AGENTS.md").write_text(BASE_PROMPT + "\n")
        env["FACTORY_API_BASE_URL"] = url
        command = [
            binary,
            "exec",
            "--model",
            "custom:Fixture-0",
            "--disable-builtin-skills",
            "--only-tools",
            "Read",
            PROMPT,
        ]
        if not enabled:
            (root / ".factory/hooks.json").write_text("{}")
        return command, env
    raise ValueError(f"unsupported host: {host}")


def probe(host, binary, enabled):
    with tempfile.TemporaryDirectory(prefix=f"loki-{host}-context-") as directory:
        parent = Path(directory)
        root, home = parent / "project", parent / "home"
        root.mkdir()
        home.mkdir()
        (home / "runtime").mkdir(mode=0o700)
        subprocess.run(
            [sys.executable, str(SOURCE / "loki.py"), "init", "--dir", str(root)],
            check=True,
            capture_output=True,
        )
        (root / ".loki/loki.json").write_text('{"rule_packs":["python"]}')
        subprocess.run(["git", "init"], cwd=root, capture_output=True, check=True)  # noqa: S607
        server = ThreadingHTTPServer(("127.0.0.1", 0), ModelStub)
        server.observations = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        command, env = host_command(host, binary, root, home, url, enabled)
        started = time.monotonic()
        version_text = ""
        try:
            version = subprocess.run(
                [binary, "--version"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            version_text = version.stdout.strip()
            result = subprocess.run(
                command,
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=35,
                check=False,
            )
            status, stderr = result.returncode, result.stderr[-4000:]
            completed = "fixture-ok" in result.stdout
        except subprocess.TimeoutExpired:
            status, stderr, completed = None, "host timed out", False
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        observations = list(server.observations)
        delivered = any(
            item["policy_present"]
            and item["python_guidance_present"]
            and item["prompt_present"]
            for item in observations
        )
        return {
            "host": host,
            "enabled": enabled,
            "version": version_text,
            "exit": status,
            "completed_stub_reply": completed,
            "context_delivered": delivered,
            "requests": observations,
            "expectation_met": (
                bool(observations)
                and delivered == enabled
                and all(item["base_prompt_preserved"] for item in observations)
                and status == 0
                and completed
            ),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "diagnostic": stderr,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--hosts",
        nargs="+",
        choices=("pi", "omp", "claude", "codex", "factory"),
        default=["pi", "omp", "claude", "codex", "factory"],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for host in args.hosts:
        binary = shutil.which("droid" if host == "factory" else host)
        if binary:
            for enabled in (False, True):
                results.append(probe(host, binary, enabled))
        else:
            results.append(
                {
                    "host": host,
                    "expectation_met": False,
                    "diagnostic": "host binary unavailable",
                }
            )
    report = {
        "scope": "real hosts, isolated homes, loopback stub; no provider credentials",
        "loading": (
            "installed project hooks/extensions through host discovery; "
            "fixture trust only"
        ),
        "engine_sha256": hashlib.sha256((SOURCE / "loki.py").read_bytes()).hexdigest(),
        "adapter_sha256": {
            name: hashlib.sha256((SOURCE / "shim" / name).read_bytes()).hexdigest()
            for name in ("loki.ts", "loki-omp.ts")
        },
        "results": results,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return int(any(not item["expectation_met"] for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
