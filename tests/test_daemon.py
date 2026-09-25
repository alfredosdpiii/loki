import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import loki
from tests.helpers import capture_output, temporary_root
from tests.test_repository_guardrails import git


def wait_for(path: Path, present: bool = True, seconds: float = 60) -> None:
    limit = time.monotonic() + seconds
    while path.exists() != present:
        if time.monotonic() > limit:
            raise AssertionError(f"timed out waiting for {path} (present={present})")
        time.sleep(0.05)


@unittest.skipUnless(sys.platform != "win32" and hasattr(os, "fork"), "POSIX only")
class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"LOKI_DAEMON": "1"}))
        self.home = Path(self.enterContext(temporary_root()))
        self.root = (Path(self.enterContext(temporary_root())) / "repo").resolve()
        self.root.mkdir()
        os.environ["HOME"] = str(self.home)
        git(self.root, "init", "-q")
        subprocess.run(
            [sys.executable, str(loki.SOURCE_ROOT / "loki.py"), "init", "--dir", "."],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        (self.root / "notes.md").write_text("x\n")
        git(self.root, "add", ".")
        git(
            self.root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b"
        )
        self.engine = self.root / ".loki/loki.py"
        self.socket, self.lock = loki.daemon_paths(self.root)

    def tearDown(self):
        self.command("daemon", "stop")
        if self.socket.exists():
            wait_for(self.socket, present=False)

    def command(self, *arguments, payload=None, daemon=True):
        env = {**os.environ, "LOKI_DAEMON": "1" if daemon else "0"}
        return subprocess.run(
            [sys.executable, str(self.engine), *arguments],
            cwd=self.root,
            env=env,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def serve(self):
        process = subprocess.Popen(
            [sys.executable, str(self.engine), "--root", str(self.root)]
            + ["daemon", "serve"],
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(process.wait, 30)
        wait_for(self.socket)
        return process

    def payload(self, path, content="x\n"):
        return {
            "cwd": str(self.root),
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": content},
        }

    def test_daemon_results_match_in_process_results(self):
        self.serve()
        for payload in (
            self.payload("ordinary.txt"),
            self.payload(".claude/settings.json", "{}"),
            self.payload("app.ts", "node.innerHTML = value;\n"),
        ):
            with self.subTest(path=payload["tool_input"]["file_path"]):
                arguments = ("protect", "--harness", "claude")
                served = self.command(*arguments, payload=payload)
                local = self.command(*arguments, payload=payload, daemon=False)
                self.assertEqual(
                    (local.returncode, local.stdout, local.stderr),
                    (served.returncode, served.stdout, served.stderr),
                )
        self.assertIn("running", self.command("daemon", "status").stdout)

    def test_client_forwards_to_daemon_and_falls_back_when_stale(self):
        self.serve()
        argv = ["--root", str(self.root), "protect", "--harness", "claude"]
        raw = json.dumps(self.payload(".claude/settings.json", "{}"))
        with (
            patch.object(sys, "stdin", io.StringIO(raw)),
            patch.object(loki, "engine_digest", return_value=loki.engine_digest()),
            patch.object(loki, "__file__", str(self.engine)),
        ):
            status, _, diagnostic = capture_output(loki.daemon_client, argv)
        self.assertEqual(2, status)
        self.assertIn("protected", diagnostic)
        with (
            patch.object(sys, "stdin", io.StringIO(raw)),
            patch.object(loki, "engine_digest", return_value="different"),
        ):
            self.assertIsNone(loki.daemon_client(argv))
        wait_for(self.socket, present=False)

    def test_client_autostarts_once_and_stop_shuts_down(self):
        argv = ["--root", str(self.root), "protect", "--file", "notes.md"]
        with patch.object(loki, "__file__", str(self.engine)):
            self.assertIsNone(loki.daemon_client(argv))
            self.assertTrue(self.lock.exists())
            self.assertIsNone(loki.daemon_client(argv))
        wait_for(self.socket)
        self.assertEqual(0, self.command("protect", "--file", "notes.md").returncode)
        self.command("daemon", "stop")
        wait_for(self.socket, present=False)
        self.assertFalse(self.lock.exists())

    def test_disabled_and_irrelevant_commands_run_locally(self):
        with patch.dict(os.environ, {"LOKI_DAEMON": "0"}):
            self.assertIsNone(loki.daemon_client(["protect", "--file", "x"]))
        self.assertIsNone(loki.daemon_client(["scan"]))
        with patch.object(loki, "daemon_paths", return_value=None):
            self.assertIsNone(loki.daemon_client(["protect", "--file", "x"]))
        self.assertFalse(self.lock.exists())
