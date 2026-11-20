import hashlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git

OLD = "def load(path):\n    try:\n        return open(path).read()\n    except Exception:\n        pass\n"
NEW = "\n\ndef save(path, text):\n    try:\n        open(path, 'w').write(text)\n    except Exception:\n        pass\n"
FALLBACK = "import os\n\nURL = os.getenv('DATABASE_URL', 'localhost')\n"


def squiggle(line, kind):
    return loki.HygieneSquiggle(line, kind, "why")


def commit(root, message="base"):
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", message)


def model_runs():
    return loki.hygiene_score(["x = 1\n"])[0] is not None


def nits_runs():
    return loki.nits_score([("a.py", "x = 1\n")])[0] is not None


def fake_python(root, code):
    script = write_file(
        root, f"python{code}", f"#!/bin/sh\necho 'Boom: bad' >&2\nexit {code}\n"
    )
    script.chmod(0o755)
    return [str(script)]


class MergeTests(unittest.TestCase):
    def test_notes_cover_added_lines_of_the_default_kinds(self):
        before, after = "a = 1\nb = 2\n", "a = 1\nnew = 3\nb = 2\nlonger = 4\n"
        found = [squiggle(1, "swallowed_error"), squiggle(2, "swallowed_error")]
        found.append(squiggle(4, "dense_line"))
        merge = loki.merge_hygiene_notes
        self.assertEqual(
            ["src/a.py:2: loki/hygiene-swallowed-error: why: `new = 3`"],
            merge("src/a.py", before, after, found, [], "on"),
        )
        self.assertEqual(
            [
                "src/a.py:2: loki/hygiene-swallowed-error: why: `new = 3`",
                "src/a.py:4: loki/hygiene-dense-line: why: `longer = 4`",
            ],
            merge("src/a.py", before, after, found, [], "all"),
        )
        self.assertEqual([], merge("src/a.py", after, after, found, [], "all"))
        self.assertEqual([], merge("src/a.py", before, after, found, [], "off"))

    def test_one_note_where_nits_and_the_model_agree_and_it_is_the_nits_one(self):
        before, after = "a = 1\n", "a = 1\nexcept Exception:\nurl = 2\n"
        model = [squiggle(1, "noisy_comment"), squiggle(2, "swallowed_error")]
        model.append(squiggle(3, "noisy_comment"))
        nits = [squiggle(1, "config_fallback"), squiggle(2, "swallowed_error")]
        nits.append(squiggle(3, "config_fallback"))
        self.assertEqual(
            [
                "a.py:2: loki/nits-swallowed-error: why: `except Exception:`",
                "a.py:3: loki/nits-config-fallback: why: `url = 2`",
                "a.py:3: loki/hygiene-noisy-comment: why: `url = 2`",
            ],
            loki.merge_hygiene_notes("a.py", before, after, model, nits, "on"),
        )
        self.assertEqual(
            [], loki.merge_hygiene_notes("a.py", before, after, model, nits, "off")
        )

    def test_snippet_is_capped(self):
        after = "x = '" + "y" * 200 + "'\n"
        (note,) = loki.merge_hygiene_notes(
            "a.py", "", after, [squiggle(1, "special_casing")], [], "on"
        )
        self.assertTrue(note.endswith("`" + after[:80] + "`"))

    def test_more_than_ten_notes_are_truncated(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, "b.py", "")
            commit(root)
            write_file(root, "a.py", "".join(f"x{i} = {i}\n" for i in range(12)))
            scored = ([[squiggle(i, "swallowed_error") for i in range(1, 13)]], None)
            with (
                patch.object(loki, "hygiene_score", return_value=scored),
                patch.object(loki, "nits_score", return_value=([[]], None)),
            ):
                notes = loki.hygiene_against(root, ["a.py"], "HEAD", "on")
            self.assertEqual(11, len(notes))
            self.assertEqual("... 2 more hygiene notes", notes[-1])


class LevelTests(unittest.TestCase):
    def test_policy_validates_and_defaults_on(self):
        self.assertEqual("on", loki.hygiene_policy({}))
        for value in ("off", "on", "all"):
            self.assertEqual(value, loki.validate_config({"hygiene": value})["hygiene"])
        for value in ("loud", True, 1, None):
            with self.assertRaisesRegex(
                ValueError, "hygiene must be 'off', 'on', or 'all'"
            ):
                loki.validate_config({"hygiene": value})

    def test_variable_wins_over_the_policy(self):
        level = loki.hygiene_level
        self.assertEqual("on", level({}, ""))
        self.assertEqual("all", level({"hygiene": "all"}, ""))
        self.assertEqual("off", level({"hygiene": "all"}, "off"))
        self.assertEqual("all", level({"hygiene": "off"}, " ALL "))
        self.assertEqual("on", level({}, "yes"))
        self.assertEqual("off", level({"hygiene": "on"}, "0"))
        self.assertEqual("on", level({"hygiene": "on"}, "loud"))
        self.assertEqual("off", level({"hygiene": "off"}, ""), "empty is unset")
        with patch.dict(os.environ, {"LOKI_HYGIENE": "all"}):
            self.assertEqual("all", level({}))
        with patch.dict(os.environ, {"LOKI_HYGIENE": ""}):
            self.assertEqual("on", level({"hygiene": "on"}))


class LauncherTests(unittest.TestCase):
    def test_launchers_are_offline_and_pinned(self):
        with patch.object(loki.shutil, "which", return_value="/bin/uv"):
            nits = loki.nits_launchers("/my/python")
            model = loki.hygiene_launchers(sys.executable)
        self.assertEqual([["/my/python"], [sys.executable]], nits[:2])
        self.assertEqual([[sys.executable]], model[:1])
        self.assertEqual(2, len(model))
        for launcher in (nits[-1], model[-1]):
            self.assertIn("--offline", launcher)
        self.assertTrue(nits[-1][-2].endswith(loki.NITS_COMMIT))
        with patch.object(loki.shutil, "which", return_value=None):
            self.assertEqual([[sys.executable]], loki.nits_launchers())

    def test_drive_falls_back_and_reports_failures(self):
        drive = loki.drive_hygiene_tool
        with temporary_root() as root:
            missing, failed = fake_python(root, 3), fake_python(root, 4)
            other = fake_python(root, 1)
            self.assertEqual(
                (None, "Boom: bad"),
                drive(
                    [missing, other, ["/nonexistent/python"], failed],
                    "",
                    {},
                    deadline=None,
                    missing="m",
                ),
            )
            self.assertEqual(
                (None, "m"),
                drive([missing, ["/nonexistent"]], "", {}, deadline=None, missing="m"),
            )
            self.assertEqual(
                [[loki.HygieneSquiggle(2, "k", "msg")]],
                drive(
                    [missing, [sys.executable]],
                    'import json,sys; json.load(sys.stdin); print(\'[[[2, "k", "msg"]]]\')',
                    {},
                    deadline=None,
                    missing="m",
                )[0],
            )
            self.assertEqual(
                (None, "unreadable reply"),
                drive(
                    [[sys.executable]], "print('nope')", {}, deadline=None, missing="m"
                ),
            )
            self.assertEqual(
                (None, "timed out"),
                drive([[sys.executable]], "", {}, deadline=0.0, missing="m"),
            )
            with patch.object(
                loki.subprocess,
                "run",
                side_effect=loki.subprocess.TimeoutExpired("p", 1),
            ):
                self.assertEqual(
                    (None, "timed out"),
                    drive([[sys.executable]], "", {}, deadline=None, missing="m"),
                )

    def test_missing_model_says_so(self):
        with temporary_root() as root, patch.object(loki, "SOURCE_ROOT", root):
            self.assertEqual(
                (None, "vendored codehygiene model is missing"),
                loki.hygiene_score(["x\n"]),
            )

    def test_vendored_model_matches_upstream_hashes(self):
        vendored = loki.SOURCE_ROOT / "vendor" / "codehygiene"
        upstream = (vendored / "UPSTREAM.md").read_text(encoding="utf-8")
        for name in ("__init__.py", "weights.npz"):
            digest = hashlib.sha256((vendored / name).read_bytes()).hexdigest()
            self.assertIn(f"`{name}` sha256 `{digest}`", upstream)


class AgainstTests(unittest.TestCase):
    def test_skips_files_it_does_not_read(self):
        with temporary_root() as root:
            write_file(root, "notes.md", "x\n")
            write_file(root, "vendor/lib/a.py", OLD)
            write_file(root, "src/gen.generated.ts", OLD)
            with patch.object(loki, "hygiene_score") as score:
                files = [
                    "notes.md",
                    "vendor/lib/a.py",
                    "src/gen.generated.ts",
                    "gone.py",
                ]
                self.assertEqual([], loki.hygiene_against(root, files, "HEAD", "all"))
            score.assert_not_called()
        self.assertTrue(loki.hygiene_checked("src/a.RS"))
        self.assertFalse(loki.hygiene_checked("dist/a.py"))
        self.assertTrue(loki.nits_reads("a.tsx"))
        self.assertFalse(loki.nits_reads("a.go"))

    def test_gaps_and_unreadable_base(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, "a.go", "package a\n")
            write_file(root, "b.py", "x = 1\n")
            with patch.object(
                loki, "hygiene_score", return_value=(None, "no numpy")
            ) as score:
                self.assertEqual(
                    ["NOT CHECKED hygiene: no numpy"],
                    loki.hygiene_against(root, ["a.go"], "HEAD", "on"),
                )
            self.assertEqual(1, score.call_count)
            scored = ([[squiggle(1, "swallowed_error")]], None)
            with (
                patch.object(loki, "hygiene_score", return_value=scored),
                patch.object(loki, "nits_score", return_value=(None, "no nits")),
            ):
                notes = loki.hygiene_against(root, ["b.py"], "nosuchrev", "on")
            self.assertEqual("NOT CHECKED nits: no nits", notes[0])
            self.assertTrue(notes[1].startswith("NOT CHECKED hygiene: git:"))
            self.assertEqual([], loki.hygiene_against(root, ["b.py"], "HEAD", "off"))
            self.assertEqual([], loki.changed_hygiene(root, "HEAD", "off"))


class LiveModelTests(unittest.TestCase):
    def test_reports_the_added_swallowed_error_not_the_committed_one(self):
        if not model_runs():
            return  # no Python with NumPy here, as with a missing Ruff
        with temporary_root() as root:
            root = root.resolve()
            git(root, "init", "-q")
            write_file(root, "store.py", OLD)
            write_file(root, "notes.md", "x\n")
            commit(root)
            targets = [root / "store.py", root / "notes.md"]
            self.assertEqual([], loki.written_hygiene(root, targets, "on"))
            write_file(root, "store.py", OLD + NEW)
            notes = loki.hygiene_against(
                root, ["store.py", "notes.md"], "HEAD", "on", nits_runner=[]
            )
            self.assertEqual(2, len(notes), notes)
            self.assertTrue(
                notes[0].startswith("store.py:11: loki/hygiene-swallowed-error: ")
            )
            self.assertTrue(notes[0].endswith("`except Exception:`"))
            self.assertTrue(notes[1].startswith("NOT CHECKED nits: "))
            self.assertIn("uv run --no-project --with git+https://", notes[1])
            self.assertEqual([], loki.written_hygiene(root, targets, "off"))
            commit(root, "more")
            self.assertEqual([], loki.written_hygiene(root, targets, "on"))

            def from_model(found):
                return [note for note in found if ": loki/hygiene-" in note]

            self.assertEqual(
                from_model(notes),
                from_model(loki.changed_hygiene(root, "HEAD~1", "on")),
            )
            self.assertEqual([], loki.changed_hygiene(root, "HEAD", "on"))
            self.assertEqual([], loki.changed_hygiene(root, "HEAD~1", "off"))


class LiveNitsTests(unittest.TestCase):
    def test_low_precision_rules_only_at_all(self):
        if not nits_runs():
            return  # nits is neither installed nor in uv's cache here
        with temporary_root() as root:
            root = root.resolve()
            git(root, "init", "-q")
            write_file(root, "old.py", FALLBACK)
            write_file(root, "store.py", "LIMIT = 10\n")
            commit(root)
            write_file(root, "old.py", FALLBACK + "LIMIT = 10\n")
            write_file(root, "store.py", FALLBACK + NEW)
            files = ["old.py", "store.py"]

            def nits_only(level):
                found = loki.hygiene_against(root, files, "HEAD", level)
                return [note for note in found if ": loki/nits-" in note]

            on = nits_only("on")
            self.assertEqual(1, len(on), on)
            self.assertTrue(
                on[0].startswith("store.py:3: loki/nits-config-fallback: p0.95 ")
            )
            self.assertTrue(on[0].endswith("'localhost')`"))
            every = nits_only("all")
            self.assertTrue(
                any(
                    n.startswith("store.py:9: loki/nits-swallowed-error: p0.")
                    for n in every
                ),
                every,
            )
            if model_runs():
                both = loki.hygiene_against(root, files, "HEAD", "all")
                same = [
                    n
                    for n in both
                    if n.startswith("store.py:9: ") and "swallowed-error" in n
                ]
                self.assertEqual(1, len(same), both)


class CommandTests(unittest.TestCase):
    SCORED = ([[squiggle(2, "swallowed_error")]], None)

    def scored(self):
        return (
            patch.object(loki, "hygiene_score", return_value=self.SCORED),
            patch.object(loki, "nits_score", return_value=(None, "no nits")),
        )

    def repository(self, root, config=None):
        git(root, "init", "-q")
        write_file(root, "a.py", "x = 1\n")
        if config is not None:
            write_file(root, ".loki/loki.json", json.dumps(config))
        commit(root)
        write_file(root, "a.py", "x = 1\ny = 2\n")

    def hook(self, root, *extra):
        model, nits = self.scored()
        with (
            argv("--root", str(root), "hook", "--file", "a.py", *extra),
            model,
            nits,
            patch.object(loki, "check_file", return_value=[]),
            patch.object(loki, "written_slop", return_value=[]),
        ):
            return capture_output(loki.main)

    def test_hook_reports_hygiene_when_configured(self):
        with temporary_root() as root:
            root = root.resolve()
            self.repository(root, {"hygiene": "on"})
            status, _, stderr = self.hook(root)
            self.assertEqual(0, status)
            self.assertIn("a.py:2: loki/hygiene-swallowed-error: why: `y = 2`", stderr)
            self.assertIn("NOT CHECKED nits: no nits", stderr)

    def test_hook_follows_the_variable_in_both_formats(self):
        with temporary_root() as root:
            root = root.resolve()
            self.repository(root)
            status, _, stderr = self.hook(root)
            self.assertEqual(0, status)
            self.assertIn("loki/hygiene-swallowed-error", stderr)
            status, stdout, _ = self.hook(root, "--format", "json")
            self.assertEqual(0, status)
            self.assertIn("loki/hygiene-swallowed-error", stdout)
            with patch.dict(os.environ, {"LOKI_HYGIENE": "off"}):
                status, _, stderr = self.hook(root)
            self.assertEqual(0, status)
            self.assertNotIn("hygiene", stderr)
            with (
                patch.dict(os.environ, {"LOKI_HYGIENE": "on"}),
                patch.object(
                    loki, "written_hygiene", side_effect=ValueError("git: boom")
                ),
            ):
                _, _, stderr = self.hook(root)
            self.assertIn("NOT CHECKED hygiene: git: boom", stderr)

    def test_hygiene_subcommand(self):
        with temporary_root() as root:
            root = root.resolve()
            self.repository(root, {"hygiene": "all"})
            model, nits = self.scored()
            with model, nits:
                with argv("--root", str(root), "hygiene", "--json"):
                    status, stdout, _ = capture_output(loki.main)
                self.assertEqual(0, status)
                self.assertEqual(
                    {
                        "findings": [
                            "a.py:2: loki/hygiene-swallowed-error: why: `y = 2`"
                        ],
                        "not_checked": ["NOT CHECKED nits: no nits"],
                    },
                    json.loads(stdout),
                )
                with argv(
                    "--root", str(root), "hygiene", "--file", "a.py", "--level", "on"
                ):
                    status, stdout, _ = capture_output(loki.main)
                self.assertIn("loki/hygiene-swallowed-error", stdout)
                with argv("--root", str(root), "hygiene", "--base", "nosuchrev"):
                    status, _, stderr = capture_output(loki.main)
                self.assertEqual(1, status)
                self.assertIn("loki: git:", stderr)
            commit(root, "more")
            with argv("--root", str(root), "hygiene"):
                status, stdout, _ = capture_output(loki.main)
            self.assertEqual((0, ""), (status, stdout))

    def test_init_installs_the_vendored_model(self):
        with temporary_root() as root:
            capture_output(loki.install_target, root)
            for name in ("__init__.py", "weights.npz"):
                installed = root / ".loki/vendor/codehygiene" / name
                source = loki.SOURCE_ROOT / "vendor/codehygiene" / name
                self.assertEqual(source.read_bytes(), installed.read_bytes())


if __name__ == "__main__":
    unittest.main()
