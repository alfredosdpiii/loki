import io
import json
import os
import sys
import unittest
from unittest.mock import patch

import loki
from tests.helpers import argv, capture_output, temporary_root, write_file
from tests.test_repository_guardrails import git


def rules(path, text, *, fallback=False):
    return [
        rule for rule, _, _ in loki.content_rule_findings(path, text, fallback=fallback)
    ]


class MaskingTests(unittest.TestCase):
    def test_javascript_masks_comments_strings_templates_and_regexes(self):
        text = (
            "const a = 'x.innerHTML = y'; // eval(z)\n"
            "/* location = q */ const b = `${c}`; const r = /catch {}/g;\n"
            "const d = a / 2 / 3; return /x/.test(d);\n"
        )
        masked = loki.mask_javascript(text)
        self.assertEqual(len(text), len(masked))
        self.assertEqual(text.count("\n"), masked.count("\n"))
        for hidden in ("innerHTML", "eval", "location", "catch", "${c}"):
            self.assertNotIn(hidden, masked)
        self.assertIn("a / 2 / 3", masked)

    def test_unterminated_literals_stop_at_line_or_end(self):
        self.assertEqual("'   \nx", loki.mask_javascript("'abc\nx"))
        self.assertEqual("     ", loki.mask_javascript("/* ab"))
        self.assertEqual('"    ', loki.mask_rust('"ab\\"'))
        self.assertEqual('r"  ', loki.mask_rust('r"ab'))
        self.assertEqual("~s(  ", loki.mask_elixir("~s(ab"))
        self.assertEqual('"""  ', loki.mask_elixir('"""ab'))
        self.assertEqual("/  ", loki.mask_javascript("/[/"))

    def test_elixir_masks_comments_sigils_heredocs_and_char_literals(self):
        text = (
            '# params["admin"] == true\n'
            'x = ~c"http://a" <> "b" <> ?# <> ?\\n\n'
            "y = '''\nparams\n'''\nvalid? = admin?\n"
        )
        masked = loki.mask_elixir(text)
        self.assertEqual(len(text), len(masked))
        self.assertNotIn("admin", masked.split("\n")[0])
        self.assertNotIn("http", masked)
        self.assertIn("valid? = admin?", masked)
        self.assertNotIn("params", masked.split("'''")[1])

    def test_rust_masks_nested_comments_raw_strings_and_chars_not_lifetimes(self):
        text = (
            "/* a /* todo!() */ b */ let s = r#\"todo!()\"#; let c = '\\u{1F600}';\n"
            "fn f<'a>(x: &'a str) -> char { 'x' } // unimplemented!()\n"
            'let raw = br"x"; let ident = var"x";\n'
        )
        masked = loki.mask_rust(text)
        self.assertEqual(len(text), len(masked))
        self.assertNotIn("todo", masked)
        self.assertNotIn("unimplemented", masked)
        self.assertIn("<'a>", masked)
        self.assertIn("&'a str", masked)

    def test_argument_and_expression_helpers(self):
        masked = "f(a, (b, c), [d])"
        spans = loki.split_arguments(masked, 1)
        self.assertEqual(["a", " (b, c)", " [d]"], [masked[s:e] for s, e in spans])
        self.assertEqual([], loki.split_arguments("f()", 1))
        self.assertEqual(len("x = (a"), loki.expression_end("x = (a", 4))
        self.assertEqual(len("(a"), loki.matching_close("(a", 0))


class JavaScriptRuleTests(unittest.TestCase):
    def test_html_sinks_require_literal_values(self):
        for defect in (
            "node.innerHTML = input;",
            "node.outerHTML += `<b>${name}</b>`",
            'node.insertAdjacentHTML("beforeend", html)',
            "document.write(markup)",
            "document.writeln(markup)",
            "<div dangerouslySetInnerHTML={{ __html: html }} />",
        ):
            with self.subTest(defect=defect):
                self.assertEqual(["loki/unsanitized-html"], rules("a.tsx", defect))
        for control in (
            "node.textContent = input;",
            'node.innerHTML = "";',
            "node.innerHTML = `<br>`;",
            'node.insertAdjacentHTML("beforeend", "<br>")',
            'document.write("ok")',
            "node.innerHTML == other",
            "<div dangerouslySetInnerHTML={{ __html: '<br>' }} />",
            "const text = 'node.innerHTML = input';",
        ):
            with self.subTest(control=control):
                self.assertEqual([], rules("a.tsx", control))

    def test_navigation_targets_must_be_pinned(self):
        for defect in (
            "location.href = input;",
            "window.location = next",
            "document.location.href = `${base}/x`",
            "location.assign(url)",
            "window.location.replace(target)",
            "location.href = '//evil.example' + path",
        ):
            with self.subTest(defect=defect):
                self.assertEqual(["loki/open-redirect"], rules("a.ts", defect))
        for control in (
            "if (input === '/home') location.href = '/home';",
            "location.href = `/users/${id}`",
            "location.href = '/items/' + id",
            "location.href = 'https://example.com/' + path",
            "location.assign('#top')",
            "location.replace()",
            "const location = 1; other.location = input",
            "if (location.href == input) {}",
        ):
            with self.subTest(control=control):
                self.assertEqual([], rules("a.ts", control))

    def test_dynamic_code_execution(self):
        self.assertEqual(["loki/code-eval"], rules("a.js", "eval(source)"))
        self.assertEqual(["loki/code-eval"], rules("a.js", "new Function('a', body)"))
        self.assertEqual([], rules("a.js", "eval('1 + 1'); obj.eval(x); eval()"))

    def test_fallback_rules_cover_oxlint_preview_equivalents(self):
        cases = {
            "try { run(); } catch {}": ["no-empty"],
            "try { run(); } catch (error) { }": ["no-empty"],
            "try { run(); } catch { /* optional */ }": [],
            "try { run(); } catch { return null; }": [],
            "new Promise(async resolve => resolve(1))": ["no-async-promise-executor"],
            "try { a(); } finally { return 1; }": ["no-unsafe-finally"],
            "try { a(); } finally { if (x) { throw e; } }": ["no-unsafe-finally"],
            "try { a(); } finally { done(() => { return 1; }); }": [],
            "try { a(); } finally { log(); }": [],
            "debugger;": ["no-debugger"],
            "const s = 'debugger';": [],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(expected, rules("a.ts", text, fallback=True))

    def test_fallback_test_rules_follow_framework_bindings(self):
        framework = 'import { describe, it as check, expect } from "vitest";\n'
        self.assertEqual(
            ["no-focused-tests"],
            rules(
                "src/a.ts", framework + "describe.only('x', () => {});", fallback=True
            ),
        )
        self.assertEqual(
            ["no-disabled-tests"],
            rules("src/a.ts", framework + "check.skip('x', () => {});", fallback=True),
        )
        self.assertEqual(
            ["no-disabled-tests"],
            rules("a.test.ts", 'test["skip"]("x", () => {});', fallback=True),
        )
        self.assertEqual(
            [], rules("a.test.ts", 'test["each"]("x", () => {});', fallback=True)
        )
        self.assertEqual(
            [],
            rules(
                "a.test.ts", "const test = { skip() {} }; test.skip();", fallback=True
            ),
        )
        self.assertEqual(
            [],
            rules(
                "src/a.ts",
                'import { test } from "./local"; test.skip();',
                fallback=True,
            ),
        )
        self.assertEqual(
            [], rules("src/a.ts", "describe.only('x', () => {});", fallback=True)
        )

    def test_fallback_is_javascript_only(self):
        self.assertEqual([], rules("a.py", "x = 1", fallback=True))
        self.assertEqual([], rules("README.md", "location.href = x"))


class OtherLanguageRuleTests(unittest.TestCase):
    def test_python_authorization_from_request_data(self):
        for defect in (
            'return request["is_admin"] is True',
            'if request.args.get("role") == "admin":\n    pass',
            'allowed = params["admin"] and user',
            'ok = not request.form["is_staff"]',
            'assert request.json["permissions"]',
            'x = 1 if req.cookies["superuser"] else 0',
            'while request.headers.get("x_scope"):\n    pass',
        ):
            with self.subTest(defect=defect):
                self.assertEqual(["loki/request-authorization"], rules("a.py", defect))
        for control in (
            'return user["is_admin"] is True',
            'return request.user["is_admin"] is True',
            'return request.session.get("role") == "admin"',
            'name = request["name"] == "x"',
            'role = request["role"]',
            "if request.get(key): pass",
            "if request.get(): pass",
            "if items[0]: pass",
            "def broken(:",
        ):
            with self.subTest(control=control):
                self.assertEqual([], rules("a.py", control))

    def test_elixir_request_authorization_and_ssrf(self):
        head = "defmodule W do\n  use W, :controller\n"
        self.assertEqual(
            ["loki/request-authorization"],
            rules(
                "a.ex", head + '  def h(_c, params), do: params["admin"] == true\nend'
            ),
        )
        self.assertEqual(
            ["loki/request-authorization"],
            rules(
                "a.ex", head + '  def h(c, p), do: if conn.params["role"], do: 1\nend'
            ),
        )
        self.assertEqual(
            ["loki/request-authorization"],
            rules("a.ex", head + '  def h(c, %{"is_admin" => true}), do: c\nend'),
        )
        self.assertEqual(
            [],
            rules(
                "a.ex", head + '  def h(c, %{"name" => true}), do: params["name"]\nend'
            ),
        )
        self.assertEqual(
            [],
            rules(
                "a.ex",
                head + '  def h(c, p), do: Map.put(c, :role, params["role"])\nend',
            ),
        )
        ssrf = (
            '  def h(_c, %{"url" => url}), '
            "do: :httpc.request(String.to_charlist(url))\n"
        )
        self.assertEqual(["loki/ssrf"], rules("a.ex", head + ssrf + "end"))
        self.assertEqual(
            ["loki/ssrf"],
            rules("a.ex", head + '  def h(c, p), do: Req.get!(params["url"])\nend'),
        )
        self.assertEqual(
            ["loki/ssrf"],
            rules(
                "a.ex",
                head + "  def h(c, query_params), do: HTTPoison.get(query_params)\nend",
            ),
        )
        self.assertEqual(
            [],
            rules(
                "a.ex",
                head
                + '  def h(_c, _p), do: :httpc.request(~c"https://example.invalid/")\nend',
            ),
        )
        self.assertEqual(
            [],
            rules(
                "a.ex", head + '  def h(_c, %{"id" => id}), do: Req.get!(@base)\nend'
            ),
        )

    def test_rust_placeholders(self):
        self.assertEqual(
            ["loki/placeholder"], rules("a.rs", "fn f() -> u32 { todo!() }")
        )
        self.assertEqual(
            ["loki/placeholder"], rules("a.rs", "fn f() { unimplemented![] }")
        )
        self.assertEqual(
            [], rules("a.rs", 'fn f() { let s = "todo!()"; my::todo!(); }')
        )


class NetNewTests(unittest.TestCase):
    def test_existing_findings_may_move_but_new_ones_are_reported(self):
        old = "node.innerHTML = a;\n"
        moved = "\n\nnode.innerHTML = a;\n"
        added = moved + "other.innerHTML = b;\n"
        self.assertEqual([], loki.content_rule_violations([("a.ts", old, moved)]))
        self.assertEqual(
            [
                "a.ts:4: loki/unsanitized-html: cross-site scripting (XSS): "
                "non-literal HTML assigned to innerHTML; use textContent or a sanitizer"
            ],
            loki.content_rule_violations([("a.ts", old, added)]),
        )


class PreviewIntegrationTests(unittest.TestCase):
    def protect(self, root, name, data, *, strict=False):
        payload = {"cwd": str(root), "tool_name": name, "tool_input": data}
        with (
            argv("--root", str(root), "protect", "--harness", "claude"),
            patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            patch.dict(os.environ, {"LOKI_STRICT": "1" if strict else "0"}),
        ):
            return capture_output(loki.main)

    def test_python_rust_and_elixir_writes_are_denied_before_landing(self):
        cases = {
            "app.py": 'def allowed(request):\n    return request["is_admin"] is True\n',
            "src/lib.rs": "pub fn count() -> u32 { todo!() }\n",
            "lib/web.ex": 'def h(_c, params), do: params["admin"] == true\n',
        }
        for path, content in cases.items():
            with self.subTest(path=path), temporary_root() as root:
                status, _, diagnostic = self.protect(
                    root, "Write", {"file_path": path, "content": content}
                )
                self.assertEqual(2, status)
                self.assertIn("loki/", diagnostic)
                self.assertFalse((root / path).exists())

    def test_non_javascript_without_exact_preview_defers_to_post_write(self):
        with temporary_root() as root:
            status, output, diagnostic = self.protect(
                root,
                "Edit",
                {"file_path": "app.py", "old_string": "a", "new_string": "b"},
            )
            self.assertEqual((0, "", ""), (status, output, diagnostic))

    def test_clean_python_preview_is_silent(self):
        with temporary_root() as root:
            status, output, diagnostic = self.protect(
                root, "Write", {"file_path": "app.py", "content": "x = 1\n"}
            )
            self.assertEqual((0, "", ""), (status, output, diagnostic))


class PostWriteContentTests(unittest.TestCase):
    def test_written_content_is_compared_with_head(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, "app.ts", "node.innerHTML = old;\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            path = write_file(
                root, "app.ts", "\nnode.innerHTML = old;\nx.innerHTML = y;\n"
            )
            findings = loki.written_content_violations(
                path, root, "app.ts", fallback=True, deadline=None
            )
            self.assertEqual(1, len(findings))
            self.assertIn("app.ts:3: loki/unsanitized-html", findings[0])
            path.write_text("try { a(); } catch {}\n")
            self.assertEqual(
                ["no-empty"],
                [
                    item.split(": ")[1]
                    for item in loki.written_content_violations(
                        path, root, "app.ts", fallback=True, deadline=None
                    )
                ],
            )
            self.assertEqual("", loki.head_text(root, "missing.ts"))

    def test_git_failures_skip_post_write_rules(self):
        with temporary_root() as root:
            path = write_file(root, "app.ts", "node.innerHTML = value;\n")
            self.assertEqual(
                [],
                loki.written_content_violations(
                    path, root, "app.ts", fallback=False, deadline=None
                ),
            )

    def test_non_blob_head_entries_count_as_new(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, "dir/file.txt", "x")
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            self.assertEqual("", loki.head_text(root, "dir"))


@unittest.skipUnless(loki.shutil.which("ruff"), "Ruff unavailable")
class PreviewRuffTests(unittest.TestCase):
    def test_new_ruff_findings_are_denied_before_the_write(self):
        template = (loki.SOURCE_ROOT / "templates/.ruff.toml").read_text()
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, ".ruff.toml", template)
            write_file(root, "app.py", "def read():\n    return missing\n")
            git(root, "add", ".")
            git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b")
            debt = [("app.py", "", "\n\ndef read():\n    return missing\n")]
            self.assertEqual(
                [],
                loki.preview_ruff(
                    root,
                    [("app.py", "def read():\n    return missing\n", debt[0][2])],
                    deadline=None,
                ),
            )
            findings = loki.preview_ruff(
                root,
                [("app.py", "", "def parse(t):\n    return eval(t)\n")],
                deadline=None,
            )
            self.assertEqual(1, len(findings))
            self.assertIn("app.py: S307", findings[0])
            self.assertEqual(
                [], loki.preview_ruff(root, [("a.ts", "", "x")], deadline=None)
            )

    def test_missing_committed_config_defers_to_post_write(self):
        with temporary_root() as root:
            self.assertEqual(
                [],
                loki.preview_ruff(root, [("app.py", "", "eval(x)\n")], deadline=None),
            )


class ServerSideRuleTests(unittest.TestCase):
    CASES = [
        (
            "a.py",
            "def f(request):\n    url = request.args['url']\n"
            "    return requests.get(url)\n",
            ["loki/ssrf"],
        ),
        (
            "a.py",
            "def f(request):\n    return httpx.post(url=request.json['u'])\n",
            ["loki/ssrf"],
        ),
        (
            "a.py",
            "def f(request):\n    u = request.GET.get('next')\n    full = base + u\n"
            "    return urlopen(full)\n",
            ["loki/ssrf"],
        ),
        ("a.py", "def f(request):\n    return requests.get(settings.API)\n", []),
        (
            "a.py",
            "def f(request):\n"
            "    return requests.get(API, params={'q': request.args['q']})\n",
            [],
        ),
        (
            "a.py",
            "def f(request):\n    u = request.user.profile_url\n"
            "    return requests.get(u)\n",
            [],
        ),
        ("a.py", "x: str = request.args['u']\nrequests.get(x)\n", ["loki/ssrf"]),
        (
            "a.js",
            "app.get('/', (req, res) => res.redirect(req.query.next));",
            ["loki/open-redirect"],
        ),
        ("a.js", "res.redirect('/home'); res.redirect()", []),
        (
            "a.js",
            "const { exec } = require('child_process'); exec(`ls ${dir}`);",
            ["loki/command-injection"],
        ),
        ("a.js", "child_process.execSync(command)", ["loki/command-injection"]),
        ("a.js", "import { exec } from 'node:child_process'; exec('ls -la');", []),
        ("a.js", "const m = /a/.exec(s); exec(s);", []),
        (
            "a.ts",
            "db.query(`SELECT * FROM users WHERE id = ${id}`)",
            ["loki/sql-injection"],
        ),
        (
            "a.ts",
            "db.query('SELECT * FROM users WHERE id = ' + id)",
            ["loki/sql-injection"],
        ),
        ("a.ts", "db.query('SELECT * FROM users WHERE id = $1', [id])", []),
        ("a.ts", "db.query(); r.query(x)", []),
    ]

    def test_cases(self):
        for path, text, expected in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(expected, rules(path, text))


GITHUB_TOKEN = "ghp_" + "aZ3kQ9mB7xL2pW8vR4tY6uI1oE5nC0sD9fGh"
WORKFLOW = """on: pull_request
jobs:
  a:
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - run: |
          echo hi
          echo ${{ github.head_ref }}
      - name: ok
        env:
          T: ${{ github.event.pull_request.title }}
"""


class GenericRuleTests(unittest.TestCase):
    CASES = [
        ("config.py", f"TOKEN = '{GITHUB_TOKEN}'\n", ["loki/secret"]),
        (".env", "AWS_KEY=AKIA" + "Z7QK3MBX2PWV8R4T\n", ["loki/secret"]),
        ("docs.md", "AKIAIOSFODNN7EXAMPLE\n", []),
        ("a.txt", "AKIAAAAAAAAAAAAAAAAA\n", []),
        ("key.pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n", ["loki/secret"]),
        (
            "a.py",
            "<<<<<<< HEAD\nx=1\n=======\nx=2\n>>>>>>> branch\n",
            ["loki/conflict-marker", "loki/conflict-marker"],
        ),
        ("README.md", "Title\n=======\n", []),
        (
            ".github/workflows/ci.yml",
            WORKFLOW,
            ["loki/actions-injection", "loki/actions-injection"],
        ),
        (".github/workflows/ci.yml", "steps:\n  - run: echo ${{ github.sha }}\n", []),
        ("ci.yml", WORKFLOW, []),
        (
            "a.ts",
            "const agent = new https.Agent({ rejectUnauthorized: false });",
            ["loki/tls-verification"],
        ),
        (
            "a.js",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
            ["loki/tls-verification"],
        ),
        (
            "a.js",
            "// rejectUnauthorized: false\nconst s = 'rejectUnauthorized: false';",
            [],
        ),
    ]

    def test_cases(self):
        for path, text, expected in self.CASES:
            with self.subTest(path=path, text=text[:40]):
                self.assertEqual(expected, rules(path, text))

    def test_secrets_are_denied_before_landing_in_any_file(self):
        with temporary_root() as root:
            payload = {
                "cwd": str(root),
                "tool_name": "Write",
                "tool_input": {"file_path": ".env", "content": f"T={GITHUB_TOKEN}\n"},
            }
            with (
                argv("--root", str(root), "protect", "--harness", "claude"),
                patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            ):
                status, _, diagnostic = capture_output(loki.main)
            self.assertEqual(2, status)
            self.assertIn("loki/secret", diagnostic)
            self.assertNotIn(GITHUB_TOKEN, diagnostic)

    def test_post_write_checks_non_source_files(self):
        with temporary_root() as root:
            git(root, "init", "-q")
            write_file(root, "README.md", "x\n")
            git(root, "add", ".")
            git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b")
            path = write_file(root, "notes.txt", f"{GITHUB_TOKEN}\n")
            findings = loki.check_file(path, root, {})
            self.assertEqual(1, len(findings))
            self.assertIn("notes.txt:1: loki/secret", findings[0])
            big = write_file(root, "big.txt", "x" * (4 * 1024 * 1024 + 1))
            self.assertEqual([], loki.check_file(big, root, {}))


class ScanContentTests(unittest.TestCase):
    def test_scan_reports_new_findings_in_changed_text_files(self):
        change = loki.FileChange
        findings = loki.changed_content_violations(
            [
                change("a.ts", b"", b"node.innerHTML = x;\n", None, "100644"),
                change("gone.ts", b"x", None, "100644", None),
                change("bin.dat", None, b"\xff\xfe", None, "100644"),
                change("big.txt", None, b"x" * (4 * 1024 * 1024 + 1), None, "100644"),
            ]
        )
        self.assertEqual(1, len(findings))
        self.assertIn("a.ts:1: loki/unsanitized-html", findings[0])


class ShellTimingOriginRuleTests(unittest.TestCase):
    CASES = [
        ("a.py", "import subprocess\nsubprocess.run(['sh', '-c', cmd])\n", 1),
        ("a.py", "subprocess.check_output(['bash', '-c', f'x {y}'])\n", 1),
        ("a.py", "subprocess.run(['sh', '-c', 'ls -la'])\n", 0),
        ("a.py", "subprocess.run(['tar', '-c', path])\n", 0),
        ("a.py", "subprocess.run(args)\n", 0),
        ("a.py", "if hmac.new(k, m, sha256).hexdigest() == sig:\n    pass\n", 1),
        ("a.py", "if expected_signature == provided:\n    pass\n", 1),
        ("a.py", "e = h.hexdigest()\np = x\nok = e == p\n", 1),
        ("a.py", "if signature == '':\n    pass\n", 0),
        ("a.py", "if len(digest) == 64:\n    pass\n", 0),
        ("a.py", "x = compute()\nif x == y:\n    pass\n", 0),
        ("a.py", "if a < signature:\n    pass\n", 0),
        ("a.js", "if (sig === expectedSignature) {}", 1),
        ("a.js", "if (hmac.digest('hex') !== header) {}", 1),
        ("a.js", "if (signature === undefined) {}", 0),
        ("a.js", "if (signature.length === 64) {}", 0),
        (
            "a.ts",
            "window.addEventListener('message', (e) => {\n"
            "  if (e.origin !== ORIGIN) return;\n  go(e.data);\n});",
            0,
        ),
        ("a.ts", "window.addEventListener('message', (e) => go(e.data));", 1),
        ("a.ts", "addEventListener('message', ({ data, origin }) => ok(origin));", 0),
        ("a.ts", "el.addEventListener('click', () => go());", 0),
        (
            "a.js",
            'import { exec } from "node:child_process";\n'
            "const run = util.promisify(exec);\nrun(`convert ${a}`);",
            1,
        ),
        (
            "a.rs",
            'let o = Command::new("sh").arg("-c").arg(format!("convert {}", p));',
            1,
        ),
        ("a.rs", 'let o = Command::new("bash").args(["-c"]).arg(cmd);', 1),
        ("a.rs", 'let o = Command::new("convert").arg(p).output();', 0),
        ("a.rs", 'let o = Command::new("sh").arg("-c").arg("ls -la").output();', 0),
        ("a.ex", 'System.cmd("sh", ["-c", "convert #{path}"])', 1),
        ("a.ex", 'System.cmd("sh", ["-c", command])', 1),
        ("a.ex", 'System.cmd("convert", [path, "-resize", "10"])', 0),
        ("a.ex", 'System.cmd("sh", ["-c", "uptime"])', 0),
        ("a.ex", ':os.cmd(~c"uptime")', 0),
        ("a.ex", ":os.cmd(String.to_charlist(cmd))", 1),
    ]

    def test_cases(self):
        for path, text, expected in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(expected, len(rules(path, text)), rules(path, text))
