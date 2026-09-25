"""Versioned synthetic cases, specified before observing either product's results.

These are author-written cases, not an independent or statistically representative
sample. Expected defects include deliberately unsupported semantic security cases.
"""

import hashlib
import json

VERSION = 2


def step(path, content, kind, markers=(), *, tool="Write", **extra):
    return {
        "path": path,
        "content": content,
        "kind": kind,
        "markers": list(markers),
        "tool": tool,
        **extra,
    }


def corpus():
    cases = []

    def pair(name, language, path, bad, good, markers, *, base=None, family="bug"):
        for phase, content in (("defect", bad), ("control", good)):
            cases.append(
                {
                    "id": f"{language}/{name}/{phase}",
                    "pair": f"{language}/{name}",
                    "language": language,
                    "family": family,
                    "base": base or {},
                    "steps": [
                        step(path, content, phase, markers if phase == "defect" else ())
                    ],
                }
            )

    python = [
        (
            "undefined-return",
            "def total():\n    return missing_total\n",
            "def total():\n    return 42\n",
            [r"F821", r"undefined.name", r"not defined"],
        ),
        (
            "mutable-default",
            "def collect(value, items=[]):\n"
            "    items.append(value)\n    return items\n",
            "def collect(value, items=None):\n"
            "    if items is None:\n        items = []\n"
            "    items.append(value)\n    return items\n",
            [r"B006", r"mutable.*default"],
        ),
        (
            "eval-input",
            "def parse(text):\n    return eval(text)\n",
            "import json\n\n\ndef parse(text):\n    return json.loads(text)\n",
            [r"S307", r"(?:unsafe|dangerous).*eval", r"eval.*(?:unsafe|dangerous)"],
        ),
        (
            "shell-interpolation",
            "import subprocess\n\n\ndef run(name):\n"
            '    return subprocess.run(f"echo {name}", shell=True, check=True)\n',
            "import subprocess\n\n\ndef run(name):\n"
            '    return subprocess.run(["/bin/echo", name], check=True)\n',
            [r"S602", r"shell=True", r"shell.injection"],
        ),
        (
            "sql-interpolation",
            "def find(cursor, name):\n"
            "    return cursor.execute("
            "f\"SELECT id FROM users WHERE name = '{name}'\")\n",
            "def find(cursor, name):\n"
            '    return cursor.execute("SELECT id FROM users WHERE name = ?", '
            "(name,))\n",
            [r"S608", r"SQL.injection"],
        ),
        (
            "unsafe-deserialization",
            "import pickle\n\n\ndef parse(data):\n    return pickle.loads(data)\n",
            "import json\n\n\ndef parse(data):\n    return json.loads(data)\n",
            [r"S301", r"pickle", r"deserializ"],
        ),
        (
            "broad-exception-loss",
            "def read(value):\n    try:\n        return int(value)\n"
            "    except Exception:\n        pass\n",
            "def read(value):\n    try:\n        return int(value)\n"
            "    except ValueError:\n        return None\n",
            [r"S110", r"except.*pass", r"swallow"],
        ),
        (
            "return-type",
            'def count() -> int:\n    return "three"\n',
            "def count() -> int:\n    return 3\n",
            [r"return.value", r"incompatible.*return", r"expected.*int"],
        ),
        (
            "syntax",
            "def count(:\n    return 3\n",
            "def count():\n    return 3\n",
            [r"syntax", r"expected.*parameter"],
        ),
        (
            "authorization-from-request",
            'def allowed(request, user):\n    return request["is_admin"] is True\n',
            'def allowed(request, user):\n    return user["is_admin"] is True\n',
            [r"authorization", r"trust.*(?:request|client)", r"privilege"],
        ),
    ]
    for name, bad, good, markers in python:
        pair(name, "python", "app.py", bad, good, markers)

    typescript = [
        (
            "assignment-type",
            'export const attempts: number = "three";\n',
            "export const attempts: number = 3;\n",
            [r"TS2322", r"not assignable to type"],
        ),
        (
            "argument-type",
            "function double(value: number) { return value * 2; }\n"
            'export const result = double("two");\n',
            "function double(value: number) { return value * 2; }\n"
            "export const result = double(2);\n",
            [r"TS2345", r"not assignable.*parameter"],
        ),
        (
            "null-access",
            "export function length(value: string | null) { return value.length; }\n",
            "export function length(value: string | null) { return value?.length; }\n",
            [r"TS18047", r"possibly.*null"],
        ),
        (
            "swallowed-error",
            "export function parse(text: string) {\n"
            "  try { return JSON.parse(text); } catch {}\n}\n",
            "export function parse(text: string) {\n"
            "  try { return JSON.parse(text); } catch { return null; }\n}\n",
            [r"no-empty", r"empty.*(?:catch|block)", r"swallow"],
        ),
        (
            "async-promise",
            "export const pending = new Promise(async resolve => { resolve(1); });\n",
            "export const pending = new Promise(resolve => { resolve(1); });\n",
            [r"no-async-promise-executor", r"async.*executor"],
        ),
        (
            "finally-return",
            "export function run() { try { throw new Error('failed'); } "
            "finally { return 1; } }\n",
            "export function run() { try { throw new Error('failed'); } "
            "finally { console.error('cleanup'); } }\n",
            [r"no-unsafe-finally", r"unsafe.*finally", r"finally.*(?:return|override)"],
        ),
        (
            "dom-injection",
            "export function show(node: HTMLElement, input: string) "
            "{ node.innerHTML = input; }\n",
            "export function show(node: HTMLElement, input: string) "
            "{ node.textContent = input; }\n",
            [r"no-unsanitized", r"cross.site.scripting", r"\bXSS\b"],
        ),
        (
            "redirect-from-input",
            "export function navigate(input: string) { location.href = input; }\n",
            "export function navigate(input: string) "
            "{ if (input === '/home') location.href = '/home'; }\n",
            [r"open.redirect", r"unvalidated.redirect"],
        ),
        (
            "syntax",
            "export const value = ;\n",
            "export const value = 1;\n",
            [r"parse", r"syntax", r"expression expected", r"unexpected"],
        ),
    ]
    for name, bad, good, markers in typescript:
        pair(name, "typescript", "src/main.ts", bad, good, markers)
    pair(
        "cross-file-contract",
        "typescript",
        "src/api.ts",
        'export function amount() { return "five"; }\n',
        "export function amount() { return 5; }\n",
        [r"TS2322", r"not assignable to type"],
        base={
            "src/api.ts": "export function amount() { return 4; }\n",
            "src/main.ts": "import { amount } from './api';\n"
            "export const value: number = amount();\n",
        },
        family="cross-file",
    )
    pair(
        "removed-export",
        "typescript",
        "src/api.ts",
        "export const other = 4;\n",
        "export const value = 5;\n",
        [r"TS2305", r"no exported member", r"missing.*export"],
        base={
            "src/api.ts": "export const value = 4;\n",
            "src/main.ts": "import { value } from './api';\nexport { value };\n",
        },
        family="cross-file",
    )
    for name, bad, good, markers in (
        (
            "disabled-suite",
            'import { describe, it, expect } from "vitest"; '
            'describe.skip("suite", () => { '
            'it("adds", () => { expect(2 + 2).toBe(4); }); });\n',
            'import { describe, it, expect } from "vitest"; '
            'describe("suite", () => { '
            'it("adds", () => { expect(2 + 2).toBe(4); }); });\n',
            [r"disabled.test", r"skip", r"disabled.*suite"],
        ),
        (
            "focused-suite",
            'import { describe, it, expect } from "vitest"; '
            'describe.only("suite", () => { '
            'it("adds", () => { expect(2 + 2).toBe(4); }); });\n',
            'import { describe, it, expect } from "vitest"; '
            'describe("suite", () => { '
            'it("adds", () => { expect(2 + 2).toBe(4); }); });\n',
            [r"focused.test", r"only", r"focused.*suite"],
        ),
    ):
        pair(name, "javascript", "checks.test.js", bad, good, markers, family="tests")

    go = [
        (
            "format-type",
            'package main\nimport "fmt"\nfunc main() { fmt.Printf("%d", "text") }\n',
            'package main\nimport "fmt"\nfunc main() { fmt.Printf("%s", "text") }\n',
            [r"Printf", r"format.*(?:type|string)", r"printf"],
        ),
        (
            "undefined-name",
            "package main\nfunc main() { missing() }\n",
            "package main\nfunc main() {}\n",
            [r"undefined.*missing", r"undeclared"],
        ),
        (
            "discarded-error",
            'package main\nimport "os"\nfunc main() { _ = os.Remove("unused") }\n',
            'package main\nimport "os"\nfunc main() { '
            'if err := os.Remove("unused"); err != nil { panic(err) } }\n',
            [r"errcheck", r"error.*(?:not checked|ignored|unchecked)"],
        ),
        (
            "duration-square",
            'package main\nimport "time"\n'
            "func scale(d time.Duration) time.Duration { return d * time.Second }\n"
            "func main() { _ = scale(time.Second) }\n",
            'package main\nimport "time"\n'
            "func scale(d time.Duration) time.Duration { return d }\n"
            "func main() { _ = scale(time.Second) }\n",
            [r"durationcheck", r"duration.*(?:multipli|duration)"],
        ),
    ]
    for name, bad, good, markers in go:
        pair(name, "go", "main.go", bad, good, markers)
    rust = [
        (
            "type-mismatch",
            'pub fn count() -> u32 { "five" }\n',
            "pub fn count() -> u32 { 5 }\n",
            [r"E0308", r"mismatched types"],
        ),
        (
            "use-after-move",
            'pub fn count() -> usize { let a = String::from("x"); '
            "let b = a; a.len() + b.len() }\n",
            'pub fn count() -> usize { let a = String::from("x"); '
            "let b = &a; a.len() + b.len() }\n",
            [r"E0382", r"borrow of moved value"],
        ),
        (
            "ignored-result",
            'pub fn read() { std::fs::read_to_string("unused"); }\n',
            "pub fn read() -> std::io::Result<String> "
            '{ std::fs::read_to_string("unused") }\n',
            [r"unused_must_use", r"unused.*Result", r"must be used"],
        ),
        (
            "placeholder",
            "pub fn count() -> u32 { todo!() }\n",
            "pub fn count() -> u32 { 5 }\n",
            [r"todo", r"placeholder", r"unimplemented"],
        ),
    ]
    for name, bad, good, markers in rust:
        pair(name, "rust", "src/lib.rs", bad, good, markers)

    controller = "lib/loki_phoenix_fixture_web/input_controller.ex"
    prefix = (
        "defmodule LokiPhoenixFixtureWeb.InputController do\n"
        "  @moduledoc false\n  use LokiPhoenixFixtureWeb, :controller\n\n"
    )
    for name, bad, good, markers in (
        (
            "decode-untrusted-term",
            'def handle(_conn, %{"data" => data}), do: :erlang.binary_to_term(data)',
            'def handle(_conn, %{"data" => data}), do: Jason.decode(data)',
            [r"BinToTerm", r"binary_to_term", r"deserialization"],
        ),
        (
            "code-from-request",
            'def handle(_conn, %{"data" => data}), do: Code.eval_string(data)',
            'def handle(_conn, %{"data" => data}), do: Jason.decode(data)',
            [r"CodeModule", r"code.execution", r"eval_string"],
        ),
        (
            "atom-from-request",
            'def handle(_conn, %{"data" => data}), do: String.to_atom(data)',
            'def handle(_conn, %{"data" => data}), do: data in ["one", "two"]',
            [r"StringToAtom", r"UnsafeToAtom", r"atom.*exhaust"],
        ),
        (
            "ssrf",
            'def handle(_conn, %{"url" => url}), '
            "do: :httpc.request(String.to_charlist(url))",
            'def handle(_conn, _params), do: :httpc.request(~c"https://example.invalid/")',
            [r"\bSSRF\b", r"server.side.request", r"untrusted.*URL"],
        ),
        (
            "request-authorization",
            'def handle(_conn, params), do: params["admin"] == true',
            "def handle(conn, _params), do: conn.assigns.current_user.admin?",
            [r"authorization", r"privilege", r"trust.*(?:request|client)"],
        ),
    ):
        pair(
            name,
            "elixir",
            controller,
            prefix + "  " + bad + "\nend\n",
            prefix + "  " + good + "\nend\n",
            markers,
            family="phoenix-security",
        )

    # Admission-only cases never execute proposed commands or escaped writes.
    for name, path, content, kind, tool, markers in (
        (
            "outside-root",
            "../outside.py",
            "value = 1\n",
            "defect",
            "Write",
            ["outside", "escape", "root"],
        ),
        (
            "policy-write",
            ".claude/settings.json",
            "{}\n",
            "defect",
            "Write",
            ["protect", "policy", "hook"],
        ),
        (
            "policy-via-symlink",
            "policy-link",
            "{}\n",
            "defect",
            "Write",
            ["protect", "policy", "symlink", "hook"],
        ),
        ("ordinary-doc", "notes.md", "A plain project note.\n", "control", "Write", []),
        (
            "reset-hard",
            None,
            "git reset --hard",
            "defect",
            "Bash",
            ["destructive", "reset", "blocked"],
        ),
        (
            "source-redirect",
            None,
            "printf 'x' > app.py",
            "defect",
            "Bash",
            ["shell", "redirect", "write"],
        ),
        ("status", None, "git status --short", "control", "Bash", []),
        ("reviewed-test", None, "npm test", "control", "Bash", []),
        (
            "documentation-redirect",
            None,
            "printf 'note' > notes.txt",
            "control",
            "Bash",
            [],
        ),
    ):
        cases.append(
            {
                "id": f"admission/{name}",
                "pair": None,
                "language": "none",
                "family": "admission",
                "base": {},
                "steps": [
                    step(path, content, kind, markers, tool=tool, admission_only=True)
                ],
            }
        )
    for language, path, old, good, markers in (
        (
            "python",
            "app.py",
            "def read():\n    return missing\n",
            "def read():\n    return 4\n",
            [r"F821", r"undefined.name", r"not defined"],
        ),
        (
            "typescript",
            "src/main.ts",
            'export const value: number = "old";\n',
            "export const value: number = 4;\n",
            [r"TS2322", r"not assignable"],
        ),
    ):
        cases.extend(
            [
                {
                    "id": f"debt/{language}/shift",
                    "pair": None,
                    "language": language,
                    "family": "existing-debt",
                    "base": {path: old},
                    "steps": [step(path, "\n\n" + old, "control")],
                },
                {
                    "id": f"workflow/{language}/break-repair",
                    "pair": None,
                    "language": language,
                    "family": "workflow",
                    "base": {path: good},
                    "steps": [
                        step(path, old, "defect", markers),
                        step(path, good.replace("4", "5"), "control"),
                    ],
                },
            ]
        )
    for name, path, content in (
        (
            "literal",
            "src/main.ts",
            'export const example = "catch {} test.skip() debugger;";\n',
        ),
        (
            "comment",
            "src/main.ts",
            "// catch {} and debugger; are documentation.\nexport const value = 1;\n",
        ),
        ("regex", "src/main.ts", r"export const pattern = /catch \{\}/;" + "\n"),
        ("test-assertion", "test_app.py", "def test_value():\n    assert 2 + 2 == 4\n"),
    ):
        language = "python" if path.endswith(".py") else "typescript"
        cases.append(
            {
                "id": f"control/{name}",
                "pair": None,
                "language": language,
                "family": "lexical-control",
                "base": {},
                "steps": [step(path, content, "control")],
            }
        )
    for size in (10, 1000, 10000):
        cases.append(
            {
                "id": f"scale/{size}-tracked-files",
                "pair": None,
                "language": "python",
                "family": "scale",
                "tracked_files": size,
                "base": {},
                "steps": [step("app.py", "def total():\n    return 43\n", "control")],
            }
        )
    for case in list(cases):
        if case["pair"] in (
            "python/undefined-return",
            "typescript/assignment-type",
            "javascript/disabled-suite",
        ):
            cases.append(
                {
                    **case,
                    "id": "exact-edit/" + case["id"],
                    "pair": "exact-edit/" + case["pair"],
                    "family": "exact-edit",
                    "steps": [{**item, "tool": "Edit"} for item in case["steps"]],
                }
            )
    cases.append(
        {
            "id": "workflow/typescript/multi-file-repair",
            "pair": None,
            "language": "typescript",
            "family": "workflow",
            "base": {
                "src/api.ts": "export function amount() { return 4; }\n",
                "src/main.ts": "import { amount } from './api';\n"
                "export const value: number = amount();\n",
            },
            "steps": [
                step(
                    "src/api.ts",
                    'export function amount() { return "five"; }\n',
                    "defect",
                    [r"TS2322", r"not assignable"],
                ),
                step(
                    "src/main.ts",
                    "import { amount } from './api';\n"
                    "export const value: string | number = amount();\n",
                    "control",
                ),
            ],
        }
    )
    return cases


def manifest():
    cases = corpus()
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate corpus IDs")
    encoded = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    return {
        "version": VERSION,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "cases": cases,
    }
