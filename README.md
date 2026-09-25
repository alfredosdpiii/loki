# Loki

Loki puts deterministic checks around AI coding agents. It blocks edits to its
own policy files before they happen, checks source files after each write, and
runs repository-wide checks in CI.

Loki has no runtime dependencies. It needs Python 3.11 or newer.

## Supported agents

| Agent | Project integration |
| --- | --- |
| Claude Code | `.claude/settings.json` hooks |
| Codex | `.codex/hooks.json` hooks |
| Factory Droid | `.factory/hooks.json` hooks |
| Pi | `.pi/extensions/loki.ts` |
| OMP | `.omp/extensions/loki.ts` |

Claude supports Write/Edit/MultiEdit. Codex supports the canonical `apply_patch`
envelope. Factory supports Create/Edit; ApplyPatch is rejected until its payload
contract is verified. Unknown matched writes and malformed payloads are denied.
OMP uses its host-bundled native inspector for multi-file edits; unavailable
inspection rejects edits. OMP supports local filesystem targets and local
`file://` URLs, not remote/device URIs, selectors, archive members or SQLite rows.

## Install

Run the installer from this checkout and point it at a Git repository:

```bash
python3 /path/to/loki/loki.py init --dir /path/to/repository
```

The installer copies Loki into `.loki/`, adds the agent adapters, and installs
starter configuration for Ruff, Oxlint, golangci-lint, and GitHub Actions. It
merges supported JSON files and leaves existing standalone configuration files
untouched, except for adding Codex's hook-activation flag where safe.

Upgrade with `init --force`. Unrelated hook handlers survive upgrades. Bootstrap
and policy upgrades require independent review; scans reject their changes until
the accepted policy commit becomes the comparison base.

After installation:

1. Codex: trust the project, run `/hooks`, and approve the project hooks.
   The installer adds `features.hooks = true` to `.codex/config.toml` when absent.
   It preserves an explicit disable and reports TOML layouts requiring manual
   activation. It does not grant project or hook trust.
2. Pi: accept the project trust prompt.
3. Factory Droid loads `.factory/hooks.json`; Claude Code and OMP need no extra
   Loki approval.
4. For JavaScript or TypeScript, run the package-manager command printed by the
   installer.

Check the installation:

```bash
python3 .loki/loki.py scan
```

Use `--strict` in CI when a missing compiler or linter should fail the job:

```bash
python3 .loki/loki.py scan --strict --base origin/main
```

Add `--online` to check package names against their public registries.

The installer registers policy guidance at Claude prompt submission,
Codex/Factory session start, and Pi/OMP `before_agent_start`. Guidance describes
configured policy; it does not prove that a host activated its hooks or that an
analyzer is available. Enforcement remains in the checker and adapters.
Successful ordinary tool checks do not repeat the full policy. Hook warnings enter
the matching pre-tool or post-tool context; failures identify post-write checks as such.
The shared Pi/OMP adapter preserves both string prompts and OMP's array of prompt
segments. Unknown prompt shapes are left unchanged rather than replaced.

## What runs on every write

Before an agent edits a file, Loki checks every declared target, including move
destinations and deletions. Both spelled and resolved paths must stay inside the
project. Protected paths include `.loki/**`, owned agent hooks and
`.github/workflows/loki.yml`. `LOKI_ALLOW_PROTECTED=1` bypasses local pattern
protection only, never root confinement or repository integrity checks.

JavaScript/TypeScript writes with an exact content preview also get parser-backed
pre-write checks for empty blocks, disabled/focused tests, async Promise executors,
ignored executor returns, unsafe `finally` and optional chaining, constant binary
conditions, and debugger statements. These use the project's
`node_modules/.bin/oxlint`, or `oxlint` on PATH, verified with version 1.83.0.
They run against temporary before/after copies with fixed rules, no candidate
config and neutralized inline lint directives. No project file is changed.
Oxlint permits commented empty blocks; Loki does not judge whether the explanation
is truthful. Without Oxlint, Loki applies parser-free equivalents of those rules
(empty catch, async executor, unsafe `finally`, debugger, focused and disabled tests
bound to a test framework) and still reports `NOT CHECKED` for the missing analyzer.

Loki also has tool-free content rules that need no analyzer. They run on exact
previews before the write and again on the written file against its committed text:

| Language | Built-in rule |
| --- | --- |
| JavaScript/TypeScript | Non-literal HTML reaching `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` or `dangerouslySetInnerHTML` (XSS) |
| JavaScript/TypeScript | Navigation to a target not pinned by a same-origin or fixed-host literal, or returned by a sanitizer-named function such as `safeRedirect(...)` (open redirect) |
| JavaScript/TypeScript | `eval` or `new Function` with non-literal source |
| JavaScript/TypeScript | `res.redirect(...)` with `req.query`, `req.body`, `req.params`, headers or cookies (open redirect) |
| JavaScript/TypeScript | `child_process` `exec`/`execSync` with a non-literal command (command injection) |
| JavaScript/TypeScript | `.query`/`.execute`/`.raw`/`.unsafe`/`.prepare` with SQL built by `${}` or `+` (SQL injection) |
| Python | Privilege-named request fields (`request["is_admin"]`, `request.args.get("role")`) in comparisons or conditions |
| Python | `requests`, `httpx` or `urlopen` URLs derived from request data within a function (SSRF) |
| Elixir | Privilege-named `params` in comparisons or conditions, and `"admin" => true` in function heads |
| Elixir | HTTP client calls whose arguments use request parameters bound in the function head (SSRF) |
| Rust | `todo!()` and `unimplemented!()` placeholders |
| Any text file | Hardcoded credentials: AWS, GitHub, Slack, Stripe live, npm, Google and model-provider keys, private keys. Low-entropy and placeholder values are skipped |
| Any text file | Unresolved merge conflict markers |
| GitHub workflows and actions | Untrusted `github.event` fields or `github.head_ref` interpolated into `run:` scripts |
| JavaScript/TypeScript | `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0` |

`scan` applies the same rules to changed text files, net-new against the base.
Strings and comments are masked before matching, and findings compare by rule and
source-line text, so moved existing findings pass. These are narrow heuristics.
The authorization rules catch the direct pattern, not authorization logic in general.

Supported previews are Claude Write/Edit/MultiEdit, Factory Create/Edit,
Pi write/exact edit, and OMP write. Ambiguous replacements, Codex patches and OMP
native edit formats report `NOT CHECKED` for JavaScript/TypeScript content preview;
other languages rely on their post-write checks. Their path checks
remain active. Missing analyzers and incomplete reports also produce `NOT CHECKED`;
set `LOKI_STRICT=1` to deny those writes. `protect --file` alone remains a path check.

Findings are compared against the current on-disk file using rule, message,
source-line text, diagnostic span text and multiplicity. Unchanged-line debt and
line shifts pass, but edits to a line containing an existing finding may block.
This does not establish semantic equivalence or prevent races after admission.
Preview inputs and reconstructed files are limited to 4 MiB, with at most 256
sequential edits.

After a write, Loki inspects repository integrity before running formatters.
A single 20-second deadline covers the hook batch. Missing optional tools emit
`NOT CHECKED`; strict mode fails. Post-write failures report errors, not rollback.

| Language | Write-time checks | Repository checks |
| --- | --- | --- |
| Python | Net-new Ruff, import and AST checks; net-new mypy errors when mypy is installed; no automatic rewriting | Ruff, import and AST checks |
| JavaScript/TypeScript | Pre-write preview where supported; post-write Oxlint fixes; net-new project type errors when a committed `tsconfig.json` and compiler exist | Oxlint; project type check |
| Go | gofmt, go vet; golangci-lint issues on changed lines when installed | golangci-lint |
| Rust | rustfmt; net-new Clippy and compiler diagnostics for the enclosing crate | Clippy |
| Elixir/HEEx | Enclosing Mix project: format, net-new Credo; net-new Sobelow with the default Phoenix pack | Project tier per enclosing Mix project |

The added write-time analyzers compare against the committed base, so existing
debt and line shifts pass:

- **mypy** runs on the written Python files with fixed flags and an empty config
  file (`--ignore-missing-imports --follow-imports=silent`), so a working-tree
  config cannot weaken it. The committed text is supplied with `--shadow-file`,
  and that second run happens only when the first reports errors. It uses the
  project's `.venv/bin/mypy` or `mypy` on PATH, with a per-repository cache under
  `~/.cache/loki/mypy`.
- **golangci-lint** runs `--new-from-rev=HEAD` on the written file's package with
  the protected `.golangci.yml`, concurrently with `go vet`; its findings are
  reported only when `go vet` passes. The template enables gosec (SQL string
  building, variable request URLs, tainted subprocesses, disabled TLS
  verification) with its noisiest checks (G104, G301, G302, G304, G306, G404)
  excluded. errcheck skips conventionally ignored deferred closes (`io.Closer`,
  `*os.File`, `*os.Root`, `*sql.Rows`) and `http.ResponseWriter.Write`.
- **Clippy** runs `cargo clippy --offline --all-targets` with the Loki restriction
  lints as warnings. Findings are matched against a materialized base crate that
  shares the project's `target` directory, built only when the candidate has
  findings. Clippy restriction lints and compiler errors such as `E0308` and
  `E0382` are reported.

Missing optional analyzers are skipped; analyzer failures and timeouts are
`NOT CHECKED`, and strict mode fails them.

Scans compare actual base bytes and modes with the working tree, including staged
and nonignored untracked files. The default base is HEAD. Explicit invalid bases,
unmerged indexes and inspection failures fail. Non-strict scans outside Git
report repository checks as `NOT CHECKED`; strict scans require Git.

### Language policy defaults

| Language | Strengthened rules | Where they run |
| --- | --- | --- |
| Python | Pylint error rules, logging misuse, dangling asyncio tasks, stale suppressions, alongside existing Ruff safety rules | Committed-policy hook delta and repository lint |
| JavaScript/TypeScript | Eleven fixed preview rules; matching installed Oxlint rules and test plugins | Supported pre-write previews; post-write and scan policy |
| Go | Explicitly discarded errors, unchecked type assertions, wrapped-error comparisons, discarded nonnil errors, duration multiplication | golangci-lint repository scans |
| Rust | Compiler/Clippy warnings fail; `expect` joins the existing `unwrap`, `todo`, and `unimplemented` restrictions | Clippy repository scans, all targets |
| Elixir | Unsafe shell APIs, runtime atom creation, discarded immutable results, constant operations and rescue mistakes | Credo hooks and project checks after policy adoption |

The Ruff template ignores S603 and S607, which flag every shell-free
`subprocess` call and bare executable name, and E501, since the formatter owns
line length. `shell=True` and shell-string execution are still caught by S602,
S604 and S605.

The Oxlint template reports the anti-slop type-evidence rules and
`unicorn/no-array-sort` as warnings. Post-write hooks deliver up to ten warning
lines to the agent as `oxlint advisory (not blocking)` context; correctness,
suspicious and the pre-write preview rules still block. These rules encode taste
and type-discipline policy, not defects, so they no longer reject legitimate code.
Set them back to `"error"` in `.oxlintrc.json` to make them blocking.

The installer preserves existing `.ruff.toml`, `.golangci.yml` and `.credo.exs`,
including during `init --force`. Reconcile them with the templates and independently
review/commit the changes before relying on the stronger base-owned policy.
Oxlint upgrades merge the new rules and plugins, retaining unrelated rules but
updating Loki-owned settings. Engine-defined preview rules and Rust flags change
when the engine is upgraded.

A missing `.credo.exs` is installed when the target directory contains `mix.exs`.
For nested Mix projects, copy and review `templates/.credo.exs` in each project.
Root and nested Credo configuration files are now protected. Existing Sobelow
thresholds and compilation/Dialyzer tiers are unchanged.

These are policy restrictions, not proof that every flagged use is a bug.
Credo's atom rule also flags deliberate runtime atom/module construction, and
Rust's `expect` restriction includes tests. Those cases need policy review.
Go and Rust now run golangci-lint and Clippy at write time as described above.
SSRF and application-specific authorization are covered only by the narrow
built-in patterns listed earlier.

Run paired defects and repairs across all five languages:

```bash
python3 benchmarks/language_rules.py \
  --oxlint /absolute/path/to/oxlint \
  --golangci /absolute/path/to/golangci-lint \
  --credo-project /path/to/prepared/mix-project \
  --output /path/to/language-results.json
```

The runner also needs Ruff, Cargo/Clippy, and a compatible Elixir/OTP pair on PATH.
It uses temporary projects, records tool versions and policy hashes, and never
runs the fixture programs. Missing analyzers fail the matrix rather than counting
as clean results.

### Elixir and Phoenix

For nested projects, run `python3 loki.py elixir --project api --tier project --json`.
`--file lib/my_app/example.ex` selects files for the fast checks.
Ordinary `scan` groups Elixir/HEEx sources by their enclosing Mix project and runs
the project tier from each directory. Source discovery excludes `deps/` and
`_build/`. Missing analyzers are reported; strict scans fail on missing coverage.
Dialyzer remains an explicit deep-tier check rather than running on every scan.

`elixir --project api --credo-new --json` compares structured Credo findings in
isolated committed-base and candidate trees. It uses the base `.credo.exs` and the
same compiled dev analyzer, without running candidate Mix aliases. Existing matching
findings pass; new check/message/source-line fingerprints fail. Changes to Mix or
Credo configuration require separate review. The compiled analyzer and dependencies
remain trusted local inputs, not authenticated by this mode. Ordinary Elixir hooks
now use this comparison after checking formatting, under the shared 20-second
deadline. Unavailable comparison is `NOT CHECKED` in non-strict hooks and fails
strict hooks. Explicit tiers and repository scans retain whole-project checks.
They do not subtract baseline findings.
Multi-file hooks perform one Ruff comparison per Python batch and one comparison
per analyzer per enclosing Mix project. Credo unavailability does not skip Sobelow.
Per-file formatting/AST checks remain.
Reuse lasts only for that invocation, never across edits. Elixir files without an
enclosing Mix project are explicitly `NOT CHECKED`; strict hooks fail.

| Tier | Required checks |
| --- | --- |
| `fast` | `mix format --check-formatted`, strict Credo JSON |
| `project` | Fast checks, compile with warnings as errors, Sobelow |
| `deep` | Project checks plus Dialyxir/Dialyzer |

Ordinary hooks compare Sobelow source findings in isolated base and candidate
trees. Fingerprints include confidence, repository path, rule, source-line text
and diagnostic details, with multiplicity. Line-number shifts alone do not create
new findings. This remains diagnostic matching, not semantic equivalence.

This mode invokes the prepared dev Sobelow and Jason BEAM files directly. It does
not evaluate candidate Mix aliases or share writable `deps`/`_build` trees.
It uses `--private --strict --no-config`, ignores skip annotations, and rejects
Mix, Sobelow and application-config changes pending review. Even committed Sobelow
suppressions are ignored in this mode. Dependency vulnerability checks are excluded;
this is a source-security check, not a dependency audit. Compiled analyzers remain
trusted local inputs. Formatting and explicit project-tier Mix tasks still evaluate
project code and are not sandboxed.

The default hook threshold blocks new high-confidence findings, warns at medium,
and includes low findings as informational post-tool context. `none` disables the
corresponding block or warning threshold, not informational visibility. Analyzer
coverage notices remain visible and fail strict hooks. Credo and Sobelow rule
identifiers feed structured evidence.
Missing analyzer dependencies, invalid output and timeouts are `NOT CHECKED`, not
clean results; the explicit command exits nonzero. Hooks use the shared deadline;
explicit project/deep runs allow the existing per-command timeout. PLT creation can
exceed it and must then be prepared separately by the operator.

Loki does not add dependencies, fetch packages, run setup aliases, start Phoenix,
or invoke migrations/tests automatically. Mix tasks still evaluate project code and
can compile dependencies; use a trusted project or isolated copy. HEEx formatting
and compilation require the project's Phoenix/LiveView formatter/compiler setup.
This is analyzer integration, not universal proof of authorization, safe migrations,
supervision, or absence of N+1 queries. Existing Credo debt can still fail strict checks.

`rule_packs` defaults to `core`, `python`, `typescript`, `phoenix` and `shell`.
These select guidance; the Phoenix pack also enables write-time Sobelow.
Use `languages` to disable post-write language checks; fixed admission checks
remain active. Selecting the shell pack does not
install shell interception; that requires `init --shell-guard`.
`elixir_security.sobelow.block` accepts `none`, `low`, `medium` or `high`;
`warn` reports findings at that level without blocking. Defaults are high block,
medium warning. The injected context reflects these values.

### Reproduce the Phoenix benchmark

Copy `benchmarks/fixtures/phoenix/` to a disposable directory, including dotfiles
and the pinned `mix.lock`. Run `mix deps.get` and `mix deps.compile` there with a
compatible Elixir/OTP pair. The verified pair was Elixir 1.17.3 and OTP 27.
Then run:

```bash
python3 benchmarks/phoenix.py \
  --prepared-project /path/to/disposable/phoenix \
  --output /path/to/results.json --runs 2
```

The runner copies the prepared dependencies into a fresh project. It checks
installed hook commands, old-debt tolerance, bad/repair pairs, warning context,
and explicit HEEx/component compilation. It never calls the unsafe functions,
starts Phoenix, or connects to a database. Preparation is excluded from timings.
`--sobelow-block none` tests advisory-only behavior; `low` tests stricter blocking.
Git commits use the operator's existing identity and fail if it is unconfigured.

Sobelow distinguishes standard `use AppWeb, :controller` code from plain helpers.
The fixture includes both. Caller-controlled URL and authorization examples are
known coverage gaps, not security passes. Successful component repairs can still
fail the full project gate because that mode retains existing Credo debt.

The Phoenix benchmark does not test host startup. Separate real-host and
competitor probes are described below.

### Verify context in real hosts

```bash
python3 benchmarks/host_context.py --output /path/to/context-results.json
```

This starts installed agents with fresh homes and a loopback-only model stub.
It compares installed project-hook discovery against no-hook controls, checks
the actual model request for guidance, and verifies that the base prompt survives.
No existing sessions or provider credentials are used. Factory's platform requests
also go to the local stub. Codex runs in its read-only sandbox with trust granted
only for the generated fixture; Pi receives per-run fixture approval.

Verified discovery on 2026-09-20: OMP 18.2.6, Claude Code 2.1.258, Codex 0.152.1
and Factory 0.223.0. Pi 0.84.4 passed an earlier explicit-extension probe, but its
later startup failed with `supervisor_generation_stale`, including the no-hook
control. Automatic Pi discovery remains unverified in that run.

These are real host lifecycle tests with synthetic inference. They do not prove
that every tool operation is intercepted or that a user's live installation is
active. The runner exits nonzero for unavailable hosts or failed controls.

### Compare installed pre-hooks

`benchmarks/compare.py` retains the historical competitor pin.
The refreshed runner uses Interlinked commit
`207330d8131c5203ecc74e9fd4c24ba416463718`:

```bash
python3 benchmarks/compare_hooks.py \
  --interlinked /path/to/pinned/built/interlinked-cli \
  --node /absolute/path/to/node \
  --runs 5 --output /path/to/comparison.json
```

It installs both products in separate disposable Git repositories and runs matched
Claude pre-hook inputs with a warm local Interlinked daemon. Loki's conservative
shell guard is explicitly enabled. Proposed tools never execute. Admission decisions
and unavailable or deferred checks are recorded separately. This small pre-write
comparison is not an overall product ranking or a post-write analyzer comparison.
Add `--reviewed-test-command` for a separate run with an explicit, committed
permission for `npm test`. Reports include the permission configuration. Both
variants use the same package manifest; do not present the opted-in result as a
default-policy improvement.
Use `--oxlint /absolute/path/to/oxlint --content-controls` to make the same analyzer
available in both fixtures and add parser lookalikes, aliases and suppression
probes. The report records the analyzer version. Without it, Loki reports missing
pre-write content coverage rather than claiming a clean check.

The base commit's `protected_extra` patterns protect selected tests and fixtures
against any byte or mode change. Candidate policy cannot remove that protection
or replace the base command arrays. Ordinary test deletion/assertion/skip checks
remain heuristics, not proof that tests are valid.

Byte-identical ordinary test moves with unchanged file mode are paired one-to-one;
protected paths still fail on moves. A move combined with content changes still
requires review. The starter Ruff policy permits assertions in test files only.

Snapshot payloads are limited to 64 MiB of unique base blobs plus candidate bytes,
and 100,000 requested base objects. Exceeding either limit fails explicitly;
these are payload limits, not a total-process memory guarantee. Candidate reads
pin resolved parent directories with descriptor-relative, no-follow operations
on POSIX. This narrows directory-replacement races, not all concurrent-write races.

Tracked lockfile deletion fails while its manifest remains. Manifest edits do not
require meaningless lockfile edits. Configure a frozen-lock command in
`commands.contract` for semantic synchronization; without one Loki reports
`NOT CHECKED lock synchronization`. `--online` checks package-name existence and
fails on registry outages; it does not prove supply-chain safety and is off by
default, including in the CI template.

These hooks are not a sandbox. Unobserved shell writes, races, hard-link aliases,
host-enforced hook timeouts and replacement of the candidate-owned Loki executable
require external filesystem confinement or independently managed enforcement.
CI tools/actions still use floating versions; this template is not hermetic.

## Configuration

Project policy lives in `.loki/loki.json`. The installer starts with:

```json
{
  "approved_dependencies": null,
  "commands": {
    "contract": [],
    "property": [],
    "differential": [],
    "mutation": []
  }
}
```

Add repository-owned commands as arrays of arguments. Loki runs them during a
repository scan and reports their output under the command group.

Set `protected_extra` to repository-relative patterns such as
`["tests/oracles/**"]`. Dependency-name approval is opt-in; `null` disables it.
Unknown configuration keys and command groups fail validation. Commands containing
`{files}` are not invoked for an empty change list; `{base}` requires a resolved
commit. Policy-only changes must be reviewed through existing human-owned controls.

## Evidence and trusted execution

Use `protect --record` or `hook --record` to append event metadata outside the
repository under `~/.local/state/loki/`. `loki.py explain --limit 20` prints recent
events for the current project. Records contain paths, outcome, duration and engine
digest, not source bodies or command arguments. Recording is opt-in; this local
log is not tamper-proof and cannot establish that unobserved events were checked.

`scan --ruff-new` checks changed Python files using the committed base `.ruff.toml`
for both versions. It compares diagnostic code, message and source-line text with
multiplicity. Existing findings on unchanged lines do not block; new findings do.
The mode requires a self-contained base config without `extend`. It is a dedicated
Ruff check, not a replacement for the complete repository scan or cross-file typing.

Ordinary Python hooks now use this trusted-config net-new Ruff comparison for the
touched file. They require a committed, self-contained `.ruff.toml` and do not run
automatic Ruff fixes or formatting. Import/AST checks remain whole-file checks.

Project-wide TypeScript diagnostics are compared between the committed base and
the working tree, using the same compiler and the committed root `tsconfig.json`.
The working tree is checked first; the base snapshot is materialized only when the
candidate has diagnostics. Unchanged diagnostic fingerprints pass; new errors fail,
including errors in consumer files that did not change. The compiler comes from
`node_modules/typescript`, or from the TypeScript package behind `tsc` on PATH.
Base snapshots reject symlink/gitlink entries and oversized trees, and JSON changes
require separate configuration review. Dependency storage is shared, not
independently authenticated. This does not replace Oxlint.

By default (`typescript_check` unset) the check runs whenever a root `tsconfig.json`
exists. Setup problems, such as a missing compiler, an uncommitted JSON change or
an unsupported base entry, are then reported as `NOT CHECKED` rather than blocking;
strict mode fails them. `"typescript_check": true` makes the same setup problems
block, and `false` turns the check off.

`init --dir /repo --managed-dir /outside/repo/engines` installs a content-addressed
engine outside the candidate tree and points generated hooks/adapters at it.
Replacing `/repo/.loki/loki.py` does not replace that engine. The installer does not
change ownership, global hooks, sandbox settings or required CI checks. A same-user
agent can still alter owner-writable engine storage or project hook registration;
an operator must provide independent permissions/enforcement for stronger guarantees.

`python3 benchmarks/compare.py --interlinked /path/to/pinned/interlinked-cli`
runs the pinned cold pre-hook comparison. For a supervised running daemon, provide
`--workspace /fixture --socket /fixture/.interlinked/harness.sock`. Results record
engine identities, decisions, unavailability and timings. The three delivered-hook
cases are not a complete product ranking. Interlinked can encode denial in stdout
JSON with exit zero.

## Checked multi-file admission

`loki.py apply --manifest batch.json` accepts a JSON array of `write` operations
with `path`/`content`, `delete` with `path`, and `move` with `path`/`to`.
Paths must be canonical repository-relative paths. `--check-only` verifies without
applying. Checks run in an isolated tree before targets change. The command rejects
protected targets and concurrent repository changes observed before admission.
Python and configured TypeScript checks run; this is not universal language parity.
Loki writers share an advisory lock. Individual replacements are atomic, but the
whole batch is not OS-atomic or crash-atomic; uncooperative writers can still race
after the final comparison. Runtime failures attempt rollback, not guaranteed recovery.
Rollback first compares each applied target with the bytes and mode Loki wrote.
Observed concurrent changes are preserved and reported as `rollback incomplete`;
recovery continues for other targets. This comparison is not an atomic filesystem
compare-and-swap, so uncooperative writers can still race during recovery.

## Shell gate and evidence

`init --shell-guard` opts into conservative shell interception for Claude `Bash`,
Factory `Execute`, and Pi/OMP `tool_call` adapters. Simple Git status/diff/log/show,
pwd/whoami and plain `echo`/`printf` are allowed. An `echo` or `printf` may redirect
with `>` or `>>` into a `.txt`, `.md`, `.log`, `.rst`, `.csv`, `.tsv` or `.adoc` file
inside the repository that is not protected, symlinked, or under a dot-directory.
A redirect into source, configuration or any other file is denied as a write-check
bypass. Other redirects, substitutions, expansions and compound commands are rejected.
Destructive Git commands (`reset --hard`, forced `clean`/`push`, `branch -D`,
`stash drop`/`clear`, `checkout --`, `restore`, `rebase` and similar) are denied with
a message naming them. Other commands require explicit permissions. Codex shell payloads
and Pi user-entered shell events are unsupported.

An operator can review and commit exact commands in `.loki/loki.json`:

```json
{
  "shell_commands": [
    {
      "command": "npm test",
      "cwd": ".",
      "inputs": ["package.json", "package-lock.json"]
    }
  ]
}
```

Permissions default to an empty list. They come from the resolved `HEAD` commit,
never staged or working-tree policy. `cwd` is an exact repository-relative directory,
not a recursive scope. Each `inputs` entry is a repository-relative regular file
that must exist in that commit. The policy file is always an implicit input.
Loki compares actual bytes and executable mode before admitting the command,
even for files Git marks `assume-unchanged` or `skip-worktree`.

Changed, missing or symlinked inputs block the command. Extra arguments and
different command spelling need their own permission. Unknown tool-input fields
are rejected so they cannot override the checked command, environment or cwd.
Direct Git restrictions and the shell-syntax restrictions still apply. An approved
test command cannot be extended with `> notes.txt`; use checked file tools for logs.

This grants execution, not filesystem confinement. `npm test` can run lifecycle
scripts, edited tests and dependency code. Declared inputs are integrity prerequisites,
not a complete dependency list. PATH, environment, undeclared configuration and
dependencies are not authenticated. Files can also change after the hook returns.
Use an independent sandbox and protect the engine, hook registration and Git refs
when the agent must not have those powers. Do not let an agent approve its own
permissions by committing them.

`--record` includes early parser/config failures and schema-version-2 evidence.
`findings` contains rule IDs and target paths emitted by decision sites, not inferred
from message wording. Failures without an instrumented rule are explicitly
`unclassified-failure`. `policies` contains the exact bytes' SHA-256 captured when
read, their candidate/base source, path and resolved base commit where applicable.
Missing policy is recorded with a null digest. Policy files are not reread afterward.
No shell text or source bodies are stored. The log resets after 4 MiB with an explicit
retention marker. Recording failures return exit 2. This is local evidence, not
tamper-proof proof of host activation or independent enforcement.

`verify-installation --engine /path/loki.py --registration /path/hooks.json
--agent-uid UID` checks engine/registration files and ancestor ownership/modes.
It rejects agent-owned and group/world-writable paths. Operators must separately
verify ACLs, interpreter/dependency trust, hook activation and privileged identities.
An operator-owned install plus host confinement/required checks must be deployed by
the operator; this command does not install a sandbox or establish those controls.

## Development

The broader comparison protocol is in [benchmarks/README.md](benchmarks/README.md).
It separates pre-write prevention, post-write detection, explicit audits,
configuration sensitivity, and live-host activation. Synthetic cases are not a
production security guarantee or an independent product ranking.

Run the tests:

```bash
uv run --frozen pytest -q
bun test ./tests/loki-shim.test.ts ./tests/loki-omp.test.ts
```

Set `LOKI_TEST_OXLINT=/absolute/path/to/oxlint` on both the pytest and Bun commands
to run the real-analyzer and installed-adapter preview tests. They are explicitly
skipped when that variable is absent.

Check formatting and lint:

```bash
ruff check --config templates/.ruff.toml loki.py tests \
  benchmarks/phoenix.py benchmarks/host_context.py benchmarks/compare_hooks.py \
  benchmarks/language_rules.py benchmarks/recheck.py benchmarks/corpus.py \
  benchmarks/comprehensive.py benchmarks/configured.py benchmarks/native_projects.py \
  benchmarks/report_comprehensive.py
ruff format --check loki.py tests \
  benchmarks/phoenix.py benchmarks/host_context.py benchmarks/compare_hooks.py \
  benchmarks/language_rules.py benchmarks/recheck.py benchmarks/corpus.py \
  benchmarks/comprehensive.py benchmarks/configured.py benchmarks/native_projects.py \
  benchmarks/report_comprehensive.py
```
