# Loki vs Interlinked, 2026-09-25

Loki now catches more defects than Interlinked CLI in every profile measured
here. It also blocks fewer legitimate edits and prevents more edits before
they land. Interlinked is still faster on Go, Elixir and Python writes in the
shared-scaffolding profile, where it defers or skips analysis. Loki is faster on
TypeScript, on Python in native projects, and when project-local JS tools are
missing.

These results come from synthetic cases, not production repositories or live
model sessions. The development corpus was written by Loki's author, and Loki's
rules were changed while looking at it. The holdout below is the fairer test.

## Setup

- Loki commit `dd96503` (engine in a frozen snapshot; identity unchanged at the end).
- Interlinked commit `82307ea` (upstream `main` on 2026-09-23), balanced install.
  The earlier report used the older pin `207330d`, which caught 19/47 on the
  shared development corpus; this commit catches 20/47.
- Three repetitions per case, seed 20260925, fresh repository, home and daemon
  each time, bubblewrap with no network. A case counts as caught only if every
  repetition matches.
- The three suites ran concurrently on one 16-thread machine. That inflates
  absolute latency for both products equally; detection is unaffected.
- Same tools as before: Node 23.11.1, Oxlint 1.83.0 with `@oxlint/plugins`,
  TypeScript 5.9.3, Ruff 0.15.2, mypy 1.19.1, golangci-lint 2.6.2, Go 1.25.6,
  Elixir 1.17.3 on OTP 27. Clippy was 0.1.92 here, not 0.1.97.

## Results

| Suite | Loki caught | Interlinked caught | Loki prevented before write | Interlinked prevented | Loki false blocks | Interlinked false blocks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development corpus, shared tools | 47/47 | 20/47 | 36/47 | 10/47 | 0/55 | 1/55 |
| Development corpus, no project-local JS tools | 17/17 | 13/17 | 17/17 | 6/17 | 0/21 | 1/21 |
| Native Python/Go/Rust/Elixir projects | 25/25 | 12/25 | 14/25 | 1/25 | 0/26 | 0/26 |
| Holdout, first run before any tuning (1 repetition) | 25/48 | 11/48 | 10/48 | 6/48 | 11/48 | 1/48 |
| Holdout, after tuning (3 repetitions) | 32/48 | 11/48 | 17/48 | 6/48 | 0/48 | 1/48 |

On the 2026-09-21 run, Loki caught 26/47 shared and 2/17 missing-tool defects,
with 2/55 false blocks.

Loki's explicit `scan --base HEAD` still finds 8/8 targeted Go/Rust defects with
8/8 controls passing; Interlinked's `verify --json` finds 0/8.

### The holdout

A separate agent wrote the 48 holdout pairs (`benchmarks/holdout_cases.json`).
It could not read either product's code, templates or the development corpus,
and it checked every control against real compilers and linters. The cases were
committed (`082eb47`) before Loki ran on them.

The first run is the honest generalization number: Loki caught 25/48 against
Interlinked's 11/48, but it also blocked 11 legitimate controls. Ten of those came
from taste and noise rules (the anti-slop Oxlint plugin, Ruff E501/S607, gosec
G304, errcheck on deferred closes). The eleventh was a false positive in Loki's
own open-redirect rule. Two misses exposed a real bug: new TypeScript files were
skipped by the pre-write type check but still marked as validated.

After fixing those and adding rules for shell `-c` injection, timing-unsafe
comparisons, `postMessage` origin checks and `defer` in loops, Loki reached
32/48 with no false blocks. From that point the holdout is no longer blind, so
treat 32/48 as a tuned result.

Sixteen holdout defects remain uncaught by Loki. Most are semantic (inverted
expiry check, off-by-one pagination, tautological test, numeric sort without a
comparator), need type-aware or taint analysis (floating promise, prototype
pollution, path traversal through `os.path.join`/`Path::join`, SSRF through
`fetch`), or would need a compile step Loki does not run in hooks (Elixir
undefined function). Interlinked missed all 16 as well. Every holdout defect
Interlinked catches, Loki also catches.

## Latency

Startup-warmed hook wall-clock, pre plus post, milliseconds (median / p95).
Each fixture has a cold compiler cache, so these are cold-analysis numbers.

| Language (development corpus, shared) | Loki | Interlinked |
| --- | ---: | ---: |
| TypeScript | 875 / 1,150 | 5,991 / 6,504 |
| TypeScript, no project-local tools | 659 / 931 | 10,652 / 10,956 |
| Python | 232 / 911 | 308 / 494 |
| Python, native projects | 239 / 1,075 | 1,275 / 1,937 |
| Rust | 399 / 548 | 282 / 317 |
| Elixir | 895 / 2,169 | 182 / 209 |
| Go | 3,253 / 3,732 | 278 / 305 |

- **Go and Elixir.** The gap there is Loki doing work Interlinked skips.
  Interlinked defers its Go checks in this hook path and caught none of the Go
  or Elixir defects. Loki builds the package (`go vet`, golangci-lint) and runs
  Credo/Sobelow from a cold cache.
- **Python.** In the holdout, Loki's Python median rises to about 1 s because
  most holdout Python files are annotated, which triggers a cold mypy run.

## What changed in Loki

- **TypeScript type checking** is on by default when a committed `tsconfig.json`
  exists. It checks proposed content before the write, including new files, and
  doesn't compile the same tree twice.
- **Tool resolution.** Oxlint and `tsc` are found on PATH when a project doesn't
  install them, and parser-free fallbacks cover the Oxlint preview rules.
- **Write-time analyzers:** mypy on annotated Python, golangci-lint on changed
  lines (now with gosec and `deferInLoop`), and Clippy/rustc against the
  committed base. Ruff also runs before the write.
- **Tool-free rules**, net-new, before and after writes and in `scan`:
  - XSS, open redirects, `eval`, command and SQL injection, disabled TLS
    verification and `postMessage` origin checks in JS/TS.
  - Request-derived authorization and SSRF in Python and Elixir.
  - Shell `-c` injection in Python, Rust, Elixir and JS.
  - Timing-unsafe signature comparison in Python and JS.
  - Rust placeholders.
  - Hardcoded credentials, merge-conflict markers and GitHub Actions script
    injection in any file.
- **Taste rules** (anti-slop Oxlint plugin, `no-array-sort`) are now advisory
  context rather than blocking. Ruff ignores E501/S603/S607. errcheck skips
  conventionally ignored deferred closes.
- **Shell guard:** `echo`/`printf` may write plain text notes, and destructive
  Git commands are denied with a message that names them.

## Evidence

- [Development corpus](comprehensive-lifecycle-2026-09-25/report.md)
- [Native projects](comprehensive-native-2026-09-25/report.md)
- [Holdout, tuned](holdout-2026-09-25/report.md)
- [Holdout, untuned first run](holdout-untuned-2026-09-25/report.md), engine
  hash matching commit `082eb47`
- [Holdout cases](../benchmarks/holdout_cases.json) and
  [runner](../benchmarks/holdout.py)

Each directory holds the manifest (corpus hash, schedule, tool versions, source
hashes), every raw record, `summary.json`, `scorecard.json` and the report.
