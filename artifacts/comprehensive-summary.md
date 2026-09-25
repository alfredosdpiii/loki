# Broader benchmark, 2026-09-21

Loki does not have a blanket win over Interlinked CLI. Results depend on project
configuration, language, and whether the check runs before or after a write.
The earlier 16/16 pre-write result did not capture those differences.

This evaluation ran real installed command hooks and analyzers on a frozen,
author-written synthetic corpus. It is substantially broader than the earlier
comparison, but it is not an independent benchmark or production validation.
Neither product was modified during the measurements.

## What ran

- 99 cases with 102 individual steps, including 39 defect/control pairs.
- Python, TypeScript, JavaScript, Go, Rust, and Elixir/Phoenix.
- Whole-file writes, exact edits, cross-file breaks, same-session repairs,
  existing-debt shifts, policy/symlink attacks, and proposed shell operations.
- Shared-tool and missing-project-local-JS-tool profiles.
- Separate project-type-check-enabled and native-language-manifest comparisons.
- 1,320 edit lifecycles across 424 product/case/profile records, three independent
  trials each. These repetitions are not 1,320 independent accuracy cases.
- 64 explicit Go/Rust audit invocations, counted separately from ordinary hooks.
- 42 targeted language-rule regression expectations.
- 57 Phoenix scenario expectations across high, low, and no-block thresholds.
- Ten current-host activation probes, plus an earlier ten-probe run that selected
  older Pi and Codex binaries.

Each comparison trial used its own Git repository, home, and daemon. Commands ran
without network access, with the host filesystem read-only and fixture storage
writable. Proposed shell commands and escaped writes were never executed.
Case order was seeded and randomized. Evidence files refuse overwrites.

## Results

"Caught" requires a matching diagnostic on every repetition, before or after
writing. Post-write detection does not mean the edit was prevented. False blocks
count any rejected legitimate control. Do not pool these overlapping subsets.

| Setup | Loki caught | Interlinked caught | Loki false blocks | Interlinked false blocks |
| --- | ---: | ---: | ---: | ---: |
| Shared scaffolding and available analyzers | 26/47 | 19/47 | 2/55 | 1/55 |
| Native Python/Go/Rust/Phoenix projects | 15/25 | 12/25 | 1/26 | 0/26 |
| TypeScript with Loki project checking enabled | 12/14 | 10/14 | 0/15 | 1/15 |
| Missing project-local JS analyzers | 2/17 | 13/17 | 0/21 | 1/21 |

All completed comparison trials had consistent final outcomes. There were no
infrastructure errors in these completed matrices. Product and runner hashes
were unchanged at completion and checked again afterward.

The shared-scaffolding profile includes a JS manifest for shell-grant controls.
It therefore cannot stand in for native-language project discovery. Adding a
native Python manifest and analyzer configuration materially improved
Interlinked's results.

### By capability

- **Python:** in native Python projects, Interlinked caught 11/12 defects with no
  false blocks. Loki caught 10/12 and blocked one control. Loki missed a return-type
  error that mypy could identify. Both missed request-controlled authorization.
- **TypeScript:** ordinary Loki hooks caught 4/14 defects. The accepted
  `"typescript_check": true` setting raised that to 12/14, including cross-file
  contract failures. Interlinked caught 10/14. It missed the cross-file cases,
  while Loki missed DOM injection that Interlinked reported.
- **Phoenix:** Loki caught new deserialization, code-evaluation, and atom-creation
  findings, 3/5 security defects in the paired set. Interlinked caught 0/5.
  Both missed SSRF and client-controlled authorization.
- **Go:** ordinary Loki hooks caught 2/4 defects; Interlinked caught 0/4.
  Interlinked explicitly deferred its Go build/lint checks in the observed hook
  path. Do not interpret admission as completed analysis.
- **Rust:** ordinary Loki hooks caught 0/4, while Interlinked reported the
  placeholder macro, 1/4. Neither ordinary hook caught the type or ownership errors.
- **Explicit audits:** Loki's `scan --base HEAD` caught all eight Go/Rust defects
  and accepted all eight controls. Interlinked's `verify --json` reported none
  of those targeted defects. These commands have different product-defined scopes;
  this does not establish that Interlinked lacks every corresponding capability.
- **Missing local JS tools:** Loki lost most content detection. Interlinked retained
  more checks and could use its own or other available tooling. This profile is
  not a machine with every analyzer removed.

### False blocks and conservative scoring

Loki rejected a plain-text shell redirect because the shell guard does not admit
redirection syntax. It also rejected a shell-free `subprocess.run` control through
Ruff S603. Interlinked blocked an existing TypeScript diagnostic shifted to a new
line, despite no new type error.

Loki also denied `git reset --hard`, but its generic "requires review" message did
not match that case's frozen targeted-diagnostic criteria. The scorecard records
this as an unrelated block rather than awarding targeted detection. The command
was not admitted or executed.

## Timing

These are hook-wall-clock measurements on one machine, including sandbox and
process startup. They are not production SLAs. "Startup-warmed" trials have a
fresh fixture and daemon, preceded by two git-status hook envelopes. Compiler
result caches are not deliberately warmed.

| Setup, startup-warmed | Loki median / p95 | Interlinked median / p95 |
| --- | ---: | ---: |
| Shared scaffolding, whole lifecycle | 288 / 2,931 ms | 319 / 6,270 ms |
| Native-language projects, whole lifecycle | 210 / 2,549 ms | 286 / 1,186 ms |
| TypeScript checking enabled, whole lifecycle | 1,226 / 1,666 ms | 6,038 / 6,319 ms |
| Missing local JS tools, whole lifecycle | 200 / 253 ms | 10,675 / 10,821 ms |

The products perform different work on different paths. Loki's low missing-tool
latency accompanies missing analysis; it is not an equivalent-work speed win.
The missing-tool Interlinked path incurred repeated waits in this environment.

A valid Python edit with 10,000 additional tracked text files took a median
265 ms through Loki's hooks and 2,377 ms through Interlinked's. The 10-file case
took 246 ms and 313 ms respectively. This measures that specific workload, not
all monorepositories.

## Hosts and additional checks

All ten current-host positive/negative activation probes passed:

| Host | Tested version |
| --- | --- |
| Pi | 0.84.4 |
| OMP | 18.2.6 |
| Claude Code | 2.1.258 |
| Codex | 0.152.1 |
| Factory Droid | 0.223.0 |

These use real host processes and a credential-free loopback inference stub.
They establish automatic discovery, context delivery, preservation of original
instructions, and a working disabled-hook negative control. They do not establish
live-model tool enforcement. Pi passed without resetting user runtime state.

The separate language-rule suite passed all 42 expectations. Corrected Phoenix
runs passed all 57 scenario expectations, including HEEx/project compilation,
old-debt handling, and documented misses. "Expectation passed" does not mean
every security defect was detected.

Final repository validation passed:

- 175 Python tests and 174 subtests.
- Eight adapter tests with 100 assertions, with real Oxlint enabled.
- Ruff formatting and lint for the engine, tests, and current benchmark runners.

No product or adapter code changed. Strict TypeScript checking of the unchanged
adapters was not rerun in this task.

## Benchmark failures and corrections

The failed and interrupted evidence remains on disk:

1. Initial isolated Phoenix homes lacked a compatible Hex/runtime combination.
   A toolchain shim could also restore OTP 29 despite the parent selecting OTP 27.
   The comparison runner now selects the runtime explicitly.
2. One fixture used the nonexistent `elixir` rule-pack name. The interrupted run
   is invalidated. Corrected fixtures preserve the shipped policy and validate it
   before collecting observations.
3. Reusing a daemon across different session IDs triggered legitimate file
   reservations. The interrupted run is invalidated. Repetitions now have
   independent repositories, homes, and processes.
4. Temporary-root paths invoked Interlinked's scratchpad policy. Final comparison
   repositories live outside OS temporary roots.
5. The provisional scorer could match regexes across escaped JSON newlines.
   The audited scorer decodes native feedback and matches individual diagnostic
   lines. It excludes module-format notices and empty audit registry entries.
   Every changed classification is listed in the scorecards.
6. The first supplemental Phoenix run reproduced the shim mismatch through
   installed hooks. Corrected runs use explicit interpreter precedence.
7. The first host run selected Pi 0.84.1 and Codex 0.147.0 from the Node 23 path.
   The current-version run above is separate; both sets of raw observations remain.

No product rules were weakened or strengthened to make these cases pass.

## Evidence and reproduction

- [Protocol and commands](../benchmarks/README.md)
- [Main comparison](comprehensive-lifecycle-2026-09-21/report.md)
- [Native-project comparison](comprehensive-native-2026-09-21/report.md)
- [Type-check-enabled comparison](comprehensive-typescript-enabled-2026-09-21/report.md)
- [Current-host probes](comprehensive-current-host-activation.json)
- [Language-rule regressions](comprehensive-language-regressions.json)
- [Phoenix high](comprehensive-phoenix-corrected-high.json),
  [low](comprehensive-phoenix-corrected-low.json),
  [no-block](comprehensive-phoenix-corrected-none.json)

The comparison used Interlinked commit
`207330d8131c5203ecc74e9fd4c24ba416463718`, Node 23.11.1, Oxlint 1.83.0,
TypeScript 5.9.3, Biome 2.4.13, Ruff 0.15.2, mypy 1.19.1,
golangci-lint 2.6.2, Go 1.25.6, Clippy 0.1.97, Elixir 1.17.3, and OTP 27.
Exact executable paths, versions, hashes, source cases, schedules, and outputs
are in each manifest and adjacent record files.

Remaining work for a genuinely independent benchmark includes externally authored
holdouts, production-repository edit replay, sustained autonomous sessions,
all host write formats, and application-specific security oracles. None of those
is established by this synthetic corpus.
