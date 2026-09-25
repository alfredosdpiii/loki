# Installed-hook lifecycle benchmark

This is a synthetic, author-written benchmark, not an independent product ranking.
Both products ran unchanged. Repeated timings are not extra accuracy cases.
A caught defect requires a matching diagnostic on every repetition.
Post-write detection means the bytes already landed.

Corpus version: 2.
Corpus SHA-256: `4648d3277a8453fd45f1b6834b38cba26e207891528d8755a7447284c49aada3`.
Repetitions: 3. Schedule seed: 20260925.
Native manifests for Python/Go/Rust/Elixir; no JS package manifest or npm grant. Python pyproject declares Ruff and mypy. Other installed policies and corpus source are unchanged.
Loki project type-check opt-in: not enabled.

## Matched results

| Profile / product | Caught defects | Prevented before write | False blocks | Control feedback | Coverage warnings | Infrastructure errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shared/interlinked | 12/25 | 1/25 | 0/26 | 26/26 | 17/51 | 0 |
| shared/loki | 25/25 | 14/25 | 0/26 | 0/26 | 1/51 | 0 |

Control feedback includes legitimate advisory and unavailable-coverage notices.
It is not a false-positive count. False blocks include any blocked repetition.
Infrastructure errors stay in denominators and earn no detection credit.

## Shared-analyzer results by language

| Language | Product | Caught | Pre-write | False blocks |
| --- | --- | ---: | ---: | ---: |
| elixir | loki | 5/5 | 2/5 | 0/5 |
| elixir | interlinked | 0/5 | 0/5 | 0/5 |
| go | loki | 4/4 | 0/4 | 0/4 |
| go | interlinked | 0/4 | 0/4 | 0/4 |
| python | loki | 12/12 | 11/12 | 0/13 |
| python | interlinked | 11/12 | 1/12 | 0/13 |
| rust | loki | 4/4 | 1/4 | 0/4 |
| rust | interlinked | 1/4 | 0/4 | 0/4 |

## Paired cases

A successful pair catches the defect on every run and never blocks its control.
Pair counts exclude standalone admission, scaling, debt, and workflow cases.

| Profile / product | Successful pairs |
| --- | ---: |
| shared/interlinked | 11/24 |
| shared/loki | 24/24 |

## Hook latency

Milliseconds, including process and sandbox startup. Post-write latency excludes denied writes.
First invocation uses a fresh product process/fixture, not cold OS page caches.
Startup-warmed trials use their own fresh fixture/daemon, with two git-status hook envelopes first. No compiler-result cache is prewarmed.
Pooled timings mix languages and different amounts of work; do not treat them as a speed ranking.

| Profile / product | Cache | Pre median / p95 | Post median / p95 | Total median / p95 |
| --- | --- | ---: | ---: | ---: |
| shared/interlinked | first-invocation | 127.65 / 193.41 | 235.64 / 1779.37 | 354.54 / 1937.16 |
| shared/interlinked | startup-warmed | 126.51 / 164.85 | 243.32 / 1420.77 | 368.69 / 1576.37 |
| shared/loki | first-invocation | 109.34 / 156.20 | 492.64 / 4473.14 | 299.15 / 3932.06 |
| shared/loki | startup-warmed | 109.71 / 157.26 | 429.17 / 4291.19 | 282.57 / 3964.07 |

## Explicit Go/Rust audit commands

Separate from ordinary hooks. Loki runs `scan --base HEAD`; Interlinked runs `verify --json`.
The commands have product-defined scopes. No claim of identical internal checks.

| Product | Targeted defects found | Controls exiting zero |
| --- | ---: | ---: |
| loki | 0/0 | 0/0 |
| interlinked | 0/0 | 0/0 |

## Misses and unrelated blocks

- interlinked: `go/discarded-error/defect` step 0: missed.
- interlinked: `elixir/request-authorization/defect` step 0: missed.
- interlinked: `elixir/atom-from-request/defect` step 0: missed.
- interlinked: `rust/use-after-move/defect` step 0: missed.
- interlinked: `elixir/decode-untrusted-term/defect` step 0: missed.
- interlinked: `go/undefined-name/defect` step 0: missed.
- interlinked: `elixir/ssrf/defect` step 0: missed.
- interlinked: `elixir/code-from-request/defect` step 0: missed.
- interlinked: `rust/type-mismatch/defect` step 0: missed.
- interlinked: `go/format-type/defect` step 0: missed.
- interlinked: `go/duration-square/defect` step 0: missed.
- interlinked: `python/authorization-from-request/defect` step 0: missed.
- interlinked: `rust/ignored-result/defect` step 0: missed.

## False blocks and instability


## Scoring audit

The final scorer decodes native JSON and matches diagnostic lines, not regexes spanning escaped newlines. It excludes Node module-format notices from targeted detection. Raw records retain provisional outcomes.
Corrections are listed below and in scorecard.json.

- shared/interlinked `go/discarded-error/defect`: ['detected_after_write'] -> ['missed'].

## Coverage and limitations

Steps with post-hook byte changes: {}.
Steps with unexpected pre-hook byte changes: 0.

- Author-written cases are not independent or representative of production.
- First invocation is not an OS-cold disk/cache measurement.
- Additional context can be advisory; post-write findings do not prevent bytes landing.
- Generic denial without a target marker is not credited as targeted prevention.
- Real host activation and explicit audit scans are separate from hook effectiveness.
- Go/Rust audit commands have different product-defined scopes.
- Cases include intentional policy violations, compiler errors, and semantic security gaps.
- No live model writes, production repositories, long-running autonomous sessions, or cloud services.
- The missing-JS profile removes project-local JS tools; it is not a no-tools machine.
- The main profile supplies Biome's recommended config to both products and uses installed product policy otherwise.
- Source formatting for Go, Rust, and Elixir happens before each proposed edit, outside measured hook time.
- Native command hooks are invoked as installed. Separate live-host probes only establish startup activation.

Raw handler output, exact corpus, schedule, tool versions, hashes, and audit output are in adjacent JSON files.
