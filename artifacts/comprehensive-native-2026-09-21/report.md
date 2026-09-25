# Installed-hook lifecycle benchmark

This is a synthetic, author-written benchmark, not an independent product ranking.
Both products ran unchanged. Repeated timings are not extra accuracy cases.
A caught defect requires a matching diagnostic on every repetition.
Post-write detection means the bytes already landed.

Corpus version: 2.
Corpus SHA-256: `4648d3277a8453fd45f1b6834b38cba26e207891528d8755a7447284c49aada3`.
Repetitions: 3. Schedule seed: 20260921.
Native manifests for Python/Go/Rust/Elixir; no JS package manifest or npm grant. Python pyproject declares Ruff and mypy. Other installed policies and corpus source are unchanged.
Loki project type-check opt-in: not enabled.

## Matched results

| Profile / product | Caught defects | Prevented before write | False blocks | Control feedback | Coverage warnings | Infrastructure errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shared/interlinked | 12/25 | 1/25 | 0/26 | 26/26 | 17/51 | 0 |
| shared/loki | 15/25 | 0/25 | 1/26 | 1/26 | 0/51 | 0 |

Control feedback includes legitimate advisory and unavailable-coverage notices.
It is not a false-positive count. False blocks include any blocked repetition.
Infrastructure errors stay in denominators and earn no detection credit.

## Shared-analyzer results by language

| Language | Product | Caught | Pre-write | False blocks |
| --- | --- | ---: | ---: | ---: |
| elixir | loki | 3/5 | 0/5 | 0/5 |
| elixir | interlinked | 0/5 | 0/5 | 0/5 |
| go | loki | 2/4 | 0/4 | 0/4 |
| go | interlinked | 0/4 | 0/4 | 0/4 |
| python | loki | 10/12 | 0/12 | 1/13 |
| python | interlinked | 11/12 | 1/12 | 0/13 |
| rust | loki | 0/4 | 0/4 | 0/4 |
| rust | interlinked | 1/4 | 0/4 | 0/4 |

## Paired cases

A successful pair catches the defect on every run and never blocks its control.
Pair counts exclude standalone admission, scaling, debt, and workflow cases.

| Profile / product | Successful pairs |
| --- | ---: |
| shared/interlinked | 11/24 |
| shared/loki | 13/24 |

## Hook latency

Milliseconds, including process and sandbox startup. Post-write latency excludes denied writes.
First invocation uses a fresh product process/fixture, not cold OS page caches.
Startup-warmed trials use their own fresh fixture/daemon, with two git-status hook envelopes first. No compiler-result cache is prewarmed.
Pooled timings mix languages and different amounts of work; do not treat them as a speed ranking.

| Profile / product | Cache | Pre median / p95 | Post median / p95 | Total median / p95 |
| --- | --- | ---: | ---: | ---: |
| shared/interlinked | first-invocation | 110.95 / 157.62 | 201.71 / 1066.78 | 310.36 / 1218.76 |
| shared/interlinked | startup-warmed | 89.55 / 144.15 | 204.36 / 1043.03 | 285.99 / 1185.57 |
| shared/loki | first-invocation | 81.30 / 91.33 | 123.10 / 2483.00 | 206.53 / 2562.92 |
| shared/loki | startup-warmed | 82.56 / 93.13 | 125.64 / 2467.67 | 209.63 / 2548.86 |

## Explicit Go/Rust audit commands

Separate from ordinary hooks. Loki runs `scan --base HEAD`; Interlinked runs `verify --json`.
The commands have product-defined scopes. No claim of identical internal checks.

| Product | Targeted defects found | Controls exiting zero |
| --- | ---: | ---: |
| loki | 8/8 | 8/8 |
| interlinked | 0/8 | 8/8 |

## Misses and unrelated blocks

- loki: `go/duration-square/defect` step 0: missed.
- interlinked: `python/authorization-from-request/defect` step 0: missed.
- interlinked: `elixir/request-authorization/defect` step 0: missed.
- interlinked: `rust/type-mismatch/defect` step 0: missed.
- loki: `rust/type-mismatch/defect` step 0: missed.
- interlinked: `go/duration-square/defect` step 0: missed.
- loki: `elixir/request-authorization/defect` step 0: missed.
- loki: `rust/use-after-move/defect` step 0: missed.
- interlinked: `rust/use-after-move/defect` step 0: missed.
- interlinked: `elixir/decode-untrusted-term/defect` step 0: missed.
- loki: `python/return-type/defect` step 0: missed.
- interlinked: `go/discarded-error/defect` step 0: missed.
- interlinked: `elixir/code-from-request/defect` step 0: missed.
- loki: `elixir/ssrf/defect` step 0: missed.
- interlinked: `rust/ignored-result/defect` step 0: missed.
- loki: `rust/placeholder/defect` step 0: missed.
- interlinked: `elixir/ssrf/defect` step 0: missed.
- interlinked: `elixir/atom-from-request/defect` step 0: missed.
- loki: `rust/ignored-result/defect` step 0: missed.
- loki: `python/authorization-from-request/defect` step 0: missed.
- interlinked: `go/undefined-name/defect` step 0: missed.
- interlinked: `go/format-type/defect` step 0: missed.
- loki: `go/discarded-error/defect` step 0: missed.

## False blocks and instability

- shared/loki: `python/shell-interpolation/control` step 0: false_post_block.

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
