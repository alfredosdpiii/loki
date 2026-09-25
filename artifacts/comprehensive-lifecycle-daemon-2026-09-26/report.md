# Installed-hook lifecycle benchmark

This is a synthetic, author-written benchmark, not an independent product ranking.
Both products ran unchanged. Repeated timings are not extra accuracy cases.
A caught defect requires a matching diagnostic on every repetition.
Post-write detection means the bytes already landed.

Corpus version: 2.
Corpus SHA-256: `4648d3277a8453fd45f1b6834b38cba26e207891528d8755a7447284c49aada3`.
Repetitions: 3. Schedule seed: 20260926.
Loki shell guard and committed npm test grant; Interlinked balanced; shared analyzer paths.
Loki project type-check opt-in: not enabled.

## Matched results

| Profile / product | Caught defects | Prevented before write | False blocks | Control feedback | Coverage warnings | Infrastructure errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| missing-js/interlinked | 13/17 | 6/17 | 1/21 | 21/21 | 32/38 | 0 |
| missing-js/loki | 17/17 | 17/17 | 0/21 | 21/21 | 38/38 | 0 |
| shared/interlinked | 20/47 | 10/47 | 1/55 | 54/55 | 50/102 | 0 |
| shared/loki | 47/47 | 36/47 | 0/55 | 4/55 | 5/102 | 0 |

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
| javascript | loki | 3/3 | 3/3 | 0/3 |
| javascript | interlinked | 3/3 | 3/3 | 0/3 |
| none | loki | 5/5 | 5/5 | 0/4 |
| none | interlinked | 3/5 | 3/5 | 0/4 |
| python | loki | 12/12 | 11/12 | 0/17 |
| python | interlinked | 3/12 | 1/12 | 0/17 |
| rust | loki | 4/4 | 1/4 | 0/4 |
| rust | interlinked | 1/4 | 0/4 | 0/4 |
| typescript | loki | 14/14 | 14/14 | 0/18 |
| typescript | interlinked | 10/14 | 3/14 | 1/18 |

## Paired cases

A successful pair catches the defect on every run and never blocks its control.
Pair counts exclude standalone admission, scaling, debt, and workflow cases.

| Profile / product | Successful pairs |
| --- | ---: |
| missing-js/interlinked | 12/15 |
| missing-js/loki | 15/15 |
| shared/interlinked | 16/39 |
| shared/loki | 39/39 |

## Hook latency

Milliseconds, including process and sandbox startup. Post-write latency excludes denied writes.
First invocation uses a fresh product process/fixture, not cold OS page caches.
Startup-warmed trials use their own fresh fixture/daemon, with two git-status hook envelopes first. No compiler-result cache is prewarmed.
Pooled timings mix languages and different amounts of work; do not treat them as a speed ranking.

| Profile / product | Cache | Pre median / p95 | Post median / p95 | Total median / p95 |
| --- | --- | ---: | ---: | ---: |
| missing-js/interlinked | first-invocation | 152.87 / 229.37 | 10646.56 / 10781.29 | 10785.25 / 11192.54 |
| missing-js/interlinked | startup-warmed | 128.19 / 185.52 | 10669.73 / 10984.48 | 10755.82 / 11239.19 |
| missing-js/loki | first-invocation | 195.53 / 332.28 | 196.22 / 355.45 | 332.66 / 660.18 |
| missing-js/loki | startup-warmed | 193.15 / 362.79 | 195.20 / 376.05 | 334.18 / 710.73 |
| shared/interlinked | first-invocation | 160.12 / 254.88 | 271.96 / 6408.16 | 416.79 / 6528.31 |
| shared/interlinked | startup-warmed | 129.13 / 251.16 | 277.69 / 6308.09 | 388.88 / 6429.38 |
| shared/loki | first-invocation | 167.26 / 380.34 | 447.11 / 1533.35 | 394.21 / 1400.96 |
| shared/loki | startup-warmed | 165.30 / 361.85 | 431.32 / 1575.06 | 402.05 / 1611.17 |

## Explicit Go/Rust audit commands

Separate from ordinary hooks. Loki runs `scan --base HEAD`; Interlinked runs `verify --json`.
The commands have product-defined scopes. No claim of identical internal checks.

| Product | Targeted defects found | Controls exiting zero |
| --- | ---: | ---: |
| loki | 8/8 | 8/8 |
| interlinked | 0/8 | 8/8 |

## Misses and unrelated blocks

- interlinked: `go/undefined-name/defect` step 0: missed.
- interlinked: `typescript/removed-export/defect` step 0: missed.
- interlinked: `python/sql-interpolation/defect` step 0: missed.
- interlinked: `elixir/ssrf/defect` step 0: missed.
- interlinked: `python/broad-exception-loss/defect` step 0: missed.
- interlinked: `python/return-type/defect` step 0: missed.
- interlinked: `python/unsafe-deserialization/defect` step 0: missed.
- interlinked: `admission/policy-via-symlink` step 0: missed.
- interlinked: `elixir/code-from-request/defect` step 0: missed.
- interlinked: `elixir/atom-from-request/defect` step 0: missed.
- interlinked: `python/undefined-return/defect` step 0: missed.
- interlinked: `rust/use-after-move/defect` step 0: missed.
- interlinked: `admission/policy-write` step 0: missed.
- interlinked: `typescript/cross-file-contract/defect` step 0: missed.
- interlinked: `elixir/decode-untrusted-term/defect` step 0: missed.
- interlinked: `go/discarded-error/defect` step 0: missed.
- interlinked: `workflow/python/break-repair` step 0: missed.
- interlinked: `python/eval-input/defect` step 0: missed.
- interlinked: `rust/type-mismatch/defect` step 0: missed.
- interlinked: `typescript/redirect-from-input/defect` step 0: missed.
- interlinked: `go/format-type/defect` step 0: missed.
- interlinked: `exact-edit/python/undefined-return/defect` step 0: missed.
- interlinked: `go/duration-square/defect` step 0: missed.
- interlinked: `workflow/typescript/multi-file-repair` step 0: missed.
- interlinked: `elixir/request-authorization/defect` step 0: missed.
- interlinked: `rust/ignored-result/defect` step 0: missed.
- interlinked: `python/authorization-from-request/defect` step 0: missed.

## False blocks and instability

- shared/interlinked: `debt/typescript/shift` step 0: false_post_block.
- missing-js/interlinked: `debt/typescript/shift` step 0: false_post_block.

## Scoring audit

The final scorer decodes native JSON and matches diagnostic lines, not regexes spanning escaped newlines. It excludes Node module-format notices from targeted detection. Raw records retain provisional outcomes.
Corrections are listed below and in scorecard.json.

- shared/interlinked `typescript/removed-export/defect`: ['detected_after_write'] -> ['missed'].
- shared/interlinked `python/return-type/defect`: ['detected_after_write'] -> ['missed'].
- missing-js/interlinked `typescript/removed-export/defect`: ['detected_after_write'] -> ['missed'].
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
