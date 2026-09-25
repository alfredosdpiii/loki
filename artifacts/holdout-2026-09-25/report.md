# Installed-hook lifecycle benchmark

This is a synthetic, author-written benchmark, not an independent product ranking.
Both products ran unchanged. Repeated timings are not extra accuracy cases.
A caught defect requires a matching diagnostic on every repetition.
Post-write detection means the bytes already landed.

Corpus version: holdout-1.
Corpus SHA-256: `f3ec4c434e43323b26eb06c494a79e7002ee1a9fb59ef0c41b85ad7c57f1987f`.
Repetitions: 3. Schedule seed: 20260925.
Loki shell guard and committed npm test grant; Interlinked balanced; shared analyzer paths.
Loki project type-check opt-in: not enabled.

## Matched results

| Profile / product | Caught defects | Prevented before write | False blocks | Control feedback | Coverage warnings | Infrastructure errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shared/interlinked | 11/48 | 6/48 | 1/48 | 48/48 | 53/96 | 0 |
| shared/loki | 32/48 | 17/48 | 0/48 | 12/48 | 7/96 | 0 |

Control feedback includes legitimate advisory and unavailable-coverage notices.
It is not a false-positive count. False blocks include any blocked repetition.
Infrastructure errors stay in denominators and earn no detection credit.

## Shared-analyzer results by language

| Language | Product | Caught | Pre-write | False blocks |
| --- | --- | ---: | ---: | ---: |
| elixir | loki | 5/8 | 1/8 | 0/8 |
| elixir | interlinked | 0/8 | 0/8 | 0/8 |
| go | loki | 6/8 | 0/8 | 0/8 |
| go | interlinked | 1/8 | 0/8 | 0/8 |
| javascript | loki | 3/4 | 2/4 | 0/4 |
| javascript | interlinked | 2/4 | 2/4 | 0/4 |
| python | loki | 7/10 | 6/10 | 0/10 |
| python | interlinked | 3/10 | 2/10 | 0/10 |
| rust | loki | 4/8 | 1/8 | 0/8 |
| rust | interlinked | 0/8 | 0/8 | 0/8 |
| typescript | loki | 7/10 | 7/10 | 0/10 |
| typescript | interlinked | 5/10 | 2/10 | 1/10 |

## Paired cases

A successful pair catches the defect on every run and never blocks its control.
Pair counts exclude standalone admission, scaling, debt, and workflow cases.

| Profile / product | Successful pairs |
| --- | ---: |
| shared/interlinked | 10/48 |
| shared/loki | 32/48 |

## Hook latency

Milliseconds, including process and sandbox startup. Post-write latency excludes denied writes.
First invocation uses a fresh product process/fixture, not cold OS page caches.
Startup-warmed trials use their own fresh fixture/daemon, with two git-status hook envelopes first. No compiler-result cache is prewarmed.
Pooled timings mix languages and different amounts of work; do not treat them as a speed ranking.

| Profile / product | Cache | Pre median / p95 | Post median / p95 | Total median / p95 |
| --- | --- | ---: | ---: | ---: |
| shared/interlinked | first-invocation | 119.90 / 166.90 | 193.63 / 6056.23 | 313.63 / 6197.82 |
| shared/interlinked | startup-warmed | 102.02 / 150.29 | 191.72 / 6022.82 | 294.87 / 6133.17 |
| shared/loki | first-invocation | 110.30 / 577.14 | 854.67 / 7732.02 | 916.14 / 4850.69 |
| shared/loki | startup-warmed | 110.94 / 651.94 | 851.06 / 7415.80 | 950.91 / 4851.85 |

## Explicit Go/Rust audit commands

Separate from ordinary hooks. Loki runs `scan --base HEAD`; Interlinked runs `verify --json`.
The commands have product-defined scopes. No claim of identical internal checks.

| Product | Targeted defects found | Controls exiting zero |
| --- | ---: | ---: |
| loki | 0/0 | 0/0 |
| interlinked | 0/0 | 0/0 |

## Misses and unrelated blocks

- interlinked: `holdout/rust/get-unchecked-lookup-table/defect` step 0: missed.
- loki: `holdout/typescript/floating-promise-remove-draft/defect` step 0: missed.
- interlinked: `holdout/elixir/datetime-structural-sort/defect` step 0: missed.
- interlinked: `holdout/rust/sh-c-image-resize/defect` step 0: missed.
- loki: `holdout/python/tautological-discount-test/defect` step 0: missed.
- interlinked: `holdout/go/unchecked-json-unmarshal/defect` step 0: missed.
- interlinked: `holdout/go/nil-map-word-tally/defect` step 0: missed.
- loki: `holdout/go/report-download-traversal/defect` step 0: missed.
- interlinked: `holdout/python/upload-path-traversal/defect` step 0: missed.
- interlinked: `holdout/elixir/external-redirect-return-to/defect` step 0: missed.
- interlinked: `holdout/typescript/postmessage-missing-origin-check/defect` step 0: missed.
- interlinked: `holdout/rust/use-after-move-orders/defect` step 0: missed.
- interlinked: `holdout/rust/reentrant-mutex-deadlock/defect` step 0: missed.
- interlinked: `holdout/elixir/undefined-map-get-bang/defect` step 0: missed.
- interlinked: `holdout/javascript/exec-thumbnail-command/defect` step 0: missed.
- interlinked: `holdout/elixir/send-resp-html-interpolation/defect` step 0: missed.
- interlinked: `holdout/typescript/login-open-redirect/defect` step 0: missed.
- loki: `holdout/python/upload-path-traversal/defect` step 0: missed.
- loki: `holdout/elixir/external-redirect-return-to/defect` step 0: missed.
- interlinked: `holdout/go/mutex-value-receiver/defect` step 0: missed.
- interlinked: `holdout/go/sprintf-sql-query/defect` step 0: missed.
- interlinked: `holdout/typescript/floating-promise-remove-draft/defect` step 0: missed.
- interlinked: `holdout/elixir/invoice-send-file-traversal/defect` step 0: missed.
- interlinked: `holdout/python/optional-profile-attr/defect` step 0: missed.
- interlinked: `holdout/python/pagination-off-by-one/defect` step 0: missed.
- interlinked: `holdout/rust/usize-to-u32-return/defect` step 0: missed.
- loki: `holdout/typescript/deep-merge-prototype-pollution/defect` step 0: missed.
- loki: `holdout/python/pagination-off-by-one/defect` step 0: missed.
- interlinked: `holdout/elixir/cookie-binary-to-term/defect` step 0: missed.
- interlinked: `holdout/elixir/string-to-atom-sort-param/defect` step 0: missed.
- loki: `holdout/elixir/undefined-map-get-bang/defect` step 0: missed.
- interlinked: `holdout/python/pickle-session-cookie/defect` step 0: missed.
- loki: `holdout/rust/get-unchecked-lookup-table/defect` step 0: missed.
- interlinked: `holdout/go/inverted-session-expiry/defect` step 0: missed.
- interlinked: `holdout/javascript/link-preview-ssrf/defect` step 0: missed.
- loki: `holdout/javascript/link-preview-ssrf/defect` step 0: missed.
- loki: `holdout/rust/trailing-average-underflow/defect` step 0: missed.
- loki: `holdout/typescript/numeric-sort-without-comparator/defect` step 0: missed.
- interlinked: `holdout/typescript/numeric-sort-without-comparator/defect` step 0: missed.
- interlinked: `holdout/go/tls-insecure-skip-verify/defect` step 0: blocked_unrelated.
- loki: `holdout/elixir/datetime-structural-sort/defect` step 0: missed.
- interlinked: `holdout/typescript/deep-merge-prototype-pollution/defect` step 0: missed.
- interlinked: `holdout/python/sql-fstring-like-query/defect` step 0: missed.
- interlinked: `holdout/rust/trailing-average-underflow/defect` step 0: missed.
- interlinked: `holdout/go/report-download-traversal/defect` step 0: missed.
- loki: `holdout/rust/reentrant-mutex-deadlock/defect` step 0: missed.
- interlinked: `holdout/python/webhook-signature-eq/defect` step 0: missed.
- loki: `holdout/go/inverted-session-expiry/defect` step 0: missed.
- interlinked: `holdout/rust/attachment-path-join/defect` step 0: missed.
- interlinked: `holdout/rust/assert-true-ignored-test/defect` step 0: blocked_unrelated.
- interlinked: `holdout/elixir/system-cmd-sh-c/defect` step 0: missed.
- loki: `holdout/rust/attachment-path-join/defect` step 0: missed.
- interlinked: `holdout/python/tautological-discount-test/defect` step 0: missed.

## False blocks and instability

- shared/interlinked: `holdout/typescript/innerhtml-comment-render/control` step 0: false_block.

## Scoring audit

The final scorer decodes native JSON and matches diagnostic lines, not regexes spanning escaped newlines. It excludes Node module-format notices from targeted detection. Raw records retain provisional outcomes.
Corrections are listed below and in scorecard.json.


## Coverage and limitations

Steps with post-hook byte changes: {'loki': 1}.
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
