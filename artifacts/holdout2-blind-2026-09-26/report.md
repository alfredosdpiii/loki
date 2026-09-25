# Installed-hook lifecycle benchmark

This is a synthetic, author-written benchmark, not an independent product ranking.
Both products ran unchanged. Repeated timings are not extra accuracy cases.
A caught defect requires a matching diagnostic on every repetition.
Post-write detection means the bytes already landed.

Corpus version: holdout2_cases.
Corpus SHA-256: `27215b6ebb72353e4be4fa8bab91d7db5583de4b9450655d020cca53690f40c5`.
Repetitions: 3. Schedule seed: 20260926.
Loki shell guard and committed npm test grant; Interlinked balanced; shared analyzer paths.
Loki project type-check opt-in: not enabled.

## Matched results

| Profile / product | Caught defects | Prevented before write | False blocks | Control feedback | Coverage warnings | Infrastructure errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shared/interlinked | 12/60 | 4/60 | 2/60 | 60/60 | 69/120 | 0 |
| shared/loki | 33/60 | 19/60 | 3/60 | 21/60 | 16/120 | 0 |

Control feedback includes legitimate advisory and unavailable-coverage notices.
It is not a false-positive count. False blocks include any blocked repetition.
Infrastructure errors stay in denominators and earn no detection credit.

## Shared-analyzer results by language

| Language | Product | Caught | Pre-write | False blocks |
| --- | --- | ---: | ---: | ---: |
| elixir | loki | 3/10 | 1/10 | 0/10 |
| elixir | interlinked | 0/10 | 0/10 | 0/10 |
| go | loki | 6/10 | 0/10 | 3/10 |
| go | interlinked | 1/10 | 0/10 | 0/10 |
| javascript | loki | 3/6 | 2/6 | 0/6 |
| javascript | interlinked | 2/6 | 2/6 | 1/6 |
| python | loki | 8/12 | 7/12 | 0/12 |
| python | interlinked | 2/12 | 1/12 | 0/12 |
| rust | loki | 6/10 | 2/10 | 0/10 |
| rust | interlinked | 2/10 | 0/10 | 0/10 |
| typescript | loki | 7/12 | 7/12 | 0/12 |
| typescript | interlinked | 5/12 | 1/12 | 1/12 |

## Paired cases

A successful pair catches the defect on every run and never blocks its control.
Pair counts exclude standalone admission, scaling, debt, and workflow cases.

| Profile / product | Successful pairs |
| --- | ---: |
| shared/interlinked | 11/60 |
| shared/loki | 30/60 |

## Hook latency

Milliseconds, including process and sandbox startup. Post-write latency excludes denied writes.
First invocation uses a fresh product process/fixture, not cold OS page caches.
Startup-warmed trials use their own fresh fixture/daemon, with two git-status hook envelopes first. No compiler-result cache is prewarmed.
Pooled timings mix languages and different amounts of work; do not treat them as a speed ranking.

| Profile / product | Cache | Pre median / p95 | Post median / p95 | Total median / p95 |
| --- | --- | ---: | ---: | ---: |
| shared/interlinked | first-invocation | 143.39 / 205.23 | 236.28 / 6241.58 | 381.68 / 6388.36 |
| shared/interlinked | startup-warmed | 118.92 / 184.51 | 232.93 / 6240.50 | 355.61 / 6373.57 |
| shared/loki | first-invocation | 147.88 / 363.89 | 554.43 / 6241.46 | 681.54 / 2579.89 |
| shared/loki | startup-warmed | 149.12 / 347.45 | 597.31 / 6211.28 | 700.34 / 2779.55 |

## Explicit Go/Rust audit commands

Separate from ordinary hooks. Loki runs `scan --base HEAD`; Interlinked runs `verify --json`.
The commands have product-defined scopes. No claim of identical internal checks.

| Product | Targeted defects found | Controls exiting zero |
| --- | ---: | ---: |
| loki | 0/0 | 0/0 |
| interlinked | 0/0 | 0/0 |

## Misses and unrelated blocks

- interlinked: `holdout2/elixir/profile-fetch-user-wrong-arity/defect` step 0: missed.
- interlinked: `holdout2/python/link-checker-shared-counter/defect` step 0: missed.
- loki: `holdout2/typescript/metric-name-replace-first-only/defect` step 0: missed.
- loki: `holdout2/typescript/presence-poller-interval-leak/defect` step 0: missed.
- loki: `holdout2/rust/session-store-relock-deadlock/defect` step 0: missed.
- interlinked: `holdout2/python/inviter-optional-user/defect` step 0: missed.
- interlinked: `holdout2/go/load-timeout-ignores-second-result/defect` step 0: missed.
- interlinked: `holdout2/javascript/pdf-sniff-handle-leak/defect` step 0: missed.
- interlinked: `holdout2/go/head-sizes-concurrent-map-write/defect` step 0: missed.
- interlinked: `holdout2/rust/static-files-path-join-traversal/defect` step 0: missed.
- interlinked: `holdout2/go/invoice-query-sprintf/defect` step 0: missed.
- interlinked: `holdout2/python/webhook-retry-swallow/defect` step 0: missed.
- loki: `holdout2/elixir/invoice-show-missing-owner-check/defect` step 0: missed.
- loki: `holdout2/elixir/audit-log-write-truncates/defect` step 0: missed.
- interlinked: `holdout2/rust/config-question-mark-on-option/defect` step 0: missed.
- interlinked: `holdout2/elixir/audit-log-write-truncates/defect` step 0: missed.
- loki: `holdout2/javascript/pdf-sniff-handle-leak/defect` step 0: missed.
- loki: `holdout2/elixir/search-params-atom-keys/defect` step 0: missed.
- interlinked: `holdout2/go/batch-chunk-drops-last/defect` step 0: missed.
- interlinked: `holdout2/go/parse-size-test-self-compare/defect` step 0: missed.
- loki: `holdout2/rust/static-files-path-join-traversal/defect` step 0: missed.
- loki: `holdout2/python/discount-test-mocks-subject/defect` step 0: missed.
- loki: `holdout2/elixir/profile-fetch-user-wrong-arity/defect` step 0: missed.
- interlinked: `holdout2/rust/session-store-relock-deadlock/defect` step 0: missed.
- interlinked: `holdout2/elixir/report-sort-string-to-atom/defect` step 0: missed.
- interlinked: `holdout2/go/api-client-insecure-skip-verify/defect` step 0: blocked_unrelated.
- interlinked: `holdout2/elixir/invoice-show-missing-owner-check/defect` step 0: missed.
- loki: `holdout2/python/link-checker-shared-counter/defect` step 0: missed.
- loki: `holdout2/elixir/download-counter-agent-lost-update/defect` step 0: missed.
- loki: `holdout2/elixir/feature-flags-file-read-match/defect` step 0: missed.
- interlinked: `holdout2/javascript/prune-sessions-splice-in-foreach/defect` step 0: missed.
- loki: `holdout2/elixir/csv-export-file-never-closed/defect` step 0: missed.
- interlinked: `holdout2/go/snapshot-atomic-write-unchecked/defect` step 0: missed.
- interlinked: `holdout2/python/attachment-download-traversal/defect` step 0: missed.
- interlinked: `holdout2/rust/frame-field-get-unchecked/defect` step 0: missed.
- loki: `holdout2/typescript/tag-input-nested-quantifier/defect` step 0: missed.
- interlinked: `holdout2/typescript/metric-name-replace-first-only/defect` step 0: missed.
- interlinked: `holdout2/rust/parse-version-assert-true/defect` step 0: missed.
- interlinked: `holdout2/python/inventory-csv-open-leak/defect` step 0: missed.
- interlinked: `holdout2/rust/registry-lazy-map-unused/defect` step 0: missed.
- loki: `holdout2/typescript/assignee-find-non-null/defect` step 0: missed.
- interlinked: `holdout2/python/sqlite-order-filter-fstring/defect` step 0: missed.
- interlinked: `holdout2/typescript/assignee-find-non-null/defect` step 0: missed.
- loki: `holdout2/go/batch-chunk-drops-last/defect` step 0: missed.
- interlinked: `holdout2/typescript/login-next-open-redirect/defect` step 0: missed.
- interlinked: `holdout2/rust/leaderboard-top-n-ascending/defect` step 0: missed.
- loki: `holdout2/go/head-sizes-concurrent-map-write/defect` step 0: missed.
- interlinked: `holdout2/rust/csv-export-bufwriter-no-flush/defect` step 0: missed.
- loki: `holdout2/javascript/prune-sessions-splice-in-foreach/defect` step 0: missed.
- interlinked: `holdout2/elixir/invite-greeting-html-interpolation/defect` step 0: missed.
- interlinked: `holdout2/elixir/thumbnail-system-cmd-sh-c/defect` step 0: missed.
- interlinked: `holdout2/typescript/webhook-signature-string-compare/defect` step 0: missed.
- interlinked: `holdout2/elixir/download-counter-agent-lost-update/defect` step 0: missed.
- interlinked: `holdout2/elixir/search-params-atom-keys/defect` step 0: missed.
- interlinked: `holdout2/javascript/thumbnail-exec-template/defect` step 0: missed.
- interlinked: `holdout2/typescript/settings-deep-merge-proto/defect` step 0: missed.
- loki: `holdout2/python/inventory-csv-open-leak/defect` step 0: missed.
- loki: `holdout2/python/paginate-one-indexed-offset/defect` step 0: missed.
- loki: `holdout2/go/rate-limiter-nil-map/defect` step 0: missed.
- interlinked: `holdout2/javascript/link-preview-ssrf/defect` step 0: blocked_unrelated.
- interlinked: `holdout2/python/redact-re-sub-flags-as-count/defect` step 0: missed.
- interlinked: `holdout2/go/rate-limiter-nil-map/defect` step 0: missed.
- interlinked: `holdout2/typescript/close-editor-floating-save/defect` step 0: missed.
- loki: `holdout2/typescript/webhook-signature-string-compare/defect` step 0: missed.
- interlinked: `holdout2/python/paginate-one-indexed-offset/defect` step 0: missed.
- interlinked: `holdout2/elixir/csv-export-file-never-closed/defect` step 0: missed.
- interlinked: `holdout2/go/plugin-unzip-zip-slip/defect` step 0: missed.
- loki: `holdout2/go/parse-size-test-self-compare/defect` step 0: missed.
- loki: `holdout2/rust/leaderboard-top-n-ascending/defect` step 0: missed.
- loki: `holdout2/javascript/link-preview-ssrf/defect` step 0: missed.
- loki: `holdout2/rust/csv-export-bufwriter-no-flush/defect` step 0: missed.
- interlinked: `holdout2/typescript/latency-p95-default-sort/defect` step 0: missed.
- interlinked: `holdout2/python/discount-test-mocks-subject/defect` step 0: missed.
- interlinked: `holdout2/python/session-cookie-pickle/defect` step 0: missed.
- interlinked: `holdout2/elixir/feature-flags-file-read-match/defect` step 0: missed.

## False blocks and instability

- shared/interlinked: `holdout2/javascript/link-preview-ssrf/control` step 0: false_block.
- shared/loki: `holdout2/go/snapshot-atomic-write-unchecked/control` step 0: false_post_block.
- shared/loki: `holdout2/go/plugin-unzip-zip-slip/control` step 0: false_post_block.
- shared/loki: `holdout2/go/invoice-query-sprintf/control` step 0: false_post_block.
- shared/interlinked: `holdout2/typescript/comment-list-innerhtml/control` step 0: false_block.

## Scoring audit

The final scorer decodes native JSON and matches diagnostic lines, not regexes spanning escaped newlines. It excludes Node module-format notices from targeted detection. Raw records retain provisional outcomes.
Corrections are listed below and in scorecard.json.

- shared/interlinked `holdout2/javascript/prune-sessions-splice-in-foreach/defect`: ['detected_after_write'] -> ['missed'].
- shared/interlinked `holdout2/go/snapshot-atomic-write-unchecked/defect`: ['detected_after_write'] -> ['missed'].

## Coverage and limitations

Steps with post-hook byte changes: {'loki': 3}.
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
