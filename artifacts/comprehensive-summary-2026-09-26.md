# Loki vs Interlinked, 2026-09-26

Interlinked commit `82307ea` (balanced install) against Loki with its warm daemon
started during setup, the same way the runner starts Interlinked's daemon. The
cases are synthetic and no live model sessions were involved. Detection needs a
matching diagnostic on every repetition.

## Blind result

The second holdout (`benchmarks/holdout2_cases.json`, 60 pairs) was written by a
separate agent that could not read Loki, Interlinked, the development corpus or the
first holdout. It was committed before any Loki run (`feb3a99`) and measured with
three repetitions:

| | Loki | Interlinked |
| --- | ---: | ---: |
| Caught | 33/60 | 12/60 |
| Prevented before write | 19/60 | 4/60 |
| False blocks | 3/60 | 2/60 |

This is the least biased number in this report. [Evidence](holdout2-blind-2026-09-26/report.md).

## After tuning (commit `daebb2a`, one repetition)

All three blind false blocks were Go error-handling idioms. The fix switched
golangci-lint to its `std-error-handling` defaults and replaced gosec G305 with
Loki's `loki/zip-slip` rule. New rules were also added for general patterns among
the misses. Both holdouts are tuned from here on.

| Suite | Loki caught | Interlinked caught | Loki prevented | Interlinked prevented | Loki false blocks | Interlinked false blocks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development corpus, shared tools | 46/47 | 20/47 | 36/47 | 10/47 | 0/55 | 1/55 |
| Development corpus, no local JS tools | 17/17 | 13/17 | 17/17 | 6/17 | 0/21 | 1/21 |
| Holdout 1 | 41/48 | 11/48 | 26/48 | 6/48 | 0/48 | 1/48 |
| Holdout 2 | 42/60 | 12/60 | 29/60 | 4/60 | 0/60 | 2/60 |

The development corpus fell from 47/47 because `_ = os.Remove("unused")` is now
treated as a deliberate discard. Every holdout defect that Interlinked catches,
Loki also catches. The remaining misses are mostly semantic, concurrency and
authorization bugs that neither product reaches.

## Latency

Development corpus, three repetitions, commit `feb3a99`, startup-warmed hook
wall-clock (milliseconds, median / p95).
[Evidence](comprehensive-lifecycle-daemon-2026-09-26/report.md).

| Profile | Loki | Interlinked |
| --- | ---: | ---: |
| Shared tools, all languages | 402 / 1,611 | 389 / 6,429 |
| No local JS tools | 334 / 711 | 10,756 / 11,239 |

Per language, Loki's median is lower for TypeScript (626 vs 6,249) and Python
(321 vs 404) and similar for Rust (417 vs 404). It is higher for Go (1,452 vs 349)
and Elixir (1,230 vs 242). There Loki runs go vet, golangci-lint, Credo and
Sobelow, while Interlinked defers or skips analysis and caught none of those
defects.

## Evidence

- [Blind holdout 2](holdout2-blind-2026-09-26/report.md), 3 repetitions
- [Development corpus with daemon](comprehensive-lifecycle-daemon-2026-09-26/report.md), 3 repetitions
- [Holdout 1 with daemon](holdout-daemon-2026-09-26/report.md), 3 repetitions
- [Confirmation runs on `daebb2a`](confirm-2026-09-26/), 1 repetition each
- Earlier: [2026-09-25 summary](comprehensive-summary-2026-09-25.md)
