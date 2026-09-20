# Current-build comparison

Loki wins this configured pre-write probe set on prevention and legitimate
admission. Interlinked is faster. The evidence does not establish an overall
product win.

## Main result

Both disposable repositories had Oxlint 1.83.0 available. Loki's optional shell
guard was enabled, with a committed permission for `npm test`. Interlinked used
balanced defaults and a warm local daemon.

| Measure | Loki | Interlinked CLI |
| --- | --- | --- |
| Violation probes denied | 16/16 | 9/16 |
| Legitimate controls blocked | 1/16 | 2/16 |
| Median pre-hook latency | 119.88 ms | 76.44 ms |
| 95th-percentile latency | 149.78 ms | 95.43 ms |

Latencies pool 160 samples per product in this profile. Each of 32 cases ran five
times. Decisions were consistent within every case/product/profile. Three
profiles produced 960 measured decisions in total.

Loki's remaining legitimate block was a text-log redirect. Interlinked blocked
the documented empty catch and the shadowed local `test.skip` object.

### Results by case group

| Group | Loki violations denied | Interlinked violations denied | Loki legitimate blocks | Interlinked legitimate blocks |
| --- | --- | --- | --- | --- |
| Original probes | 6/6 | 5/6 | 1/5 | 0/5 |
| Previously added content controls | 3/3 | 1/3 | 0/4 | 2/4 |
| New language-rule defects and repairs | 7/7 | 3/7 | 0/7 | 0/7 |

Loki additionally denied hook-policy replacement, aliased/computed test disabling,
ignored Promise-executor returns, unsafe finally returns, constant nullish
conditions and debugger statements. Interlinked admitted those cases.
Both caught async Promise executors, unsafe optional chaining and focused tests.

The intended Loki diagnostics were verified for every denied violation probe.
These denials were not analyzer crashes or missing-tool failures.

## Configuration sensitivity

| Profile | Loki violations denied | Loki legitimate blocks | Interlinked violations denied | Interlinked legitimate blocks |
| --- | --- | --- | --- | --- |
| Oxlint present, no command permissions | 16/16 | 2/16 | 9/16 | 2/16 |
| Oxlint present, reviewed `npm test` | 16/16 | 1/16 | 9/16 | 2/16 |
| No Oxlint, reviewed `npm test` | 4/16 | 1/16 | 9/16 | 2/16 |

All profiles use Loki's opt-in shell guard. The first row is not a claim about a
bare installation without that guard.

Without Oxlint, Loki reported `NOT CHECKED` on 24 content cases and admitted them
under its non-strict policy. Those admissions are not successful content checks.
Interlinked reported deferred or unavailable external checks on 16 cases in each
profile. These were recorded separately from admission decisions. No aggregate
decision was classified as unavailable or review.

## Scope and limitations

- Interlinked was pinned to `207330d8131c5203ecc74e9fd4c24ba416463718`.
  Tracked source files were clean. This compares the pinned build, not an
  independently verified latest release.
- Node was 23.11.1 and Oxlint was 1.83.0.
- The runner invoked installed Claude pre-hook commands. It did not invoke model
  inference, execute proposed tools, or apply proposed writes.
- The added cases came from Loki's own rule-development fixtures. This is a
  hand-picked regression comparison, not a blind evaluation or a population
  false-positive estimate.
- Labels reflect the intended policy. A debugger statement or documented empty
  catch can be legitimate under a different policy.
- The repositories did not contain a complete TypeScript project/toolchain.
  Deferred compiler checks are not scored as pre-write denials; Interlinked may
  catch additional problems after writing.
- Latency samples were sequential, not randomized or collected on an otherwise
  controlled machine. The competitor daemon was already warm.
- Python, Go, Rust and Phoenix project checks, multi-step engineering tasks,
  Codex/OMP patch previews and production confinement were not compared.

No product code or externally edited tests were changed for this evaluation.
The new runner passed Ruff and its CLI check; the existing benchmark-contract
suite passed five tests and two subtests.

## Reproduction and raw evidence

```bash
python3 benchmarks/recheck.py \
  --interlinked /path/to/pinned/interlinked-cli \
  --node /absolute/path/to/node \
  --oxlint /absolute/path/to/oxlint \
  --runs 5 --output-dir /path/to/new/evidence-directory
```

The runner refuses to overwrite existing report files. Each report records all
case payloads, per-sample timings, hook diagnostics, capability output, engine and
compiled competitor hashes. Engine hashes were checked against the current
source after all three runs.

- `analyzer-default-permissions.json`
- `analyzer-reviewed-test.json`
- `no-analyzer-reviewed-test.json`
