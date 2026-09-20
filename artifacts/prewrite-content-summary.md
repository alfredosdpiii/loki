# Pre-write content comparison, 2026-09-20

Loki wins the expanded pre-write probe set under the tested configuration. That
does not establish an overall product win.

| Outcome | Loki | Interlinked CLI |
| --- | --- | --- |
| Harmful probes denied before execution | 9/9 | 6/9 |
| Legitimate controls blocked | 1/9 | 2/9 |
| Per-case median latency range | 67 to 122 ms | 61 to 81 ms |

There were 18 hand-picked cases and five repetitions per product and case.
Every case produced consistent decisions across its five repetitions. This set
was expanded to test the defects being fixed, not selected as an independent
sample of real development work. The counts are not population error rates.

## Setup and evidence

- Interlinked commit `207330d8131c5203ecc74e9fd4c24ba416463718`, balanced defaults,
  installed Claude hooks and a warm local daemon.
- Loki's installed Claude hooks, optional shell guard, and an explicit committed
  permission for `npm test`.
- Oxlint 1.83.0 made available through the same prepared executable in both
  disposable repositories. This is Loki's existing JavaScript analyzer dependency.
- No proposed file write or shell command executed.
- Raw samples, decisions, coverage warnings and engine identity are in
  `prewrite-content-comparison.json`.

Loki denied the Claude-policy replacement and aliased/computed test-disabling
cases that Interlinked admitted. Both denied the original empty catch, ordinary
test disabling, source redirect, outside-root write, destructive Git command
and inline-suppression probe.

Loki admitted the documented empty catch and shadowed local `test.skip` object.
Interlinked denied those controls. Loki still denied the text-log redirect, which
Interlinked allowed. Both admitted string/comment code examples and a handled catch.

Interlinked reported deferred or unavailable external checks on several admitted
TypeScript cases. The results count admission separately from coverage. They do
not claim that Interlinked completed a typecheck in those cases.

Loki was slower on the parser-backed cases, roughly 108 to 122 ms here. The test does
not establish a latency win.

## Without the analyzer

`prewrite-without-analyzer.json` reruns the original 11 cases without Oxlint, while
retaining the reviewed shell permission:

- Loki denied 4/6 harmful probes and blocked 1/5 legitimate controls.
- Interlinked denied 5/6 harmful probes and blocked none of those five controls.
- Loki explicitly reported missing pre-write content coverage.

The prevention gain therefore depends on installing the analyzer. Default
non-strict mode reports `NOT CHECKED` and admits the write when preview coverage
is unavailable. `LOKI_STRICT=1` denies it.

## Implementation

Loki reconstructs supported whole-file writes and exact replacements without
changing project files. It analyzes temporary before/after copies with fixed
`no-empty` and Jest/Vitest `no-disabled-tests` rules. Candidate config and ignore
files are excluded. Analysis copies neutralize lint-directive words so inline
suppression cannot disable these checks.

Diagnostics use source-line text, span text, rule, message and multiplicity.
Unchanged-line debt and line shifts pass. Removing one finding cannot cancel a
new finding with different source-line text. Editing an existing problematic line may
require fixing that finding.

Previews cover Claude Write/Edit/MultiEdit, Factory Create/Edit, Pi write/exact
edit and OMP write. Codex patches, OMP native edits and ambiguous replacements
remain explicitly unpreviewed. Their path checks still run.

Preview files are capped at 4 MiB and MultiEdit at 256 replacements. Replacement
growth is checked before allocating the result. The analyzer shares the hook deadline.
This remains static analysis, not execution confinement or race-free admission.
Commented empty blocks follow Oxlint's exemption; the checker cannot verify that
the explanation is honest.

## Validation

- 146 Python tests and 160 subtests passed with the real analyzer enabled.
- Eight adapter tests passed, with 100 assertions.
- Ruff formatting, installed-policy lint and strict TypeScript passed.
- Installed Claude/Factory handlers and installed Pi/OMP registered callbacks
  denied bad proposed content while leaving the files unchanged.
- Tests cover aliases, computed properties, strings, comments, shadowing, Unicode,
  old debt, repairs, multiplicity, config suppression, malformed reports and
  bounded replacement growth.

No live-host discovery rerun was performed for this revision. The earlier
four-host context proof and Pi runtime blocker remain separate evidence.
Phoenix SSRF/authorization gaps, full engineering-task comparisons and independent
deployment controls remain unresolved.
