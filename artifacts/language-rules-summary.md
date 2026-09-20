# Strengthened language policies

The paired rule matrix passed all 42 expectations: 21 defects were detected and
all 21 corresponding repairs passed. The runner analyzes or compiles the examples;
it does not run them.

| Language | Changes | Defect/repair pairs |
| --- | --- | --- |
| Python | Ruff Pylint-error and logging rules, dangling asyncio tasks, unused suppressions | 4 |
| JavaScript/TypeScript | Fixed preview rules grow from 3 to 11; async Promise executors, executor returns, unsafe control flow/chaining, constant expressions, debugger statements and focused tests | 7 |
| Go | Check blank-assigned errors and type assertions; add errorlint, nilerr and durationcheck | 5 |
| Rust | Deny compiler/Clippy warnings and `expect` alongside existing restrictions | 2 |
| Elixir | Credo starter policy for unsafe shell/atom APIs, unused immutable results and operation/rescue warnings | 3 |

JavaScript preview rules and shipped Oxlint rules are checked for alignment.
The source walker now recognizes `.mjs` and `.cjs`; uppercase extensions enter
preview coverage checks rather than being silently skipped.

## Validation

- 153 Python tests and 167 subtests passed.
- Eight adapter tests passed, with 100 assertions.
- Ruff formatting and lint passed under the stronger shipped policy.
- golangci-lint validated the Go configuration.
- A full installed Oxlint configuration, including the existing custom plugins,
  rejected an async Promise executor and accepted its repair without diagnostics.
- The Python hook was exercised against committed stronger Ruff policy, detecting
  a new dangling task and accepting the repair.

The matrix used Ruff 0.15.2, Oxlint 1.83.0, Go 1.25.6,
golangci-lint 2.6.2, Clippy 0.1.92, Elixir 1.17.3 with OTP 27.3.4.11,
and prepared Credo 1.7.12. Runtime selection was process-local.

`language-rules-expanded.json` records every result, diagnostics, tool versions,
engine/policy hashes and the prepared Credo lockfile hash. All hashes matched
the final source and templates. `installed-js-rules.json` contains the full
installed JavaScript policy probe.

Earlier evidence is retained in `language-rules-first.json` and
`language-rules-final.json`. The first run exposed noncompliant control-fixture
formatting/documentation and an incorrect assumption that every analyzer uses
exit code 1. Those fixture/reporting errors were corrected without relaxing rules.

## Adoption and limits

Existing standalone Ruff, Go and Credo policies remain untouched by installation,
including force upgrades. Operators must review and commit policy changes.
Oxlint upgrades retain unrelated settings while merging Loki-owned rules/plugins.
Fixed preview rules and Rust scan flags follow the installed engine version.

A missing Credo policy is installed only when the target itself contains
`mix.exs`. Nested Mix projects need their own reviewed policy. Root and nested
Credo configuration paths are protected.

Go and Rust strengthening applies to repository scans, not every-write hooks.
Go retains formatting/vet on writes, and Rust retains rustfmt. Python and Credo
hook changes require adopting the committed policy. JavaScript previews still
require Oxlint and supported host input; unavailable checks retain their explicit
`NOT CHECKED` behavior.

These checks enforce policy, not intent. Credo's atom restriction can flag
deliberate controlled atom/module construction. Rust's `expect` restriction
includes tests, and warnings-as-errors can surface existing debt. The fixtures
do not establish a population false-positive rate.

Sobelow thresholds, Phoenix compilation/Dialyzer tiers and existing
SSRF/authorization limitations are unchanged. Competitive and live-host
benchmarks were not rerun for this revision. The externally changed
`tests/test_prewrite_content.py` was read and left untouched.
