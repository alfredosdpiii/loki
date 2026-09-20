# Phoenix hook audit, 2026-09-20

The final evidence is in `phoenix-final-high.json`, `phoenix-final-none.json`
and `phoenix-final-low.json`. All three record the same final engine digest.
Each run has 19 scenarios and two timing samples per ordinary-hook scenario.
These are installed-command tests in disposable projects, not live-agent sessions.

## Results

- Standard Phoenix controller examples for unsafe deserialization, SQL injection,
  code evaluation and atom creation produced security findings and failed the
  default high-confidence post-write gate. The bytes had already landed.
- All six ordinary-hook repair examples passed without diagnostics.
- Existing Credo and Sobelow findings did not block valid edits or line shifts.
- A plain helper's code-evaluation finding remained informational at the default
  threshold and failed when blocking was set to low.
- With blocking set to none, security findings remained in post-tool JSON context
  without causing denial.
- Missing required component attributes and malformed HEEx failed compilation in
  the explicit project tier. The valid component and its repair compiled.
  Whole-project Credo still reported the deliberately retained baseline debt.
- Caller-controlled URL and client-controlled authorization examples received no
  targeted security finding. They remain coverage gaps.

Median ordinary-hook times across the scenarios were 1,552 ms for high blocking,
1,565 ms for none, and 1,568 ms for low. Preparation and dependency compilation
are excluded. This is a small controlled workload, not a latency guarantee.

## Validation

- 105 Python tests and 77 subtests passed.
- Six current adapter tests passed with real Python checker processes.
- The broader `bun test` command also passed six historical tests under `mutants/`.
- Installed-policy Ruff and strict TypeScript checks passed.
- Installed Claude, Codex and Factory commands worked from nested directories.
- Managed-engine upgrades preserved unrelated handlers. Installed Pi/OMP callbacks
  still used the external engine after the candidate engine was replaced.

The first benchmark used nonstandard controller declarations and overestimated
their blocking confidence. `phoenix-verification.json` preserves those failed
expectations. `phoenix-canonical.json` is an intermediate successful run, not the
final-engine evidence.

Elixir 1.17.3 with OTP 27 ran these fixtures. The Python mise shim initially reset
the selected runtime, causing a discarded preparation failure. The final runs used
process-local runtime paths and `/usr/bin/python3`; no global runtime settings or
existing application projects were changed.

Actual host session context delivery, production security controls, and a fresh
comparison against Interlinked remain unverified.
