# Benchmark protocol

The earlier pre-write comparison does not establish an overall winner. It leaves
out checks that run after edits, whole-project analysis, and ordinary repair work.

`comprehensive.py` invokes the installed Claude command hooks for both products.
It writes an admitted source edit into a disposable repository, then invokes the
installed post-write handlers. It never executes proposed shell commands or
application code. Explicit audit commands may compile the controlled fixtures.

## Cases and scoring

`corpus.py` contains paired defects and controls, exact replacements, cross-file
contract changes, existing-debt shifts, break/repair sequences, protected-path
attempts, and 10/1,000/10,000-file workloads. Languages are Python, TypeScript,
JavaScript, Go, Rust, and Elixir/Phoenix.

The corpus deliberately includes semantic security cases that neither product may
recognize. SSRF and request-controlled authorization stay in the denominator.
Cases reflect the author's knowledge of both products. They are synthetic, not an
independent holdout or a representative sample of production changes.

Before running, the runner saves the complete case list, its hash, the randomized
schedule, tool versions, command line, and source hashes. Each result uses an
exclusive file creation. Existing evidence cannot be replaced by another run.
Source identity is checked again when the run finishes.

The scorecard distinguishes:

- **Prevention:** a pre-hook denies the operation and emits a matching diagnostic.
- **Post-write detection:** a matching diagnostic reaches the host after source
  bytes land. This is not prevention, rollback, or an OS security boundary.
- **Unrelated blocking:** denial without evidence of the intended defect.
- **False blocking:** a control is blocked in any repetition, before or after writing.
- **Unavailable checks:** reported separately, even if the overall hook admits the edit.
- **Infrastructure failure:** remains in the denominator and earns no detection credit.

An accuracy result needs the same successful detection on every repetition.
Three repetitions are three timing/stability samples, not three independent cases.
Exit-zero native JSON denials count as denials. Exit-zero stderr alone does not
count as feedback delivered to Claude. Audit scoring examines actual diagnostic
entries, not the names of checks that reported zero findings.

The scorecard also decodes JSON feedback before matching individual diagnostic
lines. Otherwise a regex can span escaped `\n` sequences and mistake unrelated
advice for a compiler finding. Node module-format notices do not count as syntax
detection. Raw records retain provisional outcomes; the scorecard lists every
correction and hashes the final scorer.

Control feedback includes missing-tool notices and advisory messages. It is not
automatically a false positive. The report preserves the raw output for review.
Cold and startup-warmed timings are separate. Each repetition gets a fresh
repository, home, and daemon, avoiding leaked reservations and diagnostic caches.
The first trial has no warmup. Later trials send two git-status pre-hook envelopes
before the case, without executing the commands. That warms startup, not compiler
result caches. "Cold" does not mean flushed OS caches. Latency includes process
and sandbox startup.

## Isolation and tool parity

Each product/case/profile gets a new repository and home. Bubblewrap denies
network access, mounts the host filesystem read-only, and allows writes only to
the fixture tree and private temporary storage. There is no unsandboxed fallback.
The runner starts only known local binaries and uses an environment allowlist.
It uses the user's existing Git identity for fixture commits.

Repositories live under the ignored `artifacts/tmp/b/` directory by default,
outside OS temporary roots. Interlinked applies a distinct scratchpad policy to
paths under `/tmp`; measuring that policy would not represent ordinary repository
edits. `--work-dir` overrides the fixture parent. Keep its path short enough for
Unix domain sockets.

Both products receive the same analyzer paths. The shared profile supplies
TypeScript, Oxlint, Biome with its recommended lint config, Ruff, mypy,
golangci-lint, Go, Rust, and prepared Phoenix dependencies. This does not mean
both products invoke every available analyzer.

Loki's shell guard and a committed exact `npm test` permission are enabled.
Interlinked uses its balanced project installation. Other Loki settings remain
at their shipped values, including its disabled-by-default project type checker.
`configured.py` repeats the TypeScript cases with `"typescript_check": true`.
Keep that result separate from the ordinary installation.

The `missing-js` profile omits project-local JS analyzer links. It does not remove
system-wide tools or the competitor's own packaged dependencies. It measures that
specific degradation, not a completely tool-free machine.

Go/Rust audit results use `loki scan --base HEAD` and `interlinked verify --json`.
These have different product-defined scopes. Their findings are never added to
the ordinary-hook detection total.

The shared-scaffolding matrix places a JS package manifest in every fixture to
support its shell-grant controls. That can affect project discovery in non-JS
repositories. `native_projects.py` is a separate sensitivity run: Python gets
`pyproject.toml` with Ruff and mypy sections, and Go/Rust/Phoenix retain only their
native manifests. It omits the irrelevant npm grant for those fixtures. Do not
pool its observations with the shared-scaffolding results.

## Reproduce

Prepare the toolchains first, outside the network-isolated run. The competitor
checkout must be clean at `207330d8131c5203ecc74e9fd4c24ba416463718`, with its
`dist/` build present. The Phoenix project must use
`fixtures/phoenix/mix.exs` and `mix.lock`, with dependencies compiled under
Elixir 1.17.3 and a compatible OTP 27 installation. Provide a compatible Hex
archive as well. No global toolchain setting needs to change.

Run from the Loki checkout, substituting absolute paths:

```sh
ERL_FLAGS='+S 4:4' /usr/bin/python3 benchmarks/comprehensive.py \
  --interlinked /path/to/interlinked \
  --node /path/to/node-23/bin/node \
  --oxlint /path/to/oxlint-tools/node_modules/.bin/oxlint \
  --typescript /path/to/typescript-tools/node_modules/typescript \
  --biome /path/to/biome-tools/node_modules/.bin/biome \
  --python-tools /path/to/mypy-venv/bin \
  --golangci /path/to/golangci-lint \
  --phoenix /path/to/prepared-phoenix \
  --hex-archive /path/to/hex-archive \
  --erlang-bin /path/to/otp-27/bin \
  --runs 3 --seed 20260921 --profiles shared missing-js --scan \
  --output /path/to/new-evidence-directory

python3 -m benchmarks.report_comprehensive /path/to/new-evidence-directory
```

Use an actual Python executable, rather than a toolchain shim that might rewrite
`PATH` during startup. The explicit `--erlang-bin` also prevents that environment
problem inside fixtures.

For the type-check-enabled run, replace `comprehensive.py` with `configured.py`,
use `--profiles shared --case typescript`, and choose a new output directory.
That entry point changes only accepted fixture policy, not either product's code.
Its own hash is included in the evidence identity.

For native project discovery, use `native_projects.py --profiles shared` and
`--case '(^python/|^go/|^rust/|^elixir/|/python/)'`, with the same tool arguments
and a new output directory. This tests configuration sensitivity without changing
either product or the defect/control source.

## Separate integration and regression suites

- `host_context.py`: real installed hosts with fresh homes and a loopback model
  stub, with hooks enabled and disabled. This proves startup discovery/context
  delivery, not live-model tool enforcement.
- `phoenix.py`: installed ordinary hooks plus project-tier compilation and HEEx
  checks under multiple Sobelow confidence thresholds.
- `language_rules.py`: targeted analyzer defect/repair regressions. These were
  developed with Loki's policies and are not independent comparison cases.
- `tests/loki-shim.test.ts` and `tests/loki-omp.test.ts`: actual checker subprocesses
  through adapter callbacks, not running host inference sessions.

The smoke-run directories preserve setup failures. They are not merged into the
final comparison. Do not silently discard failures from a completed final run or
change cases and then reuse its manifest.

This protocol still does not measure long-running autonomous sessions, production
incident prevention, online dependency checks, all supported host write formats,
or unknown attacks. Those require separate experiments and explicit authorization
before using private repositories or paid model endpoints.
