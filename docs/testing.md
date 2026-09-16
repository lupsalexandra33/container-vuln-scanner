# Testing Strategy & Verification Architecture

This document defines the testing architecture, fixture lifecycle, subsystem invariants, and coverage baselines for the container vulnerability scanner.

---

## Philosophy & Core Invariants

Testing follows three core design rules established in `docs/architecture.md`:

- **Strictly Hermetic & Offline**: The entire automated test suite runs without external scanner binaries, container runtimes, or live network access. CI and contributor laptops validate changes without `trivy`, `grype`, `syft`, `clair`, or `osv-scanner` installed.
- **Deterministic Consensus**: Tests execute against immutable recorded fixtures or synthetic in-memory models. Live scanners query fluctuating remote advisory feeds that destroy reproducible consensus assertions.
- **Race Safety & Parallelism**: Every test suite must pass cleanly under `go test -race ./...`. No shared global mutable state is permitted between test packages.

Where live scanner execution is genuinely required (e.g., `cmd/vulnscan/live.go`), it is isolated from the automated suite and verified through documented manual smoke runs recorded in PR checklists.

This is the part worth stating plainly rather than leaving implicit: the whole suite runs with no scanner binaries and no container runtime anywhere on the machine running it. That is what makes the fixtures load-bearing rather than just convenient — a contributor, or CI, can validate a change to `pkg/correlate` or `pkg/report` with nothing installed but Go itself.

---

## Subsystem Test Architectures

### 1. Orchestration & Concurrency (`pkg/orchestrator`)
The orchestrator executes scanners concurrently using an `errgroup` and bounded worker pools. Testing simulates all execution permutations without spawning real OS processes:
- **Mock Interfaces**: Tested using an in-memory `mockScanner` and `mockSBOMGen` satisfying `scanner.Scanner` and `sbom.Generator`.
- **Failure Isolation**: Proves that a failing scanner (`availableErr` or execution failure) does not abort peer scanners in the worker pool; errors are tracked cleanly in `session.ScannersFailed()`.
- **Context Cancellation & Timeouts**: Asserts that `context.DeadlineExceeded` terminates slow scanner executions (`WithScannerTimeout`) without leaking goroutines.
- **Constraint Filtering**: Verifies that `Offline: true` drops network-requiring tools, and capability masks selectively filter scanners by finding class (e.g., vulnerabilities vs. misconfigurations).

### 2. Correlation & Alias Graph (`pkg/correlate`)
Correlation is implemented as a pure function: `Correlate(findings, participants) -> []model.ConsolidatedFinding`.
- **Disjoint-Set Alias Resolution**: Validates union-find path compression across divergent vendor schemes (e.g., Trivy reporting a CVE with GHSA alias vs. OSV reporting GHSA as primary).
- **Participation Hierarchy**: Asserts the exact decision tree:
  `!Ran` (DidNotRun) -> `!Detects(class, eco)` (NotCapable) -> `NoData` (EOL distros like `alpine:3.14`) -> `RanAndMissed` (active dispute).
- **Determinism Loops**: Runs identical inputs across 20 iterations to assert that Go's randomized map iteration order does not alter output slice ordering.
- **Fixture Interoperability**: Integrates directly with `testdata/fixtures/debian_11` via `pkg/normalize` to test real multi-scanner consensus.

### 3. Enrichment & Network Degradation (`pkg/enrichment`)
Enrichment joins external threat feeds (CISA KEV, FIRST EPSS) onto normalized CVEs.
- **Ephemeral HTTP Mocks**: Uses `httptest.NewServer` to serve mock KEV catalogs and EPSS JSON payloads.
- **Graceful Network Degradation**: Verifies that when remote endpoints return HTTP 500 or timeout, `EnrichAll` does not fail the scan session. Instead, it returns `Enriched=false` with descriptive warning strings.
- **Cache Isolation**: Uses `os.MkdirTemp` per test run to verify disk-cache hits, TTL expirations, and non-CVE filtering.

### 4. Storage & Schema Migrations (`pkg/store`)
Persistent storage is backed by SQLite via modern SQL drivers.
- **In-Memory Verification**: Fast tests execute against `:memory:` instances.
- **Migration Idempotency**: Tests instantiate real on-disk databases (`t.TempDir()`), close them, and re-open them to verify that DDL migration statements are safe no-ops on existing schemas.
- **Upsert Deduplication**: Asserts that successive updates to identical CVE threat records overwrite rather than duplicate rows.

### 5. Exporters & Golden Output (`pkg/report`)
Exporters render consolidated findings into JSON, HTML, and SARIF 2.1.0 formats.
- **Contract Conformance**: Verifies that SARIF output conforms to schema version `2.1.0` with proper rule message formatting (e.g., active exploit KEV indicators).
- **Semantic Rendering**: Asserts that zero-value EPSS probabilities (e.g., `0.0015`) are displayed rather than suppressed, while missing enrichment defaults cleanly.
- **Dispute Badging**: Checks that findings with low confidence or active disputes render appropriate badges across HTML and JSON summaries.

The structured exporters are, in fact, well covered: `ExportSARIF` and
`ExportJSON` both measure 100% statement coverage, and `buildSARIF` measures
92.7%. What drags `pkg/report` down to the lowest coverage in the project is
almost entirely the interactive renderers — `RenderTUI`, `ServeDashboard`, and
every helper function under `tui.go`/`web.go` measure 0%. See the corrected
entry under Known Gaps below; an earlier draft of this document attributed
the package's low coverage to the SARIF/JSON exporters, which the measured
data does not support.

---

## Test Fixture Directory Structure

Recorded scanner outputs are preserved under `testdata/fixtures/<target>/<tool>.<ext>`. Tests reference these payloads via relative paths (`../../testdata/fixtures/...`):

- `testdata/fixtures/debian_11/`: Trivy and Grype baseline outputs for standard Debian distribution packages (`deb`).
- `testdata/fixtures/alpine_3.14/`: EOL distribution fixtures used specifically to verify scanner participation models, end-of-support silence (`NoData`), and empty-set handling.
- `testdata/fixtures/node_12_alpine/`: Fixtures containing language/binary artifacts (`pkg:binary`) used to test scanner capability boundaries (`Ecosystems`).

Fixtures must remain unmodified unless an upstream schema change requires recorded re-baselining.

---

## Coverage Baseline Matrix

**Measured against commit `c87f289` on 2026-09-16.**
A coverage figure without a date or commit attached is a claim that quietly
goes stale — this table drifts as the suite grows, and should be refreshed
before anyone relies on it for a merge decision rather than assumed current
indefinitely. (These specific numbers were measured on `stage/6.1-testing`
after rebasing onto the then-current `main` — an earlier measurement in this
same review cycle reported different numbers because it was taken against an
older commit, before `[6.3]` and the `history`/`diff` PR had merged. If you
re-measure and get different numbers again, check which commit you're
actually on before assuming the code changed.)

Regenerate with:

```
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

| Package | Statement Coverage | Test Paradigm & Scope |
| :--- | :--- | :--- |
| `pkg/orchestrator` | **96.5%** | Mock scanner runners, timeout handling, error grouping, and context cancellation. |
| `pkg/model` | **93.7%** | Pure unit tests: PURL parsing, version comparisons, canonical IDs, and finding models. |
| `pkg/trust` | **92.5%** | Calibration matrix, per-scanner precision/coverage, and confidence weighting. |
| `pkg/correlate` | **89.7%** | Disjoint-set alias graphs, canonical CVE selection, participation matrix, and determinism loops. |
| `pkg/enrichment` | **87.3%** | Mock HTTP servers (`httptest`), EPSS/KEV clients, disk cache, and network fallback. |
| `pkg/policy` | **86.0%** | Policy engine rule evaluation, threshold gating, and compliance violation collection. |
| `pkg/layers` | **85.7%** | Synthetic tar image layer unpacking and file-to-layer origin attribution. |
| `pkg/store` | **78.4%** | SQLite in-memory and disk tests, migration idempotency, upserts, and KEV listing. |
| `pkg/scanner/adapters` | **69.6%** | Adapter execution substrate (`trivy`, `grype`, `clair`) and capability declarations. |
| `pkg/sbom` | **62.5%** | CycloneDX and SPDX generation and parsing workflows via mock generators. |
| `pkg/normalize` | **55.8%** | Normalizer implementations mapping raw tool payloads to canonical findings. `osv.go`'s `convert`/`osvPURL`/`osvFixState`/`osvSeverities` measure 0% — worth a follow-up look, since this is more than the empty-results-array case discussed elsewhere; the conversion path itself looks entirely untested, not just untriggered. |
| `cmd/vulnscan` | **44.1%** | CLI entrypoints, subcommand routing, flag parsing, and session history/diff. Up from 39.3% with the addition of `history`/`diff` (`runDiff` 80.3%, `runHistory` 81.0%, `discoverSessions` 84.6%). |
| `pkg/scanner` | **33.3%** | Process runner wrappers (`exec.go`) and command-line execution interfaces. |
| `pkg/report` | **9.3%** | JSON/SARIF exporters are well covered (100% / 100% / 92.7% — see note above); the TUI and web dashboard renderers are entirely untested and account for essentially all of the package's uncovered statements. |
| **Total** | **55.4%** | |

---

## Known & Accepted Gaps

1. **Live Scanning (`cmd/vulnscan/live.go`)**:
   - *Status*: Accepted gap. Confirmed by measurement: `availableScanners`, `scanLive`, and `writeSessionProvenance` all measure 0%.
   - *Reason*: Invokes live host binaries and Docker daemons. Cannot execute in hermetic CI.
   - *Mitigation*: Covered by manual smoke testing against known reference images (`alpine:3.14`). A planned mock `scanner.Scanner` interface will exercise pipeline setup in future milestones.
2. **Flag Hoisting (`cmd/vulnscan/main.go`)**:
   - *Status*: **Still open.** `hoistFlags` and `isBoolFlag` both measure 0% coverage as of this baseline. An earlier draft of this document described this as "mitigated via reflection tests in `flags_test.go`" — that file either does not exist yet or does not exercise these functions; the measured data does not support calling this mitigated. Verify which is true before merging this document, and correct this entry accordingly.
   - *Reason*: `hoistFlags` requires awareness of all boolean options to prevent positional argument misordering — a new bool flag left out of `isBoolFlag` silently breaks the argument after it, and nothing currently catches that.
3. **Replay Round-Trip Verification (`vulnscan replay --verify`)**:
   - *Status*: Partially covered. The comparison logic itself (`compareFindings` 100%, `compareFindingSets` 92.9%, `replaySession` 75.0%) is well tested, largely thanks to reuse from `diff`. The CLI entry points `runReplay` and `verifyAgainst` both measure 0% — the round-trip property is exercised indirectly through the underlying functions but not through the command itself.
   - *Mitigation*: A test invoking `runReplay`/`verifyAgainst` directly against a saved session would close this rather than relying on indirect coverage through shared helpers.
4. **Interactive Report Rendering (`pkg/report/tui.go`, `pkg/report/web.go`)**:
   - *Status*: Accepted gap, explicitly tracked.
   - *Reason*: `RenderTUI`, `ServeDashboard`, `openBrowser`, and every rendering helper underneath them measure 0% coverage. This — not the SARIF/JSON exporters — is what makes `pkg/report` the lowest-covered package in the project. Both are interactive by nature (a live terminal, a live HTTP server opening a browser), which makes them a similar category of gap to live scanning: genuinely hard to exercise in a hermetic, non-interactive test run.
   - *Mitigation*: The SARIF and JSON paths already demonstrate the right pattern — `ExportSARIF`/`ExportJSON` are structured, deterministic, and golden-testable, and already are. `RenderTUI`/`ServeDashboard` would need either a headless-terminal testing approach or a refactor separating "build the view model" from "draw it," so the view-model construction can be tested even if the actual drawing can't be.

---

## Contributor Guidelines for Pull Requests

- **Strictly Offline Tests**: Never attempt real network calls or host binary execution in `*_test.go`. Use `httptest.Server`, `t.TempDir()`, or `testdata/fixtures`.
- **Explicit Branch Coverage**: Any PR adding a condition to scanner status, fix states, or capability matrix checks must include a corresponding table test case.
- **Deterministic Collections**: When aggregating data into slices, sort outputs explicitly by canonical identifier before returning to maintain deterministic reports.

---

## Verification Commands

Run all checks from the repository root:

    # Run linting, vetting, formatting, and unit tests with race detection
    make check

    # Run tests directly with verbose logging
    go test -v -race ./...

    # Regenerate the coverage baseline above
    go test -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out