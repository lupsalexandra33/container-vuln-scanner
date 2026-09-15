# Testing Strategy & Verification Architecture

This document defines the testing architecture, fixture lifecycle, subsystem invariants, and coverage baselines for the container vulnerability scanner.

---

## Philosophy & Core Invariants

Testing follows three core design rules established in `docs/architecture.md`:

- **Strictly Hermetic & Offline**: The entire automated test suite runs without external scanner binaries, container runtimes, or live network access. CI and contributor laptops validate changes without `trivy`, `grype`, `syft`, `clair`, or `osv-scanner` installed.
- **Deterministic Consensus**: Tests execute against immutable recorded fixtures or synthetic in-memory models. Live scanners query fluctuating remote advisory feeds that destroy reproducible consensus assertions.
- **Race Safety & Parallelism**: Every test suite must pass cleanly under `go test -race ./...`. No shared global mutable state is permitted between test packages.

Where live scanner execution is genuinely required (e.g., `cmd/vulnscan/live.go`), it is isolated from the automated suite and verified through documented manual smoke runs recorded in PR checklists.

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

---

## Test Fixture Directory Structure

Recorded scanner outputs are preserved under `testdata/fixtures/<target>/<tool>.<ext>`. Tests reference these payloads via relative paths (`../../testdata/fixtures/...`):

- `testdata/fixtures/debian_11/`: Trivy and Grype baseline outputs for standard Debian distribution packages (`deb`).
- `testdata/fixtures/alpine_3.14/`: EOL distribution fixtures used specifically to verify scanner participation models, end-of-support silence (`NoData`), and empty-set handling.
- `testdata/fixtures/node_12_alpine/`: Fixtures containing language/binary artifacts (`pkg:binary`) used to test scanner capability boundaries (`Ecosystems`).

Fixtures must remain unmodified unless an upstream schema change requires recorded re-baselining.

---

## Coverage Baseline Matrix

Regenerate this table when introducing new packages or major components:

    make coverage
    # or manually:
    go test -race -coverprofile=bin/coverage.out ./...
    go tool cover -func=bin/coverage.out

| Package | Statement Coverage | Test Paradigm & Scope |
| :--- | :--- | :--- |
| `pkg/model` | **93.7%** | Pure unit tests: PURL parsing, version comparisons, canonical IDs, and finding models. |
| `pkg/orchestrator` | **96.5%** | Mock scanner runners, timeout handling, error grouping, and context cancellation. |
| `pkg/trust` | **92.5%** | Calibration matrix, Bayesian trust scoring, and scanner confidence weighting. |
| `pkg/correlate` | **89.7%** | Disjoint-set alias graphs, canonical CVE selection, participation matrix, and determinism loops. |
| `pkg/enrichment` | **87.3%** | Mock HTTP servers (`httptest`), EPSS/KEV clients, disk cache, and network fallback. |
| `pkg/policy` | **86.0%** | Policy engine rule evaluation, threshold gating, and compliance violation collection. |
| `pkg/layers` | **85.7%** | Synthetic tar image layer unpacking and file-to-layer origin attribution. |
| `pkg/store` | **78.4%** | SQLite in-memory and disk tests, migration idempotency, upserts, and KEV listing. |
| `pkg/scanner/adapters` | **69.6%** | Adapter execution substrate (`trivy`, `grype`) and capability declarations. |
| `pkg/sbom` | **62.5%** | CycloneDX and SPDX generation and parsing workflows via mock generators. |
| `pkg/normalize` | **55.8%** | Normalizer implementations mapping raw tool payloads to canonical findings. |
| `cmd/vulnscan` | **39.3%** | CLI entrypoints, subcommand routing, flag parsing, and history display (see gaps). |
| `pkg/scanner` | **33.3%** | Process runner wrappers (`exec.go`) and command-line execution interfaces. |
| `pkg/report` | **9.3%** | JSON, SARIF 2.1.0, and HTML template exporters. Statement count reflects large inline template declarations. |

---

## Known & Accepted Gaps

1. **Live Scanning (`cmd/vulnscan/live.go`)**:
   - *Status*: Accepted gap.
   - *Reason*: Invokes live host binaries and Docker daemons. Cannot execute in hermetic CI.
   - *Mitigation*: Covered by manual smoke testing against known reference images (`alpine:3.14`). A planned mock `scanner.Scanner` interface will exercise pipeline setup in future milestones.
2. **Flag Hoisting (`cmd/vulnscan/main.go`)**:
   - *Status*: Mitigated via reflection tests in Stage 6.1 (`cmd/vulnscan/flags_test.go`).
   - *Reason*: `hoistFlags` requires awareness of all boolean options to prevent positional argument misordering.
3. **Replay Round-Trip Verification (`vulnscan replay --verify`)**:
   - *Status*: Verified manually against recorded session fixtures.
   - *Mitigation*: Integration regression tests will assert bit-for-bit replay equivalence once SQLite storage schemas stabilize.

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

    # Generate full HTML statement coverage report in bin/coverage.html
    make coverage

    # Run tests directly with verbose logging
    go test -v -race ./...
