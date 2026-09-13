# Getting Started with `vulnscan`

This guide walks you from a fresh clone to running your first correlated scan, inspecting findings, and launching the interactive terminal dashboard in under 5 minutes. No external scanner installations or live container daemons are required to evaluate the engine.

---

## 1. Prerequisites

* **Go**: 1.22 or newer (`go version`)
* **Operating System**: Linux or macOS (terminal emulator supporting ANSI escape sequences)
* **Make** (optional, for running convenience build targets)

---

## 2. Build the Binary

Clone the repository and build the CLI executable:

```bash
git clone [https://github.com/lupsalexandra33/container-vuln-scanner.git](https://github.com/lupsalexandra33/container-vuln-scanner.git)
cd container-vuln-scanner
make build
```

The compiled binary will be placed in `bin/vulnscan`. Verify that the CLI is accessible:

```bash
./bin/vulnscan --help
```

*(Optional)* Install it to your system PATH to invoke `vulnscan` directly:

```bash
go install ./cmd/vulnscan
```

---

## 3. Run a Recorded Scan (Offline Fixtures)

`vulnscan` allows evaluating multi-scanner correlation without requiring live tools (Grype, Trivy, OSV) or a Docker daemon. The repository bundles canonical fixture datasets under `testdata/fixtures/`.

### Run against the Debian 11 fixture:

```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11
```

By default, this outputs an executive consolidation summary and a standard tabular report:
* **Consolidation Summary**: Shows raw finding counts across scanners vs. deduplicated, corroborated records.
* **Confidence & Sources**: Displays multi-scanner agreement ratios (e.g., `2/2 grype,trivy`).
* **Conflict Resolution**: Lists inline secondary rows (`↳`) showing the exact resolution rationale when distributions disagree on severity or fix status.

---

## 4. Launch the Interactive Terminal UI (TUI)

To explore findings interactively with real-time filtering, search, and detail inspection:

```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11 --out tui
```

### Key Controls:
* `[1 - 6]`: Filter by severity tabs (**1. ALL**, **2. CRITICAL**, **3. HIGH**, etc.)
* `[↑ / ↓]` or `[j / k]`: Navigate table rows
* `[Enter]` or `[Space]`: Toggle the **Inspector Drawer** to view package origins, container layer attribution, descriptions, and conflict rationale
* `[/]`: Search by CVE ID or package name in real-time
* `[c]`: Clear search queries and reset active filters
* `[q]` / `[Ctrl+C]`: Exit cleanly and restore the previous terminal screen buffer

---

## 5. Export Machine-Readable Formats

Export consolidated findings directly for CI/CD pipeline integration and security dashboards:

### Export OASIS SARIF 2.1.0 (for GitHub Advanced Security / GitLab):
```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11 --out sarif > results.sarif
```

### Export JSON:
```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11 --out json > results.json
```

### Export Standalone HTML Report:
```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11 --out html > report.html
```

---

## 6. Run a Live Container Scan (Optional)

When a container engine (Docker or Podman) and scanner binaries are present in your environment:

```bash
./bin/vulnscan scan debian:11-slim --out tui
```

`vulnscan` will dynamically query installed scanner adapters, execute them concurrently, attribute findings to container layers, enrich CVEs with exploit intelligence (EPSS/KEV), and render the unified result.