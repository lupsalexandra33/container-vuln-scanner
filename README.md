# container-vuln-scanner

Multi-scanner container vulnerability analysis with cross-tool correlation and
confidence scoring.

Container vulnerability scanners disagree with each other. Run Trivy and Grype
against the same image and you get different answers, sometimes almost identical,
sometimes barely overlapping. This is not a bug in either of them: each consults
different data sources and applies different version-matching logic, and each can
be correct from the perspective of the source it consults.

This project runs several scanners against the same image and answers the question
their raw output cannot:

> **If N scanners produce N different answers for the same image, what is actually
> true?**

## The problem, measured

Baseline results from `testdata/fixtures`, captured with Trivy and Grype on the
same day against the same databases:

| Image | Trivy | Grype | Both | Overlap |
|---|---|---|---|---|
| nginx:1.21 | 523 | 508 | 503 | 95% |
| debian:11 | 120 | 110 | 110 | 91% |
| python:3.9-slim | 158 | 190 | 139 | 66% |
| node:12-alpine | 52 | 128 | 12 | 7% |
| alpine:3.14 | 0 | 39 | 0 | 0% |

Agreement ranges from near-total to none. The causes are identifiable: what the
distribution's security feed actually models, what each scanner is capable of
cataloguing, and which identifier schemes each one emits, and they are what the
correlation engine is built to handle.

The full analysis, and the design decisions each measurement supports, is in
[testdata/fixtures/FINDINGS.md](testdata/fixtures/FINDINGS.md).

## What it will do

```
  image reference
        │
        ├─  SBOM generation                 canonical package inventory
        │
        ├─  parallel scanner execution      isolated failures, per-tool timeouts
        │
        ├─  normalisation                   heterogeneous output → one model
        │
        ├─  correlation                     dedupe on (vulnerability ID, PURL)
        │
        ├─  confidence scoring              weighted inter-scanner agreement
        │
        ├─  enrichment                      CVSS · EPSS · CISA KEV · layer origin
        │
        ├─  policy evaluation               pass / warn / fail
        │
        └─  reporting                       JSON · terminal · SARIF
```

The output is not a list of CVEs but a list of CVEs with context: how confident
the system is in each one, which scanners agreed, where they disagreed and why,
and which of them had no data for the target at all.

## Design

**Library first.** All logic lives in importable packages under `pkg/` with no
dependency on terminal I/O. The CLI is a thin consumer. Nothing below `cmd/`
prints to stdout, reads environment variables, or calls `os.Exit`.

**One interface for every scanner.** Command-line tools and hosted services
satisfy the same contract, so adding a scanner is a single new file.

**Correlation on canonical identity.** The same package appears under different
names across tools, and PURL identifiers differ in encoding between them. Identity
requires canonicalisation, not string comparison.

**Weighted trust, not vote counting.** Scanners are not independent and are
stronger on some ecosystems than others, so confidence is weighted agreement among
the scanners that ran and were capable of detecting the finding class.

**Versioned sessions.** Every run records tool and database versions, so a
difference between two runs can be attributed to the image rather than to the
data.

## Status

Active development, targeting September 2026.

- [x] Repository structure, CI, ownership mapping
- [x] Scanner baselining and output fixtures
- [ ] Core types, PURL handling, version comparison
- [ ] Adapter layer · Trivy, Grype
- [ ] Concurrent orchestrator
- [ ] Normalisation
- [ ] Correlation and confidence scoring
- [ ] Conflict resolution
- [x] Enrichment · CVSS, EPSS, CISA KEV
- [ ] Reporting
- [ ] Policy engine
- [ ] CLI

Automated remediation is out of scope.

## Development

```bash
make build
make check
```

Tests run against recorded scanner output in `testdata/fixtures` and require no
scanners to be installed.

To re-capture fixtures (requires trivy, grype, syft and osv-scanner):

```bash
bash scripts/capture-fixtures.sh
```

Package layout and ownership are documented in
[docs/architecture.md](docs/architecture.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
