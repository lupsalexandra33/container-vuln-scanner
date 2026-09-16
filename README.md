# container-vuln-scanner

Multi-scanner container vulnerability correlation and triage.

Container vulnerability scanners do not agree with each other. Run Trivy and
Grype against the same image and you get different answers, sometimes almost
identical, sometimes barely overlapping. This is not a bug in either of them:
each consults different data sources and applies different version-matching
logic, and each can be correct from the perspective of the source it consults.

This tool runs several scanners against the same image and answers the question
their raw output cannot:

> **If N scanners produce N different answers for the same image, what is
> actually true?**

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

Agreement ranges from near-total to none. The causes are identifiable, and they
are not the ones that seem obvious: what the distribution's security feed
actually models, what each scanner is capable of cataloguing, and which
identifier schemes each one emits.

The full analysis, and the design decision each measurement supports, is in
[testdata/fixtures/FINDINGS.md](testdata/fixtures/FINDINGS.md).

## What it does

```
  image reference or recorded output
        │
        ├─  SBOM generation            generated once, shared between scanners
        │
        ├─  concurrent scanning        per-scanner timeouts, isolated failures
        │   trivy · grype · osv-scanner · clair
        │
        ├─  normalisation              heterogeneous output → one model
        │
        ├─  correlation                dedupe on (identifier, canonical PURL),
        │                              with alias resolution across schemes
        │
        ├─  confidence scoring         weighted agreement, per ecosystem
        │
        ├─  conflict resolution        resolved, with the rejected values kept
        │
        ├─  enrichment                 CVSS · EPSS · CISA KEV · layer origin
        │
        ├─  policy evaluation          pass / warn / fail, with an exit code
        │
        └─  reporting                  table · JSON · SARIF · HTML · TUI · web
```

### On a real image

```
$ vulnscan scan alpine:3.14

Scanners: trivy (no data), grype
77 raw findings correlated into 77

CVE-2024-5535  libcrypto1.1@1.1.1t-r2  critical  1.00  1/1 grype (no data: trivy)
  origin: layer sha256:9733ccc395133a…

Session 1d5a2120-552c-424e-b7f9-fbf4cdfac7bf
  target      alpine:3.14
  duration    5.3s
  trivy       0.74.0  db 2  updated 2026-09-12
  grype       0.118.0  updated 2026-09-12
```

Trivy ran successfully and reported nothing, because Alpine's secdb records only
fixes and stops receiving them past end of life. Grype reported 77. A single
scanner run on its own would have called this image clean.

Confidence stays at 1.00 because nothing contradicted these findings, the only
other scanner had no data to contradict them with. `(no data: trivy)` is what
keeps that readable rather than misleading.

### Correlating recorded output

```
$ vulnscan scan --from testdata/fixtures/debian_11

Scanners: grype, osv (no data), trivy
433 raw findings correlated into 243

CVE-2019-1010022  libc-bin@2.31-13+deb11u14  low  1.00  2/2 grype,trivy
  severity: debian=low, nvd=critical -> low (debian is authoritative for deb packages)

243 findings
  agreement     190 confirmed by more than one scanner, 53 disputed
  conflicts     168 findings had disagreeing sources, resolved and recorded
  remediation   0 of 243 have a fix available
```

The first finding is distribution backporting in its clearest form. NVD rates it
critical because it describes upstream glibc; Debian rates it low because it
assessed how the package is actually built. A report showing critical sends
someone to fix something that is not a problem there.

## Commands

```bash
vulnscan scan <image>                    # run the installed scanners
vulnscan scan --from <dir>               # correlate recorded output
vulnscan scan --policy balanced <image>  # exit 1 if the policy fails
vulnscan scan --from <dir> --out tui     # interactive terminal UI
vulnscan scan --from <dir> --out web     # browser dashboard
vulnscan scan --save run.session <image> # store the session for later

vulnscan replay run.session              # re-derive findings, no scanner run
vulnscan replay --verify out.json run.session
vulnscan history --from .                # list saved sessions
vulnscan diff old.session new.session    # what changed between two scans

vulnscan calibrate --from testdata/fixtures
vulnscan normalize -file grype.json      # inspect one scanner's output
```

Output formats: `table`, `json`, `sarif`, `html`, `tui`, `web`.

`replay --verify` and `diff` answer opposite questions with the same machinery.
Replay holds the scanner output fixed and asks whether our logic reproduces it
identically, any difference there is a bug. Diff compares two real scans taken
at different times, where a difference is the answer: a new advisory, a fix that
landed, a rating that moved.

## Design

**A vulnerability identifier is not always a CVE.** Nine of the ten findings only
Trivy reports on debian:11 use Debian tracker `TEMP-*` identifiers. Modelling the
field as a CVE string discards them.

**Package identity needs canonicalisation.** Grype percent-encodes `+` as `%2B`
and adds an `upstream` qualifier Trivy omits. Both name the same package;
comparing the raw strings says otherwise.

**Silence has four meanings.** A scanner that did not report a finding may have
looked and disagreed, been incapable of detecting that class in that ecosystem,
had no data for the target, or never run. Only the first is disagreement, and
only the first two belong in a confidence denominator. On node:12-alpine, Grype
catalogues 41 findings against compiled binaries that Trivy does not catalogue at
all, counting that silence as dissent would score every one of them as
low-confidence for a reason unrelated to whether it is real.

**Zero findings is not a clean image.** It can mean the scanner had no data for
the target. These are different states and are modelled separately.

**Trust is per ecosystem, not per scanner.** The same two tools agree on 91% of
findings on a supported distribution and on none of them on one past end of life.
A single weight per scanner cannot express that, and every weight carries the
reasoning that produced it, printable with `--explain-weights`, and checked
against measured behaviour by `vulnscan calibrate`.

**Disagreement is the normal case.** On debian:11, 145 of 222 findings carry
severity ratings from sources that do not agree. Resolution is ordered by
authority; a distribution is authoritative about its own packages, because it
decides what a vulnerability means there, and every resolution keeps the values
it rejected and the reason it rejected them.

**A gate must be workable to be used.** All 243 findings on debian:11 are
unfixable and ten are critical. A policy that failed on any critical finding
would block every build of that image on work nobody can do, and would be
switched off within a week.

**A result you cannot reproduce is an observation nobody can check.** Sessions
record tool and database versions alongside the raw scanner output, so
correlation can be re-run later and compared. `replay --verify` exits non-zero if
the same inputs produce a different result.

## Running it

Requires Go 1.23, plus whichever scanners you want to use: Trivy, Grype,
OSV-Scanner. Syft is optional and makes scans substantially faster by generating
the SBOM once instead of each scanner pulling the image separately: on
alpine:3.14 that is the difference between three minutes and five seconds. Clair
runs as a service; see `deploy/`.

```bash
make build
./bin/vulnscan scan --from testdata/fixtures/debian_11
```

The test suite runs against recorded scanner output and needs no scanner
installed and no container runtime:

```bash
make check
```

- [docs/getting-started.md](docs/getting-started.md) - five-minute setup
- [docs/architecture.md](docs/architecture.md) - package layout and data flow
- [docs/policy.md](docs/policy.md) - policy engine and exit codes
- [docs/tui.md](docs/tui.md) - terminal UI
- [docs/testing.md](docs/testing.md) - testing strategy and coverage baseline

## Status

Working end to end: live and recorded scanning, SBOM sharing, normalisation for
three scanner formats, correlation with alias resolution, per-ecosystem trust
weighting calibrated against measured agreement, conflict resolution, enrichment,
layer attribution, policy evaluation with CI exit codes, session save, replay,
history and diff, and six output formats.

Four scanners are integrated: Trivy, Grype, OSV-Scanner, and Clair. Clair is the
one that validated the abstraction, it is a service with an asynchronous
submit/poll/retrieve lifecycle, and it went in through the same `Scanner`
interface as two tools that shell out and read JSON, with no special-casing
anywhere.

Out of scope, with reasons:

- **Approximate correlation.** Package names matched exactly on every shared
  finding across all five baseline images. Approximate matching would address a
  case the data does not contain.
- **Ecosystem-aware version comparison.** Needed to detect backports
  independently of what a scanner reports, but no finding in the baseline set has
  a fix available to compare against.
- **Docker Scout and other commercial scanners.** The adapter interface supports
  them; a fourth data source that cannot be verified without credentials would
  not demonstrate anything the project does not already show.
- **Misconfiguration and secret scanning.** The model carries the finding classes
  and the identity rules are sketched, but no scanner for them is integrated.
- **Packaging and release automation.** `make build` produces a working binary;
  a release workflow would not demonstrate anything about correlation.
- **Automated remediation.** A separate project.

## License

Apache-2.0. See [LICENSE](LICENSE).