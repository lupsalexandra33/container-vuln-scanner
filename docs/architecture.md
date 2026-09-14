# Architecture

This document explains how a container image reference becomes a list of
confidence-scored, conflict-resolved vulnerability findings, and why the
pipeline is built the way it is rather than as a simpler merge of scanner
output.

## Pipeline

    image reference
      -> SBOM generation
      -> parallel scanner execution
      -> normalisation
      -> correlation
      -> confidence scoring
      -> enrichment
      -> policy evaluation
      -> reporting

Live scans and recorded scans (`scan --from <dir>`) converge on the same
pipeline from normalisation onward. This is deliberate: if the two paths ran
through different correlation code, the fixtures in `testdata/` would stop
being a faithful stand-in for a real scan, and every test built on them would
be testing something the tool does not actually do.

## Why scanners disagree

Two scanners can both be correct and still produce different answers, for
three independent reasons:

1. **Different data sources.** Debian's security tracker and NVD can rate the
   same CVE differently, because Debian backports fixes without bumping the
   upstream version number NVD's CVSS score describes.
2. **Different capabilities.** Grype catalogues compiled binaries under
   `pkg:generic`; Trivy does not. A scanner that never looks at a class of
   package has not disagreed about it — it has said nothing.
3. **Different identifier schemes.** Grype tends to lead with a CVE, carrying
   a GHSA as an alias. OSV-Scanner does the reverse. Grouping findings by
   their primary identifier alone would treat the same vulnerability as two
   separate ones whenever two scanners lead with different schemes.

The pipeline is built to keep these three causes distinguishable all the way
through to the final report, rather than collapsing them into a single
"disagreement" signal.

## The participant model: why silence is not disagreement

Every scanner considered during a scan is represented as a `Participant`
(`pkg/correlate`), and every finding records a `Verdict` for every
participant, not just the ones that reported it. A participant's absence from
a finding falls into one of four categories, and only one of them is real
disagreement:

| Situation | Participation | Counts as disagreement? |
|---|---|---|
| Scanner never ran (not selected, crashed, filtered out) | `DidNotRun` | No |
| Scanner ran but cannot detect this class in this ecosystem | `NotCapable` | No |
| Scanner ran, was capable, but had no data for this target | `NoData` | No |
| Scanner ran, was capable, had data, and still did not report it | `RanAndMissed` | **Yes** |

This distinction is not a nicety; it changes the actual confidence number.
On `alpine:3.14`, Trivy reports zero vulnerabilities because Alpine's security
database stops receiving entries once a release goes end-of-life, while Grype
(which falls back to NVD) reports 39. Counting Trivy's silence as
disagreement would halve confidence on every one of those 39 findings for a
reason that has nothing to do with whether the findings are real. Recording
it as `NoData` instead keeps confidence at 1.0: nothing capable of
contradicting these findings did.

Confidence itself (`pkg/correlate`, `pkg/trust`) is weighted agreement among
participating scanners — `AgreeingWeight / ParticipatingWeight` — not a raw
vote count, because scanners are not equally reliable in every ecosystem.
Weights are configured per ecosystem, not globally: the same two tools that
agree on 91% of `deb` findings agree on none of the findings for an
end-of-life `apk` image, and a single per-scanner weight would encode a
ranking the evidence does not support.

## Alias resolution: correlating across identifier schemes

`pkg/correlate/aliases.go` builds a graph where every finding contributes
edges between every identifier it names (a CVE, its GHSA alias, and so on).
Each connected component in that graph is treated as one real vulnerability,
computed with union-find so that path compression keeps repeated lookups
cheap across the thousands of identifiers a real scan produces.

Within a group, a CVE is preferred as the canonical identifier where one
exists, because external sources — EPSS, the CISA KEV catalogue — key on CVE
IDs. Where a group has no CVE, the lexicographically smallest identifier is
used, which is arbitrary but deterministic: the same input must always
produce the same grouping, or the correlation key stops being a key.

This is what makes it possible for three scanners — one leading with a CVE,
one leading with a GHSA and carrying the CVE as an alias, one doing the
reverse — to correctly consolidate into a single finding rather than two or
three separate ones.

## Conflict resolution: an authority chain, not "pick the worst"

Where scanners agree on identity but disagree on a field's value — severity,
fix state — `pkg/correlate/resolve.go` resolves it through an ordered chain
of strategies rather than always taking the most severe rating. Each
resolution records what it rejected and why, in a `model.Conflict`, so the
decision can be checked rather than trusted:

1. **The distribution that owns the package decides**, where one applies. A
   `deb` package's severity is Debian's call, an `apk` package's is Alpine's,
   because the distribution knows what it backported and NVD — which
   describes the upstream software — does not.
2. **Distribution consensus outranks a single generic source.** If several
   independent distributions agree with each other and only NVD or GHSA
   dissents, the distributions win: several independent assessments of the
   same bug converging is stronger evidence than one describing the upstream
   software rather than the package as built.
3. **Absent consensus, the most severe distribution rating wins**, erring
   toward surfacing a risk rather than hiding it.
4. **With no distribution rating at all** (language ecosystems like npm have
   no distribution behind them), the most severe generic rating is used, and
   the resolution says so rather than implying an authority that is not
   there.

Fix state follows a similar but simpler priority: a named fix outranks
everything, because it is the most actionable thing a report can say; "not
affected" closes the finding; "won't fix" and "unavailable" are both dead
ends, but a reader needs to know which kind of dead end.

## Correlation methods

Only exact correlation exists today: findings resolve to the same group when
they share a canonical identifier (after alias resolution) and a canonical
package identity. A finding with no parseable identifier or no PURL is
reported on its own rather than merged into an unrelated group that happens
to share the same absence.

**Approximate correlation is a known, open gap.** Two findings that describe
the same vulnerability with slightly different version strings, or with no
clean identifier on either side, do not currently get a second chance at
matching — they stand alone. `correlate.go` reserves a `CorrelationMethod`
for this; the matching logic itself has not been built yet.

## Calibration: what the numbers can and cannot say

`vulnscan calibrate` (`pkg/trust`) measures how often each scanner's reports
were corroborated by another scanner, against the same verdicts the
correlator already recorded — the measurement and the confidence scores it
validates rest on identical evidence.

This is explicitly **not** measurement against verified ground truth, and the
tool says so in its own output. Nobody has manually confirmed which findings
are real, so a scanner that is uniquely correct where every other scanner is
wrong scores badly by construction. That is why unique findings — cases where
one scanner reported something no other capable, ran, in-data scanner
confirmed or contradicted — are counted and displayed separately rather than
folded into a precision score that would misrepresent them as noise.

Where both coverage and precision measure zero — the end-of-life `apk` case,
or `pkg:generic` binaries that only one scanner catalogues at all — the tool
reports that explicitly as "no scanner corroborated another," not as a
suggested downgrade. A suggested weight there would measure the absence of
agreement, not the quality of the scanner, and the configured value is left
to stand.

## Live vs. recorded scanning

`scan <image>` and `scan --from <dir>` both end up calling the same
`correlate.CorrelateWith`, but they build their `Participant` lists
differently:

- **Live** (`cmd/vulnscan/live.go`) reads `Capabilities()` directly from the
  constructed scanner instance, because the instance is the authority on what
  it can detect. It also builds the participant list from every scanner that
  was *constructed*, not from the scanners that produced results — the
  orchestrator can filter a scanner out during selection, and a scanner that
  was never selected must stay distinguishable from one that does not exist.
- **Recorded** (`cmd/vulnscan/scan.go`) has no live instance to ask, so
  capabilities come from a small name-keyed table instead. That table is a
  copy of what the live adapters declare, and a copy can drift — it exists
  only because a JSON file on disk cannot be asked what it can do.

Live scans also record session provenance: tool versions, vulnerability
database versions, and when the database was last updated. Without this, a
difference between two scans of the same image cannot be attributed to a
change in the image rather than a change in the data feeding the scan.

Enrichment: temporal exploitability without negative inference
Correlation establishes whether scanners agree on the software package; `pkg/enrichment` establishes whether attackers are exploiting it. It joins findings against two dynamic external telemetry sources:
1. **CISA KEV (Known Exploited Vulnerabilities):** A binary confirmation that a CVE has been weaponized in the wild.
2. **FIRST EPSS (Exploit Prediction Scoring System):** A probabilistic score ($0.0 \le p \le 1.0$) estimating the likelihood of exploitation attempts within 30 days.

Two design decisions govern enrichment:
* **Missing data is not negative proof:** When running offline, behind a strict firewall, or against emerging zero-days where telemetry is not yet indexed, `Enrichment` remains `nil`. The policy engine explicitly treats `nil` as "unknown" rather than "not exploited." A rule requiring "not in KEV" will never match an un-enriched finding, preventing silent downgrades when network calls fail.
* **Deterministic caching with bounded TTL:** Live telemetry lookups are backed by a local SQLite cache (`pkg/store`) to prevent third-party rate limits from breaking rapid CI builds and to guarantee identical runs within an active deployment window.

Layer attribution: provenance across container history
A consolidated finding tells you *what* is vulnerable; `pkg/layers` tells you *where* it was introduced in the build process.
* **Non-destructive inspection:** Rather than re-extracting massive OCI layer tarballs, layer attribution traces file-level package paths back to the container manifest's DiffIDs and Docker history metadata.
* **Actionable developer feedback:** A finding attributed to `layer #2 (RUN apt-get update && apt-get install -y zlib1g)` enables a developer to patch the specific `Dockerfile` line, whereas an attribution to the base image points the resolution toward updating the `FROM` directive.

Persistence and session history
`pkg/store` provides structured SQLite persistence with embedded, transactional schema migrations:
* **Session provenance:** Every scan records an immutable snapshot including CLI flags, participating scanner versions, database timestamps, and raw finding counts.
* **Diffing and regression detection:** Persisting consolidated models rather than raw scanner blobs allows teams to query delta changes between builds (`scan A` vs `scan B`) without re-running scanners or re-evaluating historical heuristic trees.

Reporting and visualization
The reporting layer (`pkg/report`) consumes the final `Report` model and exposes four distinct consumers:
* **Machine pipelines (JSON & SARIF 2.1.0):** SARIF output maps consolidated severity, confidence inputs, and layer attribution directly into the OASIS SARIF format for native integration with GitHub Advanced Security and GitLab Security dashboards.
* **Executive summary (HTML):** A standalone, zero-dependency HTML dashboard bundling CSS and JavaScript inline for sharing via CI artifacts.
* **Interactive Terminal UI (TUI):** Built with raw ANSI sequences, dynamic `TIOCGWINSZ` window detection, and an alternate screen buffer (`\033[?1049h`). It maintains an in-memory `strings.Builder` atomic render pipeline to eliminate flicker while rendering dynamic confidence meters (`▰▰▰▰▰`), interactive searching, and an expandable inspector drawer for verifying conflict resolutions in place.

## Package layout and ownership

| Package | Purpose | Owner |
|---|---|---|
| `pkg/model` | shared data types | Alexandra |
| `pkg/normalize` | tool output to unified model | Alexandra |
| `pkg/correlate` | cross-scanner finding identity, confidence, conflict resolution | Alexandra |
| `pkg/trust` | trust weights, calibration | Alexandra |
| `pkg/policy` | rule evaluation | Alexandra |
| `pkg/scanner` | scanner interface | Razvan |
| `pkg/scanner/adapters` | one file per tool | Razvan |
| `pkg/orchestrator` | concurrent execution | Razvan |
| `pkg/sbom` | package inventory | Razvan |
| `pkg/enrichment` | CVSS, EPSS, KEV | Daiana |
| `pkg/layers` | layer attribution | Daiana |
| `pkg/store` | persistence and history | Daiana |
| `pkg/report` | output formats | Daiana |

## Rules

1. Nothing under `pkg/` prints to stdout, reads environment variables, or calls
   `os.Exit`. Configuration is passed in; errors are returned.
2. `cmd/vulnscan` contains no business logic. It parses flags, calls into
   `pkg/`, and formats the result.
3. Every package is tested against `testdata/fixtures`, not against live
   tools, so the test suite runs without any scanner installed.
4. Live and recorded scans go through identical correlation, resolution, and
   reporting code from normalisation onward. Anywhere the two paths diverge
   is a place the fixtures stop being trustworthy.
