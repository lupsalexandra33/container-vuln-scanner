# Baseline observations

Recorded in Stage 0.2 from the fixtures in this directory. Five images, scanned
with Trivy, Grype and OSV-Scanner on the same day against the same vulnerability
databases.

These measurements are the input to the data model and correlation design. Each
"design consequence" below is a decision that follows from evidence rather than
from assumption.

## Agreement ranges from 0% to 95%

| Image | Trivy | Grype | Both | Overlap |
|---|---|---|---|---|
| nginx:1.21 | 523 | 508 | 503 | 95% |
| debian:11 | 120 | 110 | 110 | 91% |
| python:3.9-slim | 158 | 190 | 139 | 66% |
| node:12-alpine | 52 | 128 | 12 | 7% |
| alpine:3.14 | 0 | 39 | 0 | 0% |

Same two tools, same day, same databases. The spread is not noise, it has
identifiable causes, and they are not the ones that seem obvious at first.

## What actually drives divergence

### It is not end-of-life status

Both `debian:11` (11.3) and `alpine:3.14` are past end of life, and Trivy warns
about both. Yet Trivy reports 120 findings on one and 0 on the other. `nginx:1.21`
is also built on Debian 11.3 and produces 523.

### It is what the feed models

Alpine's `secdb` records vulnerabilities **together with the version that fixed
them**. It is a fix ledger. Once a release stops receiving security updates,
nothing further is added, and a scanner reading it has nothing to report, which
is why `alpine:3.14` returns zero.

The Debian Security Tracker also records issues that are **affected with no fix
available**. It keeps describing the state of a package after support ends, so
Trivy continues to report against it.

Grype behaves differently again: where the distribution feed is silent it falls
back to matching the installed version against NVD's upstream ranges, which is why
it reports 39 findings on `alpine:3.14` where Trivy reports none.

*Design consequence:* zero findings is not a clean result. It can mean the scanner
had no data for the target. These are different states and must be modelled
separately, propagated through correlation, and shown distinctly in reports. A
tool that renders them the same way is actively misleading.

### Scanner capability, not scanner knowledge

On `node:12-alpine`, findings break down by ecosystem as:

| Ecosystem | Trivy | Grype |
|---|---|---|
| Alpine packages (apk) | 23 | 90 |
| npm | 44 | 45 |
| compiled binaries | 0 | 41 |

The npm column shows near-total agreement: on language ecosystems both tools read
from overlapping sources and converge. The binary column shows Grype cataloguing
compiled artifacts (the Node runtime, statically linked libraries) that Trivy does
not catalogue at all.

*Design consequence:* confidence cannot be a count of agreeing scanners. A scanner
that cannot detect a finding class must be excluded from the denominator for that
class, otherwise every binary finding is systematically scored as low-confidence
for a reason that has nothing to do with whether it is real. This is what the
declared `Capabilities` on the scanner interface exists to express.

*Design consequence:* trust weights must be scoped per ecosystem. A single weight
per scanner cannot represent a tool that is authoritative on one ecosystem and
blind on another.

### Not every identifier is a CVE

On `debian:11`, nine of the ten findings unique to Trivy use Debian `TEMP-*`
identifiers rather than CVEs, known issues in the Debian tracker that have not
yet been assigned one. Trivy surfaces them because it reads the tracker directly.

*Design consequence:* the data model must carry the identifier scheme alongside
the identifier. Modelling the field as a CVE string discards 90% of what one
scanner uniquely contributes.

The single genuine CVE-level disagreement on that image is CVE-2023-45853
(zlib1g), reported by Trivy and missed by Grype. Worth investigating separately as
a real source-of-truth conflict rather than a structural difference.

## Package identity

Both tools emit Package URLs, but not in the same form:

```
Trivy:  pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.11
Grype:  pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64&distro=debian-11.11&upstream=db5.3
```

Grype percent-encodes `+` and adds an `upstream` qualifier that Trivy omits.

*Design consequence:* identity requires canonicalisation, percent-decoding,
qualifier ordering, and a defined set of qualifiers that participate in identity, 
not string comparison.

Package **names**, however, matched exactly on every shared finding across all five
images. Exact correlation covers the common case; approximate matching is an edge
case rather than the central mechanism, and should be built as a fallback with an
explicit uncorrelated category rather than as the primary path.

## Fix availability

Grype reports 211 matches on `debian:11`, of which **0 have a fix available**.

*Design consequence:* a policy rule that fails a build on any critical finding
would block work on vulnerabilities the team has no way to resolve. Fix
availability has to be a first-class input to policy evaluation, not a display
field.

## Summary of decisions this evidence supports

| Decision | Evidence |
|---|---|
| Identifier carries a scheme, not just a CVE string | 9 of 10 Trivy-unique findings on debian:11 are `TEMP-*` |
| No-data is a distinct state from clean | alpine:3.14 returns 0 from Trivy, 39 from Grype |
| Scanners declare capabilities; non-capable scanners leave the denominator | 41 binary findings from Grype, 0 from Trivy |
| Trust weights are scoped per ecosystem | apk 23 vs 90, npm 44 vs 45 on the same image |
| PURL comparison requires canonicalisation | `%2B` encoding and `upstream` qualifier differ between tools |
| Approximate correlation is a fallback, not the main path | package names matched exactly on every shared finding |
| Fix availability is a policy input | 211 findings, 0 fixable, on debian:11 |

## Method

Identifier sets were extracted from the fixtures in this directory with `jq`:

```bash
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' trivy.json | sort -u
jq -r '.matches[].vulnerability.id' grype.json | sort -u
```

Overlap is the size of the intersection over the size of the union. Per-image
detail, tool versions and capture timestamps are in each image's `SOURCE.md`.

Counts are of unique identifiers, not of findings: one identifier affecting
several packages is counted once. Absolute totals will therefore differ from the
figures the tools print at the end of a scan.