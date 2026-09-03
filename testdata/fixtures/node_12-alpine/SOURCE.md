# node:12-alpine

Captured: 2026-09-02 10:29 UTC
Digest:   node@sha256:d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68

## Tool versions

| Tool | Version |
|---|---|
| trivy | Version: 0.74.0 |
| grype | Version:             0.118.0 |
| syft | Version:       1.51.1 |
| osv-scanner | Version: 1.9.2 |

## Observations

Overlap of 7%: 12 shared findings out of 168 unique across both tools (Trivy 52,
Grype 128). The largest divergence in the baseline set, against near-total
agreement on debian:11 with the same two tools on the same day.

**Breakdown by ecosystem:**

| Ecosystem | Trivy | Grype |
|---|---|---|
| Alpine packages (apk) | 23 | 90 |
| npm | 44 | 45 |
| compiled binaries | 0 | 41 |

Three distinct causes, each needing different handling:

1. **Feed state (apk, 23 vs 90).** The base is an old Alpine release whose secdb
   feed no longer receives updates. Trivy reports only what remains there; Grype
   falls back to NVD version matching and keeps reporting. Same mechanism as
   alpine:3.14, where it produces 0 vs 39.

2. **Language ecosystems converge (npm, 44 vs 45).** Both tools read from
   overlapping sources (GHSA / OSV) and agree almost exactly. No divergence here.

3. **Scanner capability (binaries, 0 vs 41).** Grype catalogues compiled binaries,
   the Node runtime, statically linked libraries. Trivy does not catalogue them
   at all. This is a difference in what the tool looks at, not in what it knows.

*Design consequence:* the third case means confidence cannot be a count of
agreeing scanners. A scanner that cannot detect a finding class must be excluded
from the denominator for that class, otherwise every binary finding is
systematically scored as low-confidence. This is what the declared `Capabilities`
on the scanner interface is for.

**Package naming.** Identical across both tools on all 12 shared findings.
