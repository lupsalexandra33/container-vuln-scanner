# alpine:3.14

Captured: 2026-09-02 10:29 UTC
Digest:   alpine@sha256:0f2d5c38dd7a4f4f733e688e3a6733cb5ab1ac6e3cb4603a5dd564e5bfb80eed

## Tool versions

| Tool | Version |
|---|---|
| trivy | Version: 0.74.0 |
| grype | Version:             0.118.0 |
| syft | Version:       1.51.1 |
| osv-scanner | Version: 1.9.2 |

## Observations

Trivy reports 0 findings, Grype reports 39, with zero overlap.

Alpine's secdb records vulnerabilities together with the version that fixed them,
it is a fix ledger. Alpine 3.14 is past end of life, so nothing further is added and
Trivy has nothing to report. Grype falls back to matching installed versions against
NVD upstream ranges and continues to report.

The image is almost certainly vulnerable. This is the clearest case in the baseline
set that zero findings must not be presented as a clean result.