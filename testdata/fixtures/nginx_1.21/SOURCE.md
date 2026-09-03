# nginx:1.21

Captured: 2026-09-02 10:50 UTC
Digest:   nginx@sha256:2bcabc23b45489fb0885d69a06ba1d648aeda973fae7bb981bafbb884165e514

## Tool versions

| Tool | Version |
|---|---|
| trivy | Version: 0.74.0 |
| grype | Version:             0.118.0 |
| syft | Version:       1.51.1 |
| osv-scanner | Version: 1.9.2 |

## Observations

Highest agreement in the baseline set: 503 shared identifiers out of 528 unique,
95% overlap.

Built on Debian 11.3, which Trivy flags as end of life, yet both tools report over
500 findings each. This rules out end-of-life status as the direct cause of the
divergence seen on alpine:3.14. The Debian Security Tracker records issues that are
affected with no fix available, so it keeps describing package state after support
ends; Alpine's secdb does not.
