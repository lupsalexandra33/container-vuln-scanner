# python:3.9-slim

Captured: 2026-09-02 10:30 UTC
Digest:   python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b

## Tool versions

| Tool | Version |
|---|---|
| trivy | Version: 0.74.0 |
| grype | Version:             0.118.0 |
| syft | Version:       1.51.1 |
| osv-scanner | Version: 1.9.2 |

## Observations

66% overlap: 139 shared out of 209 unique (Trivy 158, Grype 190).

Mixed ecosystems, Debian base packages plus pip-installed Python packages. Agreement
sits between the near-total overlap on pure Debian images and the near-total
divergence on node:12-alpine. Worth revisiting once correlation is implemented, to
determine whether the gap comes from the Debian layer or from the Python packages.
