# debian:11

Captured: 2026-09-02 10:15 UTC
Digest:   debian@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9

## Tool versions

| Tool | Version |
|---|---|
| trivy | Version: 0.74.0 |
| grype | Version: 0.118.0 |
| syft | Version: 1.51.1 |
| osv-scanner |  |

## Observations

Trivy 120 unique identifiers, Grype 110. Grype is a strict subset, zero findings
unique to it. Agreement is near-total here, in sharp contrast to node:12-alpine.

**Identifier schemes.** Nine of the ten findings unique to Trivy use Debian
`TEMP-*` identifiers rather than CVEs (`TEMP-0000000-21C4F8` on libpcre2-8-0,
`TEMP-0841856-B18BAF` on bash, and others). These are known security issues in
the Debian tracker that have not yet been assigned a CVE. Trivy surfaces them
because it reads the distribution tracker directly; Grype does not.

*Design consequence:* a vulnerability identifier is not always a CVE. The data
model must carry the scheme alongside the identifier, or 90% of Trivy's unique
findings are lost.

**Real disagreement.** CVE-2023-45853 (zlib1g) is the only actual CVE reported by
Trivy and missed by Grype. Worth investigating separately as a genuine
source-of-truth conflict.

**Package naming.** Identical across both tools on every shared finding. Exact
correlation is sufficient for this image.

**PURL.** Both tools emit PURL, but not in the same form:

    Trivy:  pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.11
    Grype:  pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64&distro=debian-11.11&upstream=db5.3

Grype percent-encodes `+` and adds an `upstream` qualifier Trivy omits. Identity
requires canonicalisation, not string comparison.

**Fix availability.** Grype reports 211 matches with 0 fixed, every finding is
unfixable. A policy that fails the build on any critical finding would block work
the team cannot act on.

**Feed state.** Trivy warns that Debian 11.3 is no longer supported by the
distribution and that detection may be insufficient.
