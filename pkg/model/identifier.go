package model

import (
	"fmt"
	"regexp"
	"strings"
)

// Scheme identifies which vulnerability numbering system an identifier
// belongs to. Scanners do not agree on one: Trivy surfaces Debian tracker
// identifiers alongside CVEs, OSV-Scanner reports GHSA identifiers, and
// distributions issue their own advisory numbers.
//
// Modelling the identifier as a bare CVE string discards everything that is
// not a CVE. On debian:11, nine of the ten findings reported only by Trivy
// use Debian TEMP-* identifiers.
type Scheme string

const (
	SchemeCVE     Scheme = "CVE"     // CVE-2023-45853
	SchemeGHSA    Scheme = "GHSA"    // GHSA-x92m-jgcx-5qw2
	SchemeDebian  Scheme = "TEMP"    // TEMP-0841856-B18BAF
	SchemeDSA     Scheme = "DSA"     // DSA-5123-1, Debian security advisory
	SchemeAlpine  Scheme = "ALPINE"  // ALPINE-12345
	SchemeRHSA    Scheme = "RHSA"    // RHSA-2023:1234
	SchemeUnknown Scheme = "UNKNOWN" // anything we do not recognise
)

// VulnID is a vulnerability identifier together with the scheme it belongs to.
//
// The zero value is not valid. Construct with ParseVulnID.
type VulnID struct {
	Scheme Scheme
	ID     string // the full identifier, e.g. "CVE-2023-45853"
}

// schemePatterns maps a scheme to the shape of its identifiers. Order does not
// matter: the patterns are mutually exclusive.
var schemePatterns = []struct {
	scheme  Scheme
	pattern *regexp.Regexp
}{
	{SchemeCVE, regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)},
	{SchemeGHSA, regexp.MustCompile(`(?i)^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)},
	{SchemeDebian, regexp.MustCompile(`^TEMP-\d+-[0-9A-F]+$`)},
	{SchemeDSA, regexp.MustCompile(`^DSA-\d+-\d+$`)},
	{SchemeAlpine, regexp.MustCompile(`^ALPINE-\d+$`)},
	{SchemeRHSA, regexp.MustCompile(`^RHSA-\d{4}:\d+$`)},
}

// ParseVulnID classifies a raw identifier string.
//
// An unrecognised identifier is not an error: scanners may emit schemes we
// have not seen. It is returned with SchemeUnknown so that it can still be
// carried, correlated on exact match, and reported — just not enriched or
// resolved against schemes we do understand.
func ParseVulnID(raw string) (VulnID, error) {
	s := strings.TrimSpace(strings.ToUpper(raw))
	if s == "" {
		return VulnID{}, fmt.Errorf("empty vulnerability identifier")
	}

	for _, p := range schemePatterns {
		if p.pattern.MatchString(s) {
			return VulnID{Scheme: p.scheme, ID: s}, nil
		}
	}
	return VulnID{Scheme: SchemeUnknown, ID: s}, nil
}

// String returns the identifier as scanners write it.
func (v VulnID) String() string { return v.ID }

// IsCVE reports whether this is a CVE identifier.
//
// Enrichment sources that key on CVEs — EPSS and the CISA KEV catalogue —
// must filter on this before querying, or they receive identifiers they
// cannot resolve.
func (v VulnID) IsCVE() bool { return v.Scheme == SchemeCVE }

// Equal reports whether two identifiers are the same identifier. It is exact:
// it does not resolve aliases. Alias resolution belongs to the correlator,
// which has the alias sets to work with.
func (v VulnID) Equal(other VulnID) bool {
	return v.Scheme == other.Scheme && v.ID == other.ID
}

// VulnRef is a vulnerability as one scanner reported it: a primary identifier
// plus any aliases that scanner supplied.
//
// Aliases matter because the same vulnerability travels under different names.
// Grype may report CVE-2023-45853 while OSV-Scanner reports the GHSA that
// aliases it. Without the alias set, the correlator sees two findings.
type VulnRef struct {
	Primary VulnID
	Aliases []VulnID
}

// AllIDs returns the primary identifier followed by every alias, for callers
// that need to match against any name the vulnerability goes by.
func (r VulnRef) AllIDs() []VulnID {
	out := make([]VulnID, 0, len(r.Aliases)+1)
	out = append(out, r.Primary)
	out = append(out, r.Aliases...)
	return out
}

// PreferredID returns the identifier best suited for display and for keying
// external lookups: the CVE where one is known, otherwise the primary.
//
// Scanners disagree about which identifier is primary — OSV-Scanner leads with
// GHSA where Grype leads with the CVE for the same vulnerability. Preferring
// the CVE gives a stable key across tools.
func (r VulnRef) PreferredID() VulnID {
	if r.Primary.IsCVE() {
		return r.Primary
	}
	for _, a := range r.Aliases {
		if a.IsCVE() {
			return a
		}
	}
	return r.Primary
}
