package model

import "time"

// FindingClass distinguishes the kinds of problem a scanner can report.
//
// They are related but not interchangeable: they have different identity
// rules, different remediation paths, and different consequences. A secret has
// no CVE and no package; a misconfiguration describes the image rather than
// anything installed in it. Summing them into one total would be misleading.
type FindingClass string

const (
	// ClassVulnerability is a known vulnerability in an installed package.
	ClassVulnerability FindingClass = "vulnerability"

	// ClassMisconfiguration is a problem with how the image is built rather
	// than with what it contains: running as root, unsafe file permissions,
	// exposed ports.
	ClassMisconfiguration FindingClass = "misconfiguration"

	// ClassSecret is a credential embedded in an image layer.
	//
	// The secret value itself is never stored on a Finding — only its location
	// and kind. A report that quotes the secret it found has created a second
	// copy of the exposure.
	ClassSecret FindingClass = "secret"
)

// Severity is how serious a finding is, on a scale common to all scanners.
//
// Scanners use their own vocabularies and disagree about the same finding:
// on debian:11, Trivy and Grype assign different severities to identifiers
// they both report. Normalising onto one scale makes them comparable; the
// original value and its source are kept alongside in SeverityRating so that
// nothing is lost.
type Severity string

const (
	SeverityUnknown    Severity = "unknown"
	SeverityNegligible Severity = "negligible"
	SeverityLow        Severity = "low"
	SeverityMedium     Severity = "medium"
	SeverityHigh       Severity = "high"
	SeverityCritical   Severity = "critical"
)

// severityRank orders severities for comparison. Unknown ranks lowest: it
// means absence of information, and must never outrank a real assessment.
var severityRank = map[Severity]int{
	SeverityUnknown:    0,
	SeverityNegligible: 1,
	SeverityLow:        2,
	SeverityMedium:     3,
	SeverityHigh:       4,
	SeverityCritical:   5,
}

// Rank returns the ordering position of a severity.
func (s Severity) Rank() int { return severityRank[s] }

// MoreSevereThan reports whether s is more serious than other.
func (s Severity) MoreSevereThan(other Severity) bool { return s.Rank() > other.Rank() }

// SeverityRating is one scanner's severity assessment, with its provenance.
//
// A single finding routinely carries several: Trivy reports both the
// distribution's rating and NVD's for the same identifier. Keeping them all,
// each labelled with where it came from, is what lets conflict resolution
// prefer the distribution's view for a distribution package rather than
// picking arbitrarily.
type SeverityRating struct {
	Severity   Severity // normalised
	Source     string   // "nvd", "debian", "ghsa", "redhat"
	Original   string   // the value as the source wrote it, e.g. "Critical"
	CVSSScore  float64  // 0 when not supplied
	CVSSVector string   // e.g. "CVSS:3.1/AV:N/AC:L/..." — empty when not supplied
}

// FixState describes whether a fix exists for a finding.
//
// This must be a state rather than an empty-or-not version string. On
// debian:11, Grype reported 211 matches of which none had a fix available —
// a policy that fails a build on any critical finding would block work the
// team has no way to do. Telling "no fix exists" apart from "the scanner did
// not say" is what makes that policy expressible.
type FixState string

const (
	// FixUnknown means the scanner did not report on fix availability.
	FixUnknown FixState = "unknown"

	// FixAvailable means a fixed version exists and is named in FixedVersions.
	FixAvailable FixState = "available"

	// FixUnavailable means the source states no fix exists yet.
	FixUnavailable FixState = "unavailable"

	// FixWontFix means the maintainer has decided not to fix it — the package
	// is deprecated, or the issue is not considered exploitable in context.
	FixWontFix FixState = "wont_fix"

	// FixNotAffected means the source states this package is not affected,
	// despite matching on version. Distribution backports produce this: a
	// package can carry a security fix without its upstream version changing.
	FixNotAffected FixState = "not_affected"
)

// Finding is one problem as one scanner reported it, normalised into the
// shared model but not yet correlated with what other scanners said.
//
// One Finding is always attributable to exactly one scanner. Merging across
// scanners produces a ConsolidatedFinding.
type Finding struct {
	// Class determines which of the fields below are meaningful. A secret has
	// no Vulnerability and no Package; a misconfiguration has neither either.
	Class FindingClass

	// Scanner is the name of the tool that reported this, matching
	// Scanner.Name(). Every downstream decision about trust and agreement
	// depends on knowing which tool spoke.
	Scanner string

	// Vulnerability identifies the issue for ClassVulnerability. Its aliases
	// are what let the correlator recognise the same vulnerability reported
	// under a different scheme by another scanner.
	Vulnerability VulnRef

	// Package is the affected package for ClassVulnerability.
	//
	// It may be the zero value: not every scanner emits a PURL for every
	// finding. Such a finding can still be reported, but cannot be correlated
	// on exact identity.
	Package PURL

	// PackageName is the package name as this scanner wrote it, before PURL
	// canonicalisation — "openssl" from one tool, "libssl1.1" from another.
	// Kept for display and for approximate matching when Package is absent.
	PackageName string

	// InstalledVersion is the version found in the image.
	InstalledVersion string

	// FixState and FixedVersions describe remediation. FixedVersions is
	// populated only when FixState is FixAvailable, and can hold more than one
	// entry when several release lines are patched.
	FixState      FixState
	FixedVersions []string

	// Severities holds every severity assessment this scanner supplied, each
	// with its source. Conflict resolution reads these; nothing is discarded
	// at normalisation time.
	Severities []SeverityRating

	// Title and Description are human-readable text, when the scanner gives
	// any. Not every one does.
	Title       string
	Description string

	// References are URLs to advisories and related material.
	References []string

	// Location is where in the image the finding sits, when known: a file path
	// for a secret or a misconfiguration, a layer digest for a package.
	// Layer attribution fills this in more precisely later.
	Location string

	// PublishedAt is when the vulnerability was disclosed, when the scanner
	// reports it. Zero when unknown.
	PublishedAt time.Time
}

// PrimarySeverity returns the highest severity this scanner assigned.
//
// It is a display convenience and a fallback, not a resolution: taking the
// highest is a deliberately conservative choice for a single scanner's own
// ratings. Resolving disagreement *between* scanners is the correlator's job
// and uses source trust, not maximum.
func (f Finding) PrimarySeverity() Severity {
	worst := SeverityUnknown
	for _, r := range f.Severities {
		if r.Severity.MoreSevereThan(worst) {
			worst = r.Severity
		}
	}
	return worst
}

// SeverityFrom returns the rating from a named source, and whether one exists.
//
// Conflict resolution uses this to prefer the distribution's assessment over a
// generic one for distribution packages: the distribution is authoritative
// about its own backports.
func (f Finding) SeverityFrom(source string) (SeverityRating, bool) {
	for _, r := range f.Severities {
		if r.Source == source {
			return r, true
		}
	}
	return SeverityRating{}, false
}

// HasFix reports whether a fixed version is available to upgrade to.
func (f Finding) HasFix() bool {
	return f.FixState == FixAvailable && len(f.FixedVersions) > 0
}

// IsCorrelatable reports whether this finding carries enough identity to be
// matched exactly against findings from other scanners.
//
// A finding that is not correlatable is not dropped: it falls through to
// approximate matching, and to the uncorrelated category if that fails too.
// Silently discarding it would lose a real finding; silently merging it would
// invent agreement that was never established.
func (f Finding) IsCorrelatable() bool {
	switch f.Class {
	case ClassVulnerability:
		return f.Vulnerability.Primary.ID != "" && !f.Package.IsZero()
	default:
		// Misconfigurations and secrets have no CVE and no PURL. Their identity
		// rules are defined where those scanners are integrated.
		return false
	}
}
