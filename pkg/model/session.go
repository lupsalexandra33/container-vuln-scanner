package model

import "time"

// Target is what is being scanned.
//
// Digest is what identifies it, not Reference: a tag is a moving pointer and
// resolves to different content over time, so two runs against the same tag
// are not comparable.
type Target struct {
	Reference string // as the user gave it, e.g. "debian:11"
	Digest    string // "sha256:..." — the actual identity
	OS        string // "debian", "alpine"
	OSVersion string // "11.3", "3.14.10"

	// OSEndOfLife records that the distribution no longer receives security
	// updates. What that implies depends on the feed: Alpine's secdb records
	// only fixes, so it goes silent, while the Debian tracker keeps recording
	// affected-with-no-fix and continues to report.
	OSEndOfLife bool
}

// ToolVersion records a scanner and the vulnerability data it used.
//
// Vulnerability databases change daily. Without this, a difference between two
// runs cannot be attributed to the image rather than to the data.
type ToolVersion struct {
	Name        string
	Version     string
	DBVersion   string
	DBUpdatedAt time.Time
}

// SourceVersion records an enrichment source snapshot, for the same reason.
type SourceVersion struct {
	Name       string // "epss", "cisa-kev"
	FetchedAt  time.Time
	Identifier string // a version or ETag, when the source provides one
}

// RawResult is a scanner's unmodified output plus how the run went.
//
// Kept verbatim so that normalisation and correlation can be re-run against
// historical data without re-scanning.
type RawResult struct {
	Scanner  string
	Tool     ToolVersion
	Target   Target
	Payload  []byte // exactly what the tool produced
	Format   string // "trivy-json", "grype-json", "osv-json"
	Started  time.Time
	Duration time.Duration

	// Err is why the scanner failed, empty when it succeeded. A scanner that
	// failed is not a scanner that found nothing.
	Err string

	// NoData records that the scanner ran but had no vulnerability data for
	// this target — the alpine:3.14 case.
	NoData bool
}

// Succeeded reports whether the scanner ran to completion.
func (r RawResult) Succeeded() bool { return r.Err == "" }

// ScanSession is one complete run, and everything needed to reproduce it.
type ScanSession struct {
	ID        string
	Target    Target
	StartedAt time.Time
	Duration  time.Duration

	Tools   []ToolVersion   // every scanner and its database version
	Sources []SourceVersion // every enrichment snapshot
	Config  map[string]string

	Raw      []RawResult
	Findings []ConsolidatedFinding

	// SBOM is the package inventory at scan time: the canonical statement of
	// what was actually inside the image.
	SBOM []byte
}

// ScannersRun returns the scanners that completed successfully.
func (s ScanSession) ScannersRun() []string {
	var out []string
	for _, r := range s.Raw {
		if r.Succeeded() {
			out = append(out, r.Scanner)
		}
	}
	return out
}

// ScannersFailed returns the scanners that did not complete, mapped to why.
//
// A report that does not say which scanners failed presents a partial result
// as a complete one.
func (s ScanSession) ScannersFailed() map[string]string {
	out := map[string]string{}
	for _, r := range s.Raw {
		if !r.Succeeded() {
			out[r.Scanner] = r.Err
		}
	}
	return out
}

// IsComplete reports whether every scanner in the session succeeded.
func (s ScanSession) IsComplete() bool { return len(s.ScannersFailed()) == 0 }
