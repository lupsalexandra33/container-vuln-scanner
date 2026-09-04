package model

// Participation records how one scanner stood in relation to one finding.
//
// Two states are not enough. A scanner that did not report a finding may have
// looked and disagreed, or may have been incapable of seeing it at all. On
// node:12-alpine, Grype reported 41 findings against compiled binaries while
// Trivy reported none — because Trivy does not catalogue binaries. Counting
// that silence as disagreement would systematically understate confidence in
// every binary finding, for a reason that has nothing to do with whether the
// finding is real.
type Participation string

const (
	// Reported: the scanner ran and reported this finding.
	Reported Participation = "reported"

	// RanAndMissed: the scanner ran, was capable of detecting this class of
	// finding in this ecosystem, and did not report it. This is genuine
	// disagreement and counts against confidence.
	RanAndMissed Participation = "ran_and_missed"

	// NotCapable: the scanner ran but cannot detect this class of finding in
	// this ecosystem. Its silence carries no information and is excluded from
	// the confidence denominator.
	NotCapable Participation = "not_capable"

	// NoData: the scanner ran and was capable, but has no vulnerability data
	// for this target at all.
	//
	// On alpine:3.14, Trivy reports zero findings while Grype reports 39.
	// Alpine's secdb records vulnerabilities together with the version that
	// fixed them; once a release is past end of life nothing further is added,
	// so a scanner reading it has nothing to report. The image is not clean.
	// This state is what keeps that distinction visible.
	NoData Participation = "no_data"

	// DidNotRun: the scanner failed, timed out, or was not selected. Absence of
	// evidence, not evidence of absence.
	DidNotRun Participation = "did_not_run"
)

// CountsTowardConfidence reports whether a scanner in this state belongs in the
// confidence denominator. Only scanners that had both the opportunity and the
// ability to report do.
func (p Participation) CountsTowardConfidence() bool {
	return p == Reported || p == RanAndMissed
}

// ScannerVerdict is one scanner's position on one consolidated finding.
type ScannerVerdict struct {
	Scanner       string
	Participation Participation

	// Weight is the trust weight applied for this scanner in this ecosystem,
	// as resolved at scoring time. Recorded so a confidence score can be
	// explained after the fact rather than merely asserted.
	Weight float64

	// Finding is what this scanner reported, present only when Participation
	// is Reported. It is kept whole: conflict resolution reads the original
	// values from here, and reports attribute claims to their source.
	Finding *Finding

	// Reason explains a non-Reported state in human terms — "does not catalogue
	// binary packages", "alpine 3.14 secdb has no entries past EOL", "timed out
	// after 60s". Without it a report can say a scanner was silent but not why.
	Reason string
}

// ConflictKind classifies a disagreement between scanners that agree the
// finding exists.
type ConflictKind string

const (
	ConflictSeverity     ConflictKind = "severity"
	ConflictFixState     ConflictKind = "fix_state"
	ConflictFixedVersion ConflictKind = "fixed_version"
	ConflictPackage      ConflictKind = "package"
)

// Conflict is a field-level disagreement, its resolution, and the values that
// were not chosen.
//
// Resolution never discards the alternatives. A confidence score that cannot
// be traced back to the evidence behind it is an assertion, not a measurement,
// and a user who disagrees with the resolution has no way to check it.
type Conflict struct {
	Kind ConflictKind

	// Values maps scanner name to the value it reported, as a string.
	Values map[string]string

	// Resolved is the value chosen, and Reason states why — "distribution
	// tracker outranks NVD for distribution packages", "highest trust weight".
	Resolved string
	Reason   string
}

// CorrelationMethod records how a finding came to be a single finding.
type CorrelationMethod string

const (
	// CorrelatedExact: matched on identifier and canonical PURL. On the
	// baseline images, package names matched exactly on every shared finding,
	// so this is the common case.
	CorrelatedExact CorrelationMethod = "exact"

	// CorrelatedApproximate: matched by package name normalisation and
	// ecosystem agreement above a threshold. Every approximate match is a
	// decision made on the user's behalf, so Score and MatchReason are
	// recorded alongside.
	CorrelatedApproximate CorrelationMethod = "approximate"

	// Uncorrelated: reported by exactly one scanner and matched nothing.
	//
	// These are surfaced as their own category rather than dropped or merged.
	// A high uncorrelated count is itself a signal about data quality for an
	// image or a tool.
	Uncorrelated CorrelationMethod = "uncorrelated"
)

// ConsolidatedFinding is one finding after correlation across scanners: the
// central output of the system.
//
// It is not a list of CVEs but a CVE with context — how confident the system
// is, which scanners agreed, where they disagreed and why, and which of them
// had nothing to say.
type ConsolidatedFinding struct {
	Class FindingClass

	// Vulnerability carries every identifier any scanner used for this finding,
	// merged. PreferredID gives the stable display and lookup key.
	Vulnerability VulnRef

	// Package is the canonical identity of the affected package. Zero for
	// classes that have no package, and for uncorrelated findings whose
	// reporting scanner emitted no PURL.
	Package PURL

	// Verdicts holds one entry per scanner considered for this finding,
	// including those that did not report it. A scanner missing from this
	// slice was never in the run at all.
	Verdicts []ScannerVerdict

	// Confidence is weighted agreement in [0,1], computed over the scanners
	// whose participation counts. See ConfidenceInputs for the derivation.
	Confidence float64

	// Method records how this finding was assembled, with the score and reason
	// when it was approximate.
	Method      CorrelationMethod
	MatchScore  float64
	MatchReason string

	// Resolved values, chosen by conflict resolution where scanners disagreed.
	Severity         Severity
	InstalledVersion string
	FixState         FixState
	FixedVersions    []string

	// Conflicts records every disagreement, its resolution, and the rejected
	// alternatives.
	Conflicts []Conflict

	// Enrichment, populated after correlation. Nil when enrichment did not run
	// or its sources were unreachable — findings are marked unenriched rather
	// than the run being failed.
	Enrichment *Enrichment

	// Origin is where the finding came from in the image, filled in by layer
	// attribution.
	//
	// This is provenance, not a verdict about the layer: a later layer may
	// overwrite or delete a package an earlier one introduced, so "the
	// vulnerable package in the final image came from layer 1" is true where
	// "layer 1 is vulnerable" is not.
	Origin *Origin

	Title       string
	Description string
	References  []string
}

// Enrichment is external context that makes prioritisation possible, since
// severity alone does not distinguish urgent from theoretical.
type Enrichment struct {
	// EPSSScore estimates the probability of exploitation in the near term.
	EPSSScore      float64
	EPSSPercentile float64

	// InKEV reports presence in CISA's catalogue of vulnerabilities confirmed
	// to be exploited in real attacks. Where EPSS predicts, this observes.
	InKEV bool

	// KEVDueDate is the remediation deadline CISA set, when listed.
	KEVDueDate string
}

// Origin is where in the image a finding came from.
type Origin struct {
	LayerDigest string
	LayerIndex  int
	Instruction string // the Dockerfile instruction, when build history has it
}

// ReportedBy returns the scanners that reported this finding.
func (c ConsolidatedFinding) ReportedBy() []string {
	return c.scannersWhere(func(v ScannerVerdict) bool { return v.Participation == Reported })
}

// RanAndMissedBy returns the scanners that ran, could have reported this, and
// did not. These are the scanners that genuinely disagree.
func (c ConsolidatedFinding) RanAndMissedBy() []string {
	return c.scannersWhere(func(v ScannerVerdict) bool { return v.Participation == RanAndMissed })
}

// HadNoDataFor returns the scanners that had no vulnerability data for this
// target. Their silence says nothing about the finding.
func (c ConsolidatedFinding) HadNoDataFor() []string {
	return c.scannersWhere(func(v ScannerVerdict) bool { return v.Participation == NoData })
}

func (c ConsolidatedFinding) scannersWhere(pred func(ScannerVerdict) bool) []string {
	var out []string
	for _, v := range c.Verdicts {
		if pred(v) {
			out = append(out, v.Scanner)
		}
	}
	return out
}

// ConfidenceInputs is the derivation of a confidence score: the weight that
// agreed, the weight that could have agreed, and how many scanners were in
// each state.
//
// Every score the system reports must be explainable from its inputs.
type ConfidenceInputs struct {
	AgreeingWeight      float64
	ParticipatingWeight float64
	AgreeingCount       int
	ParticipatingCount  int
	ExcludedCount       int // not capable, no data, or did not run
}

// ConfidenceInputs computes the derivation of this finding's confidence.
//
// Only scanners whose participation counts appear in the denominator. A
// scanner that could not detect this class of finding, had no data for the
// target, or never ran is excluded rather than counted as dissenting.
func (c ConsolidatedFinding) ConfidenceInputs() ConfidenceInputs {
	var in ConfidenceInputs
	for _, v := range c.Verdicts {
		if !v.Participation.CountsTowardConfidence() {
			in.ExcludedCount++
			continue
		}
		in.ParticipatingWeight += v.Weight
		in.ParticipatingCount++
		if v.Participation == Reported {
			in.AgreeingWeight += v.Weight
			in.AgreeingCount++
		}
	}
	return in
}

// IsSingleSource reports whether exactly one scanner reported this finding.
//
// Not a defect on its own: a scanner with a data source the others lack will
// legitimately be alone. On debian:11, nine of the ten findings unique to
// Trivy used Debian tracker identifiers Grype does not carry.
func (c ConsolidatedFinding) IsSingleSource() bool {
	return len(c.ReportedBy()) == 1
}

// IsDisputed reports whether at least one capable scanner ran and did not
// report this finding.
func (c ConsolidatedFinding) IsDisputed() bool {
	return len(c.RanAndMissedBy()) > 0
}

// HasFix reports whether a fixed version is available.
func (c ConsolidatedFinding) HasFix() bool {
	return c.FixState == FixAvailable && len(c.FixedVersions) > 0
}

// IsActivelyExploited reports whether this vulnerability is in CISA's KEV
// catalogue. Absent enrichment this is false, which is a statement about what
// is known rather than about the vulnerability.
func (c ConsolidatedFinding) IsActivelyExploited() bool {
	return c.Enrichment != nil && c.Enrichment.InKEV
}
