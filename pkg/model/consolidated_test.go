package model

import (
	"math"
	"testing"
)

func TestParticipationCountsTowardConfidence(t *testing.T) {
	counts := map[Participation]bool{
		Reported:     true,
		RanAndMissed: true,

		// A scanner that could not detect this class of finding, had no data
		// for the target, or never ran had no opportunity to agree. Counting
		// its silence as dissent would penalise a finding for a reason that
		// has nothing to do with whether it is real.
		NotCapable: false,
		NoData:     false,
		DidNotRun:  false,
	}

	for p, want := range counts {
		if got := p.CountsTowardConfidence(); got != want {
			t.Errorf("%q.CountsTowardConfidence() = %v, want %v", p, got, want)
		}
	}
}

func TestConfidenceInputsExcludesIncapableScanners(t *testing.T) {
	// The node:12-alpine case. Grype catalogues compiled binaries; Trivy does
	// not. If Trivy's silence counted as disagreement, every binary finding
	// would score 0.5 despite there being no evidence against it.
	c := ConsolidatedFinding{
		Class: ClassVulnerability,
		Verdicts: []ScannerVerdict{
			{Scanner: "grype", Participation: Reported, Weight: 1.0},
			{Scanner: "trivy", Participation: NotCapable, Weight: 1.0,
				Reason: "does not catalogue binary packages"},
		},
	}

	in := c.ConfidenceInputs()

	if in.ParticipatingCount != 1 {
		t.Errorf("participating = %d, want 1 — trivy could not have reported this",
			in.ParticipatingCount)
	}
	if in.ExcludedCount != 1 {
		t.Errorf("excluded = %d, want 1", in.ExcludedCount)
	}
	if in.AgreeingWeight != in.ParticipatingWeight {
		t.Errorf("agreeing weight %v should equal participating weight %v: "+
			"the only scanner that could report did report",
			in.AgreeingWeight, in.ParticipatingWeight)
	}
}

func TestConfidenceInputsCountsGenuineDisagreement(t *testing.T) {
	// CVE-2023-45853 on zlib1g: reported by Trivy, missed by Grype, which ran
	// and was perfectly capable of reporting it. This is real disagreement and
	// must lower confidence.
	c := ConsolidatedFinding{
		Class: ClassVulnerability,
		Verdicts: []ScannerVerdict{
			{Scanner: "trivy", Participation: Reported, Weight: 1.0},
			{Scanner: "grype", Participation: RanAndMissed, Weight: 1.0},
		},
	}

	in := c.ConfidenceInputs()

	if in.ParticipatingCount != 2 {
		t.Errorf("participating = %d, want 2", in.ParticipatingCount)
	}
	if in.AgreeingWeight >= in.ParticipatingWeight {
		t.Errorf("agreeing weight %v should be below participating weight %v "+
			"when a capable scanner disagreed", in.AgreeingWeight, in.ParticipatingWeight)
	}
	if !c.IsDisputed() {
		t.Error("a finding a capable scanner missed should be disputed")
	}
}

func TestConfidenceInputsWithNoDataScanner(t *testing.T) {
	// The alpine:3.14 case. Trivy reports nothing because Alpine's secdb has no
	// entries past end of life, not because it examined the package and
	// disagreed. Its silence carries no information either way.
	c := ConsolidatedFinding{
		Class: ClassVulnerability,
		Verdicts: []ScannerVerdict{
			{Scanner: "grype", Participation: Reported, Weight: 1.0},
			{Scanner: "trivy", Participation: NoData, Weight: 1.0,
				Reason: "alpine 3.14 secdb has no entries past end of life"},
		},
	}

	in := c.ConfidenceInputs()

	if in.ParticipatingCount != 1 {
		t.Errorf("participating = %d, want 1", in.ParticipatingCount)
	}
	if c.IsDisputed() {
		t.Error("a scanner with no data has not disputed anything")
	}
	if got := c.HadNoDataFor(); len(got) != 1 || got[0] != "trivy" {
		t.Errorf("HadNoDataFor() = %v, want [trivy]", got)
	}
}

func TestConfidenceInputsWeighting(t *testing.T) {
	// Weights are per ecosystem: on node:12-alpine the two tools agreed almost
	// exactly on npm (45 against 44) but diverged fourfold on apk. A single
	// weight per scanner cannot express that.
	c := ConsolidatedFinding{
		Verdicts: []ScannerVerdict{
			{Scanner: "trivy", Participation: Reported, Weight: 0.9},
			{Scanner: "grype", Participation: Reported, Weight: 0.7},
			{Scanner: "osv", Participation: RanAndMissed, Weight: 0.4},
		},
	}

	in := c.ConfidenceInputs()

	if math.Abs(in.AgreeingWeight-1.6) > 1e-9 {
		t.Errorf("agreeing weight = %v, want 1.6", in.AgreeingWeight)
	}
	if math.Abs(in.ParticipatingWeight-2.0) > 1e-9 {
		t.Errorf("participating weight = %v, want 2.0", in.ParticipatingWeight)
	}
}

func TestVerdictAccessors(t *testing.T) {
	c := ConsolidatedFinding{
		Verdicts: []ScannerVerdict{
			{Scanner: "trivy", Participation: Reported},
			{Scanner: "grype", Participation: Reported},
			{Scanner: "osv", Participation: RanAndMissed},
			{Scanner: "clair", Participation: NoData},
			{Scanner: "scout", Participation: DidNotRun, Reason: "no credentials"},
		},
	}

	if got := c.ReportedBy(); len(got) != 2 {
		t.Errorf("ReportedBy() = %v, want two scanners", got)
	}
	if got := c.RanAndMissedBy(); len(got) != 1 || got[0] != "osv" {
		t.Errorf("RanAndMissedBy() = %v, want [osv]", got)
	}
	if c.IsSingleSource() {
		t.Error("two scanners reported this; it is not single-source")
	}
}

func TestIsSingleSource(t *testing.T) {
	// Being alone is not a defect. On debian:11, nine of the ten findings only
	// Trivy reported used Debian tracker identifiers Grype does not carry —
	// single-source, and correct.
	temp, _ := ParseVulnID("TEMP-0841856-B18BAF")
	c := ConsolidatedFinding{
		Vulnerability: VulnRef{Primary: temp},
		Verdicts: []ScannerVerdict{
			{Scanner: "trivy", Participation: Reported, Weight: 1.0},
			{Scanner: "grype", Participation: NotCapable, Weight: 1.0,
				Reason: "does not carry Debian tracker identifiers"},
		},
	}

	if !c.IsSingleSource() {
		t.Error("expected a single-source finding")
	}
	if c.IsDisputed() {
		t.Error("an incapable scanner has not disputed anything")
	}
}

func TestEnrichmentIsOptional(t *testing.T) {
	// Enrichment is a pointer so that "the sources were unreachable" is
	// distinguishable from "the score is zero". The pipeline marks findings
	// unenriched rather than failing the run.
	unenriched := ConsolidatedFinding{}
	if unenriched.IsActivelyExploited() {
		t.Error("an unenriched finding must not claim active exploitation")
	}

	enriched := ConsolidatedFinding{
		Enrichment: &Enrichment{InKEV: true, EPSSScore: 0.94},
	}
	if !enriched.IsActivelyExploited() {
		t.Error("a finding in the KEV catalogue should report as actively exploited")
	}

	known := ConsolidatedFinding{
		Enrichment: &Enrichment{InKEV: false, EPSSScore: 0.0004},
	}
	if known.IsActivelyExploited() {
		t.Error("a finding known not to be in KEV should not report as exploited")
	}
}

func TestConsolidatedHasFix(t *testing.T) {
	available := ConsolidatedFinding{
		FixState:      FixAvailable,
		FixedVersions: []string{"1.1.1t-0+deb11u1"},
	}
	if !available.HasFix() {
		t.Error("expected a fix to be available")
	}

	// Grype reported 211 matches on debian:11, none with a fix. A policy that
	// fails on any critical finding blocks work that cannot be done.
	none := ConsolidatedFinding{FixState: FixUnavailable}
	if none.HasFix() {
		t.Error("expected no fix to be available")
	}
}
