package trust

import (
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Calibration over the recorded fixtures runs from the calibrate command rather
// than from here: pkg/trust cannot import pkg/correlate, because correlate
// imports trust. The tests below cover the metric arithmetic; the end-to-end
// measurement lives in cmd/vulnscan/calibrate.go.

func metricFor(c Calibration, scanner string) (ScannerMetrics, bool) {
	for _, m := range c.Overall {
		if m.Scanner == scanner {
			return m, true
		}
	}
	return ScannerMetrics{}, false
}

// verdict builds a consolidated finding with the given participations.
func verdict(participations map[string]model.Participation, ecosystem string) model.ConsolidatedFinding {
	purl, _ := model.ParsePURL("pkg:" + ecosystem + "/debian/openssl@1.1.1n")
	f := model.ConsolidatedFinding{Class: model.ClassVulnerability, Package: purl}
	for scanner, p := range participations {
		f.Verdicts = append(f.Verdicts, model.ScannerVerdict{Scanner: scanner, Participation: p})
	}
	return f
}

func TestMeasureCountsAgreement(t *testing.T) {
	findings := []model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"trivy": model.Reported,
			"grype": model.Reported,
		}, "deb"),
		verdict(map[string]model.Participation{
			"trivy": model.Reported,
			"grype": model.Reported,
		}, "deb"),
	}

	c := Measure(findings)

	trivy, ok := metricFor(c, "trivy")
	if !ok {
		t.Fatal("expected metrics for trivy")
	}
	if trivy.Reported != 2 || trivy.Agreed != 2 {
		t.Errorf("reported = %d, agreed = %d; want 2 and 2", trivy.Reported, trivy.Agreed)
	}
	if trivy.Coverage() != 1.0 || trivy.Precision() != 1.0 {
		t.Errorf("coverage = %v, precision = %v; want 1.0 and 1.0",
			trivy.Coverage(), trivy.Precision())
	}
}

// TestIncapableScannerIsExcluded is the reason this measurement is not a naive
// count. A scanner blind to an ecosystem must not be penalised for silence
// there, or every binary finding drags Trivy's coverage down for a reason
// unrelated to how well it does its job.
func TestIncapableScannerIsExcluded(t *testing.T) {
	findings := []model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"grype": model.Reported,
			"trivy": model.NotCapable,
		}, "generic"),
	}

	c := Measure(findings)

	trivy, _ := metricFor(c, "trivy")
	if trivy.Missed != 0 {
		t.Errorf("missed = %d, want 0 — trivy could not have reported this", trivy.Missed)
	}
	if trivy.Excluded != 1 {
		t.Errorf("excluded = %d, want 1", trivy.Excluded)
	}
	if trivy.Coverage() != 0 {
		t.Errorf("coverage = %v; with no opportunities there is nothing to measure",
			trivy.Coverage())
	}
}

// TestNoDataIsExcluded is the alpine:3.14 case. Trivy reports nothing because
// Alpine's secdb has no entries past end of life, not because it looked and
// disagreed.
func TestNoDataIsExcluded(t *testing.T) {
	findings := []model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"grype": model.Reported,
			"trivy": model.NoData,
		}, "apk"),
	}

	c := Measure(findings)
	trivy, _ := metricFor(c, "trivy")

	if trivy.Missed != 0 {
		t.Errorf("missed = %d, want 0 — a scanner with no data has not missed anything", trivy.Missed)
	}
	if trivy.Excluded != 1 {
		t.Errorf("excluded = %d, want 1", trivy.Excluded)
	}
}

// TestUniqueFindingsAreCountedSeparately covers what consensus-based precision
// gets wrong. On debian:11, nine of the ten findings only Trivy reports use
// Debian tracker identifiers Grype does not carry. They are real, and this
// measurement counts them against Trivy's precision — so they are tracked
// separately, where a reader can see them.
func TestUniqueFindingsAreCountedSeparately(t *testing.T) {
	findings := []model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"trivy": model.Reported,
			"grype": model.RanAndMissed,
		}, "deb"),
	}

	c := Measure(findings)

	trivy, _ := metricFor(c, "trivy")
	if trivy.Unique != 1 {
		t.Errorf("unique = %d, want 1", trivy.Unique)
	}
	if trivy.Precision() != 0 {
		t.Errorf("precision = %v, want 0 — nothing corroborated it, which is what "+
			"the metric measures and why it needs the caveat", trivy.Precision())
	}

	grype, _ := metricFor(c, "grype")
	if grype.Missed != 1 {
		t.Errorf("grype missed = %d, want 1 — it ran, was capable, and did not report",
			grype.Missed)
	}
}

func TestSuggestedWeightIsCompressed(t *testing.T) {
	// A perfect score must not suggest complete trust, and a zero score must not
	// suggest removing a scanner. Consensus without ground truth cannot support
	// either claim.
	perfect := ScannerMetrics{Reported: 10, Agreed: 10, Missed: 0}
	if w := SuggestedWeight(perfect); w > 0.95 {
		t.Errorf("suggested weight = %v; a perfect consensus score should not imply certainty", w)
	}

	poor := ScannerMetrics{Reported: 10, Agreed: 0, Missed: 10}
	if w := SuggestedWeight(poor); w < 0.5 {
		t.Errorf("suggested weight = %v; a poor consensus score should not remove a "+
			"scanner from consideration", w)
	}

	none := ScannerMetrics{}
	if w := SuggestedWeight(none); w != 0 {
		t.Errorf("suggested weight = %v, want 0 with no evidence either way", w)
	}
}

func TestPerEcosystemBreakdown(t *testing.T) {
	// The same scanner can look very different on two ecosystems in one image,
	// which is the whole reason weights are scoped that way.
	findings := []model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"trivy": model.Reported,
			"grype": model.Reported,
		}, "deb"),
		verdict(map[string]model.Participation{
			"grype": model.Reported,
			"trivy": model.NotCapable,
		}, "generic"),
	}

	c := Measure(findings)

	if len(c.ByEcosystem["deb"]) == 0 {
		t.Error("expected a deb breakdown")
	}
	if len(c.ByEcosystem["generic"]) == 0 {
		t.Error("expected a generic breakdown")
	}

	for _, m := range c.ByEcosystem["generic"] {
		if m.Scanner == "trivy" && m.Excluded != 1 {
			t.Errorf("trivy excluded on generic = %d, want 1", m.Excluded)
		}
	}
}

func TestReportMentionsTheCaveat(t *testing.T) {
	// The limitation bounds what the numbers can be used for, so it travels
	// with them rather than living in a document nobody opens.
	c := Measure([]model.ConsolidatedFinding{
		verdict(map[string]model.Participation{
			"trivy": model.Reported,
			"grype": model.Reported,
		}, "deb"),
	})

	out := c.Report(DefaultWeights())
	if !contains(out, "consensus") || !contains(out, "ground truth") {
		t.Errorf("the report must state what it is measured against:\n%s", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
