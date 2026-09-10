package trust

import "testing"

func TestForResolvesPerEcosystem(t *testing.T) {
	w := DefaultWeights()

	tests := []struct {
		name      string
		scanner   string
		ecosystem string
		want      float64
	}{
		// Trivy reads the Debian tracker directly and surfaces entries with no
		// CVE assigned, which is why it edges ahead on deb packages.
		{"trivy on deb", "trivy", "deb", 0.90},
		{"grype on deb", "grype", "deb", 0.85},

		// On Alpine neither is weighted above the other: Trivy under-reports
		// past end of life, Grype over-reports by matching upstream ranges it
		// cannot reconcile with backports. Both fail, differently.
		{"trivy on apk", "trivy", "apk", 0.80},
		{"grype on apk", "grype", "apk", 0.80},

		// Language ecosystems: all three read overlapping sources and agree.
		{"trivy on npm", "trivy", "npm", 0.85},
		{"grype on npm", "grype", "npm", 0.85},
		{"osv on npm", "osv", "npm", 0.85},

		// osv.dev covers language ecosystems, not distribution packages — it
		// returned zero findings on debian:11, nginx:1.21 and alpine:3.14.
		{"osv on deb", "osv", "deb", 0.55},

		// Compiled binaries, which Grype emits as pkg:generic.
		{"grype on generic", "grype", "generic", 0.65},

		// No ecosystem-specific entry falls back to the default.
		{"trivy on an uncalibrated ecosystem", "trivy", "hex", 0.85},

		// Case is not significant.
		{"uppercase scanner name", "TRIVY", "DEB", 0.90},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := w.For(tt.scanner, tt.ecosystem); got != tt.want {
				t.Errorf("For(%q, %q) = %v, want %v", tt.scanner, tt.ecosystem, got, tt.want)
			}
		})
	}
}

// TestUnknownScannerIsNeutral checks the fallback. A tool we have no opinion
// about must be counted normally, not silently ignored: zero would remove it
// from the confidence denominator entirely, which is a far stronger claim than
// "we have not calibrated this one".
func TestUnknownScannerIsNeutral(t *testing.T) {
	w := DefaultWeights()

	if got := w.For("some-new-scanner", "deb"); got != 1.0 {
		t.Errorf("For(unknown, deb) = %v, want 1.0", got)
	}
	if got := w.For("some-new-scanner", "unheard-of-ecosystem"); got != 1.0 {
		t.Errorf("For(unknown, unknown) = %v, want 1.0", got)
	}
}

// TestEcosystemWeightsDifferForTheSameScanner is the point of the whole file:
// one scanner, four ecosystems, several different weights.
func TestEcosystemWeightsDifferForTheSameScanner(t *testing.T) {
	w := DefaultWeights()

	seen := map[float64]bool{}
	for _, ecosystem := range []string{"deb", "apk", "npm", "generic"} {
		seen[w.For("grype", ecosystem)] = true
	}
	if len(seen) < 3 {
		t.Errorf("grype has only %d distinct weights across four ecosystems; "+
			"per-ecosystem weighting is not doing anything", len(seen))
	}
}

func TestReasonForIsMostSpecificFirst(t *testing.T) {
	w := DefaultWeights()

	specific := w.ReasonFor("trivy", "apk")
	general := w.ReasonFor("trivy", "hex") // no apk-specific entry applies here

	if specific == general {
		t.Error("an ecosystem-specific rationale should differ from the scanner default")
	}
	if specific == "" || general == "" {
		t.Error("every weight in the default table should carry a reason")
	}
}

// TestEveryDefaultWeightHasAReason guards the property the explanation output
// depends on. A weight the reader cannot see the reasoning for is a guess
// presented as a measurement.
func TestEveryDefaultWeightHasAReason(t *testing.T) {
	w := DefaultWeights()

	for scanner := range w.Default {
		r := w.ReasonFor(scanner, "")
		if r == "" || r == "no calibration recorded; treated as neutral" {
			t.Errorf("scanner %q has a default weight but no rationale", scanner)
		}
	}
}

func TestUnknownScannerReasonSaysSo(t *testing.T) {
	w := DefaultWeights()
	if got := w.ReasonFor("some-new-scanner", "deb"); got == "" {
		t.Error("an uncalibrated scanner should still report why it is treated as neutral")
	}
}
