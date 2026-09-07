package normalize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// fixture loads recorded scanner output. Every test in this package runs
// against these rather than against live scanners, which is what makes the
// suite runnable without any scanner installed.
func fixture(t *testing.T, image, file string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", image, file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func normalizeFixture(t *testing.T, image, file, scanner, format string) []model.Finding {
	t.Helper()
	raw := model.RawResult{
		Scanner: scanner,
		Format:  format,
		Payload: fixture(t, image, file),
	}
	findings, err := NewRegistry().Normalize(raw)
	if err != nil {
		t.Fatalf("normalising %s/%s: %v", image, file, err)
	}
	return findings
}

func TestTrivyNormalizeDebian(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "trivy.json", "trivy", "trivy-json")

	if len(findings) == 0 {
		t.Fatal("expected findings from the debian:11 trivy fixture")
	}

	for i, f := range findings {
		if f.Class != model.ClassVulnerability {
			t.Errorf("finding %d: class = %q, want vulnerability", i, f.Class)
		}
		if f.Scanner != "trivy" {
			t.Errorf("finding %d: scanner = %q, want trivy", i, f.Scanner)
		}
		if f.Vulnerability.Primary.ID == "" {
			t.Errorf("finding %d: no identifier", i)
		}
		if f.PackageName == "" {
			t.Errorf("finding %d: no package name", i)
		}
	}
}

// TestTrivyPreservesNonCVEIdentifiers is the TEMP-* case. Nine of the ten
// findings only Trivy reports on debian:11 use Debian tracker identifiers
// rather than CVEs. A model that stored a bare CVE string would drop them.
func TestTrivyPreservesNonCVEIdentifiers(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "trivy.json", "trivy", "trivy-json")

	schemes := map[model.Scheme]int{}
	for _, f := range findings {
		schemes[f.Vulnerability.Primary.Scheme]++
	}

	if schemes[model.SchemeCVE] == 0 {
		t.Error("expected CVE identifiers")
	}
	if schemes[model.SchemeDebian] == 0 {
		t.Error("expected Debian TEMP-* identifiers to survive normalisation")
	}
	t.Logf("identifier schemes: %v", schemes)
}

// TestTrivyCollectsAllSeverities checks that every vendor rating is kept.
// Trivy reports VendorSeverity per source; discarding all but one would make
// conflict resolution impossible later.
func TestTrivyCollectsAllSeverities(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "trivy.json", "trivy", "trivy-json")

	multi := 0
	sources := map[string]bool{}
	for _, f := range findings {
		if len(f.Severities) > 1 {
			multi++
		}
		for _, s := range f.Severities {
			sources[s.Source] = true
		}
	}

	if multi == 0 {
		t.Error("expected at least one finding rated by more than one source")
	}
	if !sources["debian"] {
		t.Error("expected debian to appear as a severity source")
	}
	t.Logf("%d findings with multiple ratings; sources: %v", multi, keys(sources))
}

// TestTrivyFixStateOnEOLDistribution covers the debian:11 case: the
// distribution is past end of life, so almost nothing has a fix. A policy that
// failed a build on any critical finding would block work the team cannot do.
func TestTrivyFixStateOnEOLDistribution(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "trivy.json", "trivy", "trivy-json")

	states := map[model.FixState]int{}
	for _, f := range findings {
		states[f.FixState]++
	}

	if states[model.FixUnavailable] == 0 {
		t.Error("expected findings with no fix available on an EOL distribution")
	}
	t.Logf("fix states: %v", states)
}

func TestGrypeNormalizeDebian(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "grype.json", "grype", "grype-json")

	if len(findings) == 0 {
		t.Fatal("expected findings from the debian:11 grype fixture")
	}

	for i, f := range findings {
		if f.Scanner != "grype" {
			t.Errorf("finding %d: scanner = %q, want grype", i, f.Scanner)
		}
		if f.Vulnerability.Primary.ID == "" {
			t.Errorf("finding %d: no identifier", i)
		}
	}
}

// TestGrypePURLCanonicalisation is the %2B case. Grype percent-encodes '+'
// where Trivy writes it literally; both name the same package, and only
// canonicalisation makes them compare equal.
func TestGrypePURLCanonicalisation(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "grype.json", "grype", "grype-json")

	var found bool
	for _, f := range findings {
		if f.PackageName == "libdb5.3" {
			found = true
			if f.Package.IsZero() {
				t.Fatal("libdb5.3 should have a parsed PURL")
			}
			// The encoded '+' must survive as a literal '+' in the canonical form.
			if want := "5.3.28+dfsg1-0.8"; f.Package.Version != want {
				t.Errorf("version = %q, want %q — %%2B should be decoded",
					f.Package.Version, want)
			}
			// The upstream qualifier is provenance, not identity, and must not
			// appear in the correlation key.
			if contains(f.Package.Canonical(), "upstream") {
				t.Errorf("canonical form should not carry the upstream qualifier: %s",
					f.Package.Canonical())
			}
			break
		}
	}
	if !found {
		t.Skip("libdb5.3 not present in this fixture")
	}
}

// TestGrypeAliasesAreCaptured checks that relatedVulnerabilities survive.
// They are what lets the correlator recognise a finding OSV-Scanner reports
// under a GHSA as the same finding Grype reports under a CVE.
func TestGrypeAliasesAreCaptured(t *testing.T) {
	findings := normalizeFixture(t, "debian_11", "grype.json", "grype", "grype-json")

	withAliases := 0
	for _, f := range findings {
		if len(f.Vulnerability.Aliases) > 0 {
			withAliases++
		}
	}
	if withAliases == 0 {
		t.Error("expected at least one finding carrying aliases")
	}
	t.Logf("%d of %d findings carry aliases", withAliases, len(findings))
}

// TestNormalizersAgreeOnPackageIdentity is the point of the whole exercise:
// where both scanners report the same vulnerability on the same package, their
// canonical PURLs must match, or exact correlation cannot work.
func TestNormalizersAgreeOnPackageIdentity(t *testing.T) {
	trivy := normalizeFixture(t, "debian_11", "trivy.json", "trivy", "trivy-json")
	grype := normalizeFixture(t, "debian_11", "grype.json", "grype", "grype-json")

	// Index Trivy findings by (identifier, canonical package).
	key := func(f model.Finding) string {
		return f.Vulnerability.PreferredID().ID + "|" + f.Package.Canonical()
	}
	trivyKeys := map[string]bool{}
	for _, f := range trivy {
		if f.IsCorrelatable() {
			trivyKeys[key(f)] = true
		}
	}

	matched := 0
	for _, f := range grype {
		if f.IsCorrelatable() && trivyKeys[key(f)] {
			matched++
		}
	}

	if matched == 0 {
		t.Fatal("no findings matched exactly across scanners — canonicalisation is not working")
	}
	t.Logf("%d grype findings match a trivy finding on (identifier, canonical PURL)", matched)
}

func TestUnknownFormatIsRejected(t *testing.T) {
	_, err := NewRegistry().Normalize(model.RawResult{
		Scanner: "mystery",
		Format:  "mystery-json",
		Payload: []byte("{}"),
	})
	if err == nil {
		t.Error("expected an error for an unregistered format")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
