package correlate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

// vulnScanner is the capability set of a scanner that handles package
// vulnerabilities across the usual ecosystems but does not catalogue compiled
// binaries — Trivy's shape.
var vulnScanner = scanner.Capabilities{
	Classes:    []model.FindingClass{model.ClassVulnerability},
	Ecosystems: []string{"deb", "apk", "npm", "pypi", "gem", "cargo"},
}

// binaryAware adds binaries — Grype's shape.
var binaryAware = scanner.Capabilities{
	Classes:    []model.FindingClass{model.ClassVulnerability},
	Ecosystems: []string{"deb", "apk", "npm", "pypi", "gem", "cargo", "binary"},
}

func loadFindings(t *testing.T, image, file, scannerName, format string) []model.Finding {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", image, file)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	findings, err := normalize.NewRegistry().Normalize(model.RawResult{
		Scanner: scannerName,
		Format:  format,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("normalising %s/%s: %v", image, file, err)
	}
	return findings
}

func vuln(t *testing.T, scannerName, id, purl string) model.Finding {
	t.Helper()
	vid, err := model.ParseVulnID(id)
	if err != nil {
		t.Fatalf("parsing %q: %v", id, err)
	}
	p, err := model.ParsePURL(purl)
	if err != nil {
		t.Fatalf("parsing %q: %v", purl, err)
	}
	return model.Finding{
		Class:         model.ClassVulnerability,
		Scanner:       scannerName,
		Vulnerability: model.VulnRef{Primary: vid},
		Package:       p,
		PackageName:   p.Name,
	}
}

func TestCorrelateGroupsAgreement(t *testing.T) {
	const purl = "pkg:deb/debian/zlib1g@1.2.11.dfsg-2?arch=amd64&distro=debian-11"

	out := Correlate(
		[]model.Finding{
			vuln(t, "trivy", "CVE-2023-45853", purl),
			vuln(t, "grype", "CVE-2023-45853", purl),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true},
			{Name: "grype", Capabilities: binaryAware, Ran: true},
		},
	)

	if len(out) != 1 {
		t.Fatalf("got %d consolidated findings, want 1 — both scanners reported the same thing", len(out))
	}
	c := out[0]
	if got := c.ReportedBy(); len(got) != 2 {
		t.Errorf("ReportedBy() = %v, want both scanners", got)
	}
	if c.Confidence != 1 {
		t.Errorf("confidence = %v, want 1 when every capable scanner agrees", c.Confidence)
	}
	if c.Method != model.CorrelatedExact {
		t.Errorf("method = %q, want exact", c.Method)
	}
}

// TestCorrelateResolvesAliases is the case grouping on the primary identifier
// alone would get wrong: three scanners report one vulnerability, two of them
// leading with different schemes.
func TestCorrelateResolvesAliases(t *testing.T) {
	const purl = "pkg:npm/lodash@4.17.20"

	cve, _ := model.ParseVulnID("CVE-2021-23337")
	ghsa, _ := model.ParseVulnID("GHSA-35jh-r3h4-6jhm")

	trivy := vuln(t, "trivy", "CVE-2021-23337", purl)

	grype := vuln(t, "grype", "CVE-2021-23337", purl)
	grype.Vulnerability.Aliases = []model.VulnID{ghsa}

	// OSV-Scanner leads with the GHSA and carries the CVE as an alias.
	osv := vuln(t, "osv", "GHSA-35jh-r3h4-6jhm", purl)
	osv.Vulnerability.Aliases = []model.VulnID{cve}

	out := Correlate(
		[]model.Finding{trivy, grype, osv},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true},
			{Name: "grype", Capabilities: binaryAware, Ran: true},
			{Name: "osv", Capabilities: vulnScanner, Ran: true},
		},
	)

	if len(out) != 1 {
		t.Fatalf("got %d consolidated findings, want 1 — the GHSA and the CVE are the same vulnerability", len(out))
	}
	c := out[0]
	if !c.Vulnerability.Primary.IsCVE() {
		t.Errorf("primary identifier = %v, want the CVE — external sources key on it",
			c.Vulnerability.Primary)
	}
	if len(c.ReportedBy()) != 3 {
		t.Errorf("ReportedBy() = %v, want all three scanners", c.ReportedBy())
	}
}

// TestIncapableScannerIsNotDisagreement is the node:12-alpine case. Grype
// catalogues compiled binaries; Trivy does not. Counting Trivy's silence as
// dissent would score every binary finding at 0.5 with no evidence against it.
func TestIncapableScannerIsNotDisagreement(t *testing.T) {
	out := Correlate(
		[]model.Finding{
			vuln(t, "grype", "CVE-2023-1234", "pkg:binary/node@12.22.12"),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true},
			{Name: "grype", Capabilities: binaryAware, Ran: true},
		},
	)

	c := out[0]
	if c.IsDisputed() {
		t.Error("a scanner that cannot catalogue binaries has not disputed anything")
	}
	if c.Confidence != 1 {
		t.Errorf("confidence = %v, want 1 — no capable scanner contradicted this", c.Confidence)
	}

	in := c.ConfidenceInputs()
	if in.ParticipatingCount != 1 || in.ExcludedCount != 1 {
		t.Errorf("participating = %d, excluded = %d; want 1 and 1",
			in.ParticipatingCount, in.ExcludedCount)
	}
}

// TestNoDataScannerIsNotDisagreement is the alpine:3.14 case: Trivy reports
// nothing because Alpine's secdb has no entries past end of life, not because
// it examined the package and disagreed.
func TestNoDataScannerIsNotDisagreement(t *testing.T) {
	out := Correlate(
		[]model.Finding{
			vuln(t, "grype", "CVE-2022-37434", "pkg:apk/alpine/zlib@1.2.11-r3"),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true, NoData: true},
			{Name: "grype", Capabilities: binaryAware, Ran: true},
		},
	)

	c := out[0]
	if c.IsDisputed() {
		t.Error("a scanner with no data for the target has not disputed anything")
	}
	if got := c.HadNoDataFor(); len(got) != 1 || got[0] != "trivy" {
		t.Errorf("HadNoDataFor() = %v, want [trivy]", got)
	}
	if c.Confidence != 1 {
		t.Errorf("confidence = %v, want 1", c.Confidence)
	}
}

// TestGenuineDisagreementLowersConfidence covers CVE-2023-45853 on zlib1g:
// reported by Trivy, missed by Grype, which ran and was perfectly capable.
func TestGenuineDisagreementLowersConfidence(t *testing.T) {
	out := Correlate(
		[]model.Finding{
			vuln(t, "trivy", "CVE-2023-45853", "pkg:deb/debian/zlib1g@1.2.11.dfsg-2?arch=amd64"),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true},
			{Name: "grype", Capabilities: binaryAware, Ran: true},
		},
	)

	c := out[0]
	if !c.IsDisputed() {
		t.Fatal("a capable scanner that ran and did not report this has disagreed")
	}
	if c.Confidence != 0.5 {
		t.Errorf("confidence = %v, want 0.5 with one of two capable scanners reporting", c.Confidence)
	}
	if !c.IsSingleSource() {
		t.Error("expected a single-source finding")
	}
}

func TestScannerThatDidNotRunIsExcluded(t *testing.T) {
	out := Correlate(
		[]model.Finding{
			vuln(t, "trivy", "CVE-2023-45853", "pkg:deb/debian/zlib1g@1.2.11.dfsg-2"),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true},
			{Name: "clair", Capabilities: vulnScanner, Ran: false},
		},
	)

	c := out[0]
	if c.IsDisputed() {
		t.Error("a scanner that never ran has said nothing")
	}
	if c.ConfidenceInputs().ParticipatingCount != 1 {
		t.Errorf("participating = %d, want 1", c.ConfidenceInputs().ParticipatingCount)
	}
}

func TestWeightedConfidence(t *testing.T) {
	// Per-ecosystem weighting is [2.3]; this checks the arithmetic the weights
	// will feed into.
	out := Correlate(
		[]model.Finding{
			vuln(t, "trivy", "CVE-2023-45853", "pkg:deb/debian/zlib1g@1.2.11.dfsg-2"),
		},
		[]Participant{
			{Name: "trivy", Capabilities: vulnScanner, Ran: true, Weight: 0.9},
			{Name: "grype", Capabilities: binaryAware, Ran: true, Weight: 0.3},
		},
	)

	// 0.9 agreeing out of 1.2 participating.
	if got := out[0].Confidence; got < 0.749 || got > 0.751 {
		t.Errorf("confidence = %v, want 0.75", got)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	// Correlation produces a key, and a key that changes between runs is not a
	// key. Go randomises map iteration, which is what the ordering in
	// aliasGraph.union and the insertion-ordered group list defend against.
	findings := []model.Finding{
		vuln(t, "trivy", "CVE-2023-0001", "pkg:deb/debian/a@1.0"),
		vuln(t, "grype", "CVE-2023-0002", "pkg:deb/debian/b@2.0"),
		vuln(t, "trivy", "CVE-2023-0003", "pkg:deb/debian/c@3.0"),
		vuln(t, "grype", "CVE-2023-0001", "pkg:deb/debian/a@1.0"),
	}
	participants := []Participant{
		{Name: "trivy", Capabilities: vulnScanner, Ran: true},
		{Name: "grype", Capabilities: binaryAware, Ran: true},
	}

	first := Correlate(findings, participants)
	for i := 0; i < 20; i++ {
		got := Correlate(findings, participants)
		if len(got) != len(first) {
			t.Fatalf("run %d produced %d findings, first produced %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Vulnerability.Primary.ID != first[j].Vulnerability.Primary.ID {
				t.Fatalf("run %d differs at position %d: %s vs %s",
					i, j, got[j].Vulnerability.Primary.ID, first[j].Vulnerability.Primary.ID)
			}
		}
	}
}

// TestCorrelateRealFixtures runs the correlator over the recorded Trivy and
// Grype output for debian:11 and reports what comes out.
func TestCorrelateRealFixtures(t *testing.T) {
	trivy := loadFindings(t, "debian_11", "trivy.json", "trivy", "trivy-json")
	grype := loadFindings(t, "debian_11", "grype.json", "grype", "grype-json")

	all := append(append([]model.Finding{}, trivy...), grype...)
	out := Correlate(all, []Participant{
		{Name: "trivy", Capabilities: vulnScanner, Ran: true},
		{Name: "grype", Capabilities: binaryAware, Ran: true},
	})

	if len(out) == 0 {
		t.Fatal("expected consolidated findings")
	}

	var agreed, disputed, single int
	for _, c := range out {
		switch {
		case len(c.ReportedBy()) > 1:
			agreed++
		case c.IsDisputed():
			disputed++
		default:
			single++
		}
	}

	t.Logf("%d trivy + %d grype findings -> %d consolidated", len(trivy), len(grype), len(out))
	t.Logf("both scanners: %d | disputed: %d | single source without dispute: %d",
		agreed, disputed, single)

	if agreed == 0 {
		t.Error("expected findings both scanners reported — correlation is not matching anything")
	}
	if len(out) >= len(all) {
		t.Errorf("consolidated %d findings from %d inputs — nothing was merged", len(out), len(all))
	}
}
