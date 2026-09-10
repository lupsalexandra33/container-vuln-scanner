package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

const fixtureDir = "../../testdata/fixtures"

// TestRunScanOnFixtures runs the whole pipeline over recorded scanner output:
// discovery, normalisation, correlation, conflict resolution and rendering.
// It needs no scanners installed, which is what makes the fixtures worth
// keeping in the repository.
func TestRunScanOnFixtures(t *testing.T) {
	var out, errOut bytes.Buffer

	code := runScan([]string{"--from", fixtureDir + "/debian_11"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}

	got := out.String()
	for _, want := range []string{
		"grype", "trivy", // both participants listed
		"correlated into", // the correlation summary
		"agreement",       // the breakdown footer
		"conflicts",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not mention %q", want)
		}
	}
}

// TestRunScanCorrelatesAcrossScanners checks that the command reduces the raw
// findings rather than concatenating them. Two scanners reporting the same
// vulnerability on the same package must produce one consolidated finding.
func TestRunScanCorrelatesAcrossScanners(t *testing.T) {
	var out, errOut bytes.Buffer

	if code := runScan([]string{"--from", fixtureDir + "/debian_11"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, errOut.String())
	}

	// The header reads "N raw findings correlated into M". If M were not below
	// N, nothing would have merged and correlation would be doing nothing.
	line := firstLineContaining(out.String(), "correlated into")
	if line == "" {
		t.Fatal("no correlation summary in the output")
	}

	raw, consolidated, err := parseCounts(line)
	if err != nil {
		t.Fatalf("cannot read counts from %q: %v", line, err)
	}
	if consolidated >= raw {
		t.Errorf("%d raw findings produced %d consolidated; nothing was merged", raw, consolidated)
	}
	t.Logf("%d raw findings correlated into %d", raw, consolidated)
}

// TestRunScanReportsConflicts checks that resolved conflicts reach the output
// with the reason attached. A resolution the reader cannot check is an
// assertion rather than a measurement.
func TestRunScanReportsConflicts(t *testing.T) {
	var out, errOut bytes.Buffer

	if code := runScan([]string{"--from", fixtureDir + "/debian_11"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, errOut.String())
	}

	got := out.String()
	if !strings.Contains(got, "severity:") {
		t.Error("expected at least one severity conflict to be shown")
	}
	if !strings.Contains(got, "authoritative for deb packages") {
		t.Error("expected the distribution-authority resolution to appear with its reason")
	}
}

// TestRunScanJSON checks the machine-readable path.
func TestRunScanJSON(t *testing.T) {
	var out, errOut bytes.Buffer

	code := runScan([]string{"--from", fixtureDir + "/debian_11", "-out", "json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, errOut.String())
	}

	got := strings.TrimSpace(out.String())
	if !strings.HasPrefix(got, "[") {
		t.Error("expected a JSON array")
	}
	// The fields that distinguish this from a single scanner's output.
	for _, want := range []string{"Verdicts", "Confidence", "Participation"} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON output does not include %q", want)
		}
	}
}

func TestRunScanRequiresFrom(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runScan(nil, &out, &errOut); code != 2 {
		t.Errorf("exit code = %d, want 2 when --from is missing", code)
	}
}

func TestRunScanRejectsMissingDirectory(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runScan([]string{"--from", "/nonexistent-directory"}, &out, &errOut); code != 2 {
		t.Errorf("exit code = %d, want 2 for a directory that does not exist", code)
	}
}

func TestRunScanRejectsUnknownFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runScan([]string{"--from", fixtureDir + "/debian_11", "-out", "yaml"}, &out, &errOut)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 for an unsupported output format", code)
	}
}

// TestDiscoverSourcesIsDeterministic guards the participant ordering. Verdicts
// are recorded per participant in order, so filesystem iteration order must not
// reach the output.
func TestDiscoverSourcesIsDeterministic(t *testing.T) {
	first, err := discoverSources(fixtureDir + "/debian_11")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("expected to discover scanner output")
	}

	for i := 0; i < 10; i++ {
		got, err := discoverSources(fixtureDir + "/debian_11")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(first) {
			t.Fatalf("run %d found %d sources, first found %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].scanner != first[j].scanner {
				t.Fatalf("run %d differs at position %d: %s vs %s",
					i, j, got[j].scanner, first[j].scanner)
			}
		}
	}
}

// TestDiscoverSourcesSkipsUnknownFiles checks that files we have no normalizer
// for — sbom.json, sbom.cdx.json — are not mistaken for scanner output.
func TestDiscoverSourcesSkipsUnknownFiles(t *testing.T) {
	sources, err := discoverSources(fixtureDir + "/debian_11")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sources {
		if _, known := knownFormats[s.scanner]; !known {
			t.Errorf("discovered %q, which has no registered format", s.scanner)
		}
	}
}

// TestCapabilitiesDifferBetweenScanners pins the difference correlation depends
// on: Grype catalogues compiled binaries and Trivy does not, so Trivy's silence
// on such a finding is incapacity rather than disagreement.
//
// The ecosystem is "generic" rather than "binary" because that is what Grype
// emits in the PURL for a binary it identified by version detection.
func TestCapabilitiesDifferBetweenScanners(t *testing.T) {
	trivy := capabilitiesFor("trivy")
	grype := capabilitiesFor("grype")

	if containsString(trivy.Ecosystems, "generic") {
		t.Error("trivy should not declare it catalogues compiled binaries")
	}
	if !containsString(grype.Ecosystems, "generic") {
		t.Error("grype should declare it catalogues compiled binaries")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func firstLineContaining(s, sub string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	return ""
}

// parseCounts reads the two numbers out of "N raw findings correlated into M".
func parseCounts(line string) (raw, consolidated int, err error) {
	_, err = fmt.Sscanf(line, "%d raw findings correlated into %d", &raw, &consolidated)
	return raw, consolidated, err
}
