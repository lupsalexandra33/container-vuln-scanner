package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

func sampleReport() Report {
	rep := Report{
		ToolName:    "container-vuln-scanner",
		ToolVersion: "v0.1.0",
		Target:      "debian:11",
		GeneratedAt: time.Now().UTC(),
		Findings: []model.ConsolidatedFinding{
			{
				Vulnerability: model.VulnRef{
					Primary: model.VulnID{ID: "CVE-2023-45853"},
				},
				Package: model.PURL{
					Type:    "deb",
					Name:    "zlib",
					Version: "1.2.11",
				},
				InstalledVersion: "1.2.11",
				Severity:         model.SeverityCritical,
				Description:      "MiniZip buffer overflow",
				FixState:         model.FixAvailable,
				FixedVersions:    []string{"1.2.12"},
				Confidence:       1.0,
				Enrichment: &model.Enrichment{
					InKEV:          true,
					EPSSScore:      0.0015,
					EPSSPercentile: 0.48,
					KEVDueDate:     "2023-11-22",
				},
				Verdicts: []model.ScannerVerdict{
					{Scanner: "trivy", Participation: model.Reported, Weight: 1.0},
					{Scanner: "grype", Participation: model.Reported, Weight: 1.0},
				},
			},
			{
				Vulnerability: model.VulnRef{
					Primary: model.VulnID{ID: "CVE-2024-0001"},
				},
				Package: model.PURL{
					Type:    "deb",
					Name:    "openssl",
					Version: "1.1.1",
				},
				InstalledVersion: "1.1.1",
				Severity:         model.SeverityHigh,
				Description:      "SSL handshake vulnerability",
				FixState:         model.FixWontFix,
				Confidence:       0.5,
				Enrichment:       nil,
				Verdicts: []model.ScannerVerdict{
					{Scanner: "trivy", Participation: model.Reported, Weight: 1.0},
					{Scanner: "grype", Participation: model.RanAndMissed, Weight: 1.0, Reason: "differing version check"},
				},
			},
		},
	}
	rep.CalculateSummary()
	return rep
}

func TestExportJSON(t *testing.T) {
	rep := sampleReport()
	var buf bytes.Buffer
	if err := ExportJSON(&buf, rep); err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshaling generated JSON: %v", err)
	}
	if parsed.Summary.Total != 2 || parsed.Summary.Critical != 1 || parsed.Summary.FixAvailable != 1 {
		t.Errorf("unexpected summary values: %+v", parsed.Summary)
	}
	if parsed.Summary.Disputed != 1 {
		t.Errorf("expected 1 disputed finding, got %d", parsed.Summary.Disputed)
	}
}

func TestExportSARIF(t *testing.T) {
	rep := sampleReport()
	var buf bytes.Buffer
	if err := ExportSARIF(&buf, rep); err != nil {
		t.Fatalf("ExportSARIF failed: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshaling generated SARIF: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("expected 1 run with 2 results, got: %+v", doc.Runs)
	}
	if !strings.Contains(doc.Runs[0].Results[0].Message.Text, "CISA KEV") {
		t.Errorf("expected KEV indicator in message")
	}
}

func TestExportHTML(t *testing.T) {
	rep := sampleReport()
	var buf bytes.Buffer
	if err := ExportHTML(&buf, rep); err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	htmlStr := buf.String()
	if !strings.Contains(htmlStr, "CVE-2023-45853") {
		t.Errorf("expected report to contain CVE-2023-45853")
	}
	if !strings.Contains(htmlStr, "ACTIVE EXPLOIT") {
		t.Errorf("expected KEV tag in HTML table")
	}
	if !strings.Contains(htmlStr, "wont_fix") && !strings.Contains(htmlStr, "Fixed in") {
		t.Errorf("expected FixState representations in HTML")
	}
	if !strings.Contains(htmlStr, "Disputed") {
		t.Errorf("expected Disputed badge in HTML")
	}
}
