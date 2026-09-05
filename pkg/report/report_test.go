package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() Report {
	rep := Report{
		ToolName:    "container-vuln-scanner",
		ToolVersion: "v0.1.0",
		Target:      "test-image:latest",
		GeneratedAt: time.Now().UTC(),
		Findings: []Finding{
			{
				ID:             "CVE-2023-45853",
				Package:        "zlib",
				Version:        "1.2.11",
				Severity:       "CRITICAL",
				Description:    "MiniZip buffer overflow",
				FixVersion:     "1.2.12",
				InKEV:          true,
				EPSSScore:      0.0015,
				EPSSPercentile: 0.48,
			},
			{
				ID:          "CVE-2024-0001",
				Package:     "openssl",
				Version:     "1.1.1",
				Severity:    "HIGH",
				Description: "SSL handshake flaw",
				InKEV:       false,
				EPSSScore:   0.85,
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
	if parsed.Summary.Total != 2 || parsed.Summary.Critical != 1 || parsed.Summary.InKEV != 1 {
		t.Errorf("unexpected summary values: %+v", parsed.Summary)
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
}
