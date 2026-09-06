package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ExportJSON writes a formatted JSON report to the provided writer.
func ExportJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ExportSARIF converts the report into SARIF 2.1.0 format and writes it.
func ExportSARIF(w io.Writer, rep Report) error {
	sarifLog := buildSARIF(rep)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog)
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
	InformationURI string      `json:"informationUri,omitempty"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	ShortDescription sarifMultiformatText `json:"shortDescription"`
	FullDescription  sarifMultiformatText `json:"fullDescription,omitempty"`
	HelpURI          string               `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string               `json:"ruleId"`
	Level     string               `json:"level"`
	Message   sarifMultiformatText `json:"message"`
	Locations []sarifLocation      `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifMultiformatText struct {
	Text string `json:"text"`
}

func buildSARIF(rep Report) sarifDocument {
	rulesMap := make(map[string]sarifRule)
	var rules []sarifRule
	var results []sarifResult

	for _, f := range rep.Findings {
		id := f.Vulnerability.PreferredID().ID
		if id == "" {
			id = f.Vulnerability.Primary.ID
		}

		pkgName := f.Package.Name
		if pkgName == "" {
			pkgName = f.Package.Canonical()
		}

		if _, exists := rulesMap[id]; !exists {
			rule := sarifRule{
				ID: id,
				ShortDescription: sarifMultiformatText{
					Text: fmt.Sprintf("%s in %s %s", id, pkgName, f.InstalledVersion),
				},
				FullDescription: sarifMultiformatText{
					Text: f.Description,
				},
				HelpURI: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id),
			}
			rulesMap[id] = rule
			rules = append(rules, rule)
		}

		level := "warning"
		switch strings.ToLower(string(f.Severity)) {
		case "critical", "high":
			level = "error"
		case "low", "negligible":
			level = "note"
		}

		inputs := f.ConfidenceInputs()
		reporters := strings.Join(f.ReportedBy(), ", ")
		msg := fmt.Sprintf("%s (%s) detected in package %s@%s by [%s] (confidence: %.2f, %d/%d scanners agreed). FixState: %s.",
			id, f.Severity, pkgName, f.InstalledVersion, reporters, f.Confidence, inputs.AgreeingCount, inputs.ParticipatingCount, f.FixState)

		if f.IsActivelyExploited() {
			msg += " [ALERT: Known Exploited Vulnerability in CISA KEV"
			if f.Enrichment.KEVDueDate != "" {
				msg += fmt.Sprintf(", due: %s", f.Enrichment.KEVDueDate)
			}
			msg += "]"
		}

		if f.Enrichment != nil && f.Enrichment.EPSSScore > 0 {
			msg += fmt.Sprintf(" [EPSS: %.2f%%]", f.Enrichment.EPSSScore*100)
		}

		results = append(results, sarifResult{
			RuleID:  id,
			Level:   level,
			Message: sarifMultiformatText{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: rep.Target,
						},
					},
				},
			},
		})
	}

	return sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    rep.ToolName,
						Version: rep.ToolVersion,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}
}
