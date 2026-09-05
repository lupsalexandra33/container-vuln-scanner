package report

import (
	"encoding/json"
	"fmt"
	"io"
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

// Internal SARIF 2.1.0 schema models
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
		if _, exists := rulesMap[f.ID]; !exists {
			rule := sarifRule{
				ID: f.ID,
				ShortDescription: sarifMultiformatText{
					Text: fmt.Sprintf("%s in %s %s", f.ID, f.Package, f.Version),
				},
				FullDescription: sarifMultiformatText{
					Text: f.Description,
				},
				HelpURI: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", f.ID),
			}
			rulesMap[f.ID] = rule
			rules = append(rules, rule)
		}

		// Map severity to SARIF level
		level := "warning"
		switch f.Severity {
		case "CRITICAL", "HIGH":
			level = "error"
		case "LOW":
			level = "note"
		}

		msg := fmt.Sprintf("%s (%s) detected in package %s@%s.", f.ID, f.Severity, f.Package, f.Version)
		if f.InKEV {
			msg += " [ALERT: Known Exploited Vulnerability in CISA KEV]"
		}
		if f.EPSSScore > 0 {
			msg += fmt.Sprintf(" [EPSS: %.2f%%]", f.EPSSScore*100)
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
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
