package normalize

import (
	"encoding/json"
	"fmt"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

type ScoutNormalizer struct{}

func (n ScoutNormalizer) Format() string {
	return "scout-sarif"
}

func (n ScoutNormalizer) Normalize(raw model.RawResult) ([]model.Finding, error) {
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(raw.Payload, &doc); err != nil {
		return nil, fmt.Errorf("decoding scout sarif: %w", err)
	}

	var findings []model.Finding
	for _, run := range doc.Runs {
		for _, res := range run.Results {
			severity := model.SeverityUnknown
			switch res.Level {
			case "error":
				severity = model.SeverityHigh
			case "warning":
				severity = model.SeverityMedium
			case "note":
				severity = model.SeverityLow
			}

			vid, err := model.ParseVulnID(res.RuleID)
			if err != nil {
				// Fallback if the scheme isn't recognized
				vid = model.VulnID{Scheme: model.SchemeUnknown, ID: res.RuleID}
			}

			findings = append(findings, model.Finding{
				Class:   model.ClassVulnerability,
				Scanner: "scout",
				Vulnerability: model.VulnRef{
					Primary: vid,
				},
				Severities: []model.SeverityRating{
					{
						Severity: severity,
						Source:   "scout",
						Original: res.Level,
					},
				},
			})
		}
	}

	return findings, nil
}
