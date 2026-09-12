package report

import (
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Report is the canonical input payload for all formatters.
type Report struct {
	ToolName    string                      `json:"tool_name"`
	ToolVersion string                      `json:"tool_version"`
	Target      string                      `json:"target"`
	GeneratedAt time.Time                   `json:"generated_at"`
	Summary     Summary                     `json:"summary"`
	Findings    []model.ConsolidatedFinding `json:"findings"`

	// RawFindingCount is how many findings scanners reported before
	// correlation collapsed them into Findings. Zero means unknown (e.g. a
	// Report built without this set) rather than "nothing was correlated" —
	// callers that have the number should always set it, and displays should
	// treat zero as absent, not as a claim that 0 raw findings existed.
	RawFindingCount int `json:"raw_finding_count,omitempty"`
}

// Summary aggregates counts across severity, fixability, scanner consensus, and threat intel.
type Summary struct {
	Total        int `json:"total"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	InKEV        int `json:"in_kev"`
	FixAvailable int `json:"fix_available"`
	Unfixable    int `json:"unfixable"`
	Disputed     int `json:"disputed"`
	SingleSource int `json:"single_source"`
}

// CalculateSummary updates summary counts based on the consolidated findings.
func (r *Report) CalculateSummary() {
	r.Summary = Summary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			r.Summary.Critical++
		case model.SeverityHigh:
			r.Summary.High++
		case model.SeverityMedium:
			r.Summary.Medium++
		case model.SeverityLow, model.SeverityNegligible:
			r.Summary.Low++
		}

		if f.IsActivelyExploited() {
			r.Summary.InKEV++
		}

		if f.HasFix() {
			r.Summary.FixAvailable++
		} else {
			r.Summary.Unfixable++
		}

		if f.IsDisputed() {
			r.Summary.Disputed++
		}
		if f.IsSingleSource() {
			r.Summary.SingleSource++
		}
	}
}
