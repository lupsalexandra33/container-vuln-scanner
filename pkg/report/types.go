package report

import "time"

// Report is the canonical input payload for all formatters.
type Report struct {
	ToolName    string    `json:"tool_name"`
	ToolVersion string    `json:"tool_version"`
	Target      string    `json:"target"` // e.g. "nginx:1.21" or file path
	GeneratedAt time.Time `json:"generated_at"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
}

// Summary aggregates counts by severity and threat intel status.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	InKEV    int `json:"in_kev"`
}

// Finding represents a single normalized vulnerability instance with enrichment.
type Finding struct {
	ID          string `json:"id"`       // e.g. "CVE-2023-45853"
	Package     string `json:"package"`  // e.g. "zlib"
	Version     string `json:"version"`  // e.g. "1.2.11"
	Severity    string `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Title       string `json:"title"`
	Description string `json:"description"`
	FixVersion  string `json:"fix_version,omitempty"`

	// Enrichment data
	InKEV          bool    `json:"in_kev"`
	EPSSScore      float64 `json:"epss_score"`
	EPSSPercentile float64 `json:"epss_percentile"`
}

// CalculateSummary updates summary counts based on findings list.
func (r *Report) CalculateSummary() {
	r.Summary = Summary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case "CRITICAL":
			r.Summary.Critical++
		case "HIGH":
			r.Summary.High++
		case "MEDIUM":
			r.Summary.Medium++
		case "LOW":
			r.Summary.Low++
		}
		if f.InKEV {
			r.Summary.InKEV++
		}
	}
}
