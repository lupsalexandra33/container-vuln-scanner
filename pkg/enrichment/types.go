package enrichment

import "time"

// ThreatData wraps the threat intel we pull for a specific vulnerability.
type ThreatData struct {
	CVE        string     `json:"cve"`
	InKEV      bool       `json:"in_kev"`
	KEVDetails *KEVRecord `json:"kev_details,omitempty"`
	EPSSScore  float64    `json:"epss_score"`
	Percentile float64    `json:"epss_percentile"`
	EnrichedAt time.Time  `json:"enriched_at"`
}

// KEVRecord holds the actionable metadata from CISA's catalog.
type KEVRecord struct {
	VulnerabilityName string `json:"vulnerability_name"`
	DateAdded         string `json:"date_added"`
	DueDate           string `json:"due_date"`
	RequiredAction    string `json:"required_action"`
}

// CisaCatalog matches the top-level payload from CISA's raw JSON feed.
type CisaCatalog struct {
	CatalogVersion  string              `json:"catalogVersion"`
	Count           int                 `json:"count"`
	Vulnerabilities []CisaVulnerability `json:"vulnerabilities"`
}

type CisaVulnerability struct {
	CveID             string `json:"cveID"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
	RequiredAction    string `json:"requiredAction"`
}

// EPSSResponse matches the response payload from api.first.org/data/v1/epss.
type EPSSResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

