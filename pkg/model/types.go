package model

import "time"

// Target represents the input to a scan.
type Target struct {
	ImageReference string
	SBOMPath       string // Populated if the scanner takes an SBOM instead of an image
}

// ToolVersion records the version of the scanner and its database for session reproducibility.
type ToolVersion struct {
	Version           string
	DatabaseTimestamp time.Time
}

// Capabilities declares what finding classes a scanner produces and its constraints.
type Capabilities struct {
	FindingClasses  []string // e.g., "vulnerability", "misconfiguration", "secret"
	TakesSBOM       bool
	RequiresNetwork bool
}

// Finding is the normalised per-tool representation.
type Finding struct {
	ID          string
	PackageName string
	Version     string
	Severity    string
}

// RawResult holds the unmodified tool output plus execution metadata and the preliminary findings.
type RawResult struct {
	ScannerName string
	RawOutput   []byte    // The raw JSON emitted by the tool
	Findings    []Finding // The findings mapped from the raw output by the adapter
}
