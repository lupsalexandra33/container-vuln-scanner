package report

import (
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// SingleScannerReport wraps one scanner's raw, uncorrelated findings as a
// Report so `normalize`/`view`/`tui` can render through the same TUI and web
// dashboard as `scan --out tui|web`.
//
// This is not correlation — it is a single scanner's own findings with no
// second opinion to check them against. Each finding gets exactly one
// ScannerVerdict (itself, Reported) and a confidence of 1.0: full agreement
// with the only participant there is. That is an honest number here, not an
// inflated one — it says "this one scanner fully stands behind what it
// reported," not "multiple tools agree." Conflicts is always empty, and
// RawFindingCount is left at zero, so callers see no consolidation strip:
// there is nothing to show a raw-to-consolidated ratio for.
func SingleScannerReport(findings []model.Finding, scannerName, target string) Report {
	consolidated := make([]model.ConsolidatedFinding, 0, len(findings))
	for _, f := range findings {
		f := f // capture a distinct copy per iteration before taking its address

		consolidated = append(consolidated, model.ConsolidatedFinding{
			Class:         f.Class,
			Vulnerability: f.Vulnerability,
			Package:       f.Package,
			Verdicts: []model.ScannerVerdict{
				{
					Scanner:       scannerName,
					Participation: model.Reported,
					Weight:        1.0,
					Finding:       &f,
				},
			},
			Confidence:       1.0,
			Method:           model.Uncorrelated,
			Severity:         f.PrimarySeverity(),
			InstalledVersion: f.InstalledVersion,
			FixState:         f.FixState,
			FixedVersions:    f.FixedVersions,
			Title:            f.Title,
			Description:      f.Description,
			References:       f.References,
		})
	}

	rep := Report{
		ToolName:    "vulnscan",
		Target:      target,
		GeneratedAt: time.Now(),
		Findings:    consolidated,
	}
	rep.CalculateSummary()
	return rep
}
