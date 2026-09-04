package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

type GrypeAdapter struct{}

func NewGrypeAdapter() *GrypeAdapter {
	return &GrypeAdapter{}
}

func (g *GrypeAdapter) Name() string {
	return "grype"
}

func (g *GrypeAdapter) Version(ctx context.Context) (model.ToolVersion, error) {
	res, err := scanner.RunTool(ctx, "", "grype", "version", "-o", "json")
	if err != nil {
		return model.ToolVersion{}, fmt.Errorf("failed to execute grype version: %w", err)
	}

	var verOutput struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(res.Stdout, &verOutput); err != nil {
		return model.ToolVersion{}, fmt.Errorf("failed to parse grype version output: %w", err)
	}

	var dbTimestamp time.Time
	dbRes, err := scanner.RunTool(ctx, "", "grype", "db", "status", "-o", "json")
	if err == nil && len(dbRes.Stdout) > 0 {
		var dbOutput struct {
			Built time.Time `json:"built"`
		}
		if json.Unmarshal(dbRes.Stdout, &dbOutput) == nil {
			dbTimestamp = dbOutput.Built
		}
	}

	return model.ToolVersion{
		Version:           verOutput.Version,
		DatabaseTimestamp: dbTimestamp,
	}, nil
}

func (g *GrypeAdapter) Capabilities() model.Capabilities {
	return model.Capabilities{
		FindingClasses:  []string{"vulnerability"},
		TakesSBOM:       true,
		RequiresNetwork: false,
	}
}

func (g *GrypeAdapter) Available(ctx context.Context) error {
	_, err := scanner.RunTool(ctx, "", "grype", "version")
	return err
}

func (g *GrypeAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	// Execute Grype. If target has an SBOMPath, Grype can scan the SBOM directly.
	input := target.ImageReference
	if target.SBOMPath != "" {
		input = "sbom:" + target.SBOMPath
	}

	res, err := scanner.RunTool(ctx, "", "grype", input, "-o", "json", "-q")
	if err != nil {
		return model.RawResult{}, err
	}

	var root struct {
		Matches []struct {
			Vulnerability struct {
				ID       string
				Severity string
			}
			Artifact struct {
				Name    string
				Version string
			}
		}
	}
	if len(res.Stdout) > 0 {
		_ = json.Unmarshal(res.Stdout, &root)
	}

	var findings []model.Finding
	for _, match := range root.Matches {
		findings = append(findings, model.Finding{
			ID:          match.Vulnerability.ID,
			PackageName: match.Artifact.Name,
			Version:     match.Artifact.Version,
			Severity:    match.Vulnerability.Severity,
		})
	}

	return model.RawResult{
		ScannerName: g.Name(),
		RawOutput:   res.Stdout,
		Findings:    findings,
	}, nil
}
