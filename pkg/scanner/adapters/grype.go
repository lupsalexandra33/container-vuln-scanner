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
		Name:        g.Name(),
		Version:     verOutput.Version,
		DBUpdatedAt: dbTimestamp,
	}, nil
}

func (g *GrypeAdapter) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		Classes:             []model.FindingClass{model.ClassVulnerability},
		Ecosystems:          []string{"deb", "apk", "npm", "pypi", "gem", "cargo", "binary"},
		AcceptsSBOM:         true,
		RequiresNetwork:     false,
		RequiresCredentials: false,
	}
}

func (g *GrypeAdapter) Available(ctx context.Context) error {
	_, err := scanner.RunTool(ctx, "", "grype", "version")
	return err
}

func (g *GrypeAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	start := time.Now()

	input := target.Reference
	if target.SBOMPath != "" {
		input = "sbom:" + target.SBOMPath
	}

	res, err := scanner.RunTool(ctx, "", "grype", input, "-o", "json", "-q")
	if err != nil {
		return model.RawResult{}, err
	}
	if res.ExitCode != 0 && len(res.Stdout) == 0 {
		return model.RawResult{}, fmt.Errorf("grype scan failed (exit code %d): %s", res.ExitCode, string(res.Stderr))
	}

	return model.RawResult{
		Scanner:  g.Name(),
		Target:   target,
		Payload:  res.Stdout,
		Format:   "grype-json",
		Started:  start,
		Duration: time.Since(start),
	}, nil
}
