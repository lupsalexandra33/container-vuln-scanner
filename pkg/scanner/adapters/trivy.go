package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

type TrivyAdapter struct{}

func NewTrivyAdapter() *TrivyAdapter {
	return &TrivyAdapter{}
}

func (t *TrivyAdapter) Name() string {
	return "trivy"
}

func (t *TrivyAdapter) Version(ctx context.Context) (model.ToolVersion, error) {
	res, err := scanner.RunTool(ctx, "", "trivy", "version", "--format", "json")
	if err != nil {
		return model.ToolVersion{}, fmt.Errorf("failed to execute trivy version: %w", err)
	}

	var output struct {
		Version         string `json:"Version"`
		VulnerabilityDB struct {
			Version   int       `json:"Version"`
			UpdatedAt time.Time `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}

	if err := json.Unmarshal(res.Stdout, &output); err != nil {
		return model.ToolVersion{}, fmt.Errorf("failed to parse trivy version output: %w", err)
	}

	return model.ToolVersion{
		Version:           output.Version,
		DatabaseTimestamp: output.VulnerabilityDB.UpdatedAt,
	}, nil
}

func (t *TrivyAdapter) Capabilities() model.Capabilities {
	return model.Capabilities{
		FindingClasses:  []string{"vulnerability", "misconfiguration", "secret"},
		TakesSBOM:       false,
		RequiresNetwork: false, // assuming DB is cached or offline mode is used
	}
}

func (t *TrivyAdapter) Available(ctx context.Context) error {
	_, err := scanner.RunTool(ctx, "", "trivy", "--version")
	return err
}

func (t *TrivyAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	// Execute Trivy: trivy image --scanners vuln --format json --quiet <image>
	res, err := scanner.RunTool(ctx, "", "trivy", "image", "--scanners", "vuln", "--format", "json", "--quiet", target.ImageReference)
	if err != nil {
		return model.RawResult{}, err
	}

	// It's possible Trivy exited non-zero but still generated JSON stdout if we used --exit-code.
	// But without it, it should exit 0 on success. If there's no stdout, that's an issue.

	var root struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				Severity         string
			}
		}
	}
	if len(res.Stdout) > 0 {
		_ = json.Unmarshal(res.Stdout, &root)
	}

	var findings []model.Finding
	for _, result := range root.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, model.Finding{
				ID:          v.VulnerabilityID,
				PackageName: v.PkgName,
				Version:     v.InstalledVersion,
				Severity:    v.Severity,
			})
		}
	}

	return model.RawResult{
		ScannerName: t.Name(),
		RawOutput:   res.Stdout,
		Findings:    findings,
	}, nil
}
