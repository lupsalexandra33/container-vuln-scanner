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
		Name:        t.Name(),
		Version:     output.Version,
		DBVersion:   fmt.Sprintf("%d", output.VulnerabilityDB.Version),
		DBUpdatedAt: output.VulnerabilityDB.UpdatedAt,
	}, nil
}

func (t *TrivyAdapter) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		Classes:             []model.FindingClass{model.ClassVulnerability},
		Ecosystems:          []string{"deb", "apk", "npm", "pypi", "gem", "cargo"},
		AcceptsSBOM:         true,
		RequiresNetwork:     false,
		RequiresCredentials: false,
	}
}

func (t *TrivyAdapter) Available(ctx context.Context) error {
	_, err := scanner.RunTool(ctx, "", "trivy", "--version")
	return err
}

func (t *TrivyAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	start := time.Now()
	args := []string{"image", "--scanners", "vuln", "--format", "json", "--quiet", target.Reference}

	res, err := scanner.RunTool(ctx, "", "trivy", args...)
	if err != nil {
		return model.RawResult{}, err
	}
	if res.ExitCode != 0 && len(res.Stdout) == 0 {
		return model.RawResult{}, fmt.Errorf("trivy scan failed (exit code %d): %s", res.ExitCode, string(res.Stderr))
	}

	var root struct {
		Metadata struct {
			OS struct {
				EOSL bool `json:"EOSL"`
			} `json:"OS"`
		} `json:"Metadata"`
		Results []struct {
			Vulnerabilities []interface{} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	noData := false
	if len(res.Stdout) > 0 {
		if err := json.Unmarshal(res.Stdout, &root); err == nil {
			if root.Metadata.OS.EOSL {
				hasFindings := false
				for _, r := range root.Results {
					if len(r.Vulnerabilities) > 0 {
						hasFindings = true
						break
					}
				}
				if !hasFindings {
					noData = true
				}
			}
		}
	}

	return model.RawResult{
		Scanner:  t.Name(),
		Target:   target,
		Payload:  res.Stdout,
		Format:   "trivy-json",
		Started:  start,
		Duration: time.Since(start),
		NoData:   noData,
	}, nil
}
