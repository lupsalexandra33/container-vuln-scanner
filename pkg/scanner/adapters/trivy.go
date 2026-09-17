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
		Classes:             []model.FindingClass{model.ClassVulnerability, model.ClassMisconfiguration, model.ClassSecret},
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

	if target.SBOMPath != "" {
		// Hybrid Scan
		res1, err := scanner.RunTool(ctx, "", "trivy", "sbom", "--scanners", "vuln", "--format", "json", "--quiet", target.SBOMPath)
		if err != nil {
			return model.RawResult{}, err
		}

		res2, err := scanner.RunTool(ctx, "", "trivy", "image", "--scanners", "misconfig,secret", "--image-config-scanners", "misconfig,secret", "--format", "json", "--quiet", target.Reference)
		if err != nil {
			return model.RawResult{}, err
		}

		mergedPayload, err := mergeTrivyJSON(res1.Stdout, res2.Stdout)
		if err != nil {
			return model.RawResult{}, err
		}

		return model.RawResult{
			Scanner:  t.Name(),
			Target:   target,
			Payload:  mergedPayload,
			Format:   "trivy-json",
			Started:  start,
			Duration: time.Since(start),
			NoData:   checkNoData(mergedPayload),
		}, nil
	}

	args := []string{"image", "--scanners", "vuln,misconfig,secret", "--image-config-scanners", "misconfig,secret", "--format", "json", "--quiet", target.Reference}
	res, err := scanner.RunTool(ctx, "", "trivy", args...)
	if err != nil {
		return model.RawResult{}, err
	}
	if res.ExitCode != 0 && len(res.Stdout) == 0 {
		return model.RawResult{}, fmt.Errorf("trivy scan failed (exit code %d): %s", res.ExitCode, string(res.Stderr))
	}

	return model.RawResult{
		Scanner:  t.Name(),
		Target:   target,
		Payload:  res.Stdout,
		Format:   "trivy-json",
		Started:  start,
		Duration: time.Since(start),
		NoData:   checkNoData(res.Stdout),
	}, nil
}

func checkNoData(payload []byte) bool {
	if len(payload) == 0 {
		return false
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
	if err := json.Unmarshal(payload, &root); err == nil {
		if root.Metadata.OS.EOSL {
			hasFindings := false
			for _, r := range root.Results {
				if len(r.Vulnerabilities) > 0 {
					hasFindings = true
					break
				}
			}
			return !hasFindings
		}
	}
	return false
}

func mergeTrivyJSON(vulnJSON, miscJSON []byte) ([]byte, error) {
	if len(vulnJSON) == 0 {
		return miscJSON, nil
	}
	if len(miscJSON) == 0 {
		return vulnJSON, nil
	}

	var report1, report2 map[string]interface{}
	if err := json.Unmarshal(vulnJSON, &report1); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(miscJSON, &report2); err != nil {
		return nil, err
	}

	results1, ok1 := report1["Results"].([]interface{})
	results2, ok2 := report2["Results"].([]interface{})
	if ok1 && ok2 {
		report1["Results"] = append(results1, results2...)
	} else if ok2 {
		report1["Results"] = results2
	}

	return json.Marshal(report1)
}
