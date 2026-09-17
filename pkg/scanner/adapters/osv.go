package adapters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

type OSVAdapter struct{}

func NewOSVAdapter() *OSVAdapter {
	return &OSVAdapter{}
}

func (o *OSVAdapter) Name() string {
	return "osv-scanner"
}

func (o *OSVAdapter) Version(ctx context.Context) (model.ToolVersion, error) {
	res, err := scanner.RunTool(ctx, "", "osv-scanner", "--version")
	if err != nil {
		return model.ToolVersion{}, fmt.Errorf("failed to execute osv-scanner version: %w", err)
	}

	// Output format: "osv-scanner version: 2.5.1\n..."
	lines := strings.Split(string(res.Stdout), "\n")
	version := "unknown"
	if len(lines) > 0 {
		parts := strings.SplitN(lines[0], ":", 2)
		if len(parts) == 2 {
			version = strings.TrimSpace(parts[1])
		}
	}

	return model.ToolVersion{
		Name:    o.Name(),
		Version: version,
		// osv-scanner fetches updates natively at runtime; we don't have a local DB timestamp.
	}, nil
}

func (o *OSVAdapter) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		Classes:             []model.FindingClass{model.ClassVulnerability},
		Ecosystems:          []string{"npm", "pypi", "gem", "cargo", "go"}, // OSV is mostly language ecosystems
		AcceptsSBOM:         true,                                          // OSV can scan SBOMs, but we'll use scan image
		RequiresNetwork:     true,                                          // Connects to OSV API
		RequiresCredentials: false,
	}
}

func (o *OSVAdapter) Available(ctx context.Context) error {
	_, err := scanner.RunTool(ctx, "", "osv-scanner", "--version")
	return err
}

func (o *OSVAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	start := time.Now()

	args := []string{"scan", "image", "--format", "json", target.Reference}

	res, err := scanner.RunTool(ctx, "", "osv-scanner", args...)
	if err != nil {
		// OSV scanner returns non-zero exit codes if vulnerabilities are found.
		// It only truly "fails" if stdout is empty or we can't parse JSON later.
		if len(res.Stdout) == 0 {
			return model.RawResult{}, fmt.Errorf("osv-scanner scan failed (exit code %d): %s", res.ExitCode, string(res.Stderr))
		}
	}

	return model.RawResult{
		Scanner:  o.Name(),
		Target:   target,
		Payload:  res.Stdout,
		Format:   "osv-json",
		Started:  start,
		Duration: time.Since(start),
	}, nil
}
