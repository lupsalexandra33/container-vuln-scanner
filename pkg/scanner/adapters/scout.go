package adapters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

// ScoutAdapter implements the Scanner interface for Docker Scout.
// It integrates a commercial tool backed by a proprietary database.
type ScoutAdapter struct {
	baseDelay time.Duration
}

// NewScoutAdapter returns a new adapter for Docker Scout.
func NewScoutAdapter() *ScoutAdapter {
	return &ScoutAdapter{
		baseDelay: 2 * time.Second,
	}
}

// Name returns the identifier for this scanner.
func (s *ScoutAdapter) Name() string {
	return "scout"
}

// Version queries the Docker Scout CLI for its version.
func (s *ScoutAdapter) Version(ctx context.Context) (model.ToolVersion, error) {
	res, err := scanner.RunTool(ctx, "", "docker", "scout", "version")
	if err != nil {
		return model.ToolVersion{}, err
	}
	return model.ToolVersion{
		Name:    "scout",
		Version: strings.TrimSpace(string(res.Stdout)),
	}, nil
}

// Capabilities declares that Docker Scout detects vulnerabilities and requires network access.
func (s *ScoutAdapter) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		Classes:         []model.FindingClass{model.ClassVulnerability},
		RequiresNetwork: true, // Needs network to reach Docker Hub / Scout DB
	}
}

// Available checks if the docker scout plugin is installed and accessible.
func (s *ScoutAdapter) Available(ctx context.Context) error {
	res, err := scanner.RunTool(ctx, "", "docker", "scout", "version")
	if err != nil || res.ExitCode != 0 {
		return fmt.Errorf("docker scout plugin not available: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Scan runs the Docker Scout CLI against the target, implementing rate-limit backoff.
func (s *ScoutAdapter) Scan(ctx context.Context, target model.Target) (model.RawResult, error) {
	maxRetries := 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Execute Docker Scout for CVEs with JSON output.
		// Note: Authentication relies on the host's Docker credentials. By shelling out via
		// RunTool, we keep secrets entirely out of logs and our code.
		res, err := scanner.RunTool(ctx, "", "docker", "scout", "cves", "--format", "json", target.Reference)
		if err != nil {
			return model.RawResult{}, err
		}

		if res.ExitCode == 0 {
			return model.RawResult{
				Payload: res.Stdout,
				Format:  "scout-json",
			}, nil
		}

		stderrStr := strings.ToLower(string(res.Stderr))

		// Handle Operational Constraints: Detect rate limits / quota exhaustion
		if strings.Contains(stderrStr, "too many requests") ||
			strings.Contains(stderrStr, "rate limit") ||
			strings.Contains(stderrStr, "quota") {

			if attempt < maxRetries-1 {
				delay := s.baseDelay * time.Duration(1<<attempt) // Exponential backoff: 2s, 4s, ...
				select {
				case <-time.After(delay):
					continue
				case <-ctx.Done():
					return model.RawResult{}, ctx.Err()
				}
			}
		}

		// For authentication errors or other failures, return them cleanly
		// so the orchestrator isolates the failure without crashing the whole run.
		return model.RawResult{}, fmt.Errorf("docker scout failed (exit %d): %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	return model.RawResult{}, fmt.Errorf("docker scout failed after %d attempts due to rate limiting or quota exhaustion", maxRetries)
}
