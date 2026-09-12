package sbom

import (
	"context"
	"fmt"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/scanner"
)

// SyftGenerator implements the Generator interface using the syft CLI.
type SyftGenerator struct{}

// NewSyftGenerator returns a new SyftGenerator.
func NewSyftGenerator() *SyftGenerator {
	return &SyftGenerator{}
}

// Name returns the name of the tool.
func (s *SyftGenerator) Name() string {
	return "syft"
}

// Generate invokes the syft CLI to produce a CycloneDX JSON SBOM for the target.
func (s *SyftGenerator) Generate(ctx context.Context, target model.Target) ([]byte, error) {
	// Generate CycloneDX JSON
	// Pin to cyclonedx-json@1.5 because downstream tools like osv-scanner 1.9.2
	// will reject newer CycloneDX 1.6 specifications.
	// Using scanner.RunTool to reuse our execution substrate (handles timeout, ctx cancellation)
	res, err := scanner.RunTool(ctx, "", "syft", "packages", target.Reference, "-o", "cyclonedx-json@1.5", "-q")
	if err != nil {
		return nil, fmt.Errorf("failed to execute syft: %w", err)
	}

	if res.ExitCode != 0 {
		return nil, fmt.Errorf("syft failed with exit code %d: %s", res.ExitCode, string(res.Stderr))
	}

	return res.Stdout, nil
}
