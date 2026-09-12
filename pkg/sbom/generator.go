package sbom

import (
	"context"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Generator is the interface for tools that can generate an SBOM from a target.
type Generator interface {
	// Name returns the name of the SBOM generator (e.g. "syft").
	Name() string

	// Generate generates the SBOM bytes (typically CycloneDX JSON) for the target.
	Generate(ctx context.Context, target model.Target) ([]byte, error)
}
