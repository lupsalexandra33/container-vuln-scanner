package normalize

import (
	"fmt"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Normalizer converts one scanner's raw output into the shared model.
//
// It is separate from the Scanner interface so that normalisation can be
// re-run against stored raw results without re-scanning. That is what makes
// the fixtures in testdata/fixtures usable as a development substitute for
// live tools, and what allows correlation to be re-derived from historical
// sessions after the logic changes.
type Normalizer interface {
	// Format is the identifier a scanner sets on RawResult.Format, e.g.
	// "trivy-json".
	Format() string

	// Normalize converts raw output into findings.
	//
	// A finding whose identifier or PURL cannot be parsed is still returned,
	// with whatever could be recovered. Dropping it would lose a real finding
	// because of a parsing gap on our side; what it loses is the ability to be
	// correlated exactly, which IsCorrelatable then reports.
	Normalize(raw model.RawResult) ([]model.Finding, error)
}

// Registry maps output formats to the normalizer that handles them.
type Registry struct {
	byFormat map[string]Normalizer
}

// NewRegistry returns a registry with every built-in normalizer registered.
func NewRegistry() *Registry {
	r := &Registry{byFormat: map[string]Normalizer{}}
	r.Register(TrivyNormalizer{})
	r.Register(GrypeNormalizer{})
	return r
}

// Register adds a normalizer, replacing any already registered for its format.
func (r *Registry) Register(n Normalizer) {
	r.byFormat[n.Format()] = n
}

// Normalize converts a raw result using the normalizer for its format.
func (r *Registry) Normalize(raw model.RawResult) ([]model.Finding, error) {
	n, ok := r.byFormat[raw.Format]
	if !ok {
		return nil, fmt.Errorf("no normalizer registered for format %q (scanner %q)",
			raw.Format, raw.Scanner)
	}
	return n.Normalize(raw)
}

// normaliseSeverity maps a scanner's severity vocabulary onto the shared scale.
//
// Scanners write the same level differently — "Critical", "CRITICAL",
// "critical" — and Grype adds "negligible" where Trivy does not. An
// unrecognised value becomes SeverityUnknown rather than being guessed at,
// since guessing would silently invent an assessment nobody made.
func normaliseSeverity(s string) model.Severity {
	switch lower(s) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium", "moderate":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "negligible":
		return model.SeverityNegligible
	default:
		return model.SeverityUnknown
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
