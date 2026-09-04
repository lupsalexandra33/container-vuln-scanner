package scanner

import (
	"context"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Capabilities declares what a scanner can detect.
//
// This is not documentation: correlation reads it. On node:12-alpine, Grype
// reported 41 findings against compiled binaries and Trivy none, because Trivy
// does not catalogue binaries. Without a declared capability, that silence
// would be counted as disagreement and every binary finding would be scored as
// low-confidence for a reason unrelated to whether it is real.
type Capabilities struct {
	// Classes are the finding classes this scanner produces.
	Classes []model.FindingClass

	// Ecosystems are the package types it catalogues: "deb", "apk", "npm",
	// "pypi", "golang", "binary". Empty means all.
	Ecosystems []string

	// AcceptsSBOM reports whether it can scan an SBOM instead of an image.
	AcceptsSBOM bool

	// RequiresNetwork and RequiresCredentials describe what it needs to run.
	// A scanner requiring credentials must be optional: the project has to be
	// usable without them.
	RequiresNetwork     bool
	RequiresCredentials bool
}

// Detects reports whether this scanner can detect a class of finding in an
// ecosystem. The correlator uses it to decide whether a scanner's silence is
// disagreement or incapacity.
func (c Capabilities) Detects(class model.FindingClass, ecosystem string) bool {
	found := false
	for _, cl := range c.Classes {
		if cl == class {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if len(c.Ecosystems) == 0 || ecosystem == "" {
		return true
	}
	for _, e := range c.Ecosystems {
		if e == ecosystem {
			return true
		}
	}
	return false
}

// Scanner is the contract every integrated tool satisfies, whether it is a
// local binary, a hosted service, or an in-process library.
//
// Adding a scanner should mean adding one file under adapters/ and nothing
// else. If an integration requires changing this interface or special-casing
// a tool name elsewhere, the abstraction is wrong.
type Scanner interface {
	// Name is the stable identifier used in verdicts, trust weights and
	// reports. It must not change between runs.
	Name() string

	// Version reports the tool and the vulnerability data it will use. Recorded
	// in the session so results are reproducible.
	Version(ctx context.Context) (model.ToolVersion, error)

	// Capabilities declares what this scanner can detect.
	Capabilities() Capabilities

	// Available reports whether the scanner can run now — binary present,
	// service reachable, credentials valid. A scanner that is unavailable is
	// skipped, not failed.
	Available(ctx context.Context) error

	// Scan runs against the target and returns unmodified output.
	//
	// Implementations must distinguish three outcomes, which is the most common
	// source of silently wrong results: the tool ran and found nothing, the
	// tool ran and found something, and the tool failed to run. Many scanners
	// exit non-zero when findings exist; that is not a failure.
	//
	// A tool that ran but had no data for the target sets RawResult.NoData
	// rather than returning an empty result, because zero findings is not the
	// same as a clean image.
	Scan(ctx context.Context, target model.Target) (model.RawResult, error)
}

// Normalizer converts one scanner's raw output into the shared model.
//
// Separate from Scanner so that normalisation can be re-run against stored raw
// results without re-scanning — which is what makes the fixtures usable as a
// development substitute for live tools.
type Normalizer interface {
	Format() string
	Normalize(raw model.RawResult) ([]model.Finding, error)
}
