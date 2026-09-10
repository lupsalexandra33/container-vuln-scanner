package normalize

import (
	"encoding/json"
	"fmt"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// OSVNormalizer converts OSV-Scanner's JSON report into the shared model.
type OSVNormalizer struct{}

func (OSVNormalizer) Format() string { return "osv-json" }

// osvReport mirrors the parts of OSV-Scanner's output we consume.
//
// Its shape differs from the other two in ways that matter. Findings are nested
// three deep — result, package, vulnerability — rather than being a flat list.
// It leads with GHSA identifiers where Grype leads with CVEs, carrying the CVE
// as an alias; that is the case alias resolution in the correlator exists for.
// And it reports severity as a CVSS vector rather than a level, with the level
// available separately in a database-specific field.
type osvReport struct {
	Results []struct {
		Packages []osvPackage `json:"packages"`
	} `json:"results"`
}

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvVulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`

	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			// PURL here identifies the package but carries no version — it
			// describes what is affected in general, not what is installed.
			PURL string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`

	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"` // a CVSS vector, not a number
	} `json:"severity"`

	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`

	DatabaseSpecific struct {
		// Severity here is a level — "MODERATE", "HIGH" — which the top-level
		// Severity field does not provide.
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvEcosystems maps OSV's ecosystem names onto PURL types, which is what
// package identity and per-ecosystem trust weighting are keyed on.
var osvEcosystems = map[string]string{
	"npm":         "npm",
	"pypi":        "pypi",
	"go":          "golang",
	"maven":       "maven",
	"rubygems":    "gem",
	"crates.io":   "cargo",
	"packagist":   "composer",
	"nuget":       "nuget",
	"hex":         "hex",
	"pub":         "pub",
	"debian":      "deb",
	"alpine":      "apk",
	"rocky linux": "rpm",
	"alma linux":  "rpm",
	"red hat":     "rpm",
	"ubuntu":      "deb",
}

func (n OSVNormalizer) Normalize(raw model.RawResult) ([]model.Finding, error) {
	var report osvReport
	if err := json.Unmarshal(raw.Payload, &report); err != nil {
		return nil, fmt.Errorf("parsing osv report: %w", err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			for _, v := range pkg.Vulnerabilities {
				findings = append(findings, n.convert(pkg, v, raw.Scanner))
			}
		}
	}
	return findings, nil
}

func (n OSVNormalizer) convert(pkg osvPackage, v osvVulnerability, scanner string) model.Finding {
	f := model.Finding{
		Class:            model.ClassVulnerability,
		Scanner:          scanner,
		PackageName:      pkg.Package.Name,
		InstalledVersion: pkg.Package.Version,
		Title:            v.Summary,
		Description:      v.Details,
	}

	if id, err := model.ParseVulnID(v.ID); err == nil {
		f.Vulnerability.Primary = id
	}
	// OSV leads with GHSA where Grype leads with the CVE for the same
	// vulnerability. Without these aliases the correlator would see two
	// findings and report agreement as disagreement.
	for _, alias := range v.Aliases {
		if id, err := model.ParseVulnID(alias); err == nil {
			f.Vulnerability.Aliases = append(f.Vulnerability.Aliases, id)
		}
	}

	f.Package = osvPURL(pkg, v)
	f.FixState, f.FixedVersions = osvFixState(v)
	f.Severities = osvSeverities(v)

	for _, ref := range v.References {
		f.References = append(f.References, ref.URL)
	}
	return f
}

// osvPURL builds the package identity.
//
// The PURL in the affected list describes what is vulnerable in general and
// carries no version, so the installed version has to be attached from the
// package entry. Identity without the installed version would collapse every
// version of a package into one finding.
func osvPURL(pkg osvPackage, v osvVulnerability) model.PURL {
	ecosystem := osvEcosystems[lower(pkg.Package.Ecosystem)]
	if ecosystem == "" {
		ecosystem = lower(pkg.Package.Ecosystem)
	}

	var namespace, name string
	for _, a := range v.Affected {
		if a.Package.PURL == "" {
			continue
		}
		if p, err := model.ParsePURL(a.Package.PURL); err == nil {
			namespace, name = p.Namespace, p.Name
			break
		}
	}
	if name == "" {
		name = pkg.Package.Name
	}

	return model.PURL{
		Type:       ecosystem,
		Namespace:  namespace,
		Name:       name,
		Version:    pkg.Package.Version,
		Qualifiers: map[string]string{},
	}
}

// osvFixState derives the fix state from the affected version ranges.
//
// OSV expresses ranges as events: an "introduced" version and, where one
// exists, a "fixed" version. A vulnerability can have several ranges when
// separate release lines were patched independently — the ajv advisory in the
// node:12-alpine fixture has two, fixed in 6.14.0 and 8.18.0.
func osvFixState(v osvVulnerability) (model.FixState, []string) {
	var versions []string
	seen := map[string]bool{}

	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					versions = append(versions, e.Fixed)
				}
			}
		}
	}

	if len(versions) == 0 {
		// No fixed version in any range: the advisory does not name one.
		return model.FixUnavailable, nil
	}
	return model.FixAvailable, versions
}

// osvSeverities extracts the severity rating.
//
// The top-level Severity field holds CVSS vectors rather than levels, so the
// level comes from database_specific. Where neither is present the rating is
// left unknown rather than derived, since inventing an assessment nobody made
// would be worse than reporting that none exists.
func osvSeverities(v osvVulnerability) []model.SeverityRating {
	level := normaliseSeverity(v.DatabaseSpecific.Severity)
	if v.DatabaseSpecific.Severity == "" && len(v.Severity) == 0 {
		return nil
	}

	r := model.SeverityRating{
		Severity: level,
		// OSV aggregates advisories, and for npm and PyPI they come from the
		// GitHub Advisory Database. Attributing them to ghsa rather than to osv
		// keeps conflict resolution able to recognise it as a generic source
		// rather than a distribution one.
		Source:   "ghsa",
		Original: v.DatabaseSpecific.Severity,
	}
	for _, s := range v.Severity {
		if s.Score != "" {
			r.CVSSVector = s.Score
			break
		}
	}
	return []model.SeverityRating{r}
}
