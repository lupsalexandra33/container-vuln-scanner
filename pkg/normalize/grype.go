package normalize

import (
	"encoding/json"
	"fmt"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// GrypeNormalizer converts Grype's JSON report into the shared model.
type GrypeNormalizer struct{}

func (GrypeNormalizer) Format() string { return "grype-json" }

// grypeReport mirrors the parts of Grype's output we consume.
//
// Grype's shape differs from Trivy's in three ways that matter here: findings
// are a flat list of matches rather than grouped by target, severity is a
// string rather than a vendor-keyed integer map, and aliases are exposed
// directly as relatedVulnerabilities.
type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`

	// RelatedVulnerabilities are the other identifiers this vulnerability is
	// known by. This is where a CVE surfaces when Grype leads with a GHSA, and
	// it is what lets the correlator recognise a finding OSV-Scanner reports
	// under a different scheme as the same finding.
	RelatedVulnerabilities []grypeVulnerability `json:"relatedVulnerabilities"`

	Artifact grypeArtifact `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
	Description string   `json:"description"`

	Fix struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`

	CVSS []struct {
		Version string `json:"version"`
		Vector  string `json:"vector"`
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
		Source string `json:"source"`
	} `json:"cvss"`
}

type grypeArtifact struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	PURL      string `json:"purl"`
	Locations []struct {
		Path    string `json:"path"`
		LayerID string `json:"layerID"`
	} `json:"locations"`
}

func (n GrypeNormalizer) Normalize(raw model.RawResult) ([]model.Finding, error) {
	var report grypeReport
	if err := json.Unmarshal(raw.Payload, &report); err != nil {
		return nil, fmt.Errorf("parsing grype report: %w", err)
	}

	findings := make([]model.Finding, 0, len(report.Matches))
	for _, m := range report.Matches {
		findings = append(findings, n.convert(m, raw.Scanner))
	}
	return findings, nil
}

func (n GrypeNormalizer) convert(m grypeMatch, scanner string) model.Finding {
	v := m.Vulnerability

	f := model.Finding{
		Class:            model.ClassVulnerability,
		Scanner:          scanner,
		PackageName:      m.Artifact.Name,
		InstalledVersion: m.Artifact.Version,
		Description:      v.Description,
		References:       v.URLs,
	}

	if id, err := model.ParseVulnID(v.ID); err == nil {
		f.Vulnerability.Primary = id
	}
	for _, rel := range m.RelatedVulnerabilities {
		if id, err := model.ParseVulnID(rel.ID); err == nil {
			f.Vulnerability.Aliases = append(f.Vulnerability.Aliases, id)
		}
	}

	if m.Artifact.PURL != "" {
		if p, err := model.ParsePURL(m.Artifact.PURL); err == nil {
			f.Package = p
		}
	}

	if len(m.Artifact.Locations) > 0 {
		f.Location = m.Artifact.Locations[0].LayerID
	}

	f.FixState, f.FixedVersions = grypeFixState(v.Fix.State, v.Fix.Versions)
	f.Severities = n.severities(v, m.RelatedVulnerabilities)
	return f
}

// severities collects Grype's rating and any it carries from related
// identifiers.
//
// Grype reports one severity per vulnerability rather than Trivy's
// vendor-keyed map, so its provenance comes from the namespace the record was
// matched in — "debian:distro:debian:11" or "nvd:cpe". That distinction is
// what conflict resolution needs to prefer the distribution's assessment for a
// distribution package.
func (n GrypeNormalizer) severities(v grypeVulnerability, related []grypeVulnerability) []model.SeverityRating {
	var out []model.SeverityRating

	if v.Severity != "" {
		out = append(out, model.SeverityRating{
			Severity:   normaliseSeverity(v.Severity),
			Source:     grypeSource(v),
			Original:   v.Severity,
			CVSSScore:  bestCVSSScore(v),
			CVSSVector: bestCVSSVector(v),
		})
	}

	// A related record often carries NVD's rating where the primary carries the
	// distribution's, which is exactly the disagreement worth preserving.
	for _, r := range related {
		if r.Severity == "" {
			continue
		}
		src := grypeSource(r)
		if hasSource(out, src) {
			continue
		}
		out = append(out, model.SeverityRating{
			Severity:   normaliseSeverity(r.Severity),
			Source:     src,
			Original:   r.Severity,
			CVSSScore:  bestCVSSScore(r),
			CVSSVector: bestCVSSVector(r),
		})
	}
	return out
}

// grypeSource derives a source name from the namespace a record was matched
// in. Namespaces look like "debian:distro:debian:11" or "nvd:cpe"; the leading
// segment is the source.
func grypeSource(v grypeVulnerability) string {
	if v.Namespace == "" {
		return "grype"
	}
	for i := 0; i < len(v.Namespace); i++ {
		if v.Namespace[i] == ':' {
			return v.Namespace[:i]
		}
	}
	return v.Namespace
}

// bestCVSSScore prefers CVSS v3 over v2: they use different scales, and mixing
// them makes scores incomparable.
func bestCVSSScore(v grypeVulnerability) float64 {
	var v2 float64
	for _, c := range v.CVSS {
		if len(c.Version) > 0 && c.Version[0] == '3' {
			return c.Metrics.BaseScore
		}
		if v2 == 0 {
			v2 = c.Metrics.BaseScore
		}
	}
	return v2
}

func bestCVSSVector(v grypeVulnerability) string {
	var v2 string
	for _, c := range v.CVSS {
		if len(c.Version) > 0 && c.Version[0] == '3' {
			return c.Vector
		}
		if v2 == "" {
			v2 = c.Vector
		}
	}
	return v2
}

func hasSource(ratings []model.SeverityRating, source string) bool {
	for _, r := range ratings {
		if r.Source == source {
			return true
		}
	}
	return false
}

// grypeFixState maps Grype's fix vocabulary onto the shared fix state.
func grypeFixState(state string, versions []string) (model.FixState, []string) {
	switch lower(state) {
	case "fixed":
		if len(versions) == 0 {
			return model.FixUnknown, nil
		}
		return model.FixAvailable, versions

	case "not-fixed":
		// The dominant case on debian:11, where Grype reported 211 matches with
		// none fixable.
		return model.FixUnavailable, nil

	case "wont-fix":
		return model.FixWontFix, nil

	case "unknown", "":
		return model.FixUnknown, nil

	default:
		if len(versions) > 0 {
			return model.FixAvailable, versions
		}
		return model.FixUnknown, nil
	}
}
