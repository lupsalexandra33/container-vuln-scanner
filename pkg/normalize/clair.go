package normalize

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

type ClairNormalizer struct{}

func (ClairNormalizer) Format() string { return "clair-json" }

type clairReport struct {
	Vulnerabilities        map[string]clairVulnerability `json:"vulnerabilities"`
	Packages               map[string]clairPackage       `json:"packages"`
	PackageVulnerabilities map[string][]string           `json:"package_vulnerabilities"`
}

type clairVulnerability struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	NormalizedSeverity string        `json:"normalized_severity"`
	FixedInVersion     string        `json:"fixed_in_version"`
	Package            *clairPackage `json:"package"`
	Updater            string        `json:"updater"`
}

type clairPackage struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Kind    string        `json:"kind"`
	Source  *clairPackage `json:"source"`
}

func (ClairNormalizer) Normalize(raw model.RawResult) ([]model.Finding, error) {
	var report clairReport
	if err := json.Unmarshal(raw.Payload, &report); err != nil {
		return nil, fmt.Errorf("parsing clair report: %w", err)
	}

	var findings []model.Finding

	for pkgID, vulnIDs := range report.PackageVulnerabilities {
		pkg, ok := report.Packages[pkgID]
		if !ok {
			continue
		}

		for _, vulnID := range vulnIDs {
			vuln, ok := report.Vulnerabilities[vulnID]
			if !ok {
				continue
			}
			findings = append(findings, buildClairFinding(vuln, pkg))
		}
	}

	if len(report.PackageVulnerabilities) == 0 {
		for _, vuln := range report.Vulnerabilities {
			if vuln.Package != nil {
				findings = append(findings, buildClairFinding(vuln, *vuln.Package))
			}
		}
	}

	return findings, nil
}

func buildClairFinding(vuln clairVulnerability, pkg clairPackage) model.Finding {
	sev := model.SeverityUnknown
	switch strings.ToLower(vuln.NormalizedSeverity) {
	case "negligible":
		sev = model.SeverityNegligible
	case "low":
		sev = model.SeverityLow
	case "medium":
		sev = model.SeverityMedium
	case "high":
		sev = model.SeverityHigh
	case "critical":
		sev = model.SeverityCritical
	}

	fixState := model.FixUnavailable
	var fixedVersions []string
	if vuln.FixedInVersion != "" {
		fixState = model.FixAvailable
		fixedVersions = []string{vuln.FixedInVersion}
	}

	source := vuln.Updater
	if source == "" {
		source = "clair"
	}

	pkgName := pkg.Name

	// Correlator alignment: Trivy and Grype heavily group by Source Package (e.g. 'apt' instead of 'libapt-pkg7.0')
	// If Clair provides the upstream Source package, use it for alignment.
	if pkg.Source != nil && pkg.Source.Name != "" {
		pkgName = pkg.Source.Name
	} else if pkgName == "" && vuln.Package != nil {
		pkgName = vuln.Package.Name
		if vuln.Package.Source != nil && vuln.Package.Source.Name != "" {
			pkgName = vuln.Package.Source.Name
		}
	}

	pkgType := pkg.Kind
	if pkgType == "" {
		if strings.Contains(strings.ToLower(source), "alpine") {
			pkgType = "apk"
		} else if strings.Contains(strings.ToLower(source), "ubuntu") || strings.Contains(strings.ToLower(source), "debian") {
			pkgType = "deb"
		} else {
			pkgType = "unknown"
		}
	}

	vulnID, _ := model.ParseVulnID(vuln.Name)

	pkgNamespace := ""
	if pkgType == "deb" {
		if strings.Contains(strings.ToLower(source), "ubuntu") {
			pkgNamespace = "ubuntu"
		} else {
			pkgNamespace = "debian"
		}
	} else if pkgType == "apk" {
		pkgNamespace = "alpine"
	}

	purl := model.PURL{
		Type:      pkgType,
		Namespace: pkgNamespace,
		Name:      pkgName,
		Version:   pkg.Version,
	}

	return model.Finding{
		Scanner: "clair",
		Class:   model.ClassVulnerability,
		Vulnerability: model.VulnRef{
			Primary: vulnID,
		},
		Package:          purl,
		Description:      vuln.Description,
		PackageName:      pkgName,
		InstalledVersion: pkg.Version,
		Severities: []model.SeverityRating{
			{
				Severity: sev,
				Source:   source,
				Original: vuln.NormalizedSeverity,
			},
		},
		FixState:      fixState,
		FixedVersions: fixedVersions,
	}
}
