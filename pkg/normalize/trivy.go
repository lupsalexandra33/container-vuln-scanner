package normalize

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// TrivyNormalizer converts Trivy's JSON report into the shared model.
type TrivyNormalizer struct{}

func (TrivyNormalizer) Format() string { return "trivy-json" }

// trivyReport mirrors the parts of Trivy's output we consume. Fields we do not
// use are omitted: adding them later is cheap, and parsing what we ignore is
// not.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			// EOSL — "end of service life". Trivy sets this when the
			// distribution no longer receives security updates, which is the
			// signal behind the alpine:3.14 case: zero findings there means
			// the feed has nothing left to say, not that the image is clean.
			EOSL bool `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgIdentifier   struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Status           string `json:"Status"`

	Layer struct {
		DiffID string `json:"DiffID"`
	} `json:"Layer"`

	// Severity is the value Trivy chose; SeveritySource names which vendor it
	// came from. VendorSeverity carries every vendor's rating as an integer.
	Severity       string         `json:"Severity"`
	SeveritySource string         `json:"SeveritySource"`
	VendorSeverity map[string]int `json:"VendorSeverity"`

	// CVSS is keyed by the same source names as VendorSeverity, which is what
	// lets a score be attached to the rating it belongs with.
	CVSS map[string]struct {
		V2Vector string  `json:"V2Vector"`
		V3Vector string  `json:"V3Vector"`
		V2Score  float64 `json:"V2Score"`
		V3Score  float64 `json:"V3Score"`
	} `json:"CVSS"`

	Title         string    `json:"Title"`
	Description   string    `json:"Description"`
	References    []string  `json:"References"`
	PublishedDate time.Time `json:"PublishedDate"`
}

// trivySeverityLevels maps Trivy's numeric vendor severities onto the shared
// scale. The numbers are Trivy's internal ordering, not a standard.
var trivySeverityLevels = map[int]model.Severity{
	0: model.SeverityUnknown,
	1: model.SeverityLow,
	2: model.SeverityMedium,
	3: model.SeverityHigh,
	4: model.SeverityCritical,
}

func (n TrivyNormalizer) Normalize(raw model.RawResult) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(raw.Payload, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy report: %w", err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, n.convert(v, raw.Scanner))
		}
	}
	return findings, nil
}

func (n TrivyNormalizer) convert(v trivyVulnerability, scanner string) model.Finding {
	f := model.Finding{
		Class:            model.ClassVulnerability,
		Scanner:          scanner,
		PackageName:      v.PkgName,
		InstalledVersion: v.InstalledVersion,
		Title:            v.Title,
		Description:      v.Description,
		References:       v.References,
		Location:         v.Layer.DiffID,
		PublishedAt:      v.PublishedDate,
	}

	// An identifier that will not parse is kept as-is rather than dropped:
	// ParseVulnID only errors on an empty string, and returns SchemeUnknown for
	// anything it does not recognise. This is where TEMP-* identifiers survive.
	if id, err := model.ParseVulnID(v.VulnerabilityID); err == nil {
		f.Vulnerability = model.VulnRef{Primary: id}
	}

	// A finding without a parseable PURL is still reported; it simply cannot be
	// correlated on exact identity, which Finding.IsCorrelatable reports.
	if v.PkgIdentifier.PURL != "" {
		if p, err := model.ParsePURL(v.PkgIdentifier.PURL); err == nil {
			f.Package = p
		}
	}

	f.FixState, f.FixedVersions = trivyFixState(v.Status, v.FixedVersion)
	f.Severities = n.severities(v)
	return f
}

// severities collects every vendor rating Trivy supplied, each attached to the
// CVSS data from the same source.
//
// Keeping all of them is what lets conflict resolution later prefer the
// distribution's assessment for a distribution package, rather than accepting
// whichever value the scanner happened to promote to the top-level Severity
// field.
func (n TrivyNormalizer) severities(v trivyVulnerability) []model.SeverityRating {
	var out []model.SeverityRating

	for source, level := range v.VendorSeverity {
		r := model.SeverityRating{
			Severity: trivySeverityLevels[level],
			Source:   source,
			Original: v.Severity,
		}
		if c, ok := v.CVSS[source]; ok {
			// Prefer CVSS v3 where both are present: v2 uses a different scale
			// and mixing them would make scores incomparable.
			if c.V3Score > 0 {
				r.CVSSScore, r.CVSSVector = c.V3Score, c.V3Vector
			} else {
				r.CVSSScore, r.CVSSVector = c.V2Score, c.V2Vector
			}
		}
		out = append(out, r)
	}

	// Some findings carry a top-level severity with no vendor breakdown.
	if len(out) == 0 && v.Severity != "" {
		source := v.SeveritySource
		if source == "" {
			source = "trivy"
		}
		out = append(out, model.SeverityRating{
			Severity: normaliseSeverity(v.Severity),
			Source:   source,
			Original: v.Severity,
		})
	}
	return out
}

// trivyFixState maps Trivy's status vocabulary onto the shared fix state.
func trivyFixState(status, fixedVersion string) (model.FixState, []string) {
	switch lower(status) {
	case "fixed":
		if fixedVersion == "" {
			// Claiming a fix without naming a version is not actionable.
			return model.FixUnknown, nil
		}
		return model.FixAvailable, splitVersions(fixedVersion)

	case "affected":
		// Known to be affected with no fix published. On debian:11 this is the
		// overwhelming majority: Grype reported 211 matches there, none of them
		// fixable. A policy that fails a build on any critical finding would
		// block work the team has no way to do.
		return model.FixUnavailable, nil

	case "will_not_fix", "fix_deferred":
		return model.FixWontFix, nil

	case "not_affected":
		// Distribution backports produce this: the package carries the security
		// fix without its upstream version changing, so it matches a vulnerable
		// range while not actually being vulnerable.
		return model.FixNotAffected, nil

	case "end_of_life":
		// The distribution has stopped issuing fixes entirely. Not the same as
		// no fix existing for this particular issue.
		return model.FixWontFix, nil

	default:
		if fixedVersion != "" {
			return model.FixAvailable, splitVersions(fixedVersion)
		}
		return model.FixUnknown, nil
	}
}

// splitVersions splits Trivy's comma-separated fixed-version list. Several
// entries appear when more than one release line is patched.
func splitVersions(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if v := trimSpace(s[start:i]); v != "" {
				out = append(out, v)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
