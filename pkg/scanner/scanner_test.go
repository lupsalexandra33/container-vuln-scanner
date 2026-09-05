package scanner

import (
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

func TestCapabilitiesDetects(t *testing.T) {
	// Trivy: vulnerabilities in OS and language packages, but it does not
	// catalogue compiled binaries.
	trivy := Capabilities{
		Classes:    []model.FindingClass{model.ClassVulnerability},
		Ecosystems: []string{"deb", "apk", "npm", "pypi"},
	}

	// Grype: the same, plus binaries. On node:12-alpine it reported 41 binary
	// findings where Trivy reported none.
	grype := Capabilities{
		Classes:    []model.FindingClass{model.ClassVulnerability},
		Ecosystems: []string{"deb", "apk", "npm", "pypi", "binary"},
	}

	// A misconfiguration scanner examines the image, not its packages.
	dockle := Capabilities{
		Classes: []model.FindingClass{model.ClassMisconfiguration, model.ClassSecret},
	}

	tests := []struct {
		name      string
		caps      Capabilities
		class     model.FindingClass
		ecosystem string
		want      bool
	}{
		{"trivy detects deb vulnerabilities", trivy, model.ClassVulnerability, "deb", true},
		{"trivy detects npm vulnerabilities", trivy, model.ClassVulnerability, "npm", true},

		// The case the whole mechanism exists for: Trivy's silence on a binary
		// finding is incapacity, not disagreement.
		{"trivy does not detect binaries", trivy, model.ClassVulnerability, "binary", false},
		{"grype detects binaries", grype, model.ClassVulnerability, "binary", true},

		{"trivy does not detect misconfigurations", trivy, model.ClassMisconfiguration, "", false},
		{"dockle detects misconfigurations", dockle, model.ClassMisconfiguration, "", true},
		{"dockle detects secrets", dockle, model.ClassSecret, "", true},
		{"dockle does not detect vulnerabilities", dockle, model.ClassVulnerability, "deb", false},

		// An empty ecosystem list means the scanner is not ecosystem-limited.
		{
			name:      "empty ecosystem list means all ecosystems",
			caps:      Capabilities{Classes: []model.FindingClass{model.ClassVulnerability}},
			class:     model.ClassVulnerability,
			ecosystem: "anything",
			want:      true,
		},
		// An unknown ecosystem is not grounds to exclude a scanner that handles
		// the class: failing open here keeps a capable scanner in the
		// denominator rather than silently dropping it.
		{"unspecified ecosystem", trivy, model.ClassVulnerability, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caps.Detects(tt.class, tt.ecosystem); got != tt.want {
				t.Errorf("Detects(%q, %q) = %v, want %v",
					tt.class, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestCapabilitiesDetectsUnknownEcosystem(t *testing.T) {
	// A scanner that lists ecosystems does not detect one it did not list.
	trivy := Capabilities{
		Classes:    []model.FindingClass{model.ClassVulnerability},
		Ecosystems: []string{"deb", "apk"},
	}
	if trivy.Detects(model.ClassVulnerability, "cargo") {
		t.Error("a scanner should not claim an ecosystem it does not list")
	}
}
