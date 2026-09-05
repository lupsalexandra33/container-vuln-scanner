package model

import "testing"

func TestSeverityOrdering(t *testing.T) {
	ordered := []Severity{
		SeverityUnknown,
		SeverityNegligible,
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}

	for i := 1; i < len(ordered); i++ {
		if !ordered[i].MoreSevereThan(ordered[i-1]) {
			t.Errorf("%q should be more severe than %q", ordered[i], ordered[i-1])
		}
	}

	// Unknown means absence of information and must never outrank a real
	// assessment — otherwise a scanner that says nothing would silently
	// escalate a finding.
	if SeverityUnknown.MoreSevereThan(SeverityNegligible) {
		t.Error("unknown severity should not outrank a real assessment")
	}
}

func TestFindingPrimarySeverity(t *testing.T) {
	tests := []struct {
		name string
		in   []SeverityRating
		want Severity
	}{
		{
			name: "no ratings",
			in:   nil,
			want: SeverityUnknown,
		},
		{
			name: "single rating",
			in:   []SeverityRating{{Severity: SeverityHigh, Source: "nvd"}},
			want: SeverityHigh,
		},
		{
			// Trivy reports both the distribution's rating and NVD's for the
			// same identifier. Within one scanner, the highest is the
			// conservative choice; resolving between scanners is the
			// correlator's job and uses trust, not maximum.
			name: "highest of several sources",
			in: []SeverityRating{
				{Severity: SeverityMedium, Source: "debian"},
				{Severity: SeverityCritical, Source: "nvd"},
				{Severity: SeverityLow, Source: "ghsa"},
			},
			want: SeverityCritical,
		},
		{
			name: "unknown alongside a real rating",
			in: []SeverityRating{
				{Severity: SeverityUnknown, Source: "vendor"},
				{Severity: SeverityLow, Source: "nvd"},
			},
			want: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{Severities: tt.in}
			if got := f.PrimarySeverity(); got != tt.want {
				t.Errorf("PrimarySeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindingSeverityFrom(t *testing.T) {
	// Conflict resolution prefers the distribution's assessment for a
	// distribution package, because the distribution is authoritative about
	// its own backports. That lookup is what this supports.
	f := Finding{
		Severities: []SeverityRating{
			{Severity: SeverityMedium, Source: "debian", Original: "Medium"},
			{Severity: SeverityCritical, Source: "nvd", Original: "CRITICAL", CVSSScore: 9.8},
		},
	}

	got, ok := f.SeverityFrom("debian")
	if !ok {
		t.Fatal("expected a debian rating")
	}
	if got.Severity != SeverityMedium {
		t.Errorf("debian severity = %q, want %q", got.Severity, SeverityMedium)
	}

	nvd, ok := f.SeverityFrom("nvd")
	if !ok {
		t.Fatal("expected an nvd rating")
	}
	if nvd.CVSSScore != 9.8 {
		t.Errorf("nvd CVSS score = %v, want 9.8", nvd.CVSSScore)
	}

	if _, ok := f.SeverityFrom("redhat"); ok {
		t.Error("expected no rating from a source that did not supply one")
	}
}

func TestFindingHasFix(t *testing.T) {
	tests := []struct {
		name     string
		state    FixState
		versions []string
		want     bool
	}{
		{"available with a version", FixAvailable, []string{"1.1.1t-0+deb11u1"}, true},

		// On debian:11, Grype reported 211 matches with no fix available. A
		// policy that fails a build on any critical finding would block work
		// the team cannot do — telling these apart is what makes a workable
		// policy expressible.
		{"no fix exists", FixUnavailable, nil, false},
		{"maintainer will not fix", FixWontFix, nil, false},

		// Distribution backports: the package carries the security fix without
		// its upstream version changing, so it matches a vulnerable range but
		// is not actually affected.
		{"not affected", FixNotAffected, nil, false},

		// The scanner said nothing. Not the same as saying there is no fix.
		{"unknown", FixUnknown, nil, false},

		// Claiming a fix without naming a version is not actionable.
		{"available but no version given", FixAvailable, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{FixState: tt.state, FixedVersions: tt.versions}
			if got := f.HasFix(); got != tt.want {
				t.Errorf("HasFix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindingIsCorrelatable(t *testing.T) {
	cve, _ := ParseVulnID("CVE-2023-45853")
	purl, _ := ParsePURL("pkg:deb/debian/zlib1g@1.2.11.dfsg-2?arch=amd64")

	t.Run("vulnerability with an identifier and a package", func(t *testing.T) {
		f := Finding{
			Class:         ClassVulnerability,
			Vulnerability: VulnRef{Primary: cve},
			Package:       purl,
		}
		if !f.IsCorrelatable() {
			t.Error("a vulnerability with both an identifier and a PURL should be correlatable")
		}
	})

	t.Run("vulnerability without a package", func(t *testing.T) {
		// Not every scanner emits a PURL for every finding. Such a finding is
		// not dropped — it falls through to approximate matching, and to the
		// uncorrelated category if that fails too.
		f := Finding{
			Class:         ClassVulnerability,
			Vulnerability: VulnRef{Primary: cve},
			PackageName:   "zlib1g",
		}
		if f.IsCorrelatable() {
			t.Error("a finding without a PURL should not be exactly correlatable")
		}
	})

	t.Run("secret", func(t *testing.T) {
		// Secrets have no CVE and no PURL. Their identity rules belong with the
		// scanners that produce them; claiming correlatability here would be
		// claiming something not yet defined.
		f := Finding{Class: ClassSecret, Location: "/app/.env"}
		if f.IsCorrelatable() {
			t.Error("a secret should not be exactly correlatable")
		}
	})

	t.Run("misconfiguration", func(t *testing.T) {
		f := Finding{Class: ClassMisconfiguration, Title: "Image runs as root"}
		if f.IsCorrelatable() {
			t.Error("a misconfiguration should not be exactly correlatable")
		}
	})
}
