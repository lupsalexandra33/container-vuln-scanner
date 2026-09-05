package model

import "testing"

func TestParseVulnID(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantScheme Scheme
		wantID     string
		wantErr    bool
	}{
		// Identifiers observed in testdata/fixtures.
		{"cve", "CVE-2023-45853", SchemeCVE, "CVE-2023-45853", false},
		{"debian temp", "TEMP-0841856-B18BAF", SchemeDebian, "TEMP-0841856-B18BAF", false},
		{"ghsa", "GHSA-x92m-jgcx-5qw2", SchemeGHSA, "GHSA-X92M-JGCX-5QW2", false},

		// Other schemes we expect to meet.
		{"debian advisory", "DSA-5123-1", SchemeDSA, "DSA-5123-1", false},
		{"alpine", "ALPINE-12345", SchemeAlpine, "ALPINE-12345", false},
		{"redhat advisory", "RHSA-2023:1234", SchemeRHSA, "RHSA-2023:1234", false},

		// Normalisation.
		{"lowercase is normalised", "cve-2023-45853", SchemeCVE, "CVE-2023-45853", false},
		{"surrounding space is trimmed", "  CVE-2023-45853  ", SchemeCVE, "CVE-2023-45853", false},

		// An identifier we do not recognise is carried, not rejected: a scanner
		// may use a scheme we have not seen, and dropping it would lose a real
		// finding.
		{"unrecognised scheme is kept", "FOO-999", SchemeUnknown, "FOO-999", false},
		{"malformed cve is not a cve", "CVE-23-1", SchemeUnknown, "CVE-23-1", false},

		// Empty is the one genuine error.
		{"empty", "", "", "", true},
		{"whitespace only", "   ", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVulnID(tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseVulnID(%q) = %v, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVulnID(%q) returned unexpected error: %v", tt.raw, err)
			}
			if got.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
			if got.ID != tt.wantID {
				t.Errorf("id = %q, want %q", got.ID, tt.wantID)
			}
		})
	}
}

func TestVulnIDIsCVE(t *testing.T) {
	// Enrichment sources key on CVEs. Sending them a Debian tracker identifier
	// produces no result at best, an error at worst — this is the filter that
	// prevents it.
	cve, _ := ParseVulnID("CVE-2023-45853")
	temp, _ := ParseVulnID("TEMP-0841856-B18BAF")

	if !cve.IsCVE() {
		t.Error("CVE-2023-45853 should be reported as a CVE")
	}
	if temp.IsCVE() {
		t.Error("TEMP-0841856-B18BAF should not be reported as a CVE")
	}
}

func TestVulnIDEqual(t *testing.T) {
	a, _ := ParseVulnID("CVE-2023-45853")
	b, _ := ParseVulnID("cve-2023-45853") // same, differently written
	c, _ := ParseVulnID("CVE-2023-99999")

	if !a.Equal(b) {
		t.Error("identifiers differing only in case should be equal after parsing")
	}
	if a.Equal(c) {
		t.Error("different identifiers should not be equal")
	}
}

func TestVulnRefPreferredID(t *testing.T) {
	cve, _ := ParseVulnID("CVE-2023-45853")
	ghsa, _ := ParseVulnID("GHSA-x92m-jgcx-5qw2")
	temp, _ := ParseVulnID("TEMP-0841856-B18BAF")

	t.Run("cve primary is preferred", func(t *testing.T) {
		ref := VulnRef{Primary: cve, Aliases: []VulnID{ghsa}}
		if got := ref.PreferredID(); !got.Equal(cve) {
			t.Errorf("PreferredID() = %v, want %v", got, cve)
		}
	})

	t.Run("cve alias is preferred over non-cve primary", func(t *testing.T) {
		// OSV-Scanner leads with GHSA where Grype leads with the CVE for the
		// same vulnerability. Preferring the CVE gives a stable key across tools.
		ref := VulnRef{Primary: ghsa, Aliases: []VulnID{cve}}
		if got := ref.PreferredID(); !got.Equal(cve) {
			t.Errorf("PreferredID() = %v, want %v", got, cve)
		}
	})

	t.Run("primary is kept when no cve is known", func(t *testing.T) {
		ref := VulnRef{Primary: temp}
		if got := ref.PreferredID(); !got.Equal(temp) {
			t.Errorf("PreferredID() = %v, want %v", got, temp)
		}
	})
}

func TestVulnRefAllIDs(t *testing.T) {
	cve, _ := ParseVulnID("CVE-2023-45853")
	ghsa, _ := ParseVulnID("GHSA-x92m-jgcx-5qw2")

	ref := VulnRef{Primary: cve, Aliases: []VulnID{ghsa}}
	got := ref.AllIDs()

	if len(got) != 2 {
		t.Fatalf("AllIDs() returned %d ids, want 2", len(got))
	}
	if !got[0].Equal(cve) {
		t.Errorf("first id = %v, want the primary %v", got[0], cve)
	}
}
