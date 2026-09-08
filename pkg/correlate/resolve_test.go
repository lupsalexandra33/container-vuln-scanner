package correlate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
	"github.com/lupsalexandra33/container-vuln-scanner/pkg/normalize"
)

func rated(scanner string, ratings map[string]model.Severity) model.Finding {
	f := model.Finding{Class: model.ClassVulnerability, Scanner: scanner}
	for source, sev := range ratings {
		f.Severities = append(f.Severities, model.SeverityRating{
			Severity: sev,
			Source:   source,
			Original: string(sev),
		})
	}
	return f
}

func TestResolveSeverityNoConflict(t *testing.T) {
	sev, conflict := ResolveSeverity(
		[]model.Finding{rated("trivy", map[string]model.Severity{
			"debian": model.SeverityHigh,
			"nvd":    model.SeverityHigh,
		})},
		"deb",
	)

	if sev != model.SeverityHigh {
		t.Errorf("severity = %q, want high", sev)
	}
	if conflict != nil {
		t.Error("sources that agree should not produce a conflict record")
	}
}

// TestDistributionOutranksNVD is the backporting case. Debian applies security
// fixes without changing upstream version numbers, so NVD — which describes the
// upstream software — can rate a package differently from the distribution that
// actually built it. For a deb package, Debian's assessment is the one that
// describes what is installed.
func TestDistributionOutranksNVD(t *testing.T) {
	sev, conflict := ResolveSeverity(
		[]model.Finding{rated("trivy", map[string]model.Severity{
			"debian": model.SeverityLow,
			"nvd":    model.SeverityCritical,
		})},
		"deb",
	)

	if sev != model.SeverityLow {
		t.Errorf("severity = %q, want low — debian is authoritative for deb packages", sev)
	}
	if conflict == nil {
		t.Fatal("expected a recorded conflict")
	}
	if conflict.Values["nvd"] != string(model.SeverityCritical) {
		t.Errorf("the rejected NVD value should be recorded, got %v", conflict.Values)
	}
	if conflict.Reason == "" {
		t.Error("a resolution without a reason cannot be checked by a reader")
	}
	t.Logf("resolved to %s: %s", conflict.Resolved, conflict.Reason)
}

// TestDistributionConsensusOutranksNVD is CVE-2022-3715 in bash on debian:11:
// six distributions rate it MEDIUM, NVD alone rates it HIGH, and Trivy promotes
// NVD's value. Six independent assessments of the same bug converging is
// stronger evidence than one describing the upstream software.
func TestDistributionConsensusOutranksNVD(t *testing.T) {
	sev, conflict := ResolveSeverity(
		[]model.Finding{rated("trivy", map[string]model.Severity{
			"alma":        model.SeverityMedium,
			"amazon":      model.SeverityMedium,
			"oracle-oval": model.SeverityMedium,
			"redhat":      model.SeverityMedium,
			"rocky":       model.SeverityMedium,
			"ubuntu":      model.SeverityMedium,
			"nvd":         model.SeverityHigh,
		})},
		"deb", // no debian rating present, so no single authority applies
	)

	if sev != model.SeverityMedium {
		t.Errorf("severity = %q, want medium — six distributions agree against NVD alone", sev)
	}
	if conflict == nil {
		t.Fatal("expected a recorded conflict")
	}
	t.Logf("resolved to %s: %s", conflict.Resolved, conflict.Reason)
}

func TestDistributionsDisagreeAmongThemselves(t *testing.T) {
	// No consensus and no authority for this ecosystem: err toward surfacing
	// rather than hiding.
	sev, conflict := ResolveSeverity(
		[]model.Finding{rated("trivy", map[string]model.Severity{
			"ubuntu": model.SeverityMedium,
			"redhat": model.SeverityHigh,
			"nvd":    model.SeverityLow,
		})},
		"deb",
	)

	if sev != model.SeverityHigh {
		t.Errorf("severity = %q, want high", sev)
	}
	if conflict == nil {
		t.Fatal("expected a recorded conflict")
	}
}

func TestGenericSourcesOnly(t *testing.T) {
	// npm packages have no distribution behind them, so generic sources are all
	// there is — and the resolution says so rather than implying authority.
	sev, conflict := ResolveSeverity(
		[]model.Finding{rated("grype", map[string]model.Severity{
			"nvd":  model.SeverityHigh,
			"ghsa": model.SeverityCritical,
		})},
		"npm",
	)

	if sev != model.SeverityCritical {
		t.Errorf("severity = %q, want critical", sev)
	}
	if conflict == nil {
		t.Fatal("expected a recorded conflict")
	}
	t.Logf("resolved to %s: %s", conflict.Resolved, conflict.Reason)
}

func TestResolveSeverityAcrossScanners(t *testing.T) {
	// Two scanners quoting the same source at different snapshot times. Keeping
	// the more severe reading means a disagreement is never resolved by
	// discarding the worse half of it.
	sev, _ := ResolveSeverity(
		[]model.Finding{
			rated("trivy", map[string]model.Severity{"debian": model.SeverityMedium}),
			rated("grype", map[string]model.Severity{"debian": model.SeverityHigh}),
		},
		"deb",
	)

	if sev != model.SeverityHigh {
		t.Errorf("severity = %q, want high", sev)
	}
}

func TestResolveFixStatePrefersActionable(t *testing.T) {
	tests := []struct {
		name    string
		in      []model.Finding
		want    model.FixState
		wantVer bool
	}{
		{
			name: "a named fix outranks no fix",
			in: []model.Finding{
				{Scanner: "trivy", FixState: model.FixAvailable, FixedVersions: []string{"1.2.13"}},
				{Scanner: "grype", FixState: model.FixUnavailable},
			},
			want:    model.FixAvailable,
			wantVer: true,
		},
		{
			name: "not affected closes the finding",
			in: []model.Finding{
				{Scanner: "trivy", FixState: model.FixNotAffected},
				{Scanner: "grype", FixState: model.FixUnavailable},
			},
			want: model.FixNotAffected,
		},
		{
			// The debian:11 case: every finding is unfixable, and the report
			// must say which kind of unfixable.
			name: "wont-fix outranks unavailable",
			in: []model.Finding{
				{Scanner: "trivy", FixState: model.FixWontFix},
				{Scanner: "grype", FixState: model.FixUnavailable},
			},
			want: model.FixWontFix,
		},
		{
			name: "agreement produces no conflict",
			in: []model.Finding{
				{Scanner: "trivy", FixState: model.FixUnavailable},
				{Scanner: "grype", FixState: model.FixUnavailable},
			},
			want: model.FixUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, versions, conflict := ResolveFixState(tt.in)
			if state != tt.want {
				t.Errorf("fix state = %q, want %q", state, tt.want)
			}
			if tt.wantVer && len(versions) == 0 {
				t.Error("expected a fixed version to be carried through")
			}
			if tt.name == "agreement produces no conflict" && conflict != nil {
				t.Error("agreement should not produce a conflict record")
			}
		})
	}
}

func TestConflictSummaryIsStable(t *testing.T) {
	// The summary is rendered into reports, so it must not change between runs
	// on the same input.
	c := []model.Conflict{{
		Kind:     model.ConflictSeverity,
		Values:   map[string]string{"nvd": "critical", "debian": "low", "ubuntu": "low"},
		Resolved: "low",
		Reason:   "debian is authoritative for deb packages",
	}}

	first := ConflictSummary(c)
	for i := 0; i < 20; i++ {
		if got := ConflictSummary(c); got != first {
			t.Fatalf("summary changed between runs:\n  %s\n  %s", first, got)
		}
	}
	t.Logf("%s", first)
}

// TestResolutionOnRealFixtures runs resolution over the recorded debian:11
// output and reports how much of it is disputed.
func TestResolutionOnRealFixtures(t *testing.T) {
	load := func(file, scanner, format string) []model.Finding {
		path := filepath.Join("..", "..", "testdata", "fixtures", "debian_11", file)
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}
		findings, err := normalize.NewRegistry().Normalize(model.RawResult{
			Scanner: scanner, Format: format, Payload: payload,
		})
		if err != nil {
			t.Fatalf("normalising: %v", err)
		}
		return findings
	}

	all := append(load("trivy.json", "trivy", "trivy-json"),
		load("grype.json", "grype", "grype-json")...)

	out := Correlate(all, []Participant{
		{Name: "trivy", Capabilities: vulnScanner, Ran: true},
		{Name: "grype", Capabilities: binaryAware, Ran: true},
	})

	var withConflicts, severityConflicts, fixConflicts int
	reasons := map[string]int{}
	for _, c := range out {
		if len(c.Conflicts) > 0 {
			withConflicts++
		}
		for _, cf := range c.Conflicts {
			switch cf.Kind {
			case model.ConflictSeverity:
				severityConflicts++
				reasons[cf.Reason]++
			case model.ConflictFixState:
				fixConflicts++
			}
		}
	}

	t.Logf("%d of %d consolidated findings carry a recorded conflict", withConflicts, len(out))
	t.Logf("severity conflicts: %d | fix state conflicts: %d", severityConflicts, fixConflicts)
	for reason, n := range reasons {
		t.Logf("  %3d resolved because %s", n, reason)
	}

	if severityConflicts == 0 {
		t.Error("expected severity conflicts — 145 of 222 findings have disagreeing sources")
	}
}
