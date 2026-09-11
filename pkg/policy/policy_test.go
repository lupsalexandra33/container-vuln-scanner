package policy

import (
	"strings"
	"testing"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// finding builds a consolidated finding for testing.
func finding(id string, sev model.Severity, fix bool) model.ConsolidatedFinding {
	vid, _ := model.ParseVulnID(id)
	purl, _ := model.ParsePURL("pkg:deb/debian/openssl@1.1.1n")

	f := model.ConsolidatedFinding{
		Class:         model.ClassVulnerability,
		Vulnerability: model.VulnRef{Primary: vid},
		Package:       purl,
		Severity:      sev,
		Confidence:    1.0,
	}
	if fix {
		f.FixState = model.FixAvailable
		f.FixedVersions = []string{"1.1.1t"}
	} else {
		f.FixState = model.FixUnavailable
	}
	return f
}

func withKEV(f model.ConsolidatedFinding, inKEV bool, epss float64) model.ConsolidatedFinding {
	f.Enrichment = &model.Enrichment{InKEV: inKEV, EPSSScore: epss}
	return f
}

// TestUnfixableFindingsDoNotFailTheBuild is the case the whole design turns on.
// On debian:11 all 243 consolidated findings are unfixable and ten of them are
// critical. A policy that failed on any critical finding would block every
// build of that image on work nobody can do.
func TestUnfixableFindingsDoNotFailTheBuild(t *testing.T) {
	findings := []model.ConsolidatedFinding{
		finding("CVE-2023-0001", model.SeverityCritical, false),
		finding("CVE-2023-0002", model.SeverityCritical, false),
		finding("CVE-2023-0003", model.SeverityHigh, false),
	}

	d := Balanced().Evaluate(findings)

	if d.Outcome == Fail {
		t.Errorf("outcome = %q, want warn — nothing here can be acted on", d.Outcome)
	}
	if d.Counts[Warn] != 3 {
		t.Errorf("warn count = %d, want 3", d.Counts[Warn])
	}
	if d.Outcome.ExitCode() != 0 {
		t.Errorf("exit code = %d, want 0 — a warn must not break a pipeline", d.Outcome.ExitCode())
	}
}

// TestFixableCriticalFails is the other half: severe, actionable, corroborated.
func TestFixableCriticalFails(t *testing.T) {
	d := Balanced().Evaluate([]model.ConsolidatedFinding{
		finding("CVE-2023-0001", model.SeverityCritical, true),
	})

	if d.Outcome != Fail {
		t.Errorf("outcome = %q, want fail", d.Outcome)
	}
	if d.Outcome.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", d.Outcome.ExitCode())
	}
}

// TestActivelyExploitedOutranksSeverity covers the case severity alone gets
// wrong: a medium finding confirmed to be under attack matters more than a
// critical one nobody has ever exploited.
func TestActivelyExploitedOutranksSeverity(t *testing.T) {
	exploited := withKEV(finding("CVE-2023-0001", model.SeverityMedium, true), true, 0.94)
	theoretical := withKEV(finding("CVE-2023-0002", model.SeverityCritical, false), false, 0.0004)

	d := Balanced().Evaluate([]model.ConsolidatedFinding{exploited, theoretical})

	if d.Outcome != Fail {
		t.Fatalf("outcome = %q, want fail — one finding is under active exploitation", d.Outcome)
	}

	var kevRuleFired bool
	for _, m := range d.Matches {
		if strings.Contains(m.Rule.Name, "actively exploited") && m.Rule.Outcome == Fail {
			kevRuleFired = true
			if len(m.Findings) != 1 {
				t.Errorf("the KEV rule matched %d findings, want 1", len(m.Findings))
			}
		}
	}
	if !kevRuleFired {
		t.Error("expected the actively-exploited rule to fire")
	}
}

// TestUnenrichedFindingIsNotTreatedAsSafe guards a subtle failure. When
// enrichment did not run, Enrichment is nil — and treating that as "not in KEV"
// would silently downgrade a finding on the strength of data never fetched.
func TestUnenrichedFindingIsNotTreatedAsSafe(t *testing.T) {
	unenriched := finding("CVE-2023-0001", model.SeverityCritical, true)
	if unenriched.Enrichment != nil {
		t.Fatal("test setup: expected no enrichment")
	}

	rule := Rule{
		Condition: Condition{InKEV: boolPtr(false)},
		Outcome:   Pass,
	}
	if rule.Matches(unenriched) {
		t.Error("a rule requiring 'not in KEV' must not match a finding where enrichment " +
			"never ran — absence of data is not evidence of absence")
	}
}

func TestConfidenceGatesFailure(t *testing.T) {
	// A finding one scanner reported and another capable scanner missed is
	// weaker evidence. The balanced policy requires corroboration before it
	// blocks a build on a critical finding.
	disputed := finding("CVE-2023-0001", model.SeverityCritical, true)
	disputed.Confidence = 0.4

	corroborated := finding("CVE-2023-0002", model.SeverityCritical, true)
	corroborated.Confidence = 1.0

	if d := Balanced().Evaluate([]model.ConsolidatedFinding{disputed}); d.Outcome == Fail {
		t.Error("a critical finding at 0.4 confidence should not fail the build on its own")
	}
	if d := Balanced().Evaluate([]model.ConsolidatedFinding{corroborated}); d.Outcome != Fail {
		t.Error("a corroborated fixable critical finding should fail the build")
	}
}

func TestExceptionsSuppressWithReason(t *testing.T) {
	p := Balanced()
	p.Exceptions = []Exception{{
		VulnID:  "CVE-2023-0001",
		Reason:  "not reachable from our entry points",
		Expires: "2026-12-31",
	}}

	d := p.Evaluate([]model.ConsolidatedFinding{
		finding("CVE-2023-0001", model.SeverityCritical, true),
	})

	if d.Outcome != Pass {
		t.Errorf("outcome = %q, want pass — the only finding is suppressed", d.Outcome)
	}
	if len(d.Suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1", len(d.Suppressed))
	}
	// Accepting a risk must stay visible rather than making the finding vanish.
	if d.Suppressed[0].Exception.Reason == "" {
		t.Error("a suppression without a recorded reason is indistinguishable from a bug")
	}
}

func TestExceptionMatchesAliases(t *testing.T) {
	// A team writes an exception for the CVE; the scanner may lead with the
	// GHSA. Matching only the primary identifier would leave the exception
	// silently ineffective.
	cve, _ := model.ParseVulnID("CVE-2021-23337")
	ghsa, _ := model.ParseVulnID("GHSA-35jh-r3h4-6jhm")

	f := finding("CVE-2021-23337", model.SeverityCritical, true)
	f.Vulnerability = model.VulnRef{Primary: ghsa, Aliases: []model.VulnID{cve}}

	e := Exception{VulnID: "CVE-2021-23337", Reason: "accepted"}
	if !e.matches(f) {
		t.Error("an exception naming the CVE should match a finding reported under its GHSA")
	}
}

func TestStrictBlocksMoreThanBalanced(t *testing.T) {
	fixable := finding("CVE-2023-0001", model.SeverityHigh, true)

	if d := Balanced().Evaluate([]model.ConsolidatedFinding{fixable}); d.Outcome != Warn {
		t.Errorf("balanced outcome = %q, want warn for a fixable high", d.Outcome)
	}
	if d := Strict().Evaluate([]model.ConsolidatedFinding{fixable}); d.Outcome != Fail {
		t.Errorf("strict outcome = %q, want fail for a fixable high", d.Outcome)
	}
}

// TestStrictStillWarnsOnUnfixable checks that even the strict policy does not
// block on work that cannot be done. A gate that fires on the unfixable gets
// bypassed, and a bypassed gate protects nothing.
func TestStrictStillWarnsOnUnfixable(t *testing.T) {
	d := Strict().Evaluate([]model.ConsolidatedFinding{
		finding("CVE-2023-0001", model.SeverityCritical, false),
	})
	if d.Outcome != Warn {
		t.Errorf("outcome = %q, want warn — strict still does not block on the unfixable", d.Outcome)
	}
}

func TestAdvisoryNeverFails(t *testing.T) {
	worst := withKEV(finding("CVE-2023-0001", model.SeverityCritical, true), true, 0.99)

	d := Advisory().Evaluate([]model.ConsolidatedFinding{worst})
	if d.Outcome == Fail {
		t.Error("the advisory policy must never fail a build, by definition")
	}
	if d.Outcome.ExitCode() != 0 {
		t.Errorf("exit code = %d, want 0", d.Outcome.ExitCode())
	}
}

func TestExplainNamesTheRule(t *testing.T) {
	// A build blocked without a stated reason is a build the team works around.
	d := Balanced().Evaluate([]model.ConsolidatedFinding{
		finding("CVE-2023-0001", model.SeverityCritical, true),
	})

	out := d.Explain()
	for _, want := range []string{"FAIL", "critical", "CVE-2023-0001"} {
		if !strings.Contains(out, want) {
			t.Errorf("explanation does not mention %q:\n%s", want, out)
		}
	}
}

func TestByName(t *testing.T) {
	for _, name := range Names() {
		if _, ok := ByName(name); !ok {
			t.Errorf("ByName(%q) reported unknown, but it is in Names()", name)
		}
	}
	if _, ok := ByName("nonexistent"); ok {
		t.Error("ByName should report an unknown policy as unknown")
	}
	if p, ok := ByName(""); !ok || p.Name != "balanced" {
		t.Error("an empty name should resolve to the balanced policy")
	}
}

func TestEmptyFindingsPass(t *testing.T) {
	d := Balanced().Evaluate(nil)
	if d.Outcome != Pass {
		t.Errorf("outcome = %q, want pass with no findings", d.Outcome)
	}
}
